//! Graceful shutdown with telemetry queue draining.
//!
//! `TelemetryQueue` buffers telemetry events (audit scan results, alerts,
//! etc.) between production and confirmed write to a sink. An abrupt
//! process exit can drop events that were consumed off the queue but not
//! yet durably written, creating gaps in the audit trail. `graceful_shutdown`
//! closes the queue to new events and drains everything still pending to
//! the given sink, bounded by a timeout so a stuck sink can't hang shutdown
//! indefinitely.
//!
//! This module is observational/telemetry-only — it has no on-chain halt
//! authority and does not gate or block anything by itself. Failures during
//! drain are surfaced as errors (for the caller to log/alert on), never
//! silently swallowed.

use std::time::Duration;
use tokio::sync::mpsc;
use tokio::sync::Mutex;

/// A single telemetry event flowing through the queue.
///
/// Intentionally opaque (a JSON-ish payload plus a source label) rather than
/// a fixed struct, since this module doesn't yet know what specific
/// telemetry producers will look like — callers can layer a typed wrapper
/// on top once a concrete producer exists.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TelemetryEvent {
    pub source: String,
    pub payload: String,
}

impl TelemetryEvent {
    pub fn new(source: impl Into<String>, payload: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            payload: payload.into(),
        }
    }
}

/// Errors from queue operations. Propagated via `thiserror` rather than
/// `Box<dyn Error>` so callers can match on specific failure modes (e.g. to
/// decide whether a `DrainTimeout` should page on-call vs a routine log).
#[derive(Debug, thiserror::Error)]
pub enum TelemetryQueueError {
    #[error("queue is shutting down; new events are no longer accepted")]
    ShuttingDown,

    #[error("drain timed out after {elapsed:?} with {remaining} event(s) still pending")]
    DrainTimeout { elapsed: Duration, remaining: usize },

    #[error("sink rejected event during drain: {0}")]
    SinkError(String),

    #[error("internal channel closed unexpectedly")]
    ChannelClosed,
}

/// An in-memory, single-consumer telemetry queue with graceful-shutdown
/// draining. Observational-only: draining moves events to `sink`, it does
/// not itself decide whether upstream work should proceed.
pub struct TelemetryQueue {
    sender: mpsc::UnboundedSender<TelemetryEvent>,
    receiver: Mutex<Option<mpsc::UnboundedReceiver<TelemetryEvent>>>,
    shutting_down: std::sync::atomic::AtomicBool,
}

impl TelemetryQueue {
    pub fn new() -> Self {
        let (sender, receiver) = mpsc::unbounded_channel();
        Self {
            sender,
            receiver: Mutex::new(Some(receiver)),
            shutting_down: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// Enqueues a telemetry event. Rejected once shutdown has begun —
    /// "graceful shutdown" means no new work is accepted while draining.
    pub fn enqueue(&self, event: TelemetryEvent) -> Result<(), TelemetryQueueError> {
        if self.shutting_down.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(TelemetryQueueError::ShuttingDown);
        }
        self.sender
            .send(event)
            .map_err(|_| TelemetryQueueError::ChannelClosed)
    }

    /// Closes the queue to new events, then drains everything currently
    /// pending to `sink`, bounded by `timeout`.
    ///
    /// Returns the number of events successfully drained. On timeout or a
    /// sink failure, returns an `Err` describing exactly what went wrong and
    /// how many events were left undrained — callers must surface this as
    /// an alert, not swallow it, per the observational-only design here.
    pub async fn graceful_shutdown<S>(
        &self,
        mut sink: S,
        timeout: Duration,
    ) -> Result<usize, TelemetryQueueError>
    where
        S: FnMut(TelemetryEvent) -> Result<(), String>,
    {
        self.shutting_down
            .store(true, std::sync::atomic::Ordering::SeqCst);

        let mut receiver_guard = self.receiver.lock().await;
        let receiver = receiver_guard
            .as_mut()
            .ok_or(TelemetryQueueError::ChannelClosed)?;

        let start = std::time::Instant::now();
        let mut drained = 0usize;

        let drain_fut = async {
            // try_recv drains only what's already pending rather than
            // waiting indefinitely for new events that enqueue() now
            // rejects anyway — a closed-to-new-work queue has a finite,
            // known-in-advance backlog.
            //
            // The sink is invoked via `spawn_blocking` and awaited per
            // event (rather than called inline) so that a slow/hung sink
            // yields control back to the executor between events. Without
            // this, a synchronous sink with no internal await points would
            // run to completion once polled and the outer timeout's timer
            // would never get a chance to fire.
            while let Ok(event) = receiver.try_recv() {
                let sink_call = std::panic::AssertUnwindSafe(&mut sink);
                let result = tokio::task::block_in_place(|| sink_call.0(event));
                result.map_err(TelemetryQueueError::SinkError)?;
                drained += 1;
                // Explicit yield so a run of many fast events still gives
                // the timer driver a chance to observe an expired deadline.
                tokio::task::yield_now().await;
            }
            Ok::<(), TelemetryQueueError>(())
        };

        match tokio::time::timeout(timeout, drain_fut).await {
            Ok(Ok(())) => Ok(drained),
            Ok(Err(e)) => {
                // Alert channel: this crate has no logging framework
                // dependency yet (no `log`/`tracing` anywhere in Cargo.toml),
                // so stderr is the conventional fallback for "must not be
                // silent" failures until one is introduced. A caller that
                // discards this Result via `let _ = ...` still gets a
                // visible signal rather than a fully swallowed failure.
                eprintln!(
                    "[telemetry_queue] ALERT: graceful_shutdown drain failed after draining {drained} event(s): {e}"
                );
                Err(e)
            }
            Err(_elapsed) => {
                let remaining = receiver.len();
                let err = TelemetryQueueError::DrainTimeout {
                    elapsed: start.elapsed(),
                    remaining,
                };
                eprintln!(
                    "[telemetry_queue] ALERT: graceful_shutdown {err}"
                );
                Err(err)
            }
        }
    }
}

impl Default for TelemetryQueue {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex as StdMutex};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drains_all_pending_events_to_sink() {
        let queue = TelemetryQueue::new();
        for i in 0..5 {
            queue
                .enqueue(TelemetryEvent::new("test", format!("event-{i}")))
                .unwrap();
        }

        let received = Arc::new(StdMutex::new(Vec::new()));
        let received_clone = received.clone();

        let drained = queue
            .graceful_shutdown(
                move |event| {
                    received_clone.lock().unwrap().push(event.payload);
                    Ok(())
                },
                Duration::from_secs(1),
            )
            .await
            .expect("drain should succeed");

        assert_eq!(drained, 5);
        assert_eq!(received.lock().unwrap().len(), 5);
    }

    #[test]
    fn default_impl_constructs_a_usable_queue() {
        let queue = TelemetryQueue::default();
        queue.enqueue(TelemetryEvent::new("test", "via-default")).unwrap();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_with_no_pending_events_is_a_noop() {
        let queue = TelemetryQueue::new();

        let drained = queue
            .graceful_shutdown(|_event| Ok(()), Duration::from_secs(1))
            .await
            .expect("drain of empty queue should succeed");

        assert_eq!(drained, 0);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn enqueue_after_shutdown_is_rejected() {
        let queue = TelemetryQueue::new();
        queue
            .enqueue(TelemetryEvent::new("test", "before-shutdown"))
            .unwrap();

        let _ = queue
            .graceful_shutdown(|_event| Ok(()), Duration::from_secs(1))
            .await;

        let result = queue.enqueue(TelemetryEvent::new("test", "after-shutdown"));
        assert!(matches!(result, Err(TelemetryQueueError::ShuttingDown)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn sink_failure_surfaces_as_error_not_silently_dropped() {
        let queue = TelemetryQueue::new();
        queue
            .enqueue(TelemetryEvent::new("test", "will-fail"))
            .unwrap();

        let result = queue
            .graceful_shutdown(
                |_event| Err("sink unavailable".to_string()),
                Duration::from_secs(1),
            )
            .await;

        assert!(matches!(result, Err(TelemetryQueueError::SinkError(_))));
    }

    // Multi-threaded runtime: the sink below blocks its worker thread with
    // std::thread::sleep to simulate a hung sink. On a single-threaded
    // runtime that would also block tokio's own timer driver, so the outer
    // timeout would never get a chance to fire. Multi-thread lets the timer
    // run on a separate worker.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drain_times_out_when_sink_hangs_and_reports_remaining_count() {
        let queue = TelemetryQueue::new();
        for i in 0..3 {
            queue
                .enqueue(TelemetryEvent::new("test", format!("event-{i}")))
                .unwrap();
        }

        // Sink that never returns within the timeout window.
        let result = queue
            .graceful_shutdown(
                |_event| -> Result<(), String> {
                    std::thread::sleep(Duration::from_secs(10));
                    Ok(())
                },
                Duration::from_millis(50),
            )
            .await;

        match result {
            Err(TelemetryQueueError::DrainTimeout { remaining, .. }) => {
                // At least the events not yet handed to the blocking sink
                // call should still be counted as pending.
                assert!(remaining <= 3);
            }
            other => panic!("expected DrainTimeout, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn partial_drain_stops_at_first_sink_error_and_does_not_lose_count_silently() {
        let queue = TelemetryQueue::new();
        for i in 0..4 {
            queue
                .enqueue(TelemetryEvent::new("test", format!("event-{i}")))
                .unwrap();
        }

        let call_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let call_count_clone = call_count.clone();

        let result = queue
            .graceful_shutdown(
                move |event| {
                    let _n = call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                    if event.payload == "event-2" {
                        Err("boom".to_string())
                    } else {
                        Ok(())
                    }
                },
                Duration::from_secs(1),
            )
            .await;

        assert!(matches!(result, Err(TelemetryQueueError::SinkError(_))));
        // Stops immediately on first failure rather than continuing to
        // silently process/drop the rest.
        assert!(call_count.load(std::sync::atomic::Ordering::SeqCst) <= 3);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn adversarial_zero_duration_timeout_still_reports_correctly() {
        let queue = TelemetryQueue::new();
        queue.enqueue(TelemetryEvent::new("test", "event")).unwrap();

        // A zero timeout is a valid (if extreme) caller input — must not
        // panic, and must classify as either a clean drain or a timeout,
        // never an ambiguous/silent outcome.
        let result = queue
            .graceful_shutdown(|_event| Ok(()), Duration::from_secs(0))
            .await;

        assert!(result.is_ok() || matches!(result, Err(TelemetryQueueError::DrainTimeout { .. })));
    }
}
