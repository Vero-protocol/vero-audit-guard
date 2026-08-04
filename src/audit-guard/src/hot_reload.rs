use notify::{Event, EventKind, RecursiveMode, Watcher};
use std::path::{Path, PathBuf};
use thiserror::Error;
use log::{error, info, warn};
use tokio::sync::mpsc;

/// Errors that can occur during policy hot-reloading operations.
#[derive(Error, Debug)]
pub enum HotReloadError {
    #[error("Failed to initialize or update watcher: {0}")]
    WatchError(#[from] notify::Error),
    #[error("Target policy path does not exist: {0}")]
    PathNotFound(PathBuf),
    #[error("Invalid or adversarial path detected: {0}")]
    InvalidPath(PathBuf),
}

/// Monitors policy files for changes and safely propagates events without process termination.
/// Operates strictly in an observational context.
pub struct PolicyWatcher {
    path: PathBuf,
}

impl PolicyWatcher {
    /// Creates a new `PolicyWatcher`.
    /// Validates the path exists to prevent silent startup failures.
    pub fn new<P: AsRef<Path>>(path: P) -> Result<Self, HotReloadError> {
        let path_buf = path.as_ref().to_path_buf();
        
        // Adversarial path checking (simple directory traversal prevention check)
        if path_buf.to_string_lossy().contains("..") {
            error!("Telemetry Alert: Adversarial path sequence detected: {:?}", path_buf);
            return Err(HotReloadError::InvalidPath(path_buf));
        }

        if !path_buf.exists() {
            error!("Telemetry Alert: Policy path not found: {:?}", path_buf);
            return Err(HotReloadError::PathNotFound(path_buf));
        }

        Ok(Self { path: path_buf })
    }

    /// Spawns a background task to watch the configured policy path.
    /// Emits `notify::Event` instances over an MPSC channel for downstream processing.
    pub fn watch(&self) -> Result<mpsc::Receiver<Event>, HotReloadError> {
        let (tx, rx) = mpsc::channel(100);
        let path = self.path.clone();

        tokio::spawn(async move {
            let (watcher_tx, mut watcher_rx) = mpsc::unbounded_channel();
            
            // Standard closure for notify
            let mut watcher = match notify::recommended_watcher(move |res: notify::Result<Event>| {
                match res {
                    Ok(event) => {
                        let _ = watcher_tx.send(event);
                    }
                    Err(e) => {
                        error!("Telemetry Alert: File watcher encountered an error: {}", e);
                    }
                }
            }) {
                Ok(w) => w,
                Err(e) => {
                    error!("Telemetry Alert: Failed to create recommended_watcher: {}", e);
                    return;
                }
            };

            if let Err(e) = watcher.watch(&path, RecursiveMode::Recursive) {
                error!("Telemetry Alert: Failed to watch policy path {:?}: {}", path, e);
                return;
            }

            info!("Observational policy hot-reload watcher started on {:?}", path);

            while let Some(event) = watcher_rx.recv().await {
                // Filter to only meaningful policy modification events
                if matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                ) {
                    info!("Policy change detected at paths: {:?}", event.paths);
                    if tx.send(event).await.is_err() {
                        warn!("Policy watcher downstream channel dropped. Terminating watcher.");
                        break;
                    }
                }
            }
        });

        Ok(rx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_valid_path_initialization() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("policy.json");
        fs::write(&file_path, "{}").unwrap();

        let watcher = PolicyWatcher::new(&file_path);
        assert!(watcher.is_ok());
    }

    #[test]
    fn test_invalid_path_initialization() {
        let watcher = PolicyWatcher::new("/does/not/exist/12345");
        assert!(matches!(watcher, Err(HotReloadError::PathNotFound(_))));
    }

    #[test]
    fn test_adversarial_path_traversal() {
        let watcher = PolicyWatcher::new("/var/policies/../../etc/passwd");
        assert!(matches!(watcher, Err(HotReloadError::InvalidPath(_))));
    }

    #[tokio::test]
    async fn test_watch_event_propagation() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("policy.json");
        fs::write(&file_path, "{}").unwrap();

        let watcher = PolicyWatcher::new(&file_path).unwrap();
        let mut rx = watcher.watch().unwrap();

        // Allow the watcher task to initialize
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Simulate an external edit to the policy file
        fs::write(&file_path, "{\"updated\": true}").unwrap();

        // Allow some time for the filesystem event to propagate
        let event = tokio::time::timeout(std::time::Duration::from_secs(2), rx.recv())
            .await
            .expect("Timeout waiting for notify event")
            .expect("Channel closed unexpectedly");

        assert!(event.paths.contains(&file_path));
    }
}
