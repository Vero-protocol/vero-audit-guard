use crate::error::TelemetryError;
use lazy_static::lazy_static;
use prometheus::{Encoder, Gauge, IntCounter, IntGauge, Registry, TextEncoder};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    // Observe queue depth
    pub static ref QUEUE_DEPTH: IntGauge = IntGauge::new(
        "queue_depth",
        "Current number of items in the processing queue"
    ).expect("metric can be created");

    // Observe confirmation rate (e.g. number of confirmations)
    pub static ref CONFIRMATION_RATE: IntCounter = IntCounter::new(
        "confirmation_rate_total",
        "Total number of confirmations processed"
    ).expect("metric can be created");

    // Observe write latency
    pub static ref WRITE_LATENCY_MS: Gauge = Gauge::new(
        "write_latency_ms",
        "Write latency in milliseconds"
    ).expect("metric can be created");

    // Observe reload status (1 for reloading, 0 for idle/ready)
    pub static ref RELOAD_STATUS: IntGauge = IntGauge::new(
        "reload_status",
        "Current reload status (1 = reloading, 0 = ready)"
    ).expect("metric can be created");
}

pub fn init_telemetry() -> Result<(), TelemetryError> {
    // Structured logging with tracing
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));

    let subscriber = tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer().json()); // structured JSON logging

    // We ignore errors if the global logger was already set
    let _ = subscriber.try_init();

    // Register metrics
    // Ignore errors if metrics are already registered (e.g. during multiple test runs)
    let _ = REGISTRY.register(Box::new(QUEUE_DEPTH.clone()));
    let _ = REGISTRY.register(Box::new(CONFIRMATION_RATE.clone()));
    let _ = REGISTRY.register(Box::new(WRITE_LATENCY_MS.clone()));
    let _ = REGISTRY.register(Box::new(RELOAD_STATUS.clone()));

    Ok(())
}

pub fn gather_metrics() -> Result<String, TelemetryError> {
    let mut buffer = vec![];
    let encoder = TextEncoder::new();
    let metric_families = REGISTRY.gather();
    encoder.encode(&metric_families, &mut buffer)?;

    String::from_utf8(buffer)
        .map_err(|e| TelemetryError::ExportError(format!("Invalid UTF-8 in metrics output: {}", e)))
}
