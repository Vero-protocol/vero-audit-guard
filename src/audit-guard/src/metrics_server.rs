use crate::error::TelemetryError;
use crate::telemetry::gather_metrics;
use axum::{routing::get, Router};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{error, info};

async fn metrics_handler() -> String {
    match gather_metrics() {
        Ok(metrics) => metrics,
        Err(e) => {
            error!("Failed to gather metrics: {}", e);
            format!("Error: {}", e)
        }
    }
}

pub async fn start_metrics_server(port: u16) -> Result<(), TelemetryError> {
    let app = Router::new().route("/metrics", get(metrics_handler));
    let addr = SocketAddr::from(([0, 0, 0, 0], port));

    let listener = TcpListener::bind(addr).await?;
    info!("Metrics server listening on {}", addr);

    axum::serve(listener, app)
        .await
        .map_err(TelemetryError::ServerError)
}
