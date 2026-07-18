use axum::{http::StatusCode, routing::get, Json, Router};
use serde::Serialize;
use std::net::SocketAddr;
use tokio::net::TcpListener;

use crate::{error::HealthError, health::is_ready};

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
}

/// Liveness endpoint: returns 200 OK as long as the server is running.
async fn live_handler() -> (StatusCode, Json<HealthResponse>) {
    (StatusCode::OK, Json(HealthResponse { status: "alive" }))
}

/// Readiness endpoint: returns 200 OK if fully healthy, 503 Service Unavailable if degraded.
async fn ready_handler() -> (StatusCode, Json<HealthResponse>) {
    if is_ready() {
        (StatusCode::OK, Json(HealthResponse { status: "ready" }))
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(HealthResponse { status: "degraded" }),
        )
    }
}

/// Start the health check HTTP server on the given port.
pub async fn start_health_server(port: u16) -> Result<(), HealthError> {
    let app = Router::new()
        .route("/healthz/live", get(live_handler))
        .route("/healthz/ready", get(ready_handler));

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    axum::serve(listener, app)
        .await
        .map_err(HealthError::ServerError)
}
