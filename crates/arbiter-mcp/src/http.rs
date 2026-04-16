//! HTTP transport for the Arbiter MCP Firewall.
//!
//! Implements MCP Streamable HTTP transport (2025-11-25) with:
//! - Session management (`Mcp-Session-Id` header)
//! - Bearer token authorization
//! - Origin allowlist (DNS rebinding defense)
//! - Per-session rate limiting (token bucket)
//! - Localhost-only binding by default

use anyhow::{Context, Result};
use axum::body::Body;
use axum::extract::State;
use axum::http::header::{AUTHORIZATION, CONTENT_TYPE, ORIGIN};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::firewall::{evaluate_message, EvaluateResult};
use crate::Interceptor;

// ── Configuration ──────────────────────────────────────────────────────────

/// Configuration for the HTTP transport.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpConfig {
    /// Host to bind to. Default: "127.0.0.1" (localhost only).
    #[serde(default = "default_host")]
    pub host: String,
    /// Port to listen on. Default: 8080.
    #[serde(default = "default_port")]
    pub port: u16,
    /// Bearer token for authorization. All requests must include this.
    pub auth_token: String,
    /// Allowed Origin headers. Empty = reject all cross-origin requests.
    #[serde(default)]
    pub allowed_origins: Vec<String>,
    /// Maximum requests per session per minute. Default: 60.
    #[serde(default = "default_rate_limit")]
    pub rate_limit_per_minute: u32,
}

fn default_host() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    8080
}
fn default_rate_limit() -> u32 {
    60
}

// ── Session State ──────────────────────────────────────────────────────────

/// Session lifecycle states per MCP spec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionState {
    /// Session created, awaiting initialize.
    Created,
    /// Initialize received, fully active.
    Active,
    /// Session terminated.
    Closed,
}

/// Per-session state tracked by the server.
#[derive(Debug, Clone)]
pub struct Session {
    pub state: SessionState,
    /// Token bucket: remaining tokens for rate limiting.
    pub tokens: u32,
    /// Last token refill timestamp.
    pub last_refill: std::time::Instant,
}

// ── Shared Server State ────────────────────────────────────────────────────

/// Shared state accessible by all request handlers.
#[derive(Clone)]
pub struct AppState {
    pub interceptor: Interceptor,
    pub config: HttpConfig,
    pub sessions: Arc<Mutex<HashMap<String, Session>>>,
}

// ── Middleware: Authorization ───────────────────────────────────────────────

async fn auth_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Allow .well-known endpoints without auth
    if request.uri().path().starts_with("/.well-known/") {
        return Ok(next.run(request).await);
    }

    let auth_header = headers
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let expected = format!("Bearer {}", state.config.auth_token);
    if auth_header != expected {
        warn!("unauthorized request: invalid or missing Bearer token");
        return Err(StatusCode::UNAUTHORIZED);
    }

    Ok(next.run(request).await)
}

// ── Middleware: Origin Validation ───────────────────────────────────────────

async fn origin_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    if let Some(origin) = headers.get(ORIGIN).and_then(|v| v.to_str().ok()) {
        if !state.config.allowed_origins.iter().any(|o| o == origin) {
            warn!(origin = %origin, "rejected: origin not in allowlist");
            return Err(StatusCode::FORBIDDEN);
        }
    }
    // No Origin header = same-origin request, allowed.
    Ok(next.run(request).await)
}

// ── Middleware: Rate Limiting ───────────────────────────────────────────────

async fn rate_limit_middleware(
    State(state): State<AppState>,
    headers: HeaderMap,
    request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Rate limit only applies to sessions
    if let Some(session_id) = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
    {
        let mut sessions = state.sessions.lock().await;
        if let Some(session) = sessions.get_mut(session_id) {
            // Refill tokens based on elapsed time
            let elapsed = session.last_refill.elapsed().as_secs_f64();
            let refill = (elapsed * state.config.rate_limit_per_minute as f64 / 60.0) as u32;
            if refill > 0 {
                session.tokens =
                    (session.tokens + refill).min(state.config.rate_limit_per_minute);
                session.last_refill = std::time::Instant::now();
            }

            if session.tokens == 0 {
                warn!(session_id = %session_id, "rate limit exceeded");
                return Err(StatusCode::TOO_MANY_REQUESTS);
            }
            session.tokens -= 1;
        }
    }

    Ok(next.run(request).await)
}

// ── Route Handlers ─────────────────────────────────────────────────────────

/// POST /mcp — Main MCP JSON-RPC endpoint.
async fn mcp_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Parse the JSON-RPC request to check for initialize
    let is_initialize = serde_json::from_str::<serde_json::Value>(&body)
        .ok()
        .and_then(|v| v.get("method")?.as_str().map(|s| s.to_string()))
        .as_deref()
        == Some("initialize");

    // Session management
    let response_session_id = if is_initialize {
        // Create new session
        let new_id = uuid::Uuid::new_v4().to_string();
        let session = Session {
            state: SessionState::Active,
            tokens: state.config.rate_limit_per_minute,
            last_refill: std::time::Instant::now(),
        };
        state.sessions.lock().await.insert(new_id.clone(), session);
        info!(session_id = %new_id, "session created");
        Some(new_id)
    } else if let Some(ref sid) = session_id {
        // Validate existing session
        let sessions = state.sessions.lock().await;
        match sessions.get(sid) {
            Some(s) if s.state == SessionState::Active => Some(sid.clone()),
            Some(s) if s.state == SessionState::Closed => {
                return (StatusCode::GONE, "Session closed").into_response();
            }
            _ => {
                return (StatusCode::NOT_FOUND, "Unknown session").into_response();
            }
        }
    } else if !is_initialize {
        // Non-initialize request without session ID
        return (StatusCode::BAD_REQUEST, "Missing Mcp-Session-Id header").into_response();
    } else {
        None
    };

    // Evaluate the message through the interceptor
    match evaluate_message(&state.interceptor, &body).await {
        Ok(EvaluateResult::Forward {
            original_message: _,
            tool_name,
            agent_id,
        }) => {
            let result = serde_json::json!({
                "jsonrpc": "2.0",
                "id": serde_json::from_str::<serde_json::Value>(&body)
                    .ok()
                    .and_then(|v| v.get("id").cloned())
                    .unwrap_or(serde_json::Value::Null),
                "result": {
                    "status": "forwarded",
                    "tool_name": tool_name,
                    "agent_id": agent_id,
                }
            });

            let mut response = (StatusCode::OK, Json(result)).into_response();
            if let Some(sid) = response_session_id {
                response
                    .headers_mut()
                    .insert("mcp-session-id", sid.parse().unwrap());
            }
            response.headers_mut().insert(
                "mcp-protocol-version",
                "2025-11-25".parse().unwrap(),
            );
            response
        }
        Ok(EvaluateResult::Block { response_json }) => {
            let mut response = (
                StatusCode::OK,
                [(CONTENT_TYPE, "application/json")],
                response_json,
            )
                .into_response();
            if let Some(sid) = response_session_id {
                response
                    .headers_mut()
                    .insert("mcp-session-id", sid.parse().unwrap());
            }
            response.headers_mut().insert(
                "mcp-protocol-version",
                "2025-11-25".parse().unwrap(),
            );
            response
        }
        Err(e) => {
            warn!("interceptor error: {e}");
            let error_body = serde_json::json!({
                "jsonrpc": "2.0",
                "id": null,
                "error": {
                    "code": -32603,
                    "message": format!("Internal error: {e}")
                }
            });
            (StatusCode::INTERNAL_SERVER_ERROR, Json(error_body)).into_response()
        }
    }
}

/// DELETE /mcp — Session termination.
async fn mcp_delete_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let session_id = headers
        .get("mcp-session-id")
        .and_then(|v| v.to_str().ok());

    match session_id {
        Some(sid) => {
            let mut sessions = state.sessions.lock().await;
            if let Some(session) = sessions.get_mut(sid) {
                session.state = SessionState::Closed;
                info!(session_id = %sid, "session closed");
                StatusCode::OK
            } else {
                StatusCode::NOT_FOUND
            }
        }
        None => StatusCode::BAD_REQUEST,
    }
}

/// GET /.well-known/oauth-protected-resource — RFC 9728 Resource Metadata.
async fn well_known_handler() -> impl IntoResponse {
    let metadata = serde_json::json!({
        "resource": "arbiter-mcp-firewall",
        "authorization_servers": [],
        "bearer_methods_supported": ["header"],
        "scopes_supported": ["mcp:read", "mcp:write", "mcp:admin"],
    });
    (StatusCode::OK, Json(metadata))
}

/// GET /health — Health check endpoint.
async fn health_handler() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({"status": "ok"})))
}

// ── Server Builder ─────────────────────────────────────────────────────────

/// Build the axum router with all middleware and routes.
pub fn build_router(interceptor: Interceptor, config: HttpConfig) -> Router {
    let state = AppState {
        interceptor,
        config: config.clone(),
        sessions: Arc::new(Mutex::new(HashMap::new())),
    };

    Router::new()
        .route("/mcp", post(mcp_handler).delete(mcp_delete_handler))
        .route("/.well-known/oauth-protected-resource", get(well_known_handler))
        .route("/health", get(health_handler))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            rate_limit_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            origin_middleware,
        ))
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth_middleware,
        ))
        .with_state(state)
}

/// Start the HTTP server.
///
/// Binds to `config.host:config.port`. If `config.host` is not `127.0.0.1`
/// or `::1`, a warning is emitted (network exposure).
pub async fn serve(interceptor: Interceptor, config: HttpConfig) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", config.host, config.port)
        .parse()
        .context("parsing bind address")?;

    if !addr.ip().is_loopback() {
        warn!(
            addr = %addr,
            "binding to non-loopback address — ensure TLS is configured"
        );
    }

    info!(addr = %addr, "HTTP transport listening");

    let router = build_router(interceptor, config);
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .context("binding TCP listener")?;
    axum::serve(listener, router)
        .await
        .context("HTTP server error")?;

    Ok(())
}
