//! Async LLM runtime — OpenAI-compatible HTTP client and task executor.
//!
//! All I/O is async via Tokio + reqwest.

pub mod client;
pub mod executor;

/// Errors specific to the LLM runtime.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("LLM request failed: {0}")]
    RequestFailed(String),

    #[error("LLM returned no content")]
    EmptyResponse,

    #[error("LLM service unreachable at {url}: {reason}")]
    ServiceUnavailable { url: String, reason: String },

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),
}

pub type RuntimeResult<T> = std::result::Result<T, RuntimeError>;
