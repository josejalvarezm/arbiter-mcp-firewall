use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// A task descriptor submitted for policy evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Task {
    pub id: String,
    pub task_type: String,
    pub payload: serde_json::Value,
    pub submitted_at: DateTime<Utc>,
}

/// The result returned by an agent after executing a task.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaskResult {
    pub task_id: String,
    pub agent_id: String,
    pub status: TaskStatus,
    pub output: Option<String>,
    pub errors: Vec<String>,
    pub completed_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum TaskStatus {
    Success,
    Failed,
    Refused,
}

/// A decision log entry produced by the engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionLogEntry {
    pub timestamp: DateTime<Utc>,
    pub task_id: String,
    pub agent: String,
    pub rationale: String,
    pub outcome: Option<TaskStatus>,
}

/// An egress (server→client) audit entry logged by the firewall.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EgressLogEntry {
    pub timestamp: DateTime<Utc>,
    /// SHA-256 hex digest of the raw response content.
    pub content_hash: String,
    /// JSON-RPC `id` from the response, if parseable.
    pub request_id: Option<serde_json::Value>,
    /// Byte length of the raw response.
    pub size_bytes: usize,
}

/// Shadow-tier classification result logged by the async SetFit evaluator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShadowLogEntry {
    pub timestamp: DateTime<Utc>,
    /// The task ID that triggered the shadow evaluation.
    pub task_id: String,
    /// Label returned by the classifier ("safe" or a boundary category).
    pub label: String,
    /// Confidence score from the classifier (0.0–1.0).
    pub confidence: f64,
    /// Whether the classifier would have refused this request.
    pub would_refuse: bool,
    /// Classifier latency in milliseconds.
    pub latency_ms: f64,
}
