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

// ── M4 types ───────────────────────────────────────────────────────────────

/// MCP tool annotations from `tools/list` responses (MCP 2025-11-25).
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ToolAnnotations {
    /// If true, the tool may perform destructive operations (write/delete).
    #[serde(default)]
    pub destructive_hint: Option<bool>,
    /// If true, the tool only reads data and has no side effects.
    #[serde(default)]
    pub read_only_hint: Option<bool>,
    /// If true, the tool interacts with external/open-world systems.
    #[serde(default)]
    pub open_world_hint: Option<bool>,
}

/// A registered tool's metadata, captured from `tools/list` responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMeta {
    pub name: String,
    pub annotations: ToolAnnotations,
    /// JSON Schema for the tool's output, if declared.
    #[serde(default)]
    pub output_schema: Option<serde_json::Value>,
}

/// Content types for multi-modal MCP messages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ContentType {
    Text,
    Image,
    Audio,
    Resource,
}

/// A content block extracted from an MCP response (text, image, or audio).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContentBlock {
    pub content_type: ContentType,
    /// SHA-256 hex digest of the content (text bytes or binary data).
    pub content_hash: String,
    /// Byte length of the raw content.
    pub size_bytes: usize,
    /// MIME type for binary content (e.g. "image/png", "audio/wav").
    #[serde(default)]
    pub mime_type: Option<String>,
}

/// Audit entry for tool annotation inconsistency detection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnnotationInconsistencyEntry {
    pub timestamp: DateTime<Utc>,
    pub tool_name: String,
    pub declared_read_only: bool,
    pub observed_behavior: String,
    pub request_id: Option<serde_json::Value>,
}

/// Audit entry for schema validation results.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaViolationEntry {
    pub timestamp: DateTime<Utc>,
    pub tool_name: String,
    pub request_id: Option<serde_json::Value>,
    /// Description of the schema mismatch.
    pub violation: String,
}

/// Audit entry for elicitation interception.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ElicitationLogEntry {
    pub timestamp: DateTime<Utc>,
    pub request_id: Option<serde_json::Value>,
    /// The data type the server is requesting (e.g., "password", "email").
    pub requested_type: String,
    /// Whether the elicitation was allowed or blocked.
    pub allowed: bool,
    /// Reason for the decision.
    pub reason: String,
}

/// Audit entry for multi-modal content pass-through.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiModalLogEntry {
    pub timestamp: DateTime<Utc>,
    pub request_id: Option<serde_json::Value>,
    pub blocks: Vec<ContentBlock>,
    pub total_size_bytes: usize,
}
