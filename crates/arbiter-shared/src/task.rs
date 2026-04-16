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
