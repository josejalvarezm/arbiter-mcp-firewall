use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::boundary::PolicyBoundary;

/// The compiled contract manifest — single source of truth produced by the compiler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContractManifest {
    pub version: String,
    pub compiled_at: DateTime<Utc>,
    pub global: GlobalContract,
    pub agents: HashMap<String, AgentContract>,
    #[serde(default)]
    pub boundaries: Vec<PolicyBoundary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalContract {
    pub rules: Vec<String>,
    pub constraints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentContract {
    pub id: String,
    pub version: u32,
    pub rules: Vec<String>,
    pub constraints: Vec<String>,
    pub capabilities: Vec<String>,
}
