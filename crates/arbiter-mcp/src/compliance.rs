//! M4: Full MCP 2025-11-25 compliance module.
//!
//! Provides:
//! - Tool annotation tracking and destructive-tool policy enforcement
//! - Output schema validation
//! - Multi-modal content hashing and size enforcement
//! - Elicitation interception

use anyhow::{Context, Result};
use arbiter_shared::task::{
    AnnotationInconsistencyEntry, ContentBlock, ContentType, ElicitationLogEntry,
    MultiModalLogEntry, SchemaViolationEntry, ToolAnnotations, ToolMeta,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex;

// ── Tool Registry (M4.1) ──────────────────────────────────────────────────

/// Tracks tool metadata from `tools/list` responses.
#[derive(Debug, Clone)]
pub struct ToolRegistry {
    tools: Arc<Mutex<HashMap<String, ToolMeta>>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self {
            tools: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Ingest a `tools/list` response and register all tool metadata.
    pub async fn ingest_tools_list(&self, response: &serde_json::Value) -> Result<()> {
        let tools_array = response
            .get("result")
            .and_then(|r| r.get("tools"))
            .and_then(|t| t.as_array())
            .context("missing result.tools array in tools/list response")?;

        let mut registry = self.tools.lock().await;
        for tool in tools_array {
            let name = tool
                .get("name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }

            let annotations = tool
                .get("annotations")
                .map(|a| serde_json::from_value::<ToolAnnotations>(a.clone()).unwrap_or_default())
                .unwrap_or_default();

            let output_schema = tool
                .get("outputSchema")
                .cloned();

            registry.insert(
                name.clone(),
                ToolMeta {
                    name,
                    annotations,
                    output_schema,
                },
            );
        }
        Ok(())
    }

    /// Check if a tool is declared as destructive.
    pub async fn is_destructive(&self, tool_name: &str) -> Option<bool> {
        let registry = self.tools.lock().await;
        registry
            .get(tool_name)
            .and_then(|t| t.annotations.destructive_hint)
    }

    /// Check if a tool is declared as read-only.
    pub async fn is_read_only(&self, tool_name: &str) -> Option<bool> {
        let registry = self.tools.lock().await;
        registry
            .get(tool_name)
            .and_then(|t| t.annotations.read_only_hint)
    }

    /// Get the output schema for a tool, if declared.
    pub async fn output_schema(&self, tool_name: &str) -> Option<serde_json::Value> {
        let registry = self.tools.lock().await;
        registry
            .get(tool_name)
            .and_then(|t| t.output_schema.clone())
    }

    /// Get all registered tool names.
    pub async fn tool_names(&self) -> Vec<String> {
        let registry = self.tools.lock().await;
        registry.keys().cloned().collect()
    }
}

// ── Destructive Tool Policy (M4.1) ────────────────────────────────────────

/// Check whether a destructive tool call should be allowed.
///
/// Returns `Err` with reason if the tool is destructive and not in the allowlist.
pub fn check_destructive_policy(
    tool_name: &str,
    is_destructive: Option<bool>,
    allowlist: &[String],
) -> Result<(), String> {
    if is_destructive == Some(true) && !allowlist.iter().any(|a| a == tool_name) {
        return Err(format!(
            "Tool '{tool_name}' is marked destructive but not in the manifest destructive_allowlist"
        ));
    }
    Ok(())
}

// ── Output Schema Validation (M4.2) ───────────────────────────────────────

/// Validate a tool response against its declared output schema.
///
/// Returns a list of violations (empty = valid). Uses structural validation:
/// - Checks `type` matches
/// - Checks `required` properties are present
/// - Checks `properties` key names exist
///
/// This is intentionally a lightweight validator (not a full JSON Schema engine)
/// to avoid pulling in a large dependency.
pub fn validate_output_schema(
    response_result: &serde_json::Value,
    schema: &serde_json::Value,
) -> Vec<String> {
    let mut violations = Vec::new();

    // Check top-level type
    if let Some(expected_type) = schema.get("type").and_then(|t| t.as_str()) {
        let actual_type = json_type_name(response_result);
        if actual_type != expected_type {
            violations.push(format!(
                "expected type '{expected_type}', got '{actual_type}'"
            ));
            return violations; // type mismatch makes further checks meaningless
        }
    }

    // For objects: check required properties and property types
    if response_result.is_object() {
        if let Some(required) = schema.get("required").and_then(|r| r.as_array()) {
            for req in required {
                if let Some(prop_name) = req.as_str() {
                    if response_result.get(prop_name).is_none() {
                        violations.push(format!("missing required property '{prop_name}'"));
                    }
                }
            }
        }

        if let Some(properties) = schema.get("properties").and_then(|p| p.as_object()) {
            for (prop_name, prop_schema) in properties {
                if let Some(prop_value) = response_result.get(prop_name) {
                    if let Some(expected_type) = prop_schema.get("type").and_then(|t| t.as_str()) {
                        let actual_type = json_type_name(prop_value);
                        if actual_type != expected_type {
                            violations.push(format!(
                                "property '{prop_name}': expected type '{expected_type}', got '{actual_type}'"
                            ));
                        }
                    }
                }
            }
        }
    }

    violations
}

fn json_type_name(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Build a `SchemaViolationEntry` from validation results.
pub fn build_schema_violation(
    tool_name: &str,
    request_id: Option<serde_json::Value>,
    violations: &[String],
) -> SchemaViolationEntry {
    SchemaViolationEntry {
        timestamp: Utc::now(),
        tool_name: tool_name.to_string(),
        request_id,
        violation: violations.join("; "),
    }
}

// ── Multi-Modal Content (M4.3) ────────────────────────────────────────────

/// Extract content blocks from an MCP response's `result.content` array.
///
/// Hashes each block and enforces the binary size limit.
/// Returns `(blocks, total_size)` for audit logging.
pub fn extract_content_blocks(
    response: &serde_json::Value,
    max_binary_size: usize,
) -> Result<(Vec<ContentBlock>, usize), String> {
    let content_array = match response
        .get("result")
        .and_then(|r| r.get("content"))
        .and_then(|c| c.as_array())
    {
        Some(arr) => arr,
        None => return Ok((Vec::new(), 0)),
    };

    let mut blocks = Vec::new();
    let mut total_size = 0usize;

    for item in content_array {
        let type_str = item
            .get("type")
            .and_then(|t| t.as_str())
            .unwrap_or("text");

        let (content_type, data_bytes, mime_type) = match type_str {
            "text" => {
                let text = item.get("text").and_then(|t| t.as_str()).unwrap_or("");
                (ContentType::Text, text.as_bytes().to_vec(), None)
            }
            "image" => {
                let data = item.get("data").and_then(|d| d.as_str()).unwrap_or("");
                let mime = item
                    .get("mimeType")
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string());
                let decoded = base64_decode(data);
                (ContentType::Image, decoded, mime)
            }
            "audio" => {
                let data = item.get("data").and_then(|d| d.as_str()).unwrap_or("");
                let mime = item
                    .get("mimeType")
                    .and_then(|m| m.as_str())
                    .map(|s| s.to_string());
                let decoded = base64_decode(data);
                (ContentType::Audio, decoded, mime)
            }
            "resource" => {
                let text = item
                    .get("resource")
                    .and_then(|r| r.get("text"))
                    .and_then(|t| t.as_str())
                    .unwrap_or("");
                (ContentType::Resource, text.as_bytes().to_vec(), None)
            }
            _ => {
                // Unknown content type — hash the raw JSON
                let raw = serde_json::to_string(item).unwrap_or_default();
                (ContentType::Text, raw.into_bytes(), None)
            }
        };

        let size = data_bytes.len();
        total_size += size;

        // Enforce binary size limit
        if matches!(content_type, ContentType::Image | ContentType::Audio)
            && size > max_binary_size
        {
            return Err(format!(
                "binary content exceeds max size: {size} > {max_binary_size} bytes"
            ));
        }

        let content_hash = format!("{:x}", Sha256::new().chain_update(&data_bytes).finalize());

        blocks.push(ContentBlock {
            content_type,
            content_hash,
            size_bytes: size,
            mime_type,
        });
    }

    Ok((blocks, total_size))
}

/// Build a `MultiModalLogEntry` from extracted content blocks.
pub fn build_multimodal_entry(
    request_id: Option<serde_json::Value>,
    blocks: Vec<ContentBlock>,
    total_size: usize,
) -> MultiModalLogEntry {
    MultiModalLogEntry {
        timestamp: Utc::now(),
        request_id,
        blocks,
        total_size_bytes: total_size,
    }
}

/// Minimal base64 decoder (avoids adding a `base64` crate dependency).
/// Tolerant of whitespace and padding.
fn base64_decode(input: &str) -> Vec<u8> {
    let table: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;
    let mut out = Vec::with_capacity(input.len() * 3 / 4);

    for &b in input.as_bytes() {
        let val = match table.iter().position(|&c| c == b) {
            Some(v) => v as u32,
            None => continue, // skip whitespace, padding, etc.
        };
        buf = (buf << 6) | val;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    out
}

// ── Elicitation Interception (M4.4) ───────────────────────────────────────

/// Check whether an elicitation request should be allowed.
///
/// Examines the `requestedSchema` or `message` of an `elicitation/create` request
/// to determine if the server is requesting blocked data types.
pub fn check_elicitation(
    params: &serde_json::Value,
    blocked_types: &[String],
) -> ElicitationLogEntry {
    let message = params
        .get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("");

    let requested_schema = params
        .get("requestedSchema")
        .and_then(|s| s.as_object());

    // Collect the field names and types from the schema
    let mut requested_type = String::new();
    if let Some(schema) = requested_schema {
        if let Some(props) = schema.get("properties").and_then(|p| p.as_object()) {
            let field_names: Vec<&str> = props.keys().map(|k| k.as_str()).collect();
            requested_type = field_names.join(", ");
        }
    }
    if requested_type.is_empty() {
        requested_type = message.to_string();
    }

    // Check against blocked types (case-insensitive substring match)
    let lower_type = requested_type.to_lowercase();
    let lower_msg = message.to_lowercase();

    let blocked = blocked_types.iter().any(|bt| {
        let bt_lower = bt.to_lowercase();
        lower_type.contains(&bt_lower) || lower_msg.contains(&bt_lower)
    });

    let reason = if blocked {
        format!("elicitation blocked: requested type matches blocked pattern")
    } else {
        "elicitation allowed".to_string()
    };

    ElicitationLogEntry {
        timestamp: Utc::now(),
        request_id: params.get("id").cloned(),
        requested_type,
        allowed: !blocked,
        reason,
    }
}

/// Build annotation inconsistency entry.
pub fn build_inconsistency_entry(
    tool_name: &str,
    declared_read_only: bool,
    observed_behavior: &str,
    request_id: Option<serde_json::Value>,
) -> AnnotationInconsistencyEntry {
    AnnotationInconsistencyEntry {
        timestamp: Utc::now(),
        tool_name: tool_name.to_string(),
        declared_read_only,
        observed_behavior: observed_behavior.to_string(),
        request_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_tool_blocked_without_allowlist() {
        let result = check_destructive_policy("rm_file", Some(true), &[]);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("destructive"));
    }

    #[test]
    fn destructive_tool_allowed_with_allowlist() {
        let allowlist = vec!["rm_file".to_string()];
        let result = check_destructive_policy("rm_file", Some(true), &allowlist);
        assert!(result.is_ok());
    }

    #[test]
    fn non_destructive_tool_always_passes() {
        let result = check_destructive_policy("read_file", Some(false), &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn unknown_annotations_pass() {
        let result = check_destructive_policy("unknown_tool", None, &[]);
        assert!(result.is_ok());
    }

    #[test]
    fn schema_validation_type_mismatch() {
        let schema = serde_json::json!({"type": "object"});
        let response = serde_json::json!("a string");
        let violations = validate_output_schema(&response, &schema);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("expected type 'object'"));
    }

    #[test]
    fn schema_validation_missing_required() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["name", "age"],
            "properties": {
                "name": {"type": "string"},
                "age": {"type": "number"}
            }
        });
        let response = serde_json::json!({"name": "Alice"});
        let violations = validate_output_schema(&response, &schema);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("age"));
    }

    #[test]
    fn schema_validation_property_type_mismatch() {
        let schema = serde_json::json!({
            "type": "object",
            "properties": {
                "count": {"type": "number"}
            }
        });
        let response = serde_json::json!({"count": "not a number"});
        let violations = validate_output_schema(&response, &schema);
        assert_eq!(violations.len(), 1);
        assert!(violations[0].contains("count"));
    }

    #[test]
    fn schema_validation_valid_response() {
        let schema = serde_json::json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"},
                "count": {"type": "number"}
            }
        });
        let response = serde_json::json!({"name": "test", "count": 42});
        let violations = validate_output_schema(&response, &schema);
        assert!(violations.is_empty());
    }

    #[test]
    fn multimodal_text_content() {
        let response = serde_json::json!({
            "result": {
                "content": [
                    {"type": "text", "text": "Hello, world!"}
                ]
            }
        });
        let (blocks, total) = extract_content_blocks(&response, 10 * 1024 * 1024).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].content_type, ContentType::Text);
        assert_eq!(blocks[0].size_bytes, 13);
        assert_eq!(total, 13);
    }

    #[test]
    fn multimodal_binary_size_limit() {
        // Create a response with a large "image" (base64 of many bytes)
        let large_data = "AAAA".repeat(1000); // ~3000 decoded bytes
        let response = serde_json::json!({
            "result": {
                "content": [
                    {"type": "image", "data": large_data, "mimeType": "image/png"}
                ]
            }
        });
        let result = extract_content_blocks(&response, 100); // limit = 100 bytes
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("exceeds max size"));
    }

    #[test]
    fn elicitation_blocked_for_password() {
        let params = serde_json::json!({
            "message": "Please enter your password",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "password": {"type": "string"}
                }
            }
        });
        let blocked = vec!["password".to_string()];
        let entry = check_elicitation(&params, &blocked);
        assert!(!entry.allowed);
    }

    #[test]
    fn elicitation_allowed_for_name() {
        let params = serde_json::json!({
            "message": "What is your name?",
            "requestedSchema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string"}
                }
            }
        });
        let blocked = vec!["password".to_string(), "secret".to_string()];
        let entry = check_elicitation(&params, &blocked);
        assert!(entry.allowed);
    }

    #[tokio::test]
    async fn tool_registry_ingests_tools_list() {
        let registry = ToolRegistry::new();
        let response = serde_json::json!({
            "result": {
                "tools": [
                    {
                        "name": "write_file",
                        "annotations": {
                            "destructive_hint": true,
                            "read_only_hint": false
                        },
                        "outputSchema": {
                            "type": "object",
                            "properties": {"path": {"type": "string"}}
                        }
                    },
                    {
                        "name": "read_file",
                        "annotations": {
                            "read_only_hint": true
                        }
                    }
                ]
            }
        });

        registry.ingest_tools_list(&response).await.unwrap();
        assert_eq!(registry.is_destructive("write_file").await, Some(true));
        assert_eq!(registry.is_read_only("read_file").await, Some(true));
        assert!(registry.output_schema("write_file").await.is_some());
        assert!(registry.output_schema("read_file").await.is_none());
    }

    #[test]
    fn base64_decode_works() {
        let decoded = base64_decode("SGVsbG8=");
        assert_eq!(decoded, b"Hello");
    }
}
