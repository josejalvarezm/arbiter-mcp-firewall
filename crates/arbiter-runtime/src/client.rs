//! Async OpenAI-compatible HTTP client.

use crate::{RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};
use tracing::instrument;

/// Configuration for the LLM client.
#[derive(Debug, Clone)]
pub struct LlmClientConfig {
    pub base_url: String,
    pub chat_model: String,
    pub embedding_model: Option<String>,
    pub max_tokens: u32,
    pub temperature: f32,
}

impl Default for LlmClientConfig {
    fn default() -> Self {
        LlmClientConfig {
            base_url: "http://localhost:1234/v1".to_string(),
            chat_model: "default".to_string(),
            embedding_model: Some("text-embedding-nomic-embed-text-v1.5".to_string()),
            max_tokens: 512,
            temperature: 0.0,
        }
    }
}

// --- Request/Response types (OpenAI-compatible) ---

#[derive(Debug, Serialize)]
struct ChatRequest {
    model: String,
    messages: Vec<ChatMessage>,
    max_tokens: u32,
    temperature: f32,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_format: Option<ResponseFormat>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ResponseFormat {
    #[serde(rename = "type")]
    format_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChatMessage {
    pub role: String,
    pub content: String,
}

#[derive(Debug, Deserialize)]
struct ChatResponse {
    choices: Vec<ChatChoice>,
    usage: Option<Usage>,
}

#[derive(Debug, Deserialize)]
struct ChatChoice {
    message: ChatResponseMessage,
}

#[derive(Debug, Deserialize)]
struct ChatResponseMessage {
    content: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Usage {
    prompt_tokens: u32,
    completion_tokens: u32,
    total_tokens: u32,
}

#[derive(Debug, Serialize)]
struct EmbeddingRequest {
    model: String,
    input: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct EmbeddingResponse {
    data: Vec<EmbeddingData>,
}

#[derive(Debug, Deserialize)]
struct EmbeddingData {
    embedding: Vec<f32>,
}

/// The result of a chat completion call.
#[derive(Debug, Clone)]
pub struct ChatCompletion {
    pub content: String,
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub total_tokens: u32,
}

/// Async HTTP client for OpenAI-compatible APIs.
pub struct LlmClient {
    config: LlmClientConfig,
    http: reqwest::Client,
}

impl LlmClient {
    pub fn new(config: LlmClientConfig) -> RuntimeResult<Self> {
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| RuntimeError::RequestFailed(format!("Failed to build HTTP client: {e}")))?;

        Ok(LlmClient { config, http })
    }

    pub fn default_local() -> RuntimeResult<Self> {
        Self::new(LlmClientConfig::default())
    }

    /// Check if the LLM service is reachable.
    #[instrument(skip(self))]
    pub async fn health_check(&self) -> RuntimeResult<Vec<String>> {
        let url = format!("{}/models", self.config.base_url);
        let resp: serde_json::Value = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| RuntimeError::ServiceUnavailable {
                url: url.clone(),
                reason: e.to_string(),
            })?
            .json()
            .await
            .map_err(|e| RuntimeError::RequestFailed(e.to_string()))?;

        let models: Vec<String> = resp["data"]
            .as_array()
            .unwrap_or(&vec![])
            .iter()
            .filter_map(|m| m["id"].as_str().map(String::from))
            .collect();

        Ok(models)
    }

    /// Send a chat completion request.
    #[instrument(skip(self, system_prompt, user_message))]
    pub async fn chat(
        &self,
        system_prompt: &str,
        user_message: &str,
    ) -> RuntimeResult<ChatCompletion> {
        self.chat_internal(system_prompt, user_message, None).await
    }

    /// Send a chat completion with JSON response format enforced.
    pub async fn chat_json(
        &self,
        system_prompt: &str,
        user_message: &str,
    ) -> RuntimeResult<ChatCompletion> {
        self.chat_internal(
            system_prompt,
            user_message,
            Some(ResponseFormat {
                format_type: "json_object".to_string(),
            }),
        )
        .await
    }

    /// Compute embeddings for a list of texts.
    #[instrument(skip(self, texts))]
    pub async fn embed(&self, texts: &[&str]) -> RuntimeResult<Vec<Vec<f32>>> {
        let model = self.config.embedding_model.as_deref().unwrap_or("default");
        let url = format!("{}/embeddings", self.config.base_url);

        let request = EmbeddingRequest {
            model: model.to_string(),
            input: texts.iter().map(|t| t.to_string()).collect(),
        };

        let resp: EmbeddingResponse = self
            .http
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RuntimeError::ServiceUnavailable {
                url: url.clone(),
                reason: e.to_string(),
            })?
            .json()
            .await
            .map_err(|e| RuntimeError::RequestFailed(e.to_string()))?;

        Ok(resp.data.into_iter().map(|d| d.embedding).collect())
    }

    async fn chat_internal(
        &self,
        system_prompt: &str,
        user_message: &str,
        response_format: Option<ResponseFormat>,
    ) -> RuntimeResult<ChatCompletion> {
        let url = format!("{}/chat/completions", self.config.base_url);

        let request = ChatRequest {
            model: self.config.chat_model.clone(),
            messages: vec![
                ChatMessage {
                    role: "system".to_string(),
                    content: system_prompt.to_string(),
                },
                ChatMessage {
                    role: "user".to_string(),
                    content: user_message.to_string(),
                },
            ],
            max_tokens: self.config.max_tokens,
            temperature: self.config.temperature,
            response_format,
        };

        let resp: ChatResponse = self
            .http
            .post(&url)
            .json(&request)
            .send()
            .await
            .map_err(|e| RuntimeError::ServiceUnavailable {
                url: url.clone(),
                reason: e.to_string(),
            })?
            .json()
            .await
            .map_err(|e| RuntimeError::RequestFailed(e.to_string()))?;

        let content = resp
            .choices
            .first()
            .and_then(|c| c.message.content.clone())
            .unwrap_or_default();

        if content.trim().is_empty() {
            return Err(RuntimeError::EmptyResponse);
        }

        let usage = resp.usage.unwrap_or(Usage {
            prompt_tokens: 0,
            completion_tokens: 0,
            total_tokens: 0,
        });

        Ok(ChatCompletion {
            content,
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
            total_tokens: usage.total_tokens,
        })
    }
}
