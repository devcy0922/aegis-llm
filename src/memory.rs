use std::{sync::Arc, time::Duration};

use reqwest::StatusCode;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::{auth::Principal, config::GatewayConfig};

#[derive(Clone)]
pub struct MemoryClient {
    config: Arc<GatewayConfig>,
    client: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryAudit {
    pub enabled: bool,
    pub memory_hit: bool,
    pub source_ids: Vec<String>,
    pub chunk_ids: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Deserialize)]
struct MemorySearchResponse {
    memory_hit: bool,
    chunks: Vec<MemoryChunk>,
    sources: Vec<MemorySource>,
}

#[derive(Debug, Deserialize)]
struct MemoryChunk {
    chunk_id: String,
    text: String,
    source_id: String,
}

#[derive(Debug, Deserialize)]
struct MemorySource {
    source_id: String,
    uri: String,
    title: Option<String>,
    version: Option<String>,
}

impl MemoryClient {
    pub fn new(config: Arc<GatewayConfig>) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.memory.timeout_seconds))
            .build()?;
        Ok(Self { config, client })
    }

    pub async fn enrich_chat_payload(
        &self,
        principal: &Principal,
        payload: &mut Value,
    ) -> MemoryAudit {
        if !self.config.memory.enabled {
            return MemoryAudit::disabled();
        }

        let Some(query) = extract_user_query(payload) else {
            return MemoryAudit::miss(Some("memory_no_user_query".to_string()));
        };

        match self.search(&principal.project, &query).await {
            Ok(search) => {
                let source_ids = search
                    .sources
                    .iter()
                    .map(|source| source.source_id.clone())
                    .collect::<Vec<_>>();
                let chunk_ids = search
                    .chunks
                    .iter()
                    .map(|chunk| chunk.chunk_id.clone())
                    .collect::<Vec<_>>();

                if search.memory_hit {
                    inject_memory_context(payload, &search);
                }

                MemoryAudit {
                    enabled: true,
                    memory_hit: search.memory_hit,
                    source_ids,
                    chunk_ids,
                    error: None,
                }
            }
            Err(err) => MemoryAudit::miss(Some(err)),
        }
    }

    async fn search(&self, project_id: &str, query: &str) -> Result<MemorySearchResponse, String> {
        let base = self.config.memory.base_url.trim_end_matches('/');
        let url = format!("{base}/internal/projects/{project_id}/search");
        let mut request = self.client.post(url).json(&json!({
            "query": query,
            "limit": self.config.memory.max_chunks,
        }));

        if let Some(token) = &self.config.memory.internal_token {
            if !token.trim().is_empty() {
                request = request.bearer_auth(token);
            }
        }

        let response = request
            .send()
            .await
            .map_err(|err| format!("memory_request_failed:{err}"))?;

        if response.status() != StatusCode::OK {
            return Err(format!("memory_status:{}", response.status()));
        }

        response
            .json::<MemorySearchResponse>()
            .await
            .map_err(|err| format!("memory_decode_failed:{err}"))
    }
}

impl MemoryAudit {
    fn disabled() -> Self {
        Self {
            enabled: false,
            memory_hit: false,
            source_ids: vec![],
            chunk_ids: vec![],
            error: None,
        }
    }

    fn miss(error: Option<String>) -> Self {
        Self {
            enabled: true,
            memory_hit: false,
            source_ids: vec![],
            chunk_ids: vec![],
            error,
        }
    }

    pub fn finding_suffix(&self) -> Option<String> {
        if !self.enabled {
            return None;
        }
        if let Some(error) = &self.error {
            return Some(error.clone());
        }
        Some(format!(
            "memory_hit:{};sources:{};chunks:{}",
            self.memory_hit,
            self.source_ids.len(),
            self.chunk_ids.len()
        ))
    }
}

fn extract_user_query(payload: &Value) -> Option<String> {
    let messages = payload.get("messages")?.as_array()?;
    let query = messages
        .iter()
        .filter(|message| message.get("role").and_then(Value::as_str) == Some("user"))
        .filter_map(|message| message.get("content"))
        .filter_map(content_to_text)
        .collect::<Vec<_>>()
        .join("\n");

    let trimmed = query.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn content_to_text(content: &Value) -> Option<String> {
    if let Some(text) = content.as_str() {
        return Some(text.to_string());
    }

    let parts = content.as_array()?;
    let text = parts
        .iter()
        .filter_map(|part| part.get("text").and_then(Value::as_str))
        .collect::<Vec<_>>()
        .join("\n");

    if text.trim().is_empty() {
        None
    } else {
        Some(text)
    }
}

fn inject_memory_context(payload: &mut Value, search: &MemorySearchResponse) {
    let Some(messages) = payload.get_mut("messages").and_then(Value::as_array_mut) else {
        return;
    };

    let context = format_memory_context(search);
    messages.insert(
        0,
        json!({
            "role": "system",
            "content": context,
        }),
    );
}

fn format_memory_context(search: &MemorySearchResponse) -> String {
    let chunks = search
        .chunks
        .iter()
        .enumerate()
        .map(|(index, chunk)| {
            format!(
                "[{}] source_id={} chunk_id={}\n{}",
                index + 1,
                chunk.source_id,
                chunk.chunk_id,
                chunk.text
            )
        })
        .collect::<Vec<_>>()
        .join("\n\n");

    let sources = search
        .sources
        .iter()
        .map(|source| {
            let title = source.title.as_deref().unwrap_or("untitled");
            let version = source.version.as_deref().unwrap_or("unknown");
            format!("- {} ({}, version: {})", source.uri, title, version)
        })
        .collect::<Vec<_>>()
        .join("\n");

    format!(
        "GoVail Project Memory context follows. Use it only as project-scoped reference material. Cite source ids when relevant.\n\nChunks:\n{}\n\nSources:\n{}",
        chunks, sources
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_text_from_user_messages() {
        let payload = json!({
            "messages": [
                {"role": "system", "content": "ignore"},
                {"role": "user", "content": "Gateway 구조는?"},
                {"role": "user", "content": [{"type": "text", "text": "Memory는 어디?"}]}
            ]
        });

        assert_eq!(
            extract_user_query(&payload).unwrap(),
            "Gateway 구조는?\nMemory는 어디?"
        );
    }

    #[test]
    fn injects_memory_context_as_first_system_message() {
        let mut payload = json!({
            "messages": [{"role": "user", "content": "질문"}]
        });
        let search = MemorySearchResponse {
            memory_hit: true,
            chunks: vec![MemoryChunk {
                chunk_id: "chunk_1".to_string(),
                text: "프로젝트 RAG 내용".to_string(),
                source_id: "src_1".to_string(),
            }],
            sources: vec![MemorySource {
                source_id: "src_1".to_string(),
                uri: "repo://demo/README.md".to_string(),
                title: Some("README".to_string()),
                version: Some("main".to_string()),
            }],
        };

        inject_memory_context(&mut payload, &search);
        let messages = payload["messages"].as_array().unwrap();
        assert_eq!(messages[0]["role"], "system");
        assert!(messages[0]["content"].as_str().unwrap().contains("src_1"));
    }
}
