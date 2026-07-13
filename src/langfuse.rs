use std::sync::Arc;

use chrono::{DateTime, Utc};
use regex::Regex;
use reqwest::Url;
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{auth::Principal, config::GatewayConfig};

#[derive(Clone)]
pub struct LangfuseClient {
    config: Arc<GatewayConfig>,
    client: reqwest::Client,
}

#[derive(Debug, Clone)]
pub struct LangfuseRecord {
    pub trace_id: String,
    pub name: String,
    pub project: String,
    pub user_id: String,
    pub model: Option<String>,
    pub input: Value,
    pub output: Option<Value>,
    pub usage: Option<TokenUsage>,
    pub start_time: DateTime<Utc>,
    pub end_time: DateTime<Utc>,
    pub status: String,
    pub finding: Option<String>,
    pub route_target: Option<String>,
    pub risk_level: Option<String>,
    pub workflow_type: Option<String>,
    pub decision_reason: Option<String>,
    pub approval_required: Option<bool>,
    pub risk_score: Option<f64>,
    pub route_confidence: Option<f64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct TokenUsage {
    pub input: Option<u64>,
    pub output: Option<u64>,
    pub total: Option<u64>,
}

impl LangfuseClient {
    pub fn new(config: Arc<GatewayConfig>) -> Self {
        Self {
            config,
            client: reqwest::Client::new(),
        }
    }

    pub fn enabled(&self) -> bool {
        self.config.langfuse.enabled
    }

    pub async fn record_generation(&self, principal: &Principal, record: LangfuseRecord) {
        if !self.enabled() {
            return;
        }

        let trace_id = record.trace_id.clone();
        let risk_score = record.risk_score;
        let route_confidence = record.route_confidence;
        let approval_required = record.approval_required;

        if let Err(err) = self.try_record_generation(principal, record).await {
            tracing::warn!(error = %err, "failed to export Langfuse generation");
        }

        // Router 점수(Score) 내보내기 수행
        if let Some(score) = risk_score {
            self.record_score(LangfuseScore {
                trace_id: trace_id.clone(),
                name: "risk_score".to_string(),
                value: score,
                comment: None,
            })
            .await;
        }
        if let Some(conf) = route_confidence {
            self.record_score(LangfuseScore {
                trace_id: trace_id.clone(),
                name: "route_confidence".to_string(),
                value: conf,
                comment: None,
            })
            .await;
        }
        if let Some(appr) = approval_required {
            self.record_score(LangfuseScore {
                trace_id: trace_id.clone(),
                name: "approval_status".to_string(),
                value: if appr { 0.5 } else { 1.0 }, // 0.5 = Awaiting, 1.0 = Allowed/No Risk
                comment: None,
            })
            .await;
        }
    }

    async fn try_record_generation(
        &self,
        principal: &Principal,
        record: LangfuseRecord,
    ) -> anyhow::Result<()> {
        let public_key = self
            .config
            .langfuse
            .public_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing Langfuse public key"))?;
        let secret_key = self
            .config
            .langfuse
            .secret_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing Langfuse secret key"))?;
        let url = ingestion_url(&self.config.langfuse.host)?;
        let generation_id = Uuid::new_v4().to_string();
        let input = self.capture_value(record.input);
        let output = record.output.map(|value| self.capture_value(value));

        let trace_body = json!({
            "id": record.trace_id,
            "name": record.name,
            "timestamp": record.start_time,
            "userId": record.user_id,
            "metadata": {
                "client_project": record.project.clone(),
                "key_hash": principal.key_hash,
                "role": principal.role,
                "status": record.status,
                "finding": record.finding,
                "capture": self.config.langfuse.capture,
                "route_target": record.route_target,
                "risk_level": record.risk_level,
                "workflow_type": record.workflow_type,
                "decision_reason": record.decision_reason,
                "approval_required": record.approval_required,
            }
        });

        let mut generation_body = json!({
            "id": generation_id,
            "traceId": record.trace_id,
            "name": record.name,
            "startTime": record.start_time,
            "endTime": record.end_time,
            "model": record.model,
            "input": input,
            "output": output,
            "metadata": {
                "client_project": record.project,
                "key_hash": principal.key_hash,
                "status": record.status,
                "finding": record.finding,
            }
        });

        if let Some(usage) = record.usage {
            generation_body["usage"] = serde_json::to_value(usage)?;
        }

        let body = json!({
            "batch": [
                {
                    "id": Uuid::new_v4().to_string(),
                    "type": "trace-create",
                    "timestamp": record.start_time,
                    "body": trace_body
                },
                {
                    "id": Uuid::new_v4().to_string(),
                    "type": "generation-create",
                    "timestamp": record.end_time,
                    "body": generation_body
                }
            ],
            "metadata": {
                "sdk_name": "aegis-gateway",
                "sdk_version": env!("CARGO_PKG_VERSION")
            }
        });

        self.client
            .post(url)
            .basic_auth(public_key, Some(secret_key))
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    fn capture_value(&self, value: Value) -> Value {
        if self.config.langfuse.capture == "metadata_only" {
            return json!({
                "redaction": "metadata_only",
                "value_type": value_type(&value),
            });
        }
        redact_value(value)
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LangfuseScore {
    pub trace_id: String,
    pub name: String,
    pub value: f64,
    pub comment: Option<String>,
}

impl LangfuseClient {
    pub async fn record_score(&self, score: LangfuseScore) {
        if !self.enabled() {
            return;
        }

        if let Err(err) = self.try_record_score(score).await {
            tracing::warn!(error = %err, "failed to export Langfuse score");
        }
    }

    async fn try_record_score(&self, score: LangfuseScore) -> anyhow::Result<()> {
        let public_key = self
            .config
            .langfuse
            .public_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing Langfuse public key"))?;
        let secret_key = self
            .config
            .langfuse
            .secret_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("missing Langfuse secret key"))?;
        let url = ingestion_url(&self.config.langfuse.host)?;
        let score_id = Uuid::new_v4().to_string();
        let now = Utc::now();

        let score_body = json!({
            "traceId": score.trace_id,
            "name": score.name,
            "value": score.value,
            "comment": score.comment,
        });

        let body = json!({
            "batch": [
                {
                    "id": score_id,
                    "type": "score-create",
                    "timestamp": now,
                    "body": score_body
                }
            ],
            "metadata": {
                "sdk_name": "aegis-gateway",
                "sdk_version": env!("CARGO_PKG_VERSION")
            }
        });

        self.client
            .post(url)
            .basic_auth(public_key, Some(secret_key))
            .json(&body)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }
}

pub fn extract_chat_output(value: &Value) -> Option<Value> {
    value
        .get("choices")
        .and_then(Value::as_array)
        .map(|choices| {
            Value::Array(
                choices
                    .iter()
                    .filter_map(|choice| {
                        choice
                            .get("message")
                            .or_else(|| choice.get("delta"))
                            .or_else(|| choice.get("text"))
                            .cloned()
                    })
                    .collect(),
            )
        })
        .filter(|items| items.as_array().is_some_and(|arr| !arr.is_empty()))
}

pub fn extract_embedding_output(value: &Value) -> Option<Value> {
    value
        .get("data")
        .and_then(Value::as_array)
        .map(|items| json!({ "embedding_count": items.len() }))
}

pub fn extract_usage(value: &Value) -> Option<TokenUsage> {
    let usage = value.get("usage")?;
    Some(TokenUsage {
        input: usage
            .get("prompt_tokens")
            .or_else(|| usage.get("input_tokens"))
            .and_then(Value::as_u64),
        output: usage
            .get("completion_tokens")
            .or_else(|| usage.get("output_tokens"))
            .and_then(Value::as_u64),
        total: usage.get("total_tokens").and_then(Value::as_u64),
    })
}

fn ingestion_url(host: &str) -> anyhow::Result<Url> {
    let base = host.trim_end_matches('/');
    Ok(Url::parse(&format!("{base}/api/public/ingestion"))?)
}

fn redact_value(value: Value) -> Value {
    match value {
        Value::String(text) => Value::String(redact_text(&text)),
        Value::Array(items) => Value::Array(items.into_iter().map(redact_value).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, value)| {
                    let redacted = if is_sensitive_key(&key) {
                        Value::String("[REDACTED]".to_string())
                    } else {
                        redact_value(value)
                    };
                    (key, redacted)
                })
                .collect(),
        ),
        other => other,
    }
}

fn redact_text(text: &str) -> String {
    let patterns = [
        r"ghp_[A-Za-z0-9_]{20,}",
        r"sk-[A-Za-z0-9_\-]{20,}",
        r"AKIA[0-9A-Z]{16}",
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----",
        r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}",
        r"\b\d{3}-\d{2}-\d{4}\b",
    ];

    patterns.iter().fold(text.to_string(), |acc, pattern| {
        Regex::new(pattern)
            .map(|regex| regex.replace_all(&acc, "[REDACTED]").to_string())
            .unwrap_or(acc)
    })
}

fn is_sensitive_key(key: &str) -> bool {
    let key = key.to_lowercase();
    [
        "authorization",
        "api_key",
        "apikey",
        "token",
        "password",
        "secret",
        "private_key",
    ]
    .iter()
    .any(|needle| key.contains(needle))
}

fn value_type(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "bool",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn redacts_secrets_and_pii_recursively() {
        let value = json!({
            "messages": [{"content": "mail me at admin@example.com with sk-abcdefghijklmnopqrstuvwxyz123456"}],
            "headers": {"authorization": "Bearer raw-token"}
        });

        let redacted = redact_value(value);
        let raw = redacted.to_string();
        assert!(!raw.contains("admin@example.com"));
        assert!(!raw.contains("sk-abcdefghijklmnopqrstuvwxyz123456"));
        assert!(!raw.contains("raw-token"));
        assert!(raw.contains("[REDACTED]"));
    }

    #[test]
    fn extracts_openai_usage() {
        let value = json!({
            "usage": {
                "prompt_tokens": 10,
                "completion_tokens": 3,
                "total_tokens": 13
            }
        });

        let usage = extract_usage(&value).unwrap();
        assert_eq!(usage.input, Some(10));
        assert_eq!(usage.output, Some(3));
        assert_eq!(usage.total, Some(13));
    }
}
