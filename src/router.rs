use std::{sync::Arc, time::Duration};

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{auth::Principal, config::GatewayConfig};

#[derive(Debug, Clone, Serialize)]
pub struct RoutingSummary {
    pub trace_id: String,
    pub project_id: String,
    pub client: Option<String>,
    pub route_mode: String,
    pub requested_model: Option<String>,
    pub user_intent_summary: String,
    pub task_signals: TaskSignals,
    pub requested_output: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct TaskSignals {
    pub mentions_repo: bool,
    pub mentions_write_or_execute: bool,
    pub mentions_deploy_or_ops: bool,
    pub mentions_security_review: bool,
    pub has_attached_diff: bool,
    pub estimated_scope: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct RouteDecision {
    pub route_target: String,
    pub model_slot: Option<String>,
    pub confidence: f32,
    pub route_confidence: f32,
    pub intent: String,
    pub risk_level: String,
    pub risk_score: f64,
    pub approval_required: bool,
    pub workflow_type: Option<String>,
    pub decision_source: String,
    pub reason_code: String,
    pub reason: String,
    pub rag_namespace: Option<String>,
}

#[derive(Clone)]
pub struct RouterClient {
    config: Arc<GatewayConfig>,
    client: reqwest::Client,
}

impl RouterClient {
    pub fn new(config: Arc<GatewayConfig>) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.router.timeout_ms))
            .build()?;
        Ok(Self { config, client })
    }

    pub async fn decide(&self, summary: &RoutingSummary) -> anyhow::Result<RouteDecision> {
        if let Some(ref client) = summary.client {
            if client.contains("mcp-client") {
                return Ok(RouteDecision {
                    route_target: "runtime".to_string(),
                    model_slot: Some("fast".to_string()),
                    confidence: 1.0,
                    route_confidence: 1.0,
                    intent: "pr_check".to_string(),
                    risk_level: "low".to_string(),
                    risk_score: 0.1,
                    approval_required: false,
                    workflow_type: Some("pr_create".to_string()),
                    decision_source: "mcp_client_rule".to_string(),
                    reason_code: "mcp_client_detected".to_string(),
                    reason: "MCP client signature detected in client header/payload".to_string(),
                    rag_namespace: Some(format!("rag-{}", summary.project_id)),
                });
            }
        }

        let response = self
            .client
            .post(&self.config.router.decide_url)
            .json(summary)
            .send()
            .await?;

        if !response.status().is_success() {
            anyhow::bail!("router returned HTTP {}", response.status());
        }

        Ok(response.json::<RouteDecision>().await?)
    }
}

pub fn should_call_router(config: &GatewayConfig, headers: &HeaderMap, payload: &Value) -> bool {
    if !config.router.enabled {
        return false;
    }

    let client = extract_client(headers, payload);
    if let Some(ref c) = client {
        if c.contains("mcp-client") {
            return true;
        }
    }

    let route_source = header_str(headers, "x-govail-route-source");
    if route_source.as_deref() == Some("runtime") {
        return false;
    }

    let route_target = header_str(headers, "x-govail-route-target");
    if route_target.as_deref() == Some("llm") {
        return false;
    }

    let route_mode = extract_route_mode(payload);
    route_mode != "llm"
}

pub fn hop_count(headers: &HeaderMap) -> u8 {
    header_str(headers, "x-govail-route-hop")
        .and_then(|value| value.parse::<u8>().ok())
        .unwrap_or(0)
}

pub fn build_summary(
    trace_id: &str,
    principal: &Principal,
    headers: &HeaderMap,
    payload: &Value,
    model: Option<String>,
) -> RoutingSummary {
    let last_user_message = last_user_message(payload);
    RoutingSummary {
        trace_id: trace_id.to_string(),
        project_id: principal.project.clone(),
        client: extract_client(headers, payload),
        route_mode: extract_route_mode(payload),
        requested_model: model,
        user_intent_summary: summarize_for_routing(&last_user_message),
        task_signals: detect_task_signals(&last_user_message, payload),
        requested_output: detect_requested_output(&last_user_message),
        session_id: payload
            .get("user")
            .and_then(|value| value.as_str())
            .map(ToString::to_string),
    }
}

pub fn fallback_decision(config: &GatewayConfig, reason: impl Into<String>) -> RouteDecision {
    let route_target = config.router.fallback.clone();
    let approval_required = route_target == "runtime";
    RouteDecision {
        route_target,
        model_slot: Some("fast".to_string()),
        confidence: 0.0,
        route_confidence: 0.0,
        intent: "unknown".to_string(),
        risk_level: "unknown".to_string(),
        risk_score: 0.3,
        approval_required,
        workflow_type: None,
        decision_source: "fallback".to_string(),
        reason_code: "router_unavailable".to_string(),
        reason: reason.into(),
        rag_namespace: None,
    }
}

pub fn apply_model_slot(payload: &mut Value, decision: &RouteDecision) {
    let Some(model_slot) = decision.model_slot.as_deref() else {
        return;
    };
    if model_slot == "auto" {
        return;
    }

    let requested_model = payload
        .get("model")
        .and_then(|value| value.as_str())
        .unwrap_or("auto");

    if requested_model == "auto" {
        if let Some(obj) = payload.as_object_mut() {
            obj.insert("model".to_string(), Value::String(model_slot.to_string()));
        }
    }
}

pub fn decision_finding(decision: &RouteDecision) -> String {
    format!(
        "route_decision:{}:{}:{}:{:.2}",
        decision.route_target,
        decision.model_slot.as_deref().unwrap_or("none"),
        decision.reason_code,
        decision.confidence
    )
}

fn extract_route_mode(payload: &Value) -> String {
    payload
        .get("metadata")
        .and_then(|metadata| metadata.get("govail"))
        .and_then(|govail| govail.get("route_mode"))
        .and_then(|value| value.as_str())
        .or_else(|| payload.get("route_mode").and_then(|value| value.as_str()))
        .unwrap_or("auto")
        .to_string()
}

fn extract_client(headers: &HeaderMap, payload: &Value) -> Option<String> {
    header_str(headers, "x-govail-client")
        .or_else(|| {
            payload
                .get("metadata")
                .and_then(|m| m.get("client"))
                .and_then(|c| c.as_str())
                .map(ToString::to_string)
        })
        .or_else(|| header_str(headers, "user-agent"))
}

fn header_str(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
}

fn last_user_message(payload: &Value) -> String {
    let Some(messages) = payload.get("messages").and_then(|value| value.as_array()) else {
        return String::new();
    };

    for message in messages.iter().rev() {
        if message.get("role").and_then(|value| value.as_str()) != Some("user") {
            continue;
        }

        let Some(content) = message.get("content") else {
            continue;
        };

        if let Some(text) = content.as_str() {
            return text.to_string();
        }

        if let Some(parts) = content.as_array() {
            let text = parts
                .iter()
                .filter_map(|part| part.get("text").and_then(|value| value.as_str()))
                .collect::<Vec<_>>()
                .join(" ");
            if !text.is_empty() {
                return text;
            }
        }
    }

    String::new()
}

fn summarize_for_routing(text: &str) -> String {
    const MAX_CHARS: usize = 800;
    let normalized = text.split_whitespace().collect::<Vec<_>>().join(" ");
    normalized.chars().take(MAX_CHARS).collect()
}

fn detect_task_signals(text: &str, payload: &Value) -> TaskSignals {
    let lower = text.to_lowercase();
    let has_diff_marker = lower.contains("diff --git")
        || lower.contains("@@")
        || lower.contains("pull request")
        || lower.contains("pr ");

    TaskSignals {
        mentions_repo: contains_any(
            &lower,
            &["repo", "repository", "workspace", "전체", "저장소", "레포"],
        ),
        mentions_write_or_execute: contains_any(
            &lower,
            &[
                "write", "edit", "modify", "commit", "push", "구현", "수정", "커밋", "실행",
            ],
        ),
        mentions_deploy_or_ops: contains_any(
            &lower,
            &[
                "deploy",
                "release",
                "docker",
                "server",
                "배포",
                "운영",
                "서버",
                "인프라",
            ],
        ),
        mentions_security_review: contains_any(
            &lower,
            &[
                "security",
                "secret",
                "dlp",
                "policy",
                "vulnerability",
                "보안",
                "시크릿",
                "취약점",
                "정책",
            ],
        ),
        has_attached_diff: has_diff_marker
            || payload.get("diff").is_some()
            || payload.get("files").is_some(),
        estimated_scope: if contains_any(
            &lower,
            &["전체", "workspace", "repo", "repository", "레포"],
        ) {
            "repo_or_workspace".to_string()
        } else if has_diff_marker {
            "diff_or_pr".to_string()
        } else {
            "single_prompt".to_string()
        },
    }
}

fn detect_requested_output(text: &str) -> Option<String> {
    let lower = text.to_lowercase();
    if contains_any(&lower, &["review", "검토", "리뷰"]) {
        Some("review".to_string())
    } else if contains_any(&lower, &["summary", "요약", "브리핑"]) {
        Some("summary".to_string())
    } else if contains_any(&lower, &["plan", "계획", "설계"]) {
        Some("plan".to_string())
    } else {
        None
    }
}

fn contains_any(text: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| text.contains(needle))
}
