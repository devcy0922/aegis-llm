use std::time::Instant;

use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, Utc};
use clap::Parser;
use futures_util::TryStreamExt;
use aegis_llm::{
    audit::AuditEvent,
    auth::{self, Principal},
    config::GatewayConfig,
    langfuse::{self, LangfuseRecord},
    model_policy, router as route_router,
    security::{extract_model, scan_chat_payload},
    AppState,
};
use serde_json::{json, Value};
use tower_http::{cors::CorsLayer, trace::TraceLayer};
use tracing::{error, info};
use uuid::Uuid;

#[derive(Debug, Parser)]
struct Args {
    #[arg(
        long,
        env = "GOVAIL_CONFIG",
        default_value = "configs/gateway.example.toml"
    )]
    config: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            std::env::var("RUST_LOG")
                .unwrap_or_else(|_| "aegis_llm=info,tower_http=info".to_string()),
        )
        .init();

    let args = Args::parse();
    let config = GatewayConfig::load(&args.config).await?;
    let bind = config.server.bind;
    let state = AppState::new(config)?;
    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(bind).await?;

    info!(%bind, "Govail Gateway listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/v1/models", get(models))
        .route("/v1/chat/completions", post(chat_completions))
        .route("/v1/responses", post(responses))
        .route("/responses", post(responses))
        .route("/v1/embeddings", post(embeddings))
        .route("/v1/scores", post(submit_score))
        // ── [NEW] Runtime API 프록시 라우트 ──
        .route("/api/jobs", post(proxy_to_runtime))
        .route(
            "/api/jobs/*path",
            get(proxy_to_runtime).post(proxy_to_runtime),
        )
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

async fn health() -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "service": "govail-gateway"
    }))
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4")],
        state.metrics.render_prometheus(),
    )
}

async fn models(state: State<AppState>, headers: HeaderMap) -> Result<Response, Response> {
    let _trace_id = headers
        .get("X-GoVail-Trace-Id")
        .or_else(|| headers.get("x-trace-id"))
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let principal = auth::authenticate(state.clone(), headers)
        .await
        .map_err(IntoResponse::into_response)?;
    state.metrics.record_request();

    match state.proxy.proxy_models(&_trace_id).await {
        Ok(response) => Ok(response),
        Err(err) => {
            state.metrics.record_upstream_error();
            Err((
                err.status(),
                Json(json!({ "error": err.message(), "key_id": principal.key_id })),
            )
                .into_response())
        }
    }
}

struct AuditGuard {
    state: AppState,
    principal: Principal,
    trace_id: String,
    model: Option<String>,
    route: String,
    memory_audit: Option<aegis_llm::memory::MemoryAudit>,
    started: Instant,
    completed: bool,
}

impl AuditGuard {
    fn new(
        state: AppState,
        principal: Principal,
        trace_id: String,
        model: Option<String>,
        route: String,
        started: Instant,
    ) -> Self {
        Self {
            state,
            principal,
            trace_id,
            model,
            route,
            memory_audit: None,
            started,
            completed: false,
        }
    }

    fn complete(&mut self) {
        self.completed = true;
    }
}

impl Drop for AuditGuard {
    fn drop(&mut self) {
        if !self.completed {
            let event = AuditEvent {
                ts: Utc::now(),
                trace_id: self.trace_id.clone(),
                key_id: self.principal.key_id.clone(),
                key_hash: self.principal.key_hash.clone(),
                project: self.principal.project.clone(),
                model: self.model.clone(),
                route: self.route.clone(),
                status: "client_disconnected".to_string(),
                finding: Some("connection_reset_by_client".to_string()),
                memory: self.memory_audit.clone(),
                latency_ms: self.started.elapsed().as_millis(),
                request: None,
                response: None,
            };

            let logger = self.state.audit.clone();
            tokio::spawn(async move {
                if let Err(err) = logger.append(&event).await {
                    error!(error = %err, "failed to append audit event on drop");
                }
            });
        }
    }
}

async fn chat_completions(
    state: State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Response, Response> {
    let started = Instant::now();
    let wall_started = Utc::now();
    let trace_id = headers
        .get("X-GoVail-Trace-Id")
        .or_else(|| headers.get("x-trace-id"))
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let principal = auth::authenticate(state.clone(), headers.clone())
        .await
        .map_err(IntoResponse::into_response)?;
    state.metrics.record_request();

    let mut payload = payload;
    if state.config.security.redact_pii {
        aegis_llm::security::redact_pii_in_value(&mut payload);
    }

    let mut model = extract_model(&payload).map(ToString::to_string);

    // AuditGuard 생성
    let mut audit_guard = AuditGuard::new(
        (*state).clone(),
        principal.clone(),
        trace_id.clone(),
        model.clone(),
        "litellm".to_string(),
        started,
    );

    if let Some(model) = &model {
        if !principal.can_use_model(model) {
            state.metrics.record_blocked();
            record_langfuse(
                &state,
                &principal,
                LangfuseInput {
                    trace_id: &trace_id,
                    name: "chat_completions",
                    model: Some(model.clone()),
                    input: payload.clone(),
                    output: None,
                    usage: None,
                    start_time: wall_started,
                    end_time: Utc::now(),
                    status: "blocked",
                    finding: Some("model_not_allowed".to_string()),
                    decision: None,
                },
            )
            .await;
            audit(
                &state,
                &principal,
                AuditInput {
                    trace_id: &trace_id,
                    model: model.clone().into(),
                    route: "policy",
                    status: "blocked",
                    finding: Some("model_not_allowed".to_string()),
                    memory: None,
                    latency_ms: started.elapsed().as_millis(),
                },
            )
            .await;
            audit_guard.complete();
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "model is not allowed for this API key",
                    "model": model,
                    "trace_id": trace_id
                })),
            )
                .into_response());
        }
    }

    let findings = scan_chat_payload(
        &payload,
        state.config.security.max_prompt_chars,
        state.config.security.deny_prompt_injection,
        state.config.security.deny_secret_patterns,
        state.config.security.deny_patterns.as_deref(),
    );

    if let Some(finding) = findings.first() {
        state.metrics.record_blocked();
        let finding_text = format!("{}:{}", finding.kind, finding.detail);
        record_langfuse(
            &state,
            &principal,
            LangfuseInput {
                trace_id: &trace_id,
                name: "chat_completions",
                model: model.clone(),
                input: payload.clone(),
                output: None,
                usage: None,
                start_time: wall_started,
                end_time: Utc::now(),
                status: "blocked",
                finding: Some(finding_text.clone()),
                decision: None,
            },
        )
        .await;
        audit(
            &state,
            &principal,
            AuditInput {
                trace_id: &trace_id,
                model: model.clone(),
                route: "security",
                status: "blocked",
                finding: Some(finding_text),
                memory: None,
                latency_ms: started.elapsed().as_millis(),
            },
        )
        .await;
        audit_guard.complete();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "request blocked by security policy",
                "finding": {
                    "kind": finding.kind,
                    "detail": finding.detail
                },
                "trace_id": trace_id
            })),
        )
            .into_response());
    }

    if route_router::hop_count(&headers) > state.config.router.max_hops {
        state.metrics.record_blocked();
        audit(
            &state,
            &principal,
            AuditInput {
                trace_id: &trace_id,
                model: model.clone(),
                route: "router",
                status: "blocked",
                finding: Some("route_hop_limit_exceeded".to_string()),
                memory: None,
                latency_ms: started.elapsed().as_millis(),
            },
        )
        .await;
        audit_guard.complete();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "route hop limit exceeded",
                "trace_id": trace_id
            })),
        )
            .into_response());
    }

    let mut router_decision: Option<crate::route_router::RouteDecision> = None;

    if route_router::should_call_router(&state.config, &headers, &payload) {
        let summary =
            route_router::build_summary(&trace_id, &principal, &headers, &payload, model.clone());
        let decision = match state.router.decide(&summary).await {
            Ok(decision) => decision,
            Err(err) => route_router::fallback_decision(
                &state.config,
                format!("router decision failed: {err}"),
            ),
        };
        let decision_finding = route_router::decision_finding(&decision);

        audit(
            &state,
            &principal,
            AuditInput {
                trace_id: &trace_id,
                model: model.clone(),
                route: "router",
                status: decision.route_target.as_str(),
                finding: Some(decision_finding.clone()),
                memory: None,
                latency_ms: started.elapsed().as_millis(),
            },
        )
        .await;

        router_decision = Some(decision.clone());

        // GOVAIL_BLOCK_ON_RISK 정책 분기
        let block_on_risk = state.config.security.block_on_risk;
        if block_on_risk && decision.approval_required {
            state.metrics.record_blocked();

            // Langfuse에 차단 기록 Export
            let langfuse_record = LangfuseRecord {
                trace_id: trace_id.clone(),
                name: "chat_completion".to_string(),
                project: principal.project.clone(),
                user_id: principal.key_id.clone(),
                model: model.clone(),
                input: payload.clone(),
                output: Some(json!({
                    "error": {
                        "message": "Access blocked due to security risk. Approval required.",
                        "code": "approval_required"
                    }
                })),
                usage: None,
                start_time: wall_started,
                end_time: Utc::now(),
                status: "blocked".to_string(),
                finding: Some(format!("blocked:{}", decision.reason_code)),
                route_target: Some(decision.route_target.clone()),
                risk_level: Some(decision.risk_level.clone()),
                workflow_type: decision.workflow_type.clone(),
                decision_reason: Some(decision.reason.clone()),
                approval_required: Some(decision.approval_required),
                risk_score: Some(decision.risk_score),
                route_confidence: Some(decision.route_confidence as f64),
            };
            state
                .langfuse
                .record_generation(&principal, langfuse_record)
                .await;

            audit_guard.complete();

            let approval_id = format!("appr-{}", &trace_id[..8]);
            let approval_url = format!("http://govail-dashboard/approvals/{}", approval_id);
            return Err((
                StatusCode::CONFLICT,
                Json(json!({
                    "error": {
                        "message": "Access blocked due to security risk. Request approval if this is a false positive.",
                        "code": "approval_required",
                        "approval_id": approval_id,
                        "approval_url": approval_url
                    }
                })),
            )
                .into_response());
        }

        route_router::apply_model_slot(&mut payload, &decision);
        model = extract_model(&payload).map(ToString::to_string);
    }

    // ── 모델 Capability 기반 파라미터 Strip ──────────────────────────
    let model_name_str = model.as_deref().unwrap_or("unknown");
    let cap = model_policy::resolve_capability(&state.config, model_name_str);
    let stripped_params = model_policy::strip_unsupported_params(&mut payload, cap);
    // ── thinking 비활성화 extra_body 주입 ────────────────────────────
    // thinking_supported=false인 모델(fast, overfit-checker 등)에 대해
    // LiteLLM extra_body.chat_template_kwargs.enable_thinking=false를 자동 삽입합니다.
    model_policy::inject_extra_body(&mut payload, cap);
    let memory_audit = state
        .memory
        .enrich_chat_payload(&principal, &mut payload)
        .await;

    // AuditGuard의 memory_audit 필드 업데이트
    audit_guard.memory_audit = Some(memory_audit.clone());

    if is_streaming_request(&payload) {
        let mut redacted_request = Some(payload.clone());
        if let Some(ref mut req) = redacted_request {
            aegis_llm::security::redact_pii_in_value(req);
        }
        let audit_event = AuditEvent {
            ts: Utc::now(),
            trace_id: trace_id.clone(),
            key_id: principal.key_id.clone(),
            key_hash: principal.key_hash.clone(),
            project: principal.project.clone(),
            model: model.clone(),
            route: "litellm".to_string(),
            status: "proxied_stream".to_string(),
            finding: None,
            memory: Some(memory_audit.clone()),
            latency_ms: 0,
            request: redacted_request,
            response: None,
        };
        let langfuse_record = if state.langfuse.enabled() {
            Some(crate::langfuse::LangfuseRecord {
                trace_id: trace_id.clone(),
                name: format!("chat_completions:{}", model.as_deref().unwrap_or("unknown")),
                project: principal.project.clone(),
                user_id: principal.key_id.clone(),
                model: model.clone(),
                input: payload.clone(),
                output: None,
                usage: None,
                start_time: wall_started,
                end_time: Utc::now(),
                status: "proxied_stream".to_string(),
                finding: None,
                route_target: router_decision.as_ref().map(|d| d.route_target.clone()),
                risk_level: router_decision.as_ref().map(|d| d.risk_level.clone()),
                workflow_type: router_decision
                    .as_ref()
                    .and_then(|d| d.workflow_type.clone()),
                decision_reason: router_decision.as_ref().map(|d| d.reason.clone()),
                approval_required: router_decision.as_ref().map(|d| d.approval_required),
                risk_score: router_decision.as_ref().map(|d| d.risk_score),
                route_confidence: router_decision.as_ref().map(|d| d.route_confidence as f64),
            })
        } else {
            None
        };

        return match state
            .proxy
            .proxy_chat(
                payload.clone(),
                Some((state.audit.clone(), audit_event)),
                &trace_id,
                Some(state.langfuse.clone()),
                Some(principal.clone()),
                langfuse_record,
            )
            .await
        {
            Ok(response) => {
                let finding = combine_findings(
                    if stripped_params.is_empty() {
                        None
                    } else {
                        Some(format!("param_stripped:{}", stripped_params.join(",")))
                    },
                    memory_audit.finding_suffix(),
                );
                audit(
                    &state,
                    &principal,
                    AuditInput {
                        trace_id: &trace_id,
                        model,
                        route: "litellm",
                        status: "proxied_stream",
                        finding,
                        memory: Some(memory_audit),
                        latency_ms: started.elapsed().as_millis(),
                    },
                )
                .await;
                audit_guard.complete();
                Ok(response)
            }
            Err(err) => {
                state.metrics.record_upstream_error();
                audit_with_payload(
                    &state,
                    &principal,
                    AuditInput {
                        trace_id: &trace_id,
                        model,
                        route: "litellm",
                        status: "upstream_error",
                        finding: Some(err.message()),
                        memory: Some(memory_audit),
                        latency_ms: started.elapsed().as_millis(),
                    },
                    Some(payload),
                    None,
                )
                .await;
                audit_guard.complete();
                Err((
                    err.status(),
                    Json(json!({ "error": "upstream unavailable", "trace_id": trace_id })),
                )
                    .into_response())
            }
        };
    }

    let langfuse_input = payload.clone();
    match state
        .proxy
        .proxy_chat_buffered(payload, &trace_id, Some(principal.clone()))
        .await
    {
        Ok(response) => {
            let finding = combine_findings(
                if stripped_params.is_empty() {
                    None
                } else {
                    Some(format!("param_stripped:{}", stripped_params.join(",")))
                },
                memory_audit.finding_suffix(),
            );
            let response_json = response.json();
            let status = if response.status().is_success() {
                "proxied"
            } else {
                "upstream_error"
            };
            record_langfuse(
                &state,
                &principal,
                LangfuseInput {
                    trace_id: &trace_id,
                    name: "chat_completions",
                    model: model.clone(),
                    input: langfuse_input.clone(),
                    output: response_json
                        .as_ref()
                        .and_then(langfuse::extract_chat_output)
                        .or_else(|| response_json.clone()),
                    usage: response_json.as_ref().and_then(langfuse::extract_usage),
                    start_time: wall_started,
                    end_time: Utc::now(),
                    status,
                    finding: finding.clone(),
                    decision: router_decision.clone(),
                },
            )
            .await;
            audit_with_payload(
                &state,
                &principal,
                AuditInput {
                    trace_id: &trace_id,
                    model,
                    route: "litellm",
                    status,
                    finding,
                    memory: Some(memory_audit),
                    latency_ms: started.elapsed().as_millis(),
                },
                Some(langfuse_input),
                response_json,
            )
            .await;
            audit_guard.complete();
            response.into_response().map_err(|err| {
                (
                    err.status(),
                    Json(json!({ "error": "failed to build upstream response", "trace_id": trace_id })),
                )
                    .into_response()
            })
        }
        Err(err) => {
            state.metrics.record_upstream_error();
            audit_with_payload(
                &state,
                &principal,
                AuditInput {
                    trace_id: &trace_id,
                    model,
                    route: "litellm",
                    status: "upstream_error",
                    finding: Some(err.message()),
                    memory: Some(memory_audit),
                    latency_ms: started.elapsed().as_millis(),
                },
                Some(langfuse_input),
                None,
            )
            .await;
            audit_guard.complete();
            Err((
                err.status(),
                Json(json!({ "error": "upstream unavailable", "trace_id": trace_id })),
            )
                .into_response())
        }
    }
}

async fn responses(
    state: State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<aegis_llm::responses_adapter::ResponsesRequest>,
) -> Result<Response, Response> {
    let started = Instant::now();
    let wall_started = Utc::now();
    let trace_id = headers
        .get("X-GoVail-Trace-Id")
        .or_else(|| headers.get("x-trace-id"))
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let principal = auth::authenticate(state.clone(), headers)
        .await
        .map_err(IntoResponse::into_response)?;
    state.metrics.record_request();

    let mut completions_payload =
        aegis_llm::responses_adapter::convert_request_to_completions(payload.clone());

    if state.config.security.redact_pii {
        aegis_llm::security::redact_pii_in_value(&mut completions_payload);
    }

    let model = extract_model(&completions_payload).map(ToString::to_string);

    // AuditGuard 생성
    let mut audit_guard = AuditGuard::new(
        (*state).clone(),
        principal.clone(),
        trace_id.clone(),
        model.clone(),
        "litellm".to_string(),
        started,
    );

    if let Some(ref model) = model {
        if !principal.can_use_model(model) {
            state.metrics.record_blocked();
            record_langfuse(
                &state,
                &principal,
                LangfuseInput {
                    trace_id: &trace_id,
                    name: "responses",
                    model: Some(model.clone()),
                    input: completions_payload.clone(),
                    output: None,
                    usage: None,
                    start_time: wall_started,
                    end_time: Utc::now(),
                    status: "blocked",
                    finding: Some("model_not_allowed".to_string()),
                    decision: None,
                },
            )
            .await;
            audit(
                &state,
                &principal,
                AuditInput {
                    trace_id: &trace_id,
                    model: model.clone().into(),
                    route: "policy",
                    status: "blocked",
                    finding: Some("model_not_allowed".to_string()),
                    memory: None,
                    latency_ms: started.elapsed().as_millis(),
                },
            )
            .await;
            audit_guard.complete();
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "model is not allowed for this API key",
                    "model": model,
                    "trace_id": trace_id
                })),
            )
                .into_response());
        }
    }

    let findings = scan_chat_payload(
        &completions_payload,
        state.config.security.max_prompt_chars,
        state.config.security.deny_prompt_injection,
        state.config.security.deny_secret_patterns,
        state.config.security.deny_patterns.as_deref(),
    );

    if let Some(finding) = findings.first() {
        state.metrics.record_blocked();
        let finding_text = format!("{}:{}", finding.kind, finding.detail);
        record_langfuse(
            &state,
            &principal,
            LangfuseInput {
                trace_id: &trace_id,
                name: "responses",
                model: model.clone(),
                input: completions_payload.clone(),
                output: None,
                usage: None,
                start_time: wall_started,
                end_time: Utc::now(),
                status: "blocked",
                finding: Some(finding_text.clone()),
                decision: None,
            },
        )
        .await;
        audit(
            &state,
            &principal,
            AuditInput {
                trace_id: &trace_id,
                model: model.clone(),
                route: "security",
                status: "blocked",
                finding: Some(finding_text),
                memory: None,
                latency_ms: started.elapsed().as_millis(),
            },
        )
        .await;
        audit_guard.complete();
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "request blocked by security policy",
                "finding": {
                    "kind": finding.kind,
                    "detail": finding.detail
                },
                "trace_id": trace_id
            })),
        )
            .into_response());
    }

    let model_name_str = model.as_deref().unwrap_or("unknown");
    let cap = model_policy::resolve_capability(&state.config, model_name_str);
    let stripped_params = model_policy::strip_unsupported_params(&mut completions_payload, cap);
    model_policy::inject_extra_body(&mut completions_payload, cap);
    let memory_audit = state
        .memory
        .enrich_chat_payload(&principal, &mut completions_payload)
        .await;

    audit_guard.memory_audit = Some(memory_audit.clone());

    let is_stream = payload.stream.unwrap_or(false);

    if is_stream {
        return match state
            .proxy
            .proxy_responses_stream(
                completions_payload,
                &trace_id,
                model.clone(),
                Some(principal.clone()),
            )
            .await
        {
            Ok(response) => {
                let finding = combine_findings(
                    if stripped_params.is_empty() {
                        None
                    } else {
                        Some(format!("param_stripped:{}", stripped_params.join(",")))
                    },
                    memory_audit.finding_suffix(),
                );
                audit(
                    &state,
                    &principal,
                    AuditInput {
                        trace_id: &trace_id,
                        model,
                        route: "litellm",
                        status: "proxied_stream",
                        finding,
                        memory: Some(memory_audit),
                        latency_ms: started.elapsed().as_millis(),
                    },
                )
                .await;
                audit_guard.complete();
                Ok(response)
            }
            Err(err) => {
                state.metrics.record_upstream_error();
                audit(
                    &state,
                    &principal,
                    AuditInput {
                        trace_id: &trace_id,
                        model,
                        route: "litellm",
                        status: "upstream_error",
                        finding: Some(err.message()),
                        memory: Some(memory_audit),
                        latency_ms: started.elapsed().as_millis(),
                    },
                )
                .await;
                audit_guard.complete();
                Err((
                    err.status(),
                    Json(json!({ "error": "upstream unavailable", "trace_id": trace_id })),
                )
                    .into_response())
            }
        };
    }

    let langfuse_input = completions_payload.clone();
    match state
        .proxy
        .proxy_chat_buffered(completions_payload, &trace_id, Some(principal.clone()))
        .await
    {
        Ok(response) => {
            let finding = combine_findings(
                if stripped_params.is_empty() {
                    None
                } else {
                    Some(format!("param_stripped:{}", stripped_params.join(",")))
                },
                memory_audit.finding_suffix(),
            );

            let response_json = response.json();
            let converted_json = response_json
                .clone()
                .map(aegis_llm::responses_adapter::convert_response_to_responses);

            let status = if response.status().is_success() {
                "proxied"
            } else {
                "upstream_error"
            };
            record_langfuse(
                &state,
                &principal,
                LangfuseInput {
                    trace_id: &trace_id,
                    name: "responses",
                    model: model.clone(),
                    input: langfuse_input,
                    output: response_json
                        .as_ref()
                        .and_then(langfuse::extract_chat_output)
                        .or_else(|| response_json.clone()),
                    usage: response_json.as_ref().and_then(langfuse::extract_usage),
                    start_time: wall_started,
                    end_time: Utc::now(),
                    status,
                    finding: finding.clone(),
                    decision: None,
                },
            )
            .await;
            audit(
                &state,
                &principal,
                AuditInput {
                    trace_id: &trace_id,
                    model,
                    route: "litellm",
                    status,
                    finding,
                    memory: Some(memory_audit),
                    latency_ms: started.elapsed().as_millis(),
                },
            )
            .await;
            audit_guard.complete();

            if let Some(cj) = converted_json {
                let mut builder = Response::builder().status(response.status());
                builder = builder.header("X-GoVail-Trace-Id", &trace_id);
                builder = builder.header("content-type", "application/json");
                let body_bytes = serde_json::to_vec(&cj).unwrap_or_default();
                builder
                    .body(axum::body::Body::from(body_bytes))
                    .map_err(|e| {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({ "error": e.to_string(), "trace_id": trace_id })),
                        )
                            .into_response()
                    })
            } else {
                response.into_response().map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(json!({ "error": e.message(), "trace_id": trace_id })),
                    )
                        .into_response()
                })
            }
        }
        Err(err) => {
            state.metrics.record_upstream_error();
            audit(
                &state,
                &principal,
                AuditInput {
                    trace_id: &trace_id,
                    model,
                    route: "litellm",
                    status: "upstream_error",
                    finding: Some(err.message()),
                    memory: Some(memory_audit),
                    latency_ms: started.elapsed().as_millis(),
                },
            )
            .await;
            audit_guard.complete();
            Err((
                err.status(),
                Json(json!({ "error": "upstream unavailable", "trace_id": trace_id })),
            )
                .into_response())
        }
    }
}

async fn embeddings(
    state: State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<Value>,
) -> Result<Response, Response> {
    let started = Instant::now();
    let wall_started = Utc::now();
    let trace_id = headers
        .get("X-GoVail-Trace-Id")
        .or_else(|| headers.get("x-trace-id"))
        .and_then(|value| value.to_str().ok())
        .map(ToString::to_string)
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let principal = auth::authenticate(state.clone(), headers)
        .await
        .map_err(IntoResponse::into_response)?;
    state.metrics.record_request();

    let mut payload = payload;

    // vLLM Pydantic validation bypass: force encoding_format to "float" if it is null or missing
    if let Some(obj) = payload.as_object_mut() {
        if !obj.contains_key("encoding_format")
            || obj
                .get("encoding_format")
                .map(|v| v.is_null())
                .unwrap_or(false)
        {
            obj.insert(
                "encoding_format".to_string(),
                serde_json::Value::String("float".to_string()),
            );
        }
    }

    if state.config.security.redact_pii {
        aegis_llm::security::redact_pii_in_value(&mut payload);
    }

    let model = extract_model(&payload).map(ToString::to_string);
    if let Some(model) = &model {
        if !principal.can_use_model(model) {
            state.metrics.record_blocked();
            record_langfuse(
                &state,
                &principal,
                LangfuseInput {
                    trace_id: &trace_id,
                    name: "embeddings",
                    model: Some(model.clone()),
                    input: payload.clone(),
                    output: None,
                    usage: None,
                    start_time: wall_started,
                    end_time: Utc::now(),
                    status: "blocked",
                    finding: Some("model_not_allowed".to_string()),
                    decision: None,
                },
            )
            .await;
            audit(
                &state,
                &principal,
                AuditInput {
                    trace_id: &trace_id,
                    model: model.clone().into(),
                    route: "policy",
                    status: "blocked",
                    finding: Some("model_not_allowed".to_string()),
                    memory: None,
                    latency_ms: started.elapsed().as_millis(),
                },
            )
            .await;
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({
                    "error": "model is not allowed for this API key",
                    "model": model,
                    "trace_id": trace_id
                })),
            )
                .into_response());
        }
    }

    let findings = scan_chat_payload(
        &payload,
        state.config.security.max_prompt_chars,
        state.config.security.deny_prompt_injection,
        state.config.security.deny_secret_patterns,
        state.config.security.deny_patterns.as_deref(),
    );

    if let Some(finding) = findings.first() {
        state.metrics.record_blocked();
        let finding_text = format!("{}:{}", finding.kind, finding.detail);
        record_langfuse(
            &state,
            &principal,
            LangfuseInput {
                trace_id: &trace_id,
                name: "embeddings",
                model: model.clone(),
                input: payload.clone(),
                output: None,
                usage: None,
                start_time: wall_started,
                end_time: Utc::now(),
                status: "blocked",
                finding: Some(finding_text.clone()),
                decision: None,
            },
        )
        .await;
        audit(
            &state,
            &principal,
            AuditInput {
                trace_id: &trace_id,
                model: model.clone(),
                route: "security",
                status: "blocked",
                finding: Some(finding_text),
                memory: None,
                latency_ms: started.elapsed().as_millis(),
            },
        )
        .await;
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({
                "error": "request blocked by security policy",
                "finding": {
                    "kind": finding.kind,
                    "detail": finding.detail
                },
                "trace_id": trace_id
            })),
        )
            .into_response());
    }

    let langfuse_input = payload.clone();
    match state
        .proxy
        .proxy_embeddings_buffered(payload, &trace_id)
        .await
    {
        Ok(response) => {
            let response_json = response.json();
            let status = if response.status().is_success() {
                "proxied"
            } else {
                "upstream_error"
            };
            record_langfuse(
                &state,
                &principal,
                LangfuseInput {
                    trace_id: &trace_id,
                    name: "embeddings",
                    model: model.clone(),
                    input: langfuse_input.clone(),
                    output: response_json
                        .as_ref()
                        .and_then(langfuse::extract_embedding_output)
                        .or_else(|| response_json.clone()),
                    usage: response_json.as_ref().and_then(langfuse::extract_usage),
                    start_time: wall_started,
                    end_time: Utc::now(),
                    status,
                    finding: None,
                    decision: None,
                },
            )
            .await;
            audit_with_payload(
                &state,
                &principal,
                AuditInput {
                    trace_id: &trace_id,
                    model,
                    route: "litellm",
                    status,
                    finding: None,
                    memory: None,
                    latency_ms: started.elapsed().as_millis(),
                },
                Some(langfuse_input),
                response_json,
            )
            .await;
            response.into_response().map_err(|err| {
                (
                    err.status(),
                    Json(json!({ "error": "failed to build upstream response", "trace_id": trace_id })),
                )
                    .into_response()
            })
        }
        Err(err) => {
            state.metrics.record_upstream_error();
            audit_with_payload(
                &state,
                &principal,
                AuditInput {
                    trace_id: &trace_id,
                    model,
                    route: "litellm",
                    status: "upstream_error",
                    finding: Some(err.message()),
                    memory: None,
                    latency_ms: started.elapsed().as_millis(),
                },
                Some(langfuse_input),
                None,
            )
            .await;
            Err((
                err.status(),
                Json(json!({ "error": "upstream unavailable", "trace_id": trace_id })),
            )
                .into_response())
        }
    }
}

struct LangfuseInput<'a> {
    trace_id: &'a str,
    name: &'a str,
    model: Option<String>,
    input: Value,
    output: Option<Value>,
    usage: Option<langfuse::TokenUsage>,
    start_time: DateTime<Utc>,
    end_time: DateTime<Utc>,
    status: &'a str,
    finding: Option<String>,
    decision: Option<crate::route_router::RouteDecision>,
}

async fn record_langfuse(state: &AppState, principal: &Principal, input: LangfuseInput<'_>) {
    let model_suffix = input.model.as_deref().unwrap_or("unknown");
    let (
        route_target,
        risk_level,
        workflow_type,
        decision_reason,
        approval_required,
        risk_score,
        route_confidence,
    ) = if let Some(ref d) = input.decision {
        (
            Some(d.route_target.clone()),
            Some(d.risk_level.clone()),
            d.workflow_type.clone(),
            Some(d.reason.clone()),
            Some(d.approval_required),
            Some(d.risk_score),
            Some(d.route_confidence as f64),
        )
    } else {
        (None, None, None, None, None, None, None)
    };

    state
        .langfuse
        .record_generation(
            principal,
            LangfuseRecord {
                trace_id: input.trace_id.to_string(),
                name: format!("{}:{}", input.name, model_suffix),
                project: principal.project.clone(),
                user_id: principal.key_id.clone(),
                model: input.model,
                input: input.input,
                output: input.output,
                usage: input.usage,
                start_time: input.start_time,
                end_time: input.end_time,
                status: input.status.to_string(),
                finding: input.finding,
                route_target,
                risk_level,
                workflow_type,
                decision_reason,
                approval_required,
                risk_score,
                route_confidence,
            },
        )
        .await;
}

fn is_streaming_request(payload: &Value) -> bool {
    payload
        .get("stream")
        .and_then(Value::as_bool)
        .unwrap_or(false)
}

struct AuditInput<'a> {
    trace_id: &'a str,
    model: Option<String>,
    route: &'a str,
    status: &'a str,
    finding: Option<String>,
    memory: Option<aegis_llm::memory::MemoryAudit>,
    latency_ms: u128,
}

async fn audit(state: &AppState, principal: &Principal, input: AuditInput<'_>) {
    audit_with_payload(state, principal, input, None, None).await;
}

async fn audit_with_payload(
    state: &AppState,
    principal: &Principal,
    input: AuditInput<'_>,
    request: Option<Value>,
    response: Option<Value>,
) {
    let mut request = request;
    if let Some(ref mut req) = request {
        aegis_llm::security::redact_pii_in_value(req);
    }
    let mut response = response;
    if let Some(ref mut resp) = response {
        aegis_llm::security::redact_pii_in_value(resp);
    }

    let event = AuditEvent {
        ts: Utc::now(),
        trace_id: input.trace_id.to_string(),
        key_id: principal.key_id.clone(),
        key_hash: principal.key_hash.clone(),
        project: principal.project.clone(),
        model: input.model,
        route: input.route.to_string(),
        status: input.status.to_string(),
        finding: input.finding,
        memory: input.memory,
        latency_ms: input.latency_ms,
        request,
        response,
    };

    if let Err(err) = state.audit.append(&event).await {
        error!(error = %err, "failed to append audit event");
    }
}

fn combine_findings(left: Option<String>, right: Option<String>) -> Option<String> {
    match (left, right) {
        (Some(left), Some(right)) => Some(format!("{left};{right}")),
        (Some(left), None) => Some(left),
        (None, Some(right)) => Some(right),
        (None, None) => None,
    }
}

async fn proxy_to_runtime(
    State(state): State<AppState>,
    req: Request,
) -> Result<Response, Response> {
    let headers = req.headers().clone();

    // 1. 게이트웨이 자체 API Key 인증 검사
    let _principal = auth::authenticate(State(state.clone()), headers.clone())
        .await
        .map_err(IntoResponse::into_response)?;

    // 2. 대상 URL 생성
    let runtime_base = std::env::var("GOVAIL_RUNTIME_URL")
        .unwrap_or_else(|_| state.config.router.runtime_url.clone());

    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str().to_string())
        .unwrap_or_default();
    let target_url = format!("{}{}", runtime_base, path_and_query);

    let method = req.method().clone();
    let body = req.into_body();

    // Axum Body를 reqwest Body Stream으로 변환
    let reqwest_body = reqwest::Body::wrap_stream(
        http_body_util::BodyStream::new(body).map_ok(|frame| frame.into_data().unwrap_or_default()),
    );

    let mut builder = state
        .db_client
        .request(method, &target_url)
        .body(reqwest_body);

    for (key, value) in headers.iter() {
        if key != http::header::HOST {
            builder = builder.header(key, value);
        }
    }

    let response = builder.send().await.map_err(|err| {
        error!(error = %err, "Failed to proxy request to runtime");
        (
            StatusCode::BAD_GATEWAY,
            Json(json!({
                "error": "failed to connect to runtime server",
                "detail": err.to_string()
            })),
        )
            .into_response()
    })?;

    let status = response.status();
    let resp_headers = response.headers().clone();

    let resp_stream = response.bytes_stream();
    let axum_body = Body::from_stream(resp_stream);

    let mut axum_resp = Response::builder()
        .status(status)
        .body(axum_body)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())?;

    *axum_resp.headers_mut() = resp_headers;

    // SSE 스트림 중계 시 Nginx/Gateway 버퍼링 비활성화 헤더 추가
    if path_and_query.contains("/stream") {
        axum_resp
            .headers_mut()
            .insert("X-Accel-Buffering", http::HeaderValue::from_static("no"));
    }

    Ok(axum_resp)
}

#[derive(Debug, serde::Deserialize)]
struct ScoreRequest {
    trace_id: String,
    name: String,
    value: f64,
    comment: Option<String>,
}

async fn submit_score(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(payload): Json<ScoreRequest>,
) -> Result<impl IntoResponse, Response> {
    let _principal = auth::authenticate(State(state.clone()), headers)
        .await
        .map_err(IntoResponse::into_response)?;

    let score = langfuse::LangfuseScore {
        trace_id: payload.trace_id,
        name: payload.name,
        value: payload.value,
        comment: payload.comment,
    };

    let langfuse_client = state.langfuse.clone();
    tokio::spawn(async move {
        langfuse_client.record_score(score).await;
    });

    Ok(Json(json!({
        "status": "success",
        "message": "score submission queued"
    })))
}
