use std::{sync::Arc, time::Duration};

use axum::{
    body::Body,
    http::{header, HeaderMap, HeaderValue, Method, Response, StatusCode},
};
use bytes::Bytes;
use chrono::Utc;
use futures_util::{Stream, TryStreamExt};
use reqwest::Url;
use serde_json::{json, Value};

use crate::config::GatewayConfig;

#[derive(Clone)]
pub struct ProxyClient {
    config: Arc<GatewayConfig>,
    client: reqwest::Client,
    metrics: crate::metrics::GatewayMetrics,
}

impl ProxyClient {
    pub fn new(config: Arc<GatewayConfig>, metrics: crate::metrics::GatewayMetrics) -> anyhow::Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(config.upstream.timeout_seconds))
            .build()?;
        Ok(Self { config, client, metrics })
    }

    async fn send_with_retry_and_fallback(
        &self,
        method: Method,
        path: &str,
        payload: Option<&Value>,
        trace_id: &str,
        principal: Option<&crate::auth::Principal>,
    ) -> Result<reqwest::Response, ProxyError> {
        let max_retries = 3;
        let mut attempt = 0;
        let primary_url = upstream_url(&self.config.upstream.base_url, path)?;
        let primary_key = self.config.upstream.api_key.as_deref().unwrap_or("");
        let mut last_error = None;

        loop {
            attempt += 1;
            let mut request = self.client.request(method.clone(), primary_url.clone())
                .header("X-Aegis-Trace-Id", trace_id);
            if let Some(pr) = principal {
                request = request
                    .header("X-User-Id", &pr.key_id)
                    .header("X-User-Name", &pr.project)
                    .header("X-User-Role", &pr.role);
            }
            if !primary_key.is_empty() {
                request = request.bearer_auth(primary_key);
            }
            if let Some(ref payload) = payload {
                request = request.json(payload);
            }

            match request.send().await {
                Ok(resp) => {
                    let status = resp.status();
                    if status.is_success() || status.is_redirection() || status.is_client_error() {
                        return Ok(resp);
                    } else {
                        last_error = Some(ProxyError::InvalidUrl(format!("upstream returned status: {status}")));
                    }
                }
                Err(err) => {
                    last_error = Some(ProxyError::Upstream(err));
                }
            }

            if attempt >= max_retries {
                break;
            }
            let sleep_dur = Duration::from_millis(100 * (1 << (attempt - 1)));
            tokio::time::sleep(sleep_dur).await;
        }

        if let Some(ref fallback_base) = self.config.upstream.fallback_base_url {
            self.metrics.record_fallback();
            let fallback_url = upstream_url(fallback_base, path)?;
            let fallback_key = self.config.upstream.fallback_api_key.as_deref().unwrap_or("");
            attempt = 0;
            loop {
                attempt += 1;
                let mut request = self.client.request(method.clone(), fallback_url.clone())
                    .header("X-Aegis-Trace-Id", trace_id)
                    .header("X-Aegis-Fallback-Used", "true");
                if let Some(pr) = principal {
                    request = request
                        .header("X-User-Id", &pr.key_id)
                        .header("X-User-Name", &pr.project)
                        .header("X-User-Role", &pr.role);
                }
                if !fallback_key.is_empty() {
                    request = request.bearer_auth(fallback_key);
                }
                if let Some(ref payload) = payload {
                    request = request.json(payload);
                }

                match request.send().await {
                    Ok(resp) => {
                        let status = resp.status();
                        if status.is_success() || status.is_redirection() || status.is_client_error() {
                            return Ok(resp);
                        } else {
                            last_error = Some(ProxyError::InvalidUrl(format!("fallback upstream returned status: {status}")));
                        }
                    }
                    Err(err) => {
                        last_error = Some(ProxyError::Upstream(err));
                    }
                }

                if attempt >= max_retries {
                    break;
                }
                let sleep_dur = Duration::from_millis(100 * (1 << (attempt - 1)));
                tokio::time::sleep(sleep_dur).await;
            }
        }

        Err(last_error.unwrap_or_else(|| ProxyError::InvalidUrl("request failed without reason".to_string())))
    }

    pub async fn proxy_models(&self, trace_id: &str) -> Result<Response<Body>, ProxyError> {
        let res = self.send_with_retry_and_fallback(
            Method::GET,
            "/v1/models",
            None,
            trace_id,
            None,
        )
        .await?;

        if !res.status().is_success() {
            return Err(ProxyError::InvalidUrl(format!(
                "failed to fetch models, upstream status: {}",
                res.status()
            )));
        }

        let mut json_val: Value = match res.json().await {
            Ok(val) => val,
            Err(err) => return Err(ProxyError::Upstream(err)),
        };

        if let Some(data_arr) = json_val.get_mut("data").and_then(|v| v.as_array_mut()) {
            for model_val in data_arr.iter_mut() {
                if let Some(model_obj) = model_val.as_object_mut() {
                    // Roo Code(Zod 스키마)가 요구하는 필수 필드 주입
                    model_obj.insert("context_window".to_string(), Value::from(32768));
                    model_obj.insert("max_tokens".to_string(), Value::from(4096));
                }
            }
        }

        let body_str = serde_json::to_string(&json_val).unwrap_or_default();
        let response = Response::builder()
            .status(StatusCode::OK)
            .header("content-type", "application/json")
            .body(Body::from(body_str))
            .map_err(ProxyError::Build)?;

        Ok(response)
    }

    pub async fn proxy_chat(
        &self,
        payload: Value,
        audit_info: Option<(crate::audit::AuditLogger, crate::audit::AuditEvent)>,
        trace_id: &str,
        langfuse_client: Option<crate::langfuse::LangfuseClient>,
        principal: Option<crate::auth::Principal>,
        langfuse_record: Option<crate::langfuse::LangfuseRecord>,
    ) -> Result<Response<Body>, ProxyError> {
        self.proxy_json(
            Method::POST,
            "/v1/chat/completions",
            Some(payload),
            audit_info,
            trace_id,
            langfuse_client,
            principal,
            langfuse_record,
        )
        .await
    }

    pub async fn proxy_chat_buffered(
        &self,
        payload: Value,
        trace_id: &str,
        principal: Option<crate::auth::Principal>,
    ) -> Result<ProxyJsonResponse, ProxyError> {
        self.proxy_json_buffered(
            Method::POST,
            "/v1/chat/completions",
            Some(payload),
            trace_id,
            principal,
        )
        .await
    }

    pub async fn proxy_responses_stream(
        &self,
        payload: Value,
        trace_id: &str,
        model: Option<String>,
        principal: Option<crate::auth::Principal>,
    ) -> Result<Response<Body>, ProxyError> {
        let response = self.send_with_retry_and_fallback(
            Method::POST,
            "/v1/chat/completions",
            Some(&payload),
            trace_id,
            principal.as_ref(),
        )
        .await?;
        let status = response.status();
        let headers = response.headers().clone();

        let raw_stream = response.bytes_stream().map_err(std::io::Error::other);
        let adapter = crate::responses_adapter::ResponsesStreamAdapter::new(raw_stream, model);
        let body = Body::from_stream(adapter);

        let mut builder = Response::builder()
            .status(status)
            .header("X-Aegis-Trace-Id", trace_id);
        copy_response_headers(&headers, builder.headers_mut().expect("headers"));

        if let Some(headers_mut) = builder.headers_mut() {
            headers_mut.insert(
                header::CONTENT_TYPE,
                header::HeaderValue::from_static("text/event-stream"),
            );
        }

        builder.body(body).map_err(ProxyError::Build)
    }

    pub async fn proxy_embeddings(
        &self,
        payload: Value,
        trace_id: &str,
    ) -> Result<Response<Body>, ProxyError> {
        self.proxy_json(
            Method::POST,
            "/v1/embeddings",
            Some(payload),
            None,
            trace_id,
            None,
            None,
            None,
        )
        .await
    }

    pub async fn proxy_embeddings_buffered(
        &self,
        payload: Value,
        trace_id: &str,
    ) -> Result<ProxyJsonResponse, ProxyError> {
        self.proxy_json_buffered(
            Method::POST,
            "/v1/embeddings",
            Some(payload),
            trace_id,
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn proxy_json(
        &self,
        method: Method,
        path: &str,
        payload: Option<Value>,
        audit_info: Option<(crate::audit::AuditLogger, crate::audit::AuditEvent)>,
        trace_id: &str,
        langfuse_client: Option<crate::langfuse::LangfuseClient>,
        principal: Option<crate::auth::Principal>,
        langfuse_record: Option<crate::langfuse::LangfuseRecord>,
    ) -> Result<Response<Body>, ProxyError> {
        let response = self.send_with_retry_and_fallback(
            method,
            path,
            payload.as_ref(),
            trace_id,
            principal.as_ref(),
        )
        .await?;
        let status = response.status();
        let headers = response.headers().clone();

        let is_sse = headers
            .get(header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.contains("text/event-stream"))
            .unwrap_or(false);

        let body = if is_sse && audit_info.is_some() {
            let stream = response.bytes_stream().map_err(std::io::Error::other);
            let filtered = EgressFilterStream::new(
                stream,
                audit_info,
                langfuse_client,
                principal,
                langfuse_record,
                self.config.security.deny_patterns.clone(),
            );
            Body::from_stream(filtered)
        } else {
            let stream = response.bytes_stream().map_err(std::io::Error::other);
            Body::from_stream(stream)
        };

        let mut builder = Response::builder()
            .status(status)
            .header("X-Aegis-Trace-Id", trace_id);
        copy_response_headers(&headers, builder.headers_mut().expect("headers"));
        builder.body(body).map_err(ProxyError::Build)
    }

    async fn proxy_json_buffered(
        &self,
        method: Method,
        path: &str,
        payload: Option<Value>,
        trace_id: &str,
        principal: Option<crate::auth::Principal>,
    ) -> Result<ProxyJsonResponse, ProxyError> {
        let response = self.send_with_retry_and_fallback(
            method,
            path,
            payload.as_ref(),
            trace_id,
            principal.as_ref(),
        )
        .await?;
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.bytes().await.map_err(ProxyError::Upstream)?;
        Ok(ProxyJsonResponse {
            status,
            headers,
            body,
            trace_id: trace_id.to_string(),
        })
    }
}

#[derive(Debug, Clone)]
pub struct ProxyJsonResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
    trace_id: String,
}

impl ProxyJsonResponse {
    pub fn status(&self) -> StatusCode {
        self.status
    }

    pub fn json(&self) -> Option<Value> {
        serde_json::from_slice(&self.body).ok()
    }

    pub fn into_response(self) -> Result<Response<Body>, ProxyError> {
        let mut builder = Response::builder().status(self.status);
        builder = builder.header("X-Aegis-Trace-Id", &self.trace_id);
        copy_response_headers(&self.headers, builder.headers_mut().expect("headers"));
        builder
            .body(Body::from(self.body))
            .map_err(ProxyError::Build)
    }
}

#[derive(Debug)]
pub enum ProxyError {
    InvalidUrl(String),
    Upstream(reqwest::Error),
    Build(http::Error),
}

impl ProxyError {
    pub fn status(&self) -> StatusCode {
        match self {
            Self::InvalidUrl(_) => StatusCode::BAD_GATEWAY,
            Self::Upstream(_) => StatusCode::BAD_GATEWAY,
            Self::Build(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub fn message(&self) -> String {
        match self {
            Self::InvalidUrl(err) => format!("invalid upstream URL: {err}"),
            Self::Upstream(err) => format!("upstream request failed: {err}"),
            Self::Build(err) => format!("failed to build response: {err}"),
        }
    }
}

fn upstream_url(base_url: &str, path: &str) -> Result<Url, ProxyError> {
    let base = base_url.trim_end_matches('/');
    Url::parse(&format!("{base}{path}")).map_err(|err| ProxyError::InvalidUrl(err.to_string()))
}

fn copy_response_headers(source: &HeaderMap, target: &mut HeaderMap) {
    for (name, value) in source {
        if is_forwarded_header(name.as_str()) {
            target.insert(name.clone(), value.clone());
        }
    }
    target
        .entry(header::CONTENT_TYPE)
        .or_insert(HeaderValue::from_static("application/json"));
}

fn is_forwarded_header(name: &str) -> bool {
    matches!(
        name,
        "content-type" | "content-length" | "cache-control" | "accept-ranges"
    )
}

pub struct EgressFilterStream<S> {
    inner: S,
    buffer: String,
    audit_sender: Option<(crate::audit::AuditLogger, crate::audit::AuditEvent)>,
    is_blocked: bool,
    langfuse_client: Option<crate::langfuse::LangfuseClient>,
    principal: Option<crate::auth::Principal>,
    langfuse_record: Option<crate::langfuse::LangfuseRecord>,
    deny_patterns: Option<Vec<String>>,
}

impl<S> EgressFilterStream<S> {
    pub fn new(
        inner: S,
        audit_sender: Option<(crate::audit::AuditLogger, crate::audit::AuditEvent)>,
        langfuse_client: Option<crate::langfuse::LangfuseClient>,
        principal: Option<crate::auth::Principal>,
        langfuse_record: Option<crate::langfuse::LangfuseRecord>,
        deny_patterns: Option<Vec<String>>,
    ) -> Self {
        Self {
            inner,
            buffer: String::new(),
            audit_sender,
            is_blocked: false,
            langfuse_client,
            principal,
            langfuse_record,
            deny_patterns,
        }
    }
}

impl<S> Stream for EgressFilterStream<S>
where
    S: Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
{
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        if self.is_blocked {
            return std::task::Poll::Ready(None);
        }

        match std::pin::Pin::new(&mut self.inner).poll_next(cx) {
            std::task::Poll::Ready(Some(Ok(bytes))) => {
                if let Ok(text) = std::str::from_utf8(&bytes) {
                    self.buffer.push_str(text);
                    if let Some(finding) =
                        check_egress_danger(&self.buffer, self.deny_patterns.as_deref())
                    {
                        self.is_blocked = true;

                        // 1. 차단 시 Langfuse 기록 (비동기)
                        if let (Some(client), Some(principal), Some(mut record)) = (
                            self.langfuse_client.take(),
                            self.principal.take(),
                            self.langfuse_record.take(),
                        ) {
                            record.end_time = Utc::now();
                            record.status = "egress_blocked".to_string();
                            record.finding = Some(format!("egress_dlp:{}", finding));
                            tokio::spawn(async move {
                                client.record_generation(&principal, record).await;
                            });
                        }

                        // 2. 차단 시 감사 로그 기록 (비동기)
                        if let Some((logger, mut event)) = self.audit_sender.take() {
                            event.status = "egress_blocked".to_string();
                            event.finding = Some(format!("egress_dlp:{}", finding));
                            let (output, _usage) = parse_sse_stream_output(&self.buffer);
                            let mut redacted_response = output;
                            if let Some(ref mut resp) = redacted_response {
                                crate::security::redact_pii_in_value(resp);
                            }
                            event.response = redacted_response;
                            tokio::spawn(async move {
                                let _ = logger.append(&event).await;
                            });
                        }
                        return std::task::Poll::Ready(Some(Err(std::io::Error::new(
                            std::io::ErrorKind::PermissionDenied,
                            "egress request blocked by DLP policy",
                        ))));
                    }
                }
                std::task::Poll::Ready(Some(Ok(bytes)))
            }
            std::task::Poll::Ready(None) => {
                // 스트림 완료 시점에 도달함
                // 1. Langfuse 기록 (비동기)
                if let (Some(client), Some(principal), Some(mut record)) = (
                    self.langfuse_client.take(),
                    self.principal.take(),
                    self.langfuse_record.take(),
                ) {
                    let (output, usage) = parse_sse_stream_output(&self.buffer);
                    record.output = output;
                    record.usage = usage;
                    record.end_time = Utc::now();
                    record.status = "proxied".to_string();
                    tokio::spawn(async move {
                        client.record_generation(&principal, record).await;
                    });
                }

                // 2. 감사 로그 기록 (비동기)
                if let Some((logger, mut event)) = self.audit_sender.take() {
                    event.status = "proxied".to_string();
                    let (output, _usage) = parse_sse_stream_output(&self.buffer);
                    let mut redacted_response = output;
                    if let Some(ref mut resp) = redacted_response {
                        crate::security::redact_pii_in_value(resp);
                    }
                    event.response = redacted_response;
                    tokio::spawn(async move {
                        let _ = logger.append(&event).await;
                    });
                }
                std::task::Poll::Ready(None)
            }
            res => res,
        }
    }
}

fn check_egress_danger(text: &str, deny_patterns: Option<&[String]>) -> Option<String> {
    use regex::Regex;
    use std::sync::OnceLock;

    // 1. 표준 위험 비밀정보 검사
    static DANGER_REGEXES: OnceLock<Vec<(Regex, &'static str)>> = OnceLock::new();
    let regexes = DANGER_REGEXES.get_or_init(|| {
        vec![
            (
                Regex::new(r"\bghp_[A-Za-z0-9_]{20,}\b").unwrap(),
                "github_token",
            ),
            (
                Regex::new(r"\bsk-[A-Za-z0-9_\-]{20,}\b").unwrap(),
                "openai_key",
            ),
            (
                Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap(),
                "aws_access_key",
            ),
            (
                Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap(),
                "private_key",
            ),
        ]
    });

    for (re, name) in regexes {
        if re.is_match(text) {
            return Some((*name).to_string());
        }
    }

    // 1-1. 시스템 프롬프트 유출(Prompt Leakage) 감지
    if crate::security::is_prompt_leakage(text) {
        return Some("prompt_leakage".to_string());
    }

    // 주민등록번호(RRN)는 체크섬 유효성 검증을 필히 적용
    static RRN_REGEX: OnceLock<Regex> = OnceLock::new();
    let rrn_re = RRN_REGEX.get_or_init(|| Regex::new(r"\b\d{6}-[1-489]\d{6}\b").unwrap());
    for caps in rrn_re.captures_iter(text) {
        if let Some(matched) = caps.get(0) {
            if crate::security::is_valid_rrn(matched.as_str()) {
                return Some("rrn".to_string());
            }
        }
    }

    // 2. 동적 차단 키워드/패턴 검사
    if let Some(patterns) = deny_patterns {
        for pattern_str in patterns {
            if let Ok(re) = Regex::new(pattern_str) {
                if re.is_match(text) {
                    return Some(pattern_str.clone());
                }
            }
        }
    }

    None
}

pub fn parse_sse_stream_output(
    buffer: &str,
) -> (Option<Value>, Option<crate::langfuse::TokenUsage>) {
    let mut full_text = String::new();
    let mut prompt_tokens = None;
    let mut completion_tokens = None;
    let mut total_tokens = None;

    for line in buffer.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if line == "data: [DONE]" {
            continue;
        }
        if let Some(json_str) = line.strip_prefix("data: ") {
            if let Ok(val) = serde_json::from_str::<Value>(json_str.trim()) {
                // 1. content 추출
                if let Some(choices) = val.get("choices").and_then(Value::as_array) {
                    if let Some(choice) = choices.first() {
                        if let Some(delta) = choice.get("delta") {
                            if let Some(content) = delta.get("content").and_then(Value::as_str) {
                                full_text.push_str(content);
                            }
                        } else if let Some(text) = choice.get("text").and_then(Value::as_str) {
                            full_text.push_str(text);
                        }
                    }
                }

                // 2. usage 추출
                if let Some(usage) = val.get("usage") {
                    if let Some(p) = usage
                        .get("prompt_tokens")
                        .or_else(|| usage.get("input_tokens"))
                        .and_then(Value::as_u64)
                    {
                        prompt_tokens = Some(p);
                    }
                    if let Some(c) = usage
                        .get("completion_tokens")
                        .or_else(|| usage.get("output_tokens"))
                        .and_then(Value::as_u64)
                    {
                        completion_tokens = Some(c);
                    }
                    if let Some(t) = usage.get("total_tokens").and_then(Value::as_u64) {
                        total_tokens = Some(t);
                    }
                }
            }
        }
    }

    let output_json = if !full_text.is_empty() {
        Some(json!({
            "choices": [
                {
                    "message": {
                        "role": "assistant",
                        "content": full_text
                    }
                }
            ]
        }))
    } else {
        None
    };

    let token_usage = if prompt_tokens.is_some() || completion_tokens.is_some() {
        Some(crate::langfuse::TokenUsage {
            input: prompt_tokens,
            output: completion_tokens,
            total: total_tokens,
        })
    } else {
        None
    };

    (output_json, token_usage)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::{AuditEvent, AuditLogger};
    use chrono::Utc;
    use futures_util::stream;
    use futures_util::StreamExt;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_sse_stream_output() {
        let buffer = "data: {\"choices\":[{\"delta\":{\"content\":\"hello \"}}]}\n\ndata: {\"choices\":[{\"delta\":{\"content\":\"world\"}}]}\n\ndata: [DONE]\n\n";
        let (output, usage) = parse_sse_stream_output(buffer);
        assert!(output.is_some());
        let val = output.unwrap();
        let content = val
            .get("choices")
            .and_then(Value::as_array)
            .and_then(|arr| arr.first())
            .and_then(|c| c.get("message"))
            .and_then(|m| m.get("content"))
            .and_then(Value::as_str)
            .unwrap();
        assert_eq!(content, "hello world");
        assert!(usage.is_none());
    }

    #[tokio::test]
    async fn blocks_dangerous_sse_stream() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path().to_path_buf());

        let event = AuditEvent {
            ts: Utc::now(),
            trace_id: "sse-trace".to_string(),
            key_id: "test_key".to_string(),
            key_hash: "hash".to_string(),
            project: "test_project".to_string(),
            model: Some("test_model".to_string()),
            route: "test_route".to_string(),
            status: "proxied".to_string(),
            finding: None,
            memory: None,
            latency_ms: 10,
            request: None,
            response: None,
        };

        let chunk1 = Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"hello \"}}]}\n\n");
        let fake_key = format!("{}{}", "sk-", "abcdefghijklmnopqrst");
        let chunk2 = Bytes::from(format!(
            "data: {{\"choices\":[{{\"delta\":{{\"content\":\"my key is {} \"}}}}]}}\n\n",
            fake_key
        ));
        let chunk3 = Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"and end\"}}]}\n\n");

        let raw_stream = stream::iter(vec![Ok(chunk1), Ok(chunk2), Ok(chunk3)]);

        let mut filtered_stream =
            EgressFilterStream::new(raw_stream, Some((logger, event)), None, None, None, None);

        let res1 = filtered_stream.next().await;
        assert!(res1.is_some());
        assert!(res1.unwrap().is_ok());

        let res2 = filtered_stream.next().await;
        assert!(res2.is_some());
        let err = res2.unwrap().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        let res3 = filtered_stream.next().await;
        assert!(res3.is_none());

        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("egress_blocked"));
        assert!(content.contains("egress_dlp:openai_key"));
    }

    #[tokio::test]
    async fn blocks_prompt_leakage_sse_stream() {
        let temp_file = NamedTempFile::new().unwrap();
        let logger = AuditLogger::new(temp_file.path().to_path_buf());

        let event = AuditEvent {
            ts: Utc::now(),
            trace_id: "leakage-trace".to_string(),
            key_id: "test_key".to_string(),
            key_hash: "hash".to_string(),
            project: "test_project".to_string(),
            model: Some("test_model".to_string()),
            route: "test_route".to_string(),
            status: "proxied".to_string(),
            finding: None,
            memory: None,
            latency_ms: 10,
            request: None,
            response: None,
        };

        let chunk1 = Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"Hello. \"}}]}\n\n");
        let chunk2 = Bytes::from("data: {\"choices\":[{\"delta\":{\"content\":\"현재 판단: 모델 조회가 시도되었습니다. \"}}]}\n\n");

        let raw_stream = stream::iter(vec![Ok(chunk1), Ok(chunk2)]);

        let mut filtered_stream =
            EgressFilterStream::new(raw_stream, Some((logger, event)), None, None, None, None);

        let res1 = filtered_stream.next().await;
        assert!(res1.is_some());
        assert!(res1.unwrap().is_ok());

        let res2 = filtered_stream.next().await;
        assert!(res2.is_some());
        let err = res2.unwrap().unwrap_err();
        assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

        tokio::time::sleep(std::time::Duration::from_millis(600)).await;

        let content = std::fs::read_to_string(temp_file.path()).unwrap();
        assert!(content.contains("egress_blocked"));
        assert!(content.contains("egress_dlp:prompt_leakage"));
    }
}
