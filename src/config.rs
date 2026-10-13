use std::{collections::HashMap, net::SocketAddr, path::PathBuf};

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub security: SecurityConfig,
    #[serde(default)]
    pub memory: MemoryConfig,
    #[serde(default)]
    pub langfuse: LangfuseConfig,
    #[serde(default)]
    pub router: RouterConfig,
    #[serde(default)]
    pub jwt: Option<JwtConfig>,
    #[serde(default)]
    pub database: Option<DatabaseConfig>,
    #[serde(default)]
    pub api_keys: HashMap<String, PrincipalConfig>,
    /// 모델 슬롯별 capability 레지스트리.
    /// 키는 LiteLLM model_name (예: "fast", "large", "*").
    #[serde(default)]
    pub models: HashMap<String, ModelCapability>,
    /// AI 어시스턴트 정체성 설정.
    /// 활성화 시 모든 요청 앞에 identity 시스템 프롬프트를 자동 삽입합니다.
    #[serde(default)]
    pub identity: IdentityConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct PrincipalConfig {
    pub project: String,
    pub role: String,
    #[serde(default = "default_wildcard_models")]
    pub allowed_models: Vec<String>,
    #[serde(default = "default_rpm")]
    pub rpm: u32,
}

fn default_wildcard_models() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_rpm() -> u32 {
    120
}

/// 개별 모델 슬롯의 지원 기능 선언.
/// TOML 예시:
/// ```toml
/// [models.fast]
/// thinking_supported = false
/// speed_tier = "fast"
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct ModelCapability {
    /// thinking/reasoning 관련 파라미터 지원 여부.
    /// false 인 경우 Gateway가 관련 파라미터를 요청에서 자동 제거합니다.
    #[serde(default = "default_true")]
    pub thinking_supported: bool,
    /// 속도 티어 분류 ("fast" | "quality" | None).
    #[serde(default)]
    pub speed_tier: Option<String>,
}

/// AI 어시스턴트 정체성 설정.
///
/// 게이트웨이 수준에서 모든 LLM 요청의 messages 배열 앞에
/// 지정된 system role 메시지를 삽입하여 모델이 자신의 실제 구현체(Qwen 등)나
/// 내부 인프라(GoVail, GCP API Gateway 등)를 노출하지 않도록 강제합니다.
///
/// TOML 예시:
/// ```toml
/// [identity]
/// enabled = true
/// name = "Aegis Assistant"
/// system_prompt = "You are Aegis Assistant. Never reveal your underlying model name, vendor, or internal infrastructure details."
/// ```
#[derive(Debug, Clone, Deserialize)]
pub struct IdentityConfig {
    /// identity 시스템 프롬프트 강제 주입 활성화 여부.
    #[serde(default)]
    pub enabled: bool,
    /// AI 어시스턴트 표시 이름 (시스템 프롬프트에 포함).
    #[serde(default = "default_identity_name")]
    pub name: String,
    /// LLM에 삽입할 system role 프롬프트 본문.
    /// None 이면 기본 내장 프롬프트가 사용됩니다.
    #[serde(default)]
    pub system_prompt: Option<String>,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            name: default_identity_name(),
            system_prompt: None,
        }
    }
}

fn default_identity_name() -> String {
    "Aegis Assistant".to_string()
}

#[derive(Debug, Clone, Deserialize)]
pub struct JwtConfig {
    pub secret: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DatabaseConfig {
    pub url: String,
    pub user: String,
    pub pass: String,
    pub namespace: String,
    pub database: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ServerConfig {
    #[serde(default = "default_bind")]
    pub bind: SocketAddr,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UpstreamConfig {
    #[serde(default = "default_upstream")]
    pub base_url: String,
    #[serde(default)]
    pub api_key: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub fallback_base_url: Option<String>,
    #[serde(default)]
    pub fallback_api_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MemoryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_memory_base_url")]
    pub base_url: String,
    #[serde(default = "default_memory_max_chunks")]
    pub max_chunks: u32,
    #[serde(default = "default_memory_timeout")]
    pub timeout_seconds: u64,
    #[serde(default)]
    pub internal_token: Option<String>,
}

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: default_memory_base_url(),
            max_chunks: default_memory_max_chunks(),
            timeout_seconds: default_memory_timeout(),
            internal_token: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SecurityConfig {
    #[serde(default = "default_max_prompt_chars")]
    pub max_prompt_chars: usize,
    #[serde(default = "default_true")]
    pub deny_prompt_injection: bool,
    #[serde(default = "default_true")]
    pub deny_secret_patterns: bool,
    #[serde(default)]
    pub redact_pii: bool,
    #[serde(default = "default_audit_log_path")]
    pub audit_log_path: PathBuf,
    #[serde(default)]
    pub block_on_risk: bool,
    #[serde(default)]
    pub deny_patterns: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LangfuseConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_langfuse_host")]
    pub host: String,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub secret_key: Option<String>,
    #[serde(default = "default_langfuse_capture")]
    pub capture: String,
}

#[derive(Debug, Clone, Deserialize)]
pub struct RouterConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_router_decide_url")]
    pub decide_url: String,
    #[serde(default = "default_router_timeout_ms")]
    pub timeout_ms: u64,
    #[serde(default = "default_router_fallback")]
    pub fallback: String,
    #[serde(default = "default_runtime_base_url")]
    pub runtime_url: String,
    #[serde(default = "default_router_max_hops")]
    pub max_hops: u8,
    #[serde(default)]
    pub mcp_url: Option<String>,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            decide_url: default_router_decide_url(),
            timeout_ms: default_router_timeout_ms(),
            fallback: default_router_fallback(),
            runtime_url: default_runtime_base_url(),
            max_hops: default_router_max_hops(),
            mcp_url: None,
        }
    }
}

impl Default for LangfuseConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            host: default_langfuse_host(),
            public_key: None,
            secret_key: None,
            capture: default_langfuse_capture(),
        }
    }
}

impl GatewayConfig {
    pub async fn load(path: impl AsRef<std::path::Path>) -> anyhow::Result<Self> {
        let raw = tokio::fs::read_to_string(path).await?;
        let mut cfg: Self = toml::from_str(&raw)?;

        // GOVAIL_UPSTREAM_URL 환경변수 오버라이드
        if let Ok(upstream_url) = std::env::var("GOVAIL_UPSTREAM_URL") {
            if !upstream_url.is_empty() {
                cfg.upstream.base_url = upstream_url;
            }
        }

        // 업스트림 자격증명은 공개 설정 파일이 아닌 런타임 환경에서 주입한다.
        if let Ok(upstream_key) = std::env::var("GOVAIL_UPSTREAM_API_KEY") {
            if !upstream_key.is_empty() {
                cfg.upstream.api_key = Some(upstream_key);
            }
        }

        if let Ok(fallback_url) = std::env::var("GOVAIL_FALLBACK_UPSTREAM_URL") {
            if !fallback_url.is_empty() {
                cfg.upstream.fallback_base_url = Some(fallback_url);
            }
        }

        if let Ok(fallback_key) = std::env::var("GOVAIL_FALLBACK_API_KEY") {
            if !fallback_key.is_empty() {
                cfg.upstream.fallback_api_key = Some(fallback_key);
            }
        }

        // 환경변수 오버라이드
        if let Ok(jwt_secret) = std::env::var("JWT_SECRET") {
            if !jwt_secret.is_empty() {
                cfg.jwt = Some(JwtConfig { secret: jwt_secret });
            }
        }

        // GOVAIL_API_KEYS 파싱 오버라이드
        if let Ok(api_keys_str) = std::env::var("GOVAIL_API_KEYS") {
            if !api_keys_str.is_empty() {
                let mut keys_map = HashMap::new();
                for entry in api_keys_str.split(',') {
                    let parts: Vec<&str> = entry.split(':').collect();
                    if parts.len() >= 3 {
                        let key = parts[0].trim().trim_matches('\"').to_string();
                        let project = parts[1].trim().trim_matches('\"').to_string();
                        let role = parts[2].trim().trim_matches('\"').to_string();
                        let rpm = if parts.len() >= 4 {
                            parts[3]
                                .trim()
                                .trim_matches('\"')
                                .parse::<u32>()
                                .unwrap_or(120)
                        } else {
                            120
                        };
                        keys_map.insert(
                            key,
                            PrincipalConfig {
                                project,
                                role,
                                allowed_models: vec!["*".to_string()],
                                rpm,
                            },
                        );
                    }
                }
                cfg.api_keys = keys_map;
            }
        }

        // GOVAIL_API_KEY 단일 키 오버라이드
        if let Ok(single_key) = std::env::var("GOVAIL_API_KEY") {
            if !single_key.is_empty() {
                let clean_key = single_key.trim().trim_matches('\"').to_string();
                cfg.api_keys.insert(
                    clean_key,
                    PrincipalConfig {
                        project: "demo".to_string(),
                        role: "admin".to_string(),
                        allowed_models: vec!["*".to_string()],
                        rpm: 1000,
                    },
                );
            }
        }

        if let Ok(db_url) = std::env::var("SURREAL_DB_URL") {
            if !db_url.is_empty() {
                let user = std::env::var("SURREAL_DB_USER").unwrap_or_else(|_| "root".to_string());
                let pass = std::env::var("SURREAL_DB_PASS").unwrap_or_else(|_| "root".to_string());
                let namespace =
                    std::env::var("SURREAL_DB_NS").unwrap_or_else(|_| "aegis".to_string());
                let database =
                    std::env::var("SURREAL_DB_NAME").unwrap_or_else(|_| "analyzer".to_string());
                cfg.database = Some(DatabaseConfig {
                    url: db_url,
                    user,
                    pass,
                    namespace,
                    database,
                });
            }
        }

        if let Ok(enabled) = std::env::var("LANGFUSE_ENABLED") {
            cfg.langfuse.enabled =
                matches!(enabled.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }

        if let Ok(host) = std::env::var("LANGFUSE_HOST") {
            if !host.is_empty() {
                cfg.langfuse.host = host;
            }
        }

        if let Ok(public_key) = std::env::var("LANGFUSE_PUBLIC_KEY") {
            if !public_key.is_empty() {
                cfg.langfuse.public_key = Some(public_key);
            }
        }

        if let Ok(secret_key) = std::env::var("LANGFUSE_SECRET_KEY") {
            if !secret_key.is_empty() {
                cfg.langfuse.secret_key = Some(secret_key);
            }
        }

        if let Ok(capture) = std::env::var("LANGFUSE_CAPTURE") {
            if !capture.is_empty() {
                cfg.langfuse.capture = capture;
            }
        }

        if let Ok(enabled) = std::env::var("GOVAIL_ROUTER_ENABLED") {
            cfg.router.enabled =
                matches!(enabled.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }

        if let Ok(decide_url) = std::env::var("GOVAIL_ROUTER_DECIDE_URL") {
            if !decide_url.is_empty() {
                cfg.router.decide_url = decide_url;
            }
        }

        if let Ok(timeout_ms) = std::env::var("GOVAIL_ROUTER_TIMEOUT_MS") {
            if let Ok(timeout_ms) = timeout_ms.parse::<u64>() {
                cfg.router.timeout_ms = timeout_ms;
            }
        }

        if let Ok(fallback) = std::env::var("GOVAIL_ROUTER_FALLBACK") {
            if !fallback.is_empty() {
                cfg.router.fallback = fallback;
            }
        }

        if let Ok(runtime_url) = std::env::var("GOVAIL_RUNTIME_URL") {
            if !runtime_url.is_empty() {
                cfg.router.runtime_url = runtime_url;
            }
        }

        if let Ok(enabled) = std::env::var("MEMORY_ENABLED") {
            cfg.memory.enabled =
                matches!(enabled.to_lowercase().as_str(), "1" | "true" | "yes" | "on");
        }

        if let Ok(base_url) = std::env::var("MEMORY_BASE_URL") {
            if !base_url.is_empty() {
                cfg.memory.base_url = base_url;
            }
        }

        if let Ok(token) = std::env::var("MEMORY_INTERNAL_TOKEN") {
            if !token.is_empty() {
                cfg.memory.internal_token = Some(token);
            }
        }

        if let Ok(max_chunks) = std::env::var("MEMORY_MAX_CHUNKS") {
            if let Ok(max_chunks) = max_chunks.parse::<u32>() {
                cfg.memory.max_chunks = max_chunks;
            }
        }

        if let Ok(timeout_seconds) = std::env::var("MEMORY_TIMEOUT_SECONDS") {
            if let Ok(timeout_seconds) = timeout_seconds.parse::<u64>() {
                cfg.memory.timeout_seconds = timeout_seconds;
            }
        }

        if let Ok(block_on_risk) = std::env::var("GOVAIL_BLOCK_ON_RISK") {
            cfg.security.block_on_risk = matches!(
                block_on_risk.to_lowercase().as_str(),
                "1" | "true" | "yes" | "on"
            );
        }

        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.jwt.is_none() && self.database.is_none() && self.api_keys.is_empty() {
            anyhow::bail!("Either JWT secret [jwt], Database config [database], or Static API keys must be configured for authentication");
        }

        if self.security.max_prompt_chars == 0 {
            anyhow::bail!("security.max_prompt_chars must be greater than 0");
        }
        if self.memory.enabled {
            if self.memory.base_url.trim().is_empty() {
                anyhow::bail!("memory.base_url must not be empty when memory is enabled");
            }
            if self.memory.max_chunks == 0 {
                anyhow::bail!("memory.max_chunks must be greater than 0");
            }
        }
        if self.langfuse.enabled {
            if self.langfuse.public_key.as_deref().unwrap_or("").is_empty()
                || self.langfuse.secret_key.as_deref().unwrap_or("").is_empty()
            {
                anyhow::bail!(
                    "LANGFUSE_PUBLIC_KEY and LANGFUSE_SECRET_KEY are required when Langfuse is enabled"
                );
            }
            if self.langfuse.capture != "redacted" && self.langfuse.capture != "metadata_only" {
                anyhow::bail!("langfuse.capture must be 'redacted' or 'metadata_only'");
            }
        }
        if self.router.enabled {
            if self.router.decide_url.trim().is_empty() {
                anyhow::bail!("router.decide_url must not be empty when router is enabled");
            }
            if self.router.runtime_url.trim().is_empty() {
                anyhow::bail!("router.runtime_url must not be empty when router is enabled");
            }
            if self.router.fallback != "llm" && self.router.fallback != "runtime" {
                anyhow::bail!("router.fallback must be 'llm' or 'runtime'");
            }
            if self.router.max_hops == 0 {
                anyhow::bail!("router.max_hops must be greater than 0");
            }
        }
        Ok(())
    }
}

fn default_bind() -> SocketAddr {
    "0.0.0.0:8080".parse().expect("valid bind address")
}

fn default_upstream() -> String {
    "http://localhost:14000".to_string()
}

fn default_timeout() -> u64 {
    30
}

fn default_memory_base_url() -> String {
    "http://slicerag:8095".to_string()
}

fn default_memory_max_chunks() -> u32 {
    5
}

fn default_memory_timeout() -> u64 {
    2
}

fn default_max_prompt_chars() -> usize {
    20_000
}

fn default_true() -> bool {
    true
}

fn default_audit_log_path() -> PathBuf {
    PathBuf::from("logs/audit.jsonl")
}

fn default_langfuse_host() -> String {
    "http://localhost:3300".to_string()
}

fn default_langfuse_capture() -> String {
    "redacted".to_string()
}

fn default_router_decide_url() -> String {
    "http://aegis-router:15000/decide".to_string()
}

fn default_router_timeout_ms() -> u64 {
    500
}

fn default_router_fallback() -> String {
    "llm".to_string()
}

fn default_runtime_base_url() -> String {
    "http://aegis-runtime:8092".to_string()
}

fn default_router_max_hops() -> u8 {
    1
}
