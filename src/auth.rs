use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use axum::{
    extract::State,
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use serde_json::json;
use sha2::{Digest, Sha256};

use crate::AppState;

#[derive(Debug, Clone)]
pub struct Principal {
    pub key_id: String,
    pub key_hash: String,
    pub project: String,
    pub role: String,
    pub allowed_models: Vec<String>,
    pub rpm: u32,
}

#[derive(Debug)]
struct Window {
    started_at: Instant,
    count: u32,
}

#[derive(Debug, Clone, Default)]
pub struct RateLimiter {
    windows: Arc<Mutex<HashMap<String, Window>>>,
}

#[derive(Debug)]
pub enum AuthError {
    Missing,
    Invalid,
    RateLimited,
}

#[derive(Debug)]
pub enum RateLimitError {
    Exceeded,
    LockPoisoned,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, message) = match self {
            Self::Missing => (StatusCode::UNAUTHORIZED, "missing bearer token"),
            Self::Invalid => (StatusCode::UNAUTHORIZED, "invalid bearer token"),
            Self::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded"),
        };
        (status, axum::Json(json!({ "error": message }))).into_response()
    }
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub project: String, // 필수화 (멀티테넌시 격리용)
    pub role: Option<String>,
    pub allowed_models: Option<Vec<String>>,
    pub rpm: Option<u32>,
    pub exp: usize,
    pub jti: Option<String>,
}

async fn get_api_key_from_db(state: &AppState, token: &str) -> Option<Principal> {
    let db_cfg = state.config.database.as_ref()?;
    let url = format!("{}/sql", db_cfg.url.trim_end_matches('/'));

    let key_hash = short_hash(token);
    let query = format!(
        "SELECT project, role, rpm, allowed_models FROM api_key:{}",
        key_hash
    );

    match state
        .db_client
        .post(&url)
        .header("surreal-ns", &db_cfg.namespace)
        .header("surreal-db", &db_cfg.database)
        .header(reqwest::header::ACCEPT, "application/json")
        .basic_auth(&db_cfg.user, Some(&db_cfg.pass))
        .body(query)
        .send()
        .await
    {
        Ok(res) => {
            if res.status().is_success() {
                if let Ok(val) = res.json::<serde_json::Value>().await {
                    if let Some(result_arr) = val
                        .get(0)
                        .and_then(|v| v.get("result"))
                        .and_then(|v| v.as_array())
                    {
                        if let Some(row) = result_arr.first() {
                            let project_val = row.get("project")?;
                            let project_str = match project_val {
                                serde_json::Value::String(s) => {
                                    if s.starts_with("project:") {
                                        s.strip_prefix("project:").unwrap().to_string()
                                    } else {
                                        s.clone()
                                    }
                                }
                                _ => return None,
                            };
                            let role = row.get("role")?.as_str()?.to_string();
                            let rpm = row.get("rpm").and_then(|v| v.as_u64()).unwrap_or(120) as u32;
                            let allowed_models = row
                                .get("allowed_models")
                                .and_then(|v| v.as_array())
                                .map(|arr| {
                                    arr.iter()
                                        .filter_map(|m| m.as_str().map(ToString::to_string))
                                        .collect()
                                })
                                .unwrap_or_else(|| vec!["*".to_string()]);

                            return Some(Principal {
                                key_id: token.to_string(),
                                key_hash: short_hash(token),
                                project: project_str,
                                role,
                                allowed_models,
                                rpm,
                            });
                        }
                    }
                }
            }
            None
        }
        Err(err) => {
            tracing::error!(error = %err, token_id = %token, "failed to query static API key from SurrealDB");
            None
        }
    }
}

async fn get_project_secret(state: &AppState, project_id: &str) -> Option<String> {
    // 1. 메모리 캐시 1차 조회 (Read Lock)
    {
        let cache = state.project_secrets.read().await;
        if let Some((secret, created_at)) = cache.get(project_id) {
            if created_at.elapsed() < std::time::Duration::from_secs(300) {
                return Some(secret.clone());
            }
        }
    }

    // 2. DB 설정이 있으면 SurrealDB 조회
    if let Some(db_cfg) = &state.config.database {
        let url = format!("{}/sql", db_cfg.url.trim_end_matches('/'));
        let clean_id = project_id.replace(['\'', ':', ' '], "");
        let db_id = if clean_id.contains('-') {
            format!("⟨{}⟩", clean_id)
        } else {
            clean_id
        };
        let query = format!("SELECT jwt_secret FROM project:{}", db_id);

        match state
            .db_client
            .post(&url)
            .header("surreal-ns", &db_cfg.namespace)
            .header("surreal-db", &db_cfg.database)
            .header(reqwest::header::ACCEPT, "application/json")
            .basic_auth(&db_cfg.user, Some(&db_cfg.pass))
            .body(query)
            .send()
            .await
        {
            Ok(res) => {
                if res.status().is_success() {
                    if let Ok(val) = res.json::<serde_json::Value>().await {
                        if let Some(result_arr) = val
                            .get(0)
                            .and_then(|v| v.get("result"))
                            .and_then(|v| v.as_array())
                        {
                            if let Some(secret) = result_arr
                                .first()
                                .and_then(|v| v.get("jwt_secret"))
                                .and_then(|v| v.as_str())
                            {
                                let secret_str = secret.to_string();
                                // 캐시 적재 (Write Lock)
                                let mut cache = state.project_secrets.write().await;
                                cache.insert(
                                    project_id.to_string(),
                                    (secret_str.clone(), std::time::Instant::now()),
                                );
                                return Some(secret_str);
                            }
                        }
                    }
                }
                return None;
            }
            Err(err) => {
                tracing::error!(error = %err, project_id = %project_id, "failed to query project secret from SurrealDB");
            }
        }
    }

    // 3. DB가 없고 TOML Config 상의 기본 jwt.secret이 존재할 때의 폴백 (테스트 및 단일 연동용)
    if let Some(jwt_cfg) = &state.config.jwt {
        return Some(jwt_cfg.secret.clone());
    }

    None
}

async fn is_blacklisted(state: &AppState, token_id: &str) -> bool {
    let db_cfg = match &state.config.database {
        Some(cfg) => cfg,
        None => return false,
    };

    let url = format!("{}/sql", db_cfg.url.trim_end_matches('/'));
    let query = format!(
        "SELECT * FROM token_blacklist WHERE token_id = '{}' LIMIT 1",
        token_id.replace('\'', "''")
    );

    match state
        .db_client
        .post(&url)
        .header("surreal-ns", &db_cfg.namespace)
        .header("surreal-db", &db_cfg.database)
        .header(reqwest::header::ACCEPT, "application/json")
        .basic_auth(&db_cfg.user, Some(&db_cfg.pass))
        .body(query)
        .send()
        .await
    {
        Ok(res) => {
            if res.status().is_success() {
                if let Ok(val) = res.json::<serde_json::Value>().await {
                    if let Some(result_arr) = val
                        .get(0)
                        .and_then(|v| v.get("result"))
                        .and_then(|v| v.as_array())
                    {
                        return !result_arr.is_empty();
                    }
                }
            }
            false
        }
        Err(err) => {
            tracing::error!(error = %err, "failed to check token blacklist from SurrealDB");
            false
        }
    }
}

pub async fn authenticate(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Principal, AuthError> {
    let token = bearer_token(&headers).ok_or(AuthError::Missing)?;

    // [1단계: Memory Cache 조회]
    {
        let cache = state.api_key_cache.read().await;
        if let Some((principal, created_at)) = cache.get(token) {
            if created_at.elapsed() < std::time::Duration::from_secs(300) {
                state
                    .limiter
                    .check(&principal.key_id, principal.rpm)
                    .map_err(|_| AuthError::RateLimited)?;
                return Ok(principal.clone());
            }
        }
    }

    // [2단계: DB 조회]
    if let Some(principal) = get_api_key_from_db(&state, token).await {
        let mut cache = state.api_key_cache.write().await;
        cache.insert(
            token.to_string(),
            (principal.clone(), std::time::Instant::now()),
        );

        state
            .limiter
            .check(&principal.key_id, principal.rpm)
            .map_err(|_| AuthError::RateLimited)?;
        return Ok(principal);
    }

    // [3단계: Static Config Fallback 조회]
    if let Some(pc) = state.config.api_keys.get(token) {
        let principal = Principal {
            key_id: token.to_string(),
            key_hash: short_hash(token),
            project: pc.project.clone(),
            role: pc.role.clone(),
            allowed_models: pc.allowed_models.clone(),
            rpm: pc.rpm,
        };
        let mut cache = state.api_key_cache.write().await;
        cache.insert(
            token.to_string(),
            (principal.clone(), std::time::Instant::now()),
        );

        state
            .limiter
            .check(&principal.key_id, principal.rpm)
            .map_err(|_| AuthError::RateLimited)?;
        return Ok(principal);
    }

    // 1. 비검증 디코딩 (서명 없이 project 클레임 선파싱)
    let key = jsonwebtoken::DecodingKey::from_secret(&[]);

    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
    validation.insecure_disable_signature_validation();
    validation.validate_exp = false;
    validation.required_spec_claims.clear();

    let insecure_data =
        jsonwebtoken::decode::<Claims>(token, &key, &validation).map_err(|_| AuthError::Invalid)?;

    let project_id = insecure_data.claims.project.clone();

    // 2. 해당 프로젝트의 JWT Secret 획득 (캐시 또는 DB)
    let secret = get_project_secret(&state, &project_id)
        .await
        .ok_or(AuthError::Invalid)?;

    // 3. 획득한 Secret으로 정식 서명 및 만료 검증
    let decoding_key = jsonwebtoken::DecodingKey::from_secret(secret.as_bytes());
    let validation = jsonwebtoken::Validation::default();

    match jsonwebtoken::decode::<Claims>(token, &decoding_key, &validation) {
        Ok(token_data) => {
            let claims = token_data.claims;
            let token_identifier = claims.jti.clone().unwrap_or_else(|| short_hash(token));

            // 4. SurrealDB 블랙리스트 대조
            if is_blacklisted(&state, &token_identifier).await {
                return Err(AuthError::Invalid);
            }

            let principal = Principal {
                key_id: claims.sub.clone(),
                key_hash: short_hash(token),
                project: claims.project.clone(),
                role: claims.role.unwrap_or_else(|| "user".to_string()),
                allowed_models: claims.allowed_models.unwrap_or_default(),
                rpm: claims.rpm.unwrap_or(60),
            };

            state
                .limiter
                .check(&principal.key_id, principal.rpm)
                .map_err(|_| AuthError::RateLimited)?;
            Ok(principal)
        }
        Err(_) => Err(AuthError::Invalid),
    }
}

impl Principal {
    pub fn can_use_model(&self, model: &str) -> bool {
        self.allowed_models.is_empty()
            || self.allowed_models.iter().any(|allowed| allowed == model)
            || self.allowed_models.iter().any(|allowed| allowed == "*")
    }
}

impl RateLimiter {
    pub fn check(&self, key_id: &str, rpm: u32) -> Result<(), RateLimitError> {
        let mut windows = self
            .windows
            .lock()
            .map_err(|_| RateLimitError::LockPoisoned)?;
        let now = Instant::now();
        let window = windows.entry(key_id.to_string()).or_insert(Window {
            started_at: now,
            count: 0,
        });

        if now.duration_since(window.started_at) >= Duration::from_secs(60) {
            window.started_at = now;
            window.count = 0;
        }

        if window.count >= rpm {
            return Err(RateLimitError::Exceeded);
        }

        window.count += 1;
        Ok(())
    }
}

pub fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let raw = headers.get(AUTHORIZATION)?.to_str().ok()?;
    raw.strip_prefix("Bearer ").map(str::trim)
}

pub fn short_hash(raw: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw.as_bytes());
    let digest = hasher.finalize();
    format!("{:x}", digest)[..12].to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_without_returning_raw_key() {
        let hash = short_hash("sk-demo");
        assert_ne!(hash, "sk-demo");
        assert_eq!(hash.len(), 12);
    }

    #[test]
    fn allows_wildcard_model_policy() {
        let principal = Principal {
            key_id: "demo".into(),
            key_hash: "hash".into(),
            project: "demo".into(),
            role: "admin".into(),
            allowed_models: vec!["*".into()],
            rpm: 1,
        };
        assert!(principal.can_use_model("auto"));
    }

    #[test]
    fn enforces_rate_limit() {
        let limiter = RateLimiter::default();
        assert!(limiter.check("demo", 1).is_ok());
        assert!(limiter.check("demo", 1).is_err());
    }

    #[tokio::test]
    async fn detects_expired_and_blacklisted_tokens() {
        use crate::config::{
            GatewayConfig, LangfuseConfig, MemoryConfig, RouterConfig, SecurityConfig,
            ServerConfig, UpstreamConfig,
        };
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        // 1. 임시 Config 및 AppState 설정
        let jwt_secret = format!("unit-test-jwt-{}", "a".repeat(32));
        let config = GatewayConfig {
            server: ServerConfig {
                bind: "127.0.0.1:9099".parse().unwrap(),
            },
            upstream: UpstreamConfig {
                base_url: "http://localhost:14000".to_string(),
                api_key: None,
                timeout_seconds: 30,
                fallback_base_url: None,
                fallback_api_key: None,
            },
            security: SecurityConfig {
                max_prompt_chars: 1000,
                deny_prompt_injection: true,
                deny_secret_patterns: true,
                redact_pii: false,
                audit_log_path: "logs/test_audit.jsonl".into(),
                block_on_risk: false,
                deny_patterns: None,
            },
            memory: MemoryConfig::default(),
            langfuse: LangfuseConfig::default(),
            router: RouterConfig::default(),
            jwt: Some(crate::config::JwtConfig {
                secret: jwt_secret.clone(),
            }),
            database: None, // surrealdb 비활성화
            api_keys: Default::default(),
            models: Default::default(),
        };

        let state = AppState::new(config).unwrap();

        // 2. 유효한 단기 토큰 생성 및 검증
        let exp_future = (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize;
        let claims = Claims {
            sub: "user_test".to_string(),
            project: "test_proj".to_string(),
            role: Some("user".to_string()),
            allowed_models: Some(vec!["*".to_string()]),
            rpm: Some(10),
            exp: exp_future,
            jti: Some("test-jti-123".to_string()),
        };

        let token = encode(
            &Header::new(Algorithm::HS256),
            &claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .unwrap();

        // bearer token 검증
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());

        let res = authenticate(State(state.clone()), headers).await;
        assert!(res.is_ok());
        let principal = res.unwrap();
        assert_eq!(principal.key_id, "user_test");
        assert_eq!(principal.project, "test_proj");

        // 3. 만료된 토큰 생성 및 검증 (실패해야 함)
        let exp_past = (chrono::Utc::now() - chrono::Duration::minutes(5)).timestamp() as usize;
        let expired_claims = Claims {
            exp: exp_past,
            ..claims
        };
        let expired_token = encode(
            &Header::new(Algorithm::HS256),
            &expired_claims,
            &EncodingKey::from_secret(jwt_secret.as_bytes()),
        )
        .unwrap();

        let mut headers_expired = HeaderMap::new();
        headers_expired.insert(
            AUTHORIZATION,
            format!("Bearer {}", expired_token).parse().unwrap(),
        );

        let res_expired = authenticate(State(state.clone()), headers_expired).await;
        assert!(res_expired.is_err());
        assert!(matches!(res_expired.unwrap_err(), AuthError::Invalid));

        // 4. 블랙리스트 토큰 검사 동작 검증 (DB가 None인 경우 블랙리스트에 걸리지 않고 통과)
        let is_black = is_blacklisted(&state, "test-jti-123").await;
        assert!(!is_black); // DB가 None이므로 false 반환
    }

    #[tokio::test]
    async fn detects_multi_project_jwt_with_different_secrets() {
        use crate::config::{
            GatewayConfig, LangfuseConfig, MemoryConfig, RouterConfig, SecurityConfig,
            ServerConfig, UpstreamConfig,
        };
        use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

        // 1. JWT Secret을 미리 등록하기 위해 AppState에 직접 추가 (DB 조회 폴백 대신 캐시에 미리 적재)
        let config = GatewayConfig {
            server: ServerConfig {
                bind: "127.0.0.1:9099".parse().unwrap(),
            },
            upstream: UpstreamConfig {
                base_url: "http://localhost:14000".to_string(),
                api_key: None,
                timeout_seconds: 30,
                fallback_base_url: None,
                fallback_api_key: None,
            },
            security: SecurityConfig {
                max_prompt_chars: 1000,
                deny_prompt_injection: true,
                deny_secret_patterns: true,
                redact_pii: false,
                audit_log_path: "logs/test_audit.jsonl".into(),
                block_on_risk: false,
                deny_patterns: None,
            },
            memory: MemoryConfig::default(),
            langfuse: LangfuseConfig::default(),
            router: RouterConfig::default(),
            jwt: None,
            database: None,
            api_keys: Default::default(),
            models: Default::default(),
        };

        let state = AppState::new(config).unwrap();

        // 캐시(project_secrets)에 ProjectA 와 ProjectB 의 Secret을 다르게 적재
        let secret_a = format!("unit-test-project-a-{}", "a".repeat(32));
        let secret_b = format!("unit-test-project-b-{}", "b".repeat(32));
        {
            let mut cache = state.project_secrets.write().await;
            cache.insert(
                "ProjectA".to_string(),
                (secret_a.to_string(), Instant::now()),
            );
            cache.insert(
                "ProjectB".to_string(),
                (secret_b.to_string(), Instant::now()),
            );
        }

        // 2. ProjectA 용 정상 토큰 발행 및 검증
        let exp = (chrono::Utc::now() + chrono::Duration::minutes(5)).timestamp() as usize;
        let claims_a = Claims {
            sub: "user_a".to_string(),
            project: "ProjectA".to_string(),
            role: Some("user".to_string()),
            allowed_models: Some(vec!["*".to_string()]),
            rpm: Some(10),
            exp,
            jti: Some("jti-a".to_string()),
        };
        let token_a = encode(
            &Header::new(Algorithm::HS256),
            &claims_a,
            &EncodingKey::from_secret(secret_a.as_bytes()),
        )
        .unwrap();

        let mut headers_a = HeaderMap::new();
        headers_a.insert(
            AUTHORIZATION,
            format!("Bearer {}", token_a).parse().unwrap(),
        );
        let res_a = authenticate(State(state.clone()), headers_a).await;
        assert!(res_a.is_ok());

        // 3. ProjectA의 토큰을 ProjectB의 Secret으로 서명하여 전송 시 (실패해야 함)
        let token_a_bad = encode(
            &Header::new(Algorithm::HS256),
            &claims_a,
            &EncodingKey::from_secret(secret_b.as_bytes()), // 잘못된 Secret
        )
        .unwrap();

        let mut headers_a_bad = HeaderMap::new();
        headers_a_bad.insert(
            AUTHORIZATION,
            format!("Bearer {}", token_a_bad).parse().unwrap(),
        );
        let res_a_bad = authenticate(State(state.clone()), headers_a_bad).await;
        assert!(res_a_bad.is_err());
    }

    #[tokio::test]
    async fn detects_cache_ttl_expiration() {
        use crate::config::{
            GatewayConfig, LangfuseConfig, MemoryConfig, RouterConfig, SecurityConfig,
            ServerConfig, UpstreamConfig,
        };

        // 임시 설정 생성
        let fallback_secret = format!("unit-test-fallback-{}", "f".repeat(32));
        let cached_secret = format!("unit-test-cached-{}", "c".repeat(32));
        let config = GatewayConfig {
            server: ServerConfig {
                bind: "127.0.0.1:9099".parse().unwrap(),
            },
            upstream: UpstreamConfig {
                base_url: "http://localhost:14000".to_string(),
                api_key: None,
                timeout_seconds: 30,
                fallback_base_url: None,
                fallback_api_key: None,
            },
            security: SecurityConfig {
                max_prompt_chars: 1000,
                deny_prompt_injection: true,
                deny_secret_patterns: true,
                redact_pii: false,
                audit_log_path: "logs/test_audit.jsonl".into(),
                block_on_risk: false,
                deny_patterns: None,
            },
            memory: MemoryConfig::default(),
            langfuse: LangfuseConfig::default(),
            router: RouterConfig::default(),
            jwt: Some(crate::config::JwtConfig {
                secret: fallback_secret.clone(),
            }),
            database: None,
            api_keys: Default::default(),
            models: Default::default(),
        };

        let state = AppState::new(config).unwrap();

        // 1. 캐시에 엉뚱한 Secret을 얹고 즉시 조회 (캐시 히트 확인)
        {
            let mut cache = state.project_secrets.write().await;
            cache.insert(
                "ProjectA".to_string(),
                (cached_secret.clone(), Instant::now()),
            );
        }

        let secret = get_project_secret(&state, "ProjectA").await;
        assert_eq!(secret, Some(cached_secret));

        // 2. 캐시의 Instant 값을 300초 이전(예: 305초 전)으로 조작
        {
            let mut cache = state.project_secrets.write().await;
            if let Some(entry) = cache.get_mut("ProjectA") {
                entry.1 = Instant::now() - Duration::from_secs(305);
            }
        }

        // 캐시 만료로 인해 기본 설정 파일의 jwt.secret 값을 Fallback으로 가져오는지 검증
        let secret_expired = get_project_secret(&state, "ProjectA").await;
        assert_eq!(secret_expired, Some(fallback_secret));
    }

    #[tokio::test]
    async fn detects_static_api_key_bypass() {
        use crate::config::{
            GatewayConfig, LangfuseConfig, MemoryConfig, PrincipalConfig, RouterConfig,
            SecurityConfig, ServerConfig, UpstreamConfig,
        };

        // 1. static API Key를 포함한 Config 및 AppState 구성
        let mut api_keys = HashMap::new();
        api_keys.insert(
            "vercel-overfit-checker-prod".to_string(),
            PrincipalConfig {
                project: "overfit-checker".to_string(),
                role: "admin".to_string(),
                allowed_models: vec!["*".to_string()],
                rpm: 120,
            },
        );

        let config = GatewayConfig {
            server: ServerConfig {
                bind: "127.0.0.1:9099".parse().unwrap(),
            },
            upstream: UpstreamConfig {
                base_url: "http://localhost:14000".to_string(),
                api_key: None,
                timeout_seconds: 30,
                fallback_base_url: None,
                fallback_api_key: None,
            },
            security: SecurityConfig {
                max_prompt_chars: 1000,
                deny_prompt_injection: true,
                deny_secret_patterns: true,
                redact_pii: false,
                audit_log_path: "logs/test_audit.jsonl".into(),
                block_on_risk: false,
                deny_patterns: None,
            },
            memory: MemoryConfig::default(),
            langfuse: LangfuseConfig::default(),
            router: RouterConfig::default(),
            jwt: None,
            database: None,
            api_keys,
            models: Default::default(),
        };

        let state = AppState::new(config).unwrap();

        // 2. 등록된 static API Key로 인증 시도 시 성공적으로 Principal 반환 여부 검증
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            "Bearer vercel-overfit-checker-prod".parse().unwrap(),
        );

        let res = authenticate(State(state.clone()), headers).await;
        assert!(res.is_ok());
        let principal = res.unwrap();
        assert_eq!(principal.key_id, "vercel-overfit-checker-prod");
        assert_eq!(principal.project, "overfit-checker");
        assert_eq!(principal.role, "admin");

        // 3. 미등록 키로 인증 시도 시 실패(401 Invalid) 여부 검증
        let mut headers_invalid = HeaderMap::new();
        headers_invalid.insert(
            AUTHORIZATION,
            "Bearer unconfigured-api-key".parse().unwrap(),
        );
        let res_invalid = authenticate(State(state), headers_invalid).await;
        assert!(res_invalid.is_err());
        assert!(matches!(res_invalid.unwrap_err(), AuthError::Invalid));
    }
}
