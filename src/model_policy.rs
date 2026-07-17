use serde_json::Value;

use crate::config::{GatewayConfig, ModelCapability};

/// 기본 Capability: 명시되지 않은 모델은 thinking 지원을 가정합니다 (안전 폴백).
const DEFAULT_CAPABILITY: ModelCapability = ModelCapability {
    thinking_supported: true,
    speed_tier: None,
};

/// LiteLLM 슬롯명(model)으로 capability를 조회합니다.
///
/// 조회 우선순위:
/// 1. 정확한 슬롯명 일치 (예: "fast", "large")
/// 2. 와일드카드 폴백 ("*")
/// 3. 내장 기본값 (thinking_supported = true)
pub fn resolve_capability<'a>(config: &'a GatewayConfig, model: &str) -> &'a ModelCapability {
    if let Some(cap) = config.models.get(model) {
        return cap;
    }
    if let Some(cap) = config.models.get("*") {
        return cap;
    }
    &DEFAULT_CAPABILITY
}

/// 모델 capability에 따라 미지원 파라미터를 payload에서 제거합니다.
///
/// thinking_supported = false 인 경우 아래 파라미터를 제거합니다:
/// - `thinking`           (Anthropic 스타일)
/// - `reasoning_effort`   (OpenAI o1/o3 스타일)
/// - `reasoning_summary`  (OpenAI 스타일)
/// - `enable_thinking`    (커스텀 확장)
/// - `thinking_budget`    (커스텀 확장)
///
/// 제거된 파라미터 목록을 반환합니다 (감사 로그용).
pub fn strip_unsupported_params(payload: &mut Value, cap: &ModelCapability) -> Vec<&'static str> {
    if cap.thinking_supported {
        return vec![];
    }

    const THINKING_PARAMS: &[&str] = &[
        "thinking",
        "reasoning_effort",
        "reasoning_summary",
        "enable_thinking",
        "thinking_budget",
    ];

    let Some(obj) = payload.as_object_mut() else {
        return vec![];
    };

    let mut stripped = vec![];
    for &param in THINKING_PARAMS {
        if obj.remove(param).is_some() {
            stripped.push(param);
        }
    }
    stripped
}

/// thinking_supported = false 인 모델에 대해 LiteLLM으로 전달되는 payload에
/// `extra_body.chat_template_kwargs.enable_thinking = false` 를 자동 주입합니다.
///
/// 이미 `extra_body` 키가 존재하는 경우 기존 값을 유지하며 덮어쓰지 않습니다.
/// 단, `enable_thinking` 키가 명시되지 않은 경우에만 주입합니다.
///
/// # 적용 대상
/// - `thinking_supported = false` 인 모든 모델 슬롯
///   (예: `fast`, `overfit-checker`)
///
/// # 적용 제외
/// - `thinking_supported = true` 인 모델 (예: `large`, `auto`)
pub fn inject_extra_body(payload: &mut Value, cap: &ModelCapability) {
    if cap.thinking_supported {
        // thinking 지원 모델은 extra_body 주입 불필요
        return;
    }

    let Some(obj) = payload.as_object_mut() else {
        return;
    };

    // extra_body가 없으면 빈 객체로 초기화
    let extra_body = obj
        .entry("extra_body")
        .or_insert_with(|| serde_json::json!({}));

    let Some(extra_body_obj) = extra_body.as_object_mut() else {
        return;
    };

    // chat_template_kwargs가 없으면 빈 객체로 초기화
    let kwargs = extra_body_obj
        .entry("chat_template_kwargs")
        .or_insert_with(|| serde_json::json!({}));

    let Some(kwargs_obj) = kwargs.as_object_mut() else {
        return;
    };

    // enable_thinking이 이미 명시된 경우 덮어쓰지 않음
    kwargs_obj
        .entry("enable_thinking")
        .or_insert(serde_json::json!(false));
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use super::*;
    use crate::config::ModelCapability;

    fn make_config(models: HashMap<String, ModelCapability>) -> GatewayConfig {
        use crate::config::{
            DatabaseConfig, JwtConfig, LangfuseConfig, MemoryConfig, RouterConfig, SecurityConfig,
            ServerConfig, UpstreamConfig,
        };
        use std::net::SocketAddr;
        use std::path::PathBuf;

        GatewayConfig {
            server: ServerConfig {
                bind: "0.0.0.0:8080".parse::<SocketAddr>().unwrap(),
            },
            upstream: UpstreamConfig {
                base_url: "http://litellm:14000".to_string(),
                api_key: None,
                timeout_seconds: 30,
                fallback_base_url: None,
                fallback_api_key: None,
            },
            security: SecurityConfig {
                max_prompt_chars: 20_000,
                deny_prompt_injection: true,
                deny_secret_patterns: true,
                redact_pii: false,
                audit_log_path: PathBuf::from("logs/audit.jsonl"),
                block_on_risk: false,
                deny_patterns: None,
            },
            memory: MemoryConfig::default(),
            langfuse: LangfuseConfig::default(),
            router: RouterConfig::default(),
            jwt: Some(JwtConfig {
                secret: format!("unit-test-jwt-{}", "m".repeat(32)),
            }),
            database: None::<DatabaseConfig>,
            api_keys: HashMap::new(),
            models,
        }
    }

    #[test]
    fn thinking_params_stripped_for_fast_model() {
        let mut models = HashMap::new();
        models.insert(
            "fast".to_string(),
            ModelCapability {
                thinking_supported: false,
                speed_tier: Some("fast".to_string()),
            },
        );
        let config = make_config(models);
        let cap = resolve_capability(&config, "fast");

        let mut payload = json!({
            "model": "fast",
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": {"type": "enabled", "budget_tokens": 1000},
            "reasoning_effort": "high",
            "enable_thinking": true
        });

        let stripped = strip_unsupported_params(&mut payload, cap);

        assert!(
            payload.get("thinking").is_none(),
            "thinking 파라미터가 제거되어야 함"
        );
        assert!(
            payload.get("reasoning_effort").is_none(),
            "reasoning_effort가 제거되어야 함"
        );
        assert!(
            payload.get("enable_thinking").is_none(),
            "enable_thinking이 제거되어야 함"
        );
        assert!(
            payload.get("messages").is_some(),
            "messages는 유지되어야 함"
        );
        assert_eq!(
            stripped,
            vec!["thinking", "reasoning_effort", "enable_thinking"]
        );
    }

    #[test]
    fn thinking_params_kept_for_large_model() {
        let mut models = HashMap::new();
        models.insert(
            "large".to_string(),
            ModelCapability {
                thinking_supported: true,
                speed_tier: Some("quality".to_string()),
            },
        );
        let config = make_config(models);
        let cap = resolve_capability(&config, "large");

        let mut payload = json!({
            "model": "large",
            "messages": [{"role": "user", "content": "hi"}],
            "thinking": {"type": "enabled", "budget_tokens": 2000}
        });

        let stripped = strip_unsupported_params(&mut payload, cap);

        assert!(
            payload.get("thinking").is_some(),
            "large 모델은 thinking 유지되어야 함"
        );
        assert!(stripped.is_empty(), "strip 없어야 함");
    }

    #[test]
    fn wildcard_fallback_allows_thinking() {
        let mut models = HashMap::new();
        models.insert(
            "*".to_string(),
            ModelCapability {
                thinking_supported: true,
                speed_tier: None,
            },
        );
        let config = make_config(models);
        let cap = resolve_capability(&config, "unknown-model");

        let mut payload = json!({
            "model": "unknown-model",
            "thinking": {"type": "enabled"}
        });

        let stripped = strip_unsupported_params(&mut payload, cap);
        assert!(
            payload.get("thinking").is_some(),
            "와일드카드 폴백은 thinking 허용"
        );
        assert!(stripped.is_empty());
    }

    #[test]
    fn default_fallback_allows_thinking_when_no_config() {
        let config = make_config(HashMap::new());
        let cap = resolve_capability(&config, "any-model");

        assert!(
            cap.thinking_supported,
            "설정 없는 모델은 기본적으로 thinking 허용"
        );
    }

    #[test]
    fn strip_is_noop_on_non_object_payload() {
        let cap = ModelCapability {
            thinking_supported: false,
            speed_tier: None,
        };
        let mut payload = json!("not an object");
        let stripped = strip_unsupported_params(&mut payload, &cap);
        assert!(stripped.is_empty());
    }

    // ── inject_extra_body 테스트 ──────────────────────────────────────

    #[test]
    fn inject_extra_body_adds_enable_thinking_false_for_non_thinking_model() {
        // thinking_supported=false인 모델에 extra_body 주입 확인
        let cap = ModelCapability {
            thinking_supported: false,
            speed_tier: Some("fast".to_string()),
        };
        let mut payload = json!({
            "model": "overfit-checker",
            "messages": [{"role": "user", "content": "analyze this"}]
        });

        inject_extra_body(&mut payload, &cap);

        let enable_thinking = payload
            .get("extra_body")
            .and_then(|eb| eb.get("chat_template_kwargs"))
            .and_then(|k| k.get("enable_thinking"));

        assert_eq!(
            enable_thinking,
            Some(&json!(false)),
            "overfit-checker 모델은 enable_thinking=false가 주입되어야 함"
        );
        // 기존 messages 보존 확인
        assert!(
            payload.get("messages").is_some(),
            "messages는 유지되어야 함"
        );
    }

    #[test]
    fn inject_extra_body_noop_for_thinking_model() {
        // thinking_supported=true인 모델은 extra_body 주입 안 함
        let cap = ModelCapability {
            thinking_supported: true,
            speed_tier: Some("quality".to_string()),
        };
        let mut payload = json!({
            "model": "large",
            "messages": [{"role": "user", "content": "analyze this"}]
        });

        inject_extra_body(&mut payload, &cap);

        assert!(
            payload.get("extra_body").is_none(),
            "thinking 지원 모델은 extra_body를 주입하지 않아야 함"
        );
    }

    #[test]
    fn inject_extra_body_does_not_overwrite_existing_enable_thinking() {
        // 이미 enable_thinking이 있으면 덮어쓰지 않음
        let cap = ModelCapability {
            thinking_supported: false,
            speed_tier: None,
        };
        let mut payload = json!({
            "model": "fast",
            "messages": [{"role": "user", "content": "hi"}],
            "extra_body": {
                "chat_template_kwargs": {
                    "enable_thinking": true
                }
            }
        });

        inject_extra_body(&mut payload, &cap);

        let enable_thinking = payload
            .get("extra_body")
            .and_then(|eb| eb.get("chat_template_kwargs"))
            .and_then(|k| k.get("enable_thinking"));

        // 이미 true로 명시된 경우 변경하지 않음
        assert_eq!(
            enable_thinking,
            Some(&json!(true)),
            "이미 명시된 enable_thinking 값은 덮어쓰지 않아야 함"
        );
    }

    #[test]
    fn inject_extra_body_preserves_existing_extra_body_fields() {
        // 기존 extra_body의 다른 필드는 유지됨
        let cap = ModelCapability {
            thinking_supported: false,
            speed_tier: None,
        };
        let mut payload = json!({
            "model": "overfit-checker",
            "extra_body": {
                "some_other_param": "value",
                "chat_template_kwargs": {}
            }
        });

        inject_extra_body(&mut payload, &cap);

        assert_eq!(
            payload
                .get("extra_body")
                .and_then(|eb| eb.get("some_other_param")),
            Some(&json!("value")),
            "기존 extra_body 필드는 유지되어야 함"
        );
        assert_eq!(
            payload
                .get("extra_body")
                .and_then(|eb| eb.get("chat_template_kwargs"))
                .and_then(|k| k.get("enable_thinking")),
            Some(&json!(false)),
            "enable_thinking이 주입되어야 함"
        );
    }
}
