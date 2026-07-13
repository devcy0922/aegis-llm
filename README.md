# AegisLLM

AegisLLM은 Rust(Axum)로 개발된 고성능 AI API 보안 게이트웨이 및 프록시 서비스입니다. LLM 엔드포인트로 들어오는 요청을 실시간 인터셉트하여 보안 정책 검증, 민감 정보(PII) 마스킹, API Key 인증 및 구조화된 감사 로그 기록을 수행합니다.

## 핵심 기능

- **Prompt 보안**: Prompt Injection 및 악성 우회 입력을 API 경계면에서 사전 차단.
- **데이터 유출 방지 (DLP)**: 이메일, 주민등록번호 등 PII 정보와 평문 API Key/Secret 자동 탐지 및 마스킹.
- **3-Tier 고속 인증**: 환경변수 Static Fallback, SurrealDB 조회, JWT 검증을 단계적으로 시도하는 독립 실행형 인증 필터.
- **관측성 (Observability)**: 실시간 Prometheus 메트릭 수집 및 스트리밍 JSONL 감사 로그(Audit Log) 생성.

---

## Prompt Injection Detection

`security.rs`의 `find_prompt_injection()` 함수가 키워드 패턴 매칭 방식으로 탐지합니다.

**탐지 방식**: 소문자 변환 후 고정 키워드 목록과 `contains` 비교 (O(n·m), 정규식 없음)

**기본 탐지 패턴 (영문)**

| 패턴 | 설명 |
|---|---|
| `ignore previous instructions` | 이전 지시 무력화 시도 |
| `ignore all previous instructions` | 전체 지시 초기화 시도 |
| `reveal your system prompt` | 시스템 프롬프트 유출 요청 |
| `print the hidden prompt` | 숨김 프롬프트 출력 요청 |
| `dump the system message` | 시스템 메시지 덤프 시도 |
| `show the developer message` | 개발자 메시지 노출 요청 |

**기본 탐지 패턴 (한국어)**

| 패턴 |
|---|
| `이전 지시를 무시` |
| `시스템 프롬프트를 공개` |
| `시스템 프롬프트를 출력` |
| `시스템 프롬프트 보여` |
| `숨겨진 프롬프트를 공개` |
| `숨겨진 프롬프트를 출력` |

**패턴 추가 방법**: `gateway.toml`의 `security.deny_patterns` 배열에 정규식(PCRE)을 추가하면 `find_deny_patterns()`가 호출됩니다.

```toml
[security]
deny_prompt_injection = true
deny_patterns = [
  "(?i)act as (root|admin|god)",
  "(?i)jailbreak"
]
```

탐지 시 요청은 즉시 `400 Bad Request`로 차단되며, Upstream으로 전달되지 않습니다.

---

## Rate Limiting (RPM per Key)

API Key별로 분당 요청 수(RPM)를 제한하는 슬라이딩 윈도우 방식으로 구현되어 있습니다 (`auth.rs`의 `RateLimiter`).

**동작 원리**

1. 각 Key Hash를 기준으로 `(시작 시각, 카운트)` 윈도우를 메모리에 유지
2. 60초 윈도우 내 카운트가 `rpm` 초과 시 `429 Too Many Requests` 반환
3. 윈도우 만료 시 자동 리셋

**설정 방법 (TOML)**

```toml
[api_keys.my-service-key]
project = "my-project"
role    = "user"
rpm     = 60          # 기본값: 120

[api_keys.admin-key]
project = "ops"
role    = "admin"
rpm     = 300
```

**환경변수 방식 (Static Fallback)**

```bash
# 형식: key:project:role:rpm
AEGIS_API_KEYS="mykey:myproject:user:60,adminkey:ops:admin:300"
```

---

## OpenAI API 호환성

`responses_adapter.rs`가 OpenAI Responses API(`/v1/responses`)를 `Chat Completions` 형식으로 변환하여 하위 호환성을 제공합니다.

**지원 엔드포인트**

| 엔드포인트 | HTTP 메서드 | 설명 |
|---|---|---|
| `/v1/chat/completions` | `POST` | Chat Completion 요청 인터셉트, 필터링 및 프록시 중계 |
| `/v1/responses` | `POST` | OpenAI Responses API → Chat Completions 자동 변환 |
| `/v1/embeddings` | `POST` | Embedding 요청 프록시 (PII 스캔 포함) |
| `/v1/models` | `GET` | 인증된 Key에 허용된 모델 목록 반환 |
| `/health` | `GET` | 서비스 활성 상태 확인 (Liveness probe) |
| `/metrics` | `GET` | Prometheus 텔레메트리 메트릭 반환 |

**Responses API 변환 범위**

- `input` 필드(문자열/배열) → `messages` 배열 변환
- `instructions` → `system` role 메시지 삽입
- Tool 정의의 `additionalProperties`, `strict` 필드 자동 제거 (호환성)
- 스트리밍(`stream: true`) 지원

---

## Error Handling

**Upstream 실패**

| 상황 | 응답 | 설명 |
|---|---|---|
| Upstream 연결 불가 | `502 Bad Gateway` | TCP 연결 실패, DNS 미해석 |
| Upstream Timeout | `504 Gateway Timeout` | `upstream.timeout_seconds` 초과 |
| Upstream 4xx/5xx | 원본 상태 코드 그대로 전달 | Upstream 오류를 투명하게 relay |
| 인증 실패 | `401 Unauthorized` | API Key 누락 또는 불일치 |
| RPM 초과 | `429 Too Many Requests` | Rate limit 도달 |
| 보안 정책 위반 | `400 Bad Request` | Injection 탐지, PII 차단 |

**Timeout 설정**

```toml
[upstream]
base_url        = "http://<your-llm-upstream>/v1"
timeout_seconds = 120   # 기본값
```

**감사 로그**: 모든 요청(차단 포함)은 `logs/audit.jsonl`에 JSONL 형식으로 기록됩니다.

```jsonc
{
  "trace_id": "a1b2c3d4",
  "ts": "2025-01-01T00:00:00Z",
  "project": "my-project",
  "model": "auto",
  "blocked": true,
  "block_reason": "prompt_injection",
  "latency_ms": 2
}
```

---

## 빌드 및 실행

### 로컬 실행
```bash
cargo run --release -- --config configs/gateway.toml
```

### Docker 실행
```bash
docker build -t aegis-llm .
docker run -p 8080:8080 \
  -v ./configs/gateway.toml:/app/configs/gateway.toml \
  aegis-llm
```

---

## 환경 변수 설정

| 변수 | 설명 |
|---|---|
| `GOVAIL_CONFIG` | 불러올 TOML 설정 파일 경로 (기본: `configs/gateway.example.toml`) |
| `AEGIS_API_KEYS` | 쉼표 구분 정적 API Key (형식: `key:project:role[:rpm]`) |
| `RUST_LOG` | 로그 레벨 (기본: `aegis_llm=info,tower_http=info`) |

---

## 아키텍처 의사결정 기록

설계 배경과 트레이드오프는 [`docs/adr/`](docs/adr/) 디렉토리를 참고하세요.

- [ADR-001](docs/adr/ADR-001-rust-axum.md) — Rust + Axum 선택 근거
- [ADR-002](docs/adr/ADR-002-3tier-auth.md) — 3-Tier 인증 설계
- [ADR-003](docs/adr/ADR-003-injection-detection.md) — Prompt Injection 탐지 전략
