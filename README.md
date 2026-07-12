# AegisLLM

AegisLLM은 Rust(Axum)로 개발된 고성능 AI API 보안 게이트웨이 및 프록시 서비스입니다. LLM 엔드포인트로 들어오는 요청을 실시간 인터셉트하여 보안 정책 검증, 민감 정보(PII) 마스킹, API Key 인증 및 구조화된 감사 로그 기록을 수행합니다.

## 핵심 기능

- **프롬프트 보안**: 프롬프트 인젝션 및 악성 우회 입력을 API 경계면에서 사전 차단.
- **데이터 유출 방지 (DLP)**: 이메일, 주민등록번호 등 PII 정보와 평문 API Key/Secret 자동 탐지 및 마스킹.
- **3-Tier 고속 인증**: 외부 DB 연동 없이 환경변수(`AEGIS_API_KEYS`)의 static fallback 설정만으로 가동 가능한 독립 실행형 인증 필터.
- **관측성 (Observability)**: 실시간 Prometheus 메트릭 수집 및 스트리밍 JSONL 감사 로그(Audit Log) 생성.

## API 명세

| 엔드포인트 | HTTP 메서드 | 설명 |
|---|---|---|
| `/v1/chat/completions` | `POST` | Chat Completion 요청 인터셉트, 필터링 및 프록시 중계 |
| `/v1/models` | `GET` | 권한이 허용된 모델 목록 반환 |
| `/health` | `GET` | 서비스 활성 상태 확인 (Liveness probe) |
| `/metrics` | `GET` | Prometheus 텔레메트리 메트릭 반환 |

## 빌드 및 실행

### 로컬 실행
```bash
cargo run --release -- --config configs/gateway.toml
```

### Docker 실행
```bash
docker build -t aegis-llm .
docker run -p 8080:8080 -v ./configs/gateway.toml:/app/configs/gateway.toml aegis-llm
```

## 환경 변수 설정

- `AEGIS_CONFIG`: 불러올 TOML 설정 파일 경로.
- `AEGIS_API_KEYS`: 쉼표로 구분된 인증 키 (형식: `key:project:role[:rpm]`).
