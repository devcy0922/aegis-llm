# ADR-001: Rust + Axum 채택

| 항목 | 내용 |
|---|---|
| **상태** | 승인됨 |
| **결정일** | 2024-12 |
| **결정자** | 프로젝트 아키텍트 |

---

## 컨텍스트

AI API 게이트웨이는 LLM Upstream 앞단에서 **모든 요청을 동기적으로 인터셉트**합니다. 요구사항:

- 요청당 수십~수백 ms의 PII 스캔, 인증, 로깅을 부가 레이턴시 최소화로 처리
- 단일 바이너리 배포 (컨테이너 이미지 최소화)
- 메모리 안전성: Unsafe 코드 없이 운영 중 패닉·UAF 제거
- async I/O: LLM 스트리밍 응답(`text/event-stream`) 처리

## 검토한 대안

| 옵션 | 장점 | 단점 |
|---|---|---|
| **Go + Echo** | 빠른 개발, 익숙한 생태계 | GC 지연, goroutine 오버헤드 |
| **Python + FastAPI** | 생태계 풍부, 빠른 프로토타이핑 | GIL, 런타임 타입 오류, 느린 처리량 |
| **Node.js + Fastify** | JavaScript 생태계, 빠른 I/O | 단일 스레드 CPU 병목, 타입 안전성 부족 |
| **Rust + Axum** ✅ | Zero-cost abstraction, 컴파일 타임 안전성, Tokio async | 높은 초기 학습 비용, 느린 빌드 |

## 결정

**Rust + Axum + Tokio** 조합을 채택합니다.

### 근거

1. **Zero-cost abstraction**: 고수준 추상화(미들웨어 체인, 타입 안전 State 공유)를 런타임 오버헤드 없이 표현
2. **컴파일 타임 안전성**: 소유권·수명 체계로 데이터 레이스, 메모리 오류를 빌드 단계에서 차단
3. **Tokio 비동기 런타임**: LLM 스트리밍 응답의 청크 단위 프록시를 Future 체인으로 자연스럽게 처리
4. **단일 바이너리**: Alpine 기반 이미지에서 외부 런타임 의존성 없이 `~20 MB` 이미지 구성 가능
5. **Axum 타입 안전 라우터**: `State<T>` 추출자로 `AppState`를 Arc 공유하며 핸들러 간 컴파일 타임 타입 검증

## 트레이드오프 수용

- 초기 개발 속도는 Go/Python 대비 느림 → 게이트웨이의 기능 표면적이 좁아 문제없음
- 빌드 시간이 긺 (`cargo build --release` 수 분) → Docker 레이어 캐시로 CI에서 완화

## 결과

현재 `main.rs`, `proxy.rs`, `security.rs`, `auth.rs`가 Axum 기반으로 구현되어 있으며, 추가 비용 없이 Tower 미들웨어 체인을 확장할 수 있습니다.
