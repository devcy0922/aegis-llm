# ADR-003: Prompt Injection 탐지 전략

| 항목 | 내용 |
|---|---|
| **상태** | 승인됨 (v1), Tier-2 LLM Judge 검토 중 |
| **결정일** | 2024-12 |
| **결정자** | 프로젝트 아키텍트 |

---

## 컨텍스트

LLM 게이트웨이는 모든 요청을 실시간으로 필터링해야 합니다. Prompt Injection 탐지 방식은 크게 세 가지로 분류됩니다.

| 방식 | 설명 | 레이턴시 | 정확도 | 비용 |
|---|---|---|---|---|
| **Keyword/Regex** | 고정 패턴 목록 대조 | ~0.1 ms | 낮음 (우회 가능) | 없음 |
| **LLM Judge** | 별도 LLM이 악의성 판정 | 500~2000 ms | 높음 | LLM 비용 추가 |
| **Semantic Similarity** | 악성 프롬프트 임베딩 DB와 유사도 비교 | 10~50 ms | 중간 | 임베딩 모델 필요 |

## 결정

**v1: Keyword + Regex 방식** 채택 (현재 구현)

향후 **Tier-2 LLM Judge**를 선택적으로 활성화하는 방향으로 확장 예정.

## 근거

### Keyword 방식을 우선 채택한 이유

1. **레이턴시 제로에 가까움**: 게이트웨이의 핵심 지표는 추가 레이턴시입니다. 키워드 매칭은 `~0.1 ms`로 LLM 응답 시간(수백~수천 ms)에 비해 무시 가능합니다.
2. **비용 없음**: LLM Judge는 요청당 토큰 비용이 발생하며, 게이트웨이를 통과하는 모든 요청에 적용하면 비용이 급증합니다.
3. **의존성 없음**: Upstream LLM 장애 시에도 Injection 탐지는 독립적으로 동작합니다.
4. **운영 가시성**: 차단된 패턴이 감사 로그에 그대로 기록되어 어떤 규칙이 발동했는지 추적 가능합니다.

### 알려진 한계

- **우회 가능성**: Base64 인코딩, 공백 삽입, 유사어 치환 등으로 패턴을 회피할 수 있습니다.
- **false negative**: 신규 공격 벡터는 패턴 업데이트 전까지 탐지 불가합니다.
- **false positive 위험**: "이전 지시를 무시" 같은 패턴이 기술 문서에서도 등장할 수 있습니다 → 현재 구현은 소문자 full-match로 오탐을 최소화.

## v1 구현 상세

```
scan_chat_payload()
  ├── extract_prompt_text()       # messages[].content 또는 input 필드 추출
  ├── find_prompt_injection()     # 고정 키워드 12종 (EN 6 + KO 6)
  ├── find_secret_patterns()      # GitHub Token, OpenAI Key, AWS Key, PEM Key
  └── find_deny_patterns()        # TOML/환경변수로 주입된 사용자 정의 정규식
```

**지원 입력 형식**: `messages` 배열(Chat), `input` 문자열/배열(Embeddings/Responses API)

## 향후 확장 계획 (v2)

```toml
[security]
injection_tiers = ["keyword", "llm_judge"]   # 단계별 탐지
llm_judge_threshold = 0.85                   # 신뢰도 임계값
llm_judge_model    = "fast"                  # 경량 모델 지정
```

- Tier-1(Keyword)이 통과한 요청만 Tier-2(LLM Judge)로 전달 → 비용 최소화
- LLM Judge 결과는 캐시하여 동일 패턴 반복 시 재사용

## 관련 코드

- `src/security.rs`: `scan_chat_payload()`, `find_prompt_injection()`, `find_deny_patterns()`
- `src/config.rs`: `SecurityConfig`
