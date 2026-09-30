# [요구사항 명세서] Security Sub-Agent: A2A 프로토콜, 다중 진입점(Multi-Interface) 및 가변 DB Checkpointer 구축

기존 Python LangGraph 기반 Security Sub-Agent를 **3가지 진입점(Orchestrator, Web DevOps 플랫폼 UI, 자체 독립 Chat UI)**에서 모두 호출 가능하도록 개편하고, **가변 DB 대화 기록 저장소(PostgreSQL/SQLite)**를 적용해주세요.

---

## 1. 3가지 진입점(Interface) 요구사항

Security Sub-Agent는 동일한 LangGraph 비즈니스 로직을 공유하면서, 아래 3가지 경로로 요청을 처리해야 합니다:

1. **A2A Protocol (Orchestrator 에이전트 연동)**
   - Orchestrator가 Sub-Agent의 스킬을 탐색할 수 있도록 `AgentCard` 메타데이터 작성
   - `TaskRequest` 수신 시 LangGraph 실행 후 `TaskResponse`로 응답하는 A2A Task Handler 구현
   - `a2a-sdk` 기반 `AgentServer` 연동

2. **REST API (기존 Web DevOps 플랫폼 UI 연동)**
   - 외부 웹 플랫폼(React/Vue 등) 백엔드/프론트엔드에서 호출 가능한 REST API 엔드포인트(`POST /api/chat`) 제공
   - Request Body로 `thread_id`와 `message`를 받아 분석 결과 반환

3. **Built-in Standalone Chat UI (단독 로컬 테스트용 UI)**
   - 개발 및 로컬 테스트 목적의 경량 웹 Chat UI 서빙 (`GET /ui`)
   - 브라우저에서 직접 접속해 웹 화면 상에서 메시지를 입력하고 즉시 답변을 확인할 수 있는 HTML/JS 페이지 및 테스트 전용 통신 인터페이스 제공

> **통합 서빙**: 위 3가지 엔드포인트(A2A, REST API, Standalone UI)는 **단일 FastAPI 애플리케이션(동일 포트, 예: 8001)**으로 통합 구동되어야 합니다.

---

## 2. DB Checkpointer 및 세션 관리 요구사항

1. **환경 변수(.env) 기반 가변 DB Checkpointer (PostgreSQL <-> SQLite)**
   - 대화 맥락/기록 저장을 위해 `.env` 환경 변수 설정에 따라 DB 저장소를 유연하게 전환:
     * `USE_POSTGRES=true` (또는 `POSTGRES_URL` 존재 시): `langgraph-checkpoint-postgres` (`AsyncPostgresSaver`) 연동
     * `USE_POSTGRES=false` (또는 미설정/OFF 시): 별도 DB 서버 없이 내장 SQLite (`langgraph-checkpoint-sqlite`의 `AsyncSqliteSaver`)로 Fallback 하여 로컬 파일(`checkpoints.db`)에 저장
   - 서버 시작 시(`startup`) 선택된 DB의 Checkpointer 테이블 자동 생성 (`await checkpointer.setup()`)

2. **`thread_id` 기반 세션/맥락 독립 관리**
   - 진입점 종류와 상관없이 요청에 포함된 `thread_id`를 LangGraph execution `config` (`{"configurable": {"thread_id": thread_id}}`)에 매핑하여 사용자/세션별 대화 맥락 분리 및 영구 저장

---

## 3. 세부 구현 가이드 및 모듈 구조

- **주요 패키지**: `a2a-sdk`, `langgraph`, `langgraph-checkpoint-postgres`, `langgraph-checkpoint-sqlite`, `psycopg[binary]`, `psycopg-pool`, `python-dotenv`, `uvicorn`, `fastapi`
- **실행 및 처리 흐름**:
  1. `.env` 파싱 후 PostgreSQL 또는 SQLite Checkpointer 객체 반환 함수 작성
  2. LangGraph 핵심 그래프 구조 정의 (`StateGraph`)
  3. `AgentCard` 작성 및 A2A Task Handler 구현
  4. `AgentServer` 생성 후 내장된 FastAPI `app` 인스턴스 추출
  5. FastAPI `app`에 추가 라우트 구현:
     - `GET /ui`: 로컬 테스트용 자체 Chat UI HTML 서빙
     - `POST /api/chat`: Web DevOps 플랫폼용 REST API
  6. FastAPI `startup` 이벤트에서 선택된 Checkpointer 초기화 (`await checkpointer.setup()`)
  7. `uvicorn` 실행 구문 작성

---

위 요구사항에 맞춰, 3가지 진입점을 모두 지원하고 환경 변수에 따라 DB 저장을 가변 처리하는 전체 Python 코드를 작성해 주세요.