# Security Agent v2 운영자 인수인계

## 1. 시스템 개요

Python 3.12+와 LangGraph로 구현한 보안 업무용 에이전트입니다. 저장소 조회, 패키지 관리, 보안 점검 요청을 하나의 그래프에서 처리하고, 대화 상태는 SQLite 또는 PostgreSQL checkpointer에 저장합니다.

### 지원 인터페이스

| 인터페이스 | 경로 | 용도 |
| --- | --- | --- |
| Chainlit Chat UI | `GET /ui` | 개발자/운영자가 브라우저에서 채팅합니다. Chainlit의 **New Chat**으로 새 채팅방을 생성합니다. |
| REST API | `POST /api/chat` | 기존 Web DevOps 플랫폼 등에서 호출합니다. |
| A2A | `POST /` | Orchestrator가 A2A JSON-RPC `message/send`로 에이전트를 호출합니다. |
| Agent Card | `GET /.well-known/agent-card.json` | A2A 에이전트와 스킬 메타데이터를 조회합니다. |
| Health | `GET /health` | 프로세스와 그래프 초기화 상태를 확인합니다. |

모든 인터페이스는 단일 FastAPI 프로세스/포트에서 제공합니다. Chainlit 화면은 FastAPI의 `/ui`에 마운트됩니다.

## 2. 아키텍처와 대화 흐름

```text
Chainlit / REST / A2A
          │
          ▼
     run_chat()
          │
          ▼
 LangGraph StateGraph
   ├─ Intent Classifier (START 직후, 단일 category 구조화 분류)
   ├─ 의도별 빠른 안내 또는 초기 컨텍스트 조회
   ├─ Supervisor 라우팅
   └─ 저장소 / 패키지 / 보안 점검 Agent
          │
          ▼
 SQLite AsyncSqliteSaver  또는  PostgreSQL AsyncPostgresSaver
```

- `graph.py`: 입력 분류 노드를 `START` 직후 실행하고, 분류 결과에 따라 안내 노드 또는 컨텍스트/Supervisor 업무 흐름으로 라우팅합니다. CLI와 기존 테스트는 계속 메모리 saver를 사용합니다.
- `intent_classifier_node.py`: LLM이 최신 사용자 메시지의 의미와 문맥을 해석해 기능 안내, 저장소/패키지, SCA/Secret, 결과 조회, 미지원 SAST/CI 요청 등을 단일 category로 분류하고 해당 전문 Agent로 라우팅합니다. 기본은 LLM의 Pydantic structured output이며, 결정적 규칙 분류는 `ENABLE_LLM_ROUTER=false`로 명시한 경우에만 사용합니다. LLM 자격 증명/provider 설정 오류는 숨기거나 규칙 결과로 대체하지 않습니다.
- `api.py`: HTTP 앱과 lifespan을 관리합니다. 서버 시작 시 DB 연결, checkpointer `setup()` 및 영구 그래프 컴파일을 완료한 뒤 요청을 받습니다.
- `chat.py`: REST와 A2A가 공유하는 비동기 대화 실행 경로입니다. 일시 중단된 HITL 그래프는 같은 thread에서 입력을 이어받습니다.
- `chainlit_app.py`: 새 UI 채팅이 시작될 때 UUID `thread_id`를 만들고 Chainlit 세션에 보관합니다. 해당 방의 각 메시지는 같은 ID로 LangGraph에 전달됩니다.
- `public/message-history.js`: 현재 방의 전송 메시지를 탭 session storage에 보관하고, 입력창에서 ↑/↓로 이전/다음 입력을 불러옵니다. 방이 바뀌면 thread ID별 기록을 분리하며, 기록이 없으면 입력을 변경하지 않습니다.
- A2A는 명시적 `thread_id` 메타데이터를 받으면 그것을 사용하고, 없으면 A2A `contextId`로 대화 맥락을 분리합니다.
- Supervisor는 기능/입력 가이드, 미지원 SAST 및 CI/CD·PR 상태 확인을 지원 안내 경로로 분기합니다. 결과 조회는 이전 대화의 선택 대상이나 스캔 실행 여부에 의존하지 않고 매번 MCP의 접근 가능 제품을 확인한 뒤 결과가 필요한 대상을 선택합니다. 조치/보고서도 저장된 스캔 결과만 사용하며 새 스캔을 임의 실행하지 않습니다.

서버 모드 대화 이력은 checkpointer에 저장됩니다. Chainlit 자체의 사용자 인증 및 별도 UI 대화 목록용 data layer는 설정되어 있지 않으므로, 화면의 과거 채팅방 목록/복구 기능은 제공하지 않습니다. 저장된 LangGraph thread는 DB에 남아 있지만, 운영 환경에서 여러 사용자가 접근하거나 UI에서 이전 방을 다시 여는 기능이 필요하면 인증·인가와 Chainlit data layer 또는 별도 방 목록/복구 기능을 먼저 연결해야 합니다.

## 3. 사전 준비 및 설치

- Python `3.12` 이상
- [uv](https://docs.astral.sh/uv/)
- 기본 DB는 로컬 SQLite입니다. PostgreSQL을 쓰는 경우 접근 가능한 PostgreSQL 서버와 DB가 필요합니다.
- 에이전트의 실제 업무 연동에 필요한 LLM/API 자격 증명 및 백엔드 연결 설정

저장소 루트에서 의존성을 설치합니다.

```powershell
uv sync
```

`pyproject.toml`과 `uv.lock`을 함께 관리합니다. 의존성 변경 후 lock 파일을 갱신하고 커밋하기 전에 `uv lock --check`를 확인하세요.
Windows에서는 서버 실행 파일을 업데이트하는 동안 실행 중인 `security-agent-v2-server`가 파일을 잠글 수 있습니다. 의존성 동기화 전에 해당 서버를 정상 종료하세요.

## 4. 환경 변수 설정

저장소 루트의 `.env` 또는 실행 환경 변수를 사용합니다. `.env`는 비밀값을 포함할 수 있으므로 저장소에 커밋하지 마세요.

### 기본 SQLite 구성

별도 DB 설정이 없으면 `checkpoints.db`를 사용합니다.

```dotenv
USE_POSTGRES=false
SQLITE_CHECKPOINT_PATH=checkpoints.db
HOST=127.0.0.1
PORT=8001
```

SQLite 경로는 상대 경로 또는 절대 경로로 지정할 수 있습니다. 상대 경로는 프로세스의 현재 작업 디렉터리를 기준으로 합니다.

### PostgreSQL 구성

```dotenv
USE_POSTGRES=true
POSTGRES_URL=postgresql://<user>:<password>@<host>:5432/<database>
```

- `USE_POSTGRES=true`이면 `POSTGRES_URL`이 필수입니다. 연결/설정 실패 시 서버 시작에 실패하며 SQLite로 조용히 전환하지 않습니다.
- `USE_POSTGRES=false`이면 `POSTGRES_URL`이 있어도 SQLite를 사용합니다.
- `USE_POSTGRES`를 생략하면 `POSTGRES_URL`이 설정된 경우 PostgreSQL을, 아니면 SQLite를 사용합니다.
- DB 사용자에게 checkpointer 테이블을 만들 권한이 필요합니다. 첫 서버 시작 시 테이블을 자동 설정합니다.

### 기타 런타임 설정

| 변수 | 기본값 | 설명 |
| --- | --- | --- |
| `HOST` | `127.0.0.1` | Uvicorn bind 주소. 외부 공개가 필요한 경우 방화벽과 인증을 먼저 구성합니다. |
| `PORT` | `8001` | 통합 HTTP 서버 포트 |
| `A2A_AGENT_URL` | `http://localhost:8001` | Agent Card에 노출할 A2A 공개 URL |
| `CORS_ALLOWED_ORIGINS` | 미설정 | REST에 허용할 웹 origin을 쉼표로 구분합니다. |
| `LLM_PROVIDER` | `gemini` | 모델 제공자: `gemini` 또는 `corporate` |
| `GEMINI_MODEL` | `gemini-3.5-flash-lite` | Gemini 제공자의 모델 이름 |
| `ENABLE_LLM_ROUTER` | `true` | LLM이 사용자 의도를 의미 기반으로 분류. 규칙 기반 분류만 사용하려면 `false` |
| `SECURITY_SCAN_MCP_URL` | 미설정 | SCA/Secret 제품 조회·요청·결과를 Security MCP Server에 연결합니다. 예: `http://security-mcp-server:8000/mcp` |
| `SECURITY_SCAN_MCP_AUTH_TOKEN` | 미설정 | Security MCP Server에 보낼 Bearer JWT. 미설정 시 `SECURITY_MCP_AUTH_TOKEN`을 사용합니다. |
| `SECURITY_MCP_URL` | 미설정 | 저장소·패키지 등 기존 도구용 별도 FastMCP 서버 URL |
| `SECURITY_MCP_AUTH_TOKEN` | 미설정 | MCP 서버 HTTP ingress에서 요구하는 Bearer token |

Chainlit UI origin은 `.chainlit/config.toml`의 `project.allow_origins`에서 별도로 관리합니다. 실제 배포 도메인만 allowlist에 추가하세요.

`SECURITY_SCAN_MCP_URL`은 Streamable HTTP endpoint(`/mcp`)를 지정합니다. Security MCP Server에는 `SECURITY_SCAN_MCP_AUTH_TOKEN` 또는 공용 토큰을 `Authorization: Bearer ...`로 전달합니다. 토큰은 서버의 JWT 검증 키/알고리즘과 일치해야 하며 `exp`, `user_id`(또는 `sub`), 허용 역할(`devops-admin` 또는 `devops-viewer`)을 포함해야 합니다. 스캔 실행에는 `devops-admin`이 필요합니다. 제품 목록과 backend 권한은 MCP 서버에 전달한 이 Bearer JWT의 주체 기준입니다. 현재 채팅 요청의 `user_id` claim은 이 토큰으로 변환/위임되지 않으므로, 사용자별 권한이 필요하면 요청별 검증 JWT 전달을 별도로 구성해야 합니다.

`LLM_PROVIDER=gemini`이면 `GOOGLE_API_KEY`를, `LLM_PROVIDER=corporate`이면 `CORPORATE_LLM_API_URL`(또는 `CORPORATE_LLM_BASE_URL`)과 `CORPORATE_LLM_API_KEY`를 설정하세요. `CORPORATE_LLM_MODEL`은 선택 값입니다. 의도 분류의 structured output도 이 설정을 사용하며 모델 오류 시 규칙 기반 결과로 조용히 대체하지 않습니다. 운영 자격 증명을 로컬 기본값이나 테스트 사용자 ID로 대체하지 마세요.

참고: 위의 기존 고정 토큰 안내는 로컬 테스트 호환 설정입니다. 현재 REST chat 요청의 Keycloak Bearer JWT가 설정된 경우에는 사용자별 JWT가 고정 토큰보다 우선해 Security MCP로 전달됩니다. 자세한 개발/운영 설정과 Chainlit/A2A 제한 사항은 아래의 **사용자 JWT를 Security MCP로 전달**을 참고하세요.

`SECURITY_SCAN_MCP_URL`이 설정되면 보안 스캔 노드는 서버의 `get_my_products`, `execute_sca_scan`, `get_sca_result`, `execute_secret_scan`, `get_secret_scan_result` 도구를 사용합니다. 제품 및 결과 조회 때마다 현재 사용자가 접근 가능한 제품 목록을 다시 가져오고, 선택된 제품의 `system_id`/`service_id`로 저장된 결과를 MCP에서 조회합니다. 앞선 대화에서 스캔을 실행했는지 또는 어떤 대상을 선택했는지에 조회 결과가 종속되지 않습니다. 결과가 없는 경우에만 “해당 대상의 저장 결과 없음”을 안내합니다. 연결 오류, 인증/권한 오류, MCP tool 오류 및 잘못된 응답은 실제 점검으로 오인되지 않도록 실패로 전달되며 local mock으로 대체되지 않습니다. URL이 설정되지 않은 개발/테스트 환경에서는 기존 in-process fixture를 사용합니다. 저장소·패키지 도구용 `SECURITY_MCP_URL`은 별도 MCP 서버 설정입니다. 구현/배포는 sibling project [security-mcp-server](../security-mcp-server/README.md)을 참고하세요.

## 5. 운영자 빠른 시작

### 로컬 개발

1. Python 3.12 이상과 `uv`를 설치합니다.
2. 저장소 루트에서 의존성을 동기화합니다.
3. `.env`에 사용할 모델과 저장소 설정을 입력합니다.
4. `/health`가 `200`을 반환하는지 확인한 뒤 `/ui` 또는 REST API를 사용합니다.

```powershell
uv sync
uv run security-agent-v2-server
```

다른 터미널에서 기동 상태를 확인합니다.

```powershell
Invoke-WebRequest http://127.0.0.1:8001/health
Start-Process http://127.0.0.1:8001/ui
```

개발 환경에서 MCP 서버를 연결하지 않으면 fixture/mock 도구가 사용될 수 있습니다.
따라서 mock 결과를 실제 보안 점검 결과나 실제 저장소 생성 결과로 운영 보고하지
마세요. 실제 연동을 확인하려면 MCP와 scanner backend의 연결 및 권한을 별도로
검증해야 합니다.

### 운영 전 필수 확인

- 의미 기반 intent 분류가 기본으로 켜져 있으므로, provider/API 자격 증명과
  사용자 요청 데이터의 모델 전송 정책을 운영 전에 검증합니다. 승인된 환경에서
  결정적 규칙 분류로 제한해야 할 때만 `ENABLE_LLM_ROUTER=false`를 설정합니다.
- 운영 모델 키, MCP 토큰, PostgreSQL 비밀번호는 Git, Docker image, 로그에 넣지
  않고 Kubernetes Secret 또는 승인된 Secret Manager에서 주입합니다.
- 여러 replica 또는 worker를 사용할 때 SQLite를 사용하지 말고 PostgreSQL을
  사용합니다.
- `/health`는 프로세스와 checkpointer 초기화 상태를 확인하지만, LLM·MCP의
  업무 기능까지 검증하는 readiness 테스트는 아닙니다. 배포 후 대표 질문으로
  별도 smoke test를 실행합니다.
- 비인증 UI와 `user_id=demo` 기본값은 로컬 개발 전용입니다. 운영에서는 API
  gateway/auth middleware에서 사용자 ID와 권한을 검증합니다.

### 운영 smoke test

배포 후 아래 순서로 확인합니다.

1. `GET /health`가 `200`인지 확인합니다.
2. `GET /.well-known/agent-card.json`이 정상 응답하는지 확인합니다.
3. 고유한 `thread_id`로 기능 안내 질문을 보내고 응답을 확인합니다.
4. HITL 질문이 포함된 SCA/Secret 요청을 보내 `is_paused=true`인지 확인합니다.
5. 같은 `thread_id`로 선택/승인 입력을 보내 실행이 재개되는지 확인합니다.
6. 실제 환경에서는 테스트 데이터와 실제 운영 대상을 혼동하지 않도록 테스트
   thread와 대상명을 명확히 구분합니다.

## 6. Docker 및 Kubernetes 이미지 배포

Kubernetes manifest는 별도 배포 저장소에서 관리합니다. 이 저장소는 컨테이너 이미지 빌드를 위한 `docker/Dockerfile`만 제공합니다.

저장소 루트에서 이미지 빌드 및 로컬 실행:

```powershell
docker build -f docker/Dockerfile -t security-agent-v2:latest .
docker run --rm -p 8001:8001 -v security-agent-data:/data --env-file .env security-agent-v2:latest
```

- 컨테이너는 비루트 UID `10001`로 실행하고 HTTP `8001` 포트를 제공합니다. `/health`가 Docker health check 경로입니다.
- 기본 SQLite 사용 시 `/data`를 영구 볼륨에 마운트해야 재시작 후 대화 기록이 유지됩니다. 컨테이너 UID `10001`이 쓸 수 있도록 볼륨 권한 또는 Pod의 `fsGroup`을 구성하세요. 여러 Pod/worker로 운영할 때는 공유 로컬 SQLite 대신 PostgreSQL을 설정하세요.
- 사설 registry에 push한 뒤 별도 Kubernetes 저장소의 Deployment에서 이미지를 참조합니다. Secret, PostgreSQL 연결 정보, 모델 키는 registry/image에 bake하지 말고 Kubernetes Secret 또는 승인된 Secret 관리 시스템으로 주입하세요.
- 실행 프로파일에 맞는 `HOST=0.0.0.0`, `PORT=8001`, DB 설정 및 모델 자격 증명을 주입하세요. 외부 접근에는 인증, TLS, 네트워크 정책도 별도로 구성해야 합니다.
- 현재 로컬 MCP 도구 구현은 개발용 fixture/mock을 반환합니다. Docker 이미지가 사내 백엔드에 실제 연동된 것처럼 취급되지 않도록 MCP 연결 교체와 사용자 권한 검증을 배포 전에 완료하세요.

### Kubernetes 배포 절차

이 저장소에는 Kubernetes manifest가 없으므로 아래 예시는 배포 저장소에서
작성할 Deployment/Service의 최소 운영 기준입니다. namespace, registry,
도메인, Secret 이름은 조직 표준에 맞게 변경합니다.

1. 이미지에 버전을 부여해 빌드하고 registry에 push합니다.

```powershell
docker build -f docker/Dockerfile -t registry.example.com/security/security-agent-v2:2026.09.29 .
docker push registry.example.com/security/security-agent-v2:2026.09.29
```

2. PostgreSQL URL, 모델 키, MCP 토큰을 Secret으로 생성합니다. 아래 명령은 형식
   예시이며 실제 값은 명령행이나 Shell history에 남기지 말고 Secret Manager
   연동 또는 파일 입력 방식을 사용합니다.

```powershell
kubectl -n security create secret generic security-agent-v2-secrets `
  --from-literal=POSTGRES_URL='postgresql://user:password@postgres:5432/security' `
  --from-literal=GOOGLE_API_KEY='REDACTED' `
  --from-literal=SECURITY_MCP_AUTH_TOKEN='REDACTED'
```

3. Deployment에는 다음 환경 변수와 probe를 설정합니다.

```yaml
env:
  - name: HOST
    value: "0.0.0.0"
  - name: PORT
    value: "8001"
  - name: USE_POSTGRES
    value: "true"
  - name: LLM_PROVIDER
    value: "gemini"
  - name: POSTGRES_URL
    valueFrom:
      secretKeyRef:
        name: security-agent-v2-secrets
        key: POSTGRES_URL
  - name: GOOGLE_API_KEY
    valueFrom:
      secretKeyRef:
        name: security-agent-v2-secrets
        key: GOOGLE_API_KEY
readinessProbe:
  httpGet:
    path: /health
    port: 8001
  initialDelaySeconds: 10
  periodSeconds: 10
livenessProbe:
  httpGet:
    path: /health
    port: 8001
  initialDelaySeconds: 30
  periodSeconds: 30
securityContext:
  runAsNonRoot: true
  runAsUser: 10001
  allowPrivilegeEscalation: false
```

4. Service/Ingress에는 필요한 경로만 노출합니다. 외부에 노출할 때는 TLS,
   인증/인가, CORS allowlist, NetworkPolicy를 함께 적용합니다. A2A `/`와
   `/api/chat`는 인증 없이 공개하지 않습니다.
5. 롤링 배포 후 상태와 로그를 확인합니다.

```powershell
kubectl -n security set image deployment/security-agent-v2 `
  security-agent-v2=registry.example.com/security/security-agent-v2:2026.09.29
kubectl -n security rollout status deployment/security-agent-v2
kubectl -n security get pods -l app=security-agent-v2
kubectl -n security logs deployment/security-agent-v2 --since=10m
```

배포 실패 시 먼저 `kubectl describe pod`, 컨테이너 로그, Secret key 이름,
PostgreSQL 네트워크 정책과 DNS를 확인합니다. 이미지가 비루트 UID `10001`로
실행되므로 SQLite를 임시로 사용할 경우에도 `/data` 쓰기 권한이 필요합니다.
운영 replica가 2개 이상이면 SQLite를 사용하지 마세요.

### Docker 운영 시 주의

- `docker/Dockerfile`은 `uv sync --frozen --no-dev --no-editable`로 lock 파일과
  정확히 일치하는 의존성을 설치합니다. `pyproject.toml`을 변경하면 먼저
  `uv lock`을 실행하고 `uv lock --check`를 통과시켜야 합니다.
- 컨테이너는 UID/GID `10001`로 실행합니다. `/data`를 bind mount할 때 호스트
  디렉터리를 해당 UID가 쓸 수 있게 준비합니다.
- SQLite 파일과 `.db-wal`, `.db-shm` 파일을 실행 중에 복사하거나 삭제하지
  마세요. 백업이 필요하면 컨테이너를 중지한 뒤 파일을 복사하거나 PostgreSQL
  백업 절차를 사용합니다.

## 7. 실행 방법

### 통합 서버 (UI, REST, A2A)

```powershell
uv run security-agent-v2-server
```

브라우저에서 `http://localhost:8001/ui`를 엽니다. 왼쪽의 **New Chat**을 누를 때마다 새 채팅방과 새 UUID thread가 만들어집니다. 방을 새로 만든 직후 환영 메시지에서 `thread_id`를 확인할 수 있습니다. 채팅방 내 메시지와 HITL 응답은 동일한 ID로 이어져 checkpointer에 저장됩니다.

### CLI

```powershell
uv run security-agent-v2
```

CLI는 로컬 확인용이며 현재 대화 상태에 `MemorySaver`를 사용합니다. 프로세스 종료 후 대화 복구가 필요한 운영/연동 테스트에는 통합 서버를 사용하세요.

## 8. REST API 사용

요청:

```http
POST /api/chat
Content-Type: application/json
```

```json
{
  "thread_id": "client-generated-or-server-issued-id",
  "message": "SCA 점검을 진행해줘",
  "user_id": "authorized-user-id"
}
```

`thread_id`와 `message`는 필수입니다. `user_id`는 현 개발용 기본값 `demo`를 갖지만, 운영 배포에서는 인증 미들웨어가 검증한 사용자 ID로 교체해야 합니다. 클라이언트는 한 대화방에서 항상 같은 `thread_id`를 보내고, 새 채팅방에 대해서는 새로운 예측 불가능한 ID를 생성해야 합니다.

응답 예:

```json
{
  "response": "점검할 대상을 선택해주세요...",
  "is_paused": true
}
```

`is_paused`가 `true`이면 에이전트가 HITL 선택/승인을 기다리는 상태입니다. 다음 사용자 입력을 같은 `thread_id`로 보내면 실행이 이어집니다. 이전 클라이언트와의 호환을 위해 `POST /chat`도 유지합니다.

스캔 결과에 finding 정보가 포함된 경우 위험도 우선순위 표와 패키지/라인·CVE·CVSS·CWE 및 백엔드가 제공한 조치 내용을 표시합니다. 도구 결과에 없는 CVSS/CWE/수정 버전/코드 예시는 만들어내지 않습니다. 이전 결과가 없으면 remediation/보고서 요청은 새 스캔을 임의 실행하지 않고 먼저 결과 조회를 안내합니다.

## 9. A2A 사용

- Agent Card 확인: `GET /.well-known/agent-card.json`
- RPC: `POST /`에 JSON-RPC `message/send` 요청을 보냅니다.
- `contextId`는 기본 대화 ID로 사용됩니다. 여러 인터페이스 간 동일 대화를 연결하려면 A2A 메시지 또는 params의 metadata에 `thread_id`를 넣어 REST/UI와 같은 값을 전달합니다.
- 사용자 식별이 필요하면 신뢰할 수 있는 인증 연동을 먼저 구성하고 metadata를 검증하세요. 현재 개발용 기본 사용자 ID는 `demo`입니다.

## 10. 대화 저장 및 운영

- 각 LangGraph thread는 checkpointer에서 별도로 저장됩니다. 서로 다른 채팅방에 thread ID를 재사용하지 마세요.
- 서버는 종료 시 checkpointer 연결을 닫습니다. SQLite WAL 파일(`.db-wal`, `.db-shm`)이 보일 수 있으며, 실행 중인 DB 파일을 임의로 복사/삭제하지 마세요.
- SQLite 백업은 서버를 정지한 뒤 DB 파일을 복사하거나 SQLite 백업 API를 사용합니다. PostgreSQL 백업은 조직의 PostgreSQL 백업/복구 절차를 따릅니다.
- DB 전환 전후 데이터는 자동 이관되지 않습니다. SQLite에서 PostgreSQL로 바꾸면 기존 대화는 SQLite에 남아 있으므로 별도 마이그레이션이 필요합니다.
- `GET /health`가 실패하면 로그에서 checkpointer 연결, 환경 변수, DB 권한을 먼저 확인합니다.
- SQLite는 단일 프로세스의 로컬/개발 사용에 적합합니다. 여러 worker 또는 여러 서버 인스턴스 운영은 PostgreSQL을 사용하세요.

## 11. 테스트와 변경 검증

```powershell
uv run python -m unittest discover -s tests -v
uv run python -m compileall -q src/security_agent_v2 tests
uv lock --check
```

서버 라우트/체크포인터 동작을 검증하는 테스트는 임시 SQLite DB를 사용합니다. PostgreSQL의 실제 접속 및 운영 권한 테스트는 PostgreSQL 서버에 연결된 배포/스테이징 환경에서 별도로 수행해야 합니다.

## 12. LangGraph Studio 연결

루트의 [langgraph.json](./langgraph.json)은 `security_agent` 그래프를
`src/security_agent_v2/graph.py`의 `studio_app`으로 연결합니다. Studio는 FastAPI
또는 Chainlit을 거치지 않고 LangGraph 그래프를 직접 실행하므로, 그래프 단계와
각 노드의 상태 변화를 독립적으로 확인할 수 있습니다.

의존성 설치 후 로컬 개발 서버를 실행합니다.

```powershell
uv sync
uv run langgraph dev
```

실행 후 터미널에 표시되는 Studio URL을 브라우저에서 열고 `security_agent`
그래프를 선택합니다. `.env`의 모델/MCP 설정을 로드하므로, 실제 외부 연동 없이
그래프 라우팅만 확인하려면 개발용 fixture 설정을 사용하세요. Studio의 각 실행은
`thread_id`를 기준으로 checkpointer에 저장되며, 현재 그래프는 기본적으로
Studio 런타임의 내장 persistence를 사용합니다. 서버와 테스트에서 사용하는
`agent_app`은 기존처럼 `MemorySaver`를 유지합니다.

## 13. 주요 파일

| 파일 | 역할 |
| --- | --- |
| `docker/Dockerfile` | 비루트 컨테이너 이미지 빌드 |
| `src/security_agent_v2/api.py` | FastAPI 통합 앱, REST, A2A 및 Chainlit 마운트, 서버 lifespan |
| `src/security_agent_v2/chainlit_app.py` | Chainlit 새 채팅방 생성 및 메시지 처리 |
| `src/security_agent_v2/chat.py` | 공통 thread 기반 LangGraph 실행/resume |
| `src/security_agent_v2/checkpointer.py` | 환경 변수 설정 및 SQLite/PostgreSQL saver lifecycle |
| `src/security_agent_v2/a2a_adapter.py` | Agent Card, A2A Task Executor |
| `src/security_agent_v2/graph.py` | Security Agent LangGraph 노드 및 라우팅 조립 |
| `src/security_agent_v2/nodes/intent_classifier_node.py` | 입력 의도 분류 및 그래프 시작 라우팅 |
| `src/security_agent_v2/nodes/support_guide_node.py` | 기능·입력 안내, 미지원 SAST/CI/CD 대응 |
| `src/security_agent_v2/nodes/` | 저장소, 패키지, 보안 점검, Supervisor 및 지원 안내 노드 |
| `src/security_agent_v2/prompts/` | Supervisor·Security Scan·지원 안내의 역할 및 응답 규칙 |
| `langgraph.json` | LangGraph Studio의 그래프 진입점 및 환경 설정 |
| `.chainlit/config.toml` | Chainlit 화면/기능 설정 |
| `public/theme.json`, `public/custom.css` | Chainlit 테마 및 UI 스타일 |
| `tests/` | 그래프 업무 요구사항 및 서버 인터페이스 테스트 |

## 14. 장애 대응 및 보안 주의사항

### 주요 장애 대응

| 증상 | 우선 확인할 항목 | 조치 |
| --- | --- | --- |
| `/health`가 `503` | 서버 로그의 checkpointer 초기화 오류 | `USE_POSTGRES`, `POSTGRES_URL`, DB DNS/방화벽/권한을 확인하고 재시작 |
| 서버가 시작 직후 종료 | 환경 변수 파싱 오류 또는 필수 모델 키 누락 | `USE_POSTGRES` 형식, `POSTGRES_URL`, provider별 API 키를 확인 |
| 질문이 예상과 다른 agent로 이동 | `intent_category`, 최신 사용자 문장, `ENABLE_LLM_ROUTER` | 단순 표현으로 재현하고 분류 로그와 prompt를 확인. LLM router는 별도 검증 |
| 요청이 계속 승인/선택 대기 | 동일한 `thread_id` 사용 여부 | `is_paused=true` 응답을 확인하고 다음 입력을 같은 thread에 전송 |
| 보안 MCP 연결 실패 | `SECURITY_SCAN_MCP_URL`, Bearer JWT, NetworkPolicy, MCP `/mcp` 경로 | scan 호출은 연결 실패 시 mock으로 대체하지 않으므로 URL·토큰·서버 로그를 확인 |
| 스캔 결과가 없음 | scanner backend 연결과 대상 권한 | 등록된 대상·사용자 권한·scan task 상태를 확인. 결과를 추정하지 않음 |
| Pod가 재시작하거나 Ready가 되지 않음 | `kubectl describe`, probe, OOM, Secret | probe 지연시간, 리소스 제한, Secret key, DB 연결을 순서대로 확인 |

문제 재현 시 다음 정보를 함께 기록하면 원인 추적이 쉽습니다.

- 배포 버전/image digest, 발생 시각과 timezone
- `thread_id`(민감한 메시지 본문은 제외 가능), 요청 endpoint, `is_paused`
- 사용자 ID와 권한 그룹(토큰 원문은 기록하지 않음)
- intent category/선택된 agent와 correlation/request ID
- 서버·MCP·scanner 로그의 관련 시간대

### 보안 및 개인정보

- `.env`, API key, MCP token, PostgreSQL URL, 사용자 대화 원문을 Git issue나
  외부 로그에 복사하지 마세요. 저장소에 이미 노출된 비밀값이 있다면 즉시
  폐기·재발급하고 Git history 정리 절차를 따릅니다.
- 요청의 `user_id`를 클라이언트 JSON만으로 신뢰하지 마세요. 인증 middleware가
  검증한 subject/claims에서 설정하고, MCP와 downstream 서비스에서도 권한을
  재검증합니다.
- `thread_id`는 예측 불가능한 값을 사용하고 다른 사용자와 재사용하지 않습니다.
  thread에는 질문과 업무 결과가 저장될 수 있으므로 DB 접근 권한과 보존 기간을
  제한합니다.
- 로그에는 API key, Authorization header, PostgreSQL 비밀번호, 전체 대화 내용과
  스캔 결과의 민감한 값을 남기지 않습니다.
- `unsafe_allow_html=false`, 임의 파일 업로드 비활성화 등 현재 UI 보안 설정을
  운영에서 임의로 완화하지 않습니다.
- SAST, CI/CD 상태, 임의 URL 스캔은 지원하지 않습니다. 일반적인 설명을 실제
  보안 판정으로 보고하지 말고, 실제 finding과 조치 정보는 backend 결과에 있는
  값만 사용합니다.

### 백업·복구 및 변경 관리

- PostgreSQL은 조직 표준 PITR/백업 정책에 편입하고 복구 리허설을 정기적으로
  수행합니다.
- SQLite는 단일 인스턴스 개발/소규모 운영에만 사용하고, 백업 전 프로세스를
  중지해 WAL 상태를 정리합니다.
- 이미지 tag는 `latest` 대신 immutable tag 또는 digest를 사용하고 배포 전
  `uv lock --check`, 테스트, smoke test를 통과시킵니다.
- 환경 변수나 prompt 변경도 동작 변경으로 간주해 staging에서 대표 질문,
  HITL 재개, MCP 오류 경로를 확인한 뒤 production에 반영합니다.

## 15. 운영 전 확인 사항

`SECURITY_SCAN_MCP_URL`이 설정되지 않은 개발 환경에서는 scan fixture/mock이 사용됩니다. 설정된 scan 서버에 연결할 수 없거나 개별 도구가 오류를 반환하면 실제 결과인 것처럼 mock으로 대체하지 않고 호출을 실패 처리합니다. scan MCP 서버 구현은 sibling project [security-mcp-server](../security-mcp-server/README.md)을 참고하세요. 저장소·패키지용 기존 업무 MCP 설정은 별도입니다. 운영 적용 전에는 JWT 발급/만료 정책, 서버·scanner backend 연결, 사용자 인증·권한 검증, A2A caller 인증, 외부 네트워크 정책, DB 백업/복구 및 로그의 민감 정보 처리를 담당 서비스와 함께 검증하세요. 현재 `demo` 사용자 기본값과 비인증 채팅 UI는 로컬 개발 전용입니다.

### 사용자 JWT를 Security MCP로 전달

REST `/api/chat` 및 `/chat`은 `Authorization: Bearer <access-token>`을 받아 해당 Keycloak JWT를 scan MCP 호출에 전달합니다. 요청 토큰은 요청 실행 문맥에서만 사용하며 LangGraph 상태나 체크포인터에 기록하지 않습니다. 해당 요청 헤더가 없을 때만 `SECURITY_SCAN_MCP_AUTH_TOKEN` 또는 공용 토큰 설정을 사용합니다. 운영에서는 고정 토큰을 설정하지 말고 인증된 사용자의 access token을 agent API에 전달하세요. upstream gateway에서도 agent API 인증을 강제해야 합니다.

로컬 MCP mock 테스트에서는 MCP 서버의 개발용 `JWT_VERIFICATION_KEY`와 `JWT_ALGORITHM`으로 서명한 만료 시간이 있는 JWT를 발급해 agent `.env`의 `SECURITY_SCAN_MCP_AUTH_TOKEN`에 넣고 두 프로세스를 재시작합니다. 예시 claim은 `user_id: "local-test-user"`, `role: "devops-admin"`, `exp: <미래 Unix timestamp>`입니다. MCP 서버의 `USE_MOCK`을 `true`로 두면 로컬 샘플 제품을 조회할 수 있습니다. 이 고정 admin JWT/키를 운영에 사용하거나 Git에 커밋하지 마세요. Keycloak 토큰을 사용할 때 MCP 서버가 요구하는 서명 알고리즘, 키, 만료 및 최상위 `role` claim이 일치해야 합니다. 기본 Keycloak 역할 claim이 `realm_access.roles`에만 있다면 현재 MCP 인증기는 이를 자동으로 매핑하지 않으므로 Keycloak protocol mapper 또는 MCP 서버 claim 매핑을 설정해야 합니다. Chainlit UI와 A2A 호출은 Keycloak access token 전달이 아직 포함되어 있지 않습니다.
