📝 [시나리오 명: 애플리케이션 보안 점검 (식별자 및 유형 누락 시)]1. 트리거 (Trigger): 사용자가 대상 식별자나 점검 종류 명시 없이 "보안점검 해줘" 등 점검을 요청할 때.   2. 필수 수집 데이터 (Required Slots):request_type: "scan"   scan_type: "SECRET" 또는 "SCA"   target_type: "application" 또는 "package"   product_id 또는 package_name   3. 정상 흐름 (Happy Path):사용자가 "보안점검 해줘"라고 요청.Agent는 NLU 분석을 통해 request_type을 "scan"으로 분류하지만, scan_type, target_type, product_id는 모두 null로 둔 채 JSON을 생성한다.   Agent는 상태를 awaiting_scan_type으로 전환하고, "어떤 점검을 진행하시겠습니까? (1. SECRET, 2. SCA)"라고 질문한다.   사용자가 "1" 또는 "secret"이라고 입력한다.   Agent는 scan_type을 "SECRET"으로 업데이트하고, 상태를 awaiting_target으로 전환한 뒤 "점검할 애플리케이션(product_id)이나 패키지 이름을 알려주세요."라고 질문한다.   사용자가 "결제 앱"이라고 모호한 키워드를 입력한다.   Agent는 keyword 필드에 "결제"를 추출하고, mock_get_accessible_targets(keyword) API를 호출하여 사용자가 권한을 가진 대상 목록을 가져온다.   Agent는 "검색된 대상 목록입니다. 번호를 선택해주세요. (1. pay-api-v1, 2. pay-batch)"라고 [Interrupt] 대기한다.   사용자가 "1"을 선택하면, Agent는 product_id를 "pay-api-v1", target_type을 "application"으로 확정한다.   Agent는 mock_trigger_security_scan(product_id, scan_type)을 호출하여 점검을 실행하고, 상태를 awaiting_result로 전환하여 task_id와 함께 시작 상태를 반환한다.   4. 예외 및 재시도 흐름 (Error Handling):권한/대상 없음: 사용자가 입력한 식별자나 키워드에 대해 권한이 없거나 일치하는 대상이 없으면, Agent는 임의로 점검을 시작하지 않는다. 대신 "권한이 있는 대상과 일치하지 않습니다. 유사 항목을 확인하시겠습니까?" 등 후보 목록을 제시하고 재선택을 요구한다.   점검 유형 추정 금지: 사용자가 점검 종류를 말하지 않았을 때 Agent가 임의로(null이 아닌 값으로) scan_type을 추정하여 채우지 않고 반드시 되묻는다.   5. 연동 Tool / API 스펙 (Mock API Spec):이름: mock_get_accessible_targets(user_id: str, keyword: str = None)로직: 사용자의 user_id를 기반으로 권한이 있는 프로덕트/패키지 목록을 반환. keyword가 있으면 해당 키워드로 필터링하여 유사 후보 목록 제공.이름: mock_trigger_security_scan(target_id: str, target_type: str, scan_type: str)로직: 확정된 대상을 바탕으로 SDEP 백엔드에 보안 스캔을 트리거하고 비동기 추적을 위한 task_id를 반환.# Security Scan Agent 상세 시나리오 및 상태 정의서

본 문서는 `agent.md`의 요구사항을 바탕으로 작성된 Security Scan Agent의 핵심 시나리오입니다[cite: 1]. Claude에게 전달하여 LangGraph 상태(State) 및 노드(Node) 설계에 직접 활용할 수 있습니다.

---

## 1. [시나리오 명: 애플리케이션/패키지 보안 점검 (식별자 및 유형 누락 시)]

*   **1. 트리거 (Trigger):** 사용자가 대상 식별자나 점검 종류 명시 없이 "보안점검 해줘" 등 점검을 요청할 때[cite: 1].
*   **2. 필수 수집 데이터 (Required Slots):** 
    *   `request_type`: `"scan"`[cite: 1]
    *   `scan_type`: `"SECRET"` 또는 `"SCA"`[cite: 1]
    *   `target_type`: `"application"` 또는 `"package"`[cite: 1]
    *   `product_id` 또는 `package_name`[cite: 1]
*   **3. 정상 흐름 (Happy Path):**
    1.  사용자가 "보안점검 해줘"라고 요청한다.
    2.  Agent는 NLU 분석을 통해 `request_type`을 `"scan"`으로 분류하지만, `scan_type`, `target_type`, `product_id`는 모두 `null`로 둔 채 JSON을 생성한다[cite: 1]. 
    3.  Agent는 상태를 `awaiting_scan_type`으로 전환하고, "어떤 점검을 진행하시겠습니까? (1. SECRET, 2. SCA)"라고 질문하며 **[Interrupt]** 한다[cite: 1].
    4.  사용자가 "1" 또는 "secret"이라고 입력한다[cite: 1].
    5.  Agent는 `scan_type`을 `"SECRET"`으로 업데이트하고, 상태를 `awaiting_target`으로 전환한 뒤 "점검할 애플리케이션(product_id)이나 패키지 이름을 알려주세요."라고 질문하며 **[Interrupt]** 한다[cite: 1].
    6.  사용자가 "결제 앱"이라고 모호한 키워드를 입력한다[cite: 1].
    7.  Agent는 `keyword` 필드에 `"결제"`를 추출하고[cite: 1], `mock_get_accessible_targets(keyword)` API를 호출하여 권한을 가진 대상 목록을 가져온다.
    8.  Agent는 "검색된 대상 목록입니다. 번호를 선택해주세요. (1. pay-api-v1, 2. pay-batch)"라고 안내 후 **[Interrupt]** 대기한다[cite: 1].
    9.  사용자가 "1"을 선택하면, Agent는 `product_id`를 `"pay-api-v1"`, `target_type`을 `"application"`으로 확정한다[cite: 1].
    10. Agent는 `mock_trigger_security_scan(product_id, scan_type)`을 호출하여 점검을 실행하고, 상태를 `awaiting_result`로 전환하여 `task_id`와 함께 시작 상태를 반환한다[cite: 1].
*   **4. 예외 및 재시도 흐름 (Error Handling):**
    *   **권한/대상 없음:** 입력한 식별자나 키워드에 대해 권한이 없거나 일치하는 대상이 없으면, 임의로 점검을 시작하지 않고 "권한이 있는 대상과 일치하지 않습니다. 유사 항목을 확인하시겠습니까?"라며 후보 목록 제시 후 재선택을 요구한다[cite: 1].
    *   **점검 유형 추정 금지:** 사용자가 점검 종류를 말하지 않았을 때 임의로 `scan_type`을 추정하여 채우지 않고 반드시 되묻는다[cite: 1].

---

## 2. [시나리오 명: 과거 보안점검 결과 조회]

*   **1. 트리거 (Trigger):** 사용자가 "보안점검 결과를 보여줘" 또는 특정 대상을 명시하여 결과를 요청할 때[cite: 1].
*   **2. 필수 수집 데이터 (Required Slots):**
    *   `request_type`: `"result"`[cite: 1]
    *   `target_type` 및 식별자 (`product_id` 또는 `package_name`)[cite: 1]
    *   `scan_type`[cite: 1]
*   **3. 정상 흐름 (Happy Path):**
    1.  사용자가 대상 명시 없이 "결과 보여줘" 요청.
    2.  Agent는 `request_type`을 `"result"`로 분류하고, 대상이 없으므로 `mock_get_all_scanned_targets()`를 호출하여 전체 점검 대상 목록을 조회한다[cite: 1].
    3.  상태를 `awaiting_result_identifier`로 변경하고 사용자에게 목록을 제시 후 **[Interrupt]**[cite: 1].
    4.  사용자가 대상을 선택하면 해당 대상의 점검 이력 타입을 확인한다[cite: 1].
    5.  점검 이력이 여러 개(SCA, SECRET 모두 존재)일 경우 상태를 `awaiting_result_type`으로 변경하고 "조회할 점검 유형을 선택하세요."라고 요청 후 **[Interrupt]**[cite: 1].
    6.  사용자 선택이 완료되면 점검 유형에 따라 `get_secret_scan_result()` 또는 `get_sca_scan_result()`를 호출한다.
    7.  MCP 응답의 `sc_output_result`가 `progressing`이면 아직 점검 중이라고 안내하고, `success`이면 점검 결과를 제공한다. `failure`이면 `failure_reason`을 실패 사유로 안내한다.
*   **4. 예외 및 재시도 흐름 (Error Handling):**
    *   조회할 대상에 대한 점검 이력이 존재하지 않으면, "해당 대상의 점검 이력이 없습니다."라고 안내하고 상태를 초기화한다[cite: 1].

---

## 3. [시나리오 명: 외부 저장소 연동 확인 및 목록 조회]

*   **1. 트리거 (Trigger):** 사용자가 패키지의 사내 연동 여부를 묻거나(`repository`), 전체 연동 저장소 목록을 조회(`repository_list`)할 때[cite: 1].
*   **2. 필수 수집 데이터 (Required Slots):**
    *   `request_type`: `"repository"` 또는 `"repository_list"`[cite: 1]
    *   `package_name` (단일 패키지 확인 시 필수)[cite: 1]
    *   `external_repository_url` (추출 가능 시)[cite: 1]
*   **3. 정상 흐름 (Happy Path - 단일 패키지 연동 확인):**
    1.  사용자가 "requests 패키지가 사내 저장소에 연동되어 있나요?" 요청[cite: 1].
    2.  Agent는 `request_type: "repository"`, `package_name: "requests"`, `external_repository_url: "https://pypi.org/simple"`로 의도를 파싱한다[cite: 1].
    3.  `mock_check_repo_integration(package_name, external_repository_url)`을 호출하여 사내 연동 목록과 비교 판단한다[cite: 1].
    4.  연동 여부 결과를 사용자에게 즉시 제공한다 (결재나 추가 승인 불필요)[cite: 1].
*   **4. 정상 흐름 (Happy Path - 전체 목록 조회):**
    1.  사용자가 "현재 연동된 외부 저장소 리스트 알려줘" 요청[cite: 1].
    2.  Agent는 `request_type: "repository_list"`로 분류한다[cite: 1].
    3.  `get_external_repos_list()`를 호출하여 외부 저장소 명, 사외 저장소 URL, package type을 나열한다[cite: 1].
*   **5. 예외 및 주의 사항 (Error Handling):**
    *   **분류 오동작 방지:** `package_name`과 "다운로드/설치" 키워드가 함께 있을 경우, 절대 `repository_list`로 오분류하지 않고 `repository`로 처리해야 한다[cite: 1].

---

## 4. 연동 Tool / API 스펙 (Mock API Spec)

*   `mock_get_accessible_targets(keyword: str) -> List[dict]`
*   `mock_trigger_security_scan(target_id: str, scan_type: str) -> dict`
*   `mock_get_all_scanned_targets() -> List[dict]`
*   `mock_get_scan_result(target_id: str, scan_type: str) -> dict`
*   `mock_check_repo_integration(package_name: str, ext_url: str) -> dict`
*   `get_external_repos_list() -> List[dict]`