# 시나리오 명: 외부 저장소 추가

## 1. 트리거 (Trigger)
* 사용자가 "외부 저장소 추가하고 싶어" 등 외부망 연동을 요청할 때.

## 2. 필수 수집 데이터 (Required Slots)
* 사외 저장소 URL (`external_proxy_url`)

## 3. 정상 흐름 (Happy Path)
1. Agent는 바로 결재를 묻지 않고, 사용자에게 "추가할 사외 저장소 URL을 알려주세요."라고 질문.
2. 사용자가 URL 입력.
3. Agent는 `mock_name_external_repo(url)`를 호출하여 저장소 이름(Repo Name)을 자동 생성.
4. 자동 생성된 이름과 URL을 바탕으로 `mock_get_approval_line()` 호출.
5. 사용자에게 생성된 저장소 이름, URL, 결재 라인을 보여주며 `[Interrupt]`로 최종 승인(Yes/No) 요청.
6. 승인 시 티켓 생성.

## 4. 예외 및 재시도 흐름 (Error Handling)
* 입력받은 URL이 유효하지 않은 형식(HTTP/HTTPS 아님)이거나 Mock API에서 에러 반환 시, 프로세스를 종료하지 않고 "잘못된 URL 형식입니다. 정확한 URL을 다시 입력해주세요."라고 안내한 뒤 `[Interrupt]` 대기.

## 5. 연동 Tool / API 스펙 (Mock API Spec)
* **이름:** `mock_name_external_repo(url: str)`
* **로직:** URL Path 기반으로 저장소 이름 추출 (예: `https://registry.example.com/team/public-repository` -> `public-repository`). Path가 없으면 호스트명 기반 생성.
* **검증:** URL이 `http://` 또는 `https://`로 시작하지 않으면 에러(`ValueError`) 발생.