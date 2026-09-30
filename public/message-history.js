(() => {
  const storagePrefix = "security-agent-message-history:";
  const threadIdPattern =
    /thread_id:\s*([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/i;
  let roomKey = null;
  let history = [];
  let historyIndex = 0;
  let draft = "";
  let lastCapturedText = null;
  let lastCapturedAt = 0;

  const getComposer = (target) => {
    if (!(target instanceof HTMLElement)) return null;
    const composer = target.closest("textarea, [contenteditable='true']");
    return composer instanceof HTMLElement ? composer : null;
  };

  const getRoomKey = () => {
    const match = document.body.innerText.match(threadIdPattern);
    if (match) {
      return {
        key: match[1].toLowerCase(),
        isThreadId: true,
      };
    }

    const url = new URL(window.location.href);
    return {
      key: url.searchParams.get("threadId") || url.pathname,
      isThreadId: false,
    };
  };

  const refreshRoom = () => {
    const nextRoom = getRoomKey();
    if (
      roomKey === nextRoom.key ||
      (roomKey && !nextRoom.isThreadId && roomKey !== nextRoom.key)
    ) {
      return;
    }

    const previousRoomKey = roomKey;
    roomKey = nextRoom.key;
    historyIndex = 0;
    draft = "";
    const saved =
      sessionStorage.getItem(storagePrefix + roomKey) ||
      (previousRoomKey
        ? sessionStorage.getItem(storagePrefix + previousRoomKey)
        : null);
    if (!saved) {
      history = [];
      return;
    }

    try {
      const parsed = JSON.parse(saved);
      history = Array.isArray(parsed)
        ? parsed.filter((item) => typeof item === "string")
        : [];
      historyIndex = history.length;
    } catch (error) {
      console.warn("Could not read this chat's message history.", error);
      history = [];
    }
  };

  const getValue = (composer) =>
    composer instanceof HTMLTextAreaElement
      ? composer.value
      : composer.innerText;

  const setValue = (composer, value) => {
    if (composer instanceof HTMLTextAreaElement) {
      const setter = Object.getOwnPropertyDescriptor(
        HTMLTextAreaElement.prototype,
        "value"
      ).set;
      setter.call(composer, value);
      composer.dispatchEvent(new Event("input", { bubbles: true }));
      return;
    }

    composer.innerText = value;
    composer.dispatchEvent(new InputEvent("input", { bubbles: true }));
  };

  const renderPromptExamples = () => {
    const form = Array.from(document.querySelectorAll("form")).find((candidate) =>
      candidate.querySelector("textarea, [contenteditable='true']")
    );
    if (!form) return;

    let examples = document.querySelector(".security-agent-prompt-examples");
    if (!examples) {
      examples = document.createElement("nav");
      examples.className = "security-agent-prompt-examples";
      examples.setAttribute("aria-label", "Security Agent 질문 예시");
      examples.innerHTML = `
        <span class="security-agent-prompt-examples__label">이렇게 요청해 보세요</span>
        <div class="security-agent-prompt-examples__list">
          <button type="button" data-security-agent-prompt="보안 점검 가능한 대상을 알려줘">점검 대상 조회</button>
          <button type="button" data-security-agent-prompt="권한 있는 대상의 SCA 점검을 실행해줘">SCA 점검</button>
          <button type="button" data-security-agent-prompt="보안 점검 결과를 보여줘">점검 결과 조회</button>
          <button type="button" data-security-agent-prompt="사내 연동된 외부 저장소 목록을 알려줘">외부 저장소 조회</button>
        </div>
      `;
      form.parentElement?.insertBefore(examples, form);
    } else if (examples.nextElementSibling !== form) {
      form.parentElement?.insertBefore(examples, form);
    }
  };

  document.addEventListener("click", (event) => {
    const target = event.target;
    if (!(target instanceof Element)) return;
    const button = target.closest("[data-security-agent-prompt]");
    if (!(button instanceof HTMLButtonElement)) return;

    const form = Array.from(document.querySelectorAll("form")).find((candidate) =>
      candidate.querySelector("textarea, [contenteditable='true']")
    );
    const composer = form?.querySelector("textarea, [contenteditable='true']");
    if (!(composer instanceof HTMLElement)) return;

    setValue(composer, button.dataset.securityAgentPrompt || "");
    composer.focus();
  });

  const captureMessage = (composer) => {
    const text = getValue(composer);
    if (!text.trim()) return;

    const now = Date.now();
    if (
      text === lastCapturedText &&
      now - lastCapturedAt < 500
    ) {
      return;
    }

    refreshRoom();
    history.push(text);
    historyIndex = history.length;
    draft = "";
    lastCapturedText = text;
    lastCapturedAt = now;
    sessionStorage.setItem(
      storagePrefix + roomKey,
      JSON.stringify(history)
    );
  };

  const navigateHistory = (composer, direction) => {
    refreshRoom();
    if (history.length === 0) return;

    const currentValue = getValue(composer);
    if (
      composer instanceof HTMLTextAreaElement &&
      historyIndex === history.length &&
      currentValue.includes("\n") &&
      ((direction < 0 && composer.selectionStart !== 0) ||
        (direction > 0 && composer.selectionEnd !== currentValue.length))
    ) {
      return;
    }

    if (historyIndex === history.length) {
      draft = getValue(composer);
    }

    if (direction < 0) {
      if (historyIndex === 0) return;
      historyIndex -= 1;
      setValue(composer, history[historyIndex]);
      return;
    }

    if (historyIndex >= history.length) return;
    historyIndex += 1;
    setValue(
      composer,
      historyIndex === history.length ? draft : history[historyIndex]
    );
  };

  document.addEventListener(
    "keydown",
    (event) => {
      const composer = getComposer(event.target);
      if (!composer || event.altKey || event.ctrlKey || event.metaKey) return;

      if (event.key === "ArrowUp" || event.key === "ArrowDown") {
        const direction = event.key === "ArrowUp" ? -1 : 1;
        const before = historyIndex;
        navigateHistory(composer, direction);
        if (historyIndex !== before) event.preventDefault();
        return;
      }

      if (
        event.key === "Enter" &&
        !event.shiftKey &&
        !event.isComposing &&
        !event.nativeEvent?.isComposing
      ) {
        captureMessage(composer);
      }
    },
    true
  );

  document.addEventListener(
    "submit",
    (event) => {
      const form = event.target;
      const composer = form instanceof HTMLFormElement
        ? form.querySelector("textarea, [contenteditable='true']")
        : null;
      if (composer instanceof HTMLElement) captureMessage(composer);
    },
    true
  );

  document.addEventListener(
    "click",
    (event) => {
      const target = event.target;
      if (!(target instanceof Element)) return;
      const button = target.closest("button");
      if (!button) return;

      const label = [
        button.getAttribute("aria-label"),
        button.getAttribute("data-testid"),
        button.innerText,
      ]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      if (!/send|전송/.test(label)) return;

      const form = button.closest("form");
      const composer = form?.querySelector("textarea, [contenteditable='true']");
      if (composer instanceof HTMLElement) captureMessage(composer);
    },
    true
  );

  let roomRefreshScheduled = false;
  const observer = new MutationObserver(() => {
    if (roomRefreshScheduled) return;
    roomRefreshScheduled = true;
    requestAnimationFrame(() => {
      roomRefreshScheduled = false;
      refreshRoom();
      renderPromptExamples();
    });
  });
  observer.observe(document.body, { childList: true, subtree: true });
  refreshRoom();
  renderPromptExamples();
})();
