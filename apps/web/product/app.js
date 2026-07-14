(() => {
  "use strict";

  const routes = [
    ["/workspace", "워크스페이스"],
    ["/upload", "업로드"],
    ["/runs/demo/approval", "불변 승인"],
    ["/runs/demo", "실행 기록"],
    ["/artifacts", "아티팩트"],
    ["/reviews/demo", "검토 결과"],
    ["/exports/demo", "내보내기"],
    ["/settings/providers", "제공자 설정"],
  ];
  const screen = document.querySelector("#screen");
  const live = document.querySelector("#live-region");
  const error = document.querySelector("#error-region");
  const organizationName = document.querySelector("#organization-name");
  const digest = "56fe0a7cb28d03fdd54f0f920a6616bb9ac33cbec8046955dc2a841497d27d20";
  let dryLabState = {};
  let artifactLibrary = [];
  let providerRegistry = [];
  let providerConnections = [];
  let providerAuthorization = null;
  let providerAuthorizationTimer = 0;
  let artifactActionEpoch = 0;
  let artifactSelectionPending = 0;
  let artifactMutationPending = false;
  let loadFailure = null;

  function element(name, attributes, ...children) {
    const node = document.createElement(name);
    Object.entries(attributes || {}).forEach(([key, value]) => {
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else node.setAttribute(key, value);
    });
    children.flat().filter(Boolean).forEach((child) => node.append(child));
    return node;
  }
  function text(value) { return document.createTextNode(String(value)); }
  function panel(title, children, accent = false) { return element("section", { class: `panel${accent ? " accent" : ""}`, "aria-label": title }, element("h2", { text: title }), children); }
  function status(label, tone = "neutral") { return element("span", { class: `status ${tone}`, text: label }); }
  function button(label, action, tone = "") { return buttonWithAttributes(label, action, tone, {}); }
  function buttonWithAttributes(label, action, tone, attributes) { return element("button", { class: `button ${tone}`, type: "button", "data-action": action, text: label, ...attributes }); }
  function header(title, description, crumb = "프로젝트 / 스펙트럼 보정 실험") { return [element("p", { class: "breadcrumbs", text: crumb }), element("h1", { text: title }), element("p", { class: "lede", text: description })]; }
  function keyValues(values) { const list = element("dl", { class: "key-values" }); values.forEach(([key, value]) => list.append(element("dt", { text: key }), element("dd", { text: value }))); return list; }
  function hashValue(label, value = digest) { return element("div", {}, element("p", { class: "hash-label", text: label }), element("code", { class: "hash", text: value || "서버 확인 대기" })); }
  function value(...keys) { for (const key of keys) if (dryLabState[key] !== undefined && dryLabState[key] !== null) return dryLabState[key]; return "서버 확인 대기"; }
  function resourceList(...keys) { const found = keys.map((key) => dryLabState[key]).find(Array.isArray); return found || []; }
  function safePreviewUrl(raw, artifactOrigin) {
    try {
      const candidate = new URL(raw);
      if (
        ["http:", "https:"].includes(candidate.protocol) &&
        candidate.origin === new URL(artifactOrigin).origin
      ) return candidate.href;
    } catch (_) {
      return "about:blank";
    }
    return "about:blank";
  }
  function safeDownloadUrl(raw) {
    return typeof raw === "string" && /^\/api\/v1\/artifacts\/[A-Za-z0-9._-]+\/versions\/[A-Za-z0-9._-]+\/download$/.test(raw)
      ? raw
      : "#";
  }
  function timeline() { const list = element("ol", { class: "timeline" }); const entries = resourceList("timeline", "events"); const rows = entries.length ? entries.map((entry) => [entry.name || entry.step || "실행 단계", entry.status || "확인됨", entry.time || entry.created_at || "서버 확인", entry.tone || "neutral"]) : [["입력 검증", "대기", "서버 상태 확인 전", "neutral"], ["ActionPlan 승인", "대기", "서버 상태 확인 전", "attention"], ["격리 Python 실행", "대기", "승인 후 실행", "neutral"]]; rows.forEach(([name, state, time, tone]) => list.append(element("li", { class: tone }, element("strong", { text: name }), text(" "), status(state, tone), element("time", { text: time })))); return list; }

  function workspace(data) { const projects = data.projects.length ? data.projects.map((project) => element("li", {}, element("strong", { text: project.name || "이름 없는 프로젝트" }), element("p", { class: "metadata", text: "프로젝트 식별자와 최신 활동은 서버에서 제공됩니다." }))) : [element("li", { class: "empty-state", text: "표시할 프로젝트가 없습니다. 새 연구 입력을 업로드해 시작하세요." })]; const recent = data.recent_runs.length ? data.recent_runs.map((run) => element("li", {}, element("strong", { text: run.name || "실행 기록" }), element("p", { class: "metadata", text: run.status || "상태 정보 없음" }))) : [element("li", { class: "empty-state", text: "최근 실행 기록이 없습니다." })]; return [...header("워크스페이스", "조직의 프로젝트와 최근 연구 활동을 한 흐름으로 확인합니다.", "워크스페이스"), element("div", { class: "section-grid" }, panel("프로젝트", element("ul", { class: "activity-list" }, projects)), panel("최근 활동", element("ul", { class: "activity-list" }, recent), true))]; }
  function upload() { return [...header("연구 입력 업로드", "형식과 크기를 확인한 뒤 제한된 미리보기로 입력을 검토합니다."), element("div", { class: "section-grid" }, panel("업로드 검증", [element("p", { text: "CSV, TSV, XLSX 형식과 파일 제한을 검사합니다. 검사가 실패한 입력은 원자적으로 거부됩니다." }), element("label", { class: "field" }, text("연구 입력 파일"), element("input", { id: "dry-lab-file", type: "file", accept: ".csv,.tsv,.xlsx", "aria-describedby": "upload-help" }), element("span", { id: "upload-help", class: "help", text: "검증 결과는 서버 확인 후 표시됩니다." })), element("div", { class: "button-row" }, button("검증 및 미리보기", "upload"), button("ActionPlan 생성", "plan"))]), panel("검증된 미리보기", [status(value("upload_status", "status")), element("p", { text: "개인 식별 정보나 전체 원본을 노출하지 않는 제한된 표본 미리보기가 표시됩니다." })], true))]; }
  function approval() { return [...header("ActionPlan 승인", "실행 전에 고정된 계획, 범위, 만료 시각을 검토합니다."), element("div", { class: "section-grid" }, panel("불변 승인", [hashValue("계획 다이제스트", value("plan_digest", "digest")), keyValues([["권한 범위", value("scope")], ["만료", value("expires_at", "expires")], ["상태", value("approval_status", "status")]]), element("div", { class: "button-row" }, button("계획 승인", "approve"), button("계획 거절", "cleanup", "danger"))], true), panel("승인 전 확인", element("p", { text: "다이제스트와 범위는 승인 후 변경할 수 없습니다. 승인 또는 거절은 서버 확인 전까지 완료로 표시되지 않습니다." })) )]; }
  function run() { return [...header("보정 스펙트럼 실행 기록", "입력부터 격리 실행과 근거 검토까지 순서대로 추적합니다."), element("div", { class: "section-grid" }, panel("실행 타임라인", timeline()), element("div", { class: "stack" }, panel("현재 상태", [status(value("run_status", "status"), "attention"), element("p", { text: "연결이 끊긴 경우 마지막 확인 상태를 유지하고 복구된 이벤트만 추가합니다." }), element("div", { class: "button-row" }, button("실행 시작", "execute"), button("실행 취소", "cleanup", "danger"))], true), panel("연결된 아티팩트", element("a", { href: "/artifacts", text: "실행 아티팩트 보기" }))))]; }
  function artifactLibraryView() {
    const items = artifactLibrary.length
      ? artifactLibrary.map((artifact) =>
          element("li", { class: "artifact-library-item" },
            element("h3", {}, element("a", { href: `/artifacts/${artifact.artifact_id}`, text: artifact.name })),
            keyValues([
              ["최신 Version", `v${artifact.version_no}`],
              ["형식", artifact.media_type],
              ["체크섬", artifact.sha256],
            ]),
          ))
      : [element("li", { class: "empty-state", text: "표시할 아티팩트가 없습니다." })];
    return [
      ...header("아티팩트 라이브러리", "CSV, PNG, PDF 결과의 최신 Version을 찾고 불변 이력을 엽니다.", "아티팩트"),
      panel("조직 아티팩트", element("ul", { class: "artifact-library", "aria-label": "아티팩트 라이브러리" }, items), true),
    ];
  }
  function artifacts() {
    const artifactVersions = resourceList("artifact_versions", "versions");
    const selected = dryLabState.selected || artifactVersions.at(-1) || {};
    const tableRows = artifactVersions.map((artifact) =>
      element("tr", { "aria-current": artifact.id === selected.id ? "true" : "false" },
        element("td", { text: artifact.name || "아티팩트" }),
        element("td", { text: `v${artifact.version_no}` }),
        element("td", { text: artifact.media_type }),
        element("td", { text: artifact.sha256 }),
        element("td", {}, element("button", {
          class: "version-button",
          type: "button",
          "data-action": "select-version",
          "data-version-id": artifact.id,
          text: artifact.id === selected.id ? "선택됨" : `v${artifact.version_no} 보기`,
        })),
      ),
    );
    const cards = artifactVersions.map((artifact) =>
      element(
        "li",
        { "aria-current": artifact.id === selected.id ? "true" : "false" },
        keyValues([
          ["이름", artifact.name],
          ["버전", `v${artifact.version_no}`],
          ["형식", artifact.media_type],
          ["체크섬", artifact.sha256],
        ]),
        element("button", {
          class: "version-button",
          type: "button",
          "data-action": "select-version",
          "data-version-id": artifact.id,
          text: artifact.id === selected.id ? "선택됨" : `v${artifact.version_no} 보기`,
        }),
      ),
    );
    const lineage = Array.isArray(selected.lineage_version_ids)
      ? selected.lineage_version_ids
      : [];
    const lineageNodes = lineage.length
      ? lineage.map((versionId) => element("li", { text: versionId }))
      : [element("li", { text: "연결된 입력 Version을 서버에서 확인합니다." })];
    const previewUrl = safePreviewUrl(
      value("preview_url"),
      value("artifact_origin"),
    );
    return [
      ...header(
        "아티팩트",
        "불변 버전, 체크섬, 계보를 확인한 뒤 미리보기와 다운로드를 분리합니다.",
      ),
      element(
        "div",
        { class: "section-grid artifact-layout" },
        panel("아티팩트 버전", [
          element(
            "table",
            { class: "artifact-table" },
            element(
              "thead",
              {},
              element(
                "tr",
                {},
                ...["이름", "버전", "형식", "체크섬", "선택"].map((cell) =>
                  element("th", { scope: "col", text: cell }),
                ),
              ),
            ),
            element("tbody", {}, ...tableRows),
          ),
          element(
            "ul",
            { class: "artifact-mobile-list", "aria-label": "아티팩트 목록" },
            ...cards,
          ),
        ]),
        element(
          "div",
          { class: "stack" },
          panel("선택 Version 상세", [
            hashValue("선택 버전 체크섬", selected.sha256 || digest),
            keyValues([
              ["생성 실행", selected.producer_execution_id || "서버 확인 대기"],
              ["실행 환경 해시", selected.environment_sha256 || "서버 확인 대기"],
              ["연결된 세션", resourceList("attached_session_ids").join(", ") || "없음"],
            ]),
            element(
              "div",
              { class: "button-row" },
              button("세션에 연결", "attach"),
              button("세션 연결 해제", "detach", "secondary"),
            ),
            selected.media_type === "text/csv" ? element("div", { class: "version-create" },
              element("label", { class: "field" }, text("새 CSV 내용"), element("textarea", { id: "artifact-version-content", rows: "4" }, text("wavelength,intensity\n500,21\n"))),
              button("새 Version 생성", "create-version"),
            ) : null,
          ], true),
          panel("버전 비교", [
            keyValues([
              ["이전 Version", value("previous_version_id")],
              ["변경 바이트", String(value("changed_bytes"))],
            ]),
          ]),
        ),
      ),
      element(
        "div",
        { class: "section-grid artifact-preview-grid" },
        panel("계보 그래프", [
          element("ol", { class: "lineage-graph" }, ...lineageNodes),
        ]),
        panel("격리 미리보기", [
          element("p", {
            class: "preview-status",
            text: `${selected.name || "아티팩트"} · ${selected.media_type || "형식 확인 중"}`,
          }),
          element("iframe", {
            class: "preview-frame",
            src: previewUrl,
            title: `${selected.name || "아티팩트"} 미리보기`,
            sandbox: "",
            referrerpolicy: "no-referrer",
          }),
          element("p", {
            class: "help",
            text: "브라우저가 형식을 표시하지 못하면 검증된 Version을 다운로드해 확인하세요.",
          }),
          element("a", {
            class: "download-link",
            href: safeDownloadUrl(value("download_url")),
            download: "",
            text: "검증된 Version 다운로드",
          }),
        ], true),
      ),
    ];
  }
  function review() { const verdict = value("review_verdict", "verdict"); return [...header("검토 결과", "고정된 근거에 연결된 결과를 읽습니다. 이 화면은 재실행하지 않습니다."), element("div", { class: "section-grid" }, panel("고정된 근거", [hashValue("근거 아티팩트 체크섬", value("evidence_hash", "artifact_hash")), element("p", { text: "이 검토는 위 버전의 근거에 고정되어 있습니다." })], true), panel("검토 발견 사항", [status(verdict), element("p", { text: value("review_summary", "review_message") }), button("검토 실행", "review")]))]; }
  function exportScreen() { return [...header("내보내기", "선택한 불변 버전과 재현성 매니페스트를 함께 준비합니다."), element("div", { class: "section-grid" }, panel("선택 버전", [element("label", { class: "field" }, text("포함할 버전"), element("select", { id: "export-version" }, element("option", { text: value("selected_version", "artifact_version") }))), element("p", { class: "help", text: "내보내기는 선택한 버전만 포함하며 이후 변경으로 대체되지 않습니다." }), button("매니페스트 준비", "export")]), panel("재현성 상태", [status(value("export_status", "status")), hashValue("매니페스트 체크섬", value("export_manifest", "manifest_hash")), element("p", { text: "서버가 완료를 확인하기 전에는 내보내기 성공으로 표시되지 않습니다." }), element("p", { class: "metadata", text: `정리 상태: ${value("cleanup_status")}` })], true))]; }
  function providers() {
    const adapterDefaults = [
      { adapter_id: "openai_codex", name: "OpenAI Codex", connectable: true },
      { adapter_id: "anthropic_claude_code", name: "Anthropic Claude Code", connectable: false, reason: "자격 검증 전에는 사용할 수 없음" },
      { adapter_id: "xai_grok_build", name: "xAI Grok Build", connectable: false, reason: "자격 검증 전에는 사용할 수 없음" },
      { adapter_id: "moonshot_kimi_code", name: "Moonshot Kimi Code", connectable: false, reason: "자격 검증 전에는 사용할 수 없음" },
      { adapter_id: "zai_glm", name: "Z.ai GLM", connectable: false, reason: "unsupported_auth" },
    ];
    const adapters = adapterDefaults.map((adapter) => ({
      ...adapter,
      ...(providerRegistry.find((registered) => registered.adapter_id === adapter.adapter_id) || {}),
      connectable: adapter.adapter_id === "openai_codex",
      reason: adapter.adapter_id === "zai_glm" ? "GLM 비활성화 · unsupported_auth" : adapter.reason,
    }));
    const connectionFor = (adapterId) => providerConnections.find((connection) => connection.adapter_id === adapterId);
    const cards = adapters.map((adapter) => {
      const connection = connectionFor(adapter.adapter_id);
      const models = Array.isArray(connection?.models) ? connection.models : [];
      const selectedModel = connection?.selected_model || connection?.model_id || "";
      const revision = connection?.revision || connection?.etag || "";
      const qualified = adapter.adapter_id === "openai_codex" || adapter.qualified === true;
      const actions = [];
      if (adapter.adapter_id === "openai_codex" && !connection) {
        actions.push(buttonWithAttributes("OpenAI Codex 연결", "provider-connect", "", { id: "provider-connect-openai_codex", "data-adapter-id": adapter.adapter_id }));
      }
      if (connection && qualified) {
        actions.push(buttonWithAttributes("상태 확인", "provider-health", "secondary", { "data-connection-id": connection.id, "data-revision": revision }));
        actions.push(buttonWithAttributes("재인증", "provider-reauth", "secondary", { "data-connection-id": connection.id, "data-revision": revision }));
        actions.push(buttonWithAttributes("연결 해제", "provider-revoke", "danger", { "data-connection-id": connection.id, "data-revision": revision }));
      }
      const modelOptions = models.map((model) => {
        const modelId = model.id || model;
        const option = element("option", { value: modelId, text: model.name || modelId });
        option.selected = modelId === selectedModel;
        return option;
      });
      const modelControl = connection && qualified
        ? element("div", {}, element("label", { class: "field" }, text("선택 모델"), element("select", { id: `provider-model-${connection.id}`, "data-connection-id": connection.id, "data-revision": revision, "aria-label": `${adapter.name} 선택 모델` }, modelOptions)), buttonWithAttributes("모델 저장", "provider-model", "secondary", { "data-connection-id": connection.id, "data-revision": revision }))
        : element("p", { class: "metadata", text: adapter.reason || "연결 후 서버에서 모델 목록을 확인합니다." });
      return element("article", { class: "provider-card", "data-adapter-id": adapter.adapter_id }, element("h3", { text: adapter.name || adapter.adapter_id }), status(connection?.status || adapter.reason || "연결 대기", connection?.status === "healthy" ? "positive" : "attention"), keyValues([
        ["계정", connection?.account?.name || connection?.account_name || "연결되지 않음"],
        ["모델", models.map((model) => model.name || model.id || model).join(", ") || "서버 확인 대기"],
        ["선택 모델", selectedModel || "선택되지 않음"],
        ["상태 확인", connection?.health?.status || "서버 확인 대기"],
        ["자격 검증", connection?.qualification?.status || adapter.qualification_status || "서버 확인 대기"],
        ["연결 상태", connection?.status || adapter.reason || "연결 대기"],
      ]), modelControl, actions.length ? element("div", { class: "button-row" }, actions) : element("p", { class: "metadata", text: adapter.adapter_id === "zai_glm" ? "unsupported_auth" : "각 어댑터의 자격 검증이 완료될 때까지 연결할 수 없습니다." }));
    });
    const authorization = providerAuthorization?.authorization_url || providerAuthorization?.authorization_link;
    const instruction = providerAuthorization?.device_instruction || providerAuthorization?.instruction;
    const authorizationPanel = authorization || instruction
      ? panel("제공자 인증 진행", [
          element("p", { text: "제공자 인증을 완료한 뒤 이 화면으로 돌아오세요. 인증 정보는 이 화면에 저장하거나 표시하지 않습니다." }),
          authorization ? element("a", { id: "provider-authorization-link", href: authorization, rel: "noopener", text: "제공자 인증 열기" }) : null,
          instruction ? element("p", { class: "metadata", text: instruction }) : null,
          buttonWithAttributes("인증 취소", "provider-cancel", "danger", { id: "provider-cancel-authorization" }),
        ], true)
      : null;
    const receiptPanel = providerAuthorization?.cleanup_receipt
      ? panel("정리 영수증", element("p", { class: "metadata", text: `민감정보가 제외된 정리 영수증: ${providerAuthorization.cleanup_receipt}` }))
      : null;
    return [
      ...header("제공자 설정", "요청자 소유 연결(OAuth 구독)과 모델 선택을 서버 상태로 확인합니다.", "설정 / 제공자"),
      panel("연결 정책", element("p", { "aria-label": "자동 대체는 사용하지 않습니다", text: "OAuth 구독 연결만 사용합니다. API 키 또는 BYOK는 사용하지 않으며, 자동 대체는 하지 않습니다." }), true),
      authorizationPanel,
      receiptPanel,
      element("section", { class: "provider-grid", "aria-label": "제공자 연결 목록" }, cards),
    ].filter(Boolean);
  }

  function resourceId(path) { const match = path.match(/^\/(?:runs|artifacts|reviews|exports)\/([A-Za-z0-9._-]+)(?:\/approval)?$/); return match ? match[1] : ""; }
  function loadFailureView(failure) {
    const subject = failure.path === "/artifacts" ? "아티팩트 목록" : "페이지 정보";
    if (failure.status === 401) return [...header("인증 상태를 확인할 수 없습니다", "세션을 다시 확인한 뒤 요청을 재시도하세요.", "연구 워크벤치"), element("section", { class: "empty-state" }, element("a", { href: failure.path, text: "다시 시도" }))];
    if (failure.status === 0) return [...header("서버에 연결할 수 없습니다", `${subject}를 불러오지 못했습니다. 네트워크 연결을 확인한 뒤 재시도하세요.`, "연구 워크벤치"), element("section", { class: "empty-state" }, element("a", { href: failure.path, text: "다시 시도" }))];
    if (failure.status >= 500) return [...header("서버 응답을 확인할 수 없습니다", `${subject} 요청을 처리하지 못했습니다. 잠시 후 재시도하세요.`, "연구 워크벤치"), element("section", { class: "empty-state" }, element("a", { href: failure.path, text: "다시 시도" }))];
    return [...header("정보를 표시할 수 없습니다", `${subject}를 불러오지 못했습니다.`, "연구 워크벤치"), element("section", { class: "empty-state" }, element("a", { href: failure.path, text: "다시 시도" }))];
  }
  function viewFor(path, data) { if (loadFailure) return loadFailureView(loadFailure); if (path === "/workspace") return workspace(data); if (path === "/upload") return upload(); if (/^\/runs\/[A-Za-z0-9._-]+\/approval$/.test(path)) return approval(); if (/^\/runs\/[A-Za-z0-9._-]+$/.test(path)) return run(); if (path === "/artifacts") return artifactLibraryView(); if (/^\/artifacts\/[A-Za-z0-9._-]+$/.test(path)) return artifacts(); if (/^\/reviews\/[A-Za-z0-9._-]+$/.test(path)) return review(); if (/^\/exports\/[A-Za-z0-9._-]+$/.test(path)) return exportScreen(); if (path === "/settings/providers") return providers(); return [...header("페이지를 찾을 수 없습니다", "요청한 리소스는 존재하지 않거나 접근할 수 없습니다.", "연구 워크벤치"), element("section", { class: "empty-state" }, element("a", { href: "/workspace", text: "워크스페이스로 돌아가기" }))]; }
  function selectRoute(path) { if (/^\/runs\/[A-Za-z0-9._-]+\/approval$/.test(path)) return "/runs/demo/approval"; if (/^\/runs\/[A-Za-z0-9._-]+$/.test(path)) return "/runs/demo"; if (path === "/artifacts" || /^\/artifacts\/[A-Za-z0-9._-]+$/.test(path)) return "/artifacts"; if (/^\/reviews\/[A-Za-z0-9._-]+$/.test(path)) return "/reviews/demo"; if (/^\/exports\/[A-Za-z0-9._-]+$/.test(path)) return "/exports/demo"; return routes.find(([route]) => route === path)?.[0] || ""; }
  function updateNavigation(path) { document.querySelectorAll("[data-route]").forEach((link) => { if (link.dataset.route === path) link.setAttribute("aria-current", "page"); else link.removeAttribute("aria-current"); }); }
  function requestFailure(status, message) { const reason = new Error(message); reason.status = status; return reason; }
  async function request(path) {
    let response;
    try {
      response = await fetch(path, { method: "GET", headers: { Accept: "application/json" }, credentials: "same-origin" });
    } catch (_) {
      throw requestFailure(0, "서버에 연결할 수 없습니다.");
    }
    if (!response.ok) throw requestFailure(response.status, response.status === 401 ? "인증 상태를 확인할 수 없습니다." : "정보를 불러올 수 없습니다.");
    return response.json();
  }
  async function dryLabRequest(path, payload = {}) { const response = await fetch(path, { method: "POST", headers: { Accept: "application/json", "Content-Type": "application/json" }, credentials: "same-origin", body: JSON.stringify(payload) }); const data = await response.json().catch(() => ({})); if (!response.ok) throw new Error(data.message || data.detail || "요청을 완료하지 못했습니다."); return data; }
  async function refreshDryLabState() { dryLabState = await request("/api/v1/dry-lab/state"); }
  async function refreshArtifactLibrary() {
    const response = await request("/api/v1/artifacts");
    artifactLibrary = Array.isArray(response.artifacts) ? response.artifacts : [];
  }
  async function refreshArtifactState(
    path = location.pathname,
    versionId = "",
    requestEpoch = ++artifactActionEpoch,
  ) {
    const artifactId = resourceId(path);
    if (!artifactId) return false;
    const suffix = versionId ? `/versions/${versionId}` : "";
    const artifact = await request(`/api/v1/artifacts/${artifactId}${suffix}`);
    if (requestEpoch !== artifactActionEpoch) return false;
    dryLabState = { ...dryLabState, ...artifact, artifact_versions: artifact.versions };
    return true;
  }
  async function artifactMutationRequest(path, action, payload) {
    const response = await fetch(path, {
      method: action === "detach" ? "DELETE" : "POST",
      headers: { Accept: "application/json", "Content-Type": "application/json" },
      credentials: "same-origin",
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || data.detail || "연결을 변경하지 못했습니다.");
    return data;
  }
  function providerRevision(connection) {
    const revision = connection?.revision || connection?.etag;
    if (!revision) throw new Error("서버 revision을 확인할 수 없어 연결을 변경하지 않았습니다.");
    return revision;
  }
  function idempotencyValue() {
    if (!globalThis.crypto?.randomUUID) throw new Error("안전한 요청 식별자를 만들 수 없습니다.");
    return globalThis.crypto.randomUUID();
  }
  async function providerRequest(path, method = "GET", payload, revision) {
    const headers = { Accept: "application/json" };
    if (payload !== undefined) headers["Content-Type"] = "application/json";
    if (method === "POST") headers["Idempotency-Key"] = idempotencyValue();
    if (revision) headers["If-Match"] = revision;
    const response = await fetch(path, { method, headers, credentials: "same-origin", body: payload === undefined ? undefined : JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || data.detail || "제공자 요청을 완료하지 못했습니다.");
    return data;
  }
  async function refreshProviderState() {
    const [registry, connections] = await Promise.all([
      providerRequest("/api/v1/provider-connections/registry"),
      providerRequest("/api/v1/provider-connections"),
    ]);
    providerRegistry = Array.isArray(registry) ? registry : registry.adapters || [];
    providerConnections = Array.isArray(connections) ? connections : connections.connections || [];
  }
  function showProviderAuthorization(authorization) {
    providerAuthorization = authorization;
    window.clearTimeout(providerAuthorizationTimer);
    providerAuthorizationTimer = window.setTimeout(() => {
      providerAuthorization = null;
      if (location.pathname === "/settings/providers") render(location.pathname, { projects: [], recent_runs: [] });
    }, 300000);
  }
  async function handleProviderAction(buttonNode) {
    const action = buttonNode.dataset.action;
    if (action === "provider-connect") {
      showProviderAuthorization(await providerRequest("/api/v1/provider-connections", "POST", { adapter_id: "openai_codex", flow: "callback", redirect_uri: "/settings/providers" }));
    } else if (action === "provider-cancel") {
      const state = providerAuthorization?.state;
      if (!state) throw new Error("취소할 제공자 인증이 없습니다.");
      await providerRequest("/api/v1/provider-connections/oauth/cancel", "POST", { state });
      window.clearTimeout(providerAuthorizationTimer);
      providerAuthorization = null;
    } else {
      const connection = providerConnections.find((item) => item.id === buttonNode.dataset.connectionId);
      const revision = providerRevision(connection);
      if (action === "provider-model") {
        const select = document.querySelector(`#provider-model-${connection.id}`);
        await providerRequest(`/api/v1/provider-connections/${connection.id}/model`, "POST", { model_id: select.value }, revision);
      } else if (action === "provider-health") {
        await providerRequest(`/api/v1/provider-connections/${connection.id}/health`, "POST", undefined, revision);
      } else if (action === "provider-reauth") {
        showProviderAuthorization(await providerRequest(`/api/v1/provider-connections/${connection.id}/reauth`, "POST", undefined, revision));
      } else if (action === "provider-revoke") {
        const receipt = await providerRequest(`/api/v1/provider-connections/${connection.id}`, "DELETE", undefined, revision);
        window.clearTimeout(providerAuthorizationTimer);
        providerAuthorization = { cleanup_receipt: receipt.cleanup_receipt || receipt.receipt };
      }
    }
    await refreshProviderState();
    const receipt = providerAuthorization?.cleanup_receipt;
    live.textContent = receipt ? `연결 해제 정리 영수증: ${receipt}` : "제공자 상태를 서버에서 다시 확인했습니다.";
  }
  function updateArtifactActionLocks() {
    screen.querySelectorAll('[data-action="select-version"], [data-action="attach"], [data-action="detach"], [data-action="create-version"]').forEach((control) => {
      const mutation = ["attach", "detach", "create-version"].includes(control.dataset.action);
      control.disabled = control.getAttribute("aria-busy") === "true" || artifactMutationPending || (artifactSelectionPending > 0 && mutation);
    });
  }
  function render(path, data) { screen.replaceChildren(...viewFor(path, data)); updateArtifactActionLocks(); }
  function restoreActionFocus(action, versionId) {
    let target = null;
    if (action === "select-version") {
      target = [...screen.querySelectorAll('[data-action="select-version"]')]
        .find((candidate) => candidate.dataset.versionId === versionId && candidate.offsetParent !== null);
    } else {
      const nextAction = { attach: "detach", detach: "attach" }[action] || action;
      target = screen.querySelector(`[data-action="${nextAction}"]`);
    }
    if (!target) {
      target = screen.querySelector("h1");
      if (target) target.tabIndex = -1;
    }
    target?.focus();
  }
  async function handleAction(buttonNode) {
    const action = buttonNode.dataset.action;
    const artifactAction = ["select-version", "attach", "detach", "create-version"].includes(action);
    const requestEpoch = artifactAction ? ++artifactActionEpoch : artifactActionEpoch;
    buttonNode.dataset.requestEpoch = String(requestEpoch);
    const focusVersionId = buttonNode.dataset.versionId || "";
    buttonNode.disabled = true;
    buttonNode.setAttribute("aria-busy", "true");
    live.textContent = "서버 확인을 기다리고 있습니다.";
    if (action.startsWith("provider-")) {
      await handleProviderAction(buttonNode);
    } else if (action === "select-version") {
      const applied = await refreshArtifactState(
        location.pathname,
        buttonNode.dataset.versionId,
        requestEpoch,
      );
      if (!applied) return;
      live.textContent = "선택한 불변 Version을 불러왔습니다.";
    } else if (["attach", "detach"].includes(action)) {
      const artifactId = resourceId(location.pathname);
      const selected = dryLabState.selected || {};
      await artifactMutationRequest(`/api/v1/artifacts/${artifactId}/versions/${selected.id}/attachments`, action, { session_id: "session-demo" });
      const applied = await refreshArtifactState(
        location.pathname,
        selected.id,
        requestEpoch,
      );
      if (!applied) return;
      live.textContent = action === "attach" ? "선택한 Version을 세션에 연결했습니다." : "선택한 Version의 세션 연결을 해제했습니다.";
    } else if (action === "create-version") {
      const artifactId = resourceId(location.pathname);
      const versions = resourceList("artifact_versions", "versions");
      const latest = versions.at(-1) || {};
      const content = document.querySelector("#artifact-version-content").value;
      const created = await artifactMutationRequest(`/api/v1/artifacts/${artifactId}/versions`, action, {
        base_version_no: latest.version_no,
        name: latest.name,
        media_type: latest.media_type,
        content,
      });
      if (requestEpoch !== artifactActionEpoch) return;
      dryLabState = { ...dryLabState, ...created, artifact_versions: created.versions };
      live.textContent = "새 불변 Version을 생성했습니다.";
    } else {
      const endpoints = { upload: "/api/v1/dry-lab/upload", plan: "/api/v1/dry-lab/plan", approve: "/api/v1/dry-lab/approve", execute: "/api/v1/dry-lab/execute", review: "/api/v1/dry-lab/review", export: "/api/v1/dry-lab/export", cleanup: "/api/v1/dry-lab/cleanup" };
      const endpoint = endpoints[action];
      if (!endpoint) return;
      let payload = {};
      if (action === "upload") {
        const file = document.querySelector("#dry-lab-file").files[0];
        if (!file) throw new Error("업로드할 연구 입력 파일을 선택하세요.");
        payload = { filename: file.name, csv: await file.text(), request: "product-upload" };
      }
      if (action === "export") payload = { version: document.querySelector("#export-version").value };
      const response = await dryLabRequest(endpoint, payload);
      dryLabState = response.state || response;
      await refreshDryLabState();
      live.textContent = "서버가 작업 완료를 확인했습니다.";
    }
    error.hidden = true;
    error.textContent = "";
    render(location.pathname, { projects: [], recent_runs: [] });
    restoreActionFocus(action, focusVersionId);
  }
  function handleActionFailure(buttonNode, reason) {
    error.hidden = false;
    error.textContent = reason.message;
    live.textContent = "작업이 완료되지 않았습니다.";
    buttonNode.disabled = false;
    buttonNode.removeAttribute("aria-busy");
    buttonNode.focus();
  }
  function onScreenClick(event) {
    const buttonNode = event.target.closest("button[data-action]");
    if (!buttonNode) return;
    const action = buttonNode.dataset.action;
    const selection = action === "select-version";
    const mutation = ["attach", "detach", "create-version"].includes(action);
    if ((selection || mutation) && artifactMutationPending) return;
    if (mutation && artifactSelectionPending > 0) return;
    if (selection) artifactSelectionPending += 1;
    if (mutation) artifactMutationPending = true;
    updateArtifactActionLocks();
    handleAction(buttonNode)
      .catch((reason) => {
        const requestEpoch = Number(buttonNode.dataset.requestEpoch || "0");
        if (requestEpoch && requestEpoch !== artifactActionEpoch) return;
        handleActionFailure(buttonNode, reason);
      })
      .finally(() => {
        const requestEpoch = Number(buttonNode.dataset.requestEpoch || "0");
        if (requestEpoch && requestEpoch !== artifactActionEpoch && buttonNode.isConnected) {
          buttonNode.disabled = false;
          buttonNode.removeAttribute("aria-busy");
        }
        if (selection) artifactSelectionPending -= 1;
        if (mutation) artifactMutationPending = false;
        updateArtifactActionLocks();
        if (mutation && !buttonNode.isConnected) restoreActionFocus(action, buttonNode.dataset.versionId || "");
      });
  }
  screen.addEventListener("click", onScreenClick);
  async function start() {
    const path = location.pathname;
    let renderPath = path;
    let identityLoaded = false;
    const route = selectRoute(path);
    updateNavigation(route);
    let workspaceData = { projects: [], recent_runs: [] };
    try {
      const [identity, workspaceResponse] = await Promise.all([
        request("/api/v1/me"),
        request("/api/v1/workspace"),
      ]);
      organizationName.textContent = identity.organization?.name || "조직 정보 없음";
      identityLoaded = true;
      workspaceData = {
        projects: workspaceResponse.projects || [],
        recent_runs: workspaceResponse.recent_runs || [],
      };
      try { await refreshDryLabState(); } catch (_) { dryLabState = {}; }
      if (path === "/artifacts") await refreshArtifactLibrary();
      if (/^\/artifacts\/[A-Za-z0-9._-]+$/.test(path)) await refreshArtifactState(path);
      if (path === "/settings/providers") await refreshProviderState();
      live.textContent = "워크스페이스 정보를 불러왔습니다.";
    } catch (reason) {
      error.hidden = false;
      error.textContent = reason.message;
      if (!identityLoaded) organizationName.textContent = "조직 정보를 표시할 수 없습니다";
      live.textContent = "정보를 불러오지 못했습니다.";
      if (/^\/artifacts\/[A-Za-z0-9._-]+$/.test(path) && reason.status === 404) renderPath = "";
      else loadFailure = { path, status: reason.status || 0 };
    }
    screen.className = "screen";
    render(renderPath, workspaceData);
    screen.setAttribute("aria-busy", "false");
  }
  start();
})();
