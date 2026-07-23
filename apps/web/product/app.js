(() => {
  "use strict";

  const routes = [
    ["/workspace", "워크스페이스"],
    ["/upload", "업로드"],
    ["/artifacts", "아티팩트"],
    ["/settings/providers", "제공자 설정"],
  ];
  const MAX_TIMER_DELAY_MS = (2 ** 31) - 1;
  const PROVIDER_HEALTH_LABELS = Object.freeze({
    pending: "연결 대기",
    healthy: "정상",
    reauth_required: "재인증 필요",
    unavailable: "사용할\u00a0수\u00a0없음",
    quota_exhausted: "사용 한도 초과",
    revoked: "연결 해제됨",
  });
  const PROVIDER_ADAPTER_ID = /^[a-z][a-z0-9_]{0,63}$/u;
  const PROVIDER_AUTHORIZATION_MAX_LENGTH = 2048;
  const PROVIDER_AUTHORIZATION_ENDPOINTS = providerAuthorizationPolicy();
  const screen = document.querySelector("#screen");
  const live = document.querySelector("#live-region");
  const error = document.querySelector("#error-region");
  const organizationName = document.querySelector("#organization-name");
  const approvalTokens = new Map();
  let dryLabState = {};
  let artifactLibrary = [];
  let providerRegistry = [];
  let providerConnections = [];
  let providerAuthorization = null;
  let providerAuthorizationTimer = 0;
  let workspaceSessions = [];
  let artifactActionEpoch = 0;
  let artifactSelectionPending = 0;
  let artifactMutationPending = false;
  let artifactPreviewResizeObserver = null;
  let loadFailure = null;
  let csrfToken = "";
  let currentWorkspace = { projects: [], sessions: [], recent_runs: [] };

  const DRY_LAB_STAGES = new Set(["new", "upload", "plan", "approve", "reject", "cancel", "expire", "execute", "review", "export", "cleanup"]);
  const DRY_LAB_ACTIONS = new Set(["create-run", "approve", "reject", "cancel", "execute", "review", "export", "cleanup"]);

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
  function phrase(value) { return element("span", { class: "phrase", text: value }); }
  function panel(title, children, accent = false) { return element("section", { class: `panel${accent ? " accent" : ""}`, "aria-label": title }, element("h2", { text: title }), children); }
  function status(label, tone = "neutral") { return element("span", { class: `status ${tone}`, text: label }); }
  function button(label, action, tone = "") { return buttonWithAttributes(label, action, tone, {}); }
  function buttonWithAttributes(label, action, tone, attributes) { return element("button", { class: `button ${tone}`, type: "button", "data-action": action, text: label, ...attributes }); }
  function header(title, description, crumb = "Nipo Science") {
    return [element("header", { class: "page-header" },
      element("p", { class: "page-eyebrow breadcrumbs", text: crumb }),
      element("h1", { text: title }),
      element("p", { class: "lede" }, typeof description === "string" ? text(description) : description),
    )];
  }
  function isTechnicalValue(key, value) {
    return /(?:ID|체크섬|해시|증거|형식|시각|Version|버전|모델|계정)$/u.test(key) ||
      /^(?:[0-9a-f]{64}|[0-9a-f-]{36}|\d{4}-\d{2}-\d{2}T|[a-z]+\/[a-z0-9.+-]+|[A-Za-z0-9._-]+:\/\/)/u.test(String(value));
  }
  function keyValues(values) {
    const list = element("dl", { class: "key-values" });
    values.forEach(([key, value]) => list.append(
      element("dt", { text: key }),
      element("dd", { class: isTechnicalValue(key, value) ? "technical-value" : "", text: value }),
    ));
    return list;
  }
  function hashValue(label, value = "") { return element("div", {}, element("p", { class: "hash-label", text: label }), element("code", { class: "hash", text: value || "서버 확인 대기" })); }
  function objectSummary(label, id) { return keyValues([[`${label} ID`, id], ["생성 시각", dryLabState.created_at]]); }
  function value(key) { return dryLabState[key] !== undefined && dryLabState[key] !== null ? dryLabState[key] : "서버 확인 대기"; }
  function resourceList(key) { return Array.isArray(dryLabState[key]) ? dryLabState[key] : []; }
  function dryLabContractError() { return requestFailure(502, "서버의 실행 리소스 응답을 확인할 수 없습니다."); }
  function isObject(value) { return Boolean(value) && typeof value === "object" && !Array.isArray(value); }
  function isUuid7(value) { return typeof value === "string" && /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(value); }
  function isUtcTimestamp(value) { return typeof value === "string" && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z$/u.test(value) && !Number.isNaN(Date.parse(value)); }
  function validateDryLabResource(payload, path = "") {
    if (!isObject(payload) || !DRY_LAB_STAGES.has(payload.stage) || !isObject(payload.display)) throw dryLabContractError();
    if (!["local_dry_lab", "provider_model"].includes(payload.execution_mode)) throw dryLabContractError();
    if (payload.execution_mode === "local_dry_lab" && payload.provider !== null) throw dryLabContractError();
    if (payload.execution_mode === "provider_model" && (!isObject(payload.provider) || !isUuid7(payload.provider.connection_id) || typeof payload.provider.model_id !== "string" || !payload.provider.model_id || !["awaiting_approval", "approved", "queued", "rejected", "cancelled", "expired"].includes(payload.provider.dispatch_status))) throw dryLabContractError();
    if (typeof payload.display.stage_label !== "string" || !payload.display.stage_label || !["neutral", "attention", "positive", "danger"].includes(payload.display.stage_tone)) throw dryLabContractError();
    if (!Array.isArray(payload.links) || !Array.isArray(payload.actions) || !Array.isArray(payload.timeline)) throw dryLabContractError();
    for (const entry of payload.timeline) {
      if (!isObject(entry) || Object.keys(entry).length !== 4 || typeof entry.step !== "string" || !entry.step || typeof entry.name !== "string" || !entry.name || !["완료", "현재 단계"].includes(entry.status) || !["positive", "attention", "danger"].includes(entry.tone)) throw dryLabContractError();
    }
    const runId = payload.run_id;
    if (runId !== null && !isUuid7(runId)) throw dryLabContractError();
    if (runId !== null && !isUtcTimestamp(payload.created_at)) throw dryLabContractError();
    if (payload.review_id !== null && !isUuid7(payload.review_id)) throw dryLabContractError();
    if (payload.export_id !== null && !isUuid7(payload.export_id)) throw dryLabContractError();
    for (const link of payload.links) {
      if (!isObject(link) || typeof link.kind !== "string" || typeof link.href !== "string" || typeof link.label !== "string" || !link.label) throw dryLabContractError();
      const valid = (link.kind === "run" && link.href === `/runs/${runId}`)
        || (link.kind === "approval" && link.href === `/runs/${runId}/approval`)
        || (link.kind === "artifacts" && link.href === "/artifacts")
        || (link.kind === "review" && typeof payload.review_id === "string" && link.href === `/reviews/${payload.review_id}`)
        || (link.kind === "export" && typeof payload.export_id === "string" && link.href === `/exports/${payload.export_id}`);
      if (!valid) throw dryLabContractError();
    }
    for (const action of payload.actions) {
      if (!isObject(action) || !DRY_LAB_ACTIONS.has(action.id) || action.method !== "POST" || typeof action.label !== "string" || !action.label || typeof action.requires_ephemeral_approval !== "boolean") throw dryLabContractError();
      const validHref = action.id === "create-run"
        ? action.href === "/api/v1/runs"
        : action.href === `/api/v1/runs/${runId}/${action.id}`;
      if (!validHref) throw dryLabContractError();
    }
    if (["plan", "approve", "reject", "cancel", "expire", "execute", "review", "export", "cleanup"].includes(payload.stage)) {
      if (!isObject(payload.action_plan) || payload.action_plan.digest !== payload.plan_digest || typeof payload.action_plan.scope_label !== "string" || typeof payload.action_plan.approval_status_label !== "string" || (payload.action_plan.approval_expires_at !== null && !isUtcTimestamp(payload.action_plan.approval_expires_at)) || !Number.isInteger(payload.action_plan.approval_ttl_seconds) || payload.action_plan.approval_ttl_seconds <= 0) throw dryLabContractError();
      if (!isObject(payload.research_intent) || typeof payload.research_intent_sha256 !== "string") throw dryLabContractError();
    }
    if (["review", "export", "cleanup"].includes(payload.stage)) {
      if (!isObject(payload.review) || typeof payload.review.verdict !== "string" || !isObject(payload.review.pinned_hashes)) throw dryLabContractError();
    }
    if (["export", "cleanup"].includes(payload.stage) && (!isObject(payload.export) || typeof payload.export.manifest_sha256 !== "string" || !Array.isArray(payload.export.paths))) throw dryLabContractError();
    if (payload.stage === "cleanup") {
      if (!isObject(payload.cleanup) || Object.keys(payload.cleanup).length !== 2 || typeof payload.cleanup.removed_runtime_data !== "boolean" || !Array.isArray(payload.cleanup.preserved_artifact_hashes)) throw dryLabContractError();
      if (!payload.cleanup.preserved_artifact_hashes.every((hash) => typeof hash === "string" && /^[0-9a-f]{64}$/u.test(hash))) throw dryLabContractError();
    }
    const expected = path.match(/^\/(runs|reviews|exports)\/([A-Za-z0-9._-]+)(?:\/approval)?$/);
    if (expected) {
      const field = expected[1] === "runs" ? "run_id" : expected[1] === "reviews" ? "review_id" : "export_id";
      if (payload[field] !== expected[2]) throw dryLabContractError();
    }
    return payload;
  }
  function actionCapability(action) { return resourceList("actions").find((item) => item.id === action) || null; }
  function resourceLink(kind) { return resourceList("links").find((item) => item.kind === kind) || null; }
  function capabilityButton(action, tone = "", attributes = {}) {
    const capability = actionCapability(action);
    return capability ? buttonWithAttributes(capability.label, action, tone, { "data-endpoint": capability.href, ...attributes }) : null;
  }
  function requiredRunId() {
    const runId = dryLabState.run_id;
    if (typeof runId !== "string" || !runId) throw new Error("대상 실행을 서버에서 확인할 수 없습니다.");
    return runId;
  }
  function requiredPlanDigest() {
    const planDigest = dryLabState.plan_digest;
    if (typeof planDigest !== "string" || !planDigest) throw new Error("승인할 계획을 서버에서 확인할 수 없습니다.");
    return planDigest;
  }
  function requiredApprovalToken() {
    const token = approvalTokens.get(requiredRunId());
    if (typeof token !== "string" || !token) throw new Error("이 실행의 승인 권한을 다시 확인하세요.");
    return token;
  }
  function selectedAttachmentSessionId() {
    const sessionId = document.querySelector("#artifact-session")?.value || "";
    if (!sessionId) throw new Error("연결할 연구 세션을 선택하세요.");
    return sessionId;
  }
  function selectedDryLabSessionId() {
    const sessionId = document.querySelector("#dry-lab-session")?.value || "";
    if (!sessionId) throw new Error("연구 세션을 선택하세요.");
    return sessionId;
  }
  function selectedExecutionTarget() {
    const selected = document.querySelector("#run-execution-target")?.value || "";
    if (selected === "local_dry_lab") return { execution_mode: "local_dry_lab" };
    const connection = providerConnections.find((candidate) => candidate.id === selected);
    if (!connection || connection.status !== "healthy" || !connection.selected_model || !connection.qualification?.cleanup_verified || !connection.qualification?.live) {
      throw new Error("검증 완료된 제공자 연결과 모델을 선택하세요.");
    }
    return {
      execution_mode: "provider_model",
      connection_id: connection.id,
      model_id: connection.selected_model,
    };
  }
  function requiredFieldValue(id, label) {
    const field = document.querySelector(`#${id}`);
    const fieldValue = field?.value || "";
    if (!fieldValue || /^\s*$/u.test(fieldValue)) throw new Error(`${label} 항목을 입력하세요.`);
    return fieldValue;
  }
  function requiredLines(id, label) {
    const values = requiredFieldValue(id, label).split("\n");
    if (values.some((item) => !item || /^\s*$/u.test(item))) throw new Error(`${label} 항목에 빈 줄이 있습니다.`);
    if (new Set(values).size !== values.length) throw new Error(`${label} 항목에 중복된 줄이 있습니다.`);
    return values;
  }
  function researchIntentPayload() {
    const dataOrigin = requiredFieldValue("research-data-origin", "데이터 출처");
    const intent = {
      question: requiredFieldValue("research-question", "연구 질문"),
      rationale: requiredFieldValue("research-rationale", "연구 이유"),
      intended_benefit: requiredFieldValue("research-benefit", "기대 가치"),
      success_criteria: requiredLines("research-success-criteria", "성공 기준"),
      constraints: requiredLines("research-constraints", "연구 제약"),
      stop_conditions: requiredLines("research-stop-conditions", "중단 조건"),
      research_mode: requiredFieldValue("research-mode", "연구 모드"),
      data_origin: dataOrigin,
    };
    if (dataOrigin !== "observed") {
      intent.synthetic_generator_ref = requiredFieldValue("research-generator-ref", "합성 데이터 생성기");
      intent.synthetic_validator_ref = requiredFieldValue("research-validator-ref", "합성 데이터 검증기");
      if (intent.synthetic_generator_ref === intent.synthetic_validator_ref) {
        throw new Error("합성 데이터 생성기와 검증기는 서로 달라야 합니다.");
      }
    }
    return intent;
  }
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
  function canonicalProviderAuthorizationEndpoint(raw) {
    if (typeof raw !== "string" || raw.length > PROVIDER_AUTHORIZATION_MAX_LENGTH) return null;
    try {
      const candidate = new URL(raw);
      return candidate.protocol === "https:" && candidate.username === "" &&
        candidate.port === "" && candidate.pathname.startsWith("/") &&
        candidate.search === "" && candidate.hash === "" &&
        `${candidate.origin}${candidate.pathname}` === raw
        ? raw
        : null;
    } catch (_) {
      return null;
    }
  }
  function providerAuthorizationPolicy() {
    const policyElement = document.querySelector('meta[name="product-provider-authorization-policy"]');
    try {
      const parsed = JSON.parse(policyElement?.getAttribute("content") ?? "");
      if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") return Object.freeze({});
      const policy = {};
      for (const [adapterId, endpoint] of Object.entries(parsed)) {
        const canonical = canonicalProviderAuthorizationEndpoint(endpoint);
        if (!PROVIDER_ADAPTER_ID.test(adapterId) || !canonical) return Object.freeze({});
        policy[adapterId] = canonical;
      }
      return Object.freeze(policy);
    } catch (_) {
      return Object.freeze({});
    }
  }
  function safeProviderAuthorizationUrl(raw, adapterId) {
    const expected = PROVIDER_AUTHORIZATION_ENDPOINTS[adapterId];
    if (typeof raw !== "string" || !expected || raw.length > PROVIDER_AUTHORIZATION_MAX_LENGTH) return null;
    try {
      const candidate = new URL(raw);
      return candidate.protocol === "https:" &&
        `${candidate.origin}${candidate.pathname}` === expected &&
        raw.startsWith(`${candidate.origin}/`) && !candidate.hash &&
        candidate.href === raw
        ? raw
        : null;
    } catch (_) {
      return null;
    }
  }
  function timeline() {
    const list = element("ol", { class: "timeline" });
    const entries = resourceList("timeline");
    if (!entries.length) return element("p", { class: "empty-state", text: "기록된 실행 이벤트가 없습니다." });
    entries.forEach((entry) => list.append(element("li", { class: entry.tone }, element("strong", { text: entry.name }), text(" "), status(entry.status, entry.tone))));
    return list;
  }

  function validWorkspaceLink(link, runId) {
    if (!isObject(link) || Object.keys(link).length !== 3 || typeof link.href !== "string" || typeof link.label !== "string" || !link.label) return false;
    if (link.kind === "run") return link.href === `/runs/${runId}`;
    if (link.kind === "approval") return link.href === `/runs/${runId}/approval`;
    if (link.kind === "review") return link.href.startsWith("/reviews/") && isUuid7(link.href.slice("/reviews/".length));
    return link.kind === "export" && link.href.startsWith("/exports/") && isUuid7(link.href.slice("/exports/".length));
  }
  function validateWorkspaceRun(run) {
    const fields = ["created_at", "display_id", "id", "links", "name", "stage", "stage_label"];
    if (!isObject(run) || Object.keys(run).sort().join("|") !== fields.join("|") || !isUuid7(run.id)) throw requestFailure(502, "서버의 최근 실행 응답을 확인할 수 없습니다.");
    if (run.display_id !== `Run ${run.id.slice(-8)}` || typeof run.name !== "string" || !run.name || !DRY_LAB_STAGES.has(run.stage) || typeof run.stage_label !== "string" || !run.stage_label) throw requestFailure(502, "서버의 최근 실행 응답을 확인할 수 없습니다.");
    if (!isUtcTimestamp(run.created_at)) throw requestFailure(502, "서버의 최근 실행 응답을 확인할 수 없습니다.");
    if (!Array.isArray(run.links) || run.links.some((link) => !validWorkspaceLink(link, run.id))) throw requestFailure(502, "서버의 최근 실행 응답을 확인할 수 없습니다.");
    return run;
  }
  function workspaceResourceLink(link, runId) {
    return validWorkspaceLink(link, runId) ? element("a", { href: link.href, text: link.label }) : null;
  }
  function workspace(data) {
    const projects = data.projects.length
      ? data.projects.map((project) => element("li", {}, element("strong", { text: project.name || "이름 없는 프로젝트" }), element("p", { class: "metadata" }, text("프로젝트 식별자와 최신 활동은 서버에서 "), phrase("제공됩니다."))))
      : [element("li", { class: "empty-state", text: "표시할 프로젝트가 없습니다. 새 연구 입력을 업로드해 시작하세요." })];
    const recent = data.recent_runs.length
      ? data.recent_runs.map((run) => {
          const links = run.links.map((link) => workspaceResourceLink(link, run.id)).filter(Boolean);
          return element("li", { "data-run-id": run.id }, element("strong", { text: run.name }), element("code", { class: "activity-run-id", title: run.id, text: run.display_id }), element("p", { class: "metadata" }, text("생성 시각 "), element("time", { datetime: run.created_at, text: run.created_at })), element("p", { class: "metadata activity-status", text: run.stage_label }), links.length ? element("div", { class: "activity-links", "aria-label": `${run.display_id} 다음 행동` }, ...links) : element("p", { class: "metadata", text: "열 수 있는 리소스가 없습니다." }));
        })
      : [element("li", { class: "empty-state" }, phrase("최근 실행"), text(" "), phrase("기록이 없습니다."))];
    const metrics = [
      ["프로젝트", data.projects.length],
      ["연구 세션", data.sessions.length],
      ["최근 실행", data.recent_runs.length],
    ];
    const signalSteps = ["입력", "승인", "실행", "근거", "검토"];
    const signalTrace = element("ol", { class: "signal-trace", "aria-label": "입력→승인→실행→근거→검토" },
      ...signalSteps.map((step) => element("li", { class: "signal-step" }, element("span", { class: "signal-step-label", text: step }))),
    );
    const workspaceHero = element("section", { class: "workspace-hero", "aria-labelledby": "workspace-hero-title" },
      element("div", { class: "workspace-hero-copy" },
        element("p", { class: "page-eyebrow", text: "NIPO LABS" }),
        element("h2", { id: "workspace-hero-title", text: "Nipo Labs Research OS" }),
        element("p", { class: "lede", text: "입력부터 근거 검토까지 연구의 흐름을 한 곳에서 확인합니다." }),
        element("div", { class: "workspace-actions" },
          element("a", { class: "button", href: "/upload", text: "새 연구 시작" }),
          element("a", { class: "resource-link", href: "/artifacts", text: "아티팩트 라이브러리" }),
        ),
      ),
      element("div", { class: "workspace-signal" },
        element("p", { class: "page-eyebrow", text: "연구 신호" }),
        signalTrace,
      ),
    );
    const metricStrip = element("dl", { class: "metric-strip", "aria-label": "워크스페이스 지표" },
      ...metrics.map(([label, count]) => element("div", { class: "metric" },
        element("dt", { class: "metric-label", text: label }),
        element("dd", { class: "metric-value", text: String(count) }),
      )),
    );
    return [...header("워크스페이스", "조직의 프로젝트와 최근 연구 활동을 한 흐름으로 확인합니다.", "워크스페이스"), workspaceHero, metricStrip, element("div", { class: "section-grid workspace-grid" }, panel("프로젝트", element("ul", { class: "activity-list" }, projects)), panel("최근 활동", element("ul", { class: "activity-list" }, recent), true))];
  }
  function researchIntentForm() {
    const providerOptions = providerConnections
      .filter((connection) => connection.status === "healthy" && connection.selected_model && connection.qualification?.cleanup_verified && connection.qualification?.live)
      .map((connection) => element("option", { value: connection.id, text: `제공자 모델 · ${connection.selected_model}` }));
    return panel("왜 이 연구인가", [
      element("p", { text: "연구 질문과 검증 경계를 승인 전에 고정합니다. 실데이터와 합성데이터의 출처도 구분합니다." }),
      element("label", { class: "field" }, text("연구 질문"), element("textarea", { id: "research-question", rows: "2", required: "", "aria-describedby": "research-question-help" }), element("span", { id: "research-question-help", class: "help", text: "AI가 바꾸지 못하는 인간 소유 질문입니다." })),
      element("label", { class: "field" }, text("왜 중요한가"), element("textarea", { id: "research-rationale", rows: "2", required: "" })),
      element("label", { class: "field" }, text("기대 가치"), element("textarea", { id: "research-benefit", rows: "2", required: "" })),
      element("label", { class: "field" }, text("성공 기준"), element("textarea", { id: "research-success-criteria", rows: "3", required: "", "aria-describedby": "criteria-help" }), element("span", { id: "criteria-help", class: "help", text: "검증할 기준을 한 줄에 하나씩 입력합니다." })),
      element("label", { class: "field" }, text("연구 제약"), element("textarea", { id: "research-constraints", rows: "3", required: "", "aria-describedby": "constraints-help" }), element("span", { id: "constraints-help", class: "help", text: "도메인과 안전 제약을 한 줄에 하나씩 입력합니다." })),
      element("label", { class: "field" }, text("중단 조건"), element("textarea", { id: "research-stop-conditions", rows: "3", required: "", "aria-describedby": "stop-help" }), element("span", { id: "stop-help", class: "help", text: "증거 부족, 안전 경계, 반복 한계를 한 줄에 하나씩 입력합니다." })),
      element("label", { class: "field" }, text("연구 모드"), element("select", { id: "research-mode", required: "" }, element("option", { value: "", disabled: "", selected: "", text: "모드 선택" }), element("option", { value: "ai_for_science", text: "AI for Science 도구" }), element("option", { value: "copilot", text: "연구 코파일럿" }), element("option", { value: "bounded_agentic", text: "승인된 범위의 에이전트 실행" }))),
      element("label", { class: "field" }, text("데이터 출처"), element("select", { id: "research-data-origin", required: "" }, element("option", { value: "", disabled: "", selected: "", text: "출처 선택" }), element("option", { value: "observed", text: "관측 데이터" }), element("option", { value: "synthetic", text: "합성 데이터" }), element("option", { value: "mixed", text: "관측 및 합성 혼합" }))),
      element("label", { class: "field" }, text("합성 데이터 생성기 참조"), element("input", { id: "research-generator-ref", type: "text", "aria-describedby": "synthetic-help" })),
      element("label", { class: "field" }, text("합성 데이터 검증기 참조"), element("input", { id: "research-validator-ref", type: "text", "aria-describedby": "synthetic-help" }), element("span", { id: "synthetic-help", class: "help", text: "합성 또는 혼합 데이터일 때 서로 다른 생성기와 검증기를 입력합니다." })),
      element("label", { class: "field" }, text("연구 세션"), element("select", { id: "dry-lab-session", required: "" }, ...workspaceSessions.map((session) => element("option", { value: session.id, text: session.name || session.id })))),
      element("label", { class: "field" }, text("실행 환경"), element("select", { id: "run-execution-target", required: "" }, element("option", { value: "local_dry_lab", text: "로컬 드라이랩" }), ...providerOptions), element("span", { class: "help", text: providerOptions.length ? "제공자 실행도 같은 ActionPlan 승인 후에만 시작합니다." : "검증 완료된 제공자 연결이 없으면 로컬 드라이랩만 사용할 수 있습니다." })),
      element("label", { class: "field" }, text("실행 요청"), element("textarea", { id: "dry-lab-prompt", rows: "2", required: "" })),
      buttonWithAttributes("Run 생성 및 ActionPlan 고정", "create-run", "", { "data-endpoint": "/api/v1/runs" }),
    ], true);
  }
  function upload() {
    return [
      ...header("연구 입력 업로드", "형식과 크기를 확인하고 연구 목적과 검증 기준을 고정합니다."),
      element("div", { class: "section-grid upload-grid" },
        panel("업로드 검증", [
          element("p", {}, text("보정 메타데이터가 포함된 CSV 형식과 파일 제한을 검사합니다. 검사가 실패한 입력은 "), phrase("원자적으로"), text(" "), phrase("거부됩니다.")),
          element("label", { class: "field" }, text("연구 입력 CSV"), element("input", { id: "dry-lab-file", class: "visually-hidden", type: "file", accept: ".csv,text/csv", "aria-describedby": "dry-lab-file-name upload-help" }), element("span", { class: "button secondary file-picker", text: "CSV 선택" }), element("span", { id: "dry-lab-file-name", class: "file-name metadata", text: "선택한 파일 없음" }), element("span", { id: "upload-help", class: "help", text: "CSV 내용과 형식은 서버 확인 후 표시됩니다." })),
          element("p", { class: "help", text: "Run 생성 시 서버가 입력 검증과 ActionPlan 고정을 원자적으로 수행합니다." }),
        ]),
        element("div", { class: "stack" },
          researchIntentForm(),
          panel("검증된 미리보기", [status("Run 생성 전"), element("p", { text: "개인 식별 정보나 전체 원본을 노출하지 않는 제한된 표본 미리보기가 표시됩니다." })]),
        ),
      ),
    ];
  }
  function approval() {
    const plan = dryLabState.action_plan;
    const executeCapability = actionCapability("execute");
    const hasApproval = approvalTokens.has(requiredRunId());
    const primaryAction = actionCapability("approve")
      ? capabilityButton("approve")
      : executeCapability
        ? capabilityButton("execute", "", hasApproval ? {} : { disabled: "", "aria-describedby": "approval-memory-help" })
        : null;
    const rejectAction = capabilityButton("reject", "danger");
    const cancelAction = capabilityButton("cancel", "danger");
    const actions = [primaryAction, rejectAction, cancelAction].filter(Boolean);
    const expiryPolicy = `승인\u00a0후\u00a0${Math.round(plan.approval_ttl_seconds / 60)}분`;
    const expiry = plan.approval_expires_at
      ? element("p", { class: "approval-expiry" }, text("승인 만료 시각 "), element("time", { datetime: plan.approval_expires_at, text: plan.approval_expires_at }))
      : element("p", { class: "approval-expiry", text: `승인 유효 기간 ${expiryPolicy}` });
    return [...header("ActionPlan 승인", [text("실행 전에 고정된 계획과 1회 실행 범위, "), phrase("승인 만료를 검토합니다.")]), element("div", { class: "section-grid" }, panel("불변 승인", [status(dryLabState.display.stage_label, dryLabState.display.stage_tone), objectSummary("Run", dryLabState.run_id), hashValue("계획 다이제스트", plan.digest), keyValues([["권한 범위", plan.scope_label], ["상태", plan.approval_status_label], ["만료 정책", expiryPolicy]]), expiry, actions.length ? element("div", { class: "button-row" }, ...actions) : null, executeCapability && !hasApproval ? element("p", { id: "approval-memory-help", class: "help", text: "새로고침 후에는 승인 권한을 복원하지 않습니다. 계획을 다시 생성해 승인하세요." }) : null], true), panel("승인 전 확인", element("p", {}, text("다이제스트와 범위는 승인 후 "), phrase("변경할 수 없습니다."), text(" 서버 응답 전에는 승인 완료로 표시되지 않습니다."))) )];
  }
  function run() {
    const artifactsLink = resourceLink("artifacts");
    const nextAction = capabilityButton("review") || capabilityButton("execute");
    const cancelAction = capabilityButton("cancel", "danger");
    const providerState = dryLabState.provider;
    const providerPanel = isObject(providerState)
      ? panel("제공자 실행 경계", [status(providerState.dispatch_status === "queued" ? "대기열 등록" : "승인 대기", providerState.dispatch_status === "queued" ? "attention" : "neutral"), keyValues([["연결 ID", providerState.connection_id], ["모델", providerState.model_id], ["자격 영수증", providerState.qualification_receipt_id || "실행 전 확인 대기"]])])
      : null;
    return [...header("연구 실행 기록", [text("입력부터 격리 실행과 근거 검토까지 "), phrase("순서대로 추적합니다.")]), element("div", { class: "section-grid run-grid" }, element("div", { class: "stack" }, panel("현재 상태", [status(dryLabState.display.stage_label, dryLabState.display.stage_tone), objectSummary("Run", dryLabState.run_id), hashValue("연구 목적 체크섬", dryLabState.research_intent_sha256), element("p", {}, text("연결이 끊긴 경우 서버의 Run 리소스를 다시 읽어 "), phrase("서버 상태를"), text(" 확인합니다.")), nextAction || cancelAction ? element("div", { class: "button-row" }, ...[nextAction, cancelAction].filter(Boolean)) : null], true), providerPanel, artifactsLink ? panel("연결된 아티팩트", element("a", { class: "resource-link", href: artifactsLink.href, text: artifactsLink.label })) : null), panel("실행 타임라인", timeline()))];
  }
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
      ...header("아티팩트 라이브러리", [text("CSV, JSON, Markdown, PNG 결과의 최신 Version을 찾고 "), phrase("불변 이력을"), text(" 엽니다.")], "아티팩트"),
      panel("조직 아티팩트", element("ul", { class: "artifact-library", "aria-label": "아티팩트 라이브러리" }, items), true),
    ];
  }
  function artifacts() {
    const artifactVersions = resourceList("artifact_versions");
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
      : [element("li", {}, text("연결된 입력 Version: "), phrase("서버 확인"))];
    const previewUrl = safePreviewUrl(
      value("preview_url"),
      value("artifact_origin"),
    );
    const previewDownloadUrl = safeDownloadUrl(value("download_url"));
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
            status(selected.status === "immutable" ? "불변" : "상태 확인 필요", selected.status === "immutable" ? "positive" : "danger"),
            keyValues([
              ["Artifact ID", selected.artifact_id || value("artifact_id")],
              ["Version ID", selected.id || "서버 확인 대기"],
              ["Version", selected.version_no ? `v${selected.version_no}` : "서버 확인 대기"],
              ["생성 시각", selected.created_at || "서버 확인 대기"],
            ]),
            hashValue("선택 버전 체크섬", selected.sha256 || "서버 확인 대기"),
            keyValues([
              ["생성 실행", selected.producer_execution_id || "서버 확인 대기"],
              ["실행 환경 해시", selected.environment_sha256 || "서버 확인 대기"],
              ["연결된 세션", resourceList("attached_session_ids").join(", ") || "없음"],
            ]),
            element("label", { class: "field" }, text("연결할 연구 세션"), element("select", { id: "artifact-session" }, ...workspaceSessions.map((session) => element("option", { value: session.id, text: session.name || session.id })))),
            element(
              "div",
              { class: "button-row" },
              button("세션에 연결", "attach"),
              button("세션 연결 해제", "detach", "secondary"),
            ),
            selected.media_type === "text/csv" ? element("div", { class: "version-create" },
              element("label", { class: "field" }, text("새 CSV 내용"), element("textarea", { id: "artifact-version-content", rows: "4", placeholder: "검증할 CSV 내용을 입력하세요." })),
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
            "data-preview-download": previewUrl === "about:blank" && selected.media_type === "image/png" ? previewDownloadUrl : "",
            title: `${selected.name || "아티팩트"} 미리보기`,
            sandbox: "allow-same-origin",
            referrerpolicy: "no-referrer",
          }),
          element("p", {
            class: "help",
          }, text("브라우저가 형식을 표시하지 못하면 검증된 Version을 "), phrase("다운로드해 확인하세요.")),
          element("a", {
            class: "download-link",
            href: previewDownloadUrl,
            download: "",
            text: "검증된 Version 다운로드",
          }),
        ], true),
      ),
    ];
  }
  function review() {
    const reviewState = dryLabState.review;
    const hashes = Object.entries(reviewState.pinned_hashes);
    const exportAction = capabilityButton("export");
    const verified = reviewState.verdict === "verified";
    const finding = verified
      ? element("p", {}, text("독립 검토가 "), phrase("실행 결과와"), text(" "), phrase("고정된 체크섬을 확인했습니다."))
      : element("p", {}, text("독립 검토에서 "), phrase("실행 결과 또는"), text(" "), phrase("고정된 체크섬의 불일치를 발견했습니다."));
    return [...header("검토 결과", [text("고정된 근거에 연결된 결과를 읽습니다. "), phrase("이 화면은"), text(" "), phrase("재실행하지"), text(" "), phrase("않습니다.")]), element("div", { class: "section-grid" }, panel("검토 발견 사항", [status(reviewState.verdict, verified ? "positive" : "danger"), objectSummary("Review", dryLabState.review_id), hashValue("연구 목적 체크섬", dryLabState.research_intent_sha256), finding, exportAction ? element("div", { class: "button-row" }, exportAction) : null], true), panel("고정된 근거", [hashes.length ? keyValues(hashes) : element("p", { class: "empty-state", text: "고정된 근거가 없습니다." }), element("p", { text: "이 검토는 위 불변 버전의 근거에 고정되어 있습니다." })]))];
  }
  function exportScreen() {
    const exportState = dryLabState.export;
    const cleanupAction = capabilityButton("cleanup", "danger", { "aria-describedby": "cleanup-impact cleanup-confirmation-label" });
    const cleanupReceipt = dryLabState.cleanup;
    const cleanupPanel = cleanupAction
      ? element("section", { class: "panel destructive", "aria-label": "런타임 데이터 정리" }, element("h2", { text: "런타임 데이터 정리" }), element("p", { id: "cleanup-impact" }, text("정리하면 업로드 원본의 런타임 사본, ActionPlan과 "), phrase("승인 권한"), text(", "), phrase("임시 실행 데이터가"), text(" 제거됩니다.")), element("p", {}, text("불변 아티팩트, 체크섬, 검토 결과와 "), phrase("내보내기 매니페스트는"), text(" 보존됩니다.")), element("label", { id: "cleanup-confirmation-label", class: "cleanup-confirmation" }, element("input", { id: "cleanup-confirmation", type: "checkbox" }), text("제거 대상과 보존 대상을 확인했습니다.")), element("div", { class: "button-row" }, cleanupAction))
      : cleanupReceipt
        ? panel("정리 영수증", [status("런타임 정리 완료", "positive"), keyValues([["런타임 데이터 제거", cleanupReceipt.removed_runtime_data ? "예" : "아니요"], ["보존된 아티팩트", `${cleanupReceipt.preserved_artifact_hashes.length}개`]])])
        : null;
    return [...header("내보내기", [text("선택한 불변 버전과 재현성 매니페스트를 "), phrase("함께 준비했습니다.")]), element("div", { class: "section-grid export-grid" }, panel("재현성 상태", [status(dryLabState.display.stage_label, dryLabState.display.stage_tone), objectSummary("Export", dryLabState.export_id), hashValue("매니페스트 체크섬", exportState.manifest_sha256), hashValue("연구 목적 체크섬", dryLabState.research_intent_sha256), element("p", {}, text("서버가 매니페스트와 불변 결과 경로를 "), phrase("확인했습니다."))], true), panel("포함된 경로", [element("ul", { class: "export-paths" }, ...exportState.paths.map((path) => element("li", { text: path }))), element("p", { class: "help" }, text("내보내기는 검토에서 고정한 버전만 포함하며 이후 변경으로 "), phrase("대체되지"), text(" "), phrase("않습니다."))]), cleanupPanel)];
  }
  function providerQualification(qualification) {
    if (!qualification) return "검증 기록 없음";
    return qualification.cleanup_verified && qualification.live
      ? "라이브 자격 및 정리 검증 완료"
      : "자격 검증 전에는 사용할\u00a0수\u00a0없음";
  }
  function providerHealthLabel(health) {
    return PROVIDER_HEALTH_LABELS[health] || "상태를 확인할 수 없음";
  }
  function providers() {
    const adapters = providerRegistry.filter((adapter) => adapter && typeof adapter.id === "string");
    const connectionFor = (adapterId) => providerConnections.find((connection) => connection.adapter_id === adapterId);
    const cards = adapters.map((adapter) => {
      const connection = connectionFor(adapter.id);
      const name = adapter.name;
      const availabilityLabel = adapter.availability_label;
      const actions = [];
      if (!connection) {
        if (adapter.connectable) {
          actions.push(buttonWithAttributes(`${name} 연결`, "provider-connect", "", { id: `provider-connect-${adapter.id}`, "data-adapter-id": adapter.id }));
        }
        return element("article", { class: "provider-card", "data-adapter-id": adapter.id },
          element("h3", { text: name }),
          status(availabilityLabel, adapter.connectable ? "positive" : "attention"),
          keyValues([
            ["출시 요구", adapter.required ? "필수" : "선택"],
            ["기본 연결", adapter.default ? "예" : "아니요"],
          ]),
          adapter.disabled_reason ? element("p", { class: "metadata" }, text("비활성 이유: "), element("code", { class: "technical-value", text: adapter.disabled_reason })) : null,
          actions.length ? element("div", { class: "button-row" }, actions) : null,
        );
      }
      const models = Array.isArray(connection.models) ? connection.models : [];
      const selectedModel = connection.selected_model || "";
      const revision = connection.revision || "";
      const active = connection.status !== "revoked";
      if (active) {
        actions.push(buttonWithAttributes("상태 확인", "provider-health", "secondary", { "data-connection-id": connection.id, "data-revision": revision }));
        actions.push(buttonWithAttributes("재인증", "provider-reauth", "secondary", { "data-connection-id": connection.id, "data-revision": revision }));
        actions.push(buttonWithAttributes("연결 해제", "provider-revoke", "danger", { "data-connection-id": connection.id, "data-revision": revision }));
      }
      const modelOptions = models.map((model) => {
        const option = element("option", { value: model, text: model });
        option.selected = model === selectedModel;
        return option;
      });
      const modelControl = active && models.length
        ? element("div", {}, element("label", { class: "field" }, text("선택 모델"), element("select", { id: `provider-model-${connection.id}`, "data-connection-id": connection.id, "data-revision": revision, "aria-label": `${name} 선택 모델` }, modelOptions)), buttonWithAttributes("모델 저장", "provider-model", "secondary", { "data-connection-id": connection.id, "data-revision": revision }))
        : element("p", { class: "metadata", text: active ? "선택 가능한 모델이 없습니다." : "해제된 연결입니다." });
      const healthLabel = providerHealthLabel(connection.health);
      const statusLabel = providerHealthLabel(connection.status);
      return element("article", { class: "provider-card", "data-adapter-id": adapter.id }, element("h3", { text: name }), status(statusLabel, connection.status === "healthy" ? "positive" : "attention"), keyValues([
        ["계정", connection.account?.id || "연결되지 않음"],
        ["모델", models.join(", ") || "서버 확인 대기"],
        ["선택 모델", selectedModel || "선택되지 않음"],
        ["상태 확인", healthLabel],
        ["자격 검증", providerQualification(connection.qualification)],
        ["연결 상태", statusLabel],
      ]), modelControl, actions.length ? element("div", { class: "button-row" }, actions) : null);
    });
    const authorizationRaw = providerAuthorization?.authorization_url;
    const authorization = safeProviderAuthorizationUrl(authorizationRaw, providerAuthorization?.adapter_id);
    const instruction = providerAuthorization?.device_instruction || providerAuthorization?.instruction;
    const authorizationPanel = providerAuthorization?.state || authorization || instruction
      ? panel("제공자 인증 진행", [
          element("p", { text: "제공자 인증을 완료한 뒤 이 화면으로 돌아오세요. 인증 정보는 이 화면에 저장하거나 표시하지 않습니다." }),
          authorization ? element("a", { id: "provider-authorization-link", href: authorization, rel: "noopener", text: "제공자 인증 열기" }) : null,
          providerAuthorization?.authorization_url_rejected ? element("p", { class: "inline-warning", text: "안전한 제공자 인증 경로를 확인할 수 없어 링크를 표시하지 않았습니다." }) : null,
          instruction ? element("p", { class: "metadata", text: instruction }) : null,
          buttonWithAttributes("인증 취소", "provider-cancel", "danger", { id: "provider-cancel-authorization" }),
        ], true)
      : null;
    const cleanupReceipt = providerAuthorization?.cleanup_receipt;
    const cleanupAdapter = adapters.find((adapter) => adapter.id === cleanupReceipt?.adapter_id);
    const receiptPanel = cleanupReceipt
      ? panel("민감정보가 제외된 정리 영수증", keyValues([
          ["연결", cleanupReceipt.connection_id],
          ["제공자", cleanupAdapter?.name || "제공자 정보를 확인할 수 없음"],
          ["삭제 증거", cleanupReceipt.evidence_sha256],
          ["완료 시각", cleanupReceipt.destroyed_at],
        ]))
      : null;
    return [
      ...header("제공자 설정", element("span", {}, text("요청자 소유 연결("), phrase("OAuth 구독"), text(")과 "), phrase("모델 선택을"), text(" "), phrase("서버 상태로"), text(" 확인합니다.")), "설정 / 제공자"),
      panel("연결 정책", element("p", { "aria-label": "자동 대체 없음" }, text("OAuth 구독 연결만 사용합니다. API 키 또는 BYOK는 사용하지 않습니다. "), phrase("자동 대체"), text(" "), phrase("없음")), true),
      authorizationPanel,
      receiptPanel,
      element("section", { class: "provider-grid", "aria-label": "제공자 연결 목록" }, cards),
    ].filter(Boolean);
  }

  function resourceId(path) { const match = path.match(/^\/(?:runs|artifacts|reviews|exports)\/([A-Za-z0-9._-]+)(?:\/approval)?$/); return match ? match[1] : ""; }
  function loadFailureView(failure) {
    const subject = failure.path === "/artifacts" ? "아티팩트 목록" : "페이지 정보";
    if (failure.status === 401) return [...header("인증 상태를 확인할 수 없습니다", "세션을 다시 확인한 뒤 요청을 재시도하세요."), element("section", { class: "empty-state" }, element("a", { href: failure.path, text: "다시 시도" }))];
    if (failure.status === 0) return [...header("서버에 연결할 수 없습니다", `${subject}를 불러오지 못했습니다. 네트워크 연결을 확인한 뒤 재시도하세요.`), element("section", { class: "empty-state" }, element("a", { href: failure.path, text: "다시 시도" }))];
    if (failure.status >= 500) return [...header("서버 응답을 확인할 수 없습니다", `${subject} 요청을 처리하지 못했습니다. 잠시 후 재시도하세요.`), element("section", { class: "empty-state" }, element("a", { href: failure.path, text: "다시 시도" }))];
    return [...header("정보를 표시할 수 없습니다", `${subject}를 불러오지 못했습니다.`), element("section", { class: "empty-state" }, element("a", { href: failure.path, text: "다시 시도" }))];
  }
  function viewFor(path, data) { if (loadFailure) return loadFailureView(loadFailure); if (path === "/workspace") return workspace(data); if (path === "/upload") return upload(); if (/^\/runs\/[A-Za-z0-9._-]+\/approval$/.test(path)) return approval(); if (/^\/runs\/[A-Za-z0-9._-]+$/.test(path)) return run(); if (path === "/artifacts") return artifactLibraryView(); if (/^\/artifacts\/[A-Za-z0-9._-]+$/.test(path)) return artifacts(); if (/^\/reviews\/[A-Za-z0-9._-]+$/.test(path)) return review(); if (/^\/exports\/[A-Za-z0-9._-]+$/.test(path)) return exportScreen(); if (path === "/settings/providers") return providers(); return [...header("페이지를 찾을 수 없습니다", "요청한 리소스는 존재하지 않거나 접근할 수 없습니다."), element("section", { class: "empty-state" }, element("a", { href: "/workspace", text: "워크스페이스로 돌아가기" }))]; }
  function selectRoute(path) { if (path === "/artifacts" || /^\/artifacts\/[A-Za-z0-9._-]+$/.test(path)) return "/artifacts"; if (/^\/(?:runs|reviews|exports)\/[A-Za-z0-9._-]+(?:\/approval)?$/.test(path)) return "/workspace"; return routes.find(([route]) => route === path)?.[0] || ""; }
  function updateNavigation(path) {
    document.querySelectorAll("[data-route]").forEach((link) => {
      if (link.dataset.route === path) {
        link.setAttribute("aria-current", "page");
      } else {
        link.removeAttribute("aria-current");
      }
    });
  }
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
  function mutationHeaders() {
    if (!csrfToken) throw new Error("세션 보안 토큰을 확인할 수 없습니다.");
    const headers = { Accept: "application/json", "Content-Type": "application/json" };
    headers["X-CSRF-Token"] = csrfToken;
    return headers;
  }
  async function dryLabRequest(path, payload = {}) { const response = await fetch(path, { method: "POST", headers: mutationHeaders(), credentials: "same-origin", body: JSON.stringify(payload) }); const data = await response.json().catch(() => ({})); if (!response.ok) throw requestFailure(response.status, data.message || data.detail || data.code || "요청을 완료하지 못했습니다."); return data; }
  async function refreshNamedResource(path) {
    const match = path.match(/^\/(runs|reviews|exports)\/([A-Za-z0-9._-]+)(?:\/approval)?$/);
    if (!match) return false;
    dryLabState = validateDryLabResource(await request(`/api/v1/${match[1]}/${match[2]}`), path);
    return true;
  }
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
      headers: mutationHeaders(),
      credentials: "same-origin",
      body: JSON.stringify(payload),
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.message || data.detail || "연결을 변경하지 못했습니다.");
    return data;
  }
  function providerRevision(connection) {
    const revision = connection?.revision;
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
    if (method !== "GET") {
      if (!csrfToken) throw new Error("세션 보안 토큰을 확인할 수 없습니다.");
      headers["X-CSRF-Token"] = csrfToken;
    }
    const response = await fetch(path, { method, headers, credentials: "same-origin", body: payload === undefined ? undefined : JSON.stringify(payload) });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) {
      const providerMessage = data?.error?.message;
      throw requestFailure(
        response.status,
        typeof providerMessage === "string" && providerMessage
          ? providerMessage
          : "제공자 요청을 완료하지 못했습니다.",
      );
    }
    return data;
  }
  function validProviderAdapter(adapter) {
    return adapter && typeof adapter.id === "string" && adapter.id &&
      typeof adapter.name === "string" && adapter.name &&
      typeof adapter.availability_label === "string" && adapter.availability_label &&
      typeof adapter.required === "boolean" &&
      typeof adapter.default === "boolean" &&
      typeof adapter.connectable === "boolean" &&
      (adapter.disabled_reason === null || typeof adapter.disabled_reason === "string");
  }
  function validProviderConnection(connection) {
    const healthStates = Object.keys(PROVIDER_HEALTH_LABELS);
    return connection && typeof connection.id === "string" && connection.id &&
      typeof connection.adapter_id === "string" && connection.adapter_id &&
      typeof connection.account?.id === "string" && connection.account.id &&
      Array.isArray(connection.models) && connection.models.every((model) => typeof model === "string" && model) &&
      (connection.selected_model === null || typeof connection.selected_model === "string") &&
      healthStates.includes(connection.status) &&
      healthStates.includes(connection.health) &&
      typeof connection.qualification?.cleanup_verified === "boolean" &&
      typeof connection.qualification?.live === "boolean" &&
      typeof connection.revision === "string" && connection.revision;
  }
  async function refreshProviderState() {
    const [registry, connections] = await Promise.all([
      providerRequest("/api/v1/provider-connections/registry"),
      providerRequest("/api/v1/provider-connections"),
    ]);
    if (!Array.isArray(registry.adapters) || !registry.adapters.every(validProviderAdapter)) {
      throw requestFailure(502, "제공자 레지스트리 응답을 확인할 수 없습니다.");
    }
    if (!Array.isArray(connections.connections) || !connections.connections.every(validProviderConnection)) {
      throw requestFailure(502, "제공자 연결 응답을 확인할 수 없습니다.");
    }
    providerRegistry = registry.adapters;
    providerConnections = connections.connections;
  }
  async function refreshRunProviderState() {
    try {
      await refreshProviderState();
    } catch (reason) {
      if (reason?.status !== 403) throw reason;
      providerRegistry = [];
      providerConnections = [];
    }
  }
  function showProviderAuthorization(authorization, adapterId) {
    const safeAuthorizationUrl = safeProviderAuthorizationUrl(authorization.authorization_url, adapterId);
    providerAuthorization = {
      ...authorization,
      adapter_id: adapterId,
      authorization_url: safeAuthorizationUrl,
      authorization_url_rejected: typeof authorization.authorization_url === "string" && !safeAuthorizationUrl,
    };
    window.clearTimeout(providerAuthorizationTimer);
    const expiresIn = Date.parse(authorization.expires_at) - Date.now();
    if (Number.isFinite(expiresIn) && expiresIn > 0) {
      providerAuthorizationTimer = window.setTimeout(() => {
        providerAuthorization = null;
        if (location.pathname === "/settings/providers") render(location.pathname, { projects: [], recent_runs: [] });
      }, Math.min(expiresIn, MAX_TIMER_DELAY_MS));
    }
  }
  async function completeProviderCallback() {
    const parameters = new URLSearchParams(location.search);
    const states = parameters.getAll("state");
    if (!states.length) return;
    history.replaceState(history.state, "", `${location.pathname}${location.hash}`);
    if (states.length !== 1 || !states[0]) throw new Error("제공자 인증 상태가 올바르지 않습니다.");
    if (parameters.has("error")) {
      await providerRequest("/api/v1/provider-connections/oauth/cancel", "POST", { state: states[0] });
      throw new Error("제공자 인증이 완료되지 않았습니다.");
    }
    await providerRequest("/api/v1/provider-connections/oauth/complete", "POST", {
      state: states[0],
      flow: "callback",
      redirect_uri: "/settings/providers",
    });
    window.clearTimeout(providerAuthorizationTimer);
    providerAuthorization = null;
  }
  async function handleProviderAction(buttonNode) {
    const action = buttonNode.dataset.action;
    if (action === "provider-connect") {
      showProviderAuthorization(await providerRequest("/api/v1/provider-connections", "POST", { adapter_id: buttonNode.dataset.adapterId, flow: "callback", redirect_uri: "/settings/providers" }), buttonNode.dataset.adapterId);
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
        showProviderAuthorization(await providerRequest(`/api/v1/provider-connections/${connection.id}/reauth`, "POST", undefined, revision), connection.adapter_id);
      } else if (action === "provider-revoke") {
        const receipt = await providerRequest(`/api/v1/provider-connections/${connection.id}`, "DELETE", undefined, revision);
        window.clearTimeout(providerAuthorizationTimer);
        providerAuthorization = { cleanup_receipt: receipt.cleanup_receipt };
      }
    }
    await refreshProviderState();
    live.textContent = providerAuthorization?.cleanup_receipt ? "연결 해제와 정리 증거를 확인했습니다." : "제공자 상태를 서버에서 다시 확인했습니다.";
  }
  function updateArtifactActionLocks() {
    screen.querySelectorAll('[data-action="select-version"], [data-action="attach"], [data-action="detach"], [data-action="create-version"]').forEach((control) => {
      const mutation = ["attach", "detach", "create-version"].includes(control.dataset.action);
      control.disabled = control.getAttribute("aria-busy") === "true" || artifactMutationPending || (artifactSelectionPending > 0 && mutation);
    });
  }
  async function hydrateArtifactPreview() {
    const frame = screen.querySelector(".preview-frame[data-preview-download]");
    const downloadUrl = frame?.dataset.previewDownload;
    if (!frame || !downloadUrl || downloadUrl === "#") return;
    try {
      const response = await fetch(downloadUrl, { headers: { Accept: "image/png" }, credentials: "same-origin" });
      if (!response.ok || response.headers.get("Content-Type")?.split(";", 1)[0] !== "image/png") throw new Error("preview-unavailable");
      const bytes = new Uint8Array(await response.arrayBuffer());
      let binary = "";
      for (const byte of bytes) binary += String.fromCharCode(byte);
      const dataUrl = `data:image/png;base64,${window.btoa(binary)}`;
      if (!frame.isConnected || frame.dataset.previewDownload !== downloadUrl) return;
      frame.dataset.previewState = "loading";
      await new Promise((resolve, reject) => {
        const timeout = window.setTimeout(() => reject(new Error("preview-render-timeout")), 5_000);
        frame.addEventListener("load", () => {
          window.clearTimeout(timeout);
          resolve();
        }, { once: true });
        frame.srcdoc = `<!doctype html><meta charset="utf-8"><title>검증된 PNG 미리보기</title><img alt="검증된 PNG 미리보기" width="320" height="180" src="${dataUrl}">`;
      });
      if (!frame.isConnected || frame.dataset.previewDownload !== downloadUrl) return;
      const resizePreview = () => {
        const image = frame.contentDocument?.querySelector("img");
        if (!image || !image.naturalWidth || !image.naturalHeight) return;
        const horizontalInset = image.offsetLeft * 2;
        const renderedWidth = Math.max(1, Math.floor(frame.clientWidth - horizontalInset));
        image.width = renderedWidth;
        image.height = Math.round(renderedWidth * image.naturalHeight / image.naturalWidth);
      };
      resizePreview();
      artifactPreviewResizeObserver?.disconnect();
      artifactPreviewResizeObserver = new ResizeObserver(resizePreview);
      artifactPreviewResizeObserver.observe(frame);
      frame.dataset.previewState = "loaded";
    } catch (_) {
      frame.dataset.previewState = "unavailable";
      const previewStatus = screen.querySelector(".preview-status");
      if (previewStatus) previewStatus.textContent += " · 미리보기를 표시할 수 없음";
    }
  }
  function render(path, data) {
    artifactPreviewResizeObserver?.disconnect();
    artifactPreviewResizeObserver = null;
    screen.replaceChildren(...viewFor(path, data));
    const artifactLayout = screen.querySelector(".artifact-layout");
    if (artifactLayout?.lastElementChild?.classList.contains("stack")) {
      artifactLayout.prepend(artifactLayout.lastElementChild);
    }
    updateArtifactActionLocks();
    void hydrateArtifactPreview();
  }
  function focusRouteHeading() {
    const target = screen.querySelector("h1");
    if (target) target.tabIndex = -1;
    document.querySelector("#main-content").scrollTop = 0;
    window.scrollTo({ top: 0, left: 0, behavior: "auto" });
    target?.focus({ preventScroll: true });
  }
  function transitionToResource(action) {
    const kind = { "create-run": "approval", reject: "run", cancel: "run", execute: "run", review: "review", export: "export" }[action];
    const link = kind ? resourceLink(kind) : null;
    if (!link || link.href === location.pathname) return;
    history.pushState({}, "", link.href);
    updateNavigation(selectRoute(link.href));
  }
  function restoreActionFocus(action, versionId) {
    let target = null;
    const routeChanged = ["create-run", "reject", "cancel", "execute", "review", "export"].includes(action);
    if (routeChanged) {
      target = screen.querySelector("h1");
      if (target) target.tabIndex = -1;
    } else if (action === "select-version") {
      target = [...screen.querySelectorAll('[data-action="select-version"]')]
        .find((candidate) => candidate.dataset.versionId === versionId && candidate.offsetParent !== null);
    } else {
      const nextAction = { "create-run": "approve", approve: "execute", execute: "review", review: "export", export: "cleanup", attach: "detach", detach: "attach" }[action] || action;
      target = screen.querySelector(`[data-action="${nextAction}"]`);
    }
    if (!target) {
      target = screen.querySelector("h1");
      if (target) target.tabIndex = -1;
    }
    if (routeChanged) {
      focusRouteHeading();
      return;
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
      await artifactMutationRequest(`/api/v1/artifacts/${artifactId}/versions/${selected.id}/attachments`, action, { session_id: selectedAttachmentSessionId() });
      const applied = await refreshArtifactState(
        location.pathname,
        selected.id,
        requestEpoch,
      );
      if (!applied) return;
      live.textContent = action === "attach" ? "선택한 Version을 세션에 연결했습니다." : "선택한 Version의 세션 연결을 해제했습니다.";
    } else if (action === "create-version") {
      const artifactId = resourceId(location.pathname);
      const versions = resourceList("artifact_versions");
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
      const capability = actionCapability(action);
      const endpoint = buttonNode.dataset.endpoint;
      if (action === "create-run") {
        if (endpoint !== "/api/v1/runs") throw new Error("Run 생성 경로를 확인할 수 없습니다.");
      } else if (!capability || endpoint !== capability.href || capability.method !== "POST") {
        throw new Error("서버가 허용한 작업을 확인할 수 없습니다.");
      }
      let payload = {};
      const runId = action === "create-run" ? "" : requiredRunId();
      if (action === "create-run") {
        const file = document.querySelector("#dry-lab-file").files[0];
        if (!file) throw new Error("업로드할 연구 입력 파일을 선택하세요.");
        payload = {
          ...selectedExecutionTarget(),
          session_id: selectedDryLabSessionId(),
          prompt: requiredFieldValue("dry-lab-prompt", "실행 요청"),
          research_intent: researchIntentPayload(),
          input: { filename: file.name, media_type: "text/csv", content: await file.text() },
        };
      }
      if (action === "approve") payload.plan_digest = requiredPlanDigest();
      if (action === "execute") payload.token = requiredApprovalToken();
      if (action === "cleanup") {
        const confirmation = document.querySelector("#cleanup-confirmation");
        if (!confirmation?.checked) {
          const reason = new Error("제거 대상과 보존 대상을 확인한 뒤 정리에 동의하세요.");
          reason.focusTarget = confirmation;
          throw reason;
        }
        payload.confirmed = true;
      }
      const response = await dryLabRequest(endpoint, payload);
      if (action === "approve") {
        if (typeof response.token !== "string" || !response.token) throw new Error("승인 권한 응답을 확인할 수 없습니다.");
        approvalTokens.set(runId, response.token);
      }
      if (["reject", "cancel", "execute", "cleanup"].includes(action)) approvalTokens.delete(runId);
      dryLabState = validateDryLabResource(response);
      transitionToResource(action);
      live.textContent = "서버가 작업 완료를 확인했습니다.";
    }
    error.hidden = true;
    error.textContent = "";
    render(location.pathname, currentWorkspace);
    restoreActionFocus(action, focusVersionId);
  }
  function handleActionFailure(buttonNode, reason) {
    error.hidden = false;
    error.textContent = reason.message;
    live.textContent = "작업이 완료되지 않았습니다.";
    buttonNode.disabled = false;
    buttonNode.removeAttribute("aria-busy");
    (reason.focusTarget || buttonNode).focus();
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
  screen.addEventListener("change", (event) => {
    if (event.target.id !== "dry-lab-file") return;
    const fileName = document.querySelector("#dry-lab-file-name");
    if (fileName) fileName.textContent = event.target.files[0]?.name || "선택한 파일 없음";
  });
  async function start({ focusRoute = false } = {}) {
    loadFailure = null;
    error.hidden = true;
    error.textContent = "";
    screen.setAttribute("aria-busy", "true");
    const path = location.pathname;
    let renderPath = path;
    let identityLoaded = false;
    const route = selectRoute(path);
    updateNavigation(route);
    let workspaceData = { projects: [], sessions: [], recent_runs: [] };
    try {
      const [identity, workspaceResponse] = await Promise.all([
        request("/api/v1/me"),
        request("/api/v1/workspace"),
      ]);
      if (typeof identity.csrf_token !== "string" || !identity.csrf_token) throw requestFailure(401, "세션 보안 토큰을 확인할 수 없습니다.");
      csrfToken = identity.csrf_token;
      organizationName.textContent = identity.organization?.name || "조직 정보 없음";
      identityLoaded = true;
      if (
        !Array.isArray(workspaceResponse.projects) ||
        !Array.isArray(workspaceResponse.sessions) ||
        !Array.isArray(workspaceResponse.recent_runs)
      ) throw requestFailure(502, "워크스페이스 응답을 확인할 수 없습니다.");
      workspaceData = {
        projects: workspaceResponse.projects,
        sessions: workspaceResponse.sessions,
        recent_runs: workspaceResponse.recent_runs.map(validateWorkspaceRun),
      };
      currentWorkspace = workspaceData;
      workspaceSessions = workspaceData.sessions;
      dryLabState = {};
      await refreshNamedResource(path);
      if (path === "/upload") await refreshRunProviderState();
      if (path === "/artifacts") await refreshArtifactLibrary();
      if (/^\/artifacts\/[A-Za-z0-9._-]+$/.test(path)) await refreshArtifactState(path);
      if (path === "/settings/providers") {
        await completeProviderCallback();
        await refreshProviderState();
      }
      live.textContent = "워크스페이스 정보를 불러왔습니다.";
    } catch (reason) {
      error.hidden = false;
      error.textContent = reason.message;
      if (!identityLoaded) organizationName.replaceChildren(text("조직 정보를 "), phrase("표시할 수 없습니다"));
      live.textContent = "정보를 불러오지 못했습니다.";
      if (/^\/(?:runs|artifacts|reviews|exports)\/[A-Za-z0-9._-]+(?:\/approval)?$/.test(path) && reason.status === 404) renderPath = "";
      else loadFailure = { path, status: reason.status || 0 };
    }
    screen.className = "screen";
    render(renderPath, workspaceData);
    screen.setAttribute("aria-busy", "false");
    if (focusRoute) focusRouteHeading();
  }
  window.addEventListener("popstate", () => { void start({ focusRoute: true }); });
  void start();
})();
