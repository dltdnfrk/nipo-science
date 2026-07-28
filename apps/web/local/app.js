/*
 * Nipo Science local — single-user workbench front end.
 *
 * Two rules shape this file.
 *
 * 1. No provider key ever exists in this page beyond the instant it is
 *    submitted. The key input is write-only: its value is read once, sent, and
 *    cleared. Nothing is ever assigned back into it, nothing is written to
 *    localStorage or sessionStorage, and the API has no field able to return a
 *    key even if this file asked for one.
 * 2. Nothing claims a guarantee the product does not have. Where an execution
 *    discloses `in_process` isolation, the UI says exactly that and refuses to
 *    render a sandbox badge. Where a value is absent, the UI says it is
 *    absent instead of substituting a default.
 *
 * Every node that carries server or user data is built with `textContent`.
 * `innerHTML` is never assigned anywhere in this file.
 */

(() => {
  "use strict";

  const API = "/api/v1";
  const TOKEN_HEADER = "X-Nipo-Token";
  /*
   * The turn wire requires an explicit output budget. The panel does not ask
   * the researcher to size one; a fixed, named budget keeps every turn
   * request shaped identically.
   */
  const TURN_MAX_OUTPUT_TOKENS = 4096;

  // ------------------------------------------------------------ credential --

  /**
   * The per-run loopback session credential.
   *
   * This is not a provider key. It authorizes this page against the local
   * listener on this machine, is minted per run by `apiserver.py`, and is held
   * only in this closure: it is never persisted, never rendered, and never
   * placed in a URL that leaves the fragment.
   */
  let sessionToken = "";

  function readInjectedToken() {
    const meta = document.querySelector('meta[name="nipo-local-token"]');
    const value = meta instanceof HTMLMetaElement ? meta.content.trim() : "";
    if (value && meta instanceof HTMLMetaElement) {
      // Remove it from the document so the credential is not readable from the
      // DOM for the rest of the session.
      meta.content = "";
    }
    return value;
  }

  /**
   * Take a credential out of the URL fragment and scrub the fragment.
   *
   * A fragment is never sent to a server and never appears in a `Referer`, so
   * it is the only URL position a launcher may use. It is still removed
   * immediately so the value does not sit in the address bar or in history.
   */
  function readFragmentToken() {
    const raw = window.location.hash.replace(/^#/u, "");
    if (!raw.includes("token=")) return "";
    const params = new URLSearchParams(raw.replace(/^\/+/u, ""));
    const value = (params.get("token") ?? "").trim();
    if (!value) return "";
    params.delete("token");
    const route = params.get("r") ?? "";
    params.delete("r");
    const rest = params.toString();
    const next = route || (rest ? `?${rest}` : "/settings/models");
    window.history.replaceState(null, "", `${window.location.pathname}#${next}`);
    return value;
  }

  // -------------------------------------------------------------- API client --

  class LocalApiError extends Error {
    constructor(status, code, reason, scienceIssue) {
      super(code || `http_${status}`);
      this.status = status;
      this.code = code || "";
      this.reason = reason || "";
      // Closed science-package issue token from intake refusals; never prose.
      this.science_issue = scienceIssue || "";
    }
  }

  const ERROR_TEXT = {
    local_token_required: "로컬 세션 토큰이 필요합니다. 이 페이지를 런처에서 다시 열어 주세요.",
    local_token_invalid: "로컬 세션 토큰이 올바르지 않습니다. 워크벤치를 다시 시작해 주세요.",
    cross_origin_denied: "다른 출처에서 온 요청이라 거부되었습니다.",
    host_not_allowed: "이 주소로는 로컬 서버가 응답하지 않습니다.",
    not_found: "요청한 대상을 찾을 수 없습니다.",
    invalid_request: "요청 형식이 올바르지 않습니다.",
    invalid_name: "이름을 사용할 수 없습니다.",
    name_in_use: "같은 이름이 이미 있습니다.",
    project_archived: "보관된 프로젝트에는 쓸 수 없습니다.",
    session_archived: "보관된 세션입니다.",
    unknown_provider: "알 수 없는 제공자입니다.",
    key_not_required: "이 제공자는 API 키가 필요 없습니다.",
    key_rejected: "키를 저장하지 않았습니다.",
    model_id_malformed: "모델 ID는 `제공자:모델` 형식이어야 합니다.",
    model_not_enabled: "기본 모델은 목록에 있는 모델이어야 합니다.",
    credential_backend_unavailable: "이 컴퓨터의 자격 증명 저장소를 열 수 없습니다.",
    local_state_unreadable: "로컬 설정 파일을 읽을 수 없습니다.",
    store_unavailable: "로컬 저장소를 사용할 수 없습니다.",
    content_corrupt: "저장된 내용의 해시가 맞지 않아 읽기를 거부했습니다.",
    run_surface_unavailable: "실행 기록 표면이 아직 이 설치본에 연결되지 않았습니다.",
    review_not_found: "이 실행에는 아직 검토 기록이 없습니다.",
    review_evidence_missing: "이 실행은 고정된 결과물이 없어 검토할 증거가 없습니다.",
    export_evidence_missing: "이 실행은 커밋한 결과물이 없어 내보낼 증거가 없습니다.",
    export_selection_rejected: "선택을 그대로 내보낼 수 없습니다.",
    export_refused: "팩을 만들지 않고 거부했습니다.",
    export_pack_not_found: "그 팩을 찾을 수 없습니다. 다시 만들어 주세요.",
    download_ticket_invalid: "이 내려받기 링크는 쓸 수 없습니다. 다시 내려받기를 눌러 주세요.",
    download_ticket_expired: "내려받기 링크가 만료되었습니다. 다시 내려받기를 눌러 주세요.",
    download_ticket_spent: "이 내려받기 링크는 이미 한 번 사용되었습니다. 다시 내려받기를 눌러 주세요.",
    method_not_allowed: "허용되지 않은 요청입니다.",
    payload_too_large: "요청이 너무 큽니다.",
    internal_error: "로컬 서버에서 처리하지 못했습니다.",
    plan_not_found: "ActionPlan을 찾을 수 없습니다.",
    approval_not_found: "계획 승인 기록을 찾을 수 없습니다.",
    approval_exists: "이미 승인된 플랜입니다.",
    approval_expired: "승인 유효 기간이 지났습니다.",
    approval_consumed: "이미 사용된 승인입니다.",
    approval_digest_mismatch: "연구 의도가 승인된 플랜과 달라 거부되었습니다.",
    input_digest_mismatch: "업로드 영수증의 입력 다이제스트와 제출한 측정 입력이 달라 거부되었습니다.",
    approval_forbidden: "이 승인을 사용할 수 없습니다.",
    run_rejected: "실행을 시작하지 않고 거부했습니다.",
  };
  const LOADER_REASON_TEXT = {
    manifest_not_found: "매니페스트 파일을 찾지 못했습니다.",
    data_file_not_found: "측정 데이터 파일을 찾지 못했습니다.",
    manifest_syntax: "매니페스트 문법 오류입니다.",
    manifest_schema: "매니페스트 형식이 올바르지 않습니다.",
    manifest_kind_mismatch: "선택한 종류와 매니페스트의 종류가 다릅니다.",
    malformed_data: "측정 데이터 형식이 올바르지 않습니다.",
    metadata_rejected: "메타데이터가 거부되었습니다.",
    data_too_large: "측정 파일이 허용 크기를 넘습니다.",
    image_exceeds_product_pixel_cap: "이미지 픽셀 수가 허용 한도를 넘습니다.",
    invalid_base64: "측정 데이터 인코딩이 올바르지 않습니다.",
    unsafe_filename: "파일 이름을 사용할 수 없습니다.",
  };

  /*
   * L10 turn failures arrive as closed codes. `turn_failed` carries one of
   * the eleven provider-neutral ModelCallFailure tokens as its reason, and
   * the pre-egress refusals carry their own codes. These maps are the only
   * place those tokens become sentences: an unknown token falls back to a
   * generic sentence, never to the raw token or to provider prose.
   */
  const TURN_FAILURE_TEXT = {
    authentication: "인증에 실패했습니다. 설정에서 이 제공자의 API 키를 확인해 주세요.",
    rate_limit: "요청 한도를 초과했습니다. 잠시 뒤 같은 모델로 다시 보내 주세요.",
    quota: "제공자 계정의 할당량을 모두 사용했습니다.",
    model_unavailable: "선택한 모델을 지금 사용할 수 없습니다.",
    provider_unavailable: "제공자 서비스에 지금 연결할 수 없습니다.",
    invalid_request: "제공자가 요청 형식을 거부했습니다.",
    timeout: "제공자 응답이 제한 시간 안에 도착하지 않았습니다.",
    transport: "제공자와의 연결이 끊겼습니다.",
    malformed_response: "제공자 응답 형식이 올바르지 않습니다.",
    response_too_large: "응답이 너무 커서 받지 못했습니다.",
    unclassified: "제공자 호출이 알 수 없는 이유로 실패했습니다.",
  };

  const TURN_CODE_TEXT = {
    provider_not_configured: "이 제공자의 API 키가 등록되어 있지 않습니다. 설정에서 키를 등록하세요.",
    model_selection_locked: "이 실행은 고정된 모델만 사용합니다.",
    model_not_enabled: "작성기에서 사용하도록 설정된 모델만 고를 수 있습니다.",
  };

  function describeTurnFailure(error) {
    if (!(error instanceof LocalApiError)) return describeError(error);
    if (error.code === "turn_failed") {
      const detail = TURN_FAILURE_TEXT[error.reason] || "제공자 호출이 실패했습니다.";
      return `모델 호출이 실패했습니다. ${detail}`;
    }
    return TURN_CODE_TEXT[error.code] || describeError(error);
  }

  const NAME_REASON_TEXT = {
    empty: "이름이 비어 있습니다.",
    too_long: "이름이 255자를 넘습니다.",
    not_nfc: "이름이 유니코드 NFC 정규형이 아닙니다.",
    boundary_whitespace: "이름 앞뒤에 공백이 있습니다.",
    invisible_character: "이름에 보이지 않는 문자가 있습니다.",
    path_separator: "이름에 경로 구분자를 쓸 수 없습니다.",
    relative_segment: "`.` 또는 `..`는 이름이 될 수 없습니다.",
    trailing_dot: "이름은 마침표로 끝날 수 없습니다.",
    reserved_device_name: "예약된 장치 이름은 쓸 수 없습니다.",
    absolute_path: "절대 경로 형태의 이름은 쓸 수 없습니다.",
    drive_qualified: "드라이브 문자로 시작하는 이름은 쓸 수 없습니다.",
  };

  const KEY_REASON_TEXT = {
    empty: "키가 비어 있습니다.",
    surrounding_whitespace: "키 앞뒤에 공백이 붙어 있습니다. 붙여넣기 흔적을 지워 주세요.",
    invisible_character: "키에 보이지 않는 문자가 섞여 있습니다. 붙여넣기 흔적을 지워 주세요.",
    too_long: "키가 너무 깁니다.",
  };

  /*
   * Why the packer's own refusal is spelled out here.
   *
   * `exportpack.py` refuses a whole pack rather than sanitizing an entry, and
   * the reason it refuses is the most useful thing a researcher can be told:
   * "credential material was found in a member" and "an entry collided with a
   * reserved pack root" call for completely different actions. The API sends
   * the closed reason beside the code, so this map turns it into a sentence
   * instead of dropping it.
   */
  const EXPORT_REASON_TEXT = {
    selection_empty: "내보낼 버전을 하나 이상 선택해야 합니다.",
    selection_duplicate: "같은 버전을 두 번 선택했습니다.",
    selection_not_pinned_to_run:
      "이 실행이 커밋하지 않은 버전은 선택할 수 없습니다. 내보내기는 '최신'을 대신 찾아 주지 않습니다.",
    credential_material: "팩에 담길 내용에서 자격 증명으로 보이는 바이트가 발견되어 전체를 거부했습니다.",
    version_not_pinned: "버전이 고정되지 않은 항목이 있어 거부했습니다.",
    selection_unsorted: "선택 목록의 순서가 규칙과 달라 거부했습니다.",
    selection_mismatch: "선언한 선택과 실제로 담길 항목이 달라 거부했습니다.",
    content_digest_mismatch: "저장된 내용의 해시가 고정된 값과 달라 거부했습니다.",
    content_unavailable: "선택한 버전의 내용을 읽을 수 없어 거부했습니다.",
    version_not_found: "선택한 버전을 찾을 수 없어 거부했습니다.",
    project_archived: "보관된 프로젝트의 증거는 내보낼 수 없습니다.",
    run_not_found: "실행 기록을 찾을 수 없습니다.",
    execution_missing: "이 실행에는 커밋된 결과물이 없어 출처를 고정할 수 없습니다.",
    plan_not_found: "ActionPlan을 찾을 수 없습니다.",
    approval_not_found: "계획 승인 기록을 찾을 수 없습니다.",
    path_reserved_root: "결과물 이름이 팩이 예약한 문서 이름과 겹쳐 거부했습니다.",
    path_collision: "정규화하면 서로 겹치는 경로가 있어 거부했습니다.",
    path_directory_prefix: "한 경로가 다른 경로의 상위 디렉터리라 거부했습니다.",
    link_entry: "일반 파일이 아닌 항목이 있어 거부했습니다.",
    destination_exists: "같은 이름의 팩 파일이 이미 있어 덮어쓰지 않고 거부했습니다.",
    intent_digest_mismatch: "첨부한 ResearchIntent 바이트가 고정된 다이제스트와 달라 거부했습니다.",
    input_digest_mismatch: "첨부한 입력 바이트가 고정된 다이제스트와 달라 거부했습니다.",
    environment_digest_mismatch: "첨부한 환경 정보가 고정된 다이제스트와 달라 거부했습니다.",
    exports_unreadable:
      "내보내기 폴더가 일반 디렉터리가 아니거나 읽을 수 없어 목록을 만들지 않았습니다. 폴더를 따라가는 대신 거부했습니다.",
  };

  function describeError(error) {
    if (!(error instanceof LocalApiError)) {
      return "로컬 서버에 연결하지 못했습니다. 워크벤치가 실행 중인지 확인해 주세요.";
    }
    const base = ERROR_TEXT[error.code] || `요청이 거부되었습니다 (${error.code || error.status}).`;
    const detail =
      NAME_REASON_TEXT[error.reason] ||
      KEY_REASON_TEXT[error.reason] ||
      EXPORT_REASON_TEXT[error.reason] ||
      LOADER_REASON_TEXT[error.reason] ||
      (error.reason ? `거부 사유: ${error.reason}` : "");
    let message = detail ? `${base} ${detail}` : base;
    if (error.science_issue) {
      message = `${message} 과학 이슈: ${error.science_issue}`;
    }
    return message;
  }

  async function request(method, path, body) {
    const init = {
      method,
      // Same-origin only. A custom credential header cannot cross an origin
      // without a preflight, and the local guard refuses every preflight.
      mode: "same-origin",
      credentials: "omit",
      cache: "no-store",
      redirect: "error",
      headers: { [TOKEN_HEADER]: sessionToken },
    };
    if (body !== undefined) {
      init.headers["content-type"] = "application/json";
      init.body = JSON.stringify(body);
    }
    const response = await fetch(`${API}${path}`, init);
    if (response.status === 204) return null;
    const text = await response.text();
    let payload = null;
    if (text) {
      try {
        payload = JSON.parse(text);
      } catch {
        payload = null;
      }
    }
    if (!response.ok) {
      const code = payload && typeof payload.error === "string" ? payload.error : "";
      const reason = payload && typeof payload.reason === "string" ? payload.reason : "";
      const scienceIssue =
        payload && typeof payload.science_issue === "string" ? payload.science_issue : "";
      throw new LocalApiError(response.status, code, reason, scienceIssue);
    }
    return payload;
  }

  const api = {
    health: () => request("GET", "/health"),
    providers: () => request("GET", "/providers"),
    setKey: (id, key) => request("PUT", `/providers/${encodeURIComponent(id)}/key`, { key }),
    clearKey: (id) => request("DELETE", `/providers/${encodeURIComponent(id)}/key`),
    composer: () => request("GET", "/composer"),
    writeComposer: (enabled, fallback) =>
      request("PUT", "/composer", { enabled_models: enabled, default_model: fallback }),
    projects: () => request("GET", "/projects"),
    createProject: (name) => request("POST", "/projects", { name }),
    archiveProject: (id) => request("POST", `/projects/${id}/archive`),
    sessions: (pid) => request("GET", `/projects/${pid}/sessions`),
    createSession: (pid, title) => request("POST", `/projects/${pid}/sessions`, { title }),
    resumeSession: (pid, sid) => request("POST", `/projects/${pid}/sessions/${sid}/resume`),
    archiveSession: (pid, sid) => request("POST", `/projects/${pid}/sessions/${sid}/archive`),
    artifacts: (pid) => request("GET", `/projects/${pid}/artifacts`),
    artifact: (pid, aid) => request("GET", `/projects/${pid}/artifacts/${aid}`),
    provenance: (pid, aid, vid) =>
      request("GET", `/projects/${pid}/artifacts/${aid}/versions/${vid}/provenance`),
    runs: (pid) => request("GET", `/projects/${pid}/runs`),
    run: (pid, rid) => request("GET", `/projects/${pid}/runs/${rid}`),
    createTurn: (pid, rid, body) => request("POST", `/projects/${pid}/runs/${rid}/turns`, body),
    review: (pid, rid) => request("GET", `/projects/${pid}/runs/${rid}/review`),
    openReview: (pid, rid) => request("POST", `/projects/${pid}/runs/${rid}/review`),
    exportPlan: (pid, rid) => request("GET", `/projects/${pid}/runs/${rid}/export`),
    createExport: (pid, rid, versionIds) =>
      request("POST", `/projects/${pid}/runs/${rid}/export`, {
        artifact_version_ids: versionIds,
      }),
    exportPacks: (pid) => request("GET", `/projects/${pid}/exports`),
    deleteExportPack: (pid, packId) => request("DELETE", `/projects/${pid}/exports/${packId}`),
    downloadGrant: (pid, packId) =>
      request("POST", `/projects/${pid}/exports/${packId}/download`),
    contentUrl: (pid, aid, vid) => `${API}/projects/${pid}/artifacts/${aid}/versions/${vid}/content`,
    createActionPlan: (pid, sessionId, researchIntent) =>
      request("POST", `/projects/${pid}/action-plans`, {
        session_id: sessionId,
        research_intent: researchIntent,
      }),
    approveActionPlan: (pid, planId) =>
      request("POST", `/projects/${pid}/action-plans/${planId}/approvals`, {}),
    actionPlan: (pid, planId) => request("GET", `/projects/${pid}/action-plans/${planId}`),
    approval: (pid, approvalId) => request("GET", `/projects/${pid}/approvals/${approvalId}`),
    createRun: (pid, body) => request("POST", `/projects/${pid}/runs`, body),
    probeInput: (pid, body) => request("POST", `/projects/${pid}/inputs/probe`, body),
  };

  // ------------------------------------------------------------ DOM helpers --

  function el(tag, options, children) {
    const node = document.createElement(tag);
    const settings = options || {};
    for (const [name, value] of Object.entries(settings)) {
      if (value === null || value === undefined || value === false) continue;
      if (name === "style") {
        // The document is served under `style-src 'self'` with no
        // `'unsafe-inline'`, so a style attribute is refused by the browser:
        // the layout quietly breaks and the console fills with violations.
        // Failing loudly here turns that into a mistake that cannot ship.
        throw new Error("inline style is blocked by the document CSP; use a class");
      }
      if (name === "text") {
        node.textContent = String(value);
      } else if (name === "class") {
        node.className = String(value);
      } else if (name === "dataset") {
        for (const [key, item] of Object.entries(value)) node.dataset[key] = String(item);
      } else if (name === "on") {
        for (const [event, handler] of Object.entries(value)) node.addEventListener(event, handler);
      } else if (value === true) {
        node.setAttribute(name, "");
      } else {
        node.setAttribute(name, String(value));
      }
    }
    for (const child of children || []) {
      if (child === null || child === undefined || child === false) continue;
      node.append(typeof child === "string" ? document.createTextNode(child) : child);
    }
    return node;
  }

  function icon(path) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    svg.setAttribute("viewBox", "0 0 16 16");
    svg.setAttribute("aria-hidden", "true");
    svg.setAttribute("focusable", "false");
    const shape = document.createElementNS("http://www.w3.org/2000/svg", "path");
    shape.setAttribute("d", path);
    shape.setAttribute("fill", "none");
    shape.setAttribute("stroke", "currentColor");
    shape.setAttribute("stroke-width", "1.6");
    shape.setAttribute("stroke-linecap", "round");
    shape.setAttribute("stroke-linejoin", "round");
    svg.append(shape);
    return svg;
  }

  const ICONS = {
    check: "m3 8.4 3.2 3.2L13 4.8",
    dash: "M3.5 8h9",
    minus: "M3.5 8h9",
    alert: "M8 5v4M8 11.2v.1M8 2.2 1.6 13.4h12.8z",
    clock: "M8 4.4V8l2.4 1.6M14 8A6 6 0 1 1 2 8a6 6 0 0 1 12 0Z",
    cross: "m4.5 4.5 7 7m0-7-7 7",
  };

  function badge(kind, label, glyph) {
    return el("span", { class: `badge badge--${kind}` }, [glyph ? icon(glyph) : null, label]);
  }

  function formatMoment(value) {
    if (typeof value !== "string" || !value) return "기록 없음";
    const moment = new Date(value);
    if (Number.isNaN(moment.getTime())) return value;
    return new Intl.DateTimeFormat("ko-KR", {
      dateStyle: "medium",
      timeStyle: "short",
    }).format(moment);
  }

  function formatBytes(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) return "알 수 없음";
    if (value < 1024) return `${value} B`;
    const units = ["KB", "MB", "GB"];
    let size = value / 1024;
    let index = 0;
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024;
      index += 1;
    }
    return `${size.toFixed(1)} ${units[index]}`;
  }

  /**
   * Render a byte count exactly, beside the rounded one.
   *
   * A disk-usage screen that only ever says "1.2 GB" cannot be checked against
   * the researcher's own file manager, and the rounded form hides the
   * difference between two packs that differ by tens of megabytes.
   */
  function formatExactBytes(value) {
    if (typeof value !== "number" || !Number.isFinite(value)) return "알 수 없음";
    return `${new Intl.NumberFormat("ko-KR").format(value)} B`;
  }

  /**
   * Arm a destructive control on its first press; report armed on the second.
   *
   * The armed state has to change the control's *accessible* name, not only
   * the text a sighted reader sees. These buttons carry an `aria-label`, and
   * an `aria-label` wins over `textContent`: rewriting the visible label alone
   * would leave a screen-reader user hearing the same "지우기" twice and
   * pressing a button whose meaning had silently changed under them. Both are
   * rewritten here, in one place, so the two cannot drift apart again.
   */
  function armConfirmation(button, armedText, armedLabel) {
    if (button.dataset.confirm === "yes") return true;
    button.dataset.confirm = "yes";
    button.textContent = armedText;
    button.setAttribute("aria-label", armedLabel);
    return false;
  }

  function keyValues(pairs) {
    const list = el("dl", { class: "key-values" });
    for (const [term, value, mono] of pairs) {
      list.append(
        el("div", {}, [
          el("dt", { text: term }),
          el("dd", { class: mono ? "hash" : null, text: value }),
        ]),
      );
    }
    return list;
  }

  function emptyState(title, detail, action) {
    return el("div", { class: "empty-state" }, [
      el("h3", { text: title }),
      el("p", { text: detail }),
      action || null,
    ]);
  }

  function loadingState(label) {
    return el("div", { class: "loading-state", role: "status" }, [el("p", { text: label })]);
  }

  function pageHeader(eyebrow, title, lede) {
    return el("div", { class: "page-header" }, [
      el("p", { class: "page-header__eyebrow", text: eyebrow }),
      el("h1", { text: title }),
      lede ? el("p", { class: "page-header__lede", text: lede }) : null,
    ]);
  }

  function breadcrumb(items) {
    return el("nav", { class: "breadcrumb", "aria-label": "위치" }, [
      el(
        "ol",
        {},
        items.map((item) =>
          el("li", {}, [item.href ? el("a", { href: item.href, text: item.label }) : item.label]),
        ),
      ),
    ]);
  }

  // -------------------------------------------------- isolation disclosure --

  /**
   * Render the honest disclosure for one recorded isolation level.
   *
   * SPEC-v0.5 section 5 forbids describing in-process execution as a sandbox.
   * This returns a plain disclosure panel in every branch; there is no code
   * path here that produces a "sandboxed" or "secure" badge.
   */
  function isolationDisclosure(value) {
    if (value === "in_process") {
      return el("div", { class: "disclosure", "data-isolation": "in_process" }, [
        el("p", { class: "disclosure__title" }, [icon(ICONS.alert), "격리 없음 — 이 컴퓨터의 프로세스 안에서 실행됨"]),
        el("p", {
          text:
            "이 실행은 별도의 샌드박스 없이 Nipo Science 자신의 인터프리터 프로세스 안에서 실행되었습니다. " +
            "분석 코드와 입력 파서는 연구자 계정의 권한을 그대로 가지며, 데이터 루트와 그 안의 자격 증명 파일을 읽을 수 있습니다. " +
            "이 제품은 이 실행에 대해 파일 시스템·네트워크·시스템 호출·자원 한도 중 어떤 것도 차단하지 않습니다.",
        }),
        el("p", { class: "meta", text: "기록된 값: execution_isolation = in_process" }),
      ]);
    }
    if (value === null || value === undefined || value === "") {
      return el("div", { class: "panel panel--attention", "data-isolation": "unrecorded" }, [
        el("p", { class: "disclosure__title" }, [icon(ICONS.alert), "격리 수준이 기록되지 않았습니다"]),
        el("p", {
          text:
            "이 버전을 만든 실행의 격리 수준을 이 설치본이 답할 수 없습니다. " +
            "격리되었다고 가정하지 마십시오. 실행 기록 표면이 연결되면 값이 채워집니다.",
        }),
      ]);
    }
    return el("div", { class: "panel panel--attention", "data-isolation": String(value) }, [
      el("p", { class: "disclosure__title" }, [icon(ICONS.alert), `기록된 격리 수준: ${String(value)}`]),
      el("p", {
        text:
          "이 값은 실행이 스스로 기록한 문자열이며, 이 화면이 검증한 통제가 아닙니다. " +
          "제품이 측정하지 않은 격리는 보장되지 않습니다.",
      }),
    ]);
  }

  // ------------------------------------------------------------- app state --

  const state = {
    identity: null,
    projectId: null,
    projects: [],
  };

  const screen = document.getElementById("screen");
  const errorRegion = document.getElementById("error-region");
  const liveRegion = document.getElementById("live-region");
  const workspaceActions = document.getElementById("workspace-actions");
  const workspaceTitle = document.getElementById("workspace-title");
  const identityNode = document.getElementById("local-identity");

  let pendingAnnouncement = "";

  function writeLive(message) {
    liveRegion.textContent = "";
    window.setTimeout(() => {
      liveRegion.textContent = message;
    }, 20);
  }

  /**
   * Announce the outcome of something the researcher did.
   *
   * Most actions re-render their screen, and the re-render would otherwise
   * overwrite this with a generic "…을 표시했습니다". The outcome is held so it
   * survives that render and remains the last thing a screen reader says.
   */
  function announce(message) {
    pendingAnnouncement = message;
    writeLive(message);
  }

  /** Announce that a screen finished rendering, yielding to any action outcome. */
  function announceScreen(message) {
    const held = pendingAnnouncement;
    pendingAnnouncement = "";
    writeLive(held || message);
  }

  function showError(message) {
    errorRegion.textContent = message;
    errorRegion.hidden = false;
  }

  function clearError() {
    errorRegion.textContent = "";
    errorRegion.hidden = true;
  }

  function render(nodes) {
    screen.textContent = "";
    screen.removeAttribute("aria-busy");
    for (const node of nodes) if (node) screen.append(node);
  }

  function setBarActions(nodes) {
    workspaceActions.textContent = "";
    for (const node of nodes) if (node) workspaceActions.append(node);
  }

  // ------------------------------------------------------- settings › models --

  const PROVIDER_STATUS = {
    configured: { kind: "positive", label: "설정됨", glyph: ICONS.check },
    not_set_up: { kind: "attention", label: "설정 안 됨", glyph: ICONS.dash },
    no_key_needed: { kind: "info", label: "키 필요 없음", glyph: ICONS.minus },
  };

  function providerCard(card, onChanged) {
    const status = PROVIDER_STATUS[card.status] || {
      kind: "neutral",
      label: `알 수 없는 상태 (${card.status})`,
      glyph: ICONS.alert,
    };
    const node = el("li", {
      class: "provider-card",
      dataset: { provider: card.provider_id, status: card.status },
    });
    node.append(
      el("div", { class: "provider-card__head" }, [
        el("div", {}, [
          el("p", { class: "provider-card__name", text: card.display_name }),
          el("p", { class: "meta", text: card.provider_id }),
        ]),
        badge(status.kind, status.label, status.glyph),
      ]),
    );

    if (!card.requires_key) {
      node.append(
        el("p", {
          class: "meta",
          text: "이 제공자는 API 키 없이 사용합니다. 이 컴퓨터에서 실행되는 모델만 호출합니다.",
        }),
      );
      return node;
    }

    if (card.env_var) {
      node.append(
        el("p", { class: "provider-card__env", text: `환경 변수: ${card.env_var}` }),
      );
    }

    const form = el("form", { class: "provider-card__form", hidden: true, novalidate: true });
    const inputId = `provider-key-${card.provider_id}`;
    const helpId = `provider-key-help-${card.provider_id}`;
    const input = el("input", {
      id: inputId,
      name: "key",
      type: "password",
      autocomplete: "off",
      spellcheck: "false",
      "aria-describedby": helpId,
      placeholder: "키 붙여넣기",
    });
    form.append(
      el("div", { class: "field" }, [
        el("label", { class: "field__label", for: inputId, text: `${card.display_name} API 키` }),
        input,
        el("p", {
          class: "field__help",
          id: helpId,
          text: "저장한 뒤에는 이 화면 어디에서도 키를 다시 볼 수 없습니다. 설정 여부만 표시됩니다.",
        }),
      ]),
    );
    const submit = el("button", {
      class: "button button--primary button--small",
      type: "submit",
      text: "키 저장",
    });
    const cancel = el("button", {
      class: "button button--quiet button--small",
      type: "button",
      text: "취소",
    });
    form.append(el("div", { class: "actions" }, [submit, cancel]));

    const openForm = el("button", {
      class: "button button--small",
      type: "button",
      text: card.status === "configured" ? "키 교체" : "키 설정",
      dataset: { action: "open-key-form" },
      "aria-expanded": "false",
      "aria-controls": inputId,
    });
    const controls = el("div", { class: "actions" }, [openForm]);
    if (card.status === "configured") {
      controls.append(
        el("button", {
          class: "button button--danger button--small",
          type: "button",
          text: "키 지우기",
          dataset: { action: "clear-key" },
          on: {
            click: async (event) => {
              const button = event.currentTarget;
              if (button.dataset.confirm !== "yes") {
                button.dataset.confirm = "yes";
                button.textContent = "정말 지울까요? 한 번 더 누르세요";
                return;
              }
              button.disabled = true;
              try {
                await api.clearKey(card.provider_id);
                announce(`${card.display_name} 키를 이 컴퓨터에서 지웠습니다.`);
                clearError();
                await onChanged();
              } catch (error) {
                button.disabled = false;
                showError(describeError(error));
              }
            },
          },
        }),
      );
    }
    node.append(controls, form);

    openForm.addEventListener("click", () => {
      form.hidden = false;
      openForm.setAttribute("aria-expanded", "true");
      input.focus();
    });
    cancel.addEventListener("click", () => {
      // Clearing before hiding means an abandoned form leaves nothing behind.
      input.value = "";
      form.hidden = true;
      openForm.setAttribute("aria-expanded", "false");
      openForm.focus();
    });
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const submitted = input.value;
      // The value leaves the control before the network call, so it is not in
      // the DOM while the request is in flight and cannot be restored on error.
      input.value = "";
      if (!submitted) {
        input.setAttribute("aria-invalid", "true");
        showError("키가 비어 있어 저장하지 않았습니다.");
        input.focus();
        return;
      }
      input.removeAttribute("aria-invalid");
      submit.disabled = true;
      submit.textContent = "저장 중";
      try {
        await api.setKey(card.provider_id, submitted);
        clearError();
        announce(`${card.display_name} 키를 이 컴퓨터에 저장했습니다.`);
        await onChanged();
      } catch (error) {
        submit.disabled = false;
        submit.textContent = "키 저장";
        showError(describeError(error));
        input.focus();
      }
    });
    return node;
  }

  function composerSection(picker, reload) {
    const models = Array.isArray(picker.models) ? picker.models : [];
    const enabled = models.map((item) => item.model_id);
    const section = el("section", { class: "section", "aria-labelledby": "composer-heading" });
    section.append(
      el("div", { class: "section__head" }, [
        el("h2", { id: "composer-heading", text: "작성기 모델 선택" }),
        el("p", {
          class: "section__hint",
          text: "새 세션을 시작할 때 고를 수 있는 모델입니다. 기본 모델은 하나만 지정됩니다.",
        }),
      ]),
    );

    async function write(nextEnabled, nextDefault, message) {
      try {
        await api.writeComposer(nextEnabled, nextDefault);
        clearError();
        announce(message);
        await reload();
      } catch (error) {
        showError(describeError(error));
      }
    }

    if (models.length === 0) {
      section.append(
        emptyState(
          "선택할 모델이 없습니다",
          "아래에서 `제공자:모델` 형식으로 모델을 추가하면 작성기 선택 목록에 나타납니다.",
        ),
      );
    } else {
      const list = el("ul", { class: "composer-list" });
      for (const entry of models) {
        const row = el("li", {
          class: "composer-row",
          dataset: { model: entry.model_id, default: String(entry.is_default === true) },
        });
        row.append(
          el("div", { class: "composer-row__id" }, [
            el("span", { class: "composer-row__model", text: entry.model_id }),
            el("span", { class: "meta", text: entry.display_name }),
          ]),
        );
        const actions = el("div", { class: "actions" });
        if (entry.is_default === true) {
          actions.append(badge("positive", "기본", ICONS.check));
        } else {
          actions.append(
            el("button", {
              class: "button button--small",
              type: "button",
              text: "기본으로 지정",
              "aria-label": `${entry.model_id}을(를) 기본 모델로 지정`,
              on: {
                click: () =>
                  write(enabled, entry.model_id, `${entry.model_id}을(를) 기본 모델로 지정했습니다.`),
              },
            }),
          );
        }
        actions.append(
          el("button", {
            class: "button button--quiet button--small",
            type: "button",
            text: "목록에서 제거",
            "aria-label": `${entry.model_id}을(를) 목록에서 제거`,
            on: {
              click: () => {
                const next = enabled.filter((item) => item !== entry.model_id);
                const fallback = entry.is_default === true ? null : picker.default_model ?? null;
                return write(next, fallback, `${entry.model_id}을(를) 목록에서 제거했습니다.`);
              },
            },
          }),
        );
        row.append(actions);
        list.append(row);
      }
      section.append(list);
      if (!picker.default_model) {
        section.append(
          el("p", { class: "inline-note", "data-state": "no-default" }, [
            "기본 모델이 지정되지 않았습니다. 세션을 시작할 때 모델을 매번 골라야 합니다.",
          ]),
        );
      }
    }

    const addForm = el("form", { class: "panel", novalidate: true });
    const addInput = el("input", {
      id: "composer-add-model",
      name: "model_id",
      type: "text",
      autocomplete: "off",
      spellcheck: "false",
      placeholder: "anthropic:claude-sonnet-4",
      "aria-describedby": "composer-add-help",
    });
    addForm.append(
      el("div", { class: "form-row" }, [
        el("div", { class: "field" }, [
          el("label", { class: "field__label", for: "composer-add-model", text: "모델 추가" }),
          addInput,
          el("p", {
            class: "field__help",
            id: "composer-add-help",
            text: "`제공자:모델` 형식으로 적습니다. 제공자 ID는 위 카드에 표시된 값입니다.",
          }),
        ]),
        el("button", { class: "button button--primary", type: "submit", text: "목록에 추가" }),
      ]),
    );
    addForm.addEventListener("submit", (event) => {
      event.preventDefault();
      const value = addInput.value.trim();
      if (!value) {
        addInput.setAttribute("aria-invalid", "true");
        showError("모델 ID를 입력해 주세요.");
        addInput.focus();
        return;
      }
      addInput.removeAttribute("aria-invalid");
      addInput.value = "";
      const next = enabled.includes(value) ? enabled : [...enabled, value];
      const fallback = picker.default_model ?? (next.length === 1 ? value : null);
      void write(next, fallback, `${value}을(를) 목록에 추가했습니다.`);
    });
    section.append(addForm);
    return section;
  }

  async function renderModelSettings() {
    document.title = "모델 설정 — Nipo Science local";
    setBarActions([]);
    workspaceTitle.textContent = "모델 설정";
    render([pageHeader("설정", "모델 설정", "불러오는 중입니다."), loadingState("제공자 상태를 읽는 중")]);

    const reload = () => renderModelSettings();
    let providers;
    let picker;
    try {
      [providers, picker] = await Promise.all([api.providers(), api.composer()]);
    } catch (error) {
      showError(describeError(error));
      render([
        pageHeader("설정", "모델 설정", "제공자 상태를 읽지 못했습니다."),
        emptyState(
          "제공자 목록을 불러오지 못했습니다",
          describeError(error),
          el("button", {
            class: "button button--primary",
            type: "button",
            text: "다시 시도",
            on: { click: () => void reload() },
          }),
        ),
      ]);
      return;
    }

    const cards = Array.isArray(providers.providers) ? providers.providers : [];
    const configured = cards.filter((item) => item.status === "configured").length;
    const grid = el("ul", { class: "provider-grid" });
    for (const card of cards) grid.append(providerCard(card, reload));

    render([
      pageHeader(
        "설정",
        "모델 설정",
        "이 컴퓨터에서 호출할 제공자를 준비하고, 세션을 시작할 때 보일 모델 목록을 정합니다.",
      ),
      el("div", { class: "privacy-note" }, [
        icon("M8 1.6 2.4 4v4c0 3.1 2.3 5.6 5.6 6.4 3.3-.8 5.6-3.3 5.6-6.4V4Zm0 4.6v2.6"),
        el("p", {}, [
          el("strong", { text: "API 키는 이 컴퓨터에만 저장됩니다." }),
          " 키는 이 기기의 자격 증명 저장소에 봉인되어 남고, 서버로 올라가지 않으며, 어떤 응답이나 화면에도 다시 나타나지 않습니다. 이 화면은 키가 설정되었는지 여부만 보여 줍니다.",
        ]),
      ]),
      el("section", { class: "section", "aria-labelledby": "providers-heading" }, [
        el("div", { class: "section__head" }, [
          el("h2", { id: "providers-heading", text: "제공자" }),
          el("p", {
            class: "section__hint",
            text: `${cards.length}개 중 ${configured}개가 설정되어 있습니다.`,
          }),
        ]),
        grid,
      ]),
      composerSection(picker, reload),
    ]);
    announceScreen("모델 설정을 표시했습니다.");
  }

  // ------------------------------------------------------------- workspace --

  function projectRow(project, reload) {
    const row = el("li", { class: "object-row", dataset: { project: project.id } });
    row.append(
      el("div", { class: "object-row__body" }, [
        el("p", { class: "object-row__title" }, [
          el("a", { href: `#/projects/${project.id}`, text: project.name }),
          project.archived ? badge("neutral", "보관됨", ICONS.dash) : badge("positive", "활성", ICONS.check),
        ]),
        el("p", { class: "meta", text: `만든 시각 ${formatMoment(project.created_at)}` }),
        el("p", { class: "mono", text: project.id }),
      ]),
    );
    const actions = el("div", { class: "actions" }, [
      el("a", { class: "button button--small", href: `#/projects/${project.id}`, text: "세션 열기" }),
      el("a", {
        class: "button button--small",
        href: `#/projects/${project.id}/artifacts`,
        text: "아티팩트",
      }),
      el("a", { class: "button button--small", href: `#/projects/${project.id}/runs`, text: "실행" }),
    ]);
    if (!project.archived) {
      actions.append(
        el("button", {
          class: "button button--danger button--small",
          type: "button",
          text: "보관",
          "aria-label": `${project.name} 프로젝트 보관`,
          on: {
            click: async (event) => {
              const button = event.currentTarget;
              if (button.dataset.confirm !== "yes") {
                button.dataset.confirm = "yes";
                button.textContent = "보관하면 쓰기가 막힙니다. 한 번 더 누르세요";
                button.setAttribute(
                  "aria-label",
                  `${project.name} 프로젝트 보관 확인: 한 번 더 누르세요`,
                );
                return;
              }
              button.disabled = true;
              try {
                await api.archiveProject(project.id);
                clearError();
                announce(`${project.name} 프로젝트를 보관했습니다.`);
                await reload();
              } catch (error) {
                button.disabled = false;
                showError(describeError(error));
              }
            },
          },
        }),
      );
    }
    row.append(actions);
    return row;
  }

  /**
   * Guided first-run panel for an empty project list.
   *
   * Shown only when the workspace has zero projects. Discloses the data root,
   * loopback-only bind, in_process execution residual, and the Keychain
   * master-key residual (SPEC section 11).
   */
  function renderFirstRunGuide() {
    const createCta = el("button", {
      class: "button button--primary",
      type: "button",
      text: "첫 프로젝트 만들기",
      "data-action": "first-run-create-project",
      on: {
        click: () => {
          const heading = document.getElementById("create-project-heading");
          const input = document.getElementById("new-project-name");
          if (heading) heading.scrollIntoView({ block: "start", behavior: "smooth" });
          if (input) input.focus();
        },
      },
    });
    const settingsCta = el("a", {
      class: "button",
      href: "#/settings/models",
      text: "모델/제공자 설정 열기",
      "data-action": "first-run-open-settings",
    });

    return el(
      "div",
      {
        class: "first-run-guide",
        "data-first-run": "true",
        role: "region",
        "aria-labelledby": "first-run-heading",
      },
      [
        el("h3", { id: "first-run-heading", text: "시작하기 전에" }),
        el("p", {
          class: "first-run-guide__lede",
          text: "이 설치본은 이 컴퓨터에서만 동작하는 단일 사용자 로컬 환경입니다. 아래를 확인한 뒤 첫 프로젝트를 만드세요.",
        }),
        el("ul", { class: "first-run-guide__facts" }, [
          el("li", {
            text:
              "데이터는 홈 디렉터리의 로컬 데이터 루트(~/.nipo-science)에 저장됩니다. " +
              "클라우드 동기화 폴더 밖에 있으며, 소유자 전용 권한으로 유지됩니다.",
          }),
          el("li", {
            text:
              "서버는 루프백 전용으로만 바인딩되며, 외부 접속을 여는 설정·환경 변수·플래그는 없습니다.",
          }),
          el("li", {
            "data-isolation": "in_process",
            text:
              "분석은 공시된 in_process 방식으로 이 설치본의 프로세스 안에서 실행됩니다. " +
              "프로세스 경계를 넘는 통제를 주장하지 않으며, 연구자 계정의 권한을 그대로 사용합니다.",
          }),
          el("li", {
            text:
              "제공자 키를 봉인하는 Keychain 마스터 키 항목은 신뢰 앱 목록 없이 만들어지므로, " +
              "이 앱만 읽을 수 있다고 말하지 않습니다. 같은 계정으로 도는 다른 프로세스도 접근할 수 있습니다.",
          }),
        ]),
        el("div", { class: "actions first-run-guide__actions" }, [createCta, settingsCta]),
      ],
    );
  }

  async function renderWorkspace() {
    document.title = "워크스페이스 — Nipo Science local";
    workspaceTitle.textContent = "워크스페이스";
    setBarActions([]);
    render([pageHeader("워크스페이스", "프로젝트", "불러오는 중입니다."), loadingState("프로젝트를 읽는 중")]);

    const reload = () => renderWorkspace();
    let payload;
    try {
      payload = await api.projects();
    } catch (error) {
      showError(describeError(error));
      render([
        pageHeader("워크스페이스", "프로젝트", "프로젝트를 읽지 못했습니다."),
        emptyState("프로젝트 목록을 불러오지 못했습니다", describeError(error)),
      ]);
      return;
    }
    const projects = Array.isArray(payload.projects) ? payload.projects : [];
    state.projects = projects;
    const active = projects.filter((item) => !item.archived);

    const createForm = el("form", { class: "panel", novalidate: true });
    const nameInput = el("input", {
      id: "new-project-name",
      name: "name",
      type: "text",
      autocomplete: "off",
      "aria-describedby": "new-project-help",
      placeholder: "프로브 반응 재현 2026",
    });
    createForm.append(
      el("div", { class: "form-row" }, [
        el("div", { class: "field" }, [
          el("label", { class: "field__label", for: "new-project-name", text: "새 프로젝트 이름" }),
          nameInput,
          el("p", {
            class: "field__help",
            id: "new-project-help",
            text: "경로 구분자, 앞뒤 공백, 보이지 않는 문자는 저장 전에 거부됩니다.",
          }),
        ]),
        el("button", { class: "button button--primary", type: "submit", text: "프로젝트 만들기" }),
      ]),
    );
    createForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = nameInput.value;
      if (!value) {
        nameInput.setAttribute("aria-invalid", "true");
        showError("프로젝트 이름을 입력해 주세요.");
        nameInput.focus();
        return;
      }
      nameInput.removeAttribute("aria-invalid");
      try {
        const created = await api.createProject(value);
        clearError();
        nameInput.value = "";
        announce(`${created.name} 프로젝트를 만들었습니다.`);
        await reload();
      } catch (error) {
        showError(describeError(error));
        nameInput.setAttribute("aria-invalid", "true");
        nameInput.focus();
      }
    });

    render([
      pageHeader(
        "워크스페이스",
        "프로젝트",
        "이 컴퓨터에 등록된 프로젝트입니다. 프로젝트를 열면 세션, 실행, 아티팩트를 볼 수 있습니다.",
      ),
      el("section", { class: "section", "aria-labelledby": "projects-heading" }, [
        el("div", { class: "section__head" }, [
          el("h2", { id: "projects-heading", text: "프로젝트 목록" }),
          el("p", {
            class: "section__hint",
            text: `전체 ${projects.length}개, 활성 ${active.length}개.`,
          }),
        ]),
        projects.length === 0
          ? renderFirstRunGuide()
          : el("ul", { class: "object-list" }, projects.map((item) => projectRow(item, reload))),
      ]),
      el("section", { class: "section", "aria-labelledby": "create-project-heading" }, [
        el("h2", { id: "create-project-heading", text: "프로젝트 만들기" }),
        createForm,
      ]),
    ]);
    announceScreen("워크스페이스를 표시했습니다.");
  }

  // -------------------------------------------------------- project detail --

  function sessionRow(projectId, session, reload) {
    const row = el("li", { class: "object-row", dataset: { session: session.id } });
    row.append(
      el("div", { class: "object-row__body" }, [
        el("p", { class: "object-row__title" }, [
          session.title,
          session.archived ? badge("neutral", "보관됨", ICONS.dash) : badge("positive", "활성", ICONS.check),
        ]),
        el("p", { class: "meta", text: `마지막 활동 ${formatMoment(session.last_active_at)}` }),
        el("p", { class: "mono", text: session.id }),
      ]),
    );
    const actions = el("div", { class: "actions" });
    if (!session.archived) {
      actions.append(
        el("a", {
          class: "button button--small",
          href: `#/projects/${projectId}/sessions/${session.id}/plan`,
          text: "플랜 작성",
          "aria-label": `${session.title} 세션 플랜 작성`,
          "data-action": "open-plan",
        }),
        el("button", {
          class: "button button--small",
          type: "button",
          text: "이어서 열기",
          "aria-label": `${session.title} 세션 이어서 열기`,
          on: {
            click: async () => {
              try {
                await api.resumeSession(projectId, session.id);
                clearError();
                announce(`${session.title} 세션을 이어서 열었습니다.`);
                await reload();
              } catch (error) {
                showError(describeError(error));
              }
            },
          },
        }),
        el("button", {
          class: "button button--danger button--small",
          type: "button",
          text: "보관",
          "aria-label": `${session.title} 세션 보관`,
          on: {
            click: async (event) => {
              const button = event.currentTarget;
              if (button.dataset.confirm !== "yes") {
                button.dataset.confirm = "yes";
                button.textContent = "보관하면 되돌릴 수 없습니다. 한 번 더 누르세요";
                button.setAttribute(
                  "aria-label",
                  `${session.title} 세션 보관 확인: 한 번 더 누르세요`,
                );
                return;
              }
              button.disabled = true;
              try {
                await api.archiveSession(projectId, session.id);
                clearError();
                announce(`${session.title} 세션을 보관했습니다.`);
                await reload();
              } catch (error) {
                button.disabled = false;
                showError(describeError(error));
              }
            },
          },
        }),
      );
    }
    row.append(actions);
    return row;
  }

  async function renderProject(projectId) {
    document.title = "프로젝트 — Nipo Science local";
    workspaceTitle.textContent = "프로젝트";
    setBarActions([]);
    state.projectId = projectId;
    render([loadingState("프로젝트를 읽는 중")]);

    const reload = () => renderProject(projectId);
    let project;
    let sessions;
    try {
      [project, sessions] = await Promise.all([
        request("GET", `/projects/${projectId}`),
        api.sessions(projectId),
      ]);
    } catch (error) {
      showError(describeError(error));
      render([
        breadcrumb([{ label: "워크스페이스", href: "#/workspace" }, { label: "프로젝트" }]),
        pageHeader("프로젝트", "프로젝트를 열 수 없습니다", describeError(error)),
      ]);
      return;
    }
    workspaceTitle.textContent = project.name;
    document.title = `${project.name} — Nipo Science local`;

    const rows = Array.isArray(sessions.sessions) ? sessions.sessions : [];
    const createForm = el("form", { class: "panel", novalidate: true });
    const titleInput = el("input", {
      id: "new-session-title",
      name: "title",
      type: "text",
      autocomplete: "off",
      placeholder: "3차 프로브 재분석",
    });
    createForm.append(
      el("div", { class: "form-row" }, [
        el("div", { class: "field" }, [
          el("label", { class: "field__label", for: "new-session-title", text: "새 세션 제목" }),
          titleInput,
        ]),
        el("button", { class: "button button--primary", type: "submit", text: "세션 시작" }),
      ]),
    );
    createForm.addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = titleInput.value;
      if (!value) {
        titleInput.setAttribute("aria-invalid", "true");
        showError("세션 제목을 입력해 주세요.");
        titleInput.focus();
        return;
      }
      titleInput.removeAttribute("aria-invalid");
      try {
        const created = await api.createSession(projectId, value);
        clearError();
        titleInput.value = "";
        announce(`${created.title} 세션을 시작했습니다.`);
        await reload();
      } catch (error) {
        showError(describeError(error));
        titleInput.setAttribute("aria-invalid", "true");
        titleInput.focus();
      }
    });

    render([
      breadcrumb([{ label: "워크스페이스", href: "#/workspace" }, { label: project.name }]),
      pageHeader("프로젝트", project.name, "이 프로젝트의 세션을 시작하고, 이어서 열고, 보관합니다."),
      el("div", { class: "panel" }, [
        keyValues([
          ["프로젝트 ID", project.id, true],
          ["만든 시각", formatMoment(project.created_at)],
          ["상태", project.archived ? "보관됨 (쓰기 불가)" : "활성"],
        ]),
      ]),
      el("div", { class: "actions actions--spaced-above" }, [
        el("a", {
          class: "button",
          href: `#/projects/${projectId}/artifacts`,
          text: "아티팩트 라이브러리",
        }),
        el("a", { class: "button", href: `#/projects/${projectId}/runs`, text: "실행 기록" }),
        el("a", {
          class: "button",
          href: `#/projects/${projectId}/exports`,
          text: "내보낸 팩",
          "data-action": "open-export-packs",
        }),
      ]),
      el("section", { class: "section", "aria-labelledby": "sessions-heading" }, [
        el("div", { class: "section__head" }, [
          el("h2", { id: "sessions-heading", text: "세션" }),
          el("p", { class: "section__hint", text: `${rows.length}개의 세션이 있습니다.` }),
        ]),
        rows.length === 0
          ? emptyState("아직 세션이 없습니다", "아래에서 첫 세션을 시작하세요.")
          : el("ul", { class: "object-list" }, rows.map((item) => sessionRow(projectId, item, reload))),
      ]),
      project.archived
        ? el("p", { class: "inline-note", text: "보관된 프로젝트에는 새 세션을 만들 수 없습니다." })
        : el("section", { class: "section", "aria-labelledby": "create-session-heading" }, [
            el("h2", { id: "create-session-heading", text: "세션 시작" }),
            createForm,
          ]),
    ]);
    announceScreen(`${project.name} 프로젝트를 표시했습니다.`);
  }

  // --------------------------------------------------- plan approval (L04) --

  const RESEARCH_MODES = [
    { value: "copilot", label: "copilot — 연구자 주도, 보조 제안" },
    { value: "bounded_agentic", label: "bounded_agentic — 범위가 묶인 위임" },
    { value: "ai_for_science", label: "ai_for_science — 과학 분석 실행" },
  ];

  const DATA_ORIGINS = [
    { value: "observed", label: "observed — 관측 데이터" },
    { value: "synthetic", label: "synthetic — 합성 데이터" },
    { value: "mixed", label: "mixed — 관측과 합성 혼합" },
  ];
  const PROBE_KINDS = [
    { value: "spectrum", label: "spectrum — 스펙트럼" },
    { value: "table", label: "table — 표" },
    { value: "image", label: "image — 이미지" },
    { value: "report", label: "report — 보고서" },
  ];

  function readFileAsBase64(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => {
        const result = reader.result;
        if (typeof result !== "string") {
          reject(new Error("file_read_failed"));
          return;
        }
        const comma = result.indexOf(",");
        resolve(comma >= 0 ? result.slice(comma + 1) : result);
      };
      reader.onerror = () => reject(reader.error || new Error("file_read_failed"));
      reader.readAsDataURL(file);
    });
  }

  function readFileAsText(file) {
    return new Promise((resolve, reject) => {
      const reader = new FileReader();
      reader.onload = () => resolve(String(reader.result ?? ""));
      reader.onerror = () => reject(reader.error || new Error("file_read_failed"));
      reader.readAsText(file);
    });
  }

  function emptyIntentDraft() {
    return {
      question: "",
      rationale: "",
      intended_benefit: "",
      success_criteria: [""],
      constraints: [""],
      stop_conditions: [""],
      research_mode: "",
      data_origin: "",
      synthetic_generator_ref: "",
      synthetic_validator_ref: "",
    };
  }

  function readListItems(items) {
    return items.map((item) => String(item ?? "").trim()).filter((item) => item.length > 0);
  }

  function intentPayloadFromDraft(draft) {
    const payload = {
      question: draft.question.trim(),
      rationale: draft.rationale.trim(),
      intended_benefit: draft.intended_benefit.trim(),
      success_criteria: readListItems(draft.success_criteria),
      constraints: readListItems(draft.constraints),
      stop_conditions: readListItems(draft.stop_conditions),
      research_mode: draft.research_mode,
      data_origin: draft.data_origin,
    };
    if (draft.data_origin === "synthetic" || draft.data_origin === "mixed") {
      payload.synthetic_generator_ref = draft.synthetic_generator_ref.trim() || null;
      payload.synthetic_validator_ref = draft.synthetic_validator_ref.trim() || null;
    }
    return payload;
  }

  function validateIntentDraft(draft) {
    if (!draft.question.trim()) return "연구 질문을 입력해 주세요.";
    if (!draft.rationale.trim()) return "연구 근거를 입력해 주세요.";
    if (!draft.intended_benefit.trim()) return "기대 이득을 입력해 주세요.";
    if (readListItems(draft.success_criteria).length === 0) {
      return "성공 기준을 하나 이상 입력해 주세요.";
    }
    if (readListItems(draft.constraints).length === 0) {
      return "제약을 하나 이상 입력해 주세요.";
    }
    if (readListItems(draft.stop_conditions).length === 0) {
      return "중단 조건을 하나 이상 입력해 주세요.";
    }
    if (!draft.research_mode) return "연구 모드를 선택해 주세요.";
    if (!draft.data_origin) return "데이터 출처를 선택해 주세요.";
    if (draft.data_origin === "synthetic" || draft.data_origin === "mixed") {
      const generator = draft.synthetic_generator_ref.trim();
      const validator = draft.synthetic_validator_ref.trim();
      if (!generator || !validator) {
        return "합성·혼합 출처에는 생성기와 검증기 참조를 모두 적어 주세요.";
      }
      if (generator === validator) {
        return "생성기 참조와 검증기 참조는 서로 달라야 합니다.";
      }
    }
    return "";
  }

  function digestCode(label, value, marker) {
    return el("div", { class: "digest-row", "data-digest": marker }, [
      el("p", { class: "meta", text: label }),
      el("code", { class: "hash", text: value || "아직 없음" }),
    ]);
  }

  function textField(id, label, help, value, onChange, multiline) {
    const control = el(multiline ? "textarea" : "input", {
      id,
      name: id,
      ...(multiline
        ? { rows: "4" }
        : { type: "text", autocomplete: "off" }),
      value: multiline ? undefined : value,
      on: {
        input: (event) => onChange(event.currentTarget.value),
        change: (event) => onChange(event.currentTarget.value),
      },
    });
    if (multiline) control.value = value;
    return el("div", { class: "field" }, [
      el("label", { class: "field__label", for: id, text: label }),
      control,
      help ? el("p", { class: "field__help", text: help }) : null,
    ]);
  }

  function selectField(id, label, help, value, options, onChange) {
    const control = el(
      "select",
      {
        id,
        name: id,
        on: {
          change: (event) => onChange(event.currentTarget.value),
          input: (event) => onChange(event.currentTarget.value),
        },
      },
      [
        el("option", { value: "", text: "선택해 주세요" }),
        ...options.map((option) =>
          el("option", {
            value: option.value,
            text: option.label,
            selected: option.value === value ? true : null,
          }),
        ),
      ],
    );
    // Selected state must be applied after options exist; the attribute alone
    // is not reliable across re-renders when the empty option is first.
    control.value = value;
    return el("div", { class: "field" }, [
      el("label", { class: "field__label", for: id, text: label }),
      control,
      help ? el("p", { class: "field__help", text: help }) : null,
    ]);
  }

  function listField(id, label, help, items, onChange) {
    const rows = items.map((item, index) => {
      const inputId = `${id}-${index}`;
      return el("div", { class: "list-field__row" }, [
        el("input", {
          id: inputId,
          name: inputId,
          type: "text",
          autocomplete: "off",
          value: item,
          "aria-label": `${label} ${index + 1}`,
          on: {
            input: (event) => {
              const next = items.slice();
              next[index] = event.currentTarget.value;
              onChange(next);
            },
            change: (event) => {
              const next = items.slice();
              next[index] = event.currentTarget.value;
              onChange(next);
            },
          },
        }),
        el("button", {
          class: "button button--small",
          type: "button",
          text: "삭제",
          "aria-label": `${label} ${index + 1} 삭제`,
          disabled: items.length <= 1,
          on: {
            click: () => {
              if (items.length <= 1) return;
              const next = items.slice();
              next.splice(index, 1);
              onChange(next.length === 0 ? [""] : next, { repaint: true });
            },
          },
        }),
      ]);
    });
    return el("div", { class: "field list-field", "data-list-field": id }, [
      el("p", { class: "field__label", id: `${id}-label`, text: label }),
      el("div", { class: "list-field__rows", role: "group", "aria-labelledby": `${id}-label` }, rows),
      el("div", { class: "actions" }, [
        el("button", {
          class: "button button--small",
          type: "button",
          text: "항목 추가",
          "aria-label": `${label} 항목 추가`,
          on: {
            click: () => onChange(items.concat([""]), { repaint: true }),
          },
        }),
      ]),
      help ? el("p", { class: "field__help", text: help }) : null,
    ]);
  }

  async function renderPlanApproval(projectId, sessionId) {
    document.title = "플랜 승인 — Nipo Science local";
    workspaceTitle.textContent = "플랜 승인";
    setBarActions([]);
    state.projectId = projectId;
    render([loadingState("세션을 확인하는 중")]);

    const head = [
      breadcrumb([
        { label: "워크스페이스", href: "#/workspace" },
        { label: "프로젝트", href: `#/projects/${projectId}` },
        { label: "플랜 승인" },
      ]),
    ];

    let project;
    let sessions;
    try {
      [project, sessions] = await Promise.all([
        request("GET", `/projects/${projectId}`),
        api.sessions(projectId),
      ]);
    } catch (error) {
      showError(describeError(error));
      render([
        ...head,
        pageHeader("플랜 승인", "플랜 화면을 열 수 없습니다", describeError(error)),
      ]);
      return;
    }

    const sessionRows = Array.isArray(sessions.sessions) ? sessions.sessions : [];
    const session = sessionRows.find((item) => String(item.id) === String(sessionId)) || null;
    const sessionTitle = session ? session.title : sessionId;
    document.title = `플랜 승인 — ${project.name} — Nipo Science local`;
    workspaceTitle.textContent = "플랜 승인";

    const draft = emptyIntentDraft();
    let plan = null;
    let approval = null;
    let needsNewPlan = false;
    let busy = false;
    // ProbeInput is held only in this screen closure — never browser storage.
    let scientificInput = null;
    let inputReceipt = null;
    let probeKind = "";
    let dataFile = null;
    let manifestFile = null;

    function touchIntent(mutator, options) {
      mutator();
      let cleared = false;
      if (plan !== null || approval !== null) {
        plan = null;
        approval = null;
        needsNewPlan = true;
        cleared = true;
      }
      // Re-render only when structure or binding state changes. Typing into a
      // text field must not rebuild the form or the caret jumps on every key.
      if (cleared || (options && options.repaint)) paint();
    }

    async function onCreatePlan(event) {
      event.preventDefault();
      if (busy) return;
      const problem = validateIntentDraft(draft);
      if (problem) {
        showError(problem);
        return;
      }
      busy = true;
      paint();
      try {
        plan = await api.createActionPlan(projectId, sessionId, intentPayloadFromDraft(draft));
        approval = null;
        needsNewPlan = false;
        clearError();
        announce("플랜을 만들었습니다. 서버가 계산한 다이제스트를 확인해 주세요.");
      } catch (error) {
        showError(describeError(error));
      } finally {
        busy = false;
        paint();
      }
    }

    async function onApprovePlan(event) {
      event.preventDefault();
      if (busy || !plan || !plan.plan_id) return;
      busy = true;
      paint();
      try {
        approval = await api.approveActionPlan(projectId, plan.plan_id);
        clearError();
        announce("플랜을 승인했습니다. 이 승인은 한 번만 쓸 수 있습니다.");
      } catch (error) {
        showError(describeError(error));
      } finally {
        busy = false;
        paint();
      }
    }
    async function onLoadMeasurement(event) {
      event.preventDefault();
      if (busy) return;
      if (!probeKind) {
        showError("측정 종류를 선택해 주세요.");
        return;
      }
      if (!dataFile) {
        showError("측정 데이터 파일을 골라 주세요.");
        return;
      }
      if (!manifestFile) {
        showError("매니페스트(.manifest.toml) 파일을 골라 주세요.");
        return;
      }
      busy = true;
      paint();
      try {
        const [dataBase64, manifestToml] = await Promise.all([
          readFileAsBase64(dataFile),
          readFileAsText(manifestFile),
        ]);
        const result = await api.probeInput(projectId, {
          kind: probeKind,
          data_filename: dataFile.name,
          data_base64: dataBase64,
          manifest_toml: manifestToml,
        });
        scientificInput = result.scientific_input;
        inputReceipt = {
          kind: String(result.kind ?? probeKind),
          input_sha256: String(result.input_sha256 ?? ""),
          data_filename: dataFile.name,
        };
        clearError();
        announce("측정 파일을 불러왔습니다. 다이제스트를 확인한 뒤 실행을 시작하세요.");
      } catch (error) {
        scientificInput = null;
        inputReceipt = null;
        if (error instanceof LocalApiError) {
          showError(describeError(error));
        } else {
          showError("측정 파일을 읽지 못했습니다. 파일 선택을 다시 확인해 주세요.");
        }
      } finally {
        busy = false;
        paint();
      }
    }

    async function onStartRun(event) {
      event.preventDefault();
      if (busy || !approval || approval.consumed_at || !scientificInput) return;
      busy = true;
      paint();
      try {
        const runBody = {
          session_id: sessionId,
          approval_id: approval.approval_id,
          research_intent: intentPayloadFromDraft(draft),
          scientific_input: scientificInput,
        };
        const pinnedDigest =
          inputReceipt && typeof inputReceipt.input_sha256 === "string"
            ? inputReceipt.input_sha256.trim()
            : "";
        if (pinnedDigest) {
          runBody.input_sha256 = pinnedDigest;
        }
        const created = await api.createRun(projectId, runBody);
        clearError();
        announce("실행을 시작했습니다.");
        window.location.hash = `#/projects/${projectId}/runs/${created.run_id}`;
      } catch (error) {
        showError(describeError(error));
        busy = false;
        paint();
      }
    }

    function paint() {
      const syntheticNeeded =
        draft.data_origin === "synthetic" || draft.data_origin === "mixed";
      const nodes = [
        ...head,
        pageHeader(
          "플랜 승인",
          sessionTitle,
          "연구 의도를 작성하고 불변 ActionPlan을 만든 뒤, 한 번만 쓸 수 있는 승인을 남깁니다.",
        ),
        el("div", { class: "panel" }, [
          keyValues([
            ["프로젝트", project.name],
            ["프로젝트 ID", project.id, true],
            ["세션 ID", sessionId, true],
            ["세션 상태", session ? (session.archived ? "보관됨" : "활성") : "목록에서 찾지 못함"],
          ]),
        ]),
      ];

      if (project.archived || (session && session.archived)) {
        nodes.push(
          emptyState(
            "이 세션에서는 플랜을 만들 수 없습니다",
            project.archived
              ? "보관된 프로젝트에는 새 플랜을 만들 수 없습니다."
              : "보관된 세션에는 새 플랜을 만들 수 없습니다.",
            el("a", {
              class: "button button--primary",
              href: `#/projects/${projectId}`,
              text: "프로젝트로 돌아가기",
            }),
          ),
        );
        render(nodes);
        announceScreen("보관된 대상이라 플랜을 만들 수 없습니다.");
        return;
      }

      if (needsNewPlan) {
        nodes.push(
          el("p", {
            class: "inline-note",
            "data-plan-notice": "intent-edited",
            text: "수정된 의도는 새 승인이 필요합니다. 아래 내용으로 플랜을 다시 만들어 주세요.",
          }),
        );
      }

      nodes.push(
        el("section", { class: "section", "aria-labelledby": "intent-heading", "data-plan-form": "research-intent" }, [
          el("div", { class: "section__head" }, [
            el("h2", { id: "intent-heading", text: "ResearchIntent" }),
            el("p", {
              class: "section__hint",
              text: "과학적 기본값은 두지 않습니다. 모드와 출처는 직접 고르셔야 합니다.",
            }),
          ]),
          el("form", { class: "panel plan-form", novalidate: true, on: { submit: onCreatePlan } }, [
            textField(
              "intent-question",
              "연구 질문",
              "이번 실행이 답하려는 질문을 적어 주세요.",
              draft.question,
              (value) => touchIntent(() => {
                draft.question = value;
              }),
              true,
            ),
            textField(
              "intent-rationale",
              "연구 근거",
              "왜 이 질문이 지금 필요한지 적어 주세요.",
              draft.rationale,
              (value) => touchIntent(() => {
                draft.rationale = value;
              }),
              true,
            ),
            textField(
              "intent-benefit",
              "기대 이득",
              "이 실행이 남기기를 기대하는 이득을 적어 주세요.",
              draft.intended_benefit,
              (value) => touchIntent(() => {
                draft.intended_benefit = value;
              }),
              true,
            ),
            listField(
              "intent-success",
              "성공 기준",
              "하나 이상 필요합니다. 빈 줄은 제출 때 제외됩니다.",
              draft.success_criteria,
              (value, options) => touchIntent(() => {
                draft.success_criteria = value;
              }, options),
            ),
            listField(
              "intent-constraints",
              "제약",
              "하나 이상 필요합니다.",
              draft.constraints,
              (value, options) => touchIntent(() => {
                draft.constraints = value;
              }, options),
            ),
            listField(
              "intent-stop",
              "중단 조건",
              "하나 이상 필요합니다.",
              draft.stop_conditions,
              (value, options) => touchIntent(() => {
                draft.stop_conditions = value;
              }, options),
            ),
            selectField(
              "intent-mode",
              "연구 모드",
              "과학적 기본 선택은 없습니다. 비어 있는 첫 항목에서 직접 고르세요.",
              draft.research_mode,
              RESEARCH_MODES,
              (value) => touchIntent(() => {
                draft.research_mode = value;
              }, { repaint: true }),
            ),
            selectField(
              "intent-origin",
              "데이터 출처",
              "observed / synthetic / mixed 중 하나를 직접 고르세요.",
              draft.data_origin,
              DATA_ORIGINS,
              (value) =>
                touchIntent(() => {
                  draft.data_origin = value;
                  if (value === "observed" || value === "") {
                    draft.synthetic_generator_ref = "";
                    draft.synthetic_validator_ref = "";
                  }
                }, { repaint: true }),
            ),
            syntheticNeeded
              ? textField(
                  "intent-generator",
                  "합성 생성기 참조",
                  "synthetic 또는 mixed 출처에 필요합니다. 검증기 참조와 달라야 합니다.",
                  draft.synthetic_generator_ref,
                  (value) => touchIntent(() => {
                    draft.synthetic_generator_ref = value;
                  }),
                  false,
                )
              : null,
            syntheticNeeded
              ? textField(
                  "intent-validator",
                  "합성 검증기 참조",
                  "생성기와 독립된 검증 경로를 적어 주세요.",
                  draft.synthetic_validator_ref,
                  (value) => touchIntent(() => {
                    draft.synthetic_validator_ref = value;
                  }),
                  false,
                )
              : null,
            el("div", { class: "actions actions--spaced-above" }, [
              el("button", {
                class: "button button--primary",
                type: "submit",
                text: busy && !approval ? "플랜 생성 중…" : "플랜 생성",
                "data-action": "create-plan",
                disabled: busy,
              }),
            ]),
          ]),
        ]),
      );

      if (plan) {
        nodes.push(
          el("section", {
            class: "section",
            "aria-labelledby": "plan-digest-heading",
            "data-plan-panel": "created",
          }, [
            el("div", { class: "section__head" }, [
              el("h2", { id: "plan-digest-heading", text: "서버가 고정한 플랜" }),
              el("p", {
                class: "section__hint",
                text: "다이제스트는 서버가 계산한 값입니다. 이 화면이 고른 값이 아닙니다.",
              }),
            ]),
            el("div", { class: "panel panel--raised" }, [
              keyValues([
                ["플랜 ID", String(plan.plan_id ?? ""), true],
                ["만든 시각", formatMoment(plan.created_at)],
              ]),
              digestCode("ActionPlan SHA-256", String(plan.plan_sha256 ?? ""), "plan_sha256"),
              digestCode(
                "ResearchIntent SHA-256",
                String(plan.research_intent_sha256 ?? ""),
                "research_intent_sha256",
              ),
              approval
                ? null
                : el("div", { class: "actions actions--spaced-above" }, [
                    el("button", {
                      class: "button button--primary",
                      type: "button",
                      text: busy ? "승인 중…" : "플랜 승인",
                      "data-action": "approve-plan",
                      disabled: busy,
                      on: { click: onApprovePlan },
                    }),
                  ]),
            ]),
          ]),
        );
      }

      if (approval) {
        const consumed = approval.consumed_at
          ? `사용됨 · ${formatMoment(approval.consumed_at)}`
          : "미사용";
        nodes.push(
          el("section", {
            class: "section",
            "aria-labelledby": "approval-receipt-heading",
            "data-plan-panel": "approved",
          }, [
            el("div", { class: "section__head" }, [
              el("h2", { id: "approval-receipt-heading", text: "승인 영수증" }),
              el("p", {
                class: "section__hint",
                text: "이 승인은 한 번만 쓸 수 있습니다. 만료되거나 사용되면 새 승인이 필요합니다.",
              }),
            ]),
            el("div", { class: "panel panel--signal", "data-approval-state": approval.consumed_at ? "consumed" : "unused" }, [
              el("div", { class: "actions actions--spaced-below" }, [
                approval.consumed_at
                  ? badge("attention", "사용됨", ICONS.alert)
                  : badge("positive", "미사용", ICONS.check),
              ]),
              keyValues([
                ["승인 ID", String(approval.approval_id ?? ""), true],
                ["승인 시각", formatMoment(approval.granted_at)],
                ["만료 시각", formatMoment(approval.expires_at)],
                ["사용 상태", consumed],
              ]),
              digestCode("ActionPlan SHA-256", String(approval.plan_sha256 ?? ""), "approval_plan_sha256"),
              digestCode(
                "ResearchIntent SHA-256",
                String(approval.research_intent_sha256 ?? ""),
                "approval_research_intent_sha256",
              ),
            ]),
          ]),
        );
      }

      // L03: measurement load holds ProbeInput in screen state and unlocks Run
      // only when an unspent approval is present. Never persists research bytes.
      const approvalUnspent = Boolean(approval && !approval.consumed_at);
      const canStartRun = approvalUnspent && scientificInput !== null;
      nodes.push(
        el("section", {
          class: "section",
          "aria-labelledby": "plan-run-heading",
          "data-plan-run": "measurement",
        }, [
          el("div", { class: "section__head" }, [
            el("h2", { id: "plan-run-heading", text: "측정 입력 · 실행" }),
            el("p", {
              class: "section__hint",
              text:
                "측정 파일과 매니페스트를 불러 서버가 만든 입력을 받은 뒤, " +
                "미사용 승인이 있을 때만 실행을 시작합니다. 파일 내용은 화면에 표시하지 않습니다.",
            }),
          ]),
          el("div", { class: "panel panel--raised", "data-measurement-load": "form" }, [
            selectField(
              "probe-kind",
              "측정 종류",
              "종류는 추론하지 않습니다. spectrum / table / image / report 중 하나를 직접 고르세요.",
              probeKind,
              PROBE_KINDS,
              (value) => {
                probeKind = value;
              },
            ),
            el("div", { class: "field", "data-field": "measurement-data" }, [
              el("label", {
                class: "field__label",
                for: "measurement-data-file",
                text: "측정 데이터 파일",
              }),
              el("input", {
                id: "measurement-data-file",
                name: "measurement-data-file",
                type: "file",
                "aria-describedby": "measurement-data-help",
                on: {
                  change: (event) => {
                    const files = event.currentTarget.files;
                    dataFile = files && files[0] ? files[0] : null;
                    paint();
                  },
                },
              }),
              el("p", {
                id: "measurement-data-help",
                class: "field__help",
                text: dataFile
                  ? `선택됨: ${dataFile.name}`
                  : "분석에 쓸 측정 데이터 파일을 고르세요.",
              }),
            ]),
            el("div", { class: "field", "data-field": "measurement-manifest" }, [
              el("label", {
                class: "field__label",
                for: "measurement-manifest-file",
                text: "매니페스트 (.manifest.toml)",
              }),
              el("input", {
                id: "measurement-manifest-file",
                name: "measurement-manifest-file",
                type: "file",
                accept: ".toml,text/plain,.manifest.toml",
                "aria-describedby": "measurement-manifest-help",
                on: {
                  change: (event) => {
                    const files = event.currentTarget.files;
                    manifestFile = files && files[0] ? files[0] : null;
                    paint();
                  },
                },
              }),
              el("p", {
                id: "measurement-manifest-help",
                class: "field__help",
                text: manifestFile
                  ? `선택됨: ${manifestFile.name}`
                  : "데이터 파일과 짝이 되는 .manifest.toml 내용을 고르세요.",
              }),
            ]),
            el("div", { class: "actions actions--spaced-above" }, [
              el("button", {
                class: "button",
                type: "button",
                text: busy ? "불러오는 중…" : "측정 파일 불러오기",
                "data-action": "load-measurement",
                disabled: busy,
                on: { click: onLoadMeasurement },
              }),
            ]),
            inputReceipt
              ? el("div", {
                  class: "measurement-receipt",
                  "data-measurement-load": "held",
                }, [
                  el("p", {
                    class: "meta",
                    text: "불러온 입력 요약 — 파일 내용은 보관·표시하지 않습니다.",
                  }),
                  keyValues([
                    ["종류", inputReceipt.kind],
                    ["파일명", inputReceipt.data_filename],
                  ]),
                  digestCode(
                    "입력 SHA-256",
                    inputReceipt.input_sha256,
                    "input_sha256",
                  ),
                ])
              : el("p", {
                  class: "meta measurement-receipt__empty",
                  "data-measurement-load": "empty",
                  text: "아직 불러온 측정 입력이 없습니다.",
                }),
            approvalUnspent
              ? null
              : el("p", {
                  class: "inline-note",
                  "data-plan-run-gate": "approval-required",
                  text: approval
                    ? "이 승인은 이미 사용되었습니다. 실행하려면 플랜을 다시 승인해야 합니다."
                    : "실행을 시작하려면 먼저 플랜을 승인해야 합니다.",
                }),
            el("div", { class: "actions actions--spaced-above" }, [
              el("button", {
                class: "button button--primary",
                type: "button",
                text: busy && canStartRun ? "실행 시작 중…" : "실행 시작",
                "data-action": "start-run",
                disabled: busy || !canStartRun,
                on: { click: onStartRun },
              }),
              el("a", {
                class: "button",
                href: `#/projects/${projectId}/runs`,
                text: "실행 기록 보기",
              }),
            ]),
          ]),
        ]),
      );

      render(nodes);
      announceScreen(
        approval
          ? "승인 영수증을 표시했습니다."
          : plan
            ? "서버가 고정한 플랜 다이제스트를 표시했습니다."
            : "연구 의도 작성 화면을 표시했습니다.",
      );
    }

    paint();
  }

  // ------------------------------------------------------------ project gate --

  async function renderProjectGate(title, suffix) {
    document.title = `${title} — Nipo Science local`;
    workspaceTitle.textContent = title;
    setBarActions([]);
    render([loadingState("프로젝트를 읽는 중")]);
    let payload;
    try {
      payload = await api.projects();
    } catch (error) {
      showError(describeError(error));
      render([pageHeader(title, title, describeError(error))]);
      return;
    }
    const projects = Array.isArray(payload.projects) ? payload.projects : [];
    render([
      pageHeader(title, title, `${title}을(를) 보려면 프로젝트를 먼저 고르세요.`),
      projects.length === 0
        ? emptyState(
            "등록된 프로젝트가 없습니다",
            "워크스페이스에서 프로젝트를 먼저 만들어 주세요.",
            el("a", { class: "button button--primary", href: "#/workspace", text: "워크스페이스로 가기" }),
          )
        : el(
            "ul",
            { class: "object-list" },
            projects.map((project) =>
              el("li", { class: "object-row" }, [
                el("div", { class: "object-row__body" }, [
                  el("p", { class: "object-row__title" }, [
                    el("a", { href: `#/projects/${project.id}${suffix}`, text: project.name }),
                  ]),
                  el("p", { class: "mono", text: project.id }),
                ]),
              ]),
            ),
          ),
    ]);
  }

  // ------------------------------------------------------------- artifacts --

  async function renderArtifacts(projectId) {
    document.title = "아티팩트 — Nipo Science local";
    workspaceTitle.textContent = "아티팩트";
    setBarActions([]);
    state.projectId = projectId;
    render([loadingState("아티팩트를 읽는 중")]);
    let payload;
    try {
      payload = await api.artifacts(projectId);
    } catch (error) {
      showError(describeError(error));
      render([
        breadcrumb([{ label: "워크스페이스", href: "#/workspace" }, { label: "아티팩트" }]),
        pageHeader("아티팩트", "아티팩트를 읽을 수 없습니다", describeError(error)),
      ]);
      return;
    }
    const artifacts = Array.isArray(payload.artifacts) ? payload.artifacts : [];
    render([
      breadcrumb([
        { label: "워크스페이스", href: "#/workspace" },
        { label: "프로젝트", href: `#/projects/${projectId}` },
        { label: "아티팩트" },
      ]),
      pageHeader(
        "아티팩트",
        "아티팩트 라이브러리",
        "실행이 만든 불변 결과물입니다. 각 버전은 내용 해시로 고정되며 지워지거나 덮어써지지 않습니다.",
      ),
      artifacts.length === 0
        ? emptyState(
            "이 프로젝트에는 아티팩트가 없습니다",
            "실행이 결과물을 커밋하면 여기에 버전과 체크섬이 쌓입니다.",
          )
        : el(
            "ul",
            { class: "object-list" },
            artifacts.map((item) =>
              el("li", { class: "object-row", dataset: { artifact: item.id } }, [
                el("div", { class: "object-row__body" }, [
                  el("p", { class: "object-row__title" }, [
                    el("a", {
                      href: `#/projects/${projectId}/artifacts/${item.id}`,
                      text: item.name,
                    }),
                  ]),
                  el("p", {
                    class: "meta",
                    text: `버전 ${item.version_count}개 · 최신 v${item.head_version_no} · 만든 시각 ${formatMoment(item.created_at)}`,
                  }),
                  el("p", { class: "mono", text: item.id }),
                ]),
                el("div", { class: "actions" }, [
                  el("a", {
                    class: "button button--small",
                    href: `#/projects/${projectId}/artifacts/${item.id}`,
                    text: "버전 보기",
                  }),
                ]),
              ]),
            ),
          ),
    ]);
    announceScreen("아티팩트 라이브러리를 표시했습니다.");
  }

  async function download(projectId, artifactId, version, name) {
    const response = await fetch(api.contentUrl(projectId, artifactId, version.id), {
      mode: "same-origin",
      credentials: "omit",
      cache: "no-store",
      headers: { [TOKEN_HEADER]: sessionToken },
    });
    if (!response.ok) {
      let code = "";
      try {
        const payload = await response.json();
        code = typeof payload.error === "string" ? payload.error : "";
      } catch {
        code = "";
      }
      throw new LocalApiError(response.status, code, "");
    }
    const blob = await response.blob();
    const href = URL.createObjectURL(blob);
    const anchor = el("a", { href, download: `${name}-v${version.version_no}` });
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    URL.revokeObjectURL(href);
  }

  function provenancePanel(record) {
    return el("div", { class: "panel panel--raised", "data-provenance": record.version_id }, [
      el("h3", { class: "panel__title", text: "고정된 출처" }),
      el("p", {
        class: "meta",
        text: "아래 값은 모두 내보낸 바이트로부터 제3자가 다시 계산할 수 있는 다이제스트입니다.",
      }),
      keyValues([
        ["버전 ID", record.version_id, true],
        ["버전 번호", `v${record.version_no}`],
        ["내용 SHA-256", record.content_sha256, true],
        ["크기", formatBytes(record.size_bytes)],
        ["미디어 타입", record.media_type],
        ["생성 실행 ID", record.producing_execution_id, true],
        ["환경 SHA-256", record.environment_sha256, true],
        ["코드 SHA-256", record.code_sha256, true],
        ["런타임 어댑터", record.runtime_adapter_id],
        ["런타임 연결 ID", record.runtime_connection_id, true],
        [
          "스킬 내용 해시",
          Array.isArray(record.skill_content_hashes) && record.skill_content_hashes.length > 0
            ? record.skill_content_hashes.join("\n")
            : "기록된 값 없음",
          true,
        ],
        [
          "원본 해시",
          Array.isArray(record.source_hashes) && record.source_hashes.length > 0
            ? record.source_hashes.join("\n")
            : "기록된 값 없음",
          true,
        ],
        [
          "입력 버전",
          Array.isArray(record.input_version_ids) && record.input_version_ids.length > 0
            ? record.input_version_ids.join("\n")
            : "입력 버전 없음",
          true,
        ],
        ["기록 시각", formatMoment(record.created_at)],
      ]),
      isolationDisclosure(record.execution_isolation ?? null),
    ]);
  }

  async function renderArtifact(projectId, artifactId, versionId) {
    document.title = "아티팩트 버전 — Nipo Science local";
    workspaceTitle.textContent = "아티팩트";
    setBarActions([]);
    state.projectId = projectId;
    render([loadingState("버전 기록을 읽는 중")]);

    let detail;
    try {
      detail = await api.artifact(projectId, artifactId);
    } catch (error) {
      showError(describeError(error));
      render([
        breadcrumb([{ label: "아티팩트", href: `#/projects/${projectId}/artifacts` }, { label: "버전" }]),
        pageHeader("아티팩트", "아티팩트를 열 수 없습니다", describeError(error)),
      ]);
      return;
    }
    const versions = Array.isArray(detail.versions) ? detail.versions : [];
    workspaceTitle.textContent = detail.name;

    const table = el("table", {}, [
      el("caption", { text: `${detail.name}의 버전 ${versions.length}개. 모든 버전은 불변입니다.` }),
      el("thead", {}, [
        el("tr", {}, [
          el("th", { scope: "col", text: "버전" }),
          el("th", { scope: "col", text: "미디어 타입" }),
          el("th", { scope: "col", text: "크기" }),
          el("th", { scope: "col", text: "내용 SHA-256" }),
          el("th", { scope: "col", text: "커밋 시각" }),
          el("th", { scope: "col", text: "동작" }),
        ]),
      ]),
    ]);
    const body = el("tbody");
    for (const version of versions) {
      body.append(
        el("tr", { dataset: { version: version.id } }, [
          el("th", { scope: "row", dataset: { label: "버전" } }, [
            el("span", { text: `v${version.version_no}` }),
            " ",
            badge("neutral", "불변", ICONS.check),
          ]),
          el("td", { dataset: { label: "미디어 타입" }, text: version.media_type }),
          el("td", { dataset: { label: "크기" }, text: formatBytes(version.size_bytes) }),
          el("td", { dataset: { label: "내용 SHA-256" } }, [
            el("span", { class: "hash", text: version.content_sha256 }),
          ]),
          el("td", { dataset: { label: "커밋 시각" }, text: formatMoment(version.created_at) }),
          el("td", { dataset: { label: "동작" } }, [
            el("div", { class: "actions" }, [
              el("a", {
                class: "button button--small",
                href: `#/projects/${projectId}/artifacts/${artifactId}/versions/${version.id}`,
                text: "출처 보기",
                "aria-label": `버전 ${version.version_no}의 출처 보기`,
              }),
              el("button", {
                class: "button button--quiet button--small",
                type: "button",
                text: "내려받기",
                "aria-label": `버전 ${version.version_no} 내려받기`,
                on: {
                  click: async (event) => {
                    const button = event.currentTarget;
                    button.disabled = true;
                    try {
                      await download(projectId, artifactId, version, detail.name);
                      clearError();
                      announce(`버전 ${version.version_no}을(를) 내려받았습니다.`);
                    } catch (error) {
                      showError(describeError(error));
                    } finally {
                      button.disabled = false;
                    }
                  },
                },
              }),
            ]),
          ]),
        ]),
      );
    }
    table.append(body);

    const nodes = [
      breadcrumb([
        { label: "워크스페이스", href: "#/workspace" },
        { label: "아티팩트", href: `#/projects/${projectId}/artifacts` },
        { label: detail.name },
      ]),
      pageHeader(
        "아티팩트",
        detail.name,
        "버전은 커밋 순서대로 쌓이며 각 버전의 출처는 그 버전에 고정됩니다.",
      ),
      versions.length === 0
        ? emptyState("이 아티팩트에는 버전이 없습니다", "실행이 결과물을 커밋하면 여기에 나타납니다.")
        : el("div", { class: "table-scroll" }, [table]),
    ];

    if (versionId) {
      try {
        const record = await api.provenance(projectId, artifactId, versionId);
        nodes.push(
          el("section", { class: "section", "aria-labelledby": "provenance-heading" }, [
            el("h2", { id: "provenance-heading", text: `버전 v${record.version_no} 출처` }),
            provenancePanel(record),
          ]),
        );
      } catch (error) {
        showError(describeError(error));
        nodes.push(
          el("section", { class: "section" }, [
            el("h2", { text: "출처" }),
            el("p", { class: "inline-error", text: describeError(error) }),
          ]),
        );
      }
    }
    render(nodes);
    announceScreen(`${detail.name} 아티팩트를 표시했습니다.`);
  }

  // ------------------------------------------------------------------ runs --

  const RUN_STATE = {
    queued: { kind: "neutral", label: "대기 중", glyph: ICONS.clock },
    running: { kind: "info", label: "실행 중", glyph: ICONS.clock },
    completed: { kind: "positive", label: "완료", glyph: ICONS.check },
    failed: { kind: "danger", label: "실패", glyph: ICONS.cross },
  };

  const OUTPUT_ROLE = {
    csv: "정규화 데이터 (CSV)",
    png: "그림 (PNG)",
    markdown: "해석 노트 (Markdown)",
    ledger: "증거 원장 (JSON)",
  };

  function runStateBadge(value) {
    const entry = RUN_STATE[value];
    if (entry) return badge(entry.kind, entry.label, entry.glyph);
    return badge("neutral", `알 수 없는 상태 (${String(value)})`, ICONS.alert);
  }

  function runSurfaceUnavailable() {
    return el("div", { class: "panel panel--attention", "data-state": "run-surface-unavailable" }, [
      el("p", { class: "disclosure__title" }, [icon(ICONS.alert), "실행 기록 표면이 연결되지 않았습니다"]),
      el("p", {
        text:
          "이 설치본의 로컬 API는 실행 목록을 아직 제공하지 않습니다. 서버가 501과 " +
          "run_surface_unavailable을 답했습니다. 실행이 없다는 뜻이 아니라, 이 화면이 실행을 " +
          "읽을 수 없다는 뜻입니다.",
      }),
    ]);
  }

  async function renderRuns(projectId) {
    document.title = "실행 — Nipo Science local";
    workspaceTitle.textContent = "실행";
    setBarActions([]);
    state.projectId = projectId;
    render([loadingState("실행 기록을 읽는 중")]);

    const head = [
      breadcrumb([
        { label: "워크스페이스", href: "#/workspace" },
        { label: "프로젝트", href: `#/projects/${projectId}` },
        { label: "실행" },
      ]),
      pageHeader("실행", "실행 기록", "승인된 계획이 만든 실행과 그 실행이 커밋한 결과물입니다."),
    ];

    let payload;
    try {
      payload = await api.runs(projectId);
    } catch (error) {
      if (error instanceof LocalApiError && error.code === "run_surface_unavailable") {
        clearError();
        render([...head, runSurfaceUnavailable()]);
        announceScreen("실행 기록 표면이 아직 연결되지 않았습니다.");
        return;
      }
      showError(describeError(error));
      render([...head, emptyState("실행을 읽지 못했습니다", describeError(error))]);
      return;
    }
    const runs = Array.isArray(payload.runs) ? payload.runs : [];
    render([
      ...head,
      runs.length === 0
        ? emptyState("이 프로젝트에는 실행이 없습니다", "승인된 계획이 실행되면 여기에 기록이 남습니다.")
        : el(
            "ul",
            { class: "object-list" },
            runs.map((run) => {
              const id = String(run.run_id ?? run.id ?? "");
              return el("li", { class: "object-row", dataset: { run: id } }, [
                el("div", { class: "object-row__body" }, [
                  el("p", { class: "object-row__title" }, [
                    el("a", { href: `#/projects/${projectId}/runs/${id}`, text: `실행 ${id}` }),
                    runStateBadge(run.state),
                  ]),
                  el("p", {
                    class: "meta",
                    text: `커밋된 결과물 ${Array.isArray(run.committed_outputs) ? run.committed_outputs.length : 0}개`,
                  }),
                ]),
                el("div", { class: "actions" }, [
                  el("a", {
                    class: "button button--small",
                    href: `#/projects/${projectId}/runs/${id}`,
                    text: "실행 열기",
                  }),
                ]),
              ]);
            }),
          ),
    ]);
    announceScreen("실행 목록을 표시했습니다.");
  }

  function runOutputs(projectId, outputs) {
    const ordered = [...outputs].sort(
      (left, right) => Number(left.sequence ?? 0) - Number(right.sequence ?? 0),
    );
    const list = el("ul", { class: "run-outputs" });
    for (const output of ordered) {
      const role = String(output.role ?? "");
      const label = OUTPUT_ROLE[role] || (role ? `기타 결과물 (${role})` : "역할이 기록되지 않은 결과물");
      const item = el("li", { class: "run-output", dataset: { role } }, [
        el("div", { class: "run-output__head" }, [
          el("span", { class: "run-output__seq", text: String(output.sequence ?? "?") }),
          el("h3", { text: label }),
        ]),
        el("p", { class: "meta", text: "내용 SHA-256" }),
        el("span", { class: "hash", text: String(output.content_sha256 ?? "기록 없음") }),
      ]);
      if (output.artifact_id && output.version_id) {
        item.append(
          el("div", { class: "actions" }, [
            el("a", {
              class: "button button--small",
              href: `#/projects/${projectId}/artifacts/${output.artifact_id}/versions/${output.version_id}`,
              text: "출처 보기",
              "aria-label": `${label}의 출처 보기`,
            }),
          ]),
        );
      }
      list.append(item);
    }
    return list;
  }

  async function renderRun(projectId, runId) {
    document.title = "실행 — Nipo Science local";
    workspaceTitle.textContent = "실행";
    setBarActions([]);
    state.projectId = projectId;
    render([loadingState("실행을 읽는 중")]);

    const head = [
      breadcrumb([
        { label: "워크스페이스", href: "#/workspace" },
        { label: "실행", href: `#/projects/${projectId}/runs` },
        { label: runId },
      ]),
    ];

    let run;
    try {
      run = await api.run(projectId, runId);
    } catch (error) {
      if (error instanceof LocalApiError && error.code === "run_surface_unavailable") {
        clearError();
        render([...head, pageHeader("실행", "실행 기록", ""), runSurfaceUnavailable()]);
        return;
      }
      showError(describeError(error));
      render([...head, pageHeader("실행", "실행을 열 수 없습니다", describeError(error))]);
      return;
    }

    // The composer picker feeds the turn panel. Its failure must not take the
    // run record down with it; the panel says the list is unavailable instead.
    let picker = null;
    try {
      picker = await api.composer();
    } catch {
      picker = null;
    }

    const outputs = Array.isArray(run.committed_outputs) ? run.committed_outputs : [];
    const nodes = [
      ...head,
      pageHeader("실행", "실행 상세", "이 실행이 남긴 순서 있는 결과물과 고정된 다이제스트입니다."),
      el("div", { class: "panel", "data-run-id": String(run.run_id ?? runId) }, [
        el("div", { class: "actions actions--spaced-below" }, [
          runStateBadge(run.state),
          run.pinned_model_id ? badge("info", "모델 고정", ICONS.check) : null,
        ]),
        keyValues(
          [
            ["실행 ID", String(run.run_id ?? runId), true],
            ["생성 실행 ID", String(run.producing_execution_id ?? "기록 없음"), true],
            ["ActionPlan ID", String(run.action_plan_id ?? "기록 없음"), true],
            ["ActionPlan SHA-256", String(run.action_plan_sha256 ?? "기록 없음"), true],
            ["승인 ID", String(run.plan_approval_id ?? "기록 없음"), true],
            ["ResearchIntent SHA-256", String(run.research_intent_sha256 ?? "기록 없음"), true],
            ["입력 SHA-256", String(run.input_sha256 ?? "기록 없음"), true],
            ["코드 SHA-256", String(run.code_sha256 ?? "기록 없음"), true],
            ["환경 SHA-256", String(run.environment_sha256 ?? "기록 없음"), true],
            run.pinned_provider_id ? ["고정된 제공자", String(run.pinned_provider_id), true] : null,
            run.pinned_model_id ? ["고정된 모델", String(run.pinned_model_id), true] : null,
          ].filter(Boolean),
        ),
      ]),
    ];

    if (run.failure) {
      nodes.push(
        el("div", { class: "panel panel--danger panel--spaced-above" }, [
          el("h2", { class: "panel__title", text: "실패 원인" }),
          el("p", { class: "mono", text: JSON.stringify(run.failure) }),
        ]),
      );
    }

    nodes.push(
      el("section", { class: "section", "aria-labelledby": "outputs-heading" }, [
        el("div", { class: "section__head" }, [
          el("h2", { id: "outputs-heading", text: "커밋된 결과물" }),
          el("p", {
            class: "section__hint",
            text: "정규화 데이터 → 그림 → 해석 노트 → 증거 원장 순서로 커밋됩니다.",
          }),
        ]),
        outputs.length === 0
          ? emptyState("아직 커밋된 결과물이 없습니다", "실행이 결과물을 커밋하면 순서대로 나타납니다.")
          : runOutputs(projectId, outputs),
      ]),
      turnSection(projectId, runId, run, picker),
      el("section", { class: "section", "aria-labelledby": "isolation-heading" }, [
        el("h2", { id: "isolation-heading", text: "실행 격리 고지" }),
        isolationDisclosure(run.execution_isolation ?? null),
      ]),
      el("section", { class: "section", "aria-labelledby": "review-heading" }, [
        el("div", { class: "section__head" }, [
          el("h2", { id: "review-heading", text: "검토" }),
          el("p", {
            class: "section__hint",
            text: "검토는 고정된 증거를 추적만 합니다. 결과물을 다시 만들거나 바꾸지 않습니다.",
          }),
        ]),
        el("div", { class: "actions" }, [
          el("a", {
            class: "button button--primary button--small",
            href: `#/projects/${projectId}/runs/${runId}/review`,
            text: "검토 열기",
          }),
        ]),
      ]),
      el("section", { class: "section", "aria-labelledby": "export-heading" }, [
        el("div", { class: "section__head" }, [
          el("h2", { id: "export-heading", text: "내보내기" }),
          el("p", {
            class: "section__hint",
            text: "고른 버전 ID를 그대로 고정해, 제3자가 검사할 수 있는 재현성 팩 하나로 묶습니다.",
          }),
        ]),
        el("div", { class: "actions" }, [
          el("a", {
            class: "button button--small",
            href: `#/projects/${projectId}/runs/${runId}/export`,
            text: "재현성 팩 만들기",
            "data-action": "open-export",
          }),
          el("a", {
            class: "button button--small",
            href: `#/projects/${projectId}/exports`,
            text: "내보낸 팩 관리",
            "data-action": "open-export-packs",
          }),
        ]),
      ]),
    );
    render(nodes);
    announceScreen("실행 상세를 표시했습니다.");
  }

  /*
   * L10 turn panel.
   *
   * A model turn is bound to this Run. The researcher picks one of the
   * composer-enabled models and sends a prompt; the first successful turn
   * pins that selection on the Run, and from then on the picker offers only
   * the pinned model. A failure surfaces as closed-code Korean copy and is
   * never rerouted to another provider, model, or credential -- the
   * researcher corrects the cause and sends again with the same selection.
   *
   * Conversation text lives only in this screen's memory: the server returns
   * assistant text in the turn response and never persists it, so a reload
   * starts an empty transcript while the Run keeps its non-secret turn
   * records.
   */
  function turnSection(projectId, runId, run, picker) {
    const pinnedFromRun = typeof run.pinned_model_id === "string" ? run.pinned_model_id : "";
    const panel = {
      pinned: pinnedFromRun,
      modelId: pinnedFromRun,
      prompt: "",
      busy: false,
      failure: "",
      summary: null,
      messages: [],
    };
    const section = el("section", {
      class: "section",
      "aria-labelledby": "turn-heading",
      "data-turn-panel": "run",
    });

    function modelOptions() {
      if (panel.pinned) return [{ value: panel.pinned, label: `${panel.pinned} (고정)` }];
      const models = picker && Array.isArray(picker.models) ? picker.models : [];
      return models.map((entry) => ({
        value: String(entry.model_id),
        label: `${entry.model_id} — ${entry.display_name}`,
      }));
    }

    function refreshSendButton() {
      const button = section.querySelector('[data-action="send-turn"]');
      if (button) button.disabled = panel.busy || panel.modelId === "" || panel.prompt.trim() === "";
    }

    function pickerField(options) {
      const control = el(
        "select",
        {
          id: "turn-model",
          name: "turn-model",
          disabled: panel.busy || panel.pinned !== "",
          on: {
            change: (event) => {
              panel.modelId = event.currentTarget.value;
              refreshSendButton();
            },
          },
        },
        [
          panel.pinned ? null : el("option", { value: "", text: "선택해 주세요" }),
          ...options.map((option) =>
            el("option", {
              value: option.value,
              text: option.label,
              selected: option.value === panel.modelId ? true : null,
            }),
          ),
        ],
      );
      // Same re-render caveat as selectField: apply the value after the
      // options exist, the attribute alone is not reliable.
      control.value = panel.modelId;
      return el("div", { class: "field" }, [
        el("label", { class: "field__label", for: "turn-model", text: "모델" }),
        control,
        el("p", {
          class: "field__help",
          text: panel.pinned
            ? "이 실행에 고정된 모델입니다."
            : "작성기에서 사용하도록 설정한 모델만 고를 수 있습니다.",
        }),
      ]);
    }

    async function onSend() {
      if (panel.busy || panel.modelId === "" || panel.prompt.trim() === "") return;
      panel.busy = true;
      panel.failure = "";
      const requestMessages = [...panel.messages, { role: "user", content: panel.prompt }];
      paint();
      try {
        const result = await api.createTurn(projectId, runId, {
          model_id: panel.modelId,
          messages: requestMessages,
          max_output_tokens: TURN_MAX_OUTPUT_TOKENS,
        });
        panel.messages = [...requestMessages, { role: "assistant", content: String(result?.text ?? "") }];
        panel.prompt = "";
        // The first successful turn pins the Run server-side; the picker
        // narrows to exactly that selection from here on.
        panel.pinned = String(result?.model_id ?? panel.modelId);
        panel.summary = {
          provider: String(result?.provider_id ?? ""),
          model: String(result?.model_id ?? ""),
          requests: Number(result?.request_count ?? 0),
        };
        announce("모델 응답을 받았습니다.");
      } catch (error) {
        panel.failure = describeTurnFailure(error);
      }
      panel.busy = false;
      paint();
    }

    function paint() {
      const options = modelOptions();
      const children = [
        el("div", { class: "section__head" }, [
          el("h2", { id: "turn-heading", text: "모델 대화" }),
          el("p", {
            class: "section__hint",
            text: panel.pinned
              ? "첫 성공적인 호출이 고정한 모델만 이 실행에서 사용할 수 있습니다."
              : "이 실행에 묶인 모델 호출입니다. 첫 성공적인 호출이 모델을 고정하며, 실패를 다른 곳으로 넘기지 않습니다.",
          }),
        ]),
      ];

      const history = Array.isArray(run.turns) ? run.turns : [];
      if (history.length > 0) {
        children.push(
          el(
            "ul",
            { class: "plain-list", "data-turn-history": "run" },
            history.map((turn) =>
              el("li", {
                text: `#${turn.seq} ${turn.model_id} · 요청 ${turn.request_count}회 · 종료 ${turn.stop_reason ?? "기록 없음"} · ${formatMoment(turn.created_at)}`,
              }),
            ),
          ),
        );
      }

      if (panel.messages.length > 0) {
        children.push(
          el(
            "ol",
            { class: "turn-transcript", "data-turn-transcript": "memory" },
            panel.messages.map((message) =>
              el("li", { class: "turn-message", dataset: { role: message.role } }, [
                el("p", { class: "turn-message__role", text: message.role === "user" ? "연구자" : "모델" }),
                el("p", { class: "turn-message__text", text: message.content }),
              ]),
            ),
          ),
        );
      }

      if (panel.summary) {
        children.push(
          el("p", {
            class: "meta",
            "data-turn-summary": "last",
            text: `제공자 ${panel.summary.provider} · 모델 ${panel.summary.model} · 요청 ${panel.summary.requests}회`,
          }),
        );
      }

      if (panel.failure) {
        children.push(
          el("p", { class: "inline-error", role: "alert", "data-turn-failure": "closed", text: panel.failure }),
        );
      }

      if (picker === null) {
        children.push(
          el("p", { class: "inline-note", text: "모델 목록을 불러오지 못해 대화를 보낼 수 없습니다." }),
        );
      } else if (options.length === 0) {
        children.push(
          el("p", { class: "inline-note", text: "사용하도록 설정된 모델이 없습니다. 설정 화면에서 모델을 먼저 골라 주세요." }),
        );
      } else {
        const prompt = el("textarea", {
          id: "turn-prompt",
          name: "turn-prompt",
          rows: "4",
          disabled: panel.busy,
          on: {
            input: (event) => {
              panel.prompt = event.currentTarget.value;
              refreshSendButton();
            },
          },
        });
        prompt.value = panel.prompt;
        children.push(
          el("div", { class: "panel panel--raised", "data-turn-form": "composer" }, [
            pickerField(options),
            el("div", { class: "field" }, [
              el("label", { class: "field__label", for: "turn-prompt", text: "프롬프트" }),
              prompt,
            ]),
            el("div", { class: "actions actions--spaced-above" }, [
              el("button", {
                class: "button button--primary",
                type: "button",
                "data-action": "send-turn",
                disabled: panel.busy || panel.modelId === "" || panel.prompt.trim() === "",
                text: panel.busy ? "보내는 중…" : "전송",
                on: { click: onSend },
              }),
            ]),
          ]),
        );
      }

      section.textContent = "";
      section.append(...children);
    }

    paint();
    return section;
  }

  // ---------------------------------------------------------------- export --

  /*
   * The Export screen is the end of the ordered chain, and it is where a
   * product is most tempted to oversell. Four rules hold here and the e2e
   * suite asserts each one:
   *
   * 1. The researcher pins Version identifiers, never "the latest". Every row
   *    shows the exact `artifact_version_id` that travels, the API refuses an
   *    identifier this Run did not publish, and there is no control anywhere
   *    on this screen that means "whatever is newest".
   * 2. Every disclosure rendered after a pack exists is quoted from the pack's
   *    own `manifest.json`. This file does not compose its own summary of what
   *    the pack proves.
   * 3. A digest the pack lists under `not_recomputable_from_pack` is labelled
   *    자체 보고 and is never shown beside the recomputable ones. SPEC-v0.5
   *    section 6 forbids presenting a self-reported digest as provenance.
   * 4. `execution_isolation` goes through `isolationDisclosure`, which has no
   *    branch that draws a sandbox badge, and no verdict on this screen is
   *    rendered as a bare 검증됨.
   */

  const OUTPUT_ROLE_SHORT = {
    csv: "정규화 데이터",
    png: "그림",
    markdown: "해석 노트",
    ledger: "증거 원장",
  };

  function exportPinNote(resolution) {
    return el("div", { class: "panel panel--signal", "data-export-pinning": String(resolution) }, [
      el("h2", { class: "panel__title", text: "선택한 버전 ID가 그대로 고정됩니다" }),
      el("p", {
        text:
          "내보내기는 아티팩트의 '최신' 버전을 대신 찾지 않습니다. 아래에서 고른 " +
          "버전 ID가 그대로 팩에 기록되며, 이 실행이 커밋하지 않은 버전은 선택할 수 " +
          "없습니다. 팩을 만드는 사이에 새 버전이 생겨도 담기는 바이트는 바뀌지 않습니다.",
      }),
      el("p", { class: "meta mono", text: `selection.resolution = ${String(resolution)}` }),
    ]);
  }

  function exportChoiceRow(candidate, selected, onToggle) {
    const inputId = `export-pick-${candidate.artifact_version_id}`;
    const role = String(candidate.role ?? "");
    const label = OUTPUT_ROLE_SHORT[role] || (role ? `기타 (${role})` : "역할 없음");
    const box = el("input", {
      id: inputId,
      type: "checkbox",
      checked: selected,
      "data-version": candidate.artifact_version_id,
      on: {
        change: (event) => onToggle(candidate.artifact_version_id, event.currentTarget.checked),
      },
    });
    return el("li", { class: "export-choice", dataset: { role } }, [
      box,
      el("div", { class: "export-choice__body" }, [
        el("label", { class: "export-choice__name", for: inputId }, [
          el("span", { text: candidate.artifact_name }),
          " ",
          badge("neutral", `${label} · v${candidate.version_no}`, ICONS.check),
        ]),
        el("p", {
          class: "meta",
          text: `팩 안 경로 ${candidate.pack_path} · ${formatBytes(candidate.size_bytes)} · ${candidate.media_type}`,
        }),
        el("p", { class: "meta", text: "고정된 버전 ID" }),
        el("span", { class: "hash", text: candidate.artifact_version_id }),
        el("p", { class: "meta", text: "내용 SHA-256" }),
        el("span", { class: "hash", text: candidate.content_sha256 }),
      ]),
    ]);
  }

  function exportDocumentsPanel(plan) {
    const always = Array.isArray(plan.always_included_documents) ? plan.always_included_documents : [];
    const conditional = Array.isArray(plan.conditional_documents) ? plan.conditional_documents : [];
    return el("div", { class: "panel", "data-export-documents": "plan" }, [
      el("h2", { class: "panel__title", text: "팩에 함께 들어가는 문서" }),
      el("p", {
        class: "meta",
        text: "선택한 결과물 외에, 팩은 아래 문서를 스스로 만들어 담습니다.",
      }),
      el("ul", { class: "plain-list" }, always.map((path) => el("li", { class: "mono", text: path }))),
      el("h3", { text: "만들 때 결정되는 문서" }),
      el("p", {
        text:
          "아래 문서는 담을 바이트가 있을 때만 들어갑니다. 실행 기록 파일이 남아 있는지, " +
          "첨부한 값이 고정된 다이제스트와 일치하는지에 따라 달라지므로, 만들기 전에는 " +
          "들어간다고 약속하지 않습니다.",
      }),
      el(
        "ul",
        { class: "plain-list" },
        conditional.map((path) => el("li", { class: "mono", text: path })),
      ),
    ]);
  }

  function selfReportedPanel(verification) {
    const absent = verification && typeof verification === "object"
      ? verification.not_recomputable_from_pack
      : null;
    const entries = absent && typeof absent === "object" ? Object.entries(absent) : [];
    return el("div", { class: "panel panel--attention", "data-self-reported": String(entries.length) }, [
      el("p", { class: "disclosure__title" }, [
        icon(ICONS.alert),
        "이 팩이 스스로 보고할 뿐, 팩만으로는 다시 계산할 수 없는 값",
      ]),
      el("p", {
        text:
          "아래 다이제스트는 팩 안의 바이트로 확인할 수 없습니다. 팩이 기록한 값일 뿐이므로 " +
          "검증된 출처로 취급하면 안 됩니다. 받는 사람도 manifest.json의 " +
          "not_recomputable_from_pack에서 같은 목록을 봅니다.",
      }),
      entries.length === 0
        ? el("p", { class: "meta", text: "이 팩은 자체 보고 항목을 남기지 않았습니다." })
        : el(
            "ul",
            { class: "self-reported" },
            entries.map(([name, note]) =>
              el("li", { dataset: { digest: name } }, [
                el("p", {}, [el("span", { class: "mono", text: name }), " ", badge("attention", "자체 보고", ICONS.alert)]),
                el("p", { class: "meta", text: String(note) }),
              ]),
            ),
          ),
    ]);
  }

  function recomputablePanel(verification) {
    const present = verification && typeof verification === "object"
      ? verification.recomputable_from_pack
      : null;
    const entries = present && typeof present === "object" ? Object.entries(present) : [];
    return el("div", { class: "panel", "data-recomputable": String(entries.length) }, [
      el("h3", { class: "panel__title", text: "받는 사람이 팩만으로 다시 계산할 수 있는 값" }),
      el("p", {
        class: "meta",
        text:
          "아래 항목은 팩 안의 바이트에서 그대로 다시 계산해 비교할 수 있습니다. " +
          "다시 계산해 보기 전까지는 이 목록도 팩의 주장일 뿐입니다.",
      }),
      el(
        "ul",
        { class: "self-reported" },
        entries.map(([name, note]) =>
          el("li", { dataset: { digest: name } }, [
            el("p", { class: "mono", text: name }),
            el("p", { class: "meta", text: String(note) }),
          ]),
        ),
      ),
    ]);
  }

  function packDisclosurePanel(disclosures) {
    const values = disclosures && typeof disclosures === "object" ? disclosures : {};
    const isolation = values.execution_isolation ?? null;
    return el("section", { class: "section", "aria-labelledby": "pack-disclosure-heading" }, [
      el("div", { class: "section__head" }, [
        el("h2", { id: "pack-disclosure-heading", text: "팩이 밝히는 한계" }),
        el("p", {
          class: "section__hint",
          text: "아래 문장은 이 화면이 지어낸 요약이 아니라 팩의 manifest.json이 담고 있는 값입니다.",
        }),
      ]),
      isolationDisclosure(isolation),
      el("div", { class: "panel", "data-pack-disclosures": "true" }, [
        el("dl", { class: "key-values" }, [
          el("div", {}, [
            el("dt", { text: "기록된 격리 수준" }),
            el("dd", { class: "hash", text: String(isolation ?? "기록 없음") }),
          ]),
          el("div", { "data-sandbox-claim": String(values.execution_isolation_is_a_sandbox === true) }, [
            el("dt", { text: "이 팩이 주장하는 샌드박스" }),
            el("dd", {
              text:
                values.execution_isolation_is_a_sandbox === true
                  ? "있다고 주장합니다"
                  : "없습니다. 이 제품은 격리를 측정하지 않았고, 팩도 격리를 주장하지 않습니다.",
            }),
          ]),
        ]),
        el(
          "ul",
          { class: "self-reported" },
          Object.entries(values)
            .filter(([name]) => name !== "execution_isolation" && name !== "execution_isolation_is_a_sandbox")
            .map(([name, note]) =>
              el("li", { dataset: { disclosure: name } }, [
                el("p", { class: "mono", text: name }),
                el("p", { class: "meta", text: String(note) }),
              ]),
            ),
        ),
      ]),
    ]);
  }

  function packEntriesTable(entries) {
    const table = el("table", {}, [
      el("caption", {
        text: `팩에 담긴 항목 ${entries.length}개. 각 다이제스트는 manifest.json과 checksums.sha256 두 곳에 따로 적혀 있습니다.`,
      }),
      el("thead", {}, [
        el("tr", {}, [
          el("th", { scope: "col", text: "종류" }),
          el("th", { scope: "col", text: "팩 안 경로" }),
          el("th", { scope: "col", text: "크기" }),
          el("th", { scope: "col", text: "SHA-256" }),
        ]),
      ]),
    ]);
    const body = el("tbody");
    for (const entry of entries) {
      body.append(
        el("tr", { dataset: { entry: entry.path } }, [
          el("th", { scope: "row", dataset: { label: "종류" } }, [
            entry.kind === "artifact_version"
              ? badge("info", "결과물", ICONS.check)
              : badge("neutral", "팩 문서", ICONS.dash),
          ]),
          el("td", { dataset: { label: "팩 안 경로" } }, [el("span", { class: "mono", text: entry.path })]),
          el("td", { dataset: { label: "크기" }, text: formatBytes(entry.size_bytes) }),
          el("td", { dataset: { label: "SHA-256" } }, [el("span", { class: "hash", text: entry.sha256 })]),
        ]),
      );
    }
    table.append(body);
    return el("div", { class: "table-scroll" }, [table]);
  }

  function packDocumentsList(documents) {
    return el(
      "ul",
      { class: "plain-list" },
      documents.map((item) =>
        el("li", { dataset: { document: item.path, included: String(item.included === true) } }, [
          el("span", { class: "mono", text: item.path }),
          " ",
          item.included === true
            ? badge("positive", "담김", ICONS.check)
            : badge("neutral", "담기지 않음", ICONS.minus),
        ]),
      ),
    );
  }

  /**
   * Hand the browser one capability URL and let it download normally.
   *
   * The pack can approach 500 MiB, so it is never read into this page: no
   * `fetch`, no `Blob`, no object URL. The API mints a single-use URL that
   * expires in a minute, the anchor is clicked once, and the node is removed
   * immediately, so the capability is never in `location`, never in history,
   * and in the DOM only for the duration of one click. `rel="noreferrer"` is
   * belt and braces on top of the `referrer-policy: no-referrer` every
   * response from this listener already carries.
   */
  async function downloadPack(projectId, packId) {
    const grant = await api.downloadGrant(projectId, packId);
    const anchor = el("a", {
      href: grant.url,
      download: `nipo-export-${packId}.zip`,
      rel: "noreferrer",
    });
    document.body.append(anchor);
    anchor.click();
    anchor.remove();
    return grant;
  }

  function producedPackNodes(projectId, pack, onDownload) {
    const entries = Array.isArray(pack.entries) ? pack.entries : [];
    const documents = Array.isArray(pack.pack_documents) ? pack.pack_documents : [];
    const attested = Array.isArray(pack.attested_documents) ? pack.attested_documents : [];
    return [
      el("section", { class: "section", "aria-labelledby": "pack-heading" }, [
        el("div", { class: "section__head" }, [
          el("h2", { id: "pack-heading", text: "만들어진 팩" }),
          el("p", {
            class: "section__hint",
            text: "이 파일 하나만 있으면 받는 사람이 이 저장소도 이 컴퓨터도 없이 다이제스트를 다시 계산할 수 있습니다.",
          }),
        ]),
        el("div", { class: "panel panel--raised", "data-pack-id": String(pack.pack_id) }, [
          keyValues([
            ["팩 ID", String(pack.pack_id), true],
            ["실행 ID", String(pack.run_id), true],
            ["만든 시각", formatMoment(pack.created_at)],
            ["파일 크기", formatBytes(pack.size_bytes)],
            ["담긴 항목", `${entries.length}개`],
            ["고정된 버전", `${Array.isArray(pack.selection) ? pack.selection.length : 0}개`],
            ["manifest.json SHA-256", String(pack.manifest_sha256), true],
          ]),
          el("p", {
            class: "meta",
            text:
              "manifest.json은 자기 자신의 다이제스트를 담지 않습니다. 위 값은 checksums.sha256에 " +
              "한 번만 적혀 있는 값과 같습니다.",
          }),
          el("div", { class: "actions actions--spaced-above" }, [
            el("button", {
              class: "button button--primary",
              type: "button",
              text: "팩 내려받기",
              "data-action": "download-pack",
              on: { click: onDownload },
            }),
            // This file now exists on disk and nothing will ever remove it on
            // its own, so the screen that made it is the right place to say
            // where it went and how to get rid of it.
            el("a", {
              class: "button",
              href: `#/projects/${projectId}/exports`,
              text: "내보낸 팩 관리",
              "data-action": "open-export-packs",
            }),
          ]),
          el("p", {
            class: "meta",
            "data-download-note": "true",
            text:
              "내려받기 주소는 한 번만 쓸 수 있고 60초 뒤 만료됩니다. 세션 토큰이 아니며 이 팩 " +
              "하나만 엽니다. 다시 필요하면 이 버튼을 다시 누르세요.",
          }),
        ]),
        el("h3", { text: "고정된 아티팩트 버전 ID" }),
        el(
          "ul",
          { class: "plain-list" },
          (Array.isArray(pack.selection) ? pack.selection : []).map((value) =>
            el("li", { class: "hash", dataset: { pinned: String(value) }, text: String(value) }),
          ),
        ),
        el("h3", { text: "팩 문서" }),
        packDocumentsList(documents),
        attested.length > 0
          ? el("p", {
              class: "inline-note",
              "data-attested": attested.join(","),
              text: `이 팩은 ${attested.join(", ")}의 원본 바이트를 함께 담았기 때문에, 해당 다이제스트는 받는 사람이 다시 계산할 수 있습니다.`,
            })
          : null,
        packEntriesTable(entries),
      ]),
      packDisclosurePanel(pack.disclosures),
      selfReportedPanel(pack.verification),
      recomputablePanel(pack.verification),
    ];
  }

  async function renderExport(projectId, runId) {
    document.title = "내보내기 — Nipo Science local";
    workspaceTitle.textContent = "내보내기";
    setBarActions([]);
    state.projectId = projectId;
    render([loadingState("내보낼 수 있는 버전을 읽는 중")]);

    const head = [
      breadcrumb([
        { label: "워크스페이스", href: "#/workspace" },
        { label: "실행", href: `#/projects/${projectId}/runs` },
        { label: "실행 상세", href: `#/projects/${projectId}/runs/${runId}` },
        { label: "내보내기" },
      ]),
    ];

    let plan;
    try {
      plan = await api.exportPlan(projectId, runId);
    } catch (error) {
      showError(describeError(error));
      render([
        ...head,
        pageHeader("내보내기", "내보내기를 준비할 수 없습니다", describeError(error)),
      ]);
      announceScreen("내보내기를 준비할 수 없습니다.");
      return;
    }

    const candidates = Array.isArray(plan.candidates) ? plan.candidates : [];
    const selected = new Set(candidates.map((item) => item.artifact_version_id));
    let produced = null;

    function onToggle(versionId, checked) {
      if (checked) selected.add(versionId);
      else selected.delete(versionId);
      const button = document.querySelector('[data-action="create-pack"]');
      if (button) {
        button.disabled = selected.size === 0;
        const counter = document.querySelector("[data-selection-count]");
        if (counter) counter.textContent = `${selected.size}개 버전을 고정합니다.`;
      }
    }

    async function onCreate(event) {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        produced = await api.createExport(projectId, runId, [...selected]);
        clearError();
        announce(`재현성 팩을 만들었습니다. 항목 ${produced.entries.length}개를 담았습니다.`);
        paint();
      } catch (error) {
        showError(describeError(error));
        button.disabled = selected.size === 0;
      }
    }

    async function onDownload(event) {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        await downloadPack(projectId, produced.pack_id);
        clearError();
        announce("팩 내려받기를 시작했습니다. 이 주소는 한 번만 쓸 수 있습니다.");
      } catch (error) {
        showError(describeError(error));
      } finally {
        button.disabled = false;
      }
    }

    function paint() {
      const nodes = [
        ...head,
        pageHeader(
          "내보내기",
          "재현성 팩 만들기",
          "고른 버전과 그 출처, 승인된 계획, 검토 상태를 하나의 검사 가능한 파일로 묶습니다.",
        ),
        exportPinNote(plan.selection_resolution),
      ];

      if (candidates.length === 0) {
        nodes.push(
          emptyState(
            "이 실행에는 내보낼 결과물이 없습니다",
            "실행이 결과물을 커밋하면 그 버전이 여기에 나타납니다.",
          ),
        );
        render(nodes);
        announceScreen("이 실행에는 내보낼 결과물이 없습니다.");
        return;
      }

      const list = el(
        "ul",
        { class: "export-choices" },
        candidates.map((item) =>
          exportChoiceRow(item, selected.has(item.artifact_version_id), onToggle),
        ),
      );
      nodes.push(
        el("section", { class: "section", "aria-labelledby": "export-pick-heading" }, [
          el("div", { class: "section__head" }, [
            el("h2", { id: "export-pick-heading", text: "함께 보낼 버전 고르기" }),
            el("p", {
              class: "section__hint",
              text: "이 실행이 커밋한 버전만 고를 수 있습니다. 처음에는 모두 선택되어 있습니다.",
            }),
          ]),
          el("fieldset", { class: "export-fieldset" }, [
            el("legend", { class: "visually-hidden", text: "내보낼 아티팩트 버전" }),
            list,
          ]),
          el("p", {
            class: "meta",
            "data-selection-count": "true",
            text: `${selected.size}개 버전을 고정합니다.`,
          }),
          el("div", { class: "actions actions--spaced-above" }, [
            el("button", {
              class: "button button--primary",
              type: "button",
              text: produced ? "선택으로 다시 만들기" : "재현성 팩 만들기",
              "data-action": "create-pack",
              disabled: selected.size === 0,
              on: { click: onCreate },
            }),
          ]),
        ]),
        exportDocumentsPanel(plan),
      );

      if (produced === null) {
        nodes.push(
          el("section", { class: "section", "aria-labelledby": "pre-isolation-heading" }, [
            el("h2", { id: "pre-isolation-heading", text: "이 실행의 격리 고지" }),
            isolationDisclosure(plan.execution_isolation ?? null),
            el("p", {
              class: "meta",
              text: "같은 고지가 팩의 manifest.json에도 그대로 기록됩니다.",
            }),
          ]),
        );
      } else {
        nodes.push(...producedPackNodes(projectId, produced, onDownload));
      }

      render(nodes);
      announceScreen(
        produced === null
          ? `내보낼 수 있는 버전 ${candidates.length}개를 표시했습니다.`
          : "만들어진 팩과 그 고지를 표시했습니다.",
      );
    }

    paint();
  }

  // ------------------------------------------------------- export lifecycle --

  /*
   * Every export used to be a one-way door. A pack appeared under the data
   * root, no screen listed it, nothing removed it, and a researcher exporting
   * twice a day grew their disk by up to a gigabyte with no surface that even
   * showed the fact. This screen is the other half of that door, and its shape
   * is a decision rather than a convenience:
   *
   * 1. The total is the *filesystem's* answer. Sizes come from `stat` on the
   *    server, not from the member sizes a manifest lists, because a manifest
   *    describes what is inside a pack and not what the pack costs.
   * 2. Nothing here expires. There is no retention horizon, no scheduled
   *    cleanup, and the budget is a *warning* threshold: crossing it changes a
   *    badge and removes nothing. Losing a pack a researcher never looked at is
   *    worse than a full disk, because a full disk is loud and a missing pack
   *    is silent.
   * 3. The sweep can only ever remove packs that are already on this screen. It
   *    is a filter over the rows just painted, every candidate is named in its
   *    own list before the button is armed, and it deletes by issuing the same
   *    one-pack-at-a-time request the row button issues. The server has no
   *    endpoint that selects packs for removal, so there is nowhere for an
   *    unseen pack to be chosen.
   * 4. Removal is two-press, and the armed state changes the accessible name.
   */

  const SWEEP_KEEP_NEWEST = 3;

  function exportUsagePanel(listing) {
    const total = Number(listing.total_size_bytes ?? 0);
    const budget = Number(listing.budget_bytes ?? 0);
    const over = listing.over_budget === true;
    const undescribed = Number(listing.undescribed_count ?? 0);
    return el(
      "div",
      {
        class: over ? "panel panel--attention" : "panel panel--raised",
        "data-exports-total": String(total),
        "data-budget-state": over ? "over" : "under",
      },
      [
        el("h2", { class: "panel__title", text: "내보낸 팩이 이 컴퓨터에서 쓰는 공간" }),
        el("div", { class: "actions actions--spaced-below" }, [
          over
            ? badge("attention", "경고 기준을 넘었습니다", ICONS.alert)
            : badge("neutral", "경고 기준 안에 있습니다", ICONS.check),
        ]),
        keyValues([
          ["팩 개수", `${Number(listing.pack_count ?? 0)}개`],
          ["디스크 사용량", `${formatBytes(total)} · ${formatExactBytes(total)}`],
          ["경고 기준", `${formatBytes(budget)} · ${formatExactBytes(budget)}`],
        ]),
        el("p", {
          text:
            "위 사용량은 팩 파일이 디스크에서 실제로 차지하는 바이트를 그대로 더한 값입니다. " +
            "manifest.json이 적어 둔 담긴 항목 크기의 합이 아닙니다.",
        }),
        el("p", {
          class: "meta",
          "data-retention": "none",
          text:
            "경고 기준을 넘어도 이 화면은 아무것도 자동으로 지우지 않습니다. 보관 기한도, 예약된 " +
            "정리도, 기준을 넘겼을 때의 자동 삭제도 없습니다. 팩은 아래 목록에 보이는 것을 직접 " +
            "고를 때에만 지워집니다.",
        }),
        undescribed > 0
          ? el("p", {
              class: "inline-note",
              "data-undescribed": String(undescribed),
              text:
                `내보내기 폴더에서 ${undescribed}개 항목은 팩으로 끝까지 읽지 못했습니다. ` +
                "위 사용량은 그만큼 전부를 설명하지 못합니다.",
            })
          : null,
      ],
    );
  }

  function storedPackRow(pack, onDownload, onDelete) {
    const packId = String(pack.pack_id);
    const readable = pack.manifest_readable === true;
    const pinned = Array.isArray(pack.selection) ? pack.selection.length : 0;
    return el("tr", { dataset: { packRow: packId, readable: String(readable) } }, [
      el("th", { scope: "row", dataset: { label: "팩" } }, [
        el("span", { class: "hash", text: packId }),
        " ",
        readable
          ? badge("neutral", "manifest 읽음", ICONS.check)
          : badge("attention", "manifest 읽지 못함", ICONS.alert),
      ]),
      el("td", { dataset: { label: "실행" } }, [
        el("span", { class: "hash", text: pack.run_id ? String(pack.run_id) : "manifest에서 읽지 못함" }),
      ]),
      el("td", { dataset: { label: "시각" } }, [
        el("p", { text: `팩 기록 ${pack.created_at ? formatMoment(pack.created_at) : "읽지 못함"}` }),
        el("p", { class: "meta", text: `디스크 기록 ${formatMoment(pack.modified_at)}` }),
      ]),
      el("td", { dataset: { label: "크기" } }, [
        el("p", { text: formatBytes(pack.size_bytes) }),
        el("p", { class: "meta", "data-pack-size": String(pack.size_bytes), text: formatExactBytes(pack.size_bytes) }),
      ]),
      el("td", {
        dataset: { label: "내용" },
        text: readable
          ? `고정된 버전 ${pinned}개 · 담긴 항목 ${Number(pack.entry_count ?? 0)}개`
          : "이 파일에서는 읽지 못했습니다",
      }),
      el("td", { dataset: { label: "동작" } }, [
        el("div", { class: "actions" }, [
          el("button", {
            class: "button button--small",
            type: "button",
            text: "내려받기",
            "aria-label": `팩 ${packId} 내려받기`,
            dataset: { action: "download-stored-pack", pack: packId },
            on: { click: (event) => onDownload(event, packId) },
          }),
          el("button", {
            class: "button button--danger button--small",
            type: "button",
            text: "지우기",
            "aria-label": `팩 ${packId} 지우기`,
            dataset: { action: "delete-pack", pack: packId },
            on: { click: (event) => onDelete(event, packId) },
          }),
        ]),
      ]),
    ]);
  }

  function storedPackTable(packs, onDownload, onDelete) {
    const table = el("table", {}, [
      el("caption", {
        text:
          `이 프로젝트가 가진 팩 ${packs.length}개. 최근에 기록된 것부터 보입니다. ` +
          "크기와 기록 시각은 디스크에서, 실행과 고정된 버전은 팩의 manifest.json에서 읽었습니다.",
      }),
      el("thead", {}, [
        el("tr", {}, [
          el("th", { scope: "col", text: "팩" }),
          el("th", { scope: "col", text: "실행" }),
          el("th", { scope: "col", text: "시각" }),
          el("th", { scope: "col", text: "크기" }),
          el("th", { scope: "col", text: "내용" }),
          el("th", { scope: "col", text: "동작" }),
        ]),
      ]),
    ]);
    table.append(
      el(
        "tbody",
        {},
        packs.map((pack) => storedPackRow(pack, onDownload, onDelete)),
      ),
    );
    return el("div", { class: "table-scroll" }, [table]);
  }

  function sweepSection(candidates, onSweep) {
    const freeable = candidates.reduce((sum, item) => sum + Number(item.size_bytes ?? 0), 0);
    const nodes = [
      el("div", { class: "section__head" }, [
        el("h2", { id: "sweep-heading", text: "오래된 팩 정리" }),
        el("p", {
          class: "section__hint",
          text: `가장 최근 ${SWEEP_KEEP_NEWEST}개를 남기고, 그보다 오래 기록된 팩만 정리 대상이 됩니다.`,
        }),
      ]),
      el("p", {
        text:
          "정리는 위 목록에 이미 보이는 팩만 지웁니다. 아래에 대상이 하나도 빠짐없이 적혀 있고, " +
          "지울 때도 한 번에 하나씩 같은 요청으로 지웁니다. 서버에는 지울 팩을 스스로 고르는 " +
          "경로가 없으므로, 화면에 보인 적 없는 팩이 정리로 사라지는 일은 생기지 않습니다.",
      }),
    ];
    if (candidates.length === 0) {
      nodes.push(
        el("p", {
          class: "inline-note",
          "data-sweep-candidates": "0",
          text: `정리할 팩이 없습니다. 가진 팩이 ${SWEEP_KEEP_NEWEST}개 이하입니다.`,
        }),
      );
      return el("section", { class: "section", "aria-labelledby": "sweep-heading" }, nodes);
    }
    nodes.push(
      el("p", { class: "meta", "data-sweep-candidates": String(candidates.length), text: "정리 대상" }),
      el(
        "ul",
        { class: "plain-list" },
        candidates.map((item) =>
          el("li", { dataset: { sweepCandidate: String(item.pack_id) } }, [
            el("span", { class: "hash", text: String(item.pack_id) }),
            " ",
            el("span", {
              class: "meta",
              text: `${formatBytes(item.size_bytes)} · 디스크 기록 ${formatMoment(item.modified_at)}`,
            }),
          ]),
        ),
      ),
      el("p", {
        "data-sweep-freeable": String(freeable),
        text: `정리하면 ${formatBytes(freeable)} · ${formatExactBytes(freeable)}을(를) 되찾습니다.`,
      }),
      el("div", { class: "actions actions--spaced-above" }, [
        el("button", {
          class: "button button--danger",
          type: "button",
          text: `오래된 팩 ${candidates.length}개 정리`,
          "aria-label": `위에 적힌 오래된 팩 ${candidates.length}개 정리`,
          dataset: { action: "sweep-packs" },
          on: { click: onSweep },
        }),
      ]),
    );
    return el("section", { class: "section", "aria-labelledby": "sweep-heading" }, nodes);
  }

  async function renderExportPacks(projectId) {
    document.title = "내보낸 팩 — Nipo Science local";
    workspaceTitle.textContent = "내보낸 팩";
    setBarActions([]);
    state.projectId = projectId;
    render([loadingState("내보낸 팩을 디스크에서 읽는 중")]);

    const head = [
      breadcrumb([
        { label: "워크스페이스", href: "#/workspace" },
        { label: "프로젝트", href: `#/projects/${projectId}` },
        { label: "내보낸 팩" },
      ]),
    ];

    const reload = () => renderExportPacks(projectId);
    let listing;
    try {
      listing = await api.exportPacks(projectId);
    } catch (error) {
      showError(describeError(error));
      render([...head, pageHeader("내보내기", "내보낸 팩을 읽을 수 없습니다", describeError(error))]);
      announceScreen("내보낸 팩을 읽을 수 없습니다.");
      return;
    }

    const packs = Array.isArray(listing.packs) ? listing.packs : [];

    async function onDownload(event, packId) {
      const button = event.currentTarget;
      button.disabled = true;
      try {
        await downloadPack(projectId, packId);
        clearError();
        announce("팩 내려받기를 시작했습니다. 이 주소는 한 번만 쓸 수 있습니다.");
      } catch (error) {
        showError(describeError(error));
      } finally {
        button.disabled = false;
      }
    }

    async function remove(packId) {
      const receipt = await api.deleteExportPack(projectId, packId);
      return Number(receipt.freed_bytes ?? 0);
    }

    async function onDelete(event, packId) {
      const button = event.currentTarget;
      if (
        !armConfirmation(
          button,
          "정말 지울까요? 한 번 더 누르세요",
          `팩 ${packId} 지우기 확인: 되돌릴 수 없습니다. 한 번 더 누르세요`,
        )
      ) {
        return;
      }
      button.disabled = true;
      try {
        const freed = await remove(packId);
        clearError();
        announce(`팩 하나를 지웠습니다. ${formatBytes(freed)}을(를) 되찾았습니다.`);
        await reload();
        document.getElementById("main-content").focus();
      } catch (error) {
        button.disabled = false;
        showError(describeError(error));
      }
    }

    async function onSweep(event) {
      const button = event.currentTarget;
      const candidates = packs.slice(SWEEP_KEEP_NEWEST);
      if (
        !armConfirmation(
          button,
          `위에 적힌 ${candidates.length}개를 정말 지울까요? 한 번 더 누르세요`,
          `위에 적힌 오래된 팩 ${candidates.length}개 정리 확인: 되돌릴 수 없습니다. 한 번 더 누르세요`,
        )
      ) {
        return;
      }
      button.disabled = true;
      let freed = 0;
      try {
        // One request per pack, each naming a pack whose row is on this screen.
        for (const item of candidates) freed += await remove(String(item.pack_id));
        clearError();
        announce(`오래된 팩 ${candidates.length}개를 지웠습니다. ${formatBytes(freed)}을(를) 되찾았습니다.`);
      } catch (error) {
        showError(describeError(error));
      }
      await reload();
      document.getElementById("main-content").focus();
    }

    render([
      ...head,
      pageHeader(
        "내보내기",
        "내보낸 팩",
        "이 프로젝트가 만든 재현성 팩이 디스크에 그대로 남아 있습니다. 여기서 무엇이 얼마나 쌓였는지 보고, 필요 없는 것을 직접 지웁니다.",
      ),
      exportUsagePanel(listing),
      el("section", { class: "section", "aria-labelledby": "stored-packs-heading" }, [
        el("div", { class: "section__head" }, [
          el("h2", { id: "stored-packs-heading", text: "가진 팩" }),
          el("p", {
            class: "section__hint",
            text: "지우면 되돌릴 수 없습니다. 같은 선택으로 다시 만들 수는 있지만 같은 파일이 돌아오지는 않습니다.",
          }),
        ]),
        packs.length === 0
          ? emptyState(
              "이 프로젝트에는 내보낸 팩이 없습니다",
              "실행 화면에서 재현성 팩을 만들면 여기에 파일과 크기가 쌓입니다.",
              el("a", {
                class: "button button--primary",
                href: `#/projects/${projectId}/runs`,
                text: "실행 기록으로 가기",
              }),
            )
          : storedPackTable(packs, onDownload, onDelete),
      ]),
      packs.length === 0 ? null : sweepSection(packs.slice(SWEEP_KEEP_NEWEST), onSweep),
    ]);
    announceScreen(
      `내보낸 팩 ${packs.length}개를 표시했습니다. 디스크 사용량은 ${formatBytes(Number(listing.total_size_bytes ?? 0))}입니다.`,
    );
  }

  // ---------------------------------------------------------------- review --

  /*
   * A Review screen is where a product is most tempted to lie by omission.
   * Three rules hold here and are asserted by the e2e suite:
   *
   * 1. There is no bare "검증됨" badge anywhere in this section. Every verdict
   *    is rendered together with the sentence that bounds it, because a
   *    one-word pass invites a reader to assume coverage the Reviewer never
   *    had.
   * 2. `inconclusive` is a normal outcome. It gets the neutral treatment and
   *    the word "판정 보류", never the danger colour and never the word
   *    "오류": unreachable evidence is a correct answer under RV02.
   * 3. Every finding is rendered with the rule's own `limits`, which the API
   *    sends beside the verdict. A verdict without its limits is not shown at
   *    all -- there is no branch in this file that renders one without the
   *    other.
   */

  const REVIEW_VERDICT = {
    pass: {
      kind: "positive",
      glyph: ICONS.check,
      label: "위반 없음",
      headline: "이 검토는 확인한 범위 안에서 위반을 찾지 못했습니다",
      detail:
        "아래 '확인하지 않은 것'에 적힌 범위는 이 결과에 포함되지 않습니다. " +
        "검토는 고정된 증거를 추적만 하며 분석을 다시 실행하지 않으므로, " +
        "분석이 옳았다는 뜻이 아닙니다.",
    },
    inconclusive: {
      kind: "neutral",
      glyph: ICONS.dash,
      label: "판정 보류",
      headline: "확인할 수 없는 증거가 있어 판정을 보류했습니다",
      detail:
        "판정 보류는 검토의 실패가 아니라 정상적인 결과입니다. 증거가 없거나, " +
        "도달할 수 없거나, 이 설치본이 확인할 수 없는 종류일 때 통과 대신 " +
        "보류로 기록됩니다.",
    },
    warn: {
      kind: "attention",
      glyph: ICONS.alert,
      label: "주의",
      headline: "고정된 증거와 어긋나는 점이 있습니다",
      detail:
        "아래 규칙별 결과에서 어긋난 부분을 확인하세요. 수정은 이 검토가 아니라 " +
        "생산 경로가 새 실행과 새 버전으로 수행하며, 그 뒤에 새 검토가 붙습니다.",
    },
    fail: {
      kind: "danger",
      glyph: ICONS.cross,
      label: "위반",
      headline: "고정된 증거가 규칙을 위반합니다",
      detail:
        "이 결과물을 근거로 쓰기 전에 아래 규칙별 결과를 확인하세요. 수정은 " +
        "덮어쓰기가 아니라 새 실행과 새 버전으로만 이루어집니다.",
    },
  };

  const REVIEW_STATE_LABEL = {
    queued: "대기 중",
    running: "실행 중",
    completed: "완료",
    failed: "실패",
  };

  function reviewVerdictBadge(value) {
    const entry = REVIEW_VERDICT[value];
    if (entry) return badge(entry.kind, entry.label, entry.glyph);
    return badge("neutral", `알 수 없는 판정 (${String(value)})`, ICONS.alert);
  }

  function reviewVerdictPanel(record) {
    const entry = REVIEW_VERDICT[record.verdict] || REVIEW_VERDICT.inconclusive;
    return el(
      "div",
      { class: "panel panel--raised", "data-review-verdict": String(record.verdict) },
      [
        el("div", { class: "actions actions--spaced-below" }, [
          reviewVerdictBadge(record.verdict),
          badge("neutral", `검토 상태 ${REVIEW_STATE_LABEL[record.state] || record.state}`),
        ]),
        el("h2", { class: "panel__title", text: entry.headline }),
        el("p", { text: entry.detail }),
        el("p", {
          class: "meta",
          text:
            "이 검토는 고정된 증거만 읽습니다. 파이썬을 실행하지도, 결과물을 " +
            "다시 만들지도, 어떤 버전도 쓰지 않습니다.",
        }),
      ],
    );
  }

  function reviewCoverageList(items, heading, tone) {
    return el("div", { class: "review-coverage", "data-coverage": tone }, [
      el("h4", { text: heading }),
      el(
        "ul",
        {},
        items.map((line) => el("li", { text: line })),
      ),
    ]);
  }

  function reviewFindingCard(finding, coverage) {
    const rule = String(finding.rule_id ?? "");
    const checks = coverage && Array.isArray(coverage.checks) ? coverage.checks : [];
    const limits = coverage && Array.isArray(coverage.limits) ? coverage.limits : [];
    return el(
      "li",
      {
        class: "review-finding",
        dataset: { rule, verdict: String(finding.verdict ?? "") },
      },
      [
        el("div", { class: "review-finding__head" }, [
          el("h3", { text: rule }),
          reviewVerdictBadge(finding.verdict),
        ]),
        coverage ? el("p", { class: "review-finding__statement", text: coverage.statement }) : null,
        el("p", { class: "meta", text: `기록된 코드: ${String(finding.code ?? "")}` }),
        el("p", { text: String(finding.message ?? "") }),
        checks.length > 0 ? reviewCoverageList(checks, "확인한 것", "checked") : null,
        // Rendered unconditionally beside every verdict: a rule's limits are
        // what keeps its verdict from being read as full coverage.
        limits.length > 0
          ? reviewCoverageList(limits, "확인하지 않은 것", "unchecked")
          : el("p", { class: "meta", text: "이 규칙의 한계가 기록되지 않았습니다." }),
      ],
    );
  }

  function reviewLimitsPanel(coverage) {
    const lines = [];
    for (const entry of coverage) {
      for (const limit of Array.isArray(entry.limits) ? entry.limits : []) {
        lines.push(`${entry.rule_id}: ${limit}`);
      }
    }
    return el("div", { class: "panel panel--attention", "data-review-limits": String(lines.length) }, [
      el("p", { class: "disclosure__title" }, [icon(ICONS.alert), "이 검토가 확인하지 않은 것"]),
      el("p", {
        text:
          "아래 항목은 이 검토가 구조적으로 확인할 수 없는 범위입니다. 판정이 " +
          "'위반 없음'이더라도 여기에 적힌 것은 검사되지 않았습니다.",
      }),
      el(
        "ul",
        {},
        lines.map((line) => el("li", { text: line })),
      ),
    ]);
  }

  function reviewPinsPanel(record) {
    const versions = Array.isArray(record.pinned_artifact_version_ids)
      ? record.pinned_artifact_version_ids
      : [];
    const executions = Array.isArray(record.pinned_execution_ids)
      ? record.pinned_execution_ids
      : [];
    return el("div", { class: "panel", "data-review-id": String(record.id) }, [
      el("h2", { class: "panel__title", text: "이 검토가 고정한 증거" }),
      keyValues([
        ["검토 ID", String(record.id), true],
        ["원본 실행 ID", String(record.source_run_id), true],
        ["고정 입력 SHA-256", String(record.pinned_input_sha256), true],
        [
          "고정된 버전",
          versions.length > 0 ? versions.join("\n") : "고정된 버전 없음",
          true,
        ],
        [
          "고정된 생성 실행",
          executions.length > 0 ? executions.join("\n") : "고정된 실행 없음",
          true,
        ],
        ["열린 시각", formatMoment(record.created_at)],
        [
          "결과 제출 시각",
          record.findings_submitted_at ? formatMoment(record.findings_submitted_at) : "제출 없음",
        ],
      ]),
    ]);
  }

  function reviewNodes(projectId, runId, record) {
    const coverage = Array.isArray(record.coverage) ? record.coverage : [];
    const byRule = new Map(coverage.map((item) => [String(item.rule_id), item]));
    const findings = Array.isArray(record.findings) ? record.findings : [];
    return [
      breadcrumb([
        { label: "워크스페이스", href: "#/workspace" },
        { label: "실행", href: `#/projects/${projectId}/runs` },
        { label: "실행 상세", href: `#/projects/${projectId}/runs/${runId}` },
        { label: "검토" },
      ]),
      pageHeader(
        "검토",
        "추적 전용 검토",
        "고정된 증거를 규칙 RV01–RV05로 추적한 결과입니다. 아무것도 다시 실행하지 않았습니다.",
      ),
      reviewVerdictPanel(record),
      reviewLimitsPanel(coverage),
      el("section", { class: "section", "aria-labelledby": "findings-heading" }, [
        el("div", { class: "section__head" }, [
          el("h2", { id: "findings-heading", text: "규칙별 결과" }),
          el("p", {
            class: "section__hint",
            text: "각 규칙의 판정과 함께 그 규칙이 확인한 것과 확인하지 못한 것을 함께 봅니다.",
          }),
        ]),
        findings.length === 0
          ? emptyState(
              "제출된 규칙 결과가 없습니다",
              "이 검토는 아직 아무것도 확인하지 않았습니다. 결과가 없다는 것은 통과했다는 뜻이 아닙니다.",
            )
          : el(
              "ul",
              { class: "review-findings" },
              findings.map((finding) =>
                reviewFindingCard(finding, byRule.get(String(finding.rule_id)) || null),
              ),
            ),
      ]),
      reviewPinsPanel(record),
    ];
  }

  async function renderReview(projectId, runId) {
    document.title = "검토 — Nipo Science local";
    workspaceTitle.textContent = "검토";
    setBarActions([]);
    state.projectId = projectId;
    render([loadingState("검토 기록을 읽는 중")]);

    const head = [
      breadcrumb([
        { label: "워크스페이스", href: "#/workspace" },
        { label: "실행", href: `#/projects/${projectId}/runs` },
        { label: "검토" },
      ]),
    ];

    let record;
    try {
      record = await api.review(projectId, runId);
    } catch (error) {
      if (error instanceof LocalApiError && error.code === "review_not_found") {
        clearError();
        render([
          ...head,
          pageHeader("검토", "아직 검토하지 않은 실행입니다", "검토는 고정된 증거만 읽으며 아무것도 다시 실행하지 않습니다."),
          emptyState(
            "이 실행에는 검토 기록이 없습니다",
            "검토를 실행하면 고정된 결과물을 규칙 RV01–RV05로 추적한 결과가 남습니다. 검토는 결과물을 바꾸지 않습니다.",
            el("button", {
              class: "button button--primary",
              type: "button",
              text: "검토 실행",
              on: {
                click: async (event) => {
                  const button = event.currentTarget;
                  button.disabled = true;
                  try {
                    await api.openReview(projectId, runId);
                    announce("검토를 기록했습니다.");
                    await renderReview(projectId, runId);
                  } catch (failure) {
                    showError(describeError(failure));
                    button.disabled = false;
                  }
                },
              },
            }),
          ),
        ]);
        announceScreen("이 실행에는 검토 기록이 없습니다.");
        return;
      }
      showError(describeError(error));
      render([...head, pageHeader("검토", "검토를 열 수 없습니다", describeError(error))]);
      return;
    }
    render(reviewNodes(projectId, runId, record));
    announceScreen(`검토 결과를 표시했습니다. 종합 판정은 ${REVIEW_VERDICT[record.verdict]?.label ?? record.verdict}입니다.`);
  }

  // -------------------------------------------------------------- bootstrap --

  function renderBootstrap(message) {
    document.title = "로컬 연결 — Nipo Science local";
    workspaceTitle.textContent = "로컬 연결 필요";
    setBarActions([]);
    identityNode.textContent = "연결되지 않음";

    const form = el("form", { class: "panel", novalidate: true });
    const input = el("input", {
      id: "session-token",
      name: "token",
      type: "password",
      autocomplete: "off",
      spellcheck: "false",
      "aria-describedby": "session-token-help",
    });
    form.append(
      el("div", { class: "field" }, [
        el("label", { class: "field__label", for: "session-token", text: "로컬 세션 토큰" }),
        input,
        el("p", {
          class: "field__help",
          id: "session-token-help",
          text: "워크벤치를 시작하면 홈 폴더의 .nipo-science/api-token.json 파일에 이번 실행의 토큰이 기록됩니다. 그 값을 붙여넣으세요. 제공자 API 키가 아니며, 브라우저에 저장되지 않습니다.",
        }),
      ]),
      el("div", { class: "actions actions--spaced-above" }, [
        el("button", { class: "button button--primary", type: "submit", text: "연결" }),
      ]),
    );
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      const value = input.value.trim();
      input.value = "";
      if (!value) {
        input.setAttribute("aria-invalid", "true");
        showError("토큰을 입력해 주세요.");
        input.focus();
        return;
      }
      sessionToken = value;
      const ready = await connect();
      if (ready) {
        clearError();
        await route();
      } else {
        input.focus();
      }
    });

    render([
      pageHeader("로컬 연결", "로컬 서버에 연결해야 합니다", message),
      el("div", { class: "bootstrap" }, [
        el("div", { class: "panel panel--signal" }, [
          el("h2", { class: "panel__title", text: "이 화면은 이 컴퓨터 안에서만 통신합니다" }),
          el("p", {
            text:
              "로컬 API는 루프백 주소에만 바인딩되고, 실행마다 새로 발급한 세션 토큰을 요구하며, " +
              "다른 출처에서 온 요청과 사전 요청을 모두 거부합니다. 이 페이지는 그 토큰을 " +
              "브라우저 저장소에 남기지 않고 메모리에만 둡니다.",
          }),
        ]),
        form,
      ]),
    ]);
    announceScreen("로컬 서버 연결이 필요합니다.");
  }

  async function connect() {
    try {
      const health = await api.health();
      state.identity = health;
      identityNode.textContent = `루프백 전용 · ${window.location.host}`;
      return true;
    } catch (error) {
      showError(describeError(error));
      return false;
    }
  }

  // ---------------------------------------------------------------- router --

  const ROUTES = [
    [/^\/settings\/models$/u, () => renderModelSettings()],
    [/^\/workspace$/u, () => renderWorkspace()],
    [/^\/artifacts$/u, () => renderProjectGate("아티팩트", "/artifacts")],
    [/^\/runs$/u, () => renderProjectGate("실행", "/runs")],
    [/^\/projects\/([^/]+)$/u, (pid) => renderProject(pid)],
    [/^\/projects\/([^/]+)\/sessions\/([^/]+)\/plan$/u, (pid, sid) => renderPlanApproval(pid, sid)],
    [/^\/projects\/([^/]+)\/artifacts$/u, (pid) => renderArtifacts(pid)],
    [/^\/projects\/([^/]+)\/artifacts\/([^/]+)$/u, (pid, aid) => renderArtifact(pid, aid, null)],
    [
      /^\/projects\/([^/]+)\/artifacts\/([^/]+)\/versions\/([^/]+)$/u,
      (pid, aid, vid) => renderArtifact(pid, aid, vid),
    ],
    [/^\/projects\/([^/]+)\/runs$/u, (pid) => renderRuns(pid)],
    [/^\/projects\/([^/]+)\/runs\/([^/]+)$/u, (pid, rid) => renderRun(pid, rid)],
    [/^\/projects\/([^/]+)\/runs\/([^/]+)\/review$/u, (pid, rid) => renderReview(pid, rid)],
    [/^\/projects\/([^/]+)\/runs\/([^/]+)\/export$/u, (pid, rid) => renderExport(pid, rid)],
    [/^\/projects\/([^/]+)\/exports$/u, (pid) => renderExportPacks(pid)],
  ];

  function currentPath() {
    const raw = window.location.hash.replace(/^#/u, "");
    return raw.startsWith("/") ? raw : "/settings/models";
  }

  function markNavigation(path) {
    for (const link of document.querySelectorAll("a[data-route]")) {
      const target = link.dataset.route.replace(/^#/u, "");
      const family = target.split("/")[1] || "";
      const active =
        path === target ||
        (family === "settings" && path.startsWith("/settings")) ||
        (family === "workspace" && path.startsWith("/projects") && !/\/(artifacts|runs)/u.test(path)) ||
        (family === "artifacts" && path.includes("/artifacts")) ||
        (family === "runs" && /\/runs(\/|$)/u.test(path));
      if (active) link.setAttribute("aria-current", "page");
      else link.removeAttribute("aria-current");
    }
  }

  let routing = false;

  async function route() {
    if (routing) return;
    routing = true;
    try {
      const path = currentPath();
      markNavigation(path);
      clearError();
      // A navigation is a fresh context; an unconsumed action outcome from the
      // previous screen must not be replayed on this one.
      pendingAnnouncement = "";
      screen.setAttribute("aria-busy", "true");
      for (const [pattern, handler] of ROUTES) {
        const match = pattern.exec(path);
        if (match) {
          await handler(...match.slice(1));
          screen.removeAttribute("aria-busy");
          return;
        }
      }
      screen.removeAttribute("aria-busy");
      document.title = "찾을 수 없음 — Nipo Science local";
      render([
        pageHeader("찾을 수 없음", "이 화면은 없습니다", "주소를 확인하거나 아래에서 워크스페이스로 돌아가세요."),
        emptyState(
          "요청한 화면이 없습니다",
          "이 설치본에 존재하지 않는 경로입니다.",
          el("a", { class: "button button--primary", href: "#/workspace", text: "워크스페이스로 가기" }),
        ),
      ]);
    } finally {
      routing = false;
    }
  }

  async function boot() {
    // The injected meta value is authoritative. The listener serving this page
    // put it there, and it never touched the address bar, browser history, or
    // a `Referer`. The fragment is consulted only when no credential was
    // injected, which is the position a launcher that cannot rewrite the
    // document is in.
    sessionToken = readInjectedToken() || readFragmentToken();
    if (!sessionToken) {
      renderBootstrap("이번 실행의 로컬 세션 토큰이 이 페이지에 전달되지 않았습니다.");
      return;
    }
    const ready = await connect();
    if (!ready) {
      renderBootstrap("전달된 토큰으로 로컬 서버에 연결하지 못했습니다.");
      return;
    }
    clearError();
    await route();
  }

  window.addEventListener("hashchange", () => {
    // A launcher may hand this page a fresh credential at any time, not only
    // on first load. Take it out of the fragment before the fragment is read
    // as a route, otherwise `#token=...` would resolve to the default screen.
    const refreshed = readFragmentToken();
    if (refreshed) sessionToken = refreshed;
    if (!sessionToken) {
      renderBootstrap("이번 실행의 로컬 세션 토큰이 이 페이지에 전달되지 않았습니다.");
      return;
    }
    if (!state.identity) {
      void boot();
      return;
    }
    void route().then(() => {
      document.getElementById("main-content").focus();
    });
  });

  let booted = false;
  function bootOnce() {
    if (booted) return;
    booted = true;
    void boot();
  }

  document.addEventListener("DOMContentLoaded", bootOnce);
  if (document.readyState !== "loading") bootOnce();
})();
