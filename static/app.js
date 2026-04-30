const state = {
  token: localStorage.getItem("cds_token") || "",
  user: null,
  studies: [],
  studyId: Number(localStorage.getItem("cds_study_id") || 0),
  forms: [],
  participants: [],
  entries: [],
  queries: [],
  audit: [],
  analysis: null,
  view: "dashboard",
  selectedParticipantId: 0,
  menuOpen: false,
  error: "",
};

const app = document.querySelector("#app");

async function api(path, options = {}) {
  const headers = { "Content-Type": "application/json", ...(options.headers || {}) };
  if (state.token) headers.Authorization = `Bearer ${state.token}`;
  const response = await fetch(path, { ...options, headers });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(payload.error || response.statusText);
  }
  const type = response.headers.get("content-type") || "";
  if (type.includes("application/json")) return response.json();
  return response.text();
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

function fmtTime(seconds) {
  if (!seconds) return "";
  return new Date(seconds * 1000).toLocaleString();
}

function activeStudy() {
  return state.studies.find((study) => study.id === state.studyId) || state.studies[0];
}

async function loadAll() {
  if (!state.token) return renderLogin();
  try {
    const me = await api("/api/me");
    state.user = me.user;
    const studies = await api("/api/studies");
    state.studies = studies.studies;
    if (!state.studyId && state.studies[0]) state.studyId = state.studies[0].id;
    localStorage.setItem("cds_study_id", String(state.studyId || ""));
    await loadStudy();
  } catch (error) {
    state.token = "";
    localStorage.removeItem("cds_token");
    state.error = error.message;
  }
  render();
}

async function loadStudy() {
  if (!state.studyId) return;
  const [forms, participants, entries, queries, analysis, audit] = await Promise.all([
    api(`/api/studies/${state.studyId}/forms`),
    api(`/api/studies/${state.studyId}/participants`),
    api(`/api/studies/${state.studyId}/entries`),
    api(`/api/studies/${state.studyId}/queries`),
    api(`/api/studies/${state.studyId}/analysis`),
    api("/api/audit"),
  ]);
  state.forms = forms.forms;
  state.participants = participants.participants;
  state.entries = entries.entries;
  state.queries = queries.queries;
  state.analysis = analysis;
  state.audit = audit.audit;
}

function render() {
  if (!state.token) return renderLogin();
  const study = activeStudy();
  app.innerHTML = `
    <div class="shell">
      <aside class="sidebar ${state.menuOpen ? "open" : ""}">
        <div class="brand">
          <strong>Clinical Data Studio</strong>
          <span>Local network EDC</span>
        </div>
        <label>
          Study
          <select id="study-picker">
            ${state.studies.map((item) => `<option value="${item.id}" ${item.id === state.studyId ? "selected" : ""}>${escapeHtml(item.name)}</option>`).join("")}
          </select>
        </label>
        <nav class="nav">
          ${navButton("dashboard", "Dashboard")}
          ${navButton("participants", "Participants")}
          ${navButton("data", "Data Entry")}
          ${navButton("forms", "CRF Builder")}
          ${navButton("queries", "Review Queries")}
          ${navButton("analysis", "Analysis")}
          ${navButton("audit", "Audit Trail")}
          ${navButton("settings", "Study Setup")}
        </nav>
      </aside>
      <section class="main">
        <header class="topbar">
          <div class="row">
            <button class="icon mobile-menu" id="menu-toggle" title="Menu">☰</button>
            <div>
              <strong>${escapeHtml(study?.name || "No study")}</strong>
              <div class="small">${escapeHtml(study?.protocol_id || "")}</div>
            </div>
          </div>
          <div class="split-actions">
            <a href="/api/studies/${state.studyId}/export" target="_blank"><button class="secondary">Export CSV</button></a>
            <button class="secondary" id="logout">Logout</button>
          </div>
        </header>
        <div class="content">
          ${state.error ? `<div class="notice error">${escapeHtml(state.error)}</div>` : ""}
          ${route()}
        </div>
      </section>
    </div>
  `;
  bindShell();
  bindRoute();
}

function navButton(view, label) {
  return `<button data-view="${view}" class="${state.view === view ? "active" : ""}">${label}</button>`;
}

function route() {
  if (!state.studyId) return settingsView();
  if (state.view === "participants") return participantsView();
  if (state.view === "data") return dataView();
  if (state.view === "forms") return formsView();
  if (state.view === "queries") return queriesView();
  if (state.view === "analysis") return analysisView();
  if (state.view === "audit") return auditView();
  if (state.view === "settings") return settingsView();
  return dashboardView();
}

function dashboardView() {
  const complete = state.analysis?.completed_entry_count || 0;
  const total = state.analysis?.entry_count || 0;
  const completion = total ? Math.round((complete / total) * 100) : 0;
  return `
    <section class="grid three">
      ${metric("Participants", state.analysis?.participant_count || 0, "Enrolled or screening records")}
      ${metric("CRF Entries", total, `${completion}% complete`)}
      ${metric("Open Queries", state.analysis?.open_query_count || 0, "Needs review")}
    </section>
    <section class="panel">
      <h2>Today</h2>
      <div class="grid two">
        <div class="notice">Use Data Entry for bedside/mobile capture. Use Review Queries to track missing or questionable data.</div>
        <div class="notice">For real studies, keep identifiers minimal and export de-identified datasets for analysis.</div>
      </div>
    </section>
    <section class="panel">
      <h2>Recent Participants</h2>
      ${participantsTable(state.participants.slice(0, 6))}
    </section>
  `;
}

function metric(label, value, hint) {
  return `<div class="card metric"><span class="small">${label}</span><strong>${value}</strong><span>${escapeHtml(hint)}</span></div>`;
}

function participantsView() {
  return `
    <section class="panel">
      <div class="row">
        <h2>Participants</h2>
      </div>
      <form id="participant-form" class="form-grid">
        <label>Study ID<input name="study_uid" required placeholder="P001" /></label>
        <label>Initials<input name="initials" maxlength="6" placeholder="AB" /></label>
        <label>Status
          <select name="status">
            <option>screening</option>
            <option>enrolled</option>
            <option>completed</option>
            <option>withdrawn</option>
          </select>
        </label>
        <label>Notes<input name="notes" placeholder="Optional non-PHI note" /></label>
        <div class="full"><button>Add Participant</button></div>
      </form>
    </section>
    <section class="panel">
      ${participantsTable(state.participants)}
    </section>
  `;
}

function participantsTable(participants) {
  if (!participants.length) return `<p>No participants yet.</p>`;
  return `
    <div class="table-wrap">
      <table>
        <thead><tr><th>Study ID</th><th>Initials</th><th>Status</th><th>Created</th><th></th></tr></thead>
        <tbody>
          ${participants.map((item) => `
            <tr>
              <td><strong>${escapeHtml(item.study_uid)}</strong></td>
              <td>${escapeHtml(item.initials)}</td>
              <td><span class="pill">${escapeHtml(item.status)}</span></td>
              <td>${fmtTime(item.created_at)}</td>
              <td><button class="secondary" data-enter="${item.id}">Enter Data</button></td>
            </tr>
          `).join("")}
        </tbody>
      </table>
    </div>
  `;
}

function dataView() {
  const selected = state.participants.find((item) => item.id === state.selectedParticipantId) || state.participants[0];
  const entryCards = selected ? state.forms.map((form) => entryCard(selected, form)).join("") : "<p>Add a participant first.</p>";
  return `
    <section class="panel">
      <h2>Data Entry</h2>
      <label>
        Participant
        <select id="participant-picker">
          ${state.participants.map((item) => `<option value="${item.id}" ${selected?.id === item.id ? "selected" : ""}>${escapeHtml(item.study_uid)} ${escapeHtml(item.initials)}</option>`).join("")}
        </select>
      </label>
    </section>
    <section class="grid two">${entryCards}</section>
  `;
}

function entryCard(participant, form) {
  const existing = state.entries.find((entry) => entry.participant_id === participant.id && entry.form_id === form.id) || { data: {}, status: "draft", event_name: "Baseline" };
  return `
    <form class="card stack entry-form" data-form-id="${form.id}" data-participant-id="${participant.id}">
      <div class="row">
        <div>
          <h3>${escapeHtml(form.name)}</h3>
          <span class="pill ${existing.status === "complete" ? "ok" : "warn"}">${escapeHtml(existing.status)}</span>
        </div>
        <label>Event<input name="event_name" value="${escapeHtml(existing.event_name || "Baseline")}" /></label>
      </div>
      ${form.schema.fields.map((field) => fieldInput(field, existing.data)).join("")}
      <label>Status
        <select name="status">
          <option value="draft" ${existing.status === "draft" ? "selected" : ""}>draft</option>
          <option value="complete" ${existing.status === "complete" ? "selected" : ""}>complete</option>
        </select>
      </label>
      <div class="split-actions">
        <button>Save CRF</button>
        <button type="button" class="secondary" data-query-form="${form.id}" data-query-participant="${participant.id}">Open Query</button>
      </div>
    </form>
  `;
}

function fieldInput(field, data) {
  const value = data[field.code] ?? "";
  const required = field.required ? "required" : "";
  const visibility = field.show_if ? `data-show-field="${escapeHtml(field.show_if.field)}" data-show-value="${escapeHtml(field.show_if.equals)}"` : "";
  if (field.type === "textarea") {
    return `<label ${visibility}>${escapeHtml(field.label)}<textarea name="${escapeHtml(field.code)}" ${required}>${escapeHtml(value)}</textarea></label>`;
  }
  if (field.type === "select") {
    return `<label ${visibility}>${escapeHtml(field.label)}<select name="${escapeHtml(field.code)}" ${required}><option value=""></option>${(field.options || []).map((option) => `<option ${option === value ? "selected" : ""}>${escapeHtml(option)}</option>`).join("")}</select></label>`;
  }
  const attrs = [`name="${escapeHtml(field.code)}"`, `value="${escapeHtml(value)}"`, required];
  if (field.type === "number") {
    attrs.push('type="number"', field.min !== undefined ? `min="${field.min}"` : "", field.max !== undefined ? `max="${field.max}"` : "", "step='any'");
  } else if (field.type === "date") {
    attrs.push('type="date"');
  } else {
    attrs.push('type="text"');
  }
  return `<label ${visibility}>${escapeHtml(field.label)}<input ${attrs.join(" ")} /></label>`;
}

function formsView() {
  return `
    <section class="panel">
      <h2>CRF Builder</h2>
      <form id="form-builder" class="stack">
        <div class="form-grid">
          <label>Form name<input name="name" required placeholder="Laboratory Results" /></label>
          <label>Code<input name="code" required placeholder="labs" /></label>
        </div>
        <div id="fields" class="stack">
          ${fieldEditorRow()}
        </div>
        <div class="split-actions">
          <button type="button" class="secondary" id="add-field">Add Field</button>
          <button>Create CRF</button>
        </div>
      </form>
    </section>
    <section class="panel">
      <h2>Existing CRFs</h2>
      <div class="grid two">
        ${state.forms.map((form) => `
          <article class="card">
            <h3>${escapeHtml(form.name)}</h3>
            <p>${escapeHtml(form.code)} · v${form.version} · ${form.schema.fields.length} fields</p>
            <div class="stack">
              ${form.schema.fields.map((field) => `<span class="pill">${escapeHtml(field.label)} (${escapeHtml(field.type)})</span>`).join("")}
            </div>
          </article>
        `).join("")}
      </div>
    </section>
  `;
}

function fieldEditorRow() {
  return `
    <div class="field-editor">
      <label>Label<input name="field_label" required placeholder="Systolic BP" /></label>
      <label>Code<input name="field_code" required placeholder="systolic_bp" /></label>
      <label>Type
        <select name="field_type">
          <option value="text">text</option>
          <option value="number">number</option>
          <option value="date">date</option>
          <option value="select">select</option>
          <option value="textarea">textarea</option>
        </select>
      </label>
      <label>Required<select name="field_required"><option value="false">No</option><option value="true">Yes</option></select></label>
      <button type="button" class="secondary icon" data-remove-field title="Remove">×</button>
      <label class="full">Options for select fields<input name="field_options" placeholder="No, Yes" /></label>
      <label>Min<input name="field_min" type="number" step="any" /></label>
      <label>Max<input name="field_max" type="number" step="any" /></label>
    </div>
  `;
}

function queriesView() {
  return `
    <section class="panel">
      <h2>Review Queries</h2>
      ${state.queries.length ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>Status</th><th>Participant</th><th>Form</th><th>Field</th><th>Message</th><th></th></tr></thead>
            <tbody>
              ${state.queries.map((query) => `
                <tr>
                  <td><span class="pill ${query.status === "open" ? "bad" : "ok"}">${escapeHtml(query.status)}</span></td>
                  <td>${escapeHtml(query.study_uid || "")}</td>
                  <td>${escapeHtml(query.form_name || "")}</td>
                  <td>${escapeHtml(query.field_code || "")}</td>
                  <td>${escapeHtml(query.message)}</td>
                  <td>${query.status === "open" ? `<button class="secondary" data-close-query="${query.id}">Close</button>` : ""}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      ` : "<p>No queries.</p>"}
    </section>
  `;
}

function analysisView() {
  const summaries = state.analysis?.field_summaries || [];
  return `
    <section class="grid three">
      ${metric("Participants", state.analysis?.participant_count || 0, "Study records")}
      ${metric("Completed CRFs", state.analysis?.completed_entry_count || 0, "Marked complete")}
      ${metric("Open Queries", state.analysis?.open_query_count || 0, "Data issues")}
    </section>
    <section class="panel">
      <h2>Field Summary</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Variable</th><th>Count</th><th>Missing</th><th>Summary</th></tr></thead>
          <tbody>
            ${summaries.map((item) => `
              <tr>
                <td><strong>${escapeHtml(item.label)}</strong><br><span class="small">${escapeHtml(item.code)}</span></td>
                <td>${item.count}</td>
                <td>${item.missing}</td>
                <td>${item.type === "numeric" ? `mean ${item.mean}, range ${item.min}-${item.max}` : escapeHtml(Object.entries(item.counts || {}).map(([key, value]) => `${key}: ${value}`).join(", "))}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function auditView() {
  return `
    <section class="panel">
      <h2>Audit Trail</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Entity</th></tr></thead>
          <tbody>
            ${state.audit.map((item) => `
              <tr>
                <td>${fmtTime(item.created_at)}</td>
                <td>${escapeHtml(item.display_name || "System")}</td>
                <td>${escapeHtml(item.action)}</td>
                <td>${escapeHtml(item.entity_type)} #${escapeHtml(item.entity_id || "")}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function settingsView() {
  return `
    <section class="panel">
      <h2>Create Study</h2>
      <form id="study-form" class="form-grid">
        <label>Name<input name="name" required placeholder="My Clinical Study" /></label>
        <label>Protocol ID<input name="protocol_id" placeholder="PROT-001" /></label>
        <label class="full">Description<textarea name="description"></textarea></label>
        <div class="full"><button>Create Study</button></div>
      </form>
    </section>
    <section class="panel">
      <h2>Important Use Notes</h2>
      <p>This app is local-first and suitable for small research workflows. For regulated trials, validate the system, document SOPs, review audit trails, and maintain controlled backups.</p>
    </section>
  `;
}

function bindShell() {
  document.querySelector("#menu-toggle")?.addEventListener("click", () => {
    state.menuOpen = !state.menuOpen;
    render();
  });
  document.querySelectorAll("[data-view]").forEach((button) => {
    button.addEventListener("click", () => {
      state.view = button.dataset.view;
      state.menuOpen = false;
      state.error = "";
      render();
    });
  });
  document.querySelector("#study-picker")?.addEventListener("change", async (event) => {
    state.studyId = Number(event.target.value);
    localStorage.setItem("cds_study_id", String(state.studyId));
    await loadStudy();
    render();
  });
  document.querySelector("#logout")?.addEventListener("click", async () => {
    await api("/api/logout", { method: "POST", body: "{}" }).catch(() => {});
    state.token = "";
    localStorage.removeItem("cds_token");
    renderLogin();
  });
}

function bindRoute() {
  document.querySelector("#participant-form")?.addEventListener("submit", submitParticipant);
  document.querySelector("#study-form")?.addEventListener("submit", submitStudy);
  document.querySelector("#form-builder")?.addEventListener("submit", submitFormDefinition);
  document.querySelector("#add-field")?.addEventListener("click", () => {
    document.querySelector("#fields").insertAdjacentHTML("beforeend", fieldEditorRow());
  });
  document.querySelectorAll("[data-remove-field]").forEach((button) => button.addEventListener("click", () => button.closest(".field-editor").remove()));
  document.querySelectorAll("[data-enter]").forEach((button) => {
    button.addEventListener("click", () => {
      state.selectedParticipantId = Number(button.dataset.enter);
      state.view = "data";
      render();
    });
  });
  document.querySelector("#participant-picker")?.addEventListener("change", (event) => {
    state.selectedParticipantId = Number(event.target.value);
    render();
  });
  document.querySelectorAll(".entry-form").forEach((form) => {
    form.addEventListener("submit", submitEntry);
    form.addEventListener("input", () => applyBranching(form));
    applyBranching(form);
  });
  document.querySelectorAll("[data-query-form]").forEach((button) => button.addEventListener("click", openQuery));
  document.querySelectorAll("[data-close-query]").forEach((button) => button.addEventListener("click", () => closeQuery(button.dataset.closeQuery)));
}

function applyBranching(form) {
  form.querySelectorAll("[data-show-field]").forEach((label) => {
    const source = form.elements[label.dataset.showField];
    const visible = source && source.value === label.dataset.showValue;
    label.classList.toggle("hidden", !visible);
  });
}

async function submitParticipant(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api(`/api/studies/${state.studyId}/participants`, {
      method: "POST",
      body: JSON.stringify({ ...data, metadata: { notes: data.notes || "" } }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitStudy(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    const result = await api("/api/studies", { method: "POST", body: JSON.stringify(data) });
    state.studyId = result.study.id;
    await loadAll();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitFormDefinition(event) {
  event.preventDefault();
  const formData = new FormData(event.target);
  const editors = [...event.target.querySelectorAll(".field-editor")];
  const fields = editors.map((editor) => {
    const get = (name) => editor.querySelector(`[name="${name}"]`)?.value.trim();
    const field = {
      label: get("field_label"),
      code: get("field_code"),
      type: get("field_type"),
      required: get("field_required") === "true",
    };
    const options = get("field_options");
    if (field.type === "select" && options) field.options = options.split(",").map((item) => item.trim()).filter(Boolean);
    const min = get("field_min");
    const max = get("field_max");
    if (min !== "") field.min = Number(min);
    if (max !== "") field.max = Number(max);
    return field;
  });
  try {
    await api(`/api/studies/${state.studyId}/forms`, {
      method: "POST",
      body: JSON.stringify({ name: formData.get("name"), code: formData.get("code"), schema: { fields } }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitEntry(event) {
  event.preventDefault();
  const form = event.target;
  const data = {};
  const payload = Object.fromEntries(new FormData(form));
  const formDef = state.forms.find((item) => item.id === Number(form.dataset.formId));
  formDef.schema.fields.forEach((field) => {
    if (!form.querySelector(`[name="${field.code}"]`)?.closest(".hidden")) {
      data[field.code] = payload[field.code] || "";
    }
  });
  try {
    await api(`/api/studies/${state.studyId}/entries`, {
      method: "POST",
      body: JSON.stringify({
        participant_id: Number(form.dataset.participantId),
        form_id: Number(form.dataset.formId),
        event_name: payload.event_name || "Baseline",
        status: payload.status || "draft",
        data,
      }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function openQuery(event) {
  const message = prompt("Query message");
  if (!message) return;
  try {
    await api(`/api/studies/${state.studyId}/queries`, {
      method: "POST",
      body: JSON.stringify({
        participant_id: Number(event.target.dataset.queryParticipant),
        form_id: Number(event.target.dataset.queryForm),
        message,
      }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function closeQuery(id) {
  try {
    await api(`/api/studies/${state.studyId}/queries/${id}`, { method: "PATCH", body: JSON.stringify({ status: "closed" }) });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

function renderLogin() {
  app.innerHTML = `
    <section class="login">
      <form id="login-form" class="login-card stack">
        <div>
          <h1>Clinical Data Studio</h1>
          <p>Local-network clinical research data capture for small teams.</p>
        </div>
        ${state.error ? `<div class="notice error">${escapeHtml(state.error)}</div>` : ""}
        <label>Username<input name="username" value="admin" autocomplete="username" required /></label>
        <label>Password<input name="password" type="password" value="admin123" autocomplete="current-password" required /></label>
        <button>Login</button>
        <p class="small">Default credentials are for first startup only. Change them before real research use.</p>
      </form>
    </section>
  `;
  document.querySelector("#login-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.target));
    try {
      const result = await api("/api/login", { method: "POST", body: JSON.stringify(data) });
      state.token = result.token;
      state.user = result.user;
      state.error = "";
      localStorage.setItem("cds_token", state.token);
      await loadAll();
    } catch (error) {
      state.error = error.message;
      renderLogin();
    }
  });
}

loadAll();
