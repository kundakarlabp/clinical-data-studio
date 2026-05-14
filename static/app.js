const state = {
  token: localStorage.getItem("cds_token") || "",
  user: null,
  setupRequired: false,
  studies: [],
  memberships: [],
  studyId: Number(localStorage.getItem("cds_study_id") || 0),
  users: [],
  groups: [],
  studyMembers: [],
  apiTokens: [],
  randomization: { lists: [], allocations: [] },
  events: [],
  formEvents: [],
  surveyLinks: [],
  invitations: [],
  reports: [],
  academic: { metrics: {}, opportunities: [], cv_items: [], guidance: [] },
  caseIntake: { cases: [], series: null },
  caseAiReview: null,
  backups: [],
  forms: [],
  participants: [],
  entries: [],
  queries: [],
  quality: [],
  audit: [],
  analysis: null,
  assistantSummary: null,
  assistDraft: null,
  readiness: null,
  adminStatus: null,
  adminLogs: [],
  view: "dashboard",
  selectedParticipantId: 0,
  selectedEventId: Number(localStorage.getItem("cds_event_id") || 0),
  editingFormId: 0,
  menuOpen: false,
  online: navigator.onLine,
  installPrompt: null,
  standalone: window.matchMedia("(display-mode: standalone)").matches || navigator.standalone === true,
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
  const setup = await api("/api/setup").catch(() => ({ required: false }));
  state.setupRequired = Boolean(setup.required);
  if (state.setupRequired) return renderSetup();
  if (!state.token) return renderLogin();
  try {
    const me = await api("/api/me");
    state.user = me.user;
    state.memberships = me.memberships || [];
    if (state.user?.must_change_password) return renderPasswordChangeRequired();
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
  const manageUsers = can("manage_users");
  const viewAnalysis = can("view_analysis") || can("review_data");
  const readinessAllowed = can("manage_study") || can("review_data") || can("view_analysis");
  const [forms, events, formEvents, surveyLinks, invitations, reports, academic, caseIntake, backups, participants, entries, queries, quality, analysis, assistantSummary, readiness, audit, groups, studyMembers, apiTokens, randomization, users, adminStatus, adminLogs] = await Promise.all([
    api(`/api/studies/${state.studyId}/forms`),
    api(`/api/studies/${state.studyId}/events`),
    api(`/api/studies/${state.studyId}/form-events`),
    can("manage_forms") ? api(`/api/studies/${state.studyId}/surveys`) : Promise.resolve({ surveys: [] }),
    can("manage_forms") ? api(`/api/studies/${state.studyId}/invitations`) : Promise.resolve({ invitations: [] }),
    viewAnalysis ? api(`/api/studies/${state.studyId}/reports`) : Promise.resolve({ reports: [] }),
    viewAnalysis ? api(`/api/studies/${state.studyId}/academic`) : Promise.resolve({ academic: { metrics: {}, opportunities: [], cv_items: [], guidance: [] } }),
    (can("enter_data") || can("view_analysis") || can("review_data")) ? api(`/api/studies/${state.studyId}/case-intake`) : Promise.resolve({ cases: [], series: null }),
    can("manage_study") ? api(`/api/studies/${state.studyId}/backups`) : Promise.resolve({ backups: [] }),
    api(`/api/studies/${state.studyId}/participants`),
    api(`/api/studies/${state.studyId}/entries`),
    api(`/api/studies/${state.studyId}/queries`),
    api(`/api/studies/${state.studyId}/quality`),
    viewAnalysis ? api(`/api/studies/${state.studyId}/analysis`) : Promise.resolve({ participant_count: 0, entry_count: 0, completed_entry_count: 0, open_query_count: 0, field_summaries: [] }),
    viewAnalysis ? api(`/api/studies/${state.studyId}/assist/summary`) : Promise.resolve({ summary: null }),
    readinessAllowed ? api(`/api/studies/${state.studyId}/readiness`) : Promise.resolve({ readiness: null }),
    can("review_data") ? api(`/api/studies/${state.studyId}/audit`) : Promise.resolve({ audit: [] }),
    api(`/api/studies/${state.studyId}/groups`),
    manageUsers ? api(`/api/studies/${state.studyId}/memberships`) : Promise.resolve({ memberships: [] }),
    manageUsers ? api(`/api/studies/${state.studyId}/api-tokens`) : Promise.resolve({ tokens: [] }),
    can("manage_study") || can("review_data") ? api(`/api/studies/${state.studyId}/randomization`) : Promise.resolve({ lists: [], allocations: [] }),
    isSuperAdmin() ? api("/api/users") : Promise.resolve({ users: [] }),
    isSuperAdmin() ? api("/api/admin/status") : Promise.resolve(null),
    isSuperAdmin() ? api("/api/admin/logs") : Promise.resolve({ lines: [] }),
  ]);
  state.forms = forms.forms;
  state.events = events.events;
  state.formEvents = formEvents.form_events;
  state.surveyLinks = surveyLinks.surveys;
  state.invitations = invitations.invitations;
  state.reports = reports.reports;
  state.academic = academic.academic;
  state.caseIntake = caseIntake;
  state.backups = backups.backups;
  if (!state.selectedEventId && state.events[0]) state.selectedEventId = state.events[0].id;
  if (state.selectedEventId && !state.events.some((event) => event.id === state.selectedEventId)) state.selectedEventId = state.events[0]?.id || 0;
  localStorage.setItem("cds_event_id", String(state.selectedEventId || ""));
  state.participants = participants.participants;
  state.entries = entries.entries;
  state.queries = queries.queries;
  state.quality = quality.issues;
  state.analysis = analysis;
  state.assistantSummary = assistantSummary.summary;
  state.readiness = readiness.readiness;
  state.audit = audit.audit;
  state.groups = groups.groups;
  state.studyMembers = studyMembers.memberships;
  state.apiTokens = apiTokens.tokens;
  state.randomization = randomization;
  state.users = users.users;
  state.adminStatus = adminStatus;
  state.adminLogs = adminLogs.lines || [];
}

function isSuperAdmin() {
  return ["admin", "super_admin"].includes(state.user?.role);
}

function currentMembership() {
  if (isSuperAdmin()) return { role: "owner", data_group_id: null };
  return state.memberships.find((item) => item.study_id === state.studyId) || null;
}

function can(permission) {
  const role = currentMembership()?.role || "";
  const permissions = {
    admin: ["manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis"],
    super_admin: ["manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis"],
    owner: ["manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis"],
    project_admin: ["manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis"],
    pi: ["manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis"],
    data_entry: ["enter_data"],
    reviewer: ["review_data", "view_analysis"],
    analyst: ["export_data", "view_analysis"],
    viewer: ["view_analysis"],
    read_only: ["view_analysis"],
  };
  return (permissions[role] || []).includes(permission);
}

function render() {
  if (!state.token) return renderLogin();
  if (state.user?.must_change_password) return renderPasswordChangeRequired();
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
          ${can("manage_forms") ? navButton("dictionary", "Dictionary") : ""}
          ${can("manage_forms") ? navButton("surveys", "Surveys") : ""}
          ${can("manage_study") ? navButton("events", "Events") : ""}
          ${can("manage_study") || can("review_data") ? navButton("randomization", "Randomization") : ""}
          ${navButton("queries", "Review Queries")}
          ${navButton("quality", "Data Quality")}
          ${(can("enter_data") || can("view_analysis") || can("review_data")) ? navButton("case-intake", "Case Intake") : ""}
          ${navButton("analysis", "Analysis")}
          ${can("view_analysis") || can("export_data") ? navButton("reports", "Reports") : ""}
          ${can("view_analysis") || can("export_data") ? navButton("academic", "Academic CV") : ""}
          ${can("manage_study") ? navButton("backups", "Backups") : ""}
          ${navButton("audit", "Audit Trail")}
          ${can("manage_users") ? navButton("access", "Access") : ""}
          ${navButton("remote", "Remote Access")}
          ${navButton("settings", "Study Setup")}
        </nav>
      </aside>
      <section class="main">
        <header class="topbar">
          <div class="row">
            <button class="icon mobile-menu" id="menu-toggle" title="Menu">Menu</button>
            <div>
              <strong>${escapeHtml(study?.name || "No study")}</strong>
              <div class="small">${escapeHtml(study?.protocol_id || "")}</div>
            </div>
          </div>
          <div class="split-actions">
            ${state.installPrompt && !state.standalone ? `<button class="secondary" id="install-app">Install App</button>` : ""}
            <span class="connection ${state.online ? "online" : "offline"}">${state.online ? "Online" : "Offline"}</span>
            ${can("export_data") ? `<button class="secondary" id="export-csv">Export CSV</button><button class="secondary" id="export-codebook">Codebook</button>` : ""}
            <button class="secondary" id="logout">Logout</button>
          </div>
        </header>
        <div class="content">
          ${state.user?.must_change_password ? `<div class="notice error">Default password is still active. Change it in Study Setup before real use.</div>` : ""}
          ${state.online ? "" : `<div class="notice error">This device is offline. You can open installed pages, but clinical data saves require connection to the study computer.</div>`}
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
  if (state.view === "dictionary") return dictionaryView();
  if (state.view === "surveys") return surveysView();
  if (state.view === "events") return eventsView();
  if (state.view === "randomization") return randomizationView();
  if (state.view === "queries") return queriesView();
  if (state.view === "quality") return qualityView();
  if (state.view === "case-intake") return caseIntakeView();
  if (state.view === "analysis") return analysisView();
  if (state.view === "reports") return reportsView();
  if (state.view === "academic") return academicView();
  if (state.view === "backups") return backupsView();
  if (state.view === "audit") return auditView();
  if (state.view === "access") return accessView();
  if (state.view === "remote") return remoteAccessView();
  if (state.view === "settings") return settingsView();
  return dashboardView();
}

function dashboardView() {
  const complete = state.analysis?.completed_entry_count || 0;
  const total = state.analysis?.entry_count || 0;
  const completion = total ? Math.round((complete / total) * 100) : 0;
  return `
    <section class="metrics-grid">
      ${metric("Participants", state.analysis?.participant_count || 0, "Enrolled or screening records")}
      ${metric("CRF Entries", total, `${completion}% complete`)}
      ${metric("Open Queries", state.analysis?.open_query_count || 0, "Needs review")}
      ${metric("Quality Issues", state.quality?.length || 0, "Edit checks and missing CRFs")}
    </section>
    ${state.readiness ? readinessPanel(state.readiness) : ""}
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

function readinessPanel(readiness) {
  const visibleItems = readiness.items.filter((item) => item.status !== "pass").slice(0, 5);
  const shown = visibleItems.length ? visibleItems : readiness.items.slice(0, 4);
  return `
    <section class="panel">
      <div class="row">
        <div>
          <h2>Study Readiness</h2>
          <p>${readiness.status === "ready" ? "Core launch and review controls look ready." : readiness.status === "needs_review" ? "Some items need review before formal use or export." : "Resolve blockers before real study use."}</p>
        </div>
        <span class="readiness-score ${readiness.status}">${readiness.score}%</span>
      </div>
      <div class="readiness-list">
        ${shown.map((item) => `
          <div class="readiness-item">
            <span class="pill ${item.status === "pass" ? "ok" : item.status === "warn" ? "warn" : "bad"}">${item.status}</span>
            <div>
              <strong>${escapeHtml(item.label)}</strong>
              <p>${escapeHtml(item.detail)}</p>
              ${item.status === "pass" ? "" : `<span class="small">${escapeHtml(item.action)}</span>`}
            </div>
          </div>
        `).join("")}
      </div>
    </section>
  `;
}

function metric(label, value, hint) {
  return `<div class="card metric"><span class="small">${label}</span><strong>${value}</strong><span>${escapeHtml(hint)}</span></div>`;
}

function remoteAccessView() {
  const origin = window.location.origin;
  const lanUrl = origin.includes("127.0.0.1") || origin.includes("localhost")
    ? "Use the Wi-Fi URL printed by start.ps1, for example http://192.168.x.x:8765"
    : origin;
  return `
    <section class="panel">
      <div class="row">
        <div>
          <h2>Remote Access</h2>
          <p>Use one central running app for real study data so audit trails, locks, backups, and user permissions remain consistent.</p>
        </div>
        <span class="pill ${state.online ? "ok" : "bad"}">${state.online ? "online" : "offline"}</span>
      </div>
      <div class="remote-grid">
        <div class="remote-option recommended">
          <span class="pill ok">easiest free</span>
          <h3>One Remote Link</h3>
          <p>Run <code>.\\start_easy_remote.ps1</code>. Share the printed <code>https://*.trycloudflare.com</code> link with approved users.</p>
          <span class="small">No phone app install is needed. Keep the PowerShell window open during data entry.</span>
        </div>
        <div class="remote-option">
          <span class="pill ok">same Wi-Fi</span>
          <h3>LAN</h3>
          <p>Run <code>.\\start.ps1</code> on the study computer. Phones and other computers open the printed Wi-Fi address.</p>
          <code>${escapeHtml(lanUrl)}</code>
        </div>
        <div class="remote-option">
          <span class="pill ok">private remote</span>
          <h3>VPN Overlay</h3>
          <p>Use a private network tool such as Tailscale or ZeroTier. Install it on the study computer and approved devices, then open the study computer's private VPN address with port 8765.</p>
          <span class="small">Best balance for small teams without public internet exposure.</span>
        </div>
        <div class="remote-option">
          <span class="pill warn">public access</span>
          <h3>HTTPS Tunnel</h3>
          <p>Use Cloudflare Tunnel only with identity access controls, strong app passwords, backups, and audit review. This exposes the app beyond your LAN.</p>
          <span class="small">Use only after your study approves remote access risk.</span>
        </div>
        <div class="remote-option">
          <span class="pill bad">not suitable</span>
          <h3>Google Drive / GitHub Pages</h3>
          <p>They can store files or static pages, but they cannot run this Python app or safely manage the live SQLite clinical database.</p>
          <span class="small">Use Google Drive only for encrypted backup copies. Use GitHub only for source code, never PHI or live trial data.</span>
        </div>
      </div>
    </section>
    <section class="panel">
      <h2>Remote Setup Checklist</h2>
      <div class="readiness-list">
        ${[
          "Change default admin password and create named users.",
          "Use HTTPS/VPN for access outside the trusted Wi-Fi.",
          "Keep the study computer powered on, backed up, and physically protected.",
          "Create encrypted backups and test restore before real data entry.",
          "Record remote access approval in the validation package."
        ].map((item) => `<div class="readiness-item"><span class="pill warn">check</span><div><strong>${escapeHtml(item)}</strong></div></div>`).join("")}
      </div>
    </section>
    <section class="panel">
      <h2>Best Free Route</h2>
      <div class="readiness-list">
        ${[
          "Run .\\start_easy_remote.ps1 on the study computer.",
          "Copy the https://*.trycloudflare.com URL printed in PowerShell.",
          "Send that URL only to approved users.",
          "Keep PowerShell open until data entry is finished.",
          "Use one named account per person; never share the admin account.",
          "Create an encrypted backup after each data-entry session."
        ].map((item) => `<div class="readiness-item"><span class="pill ok">free</span><div><strong>${escapeHtml(item)}</strong></div></div>`).join("")}
      </div>
    </section>
  `;
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
        ${state.groups.length ? `<label>Data access group<select name="data_group_id"><option value="">Unassigned</option>${state.groups.map((group) => `<option value="${group.id}">${escapeHtml(group.name)}</option>`).join("")}</select></label>` : ""}
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
  const selectedEvent = state.events.find((event) => event.id === state.selectedEventId) || state.events[0];
  const mappedFormIds = state.formEvents.filter((item) => item.event_id === selectedEvent?.id).map((item) => item.form_id);
  const visibleForms = mappedFormIds.length ? state.forms.filter((form) => mappedFormIds.includes(form.id)) : state.forms;
  const entryCards = selected ? visibleForms.map((form) => entryCard(selected, form, selectedEvent)).join("") : "<p>Add a participant first.</p>";
  return `
    <section class="panel">
      <h2>Data Entry</h2>
      <div class="form-grid">
        <label>
          Participant
          <select id="participant-picker">
            ${state.participants.map((item) => `<option value="${item.id}" ${selected?.id === item.id ? "selected" : ""}>${escapeHtml(item.study_uid)} ${escapeHtml(item.initials)}</option>`).join("")}
          </select>
        </label>
        <label>
          Event / visit
          <select id="event-picker">
            ${state.events.map((event) => `<option value="${event.id}" ${selectedEvent?.id === event.id ? "selected" : ""}>${escapeHtml(event.name)} (${escapeHtml(event.arm_name)})</option>`).join("")}
          </select>
        </label>
      </div>
    </section>
    <section class="grid two">${entryCards}</section>
  `;
}

function entryCard(participant, form, selectedEvent) {
  const existing = state.entries.find((entry) => entry.participant_id === participant.id && entry.form_id === form.id && (entry.event_id === selectedEvent?.id || (!entry.event_id && entry.event_name === (selectedEvent?.code || "Baseline")))) || { data: {}, status: "draft", event_name: selectedEvent?.code || "Baseline", event_id: selectedEvent?.id || null, repeat_instance: 1 };
  const locked = Boolean(existing.locked_at);
  return `
    <form class="card stack entry-form" data-form-id="${form.id}" data-participant-id="${participant.id}">
      <div class="row">
        <div>
          <h3>${escapeHtml(form.name)}</h3>
          <span class="pill ${existing.status === "complete" ? "ok" : "warn"}">${escapeHtml(existing.status)}</span>
          ${locked ? `<span class="pill ok">locked</span>` : ""}
        </div>
        <label>Event<input name="event_name" value="${escapeHtml(selectedEvent?.name || existing.event_name || "Baseline")}" readonly /></label>
      </div>
      <input type="hidden" name="event_id" value="${escapeHtml(selectedEvent?.id || "")}" />
      <label>Repeat instance<input name="repeat_instance" type="number" min="1" value="${escapeHtml(existing.repeat_instance || 1)}" ${form.schema.repeatable ? "" : "readonly"} /></label>
      ${form.schema.fields.map((field) => fieldInput(field, existing.data)).join("")}
      <label>Status
        <select name="status">
          <option value="draft" ${existing.status === "draft" ? "selected" : ""}>draft</option>
          <option value="complete" ${existing.status === "complete" ? "selected" : ""}>complete</option>
        </select>
      </label>
      ${locked ? `<label>Change reason required for locked CRF<input name="change_reason" placeholder="Reason for updating locked data" /></label>` : ""}
      ${existing.id && can("review_data") ? `
        <div class="form-grid">
          <label>Field review
            <select name="review_field_code">
              ${form.schema.fields.map((field) => `<option value="${field.code}">${escapeHtml(field.label)}</option>`).join("")}
            </select>
          </label>
          <label>Reason<input name="field_state_reason" placeholder="Review note" /></label>
        </div>
      ` : ""}
      <div class="split-actions">
        <button>Save CRF</button>
        <button type="button" class="secondary" data-query-form="${form.id}" data-query-participant="${participant.id}">Open Query</button>
        ${existing.id && !locked ? `<button type="button" class="secondary" data-lock-entry="${existing.id}">Lock</button>` : ""}
        ${existing.id && locked ? `<button type="button" class="warning" data-unlock-entry="${existing.id}">Unlock</button>` : ""}
        ${existing.id && can("review_data") ? `<button type="button" class="secondary" data-entry-history="${existing.id}">History</button><button type="button" class="secondary" data-verify-field="${existing.id}">Verify Field</button><button type="button" class="secondary" data-freeze-field="${existing.id}">Freeze Field</button>` : ""}
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
  if (field.type === "checkbox") {
    const selected = Array.isArray(value) ? value : [];
    return `<fieldset ${visibility}><legend>${escapeHtml(field.label)}</legend>${(field.options || []).map((option) => `<label class="check"><input type="checkbox" name="${escapeHtml(field.code)}" value="${escapeHtml(option)}" ${selected.includes(option) ? "checked" : ""} />${escapeHtml(option)}</label>`).join("")}</fieldset>`;
  }
  if (field.type === "calc") {
    return `<label ${visibility}>${escapeHtml(field.label)}<input name="${escapeHtml(field.code)}" value="${escapeHtml(value)}" readonly placeholder="${escapeHtml(field.calculation || "Calculated on save")}" /></label>`;
  }
  if (field.type === "file") {
    const fileName = value?.name ? `<span class="small">Current file: ${escapeHtml(value.name)} (${Math.round((value.size || 0) / 1024)} KB)</span>` : "";
    return `<label ${visibility}>${escapeHtml(field.label)}<input name="${escapeHtml(field.code)}" type="file" ${required} />${fileName}</label>`;
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
  const editing = state.forms.find((form) => form.id === state.editingFormId);
  return `
    <section class="panel">
      <h2>${editing ? "Edit CRF" : "CRF Builder"}</h2>
      <form id="form-builder" class="stack">
        <div class="form-grid">
          <label>Form name<input name="name" required placeholder="Laboratory Results" value="${escapeHtml(editing?.name || "")}" /></label>
          <label>Code<input name="code" required placeholder="labs" value="${escapeHtml(editing?.code || "")}" /></label>
          <label>Repeatable
            <select name="repeatable">
              <option value="false" ${editing?.schema?.repeatable ? "" : "selected"}>No</option>
              <option value="true" ${editing?.schema?.repeatable ? "selected" : ""}>Yes</option>
            </select>
          </label>
          <fieldset class="full">
            <legend>Assign to events</legend>
            ${state.events.map((event) => `<label class="check"><input type="checkbox" name="event_ids" value="${event.id}" ${event.code === "baseline" ? "checked" : ""} />${escapeHtml(event.name)}</label>`).join("")}
          </fieldset>
        </div>
        <div id="fields" class="stack">
          ${(editing?.schema?.fields?.length ? editing.schema.fields : [null]).map((field) => fieldEditorRow(field)).join("")}
        </div>
        <div class="split-actions">
          <button type="button" class="secondary" id="add-field">Add Field</button>
          <button>${editing ? "Save Versioned Edit" : "Create CRF"}</button>
          ${editing ? `<button type="button" class="secondary" id="cancel-form-edit">Cancel Edit</button>` : ""}
        </div>
      </form>
    </section>
    <section class="panel">
      <h2>Existing CRFs</h2>
      <div class="grid two">
        ${state.forms.map((form) => `
          <article class="card">
            <h3>${escapeHtml(form.name)}</h3>
            <p>${escapeHtml(form.code)} - v${form.version} - ${form.schema.fields.length} fields${form.schema.repeatable ? " - repeatable" : ""}</p>
            <div class="stack">
              ${form.schema.fields.map((field) => `<span class="pill">${escapeHtml(field.label)} (${escapeHtml(field.type)})</span>`).join("")}
            </div>
            <div class="split-actions">
              <button class="secondary" data-edit-form="${form.id}">Edit</button>
              <button class="secondary" data-form-versions="${form.id}">Versions</button>
            </div>
          </article>
        `).join("")}
      </div>
    </section>
  `;
}

function dictionaryView() {
  return `
    <section class="panel">
      <h2>Data Dictionary Import</h2>
      <p>Paste a CSV exported from Codebook or matching its headers. Existing instruments with the same code are updated with a saved previous version.</p>
      <form id="dictionary-form" class="stack">
        <label>Dictionary CSV<textarea name="csv" required placeholder="instrument_name,instrument_label,events,field_order,field_name,field_label,field_type,required,choices,validation_min,validation_max,branching_logic,calculation,repeatable"></textarea></label>
        <button>Import Dictionary</button>
      </form>
    </section>
    <section class="panel">
      <h2>Record CSV Import</h2>
      <p>Paste exported or similarly structured data with study_uid, form_code or form_name, event_code, repeat_instance, and field columns.</p>
      <form id="record-import-form" class="stack">
        <label>Record CSV<textarea name="csv" required placeholder="study_uid,initials,participant_status,event_code,form_code,entry_status,repeat_instance,demographics__age"></textarea></label>
        <button>Import Records</button>
      </form>
    </section>
    <section class="panel">
      <h2>AI-Assisted CRF Draft</h2>
      <p>This assistant turns de-identified CRF item text into draft fields. It stays local by default; external AI is used only when explicitly enabled on the server.</p>
      <form id="assist-crf-form" class="stack">
        <label>CRF text<textarea name="text" required placeholder="Age&#10;Visit date&#10;Any adverse event?"></textarea></label>
        <button>Draft Schema</button>
      </form>
      ${state.assistDraft ? `
        <div class="notice">
          Drafted ${state.assistDraft.assistant.field_count} field(s) using ${escapeHtml(state.assistDraft.assistant.mode)} mode.
          ${state.assistDraft.assistant.warnings.length ? escapeHtml(state.assistDraft.assistant.warnings.join(" ")) : escapeHtml(state.assistDraft.assistant.safety_note)}
        </div>
        <label>Reviewed Draft JSON<textarea readonly>${escapeHtml(JSON.stringify(state.assistDraft.schema, null, 2))}</textarea></label>
      ` : ""}
    </section>
  `;
}

function eventsView() {
  return `
    <section class="grid two">
      <section class="panel">
        <h2>Create Event</h2>
        <form id="event-form" class="stack">
          <label>Name<input name="name" required placeholder="Month 1 Visit" /></label>
          <label>Code<input name="code" placeholder="month_1" /></label>
          <label>Arm<input name="arm_name" value="Default" /></label>
          <label>Day offset<input name="day_offset" type="number" value="0" /></label>
          <button>Create Event</button>
        </form>
      </section>
      <section class="panel">
        <h2>Map CRF To Event</h2>
        <form id="form-event-form" class="stack">
          <label>Event
            <select name="event_id">
              ${state.events.map((event) => `<option value="${event.id}">${escapeHtml(event.name)}</option>`).join("")}
            </select>
          </label>
          <label>CRF
            <select name="form_id">
              ${state.forms.map((form) => `<option value="${form.id}">${escapeHtml(form.name)}</option>`).join("")}
            </select>
          </label>
          <label>Required
            <select name="required">
              <option value="true">Yes</option>
              <option value="false">No</option>
            </select>
          </label>
          <button>Save Mapping</button>
        </form>
      </section>
    </section>
    <section class="panel">
      <h2>Schedule</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Event</th><th>Arm</th><th>Day</th><th>CRFs</th></tr></thead>
          <tbody>
            ${state.events.map((event) => {
              const mapped = state.formEvents.filter((item) => item.event_id === event.id).map((item) => item.form_name).join(", ");
              return `<tr><td><strong>${escapeHtml(event.name)}</strong><br><span class="small">${escapeHtml(event.code)}</span></td><td>${escapeHtml(event.arm_name)}</td><td>${event.day_offset}</td><td>${escapeHtml(mapped || "No CRFs mapped")}</td></tr>`;
            }).join("")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function surveysView() {
  const origin = window.location.origin;
  return `
    <section class="panel">
      <h2>Create Public Survey Link</h2>
      <form id="survey-link-form" class="form-grid">
        <label>Title<input name="title" required placeholder="Baseline Intake Survey" /></label>
        <label>CRF
          <select name="form_id" required>
            ${state.forms.map((form) => `<option value="${form.id}">${escapeHtml(form.name)}</option>`).join("")}
          </select>
        </label>
        <label>Event
          <select name="event_id">
            <option value="">Baseline/default</option>
            ${state.events.map((event) => `<option value="${event.id}">${escapeHtml(event.name)}</option>`).join("")}
          </select>
        </label>
        <label>Consent required
          <select name="consent_required">
            <option value="false">No</option>
            <option value="true">Yes</option>
          </select>
        </label>
        <label class="full">Consent text<textarea name="consent_text" placeholder="I confirm that I have read the study information and agree to submit this form."></textarea></label>
        <div class="full"><button>Create Survey Link</button></div>
      </form>
    </section>
    <section class="panel">
      <h2>Create Invitation</h2>
      <form id="invitation-form" class="form-grid">
        <label>Survey
          <select name="survey_link_id" required>
            ${state.surveyLinks.map((survey) => `<option value="${survey.id}">${escapeHtml(survey.title)}</option>`).join("")}
          </select>
        </label>
        <label>Contact<input name="contact" required placeholder="phone, email, or coordinator note" /></label>
        <label>Participant
          <select name="participant_id">
            <option value="">Unassigned</option>
            ${state.participants.map((participant) => `<option value="${participant.id}">${escapeHtml(participant.study_uid)}</option>`).join("")}
          </select>
        </label>
        <div><button ${state.surveyLinks.length ? "" : "disabled"}>Create Invitation</button></div>
      </form>
    </section>
    <section class="panel">
      <h2>Invitation Tracker</h2>
      ${state.invitations.length ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>Survey</th><th>Contact</th><th>Status</th><th>Last Sent</th><th>Link</th><th></th></tr></thead>
            <tbody>
              ${state.invitations.map((invitation) => {
                const survey = state.surveyLinks.find((item) => item.id === invitation.survey_link_id);
                const link = survey ? `${origin}/survey.html?token=${encodeURIComponent(survey.token)}&invite=${encodeURIComponent(invitation.invite_token)}` : "";
                return `
                  <tr>
                    <td>${escapeHtml(invitation.survey_title || "")}<br><span class="small">${escapeHtml(invitation.study_uid || "Unassigned")}</span></td>
                    <td>${escapeHtml(invitation.contact)}</td>
                    <td><span class="pill ${invitation.status === "completed" ? "ok" : invitation.status === "cancelled" ? "bad" : "warn"}">${escapeHtml(invitation.status)}</span><br><span class="small">${invitation.reminder_count || 0} sent/reminder action(s)</span></td>
                    <td>${fmtTime(invitation.last_sent_at)}</td>
                    <td>${link ? `<a href="${link}" target="_blank">Open</a>` : ""}</td>
                    <td>
                      <button class="secondary" data-invitation-action="mark_sent" data-invitation-id="${invitation.id}">Sent</button>
                      <button class="secondary" data-invitation-action="mark_completed" data-invitation-id="${invitation.id}">Complete</button>
                      <button class="warning" data-invitation-action="cancel" data-invitation-id="${invitation.id}">Cancel</button>
                    </td>
                  </tr>
                `;
              }).join("")}
            </tbody>
          </table>
        </div>
      ` : "<p>No invitations yet.</p>"}
    </section>
    <section class="panel">
      <h2>Active Survey Links</h2>
      ${state.surveyLinks.length ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>Title</th><th>CRF</th><th>Event</th><th>Consent</th><th>Link</th></tr></thead>
            <tbody>
              ${state.surveyLinks.map((survey) => {
                const link = `${origin}/survey.html?token=${encodeURIComponent(survey.token)}`;
                return `
                  <tr>
                    <td><strong>${escapeHtml(survey.title)}</strong><br><span class="pill ${survey.enabled ? "ok" : "bad"}">${survey.enabled ? "enabled" : "disabled"}</span></td>
                    <td>${escapeHtml(survey.form_name)}</td>
                    <td>${escapeHtml(survey.event_name || "Baseline")}</td>
                    <td>${survey.consent_required ? "Required" : "No"}</td>
                    <td><a href="${link}" target="_blank">${escapeHtml(link)}</a></td>
                  </tr>
                `;
              }).join("")}
            </tbody>
          </table>
        </div>
      ` : "<p>No survey links yet.</p>"}
    </section>
  `;
}

function fieldEditorRow(field = null) {
  return `
    <div class="field-editor">
      <label>Label<input name="field_label" required placeholder="Systolic BP" value="${escapeHtml(field?.label || "")}" /></label>
      <label>Code<input name="field_code" required placeholder="systolic_bp" value="${escapeHtml(field?.code || "")}" /></label>
      <label>Type
        <select name="field_type">
          ${["text", "number", "date", "select", "checkbox", "textarea", "calc", "file"].map((type) => `<option value="${type}" ${field?.type === type ? "selected" : ""}>${type}</option>`).join("")}
        </select>
      </label>
      <label>Required<select name="field_required"><option value="false" ${field?.required ? "" : "selected"}>No</option><option value="true" ${field?.required ? "selected" : ""}>Yes</option></select></label>
      <button type="button" class="secondary icon" data-remove-field title="Remove">X</button>
      <label class="full">Options for select or checkbox fields<input name="field_options" placeholder="No, Yes" value="${escapeHtml((field?.options || []).join(", "))}" /></label>
      <label>Min<input name="field_min" type="number" step="any" value="${escapeHtml(field?.min ?? "")}" /></label>
      <label>Max<input name="field_max" type="number" step="any" value="${escapeHtml(field?.max ?? "")}" /></label>
      <label class="full">Calculation<input name="field_calculation" placeholder="age + 10" value="${escapeHtml(field?.calculation || "")}" /></label>
      <label>Show if field<input name="field_show_if_field" placeholder="adverse_event" value="${escapeHtml(field?.show_if?.field || "")}" /></label>
      <label>Equals<input name="field_show_if_equals" placeholder="Yes" value="${escapeHtml(field?.show_if?.equals || "")}" /></label>
    </div>
  `;
}

function randomizationView() {
  const lists = state.randomization?.lists || [];
  const allocations = state.randomization?.allocations || [];
  return `
    <section class="grid two">
      <section class="panel">
        <h2>Create Randomization List</h2>
        ${can("manage_study") ? `
          <form id="randomization-list-form" class="stack">
            <label>Name<input name="name" required placeholder="Main 1:1 allocation" /></label>
            <label>Arms<input name="arms" required placeholder="Control, Treatment" /></label>
            <button>Create List</button>
          </form>
        ` : "<p>Study management permission required.</p>"}
      </section>
      <section class="panel">
        <h2>Allocate Participant</h2>
        <form id="randomization-allocate-form" class="stack">
          <label>List
            <select name="list_id" required>
              ${lists.map((item) => `<option value="${item.id}">${escapeHtml(item.name)}</option>`).join("")}
            </select>
          </label>
          <label>Participant
            <select name="participant_id" required>
              ${state.participants.map((participant) => `<option value="${participant.id}">${escapeHtml(participant.study_uid)}</option>`).join("")}
            </select>
          </label>
          <button ${lists.length && state.participants.length ? "" : "disabled"}>Allocate</button>
        </form>
      </section>
    </section>
    <section class="panel">
      <h2>Allocations</h2>
      ${allocations.length ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>Participant</th><th>List</th><th>Arm</th><th>Time</th></tr></thead>
            <tbody>
              ${allocations.map((item) => `<tr><td>${escapeHtml(item.study_uid)}</td><td>${escapeHtml(item.list_name)}</td><td><span class="pill ok">${escapeHtml(item.arm)}</span></td><td>${fmtTime(item.created_at)}</td></tr>`).join("")}
            </tbody>
          </table>
        </div>
      ` : "<p>No allocations yet.</p>"}
    </section>
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
                  <td>
                    <span class="small">${(query.responses || []).length} response(s)</span>
                    <button class="secondary" data-respond-query="${query.id}">Respond</button>
                    ${query.status === "open" ? `<button class="secondary" data-close-query="${query.id}">Close</button>` : ""}
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      ` : "<p>No queries.</p>"}
    </section>
  `;
}

function qualityView() {
  return `
    <section class="panel">
      <h2>Data Quality</h2>
      ${state.quality.length ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>Severity</th><th>Participant</th><th>Form</th><th>Event</th><th>Field</th><th>Issue</th></tr></thead>
            <tbody>
              ${state.quality.map((issue) => `
                <tr>
                  <td><span class="pill ${issue.severity === "error" ? "bad" : "warn"}">${escapeHtml(issue.severity)}</span></td>
                  <td>${escapeHtml(issue.study_uid || "")}</td>
                  <td>${escapeHtml(issue.form_name || "")}</td>
                  <td>${escapeHtml(issue.event_name || "")} #${escapeHtml(issue.repeat_instance || 1)}</td>
                  <td>${escapeHtml(issue.field_code || "")}</td>
                  <td>${escapeHtml(issue.message)}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      ` : "<p>No quality issues found.</p>"}
    </section>
  `;
}

function caseIntakeView() {
  const cases = state.caseIntake?.cases || [];
  const series = state.caseIntake?.series || { case_count: 0, group_count: 0, groups: [], missing_field_count: 0, warning_count: 0, draft_outline: [], adaptive_fields: [] };
  const ai = state.caseIntake?.ai || { provider: "local", external_ai_enabled: false, multimodal_enabled: false, model: "local-rules" };
  const review = state.caseAiReview?.response;
  return `
    <section class="metrics-grid">
      ${metric("Cases", series.case_count || 0, "Unstructured case records")}
      ${metric("Groups", series.group_count || 0, "Diagnosis/treatment clusters")}
      ${metric("Missing Items", series.missing_field_count || 0, "Publication fields to complete")}
      ${metric("Warnings", series.warning_count || 0, "De-identification or data issues")}
    </section>
    <section class="panel">
      <h2>Capture Case Evidence</h2>
      <p>Store typed notes, dictated text, photos, audio, PDFs, or scanned case details before a final CRF is ready. Keep identifiers minimal and review extracted fields before publication.</p>
      <form id="case-intake-form" class="stack">
        <div class="form-grid">
          <label>Case ID<input name="case_uid" placeholder="CASE-001" /></label>
          <label>Title<input name="title" required placeholder="Oseltamivir dose adjustment case" /></label>
          <label>Link participant
            <select name="participant_id">
              <option value="">Not linked yet</option>
              ${state.participants.map((item) => `<option value="${item.id}">${escapeHtml(item.study_uid)} ${escapeHtml(item.initials || "")}</option>`).join("")}
            </select>
          </label>
          <label>Status
            <select name="status">
              <option value="draft">draft</option>
              <option value="triaged">triaged</option>
              <option value="ready">ready</option>
              <option value="excluded">excluded</option>
            </select>
          </label>
        </div>
        <label>Typed notes / OCR text / dictated transcript<textarea name="source_text" id="case-source-text" placeholder="Paste case details, Google Lens text, discharge summary notes, or dictate using the button below."></textarea></label>
        <div class="split-actions">
          <button type="button" class="secondary" id="case-dictate">Start Dictation</button>
          <span class="small">Dictation works only in browsers that support speech recognition. Uploaded audio is stored as evidence; local transcription is not automatic.</span>
        </div>
        <label>Evidence files<input name="files" type="file" multiple accept="image/*,audio/*,.pdf,.txt,.csv" /></label>
        <button>Save And Organize Case</button>
      </form>
    </section>
    <section class="panel">
      <h2>Academic AI Review</h2>
      <div class="grid two">
        <div class="notice">
          AI mode: ${escapeHtml(ai.provider)} / ${escapeHtml(ai.model)}. ${ai.external_ai_enabled ? "External AI enabled." : "Local fallback active."} ${ai.multimodal_enabled ? "Image/audio review enabled." : "Image/audio stays local unless multimodal is enabled."}
        </div>
        <label>Question for AI<textarea id="case-ai-question" placeholder="Ask about publication potential, missing variables, evolving CRF sections, or manuscript angle."></textarea></label>
      </div>
      ${review ? `
        <div class="grid two">
          <div class="notice"><strong>Summary</strong><br>${escapeHtml(review.case_summary || "")}</div>
          <div class="notice"><strong>Publication</strong><br>${escapeHtml(review.publication_guidance?.suggested_article_type || "")}: ${escapeHtml(review.publication_guidance?.rationale || "")}</div>
        </div>
        <div class="readiness-list">
          ${(review.publication_guidance?.missing_items || []).map((item) => `<div class="readiness-item"><span class="pill warn">missing</span><div><strong>${escapeHtml(item)}</strong></div></div>`).join("")}
          ${(review.publication_guidance?.literature_search_terms || []).map((item) => `<div class="readiness-item"><span class="pill ok">search</span><div><strong>${escapeHtml(item)}</strong></div></div>`).join("")}
        </div>
        <label>AI Review JSON<textarea readonly>${escapeHtml(JSON.stringify(review, null, 2))}</textarea></label>
      ` : ""}
    </section>
    <section class="panel">
      <div class="row">
        <h2>Case Series Builder</h2>
        <button class="secondary" id="case-export">Export Case CSV</button>
      </div>
      <div class="grid two">
        <div class="notice">${escapeHtml((series.draft_outline || []).join(" "))}</div>
        <div class="notice">Group similar cases by extracted diagnosis/treatment, then complete missing age, sex, presentation, investigation, treatment, outcome, and follow-up items before writing.</div>
      </div>
      <div class="readiness-list">
        ${(series.groups || []).map((group) => `
          <div class="readiness-item">
            <span class="pill ok">${group.count}</span>
            <div><strong>${escapeHtml(group.group)}</strong><p>${escapeHtml((group.case_uids || []).join(", "))}</p><span class="small">${escapeHtml((group.tags || []).join(", "))}</span></div>
          </div>
        `).join("") || "<p>No case groups yet.</p>"}
      </div>
      <h3>Adaptive Draft CRF Fields</h3>
      <div class="stack">
        ${(series.adaptive_fields || []).map((field) => `<span class="pill">${escapeHtml(field.label)} (${escapeHtml(field.type)})</span>`).join("") || "<span class=\"small\">No adaptive fields yet.</span>"}
      </div>
    </section>
    <section class="panel">
      <h2>Case Library</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Case</th><th>Group</th><th>Extracted Details</th><th>Files</th><th>Academic AI</th><th>Status</th></tr></thead>
          <tbody>
            ${cases.map((item) => {
              const extracted = item.extracted || {};
              const clinical = extracted.clinical || {};
              const demographics = extracted.demographics || {};
              const latestReview = item.latest_ai_review?.response;
              return `
                <tr>
                  <td><strong>${escapeHtml(item.case_uid)}</strong><br><span class="small">${escapeHtml(item.title)}</span></td>
                  <td>${escapeHtml(extracted.group_label || "Ungrouped case")}<br><span class="small">${escapeHtml((item.tags || []).join(", "))}</span></td>
                  <td>
                    <strong>${escapeHtml([demographics.age ? `${demographics.age}y` : "", demographics.sex || ""].filter(Boolean).join(" / "))}</strong><br>
                    Dx: ${escapeHtml(clinical.diagnosis || "needs review")}<br>
                    Tx: ${escapeHtml(clinical.treatment || "needs review")}<br>
                    Outcome: ${escapeHtml(clinical.outcome || "needs review")}
                    ${extracted.missing_fields?.length ? `<br><span class="small">Missing: ${escapeHtml(extracted.missing_fields.join(", "))}</span>` : ""}
                    ${extracted.warnings?.length ? `<br><span class="small">${escapeHtml(extracted.warnings.join(" "))}</span>` : ""}
                  </td>
                  <td>
                    ${(item.files || []).map((file) => `<button type="button" class="secondary" data-case-id="${item.id}" data-case-file="${file.id}" data-case-file-name="${escapeHtml(file.name)}">${escapeHtml(file.name)}</button>`).join(" ") || "None"}
                  </td>
                  <td>
                    <button type="button" class="secondary" data-case-ai="${item.id}">AI Review</button>
                    ${latestReview ? `<br><span class="small">${escapeHtml(latestReview.publication_guidance?.suggested_article_type || latestReview.publication_guidance?.case_report_potential || "reviewed")}</span>` : ""}
                  </td>
                  <td><span class="pill">${escapeHtml(item.status)}</span><br><span class="small">${fmtTime(item.updated_at)}</span></td>
                </tr>
              `;
            }).join("") || `<tr><td colspan="6">No cases captured yet.</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function analysisView() {
  const summaries = state.analysis?.field_summaries || [];
  const assistant = state.assistantSummary;
  return `
    <section class="grid three">
      ${metric("Participants", state.analysis?.participant_count || 0, "Study records")}
      ${metric("Completed CRFs", state.analysis?.completed_entry_count || 0, "Marked complete")}
      ${metric("Open Queries", state.analysis?.open_query_count || 0, "Data issues")}
    </section>
    <section class="panel">
      <h2>Assistant Review</h2>
      ${assistant ? `
        <div class="grid two">
          <div class="notice">${escapeHtml((assistant.warnings || []).join(" "))}</div>
          <div class="notice">${escapeHtml((assistant.next_steps || []).join(" "))}</div>
        </div>
      ` : "<p>No assistant summary available.</p>"}
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

function reportsView() {
  return `
    <section class="panel">
      <h2>Create Report</h2>
      ${can("export_data") ? `
        <form id="report-form" class="form-grid">
          <label>Name<input name="name" required placeholder="Completed Baseline CRFs" /></label>
          <label>Description<input name="description" placeholder="Optional report note" /></label>
          <label>Participant status
            <select name="participant_status">
              <option value="">Any</option>
              <option value="screening">screening</option>
              <option value="enrolled">enrolled</option>
              <option value="completed">completed</option>
              <option value="withdrawn">withdrawn</option>
            </select>
          </label>
          <label>Entry status
            <select name="entry_status">
              <option value="">Any</option>
              <option value="draft">draft</option>
              <option value="complete">complete</option>
            </select>
          </label>
          <label>Event
            <select name="event_id">
              <option value="">Any</option>
              ${state.events.map((event) => `<option value="${event.id}">${escapeHtml(event.name)}</option>`).join("")}
            </select>
          </label>
          <label>CRF
            <select name="form_id">
              <option value="">Any</option>
              ${state.forms.map((form) => `<option value="${form.id}">${escapeHtml(form.name)}</option>`).join("")}
            </select>
          </label>
          <div class="full"><button>Save Report</button></div>
        </form>
      ` : "<p>Your role can view reports but cannot create exportable reports.</p>"}
    </section>
    <section class="panel">
      <h2>Saved Reports</h2>
      <div class="split-actions">
        <a href="/api/studies/${state.studyId}/odm" target="_blank"><button class="secondary">ODM XML</button></a>
        ${["r", "sas", "spss", "stata"].map((type) => `<a href="/api/studies/${state.studyId}/stats-package?type=${type}" target="_blank"><button class="secondary">${type.toUpperCase()} Package</button></a>`).join("")}
      </div>
      ${state.reports.length ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>Name</th><th>Filters</th><th>Created By</th><th></th></tr></thead>
            <tbody>
              ${state.reports.map((report) => `
                <tr>
                  <td><strong>${escapeHtml(report.name)}</strong><br><span class="small">${escapeHtml(report.description || "")}</span></td>
                  <td>${escapeHtml(reportFilterText(report.filters || {}))}</td>
                  <td>${escapeHtml(report.created_by_name || "")}</td>
                  <td>${can("export_data") ? `<a href="/api/studies/${state.studyId}/reports/${report.id}/export" target="_blank"><button class="secondary">Export</button></a>` : ""}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      ` : "<p>No saved reports.</p>"}
    </section>
  `;
}

function academicView() {
  const academic = state.academic || { metrics: {}, opportunities: [], cv_items: [], guidance: [] };
  const metrics = academic.metrics || {};
  const opportunities = academic.opportunities || [];
  const cvItems = academic.cv_items || [];
  return `
    <section class="metrics-grid">
      ${metric("Captured Cases", metrics.case_count || 0, "Messy evidence organized")}
      ${metric("Opportunities", metrics.opportunity_count || 0, "Case report/series leads")}
      ${metric("CV Items", metrics.cv_item_count || 0, "Academic outputs tracked")}
      ${metric("AI Reviews", metrics.ai_review_count || 0, "Audited academic AI reviews")}
    </section>
    <section class="panel">
      <div class="row">
        <div>
          <h2>Academic Workbench</h2>
          <p>Turn unstructured cases into publication leads, track academic output, and export a CV-ready portfolio.</p>
        </div>
        <div class="split-actions">
          <button class="secondary" id="academic-export-md">Export Portfolio</button>
          <button class="secondary" id="academic-export-csv">Export CV CSV</button>
        </div>
      </div>
      <div class="grid two">
        <div class="notice">AI mode: ${escapeHtml(academic.ai?.provider || "local")} / ${escapeHtml(academic.ai?.model || "local-rules")}. ${academic.ai?.external_ai_enabled ? "External OpenAI enabled." : "External AI off or local fallback active."}</div>
        <div class="notice">${escapeHtml((academic.guidance || []).join(" "))}</div>
      </div>
    </section>
    <section class="panel">
      <h2>Publication Opportunities</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Topic</th><th>Type</th><th>Potential</th><th>Cases</th><th>Next Actions</th></tr></thead>
          <tbody>
            ${opportunities.map((item) => `
              <tr>
                <td><strong>${escapeHtml(item.group)}</strong><br><span class="small">${escapeHtml(item.rationale)}</span></td>
                <td>${escapeHtml(item.suggested_article_type)}</td>
                <td><span class="pill ${item.publication_potential === "high" ? "ok" : item.publication_potential === "moderate" ? "warn" : ""}">${escapeHtml(item.publication_potential)}</span></td>
                <td>${escapeHtml((item.case_uids || []).join(", "))}</td>
                <td>
                  ${(item.next_actions || []).slice(0, 3).map((action) => `<div class="small">${escapeHtml(action)}</div>`).join("")}
                  ${(item.missing_items || []).length ? `<div class="small">Missing: ${escapeHtml(item.missing_items.join(", "))}</div>` : ""}
                  ${(item.literature_search_terms || []).length ? `<div class="small">Search: ${escapeHtml(item.literature_search_terms.join(", "))}</div>` : ""}
                </td>
              </tr>
            `).join("") || `<tr><td colspan="5">Add cases in Case Intake to generate publication opportunities.</td></tr>`}
          </tbody>
        </table>
      </div>
    </section>
    <section class="panel">
      <h2>Add CV / Publication Item</h2>
      <form id="academic-cv-form" class="form-grid">
        <label>Type
          <select name="item_type">
            ${["publication", "case_report", "case_series", "abstract", "poster", "presentation", "audit", "protocol", "dataset", "grant", "award", "teaching"].map((value) => `<option value="${value}">${escapeHtml(value.replaceAll("_", " "))}</option>`).join("")}
          </select>
        </label>
        <label>Title<input name="title" required placeholder="Oseltamivir case series abstract" /></label>
        <label>Your role<input name="role" placeholder="First author / corresponding author / presenter" /></label>
        <label>Status
          <select name="status">
            ${["planned", "drafting", "submitted", "accepted", "published", "presented", "completed"].map((value) => `<option value="${value}">${escapeHtml(value)}</option>`).join("")}
          </select>
        </label>
        <label>Date<input name="item_date" type="date" /></label>
        <label>Linked case
          <select name="linked_case_id">
            <option value="">Not linked</option>
            ${(state.caseIntake?.cases || []).map((item) => `<option value="${item.id}">${escapeHtml(item.case_uid)} - ${escapeHtml(item.title)}</option>`).join("")}
          </select>
        </label>
        <label class="full">Citation / conference / journal<textarea name="citation" placeholder="Journal, conference, DOI, PMID, or citation text"></textarea></label>
        <label class="full">Notes<textarea name="notes" placeholder="Action items, co-authors, ethics status, target journal, reviewer comments"></textarea></label>
        <div class="full"><button>Save CV Item</button></div>
      </form>
    </section>
    <section class="panel">
      <h2>CV Timeline</h2>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Item</th><th>Role</th><th>Status</th><th>Date</th><th>Linked Case</th><th>Notes</th></tr></thead>
          <tbody>
            ${cvItems.map((item) => `
              <tr>
                <td><strong>${escapeHtml(item.title)}</strong><br><span class="small">${escapeHtml(item.item_type)}</span>${item.citation ? `<br><span class="small">${escapeHtml(item.citation)}</span>` : ""}</td>
                <td>${escapeHtml(item.role || "")}</td>
                <td><span class="pill">${escapeHtml(item.status)}</span></td>
                <td>${escapeHtml(item.item_date || "")}</td>
                <td>${escapeHtml(item.linked_case_uid || "")}</td>
                <td>${escapeHtml(item.notes || "")}<br><span class="small">${escapeHtml(item.updated_by_name || "")} ${fmtTime(item.updated_at)}</span></td>
              </tr>
            `).join("") || `<tr><td colspan="6">No CV items yet.</td></tr>`}
          </tbody>
        </table>
      </div>
      <label>Portfolio Markdown<textarea readonly>${escapeHtml(academic.cv_markdown || "")}</textarea></label>
    </section>
  `;
}

function reportFilterText(filters) {
  const parts = [];
  if (filters.participant_status) parts.push(`participant: ${filters.participant_status}`);
  if (filters.entry_status) parts.push(`entry: ${filters.entry_status}`);
  if (filters.event_id) parts.push(`event id: ${filters.event_id}`);
  if (filters.form_id) parts.push(`form id: ${filters.form_id}`);
  return parts.length ? parts.join(", ") : "No filters";
}

function backupsView() {
  return `
    <section class="panel">
      <div class="row">
        <h2>Backups</h2>
        <button id="backup-create">Create Backup</button>
      </div>
      <p>Backups are local SQLite snapshots stored under the app data folder. Keep copies on an encrypted external drive for real studies.</p>
      <form id="encrypted-backup-form" class="form-grid">
        <label>Archive passphrase<input name="passphrase" type="password" minlength="12" placeholder="12+ characters" /></label>
        <div><button class="secondary">Create Encrypted Archive</button></div>
      </form>
      ${state.backups.length ? `
        <div class="table-wrap">
          <table>
            <thead><tr><th>File</th><th>Size</th><th>Created</th><th></th></tr></thead>
            <tbody>
              ${state.backups.map((backup) => `
                <tr>
                  <td>${escapeHtml(backup.name)} ${backup.encrypted ? `<span class="pill ok">encrypted</span>` : ""}</td>
                  <td>${Math.round(backup.size / 1024)} KB</td>
                  <td>${fmtTime(backup.created_at)}</td>
                  <td>
                    <a href="/api/studies/${state.studyId}/backups/${encodeURIComponent(backup.name)}" target="_blank"><button class="secondary">Download</button></a>
                    <button class="warning" data-restore-backup="${escapeHtml(backup.name)}" data-encrypted="${backup.encrypted ? "true" : "false"}">Restore</button>
                  </td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      ` : "<p>No backups yet.</p>"}
    </section>
  `;
}

function auditView() {
  return `
    <section class="panel">
      <div class="row">
        <h2>Audit Trail</h2>
        <a href="/api/studies/${state.studyId}/audit-export" target="_blank"><button class="secondary">Export CSV</button></a>
      </div>
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

function accessView() {
  const roleOptions = ["project_admin", "pi", "data_entry", "reviewer", "analyst", "viewer"];
  const globalRoleOptions = ["super_admin", "data_entry", "reviewer", "analyst", "viewer"];
  const scopeOptions = ["metadata:read", "records:read", "records:write", "export:read", "randomization:write", "ai:use"];
  return `
    <section class="grid two">
      <section class="panel">
        <h2>Create User</h2>
        ${isSuperAdmin() ? `
          <form id="user-form" class="stack">
            <label>Username<input name="username" required placeholder="coordinator1" /></label>
            <label>Display name<input name="display_name" required placeholder="Coordinator One" /></label>
            <label>Temporary password<input name="password" type="password" minlength="10" required /></label>
            <label>Global role
              <select name="role">
                ${globalRoleOptions.map((role) => `<option value="${role}">${role}</option>`).join("")}
              </select>
            </label>
            <button>Create User</button>
          </form>
        ` : "<p>Only the global admin can create new users.</p>"}
      </section>
      <section class="panel">
        <h2>Data Access Groups</h2>
        <form id="group-form" class="stack">
          <label>Group name<input name="name" required placeholder="Site A" /></label>
          <label>Code<input name="code" placeholder="site_a" /></label>
          <button>Create Group</button>
        </form>
      </section>
    </section>
    <section class="panel">
      <h2>Project Access</h2>
      <form id="membership-form" class="form-grid">
        <label>User
          <select name="user_id" required>
            ${state.users.map((user) => `<option value="${user.id}">${escapeHtml(user.username)} - ${escapeHtml(user.display_name)}</option>`).join("")}
          </select>
        </label>
        <label>Project role
          <select name="role">
            ${roleOptions.map((role) => `<option value="${role}">${role}</option>`).join("")}
          </select>
        </label>
        <label>Data access group
          <select name="data_group_id">
            <option value="">All groups</option>
            ${state.groups.map((group) => `<option value="${group.id}">${escapeHtml(group.name)}</option>`).join("")}
          </select>
        </label>
        <label>Active
          <select name="active">
            <option value="true">Yes</option>
            <option value="false">No</option>
          </select>
        </label>
        <div class="full"><button>Save Access</button></div>
      </form>
      <div class="table-wrap">
        <table>
          <thead><tr><th>User</th><th>Role</th><th>Group</th><th>Active</th></tr></thead>
          <tbody>
            ${state.studyMembers.map((item) => `
              <tr>
                <td>${escapeHtml(item.username)}<br><span class="small">${escapeHtml(item.display_name)}</span></td>
                <td><span class="pill">${escapeHtml(item.role)}</span></td>
                <td>${escapeHtml(item.data_group_name || "All groups")}</td>
                <td>${item.active ? "Yes" : "No"}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </section>
    <section class="panel">
      <h2>API Tokens</h2>
      <form id="api-token-form" class="form-grid">
        <label>User
          <select name="user_id" required>
            ${state.users.map((user) => `<option value="${user.id}">${escapeHtml(user.username)}</option>`).join("")}
          </select>
        </label>
        <label>Label<input name="label" required placeholder="Analysis script token" /></label>
        <label class="full">Scopes
          <select name="scopes" multiple size="6">
            ${scopeOptions.map((scope) => `<option value="${scope}" selected>${scope}</option>`).join("")}
          </select>
        </label>
        <div class="full"><button>Create API Token</button></div>
      </form>
      <p class="small">The token is shown once after creation. Use endpoint /api/redcap with token, content, action, and format parameters.</p>
      <div class="table-wrap">
        <table>
          <thead><tr><th>Label</th><th>User</th><th>Scopes</th><th>Active</th><th>Last Used</th><th></th></tr></thead>
          <tbody>
            ${state.apiTokens.map((item) => `
              <tr>
                <td>${escapeHtml(item.label)}</td>
                <td>${escapeHtml(item.username)}</td>
                <td><span class="small">${escapeHtml((item.scopes || []).join(", "))}</span></td>
                <td>${item.active ? "Yes" : "No"}</td>
                <td>${fmtTime(item.last_used_at)}</td>
                <td>${item.active ? `<button class="secondary" data-revoke-token="${item.id}">Revoke</button>` : ""}</td>
              </tr>
            `).join("")}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function settingsView() {
  const health = state.adminStatus?.health;
  return `
    ${isSuperAdmin() ? `
    <section class="panel">
      <h2>System Status</h2>
      <div class="grid three">
        <div><span class="small">App</span><strong>${health?.ok ? "Running" : "Needs review"}</strong></div>
        <div><span class="small">Mode</span><strong>${escapeHtml(health?.environment || "development")}</strong></div>
        <div><span class="small">Database</span><strong>${escapeHtml(health?.database_backend || "")}</strong></div>
        <div><span class="small">HTTPS</span><strong>${health?.https_detected ? "Detected" : "Not detected"}</strong></div>
        <div><span class="small">AI</span><strong>${health?.ai?.external_ai_enabled ? "External enabled" : "Local/off"}</strong></div>
        <div><span class="small">Latest backup</span><strong>${fmtTime(health?.backup?.latest_backup_at)}</strong></div>
      </div>
      <div class="split-actions">
        <button class="secondary" id="admin-backup">Create System Backup</button>
        <button class="secondary" id="refresh-admin">Refresh Status</button>
      </div>
    </section>
    <section class="panel">
      <h2>Deployment</h2>
      <p class="small">Version ${escapeHtml(health?.version || "0.1")} · Commit ${escapeHtml(health?.commit || "unknown")} · Logs at ${escapeHtml(state.adminStatus?.logs?.path || "")}</p>
      <pre class="log-view">${escapeHtml((state.adminLogs || []).slice(-80).join("\\n"))}</pre>
    </section>
    ` : ""}
    ${isSuperAdmin() ? `<section class="panel">` : `<section class="panel hidden">`}
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
      ${state.studyId && (can("review_data") || can("manage_study")) ? `
        <div class="split-actions">
          <a href="/api/studies/${state.studyId}/validation" target="_blank"><button class="secondary">Validation Evidence JSON</button></a>
          <a href="/api/studies/${state.studyId}/validation-package" target="_blank"><button class="secondary">Validation Package ZIP</button></a>
        </div>
      ` : ""}
    </section>
    <section class="panel">
      <h2>Change Password</h2>
      <form id="password-form" class="form-grid">
        <label>Current password<input name="current_password" type="password" required /></label>
        <label>New password<input name="new_password" type="password" minlength="10" required /></label>
        <div class="full"><button>Update Password</button></div>
      </form>
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
  document.querySelector("#install-app")?.addEventListener("click", async () => {
    const prompt = state.installPrompt;
    if (!prompt) return;
    prompt.prompt();
    await prompt.userChoice.catch(() => null);
    state.installPrompt = null;
    render();
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
  document.querySelector("#export-csv")?.addEventListener("click", () => downloadApi(`/api/studies/${state.studyId}/export${currentMembership()?.role === "analyst" ? "?deidentified=1" : ""}`, "clinical_data_export.csv"));
  document.querySelector("#export-codebook")?.addEventListener("click", () => downloadApi(`/api/studies/${state.studyId}/codebook`, "clinical_data_codebook.csv"));
}

function bindRoute() {
  document.querySelector("#participant-form")?.addEventListener("submit", submitParticipant);
  document.querySelector("#study-form")?.addEventListener("submit", submitStudy);
  document.querySelector("#password-form")?.addEventListener("submit", submitPassword);
  document.querySelector("#admin-backup")?.addEventListener("click", createSystemBackup);
  document.querySelector("#refresh-admin")?.addEventListener("click", async () => {
    await loadStudy();
    render();
  });
  document.querySelector("#user-form")?.addEventListener("submit", submitUser);
  document.querySelector("#group-form")?.addEventListener("submit", submitGroup);
  document.querySelector("#membership-form")?.addEventListener("submit", submitMembership);
  document.querySelector("#api-token-form")?.addEventListener("submit", submitApiToken);
  document.querySelectorAll("[data-revoke-token]").forEach((button) => button.addEventListener("click", () => revokeApiToken(button.dataset.revokeToken)));
  document.querySelector("#event-form")?.addEventListener("submit", submitEvent);
  document.querySelector("#form-event-form")?.addEventListener("submit", submitFormEvent);
  document.querySelector("#randomization-list-form")?.addEventListener("submit", submitRandomizationList);
  document.querySelector("#randomization-allocate-form")?.addEventListener("submit", submitRandomizationAllocation);
  document.querySelector("#survey-link-form")?.addEventListener("submit", submitSurveyLink);
  document.querySelector("#invitation-form")?.addEventListener("submit", submitInvitation);
  document.querySelectorAll("[data-invitation-action]").forEach((button) => button.addEventListener("click", () => updateInvitation(button.dataset.invitationId, button.dataset.invitationAction)));
  document.querySelector("#report-form")?.addEventListener("submit", submitReport);
  document.querySelector("#academic-cv-form")?.addEventListener("submit", submitAcademicCvItem);
  document.querySelector("#academic-export-md")?.addEventListener("click", () => downloadApi(`/api/studies/${state.studyId}/academic/export?format=md`, "academic_portfolio.md"));
  document.querySelector("#academic-export-csv")?.addEventListener("click", () => downloadApi(`/api/studies/${state.studyId}/academic/export?format=csv`, "academic_cv_tracker.csv"));
  document.querySelector("#case-intake-form")?.addEventListener("submit", submitCaseIntake);
  document.querySelector("#case-dictate")?.addEventListener("click", startCaseDictation);
  document.querySelector("#case-export")?.addEventListener("click", () => downloadApi(`/api/studies/${state.studyId}/case-intake/export`, "case_intake_export.csv"));
  document.querySelectorAll("[data-case-file]").forEach((button) => {
    button.addEventListener("click", () => downloadApi(`/api/studies/${state.studyId}/case-intake/${button.dataset.caseId}/files/${button.dataset.caseFile}`, button.dataset.caseFileName || "case_evidence"));
  });
  document.querySelectorAll("[data-case-ai]").forEach((button) => {
    button.addEventListener("click", () => requestCaseAiReview(button.dataset.caseAi));
  });
  document.querySelector("#backup-create")?.addEventListener("click", createBackup);
  document.querySelector("#encrypted-backup-form")?.addEventListener("submit", createEncryptedBackup);
  document.querySelectorAll("[data-restore-backup]").forEach((button) => button.addEventListener("click", () => restoreBackup(button.dataset.restoreBackup, button.dataset.encrypted === "true")));
  document.querySelector("#form-builder")?.addEventListener("submit", submitFormDefinition);
  document.querySelector("#dictionary-form")?.addEventListener("submit", submitDictionary);
  document.querySelector("#record-import-form")?.addEventListener("submit", submitRecordImport);
  document.querySelector("#assist-crf-form")?.addEventListener("submit", submitAssistCrf);
  document.querySelector("#add-field")?.addEventListener("click", () => {
    document.querySelector("#fields").insertAdjacentHTML("beforeend", fieldEditorRow());
  });
  document.querySelector("#cancel-form-edit")?.addEventListener("click", () => {
    state.editingFormId = 0;
    render();
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
  document.querySelector("#event-picker")?.addEventListener("change", (event) => {
    state.selectedEventId = Number(event.target.value);
    localStorage.setItem("cds_event_id", String(state.selectedEventId || ""));
    render();
  });
  document.querySelectorAll(".entry-form").forEach((form) => {
    form.addEventListener("submit", submitEntry);
    form.addEventListener("input", () => applyBranching(form));
    applyBranching(form);
  });
  document.querySelectorAll("[data-query-form]").forEach((button) => button.addEventListener("click", openQuery));
  document.querySelectorAll("[data-close-query]").forEach((button) => button.addEventListener("click", () => closeQuery(button.dataset.closeQuery)));
  document.querySelectorAll("[data-respond-query]").forEach((button) => button.addEventListener("click", () => respondQuery(button.dataset.respondQuery)));
  document.querySelectorAll("[data-lock-entry]").forEach((button) => button.addEventListener("click", () => lockEntry(button.dataset.lockEntry)));
  document.querySelectorAll("[data-unlock-entry]").forEach((button) => button.addEventListener("click", () => unlockEntry(button.dataset.unlockEntry)));
  document.querySelectorAll("[data-entry-history]").forEach((button) => button.addEventListener("click", () => showEntryHistory(button.dataset.entryHistory)));
  document.querySelectorAll("[data-verify-field]").forEach((button) => button.addEventListener("click", () => setFieldState(button, "verify_field")));
  document.querySelectorAll("[data-freeze-field]").forEach((button) => button.addEventListener("click", () => setFieldState(button, "freeze_field")));
  document.querySelectorAll("[data-edit-form]").forEach((button) => button.addEventListener("click", () => {
    state.editingFormId = Number(button.dataset.editForm);
    render();
  }));
  document.querySelectorAll("[data-form-versions]").forEach((button) => button.addEventListener("click", () => showFormVersions(button.dataset.formVersions)));
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

async function submitPassword(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api("/api/password", { method: "POST", body: JSON.stringify(data) });
    state.error = "Password updated.";
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function createSystemBackup() {
  try {
    await api("/api/admin/backup", { method: "POST", body: "{}" });
    await loadStudy();
    state.error = "System backup created.";
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitUser(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api("/api/users", { method: "POST", body: JSON.stringify(data) });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitGroup(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api(`/api/studies/${state.studyId}/groups`, { method: "POST", body: JSON.stringify(data) });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitMembership(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api(`/api/studies/${state.studyId}/memberships`, {
      method: "POST",
      body: JSON.stringify({
        user_id: Number(data.user_id),
        role: data.role,
        data_group_id: data.data_group_id ? Number(data.data_group_id) : null,
        active: data.active === "true",
      }),
    });
    const me = await api("/api/me");
    state.memberships = me.memberships || [];
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitApiToken(event) {
  event.preventDefault();
  const formData = new FormData(event.target);
  const data = Object.fromEntries(formData);
  try {
    const result = await api(`/api/studies/${state.studyId}/api-tokens`, {
      method: "POST",
      body: JSON.stringify({ user_id: Number(data.user_id), label: data.label, scopes: formData.getAll("scopes") }),
    });
    alert(`API token. Store it now, it will not be shown again:\\n${result.token}`);
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function revokeApiToken(tokenId) {
  if (!confirm("Revoke this API token? Scripts using it will stop working.")) return;
  try {
    await api(`/api/studies/${state.studyId}/api-tokens/${tokenId}`, {
      method: "PATCH",
      body: JSON.stringify({ active: false }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitEvent(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api(`/api/studies/${state.studyId}/events`, {
      method: "POST",
      body: JSON.stringify({ ...data, day_offset: Number(data.day_offset || 0) }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitRandomizationList(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api(`/api/studies/${state.studyId}/randomization`, {
      method: "POST",
      body: JSON.stringify({ name: data.name, arms: data.arms }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitRandomizationAllocation(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    const result = await api(`/api/studies/${state.studyId}/randomization/${data.list_id}/allocate`, {
      method: "POST",
      body: JSON.stringify({ participant_id: Number(data.participant_id) }),
    });
    state.error = `Allocated to ${result.allocation.arm}.`;
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitFormEvent(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api(`/api/studies/${state.studyId}/form-events`, {
      method: "POST",
      body: JSON.stringify({
        event_id: Number(data.event_id),
        form_id: Number(data.form_id),
        required: data.required === "true",
      }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

function fileToPayload(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onerror = () => reject(new Error("Could not read file"));
    reader.onload = () => {
      const dataUrl = String(reader.result || "");
      resolve({ name: file.name, type: file.type || "application/octet-stream", size: file.size, data: dataUrl.split(",", 2)[1] || "" });
    };
    reader.readAsDataURL(file);
  });
}

async function submitSurveyLink(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api(`/api/studies/${state.studyId}/surveys`, {
      method: "POST",
      body: JSON.stringify({
        title: data.title,
        form_id: Number(data.form_id),
        event_id: data.event_id ? Number(data.event_id) : null,
        consent_required: data.consent_required === "true",
        consent_text: data.consent_text || "",
      }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitInvitation(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api(`/api/studies/${state.studyId}/invitations`, {
      method: "POST",
      body: JSON.stringify({
        survey_link_id: Number(data.survey_link_id),
        participant_id: data.participant_id ? Number(data.participant_id) : null,
        contact: data.contact,
      }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function updateInvitation(id, action) {
  try {
    await api(`/api/studies/${state.studyId}/invitations/${id}`, {
      method: "PATCH",
      body: JSON.stringify({ action }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitReport(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  const filters = {};
  ["participant_status", "entry_status", "event_id", "form_id"].forEach((key) => {
    if (data[key]) filters[key] = key.endsWith("_id") ? Number(data[key]) : data[key];
  });
  try {
    await api(`/api/studies/${state.studyId}/reports`, {
      method: "POST",
      body: JSON.stringify({ name: data.name, description: data.description || "", filters }),
    });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitAcademicCvItem(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api(`/api/studies/${state.studyId}/academic/cv-items`, {
      method: "POST",
      body: JSON.stringify({
        item_type: data.item_type,
        title: data.title,
        role: data.role || "",
        status: data.status,
        item_date: data.item_date || "",
        citation: data.citation || "",
        notes: data.notes || "",
        linked_case_id: data.linked_case_id ? Number(data.linked_case_id) : null,
      }),
    });
    event.target.reset();
    state.error = "Academic CV item saved.";
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitCaseIntake(event) {
  event.preventDefault();
  const form = event.target;
  const data = Object.fromEntries(new FormData(form));
  const files = await Promise.all([...form.querySelector(`[name="files"]`).files].map(fileToPayload));
  try {
    const result = await api(`/api/studies/${state.studyId}/case-intake`, {
      method: "POST",
      body: JSON.stringify({
        case_uid: data.case_uid,
        title: data.title,
        participant_id: data.participant_id ? Number(data.participant_id) : null,
        status: data.status,
        source_text: data.source_text || "",
        files,
      }),
    });
    state.error = `Case saved and grouped as ${result.case.extracted?.group_label || "Ungrouped case"}.`;
    form.reset();
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

function startCaseDictation() {
  const SpeechRecognition = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SpeechRecognition) {
    state.error = "This browser does not support built-in dictation. Record audio as a file or type/paste the transcript.";
    render();
    return;
  }
  const target = document.querySelector("#case-source-text");
  const recognition = new SpeechRecognition();
  recognition.continuous = true;
  recognition.interimResults = false;
  recognition.lang = navigator.language || "en-US";
  recognition.onresult = (event) => {
    const text = [...event.results].map((result) => result[0]?.transcript || "").join(" ").trim();
    target.value = `${target.value ? `${target.value}\n` : ""}${text}`.trim();
  };
  recognition.onerror = () => {
    state.error = "Dictation stopped or permission was denied. You can still type or upload the audio file.";
    render();
  };
  recognition.start();
}

async function requestCaseAiReview(caseId) {
  const question = document.querySelector("#case-ai-question")?.value || "";
  try {
    const result = await api(`/api/studies/${state.studyId}/case-intake/${caseId}/ai-review`, {
      method: "POST",
      body: JSON.stringify({ question }),
    });
    state.caseAiReview = result.review;
    state.error = `Academic AI review created using ${result.review.mode} mode.`;
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function downloadApi(path, filename) {
  try {
    const response = await fetch(path, { headers: { Authorization: `Bearer ${state.token}` } });
    if (!response.ok) {
      const payload = await response.json().catch(() => ({ error: response.statusText }));
      throw new Error(payload.error || response.statusText);
    }
    const blob = await response.blob();
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    URL.revokeObjectURL(url);
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function createBackup() {
  try {
    await api(`/api/studies/${state.studyId}/backups`, { method: "POST", body: "{}" });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function createEncryptedBackup(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    await api(`/api/studies/${state.studyId}/backups`, { method: "POST", body: JSON.stringify({ passphrase: data.passphrase }) });
    event.target.reset();
    await loadStudy();
    render();
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
    if ((field.type === "select" || field.type === "checkbox") && options) field.options = options.split(",").map((item) => item.trim()).filter(Boolean);
    const min = get("field_min");
    const max = get("field_max");
    if (min !== "") field.min = Number(min);
    if (max !== "") field.max = Number(max);
    const calculation = get("field_calculation");
    if (calculation) field.calculation = calculation;
    const showIfField = get("field_show_if_field");
    const showIfEquals = get("field_show_if_equals");
    if (showIfField && showIfEquals) field.show_if = { field: showIfField, equals: showIfEquals };
    return field;
  });
  try {
    const eventIds = [...event.target.querySelectorAll(`[name="event_ids"]:checked`)].map((item) => Number(item.value));
    const path = state.editingFormId ? `/api/studies/${state.studyId}/forms/${state.editingFormId}` : `/api/studies/${state.studyId}/forms`;
    await api(path, {
      method: state.editingFormId ? "PATCH" : "POST",
      body: JSON.stringify({ name: formData.get("name"), code: formData.get("code"), event_ids: eventIds, schema: { fields, repeatable: formData.get("repeatable") === "true" } }),
    });
    state.editingFormId = 0;
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function restoreBackup(name, encrypted = false) {
  if (!confirm(`Restore backup ${name}? Current database will be replaced by this backup.`)) return;
  const passphrase = encrypted ? prompt("Encrypted archive passphrase") : "";
  if (encrypted && !passphrase) return;
  try {
    await api(`/api/studies/${state.studyId}/backups/${encodeURIComponent(name)}/restore`, { method: "POST", body: JSON.stringify({ passphrase }) });
    await loadAll();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitDictionary(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    const result = await api(`/api/studies/${state.studyId}/dictionary`, {
      method: "POST",
      body: JSON.stringify({ csv: data.csv }),
    });
    state.error = `Imported ${result.imported.length} instrument(s).`;
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitRecordImport(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    const result = await api(`/api/studies/${state.studyId}/records/import`, {
      method: "POST",
      body: JSON.stringify({ csv: data.csv }),
    });
    const imported = result.imported || {};
    const errorText = imported.errors?.length ? ` ${imported.errors.length} row(s) need review.` : "";
    state.error = `Imported ${imported.entries_created || 0} new and ${imported.entries_updated || 0} updated CRF entrie(s).${errorText}`;
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function submitAssistCrf(event) {
  event.preventDefault();
  const data = Object.fromEntries(new FormData(event.target));
  try {
    const result = await api("/api/assist/crf", {
      method: "POST",
      body: JSON.stringify({ text: data.text }),
    });
    state.assistDraft = result;
    state.error = "Draft created. Review the JSON before importing or saving as a CRF.";
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function showEntryHistory(entryId) {
  try {
    const result = await api(`/api/studies/${state.studyId}/entries/${entryId}/history`);
    const history = (result.history || []).map((item) => `${fmtTime(item.created_at)} ${item.display_name || "System"} ${item.action}`).join("\\n");
    const states = (result.field_states || []).map((item) => `${fmtTime(item.created_at)} ${item.field_code}: ${item.state} ${item.reason || ""}`).join("\\n");
    alert([history || "No entry history found.", states ? `\\nField states:\\n${states}` : ""].join("\\n"));
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function showFormVersions(formId) {
  try {
    const result = await api(`/api/studies/${state.studyId}/forms/${formId}/versions`);
    const lines = result.versions.map((item) => `v${item.version} saved ${fmtTime(item.saved_at)}`).join("\\n");
    alert(lines || "No prior versions saved.");
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
  for (const field of formDef.schema.fields) {
    if (!form.querySelector(`[name="${field.code}"]`)?.closest(".hidden")) {
      if (field.type === "checkbox") {
        data[field.code] = [...form.querySelectorAll(`[name="${field.code}"]:checked`)].map((item) => item.value);
      } else if (field.type === "file") {
        const file = form.querySelector(`[name="${field.code}"]`)?.files?.[0];
        if (file) {
          data[field.code] = await fileToPayload(file);
        } else {
          const existing = state.entries.find((entry) => entry.participant_id === Number(form.dataset.participantId) && entry.form_id === Number(form.dataset.formId));
          data[field.code] = existing?.data?.[field.code] || "";
        }
      } else {
        data[field.code] = payload[field.code] || "";
      }
    }
  }
  try {
    await api(`/api/studies/${state.studyId}/entries`, {
      method: "POST",
      body: JSON.stringify({
        participant_id: Number(form.dataset.participantId),
        form_id: Number(form.dataset.formId),
        event_id: payload.event_id ? Number(payload.event_id) : null,
        event_name: payload.event_name || "Baseline",
        repeat_instance: Number(payload.repeat_instance || 1),
        status: payload.status || "draft",
        change_reason: payload.change_reason || "",
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

async function lockEntry(id) {
  const reason = prompt("Lock reason") || "Reviewed and locked";
  try {
    await api(`/api/studies/${state.studyId}/entries/${id}`, { method: "PATCH", body: JSON.stringify({ action: "lock", reason }) });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function unlockEntry(id) {
  const reason = prompt("Unlock reason");
  if (!reason) return;
  try {
    await api(`/api/studies/${state.studyId}/entries/${id}`, { method: "PATCH", body: JSON.stringify({ action: "unlock", reason }) });
    await loadStudy();
    render();
  } catch (error) {
    state.error = error.message;
    render();
  }
}

async function setFieldState(button, action) {
  const form = button.closest("form");
  const fieldCode = form?.elements.review_field_code?.value;
  const reason = form?.elements.field_state_reason?.value || "";
  if (!fieldCode) return;
  try {
    await api(`/api/studies/${state.studyId}/entries/${button.dataset.verifyField || button.dataset.freezeField}`, {
      method: "PATCH",
      body: JSON.stringify({ action, field_code: fieldCode, reason }),
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

async function respondQuery(id) {
  const message = prompt("Query response");
  if (!message) return;
  try {
    await api(`/api/studies/${state.studyId}/queries/${id}/responses`, {
      method: "POST",
      body: JSON.stringify({ message }),
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
        <label>Username<input name="username" autocomplete="username" required /></label>
        <label>Password<input name="password" type="password" autocomplete="current-password" required /></label>
        <button>Login</button>
        <p class="small">Use the named account provided by your study administrator.</p>
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
      if (state.user?.must_change_password) return renderPasswordChangeRequired();
      await loadAll();
    } catch (error) {
      state.error = error.message;
      renderLogin();
    }
  });
}

function renderPasswordChangeRequired() {
  app.innerHTML = `
    <section class="login">
      <form id="forced-password-form" class="login-card stack">
        <div>
          <h1>Change Password</h1>
          <p>Your administrator requires a new password before using clinical data screens.</p>
        </div>
        ${state.error ? `<div class="notice error">${escapeHtml(state.error)}</div>` : ""}
        <label>Current password<input name="current_password" type="password" autocomplete="current-password" required /></label>
        <label>New password<input name="new_password" type="password" minlength="10" autocomplete="new-password" required /></label>
        <button>Update Password</button>
        <button type="button" class="secondary" id="forced-logout">Logout</button>
      </form>
    </section>
  `;
  document.querySelector("#forced-password-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.target));
    try {
      await api("/api/password", { method: "POST", body: JSON.stringify(data) });
      state.error = "";
      state.user.must_change_password = 0;
      await loadAll();
    } catch (error) {
      state.error = error.message;
      renderPasswordChangeRequired();
    }
  });
  document.querySelector("#forced-logout").addEventListener("click", async () => {
    await api("/api/logout", { method: "POST", body: "{}" }).catch(() => {});
    state.token = "";
    state.user = null;
    localStorage.removeItem("cds_token");
    renderLogin();
  });
}

function renderSetup() {
  app.innerHTML = `
    <section class="login">
      <form id="setup-form" class="login-card stack">
        <div>
          <h1>First Run Setup</h1>
          <p>Create the permanent administrator account before entering research data.</p>
        </div>
        ${state.error ? `<div class="notice error">${escapeHtml(state.error)}</div>` : ""}
        <label>Admin username<input name="username" placeholder="admin" autocomplete="username" required /></label>
        <label>Display name<input name="display_name" placeholder="Study Administrator" required /></label>
        <label>New password<input name="password" type="password" minlength="12" autocomplete="new-password" required /></label>
        <label>Confirm password<input name="confirm_password" type="password" minlength="12" autocomplete="new-password" required /></label>
        <button>Secure App</button>
      </form>
    </section>
  `;
  document.querySelector("#setup-form").addEventListener("submit", async (event) => {
    event.preventDefault();
    const data = Object.fromEntries(new FormData(event.target));
    try {
      await api("/api/setup", { method: "POST", body: JSON.stringify(data) });
      state.setupRequired = false;
      state.error = "Setup complete. Log in with the new administrator password.";
      renderLogin();
    } catch (error) {
      state.error = error.message;
      renderSetup();
    }
  });
}

function updateOnlineState() {
  state.online = navigator.onLine;
  if (state.user || state.setupRequired) render();
}

window.addEventListener("online", updateOnlineState);
window.addEventListener("offline", updateOnlineState);
window.addEventListener("beforeinstallprompt", (event) => {
  event.preventDefault();
  state.installPrompt = event;
  if (state.user) render();
});
window.addEventListener("appinstalled", () => {
  state.installPrompt = null;
  state.standalone = true;
  if (state.user) render();
});

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/service-worker.js").catch(() => {});
  });
}

loadAll();
