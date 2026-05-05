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
  events: [],
  formEvents: [],
  reports: [],
  backups: [],
  forms: [],
  participants: [],
  entries: [],
  queries: [],
  quality: [],
  audit: [],
  analysis: null,
  assistantSummary: null,
  view: "dashboard",
  selectedParticipantId: 0,
  selectedEventId: Number(localStorage.getItem("cds_event_id") || 0),
  editingFormId: 0,
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
  const setup = await api("/api/setup").catch(() => ({ required: false }));
  state.setupRequired = Boolean(setup.required);
  if (state.setupRequired) return renderSetup();
  if (!state.token) return renderLogin();
  try {
    const me = await api("/api/me");
    state.user = me.user;
    state.memberships = me.memberships || [];
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
  const [forms, events, formEvents, reports, backups, participants, entries, queries, quality, analysis, assistantSummary, audit, groups, studyMembers, users] = await Promise.all([
    api(`/api/studies/${state.studyId}/forms`),
    api(`/api/studies/${state.studyId}/events`),
    api(`/api/studies/${state.studyId}/form-events`),
    viewAnalysis ? api(`/api/studies/${state.studyId}/reports`) : Promise.resolve({ reports: [] }),
    can("manage_study") ? api(`/api/studies/${state.studyId}/backups`) : Promise.resolve({ backups: [] }),
    api(`/api/studies/${state.studyId}/participants`),
    api(`/api/studies/${state.studyId}/entries`),
    api(`/api/studies/${state.studyId}/queries`),
    api(`/api/studies/${state.studyId}/quality`),
    viewAnalysis ? api(`/api/studies/${state.studyId}/analysis`) : Promise.resolve({ participant_count: 0, entry_count: 0, completed_entry_count: 0, open_query_count: 0, field_summaries: [] }),
    viewAnalysis ? api(`/api/studies/${state.studyId}/assist/summary`) : Promise.resolve({ summary: null }),
    can("review_data") ? api(`/api/studies/${state.studyId}/audit`) : Promise.resolve({ audit: [] }),
    api(`/api/studies/${state.studyId}/groups`),
    manageUsers ? api(`/api/studies/${state.studyId}/memberships`) : Promise.resolve({ memberships: [] }),
    state.user?.role === "admin" ? api("/api/users") : Promise.resolve({ users: [] }),
  ]);
  state.forms = forms.forms;
  state.events = events.events;
  state.formEvents = formEvents.form_events;
  state.reports = reports.reports;
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
  state.audit = audit.audit;
  state.groups = groups.groups;
  state.studyMembers = studyMembers.memberships;
  state.users = users.users;
}

function currentMembership() {
  if (state.user?.role === "admin") return { role: "owner", data_group_id: null };
  return state.memberships.find((item) => item.study_id === state.studyId) || null;
}

function can(permission) {
  const role = currentMembership()?.role || "";
  const permissions = {
    admin: ["manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis"],
    owner: ["manage_users", "manage_study", "manage_forms", "enter_data", "review_data", "export_data", "view_analysis"],
    data_entry: ["enter_data"],
    reviewer: ["review_data", "view_analysis"],
    analyst: ["export_data", "view_analysis"],
    read_only: ["view_analysis"],
  };
  return (permissions[role] || []).includes(permission);
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
          ${can("manage_forms") ? navButton("dictionary", "Dictionary") : ""}
          ${can("manage_study") ? navButton("events", "Events") : ""}
          ${navButton("queries", "Review Queries")}
          ${navButton("quality", "Data Quality")}
          ${navButton("analysis", "Analysis")}
          ${can("view_analysis") || can("export_data") ? navButton("reports", "Reports") : ""}
          ${can("manage_study") ? navButton("backups", "Backups") : ""}
          ${navButton("audit", "Audit Trail")}
          ${can("manage_users") ? navButton("access", "Access") : ""}
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
            <a href="/api/studies/${state.studyId}/export" target="_blank"><button class="secondary">Export CSV</button></a>
            <a href="/api/studies/${state.studyId}/codebook" target="_blank"><button class="secondary">Codebook</button></a>
            <button class="secondary" id="logout">Logout</button>
          </div>
        </header>
        <div class="content">
          ${state.user?.must_change_password ? `<div class="notice error">Default password is still active. Change it in Study Setup before real use.</div>` : ""}
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
  if (state.view === "events") return eventsView();
  if (state.view === "queries") return queriesView();
  if (state.view === "quality") return qualityView();
  if (state.view === "analysis") return analysisView();
  if (state.view === "reports") return reportsView();
  if (state.view === "backups") return backupsView();
  if (state.view === "audit") return auditView();
  if (state.view === "access") return accessView();
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
      ${metric("Quality Issues", state.quality?.length || 0, "Edit checks and missing CRFs")}
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
      <p>This local helper turns pasted CRF item text into draft fields. It does not send data outside this app.</p>
      <form id="assist-crf-form" class="stack">
        <label>CRF text<textarea name="text" required placeholder="Age&#10;Visit date&#10;Any adverse event?"></textarea></label>
        <button>Draft Schema</button>
      </form>
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

function fieldEditorRow(field = null) {
  return `
    <div class="field-editor">
      <label>Label<input name="field_label" required placeholder="Systolic BP" value="${escapeHtml(field?.label || "")}" /></label>
      <label>Code<input name="field_code" required placeholder="systolic_bp" value="${escapeHtml(field?.code || "")}" /></label>
      <label>Type
        <select name="field_type">
          ${["text", "number", "date", "select", "checkbox", "textarea", "calc"].map((type) => `<option value="${type}" ${field?.type === type ? "selected" : ""}>${type}</option>`).join("")}
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

function accessView() {
  const roleOptions = ["owner", "data_entry", "reviewer", "analyst", "read_only"];
  return `
    <section class="grid two">
      <section class="panel">
        <h2>Create User</h2>
        ${state.user?.role === "admin" ? `
          <form id="user-form" class="stack">
            <label>Username<input name="username" required placeholder="coordinator1" /></label>
            <label>Display name<input name="display_name" required placeholder="Coordinator One" /></label>
            <label>Temporary password<input name="password" type="password" minlength="8" required /></label>
            <label>Global role
              <select name="role">
                ${roleOptions.map((role) => `<option value="${role}">${role}</option>`).join("")}
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
    <section class="panel">
      <h2>Change Password</h2>
      <form id="password-form" class="form-grid">
        <label>Current password<input name="current_password" type="password" required /></label>
        <label>New password<input name="new_password" type="password" minlength="8" required /></label>
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
  document.querySelector("#password-form")?.addEventListener("submit", submitPassword);
  document.querySelector("#user-form")?.addEventListener("submit", submitUser);
  document.querySelector("#group-form")?.addEventListener("submit", submitGroup);
  document.querySelector("#membership-form")?.addEventListener("submit", submitMembership);
  document.querySelector("#event-form")?.addEventListener("submit", submitEvent);
  document.querySelector("#form-event-form")?.addEventListener("submit", submitFormEvent);
  document.querySelector("#report-form")?.addEventListener("submit", submitReport);
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
    alert(JSON.stringify(result.schema, null, 2));
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
  formDef.schema.fields.forEach((field) => {
    if (!form.querySelector(`[name="${field.code}"]`)?.closest(".hidden")) {
      if (field.type === "checkbox") {
        data[field.code] = [...form.querySelectorAll(`[name="${field.code}"]:checked`)].map((item) => item.value);
      } else {
        data[field.code] = payload[field.code] || "";
      }
    }
  });
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

function renderSetup() {
  app.innerHTML = `
    <section class="login">
      <form id="setup-form" class="login-card stack">
        <div>
          <h1>First Run Setup</h1>
          <p>Create the permanent administrator account before entering research data.</p>
        </div>
        ${state.error ? `<div class="notice error">${escapeHtml(state.error)}</div>` : ""}
        <label>Admin username<input name="username" value="admin" autocomplete="username" required /></label>
        <label>Display name<input name="display_name" value="Administrator" required /></label>
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

loadAll();
