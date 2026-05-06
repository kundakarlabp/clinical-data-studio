const app = document.querySelector("#survey-app");
const params = new URLSearchParams(window.location.search);
const token = params.get("token") || "";
const invitationToken = params.get("invite") || "";
let survey = null;

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;");
}

async function api(path, options = {}) {
  const response = await fetch(path, { ...options, headers: { "Content-Type": "application/json", ...(options.headers || {}) } });
  if (!response.ok) {
    const payload = await response.json().catch(() => ({ error: response.statusText }));
    throw new Error(payload.error || response.statusText);
  }
  return response.json();
}

function fieldInput(field) {
  const required = field.required ? "required" : "";
  const visibility = field.show_if ? `data-show-field="${escapeHtml(field.show_if.field)}" data-show-value="${escapeHtml(field.show_if.equals)}"` : "";
  if (field.type === "textarea") return `<label ${visibility}>${escapeHtml(field.label)}<textarea name="${escapeHtml(field.code)}" ${required}></textarea></label>`;
  if (field.type === "select") return `<label ${visibility}>${escapeHtml(field.label)}<select name="${escapeHtml(field.code)}" ${required}><option value=""></option>${(field.options || []).map((option) => `<option>${escapeHtml(option)}</option>`).join("")}</select></label>`;
  if (field.type === "checkbox") return `<fieldset ${visibility}><legend>${escapeHtml(field.label)}</legend>${(field.options || []).map((option) => `<label class="check"><input type="checkbox" name="${escapeHtml(field.code)}" value="${escapeHtml(option)}" />${escapeHtml(option)}</label>`).join("")}</fieldset>`;
  if (field.type === "file") return `<label ${visibility}>${escapeHtml(field.label)}<input name="${escapeHtml(field.code)}" type="file" ${required} /></label>`;
  const type = field.type === "number" ? "number" : field.type === "date" ? "date" : "text";
  return `<label ${visibility}>${escapeHtml(field.label)}<input name="${escapeHtml(field.code)}" type="${type}" ${required} /></label>`;
}

function applyBranching(form) {
  form.querySelectorAll("[data-show-field]").forEach((label) => {
    const source = form.elements[label.dataset.showField];
    label.classList.toggle("hidden", !(source && source.value === label.dataset.showValue));
  });
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

function render(message = "") {
  if (!token) {
    app.innerHTML = `<section class="login"><div class="login-card"><h1>Survey link missing</h1></div></section>`;
    return;
  }
  if (!survey) {
    app.innerHTML = `<section class="login"><div class="login-card"><h1>Loading survey</h1></div></section>`;
    return;
  }
  app.innerHTML = `
    <section class="login">
      <form id="survey-form" class="login-card stack">
        <div>
          <h1>${escapeHtml(survey.title)}</h1>
          <p>${escapeHtml(survey.study_name)} ${escapeHtml(survey.protocol_id || "")}</p>
        </div>
        ${message ? `<div class="notice">${escapeHtml(message)}</div>` : ""}
        <label>Study ID<input name="study_uid" required /></label>
        <label>Initials<input name="initials" maxlength="6" /></label>
        ${survey.schema.fields.map(fieldInput).join("")}
        ${survey.consent_required ? `
          <fieldset>
            <legend>Consent</legend>
            <p>${escapeHtml(survey.consent_text || "I agree to submit this survey.")}</p>
            <label>Name<input name="signer_name" required /></label>
            <label>Signature<input name="signature_text" required placeholder="Type your full name" /></label>
          </fieldset>
        ` : ""}
        <button>Submit Survey</button>
      </form>
    </section>
  `;
  const form = document.querySelector("#survey-form");
  form.addEventListener("input", () => applyBranching(form));
  form.addEventListener("submit", submitSurvey);
  applyBranching(form);
}

async function submitSurvey(event) {
  event.preventDefault();
  const form = event.target;
  const payload = Object.fromEntries(new FormData(form));
  const data = {};
  for (const field of survey.schema.fields) {
    if (form.querySelector(`[name="${field.code}"]`)?.closest(".hidden")) continue;
    if (field.type === "checkbox") {
      data[field.code] = [...form.querySelectorAll(`[name="${field.code}"]:checked`)].map((item) => item.value);
    } else if (field.type === "file") {
      const file = form.querySelector(`[name="${field.code}"]`)?.files?.[0];
      data[field.code] = file ? await fileToPayload(file) : "";
    } else {
      data[field.code] = payload[field.code] || "";
    }
  }
  try {
    await api(`/api/public/surveys/${encodeURIComponent(token)}`, {
      method: "POST",
      body: JSON.stringify({
        participant: { study_uid: payload.study_uid, initials: payload.initials || "" },
        data,
        consent: { signer_name: payload.signer_name || "", signature_text: payload.signature_text || "" },
        invitation_token: invitationToken,
      }),
    });
    render("Survey submitted. Thank you.");
  } catch (error) {
    render(error.message);
  }
}

api(`/api/public/surveys/${encodeURIComponent(token)}`)
  .then((result) => {
    survey = result.survey;
    render();
  })
  .catch((error) => {
    app.innerHTML = `<section class="login"><div class="login-card"><h1>${escapeHtml(error.message)}</h1></div></section>`;
  });

if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("/service-worker.js").catch(() => {});
  });
}
