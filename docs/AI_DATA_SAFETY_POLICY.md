# AI Data Safety Policy

Clinical Data Studio keeps external AI off by default.

## Defaults

```text
CDS_AI_PROVIDER=local
CDS_AI_ENABLED=false
CDS_AI_ALLOW_PHI=false
```

With these settings, the app uses local rule-based assistance only.

## External AI

Enable external OpenAI only after ethics, institutional, and study approval:

```text
CDS_AI_PROVIDER=openai
CDS_AI_ENABLED=true
OPENAI_API_KEY=your_key
CDS_AI_ALLOW_PHI=false
```

When `CDS_AI_ALLOW_PHI=false`, the server blocks obvious identifiers before external AI use, including email, phone, Aadhaar-like numbers, MRN/MRD/UHID labels, address labels, and patient name labels.

## Before Sending Data To AI

Remove:

- Patient name
- MRN/MRD/UHID
- Aadhaar or national ID
- Phone
- Email
- Address
- Exact identifiers not needed for the research question

Prefer:

- Study ID
- Age range instead of full date of birth
- De-identified clinical summary
- General dates only when needed

## Audit

Every AI request is recorded in the audit trail and in the AI audit table with:

- user
- study
- linked case when available
- provider and model
- local or external mode
- purpose
- file count
- whether PHI was detected
- whether PHI was allowed
- status and error if any

## Current Safe AI Features

Low-risk helpers are available inside **Academic Workbench**:

- protocol or pasted text to CRF draft
- case note to structured summary
- dataset missing-field check
- dataset inconsistency check
- case set publication idea
- academic activity to CV item suggestion

Photo, PDF, and audio interpretation by external AI must stay behind admin enablement, PHI safety checks, and explicit confirmation. Do not make external AI automatic.

## Publication And Novelty

AI may suggest publication angles, missing data, titles, and abstract structure. It must not be treated as proof of novelty. Novelty requires a manual literature search and supervisor or co-author review.

## Project AI Policy

Each study now has its own AI policy in **Academic Workbench -> Project AI Policy**.

Default safe settings:

- local AI helpers allowed;
- external AI blocked;
- PHI blocked;
- photo/PDF/audio external AI blocked;
- allowed purposes limited to approved clinical-research helpers.

External AI is used only if both the server configuration and the project AI policy allow it. Data Entry users cannot run external AI by default. Every AI request is recorded in the AI audit trail.

## ChatGPT / OpenAI Setup

Your personal ChatGPT login is not used as the app credential. The deployed server needs an OpenAI API key in `.env`, and that key must never be committed to GitHub.

Use [OPENAI_CHATGPT_SETUP.md](OPENAI_CHATGPT_SETUP.md) for the step-by-step setup. Keep `CDS_AI_ALLOW_PHI=false` unless you have explicit approval for identifiable patient data.
