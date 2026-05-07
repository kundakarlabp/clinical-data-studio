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

Every AI request is recorded in the audit trail with mode and file count. AI suggestions are review aids, not final clinical interpretation.
