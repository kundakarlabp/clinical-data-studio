# OpenAI Academic AI Setup

Clinical Data Studio stays local by default. External AI is optional and requires an OpenAI API key on the study computer.

## Key Point

A ChatGPT subscription is not the same as API access for this app. Use the OpenAI platform to create an API key and configure billing for API use. Do not paste patient identifiers or PHI into external AI unless your study policy, consent, and data agreement allow it.

## Enable Text AI

In PowerShell before starting the app:

```powershell
$env:CDS_AI_PROVIDER = "openai"
$env:CDS_AI_ENABLED = "true"
$env:OPENAI_API_KEY = "your_openai_api_key"
$env:CDS_AI_MODEL = "gpt-5.2"
.\start.ps1
```

This enables AI-assisted CRF drafting and Academic AI review from typed, pasted, dictated, or OCR text.

## Enable Image And Audio Review

Only enable this after confirming your privacy/ethics policy permits sending uploaded evidence to OpenAI:

```powershell
$env:CDS_AI_PROVIDER = "openai"
$env:CDS_AI_ENABLED = "true"
$env:OPENAI_API_KEY = "your_openai_api_key"
$env:CDS_AI_MODEL = "gpt-5.2"
$env:CDS_AI_TRANSCRIBE_MODEL = "gpt-4o-transcribe"
$env:CDS_AI_MULTIMODAL = "1"
.\start.ps1
```

When enabled, Academic AI can send uploaded images for vision review and transcribe uploaded audio before case analysis. Text files are included as text evidence. Unsupported files remain stored locally as source evidence.

By default, `CDS_AI_ALLOW_PHI=false`. The server blocks obvious identifiers before external AI use. Keep it false unless your ethics and institutional policy explicitly approve sending PHI to an external AI service.

## What The Assistant Produces

- Structured case summary from available evidence.
- Draft demographics, clinical presentation, investigations, treatment, outcome, and follow-up fields.
- Adaptive CRF suggestions as repeated cases reveal common variables.
- Publication guidance for case report or case series potential.
- Missing data checklist, follow-up questions, manuscript outline, literature search terms, and ethics/privacy reminders.

Every AI output is a draft review aid. A clinical researcher must verify it against source records before analysis or publication.

## References

- OpenAI Responses API: https://platform.openai.com/docs/api-reference/responses
- OpenAI image input guide: https://platform.openai.com/docs/guides/images-vision
- OpenAI audio transcription API: https://platform.openai.com/docs/api-reference/audio/createTranscription
- OpenAI ChatGPT vs API billing: https://help.openai.com/en/articles/9039756-billing-settings-in-chatgpt-vs-platform
