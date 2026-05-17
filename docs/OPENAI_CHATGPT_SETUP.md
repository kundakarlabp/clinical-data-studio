# OpenAI / ChatGPT Setup For Clinical Data Studio

This app can use OpenAI models for AI helpers, but it cannot safely use a personal ChatGPT browser login or ChatGPT Plus session as the server credential.

For a hosted Lightsail app, use an OpenAI API key stored only in the server `.env` file.

The OpenAI API key must never be committed to GitHub.

## Recommended Safe Default

Keep external AI off for pilot clinical data entry:

```env
CDS_AI_ENABLED=false
CDS_AI_PROVIDER=local
CDS_AI_ALLOW_PHI=false
CDS_AI_MULTIMODAL=false
```

This keeps all AI helper behavior local/rule-based and avoids sending patient information outside your server.

## Enable OpenAI For De-identified Work

Only do this after you understand the safety policy and have your study/institution approval.

In the Lightsail `.env` file:

```env
CDS_AI_ENABLED=true
CDS_AI_PROVIDER=openai
CDS_AI_ALLOW_PHI=false
CDS_AI_MULTIMODAL=false
CDS_AI_MODEL=gpt-5.2
OPENAI_API_KEY=sk-your-openai-api-key-here
```

Then restart the app:

```bash
docker compose up -d --build
docker compose logs --tail=100 app
```

Open the app as admin:

1. Go to **Academic CV**.
2. Open **Project AI Policy**.
3. Keep **External PHI allowed** off.
4. Enable only the low-risk purposes you need, such as `case_summary`, `missing_fields`, `publication_idea`, or `cv_item`.
5. Test with de-identified text only.

## Do Not Put These In GitHub

Never commit:

- `OPENAI_API_KEY`
- `.env`
- patient data
- exported CSV files
- backups
- uploaded clinical files

## What ChatGPT Can Help With

Safe uses:

- de-identified protocol text to CRF draft suggestions
- CRF quality checking
- missing data checklist
- inconsistency detection
- publication idea planning
- CV item wording

Unsafe unless explicitly approved:

- patient names, phone numbers, addresses, UHID/MRN/MRD/Aadhaar-like identifiers
- full discharge summaries with identifiers
- images/PDFs/audio containing PHI
- raw data exports with identifiers

## GitHub Repository Connection

Your GitHub repository is connected to this development workflow through pull requests. That is separate from the app's AI feature.

The app itself should not connect directly to GitHub for clinical data storage. GitHub is for code only. Clinical data, uploads, backups, `.env`, and API keys must stay out of GitHub.

## If AI Says External AI Is Still Off

Check:

1. `.env` has `CDS_AI_ENABLED=true`.
2. `.env` has `CDS_AI_PROVIDER=openai`.
3. `OPENAI_API_KEY` is present on the server.
4. Docker was restarted after editing `.env`.
5. The study Project AI Policy allows the purpose you are trying to run.
6. PHI was not detected, unless PHI is explicitly approved.

External AI is intentionally blocked by several gates so patient data is not leaked by mistake.
