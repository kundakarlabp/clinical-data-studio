# Clinical Data Studio Deployment

## Local LAN Mode

Run on the research laptop or desktop:

```powershell
.\start.ps1
```

Open `http://127.0.0.1:8765` on the host computer. Phones and tablets must be on the same Wi-Fi and can use one of the LAN URLs printed by the script.

On first launch, complete the administrator setup screen and store the password in your study operations records.

## Firewall

If another device cannot open the app, allow Python through Windows Defender Firewall for private networks, or open TCP port `8765` only on the trusted local network.

## Data Location

The SQLite database is stored under:

```text
data\clinical_data_studio.sqlite3
```

Use the Backups page before CRF dictionary imports, CRF edits, or study review exports.

## Data Folder At-Rest Protection

On Windows, protect the app `data` folder with Encrypting File System for the current Windows account:

```powershell
.\protect_data_folder.ps1
```

This protects the live SQLite database files at rest on that Windows profile. It is not a replacement for study SOPs, Windows account security, device encryption, and encrypted backup archives. Record the output of `/api/health` or `/api/studies/<id>/validation` after enabling protection.

## Backup Policy

- Plain backups can be restored in-app.
- Encrypted archives can be downloaded or restored in-app with the passphrase used at creation.
- Store archive passphrases separately from the backup files.
- Keep at least one copy on an encrypted external drive.

## Public Survey Links

Survey links are LAN/public-within-your-network URLs created from the Surveys page. Share them only on trusted networks. Each link uses an unguessable token, but anyone with the link can submit data until the link is disabled.

For consent-required surveys, the app records signer name, typed signature, consent text, client IP address, browser user agent, and timestamp.

Survey invitations are tracked inside the app for manual phone/email workflows. Use the Invitation Tracker to record when a link was sent, reminded, completed, or cancelled. Automated SMS/email requires a separate approved messaging service and is not enabled by default.

## Health Check

For quick startup verification:

```powershell
curl.exe http://127.0.0.1:8765/api/health
```

Expected response:

```json
{"ok":true,"app":"Clinical Data Studio","database":true}
```

## Validation Package

From Settings, download the Validation Package ZIP before study launch and after major CRF or workflow changes. The package includes validation evidence JSON, CRF metadata/codebook JSON, an audit sample, a system manifest, the SOP checklist, and an execution-record template.

The Audit page also provides a CSV export for monitor review or periodic access and data-change sign-off.

## Start At Login

To install a Windows scheduled task for the current user:

```powershell
.\install_service_task.ps1
Start-ScheduledTask -TaskName ClinicalDataStudio
```

Use this only on the designated study computer after confirming backups and validation records.

## Browser Smoke Check

After starting the app, optional browser/mobile smoke automation can be run when Playwright is available:

```powershell
$env:CDS_BASE_URL = "http://127.0.0.1:8765"
.\tests\browser_smoke.ps1
```

## REDCap-style API and Exports

Create API tokens from the Access page. The local REDCap-style endpoint is:

```text
/api/redcap
```

Supported parameters include `token`, `content`, `action`, and `format`. Supported content values are `project`, `metadata`, `instrument`, `event`, `arm`, `dag`, `user`, `record`, `randomization`, and `version`.

Review API token usage in the study audit log. Revoke unused or exposed API tokens from Access -> API Tokens.

The Reports page also provides ODM XML and R/SAS/SPSS/Stata package exports. Review exported syntax before formal analysis.

## Optional AI Configuration

The CRF assistant is local by default and does not require paid services. External OpenAI drafting can be enabled only when approved for your study:

```powershell
$env:CDS_AI_PROVIDER = "openai"
$env:CDS_AI_MODEL = "gpt-5-mini"
$env:OPENAI_API_KEY = "your_api_key"
```

Use de-identified prompts only unless your policy and agreement permit PHI. Review the returned schema before creating or changing CRFs.

## Validation Reminder

This deployment guide supports a small local research workflow. A regulated clinical trial still needs documented validation, SOP approval, access review, backup restore drills, and audit review sign-off.
