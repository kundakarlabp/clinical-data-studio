# Clinical Data Studio

A local-network electronic data capture app for small clinical research projects.

## What it does now

- Runs on one laptop/desktop and serves phones/tablets on the same Wi-Fi.
- Stores data in local SQLite.
- Provides study setup, CRF schema editing, participant registry, data entry, review queries, audit trail, CSV export, and simple analysis.
- Supports server-side edit checks, repeatable CRFs, lock/unlock review flow, data quality review, and codebook export.
- Uses no paid cloud server and no subscription.

## Start

```powershell
python .\server.py
```

Open the shown URL on this computer. To use from a phone, connect the phone to the same Wi-Fi and open:

```text
http://<this-computer-ip>:8765
```

On first run, the app opens a setup screen for creating the permanent administrator password. Complete this before entering real research data.

## Scope

This is an early local-first EDC foundation. It is not yet validated for FDA 21 CFR Part 11, HIPAA, GCP, or sponsor-regulated pivotal trials. Those require validation records, SOPs, access controls, backup procedures, and documented audit review in addition to software features.

## REDCap-like Feature Roadmap

Implemented foundation:

- Metadata-driven instruments and fields
- Required/range/choice edit checks
- Branching logic for simple show-if rules
- Repeat instances for repeatable CRFs
- Participant registry and event-based CRF entry
- Data queries and data quality dashboard
- Smart study-readiness dashboard for launch blockers, quality risks, backups, access, audit, and AI policy
- Audit trail for create/update/lock/unlock actions with CSV export
- CSV data export and codebook export
- Data dictionary CSV import
- Version history for edited CRFs
- Calculated fields
- Field-level verification/freeze
- Query response history
- Saved reports and filtered report export
- Local backup, download, and restore
- Optional passphrase-protected encrypted archive export
- Optional Windows EFS data-folder at-rest protection helper
- Health endpoint and local LAN start helper
- Installable Android/desktop PWA shell with offline fallback for app pages
- Remote access guidance page for LAN, VPN overlay, HTTPS tunnel, and static/file-host limitations
- Remote access helper script for LAN URL, Tailscale, and Cloudflare Tunnel checks
- First-run administrator password setup
- Login lockout after repeated failed attempts
- Local CRF draft assistant from pasted text with optional structured OpenAI drafting when explicitly enabled
- Local analysis/review assistant summary
- Record CSV import into participant CRFs
- Entry history and field-state review visibility
- Public survey links for local-network participant entry
- E-consent style name/signature capture tied to survey submissions
- File upload fields stored inside CRF data records
- Smart Case Intake for unstructured retrospective case notes, photos, audio evidence, local extraction, grouping, and case-series CSV export
- Optional OpenAI Academic AI review for multimodal case interpretation, adaptive CRF suggestions, and publication guidance
- Academic Workbench for publication opportunities, CV item tracking, and Markdown/CSV academic portfolio export
- Windows scheduled-task start-at-login helper
- Validation execution record template
- Survey invitation and reminder tracking
- Validation evidence JSON export
- Downloadable validation package with evidence, audit sample, codebook, SOP checklist, and execution-record template
- Optional Playwright browser/mobile smoke script
- REDCap-style token API for project, metadata, instruments, events, records, and randomization
- REDCap-style user-rights, data access group, arm, and API-version exports
- API token usage audit entries and token revoke workflow
- ODM-like XML project export
- R, SAS, SPSS, and Stata import package exports
- Simple allocation randomization module
- API and mobile shell regression tests

Next planned build steps:

- Optional audited database-at-rest encryption layer
- Automated EFS/device-encryption compliance checks beyond local status reporting
- Broader browser automation across common Android/iOS viewport sizes
- Email/SMS integration for automated invitations
- Full REDCap API edge-case parity only if a specific importing system requires it

## REDCap-style Local API

Create an API token from Access -> API Tokens. Use `/api/redcap` with parameters such as:

- `token`: generated API token
- `content`: `project`, `metadata`, `instrument`, `event`, `arm`, `dag`, `user`, `record`, `randomization`, or `version`
- `action`: `export`, `import`, or `allocate`
- `format`: `json` or `csv`

This is REDCap-style compatibility for local workflows, not an official REDCap API implementation.

## Optional AI

The CRF drafting assistant runs locally by default. To enable external structured AI drafting, set:

```powershell
$env:CDS_AI_PROVIDER = "openai"
$env:CDS_AI_ENABLED = "true"
$env:CDS_AI_MODEL = "gpt-5-mini"
$env:OPENAI_API_KEY = "your_api_key"
```

Do not send patient identifiers or PHI to external AI unless your study policy and data agreement allow it. AI drafts must be reviewed before use.

For case-report and case-series AI review with images/audio, see [docs/OPENAI_ACADEMIC_AI.md](docs/OPENAI_ACADEMIC_AI.md). A ChatGPT subscription does not automatically give this local app API access; configure an OpenAI API key on the study computer.

## Case Reports And Case Series

Use **Case Intake** when case material arrives as notes, images, audio, scanned details, or rough typed summaries before a formal CRF is ready. The app stores original evidence, extracts draft demographics/diagnosis/treatment/outcome fields locally, groups similar cases, and exports a case-series CSV. See [docs/CASE_SERIES_WORKFLOW.md](docs/CASE_SERIES_WORKFLOW.md).

Use **Academic CV** to convert grouped cases into publication opportunities, track abstracts/posters/manuscripts/presentations/audits, and export a CV-ready portfolio. See [docs/ACADEMIC_WORKBENCH.md](docs/ACADEMIC_WORKBENCH.md).

## Android And Multi-Device Use

Run the app on one study computer with `.\start.ps1`, then open the shown Wi-Fi URL on phones, tablets, or other computers. On Android Chrome, use **Add to Home screen** or the app's **Install App** prompt to create an app icon.

The installed app shell can open while offline, but clinical data save/sync still requires connection to the study computer. For completely separate non-connected sites, use exports/imports or backups until offline sync is explicitly validated.

For Android install steps and offline draft behavior, see [docs/ANDROID_PWA_SETUP.md](docs/ANDROID_PWA_SETUP.md).

For a later optional native Android shell, see [docs/ANDROID_CAPACITOR_BUILD.md](docs/ANDROID_CAPACITOR_BUILD.md). Use this only after the hosted PWA is stable.

## Remote Access

For real study data, keep one central running app and database. This preserves audit trail order, record locking, user permissions, backups, and query review history.

Simplest free remote option:

```powershell
.\start_easy_remote.ps1
```

This starts the app on your computer and opens a free temporary Cloudflare Tunnel. Share the printed `https://*.trycloudflare.com` link only with approved users. Keep the PowerShell window open while users enter data.

Recommended options:

- Same Wi-Fi/LAN: simplest and safest for bedside or department use.
- Private VPN overlay: use a tool such as Tailscale or ZeroTier so approved phones and computers can reach the study computer remotely without making the app public.
- HTTPS tunnel or hosted server: use only with study approval, HTTPS, strong named users, backup drills, firewall review, and documented access review.

Run `.\remote_access.ps1` after starting the app to print the LAN address and detect whether Tailscale or cloudflared is available on the study computer.

For a free remote-access decision guide and Oracle Always Free VM notes, see [docs/FREE_REMOTE_ACCESS.md](docs/FREE_REMOTE_ACCESS.md).

Do not use GitHub Pages or Google Drive as the live clinical database host. GitHub Pages is for static site files, not this Python backend and SQLite database. Google Drive can store encrypted backup archives, but live SQLite databases are not safe to edit through file-sync storage from multiple users. Do not place PHI, identifiers, live exports, database files, or backup passphrases in a public or shared GitHub repository.
