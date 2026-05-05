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

## Backup Policy

- Plain backups can be restored in-app.
- Encrypted archives can be downloaded or restored in-app with the passphrase used at creation.
- Store archive passphrases separately from the backup files.
- Keep at least one copy on an encrypted external drive.

## Public Survey Links

Survey links are LAN/public-within-your-network URLs created from the Surveys page. Share them only on trusted networks. Each link uses an unguessable token, but anyone with the link can submit data until the link is disabled.

For consent-required surveys, the app records signer name, typed signature, consent text, client IP address, browser user agent, and timestamp.

## Health Check

For quick startup verification:

```powershell
curl.exe http://127.0.0.1:8765/api/health
```

Expected response:

```json
{"ok":true,"app":"Clinical Data Studio","database":true}
```

## Start At Login

To install a Windows scheduled task for the current user:

```powershell
.\install_service_task.ps1
Start-ScheduledTask -TaskName ClinicalDataStudio
```

Use this only on the designated study computer after confirming backups and validation records.

## Validation Reminder

This deployment guide supports a small local research workflow. A regulated clinical trial still needs documented validation, SOP approval, access review, backup restore drills, and audit review sign-off.
