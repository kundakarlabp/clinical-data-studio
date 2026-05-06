# Free Remote Access Setup

This app needs one central running instance and one central database for real study data. Do not run separate live database copies on multiple computers.

## Best Free Path For A Small Study

Use a private VPN overlay such as Tailscale or ZeroTier.

Why this is the best first choice:

- No paid cloud server is required.
- The study database stays on your study computer.
- Approved users can connect from outside the local Wi-Fi.
- The app is not exposed directly to the public internet.
- Phones, tablets, and laptops can still use the browser/PWA app.

Basic workflow:

1. Install Tailscale or ZeroTier on the study computer.
2. Install the same tool on each approved phone, tablet, or computer.
3. Sign all devices into the same private network.
4. Start Clinical Data Studio on the study computer:

```powershell
.\start.ps1
```

5. Print available remote addresses:

```powershell
.\remote_access.ps1
```

6. Open the private VPN address from approved devices, for example:

```text
http://100.x.y.z:8765
```

Each user should log in with their own Clinical Data Studio account. Do not share the administrator password.

## If Users Cannot Install A VPN App

Use Cloudflare Tunnel only after study approval.

Cloudflare Tunnel can publish the local app through Cloudflare without opening an inbound port on your router. For real clinical data, pair it with Cloudflare Access or an equivalent identity gate. A quick temporary tunnel is useful for a demo, but it is not enough for PHI or real trial data.

Demo-only quick tunnel after installing `cloudflared`:

```powershell
cloudflared tunnel --url http://127.0.0.1:8765
```

Production-style tunnel needs:

- A domain or approved hostname.
- Cloudflare Access login policy for named users.
- Strong Clinical Data Studio user passwords.
- Encrypted backups and restore drills.
- Documented approval in the validation package.

## If You Want A True Free Cloud Server

Oracle Cloud Always Free is the most practical free VM-style option, but it is more operational work than Tailscale.

Use it only if you are comfortable managing a Linux server:

1. Create an Oracle Cloud Free Tier account.
2. Create an Always Free Ubuntu VM in the home region.
3. Use an Always Free eligible shape only.
4. Add your SSH key.
5. Clone this repository on the VM.
6. Run the Linux service installer from the cloned folder:

```bash
sudo bash deploy/install_linux_service.sh
```

7. Prefer Tailscale or Cloudflare Tunnel in front of the VM instead of opening the app directly to the whole internet.

Important limitations:

- Oracle may have temporary capacity shortages for Always Free shapes.
- Signup commonly requires a phone number and credit card.
- You are responsible for server patching, backups, firewall rules, and access review.
- Do not put real identifiable patient data there until your study approves the hosting arrangement.

## Not Suitable For Live Clinical Data Entry

- GitHub Pages: static documentation only. It cannot run this Python backend or the live SQLite database.
- GitHub repositories: source code only. Never commit PHI, live databases, exports, backups, or passphrases.
- Google Drive live sync: encrypted backup file storage only. Do not run the live SQLite database from a synced folder.
- Free app hosts with sleeping or ephemeral storage: acceptable for demos, not for reliable clinical capture unless persistent storage and backups are verified.

## Minimum Safety Rules

- Change the administrator password before remote use.
- Create a named account for every user.
- Give each user only the permissions needed for their work.
- Make an encrypted backup before and after each data-entry day.
- Test restore before real study launch.
- Review the Audit Trail weekly.
- Keep the study computer or cloud VM patched and physically/account protected.
