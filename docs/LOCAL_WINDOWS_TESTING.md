# Local Windows Testing

Use this on your own computer before deploying to Lightsail.

## Run With SQLite

```powershell
cd "C:\path\to\clinical-data-studio"
python server.py migrate
python server.py
```

Open:

```text
http://127.0.0.1:8765
```

## Run Browser Tests

```powershell
python -m unittest discover -s tests
powershell -ExecutionPolicy Bypass -File .\tests\browser_smoke.ps1
```

## Test Docker Locally

Install Docker Desktop, then:

```powershell
docker compose -f docker-compose.local.yml up --build
```

Open:

```text
http://127.0.0.1:8765
```

Default local Docker login:

```text
admin
LocalDockerAdmin123
```

Do not use this password for real deployment.
