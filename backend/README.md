# VULNIX — FastAPI backend

Real, working backend for the VULNIX security assessment platform: auth,
SQLite/Postgres storage, background assessment jobs, live SSE progress,
a passive URL-assessment engine (headers/TLS/recon), a ZIP static-analysis
engine (secrets/config/dependency/source checks), retest, and report export.

## What's genuinely real vs. simulated

- **Real:** HTTP header inspection, TLS handshake/version/cert-expiry checks,
  passive existence checks (`/.git/config`, `/.env`, `security.txt`), error
  verbosity probing, ZIP secret/config/dependency/SQL-pattern static analysis,
  scoring, retest-against-live-target, JSON/CSV/PDF export, JWT auth, rate
  limiting, audit log, SSRF guarding, zip-slip/zip-bomb protection.
- **Not included (by design):** active exploitation of any kind, port
  sweeping across arbitrary ranges (a hosted multi-tenant API doing that is
  both legally risky and easy to abuse — this scans only the service already
  under assessment), and a full CVE feed (the dependency check ships with a
  small offline sample list; swap in a real call to `api.osv.dev` for
  production use).

## Setup

```bash
cd vulnix-backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edit JWT_SECRET at minimum
uvicorn app.main:app --reload --port 8000
```

Visit `http://localhost:8000/docs` for interactive OpenAPI docs.

By default this uses SQLite (`vulnix.db`). For Postgres, set in `.env`:

```
DATABASE_URL=postgresql+psycopg2://user:pass@host:5432/vulnix
```

and additionally `pip install psycopg2-binary`.

## API overview

| Method | Path                              | Purpose                                   |
|--------|------------------------------------|--------------------------------------------|
| POST   | `/auth/signup`                     | Create a user                              |
| POST   | `/auth/login`                      | Get a JWT                                  |
| GET    | `/auth/me`                         | Current user                               |
| POST   | `/assessments/url`                 | Start a URL assessment (SSRF-validated)    |
| POST   | `/assessments/zip`                 | Start a ZIP assessment (multipart upload)  |
| GET    | `/assessments`                     | List your assessments                      |
| GET    | `/assessments/{id}`                | Get one assessment + findings              |
| GET    | `/assessments/{id}/stream`         | SSE: live phase/progress/finding counts    |
| POST   | `/assessments/{id}/stop`           | Stop a running assessment                  |
| POST   | `/findings/{id}/retest`            | Re-run the live check behind one finding   |
| GET    | `/reports/{id}/json`               | Export report as JSON                      |
| GET    | `/reports/{id}/csv`                | Export findings as CSV                     |
| GET    | `/reports/{id}/pdf`                | Export report as PDF                       |

All routes except `/auth/*` and `/health` require
`Authorization: Bearer <token>`.

### Example flow

```bash
curl -X POST localhost:8000/auth/signup -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"correcthorsebattery"}'

TOKEN=$(curl -s -X POST localhost:8000/auth/login -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"correcthorsebattery"}' | python -c "import sys,json;print(json.load(sys.stdin)['access_token'])")

curl -X POST localhost:8000/assessments/url -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"target":"https://example.com","authorized":true}'

# then GET /assessments/{id}/stream to watch it run
```

## Security controls implemented

- **SSRF guard** (`security_utils.validate_target_url`): resolves the
  hostname and rejects private/loopback/link-local/reserved/metadata IPs
  before any request is made; every redirect hop is re-validated the same way.
- **Safe ZIP extraction** (`security_utils.safe_extract_zip`): rejects
  absolute paths, entries that resolve outside the extraction directory
  (zip-slip), symlink entries, and enforces max file count / total
  uncompressed size (zip-bomb protection). Uploaded code is never executed —
  files are only opened as text for pattern matching.
- **Auth & authorization**: JWT-based auth; every assessment/finding/report
  route checks resource ownership. The SSE progress endpoint accepts the
  JWT as a `?token=` query param (browser `EventSource` can't set headers)
  in addition to the standard `Authorization` header used everywhere else.
- **Input validation**: Pydantic schemas on every request body; a caller
  must explicitly set `authorized: true` to start an assessment, and every
  assessment/retest/stop action is written to `audit_log` with user + IP.
  Authorization/scope confirmation is, by design, an application-level
  fact the API cannot itself verify — it's a legal/organizational control,
  not a technical one.
- **Rate limiting**: in-memory sliding window per client IP (swap for Redis
  in a multi-instance deployment).
- **Timeouts**: every outbound check uses `CHECK_TIMEOUT_SECONDS`.
- **CORS**: bearer-token auth means no cookies cross origins, so
  `CORS_ORIGINS=*` is safe for local dev (`allow_credentials` is off).
  Tighten to your real frontend origin(s) before deploying.

## Frontend

The `frontend/` folder alongside this one (`../frontend`) is a Vite/React
app already wired to every endpoint below — see its README for setup.
