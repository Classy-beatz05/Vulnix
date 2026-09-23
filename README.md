# VULNIX — Security Assessment Platform

Full-stack app: FastAPI backend performing real, passive security checks
(headers, TLS, ZIP static analysis) + a React/Tailwind frontend fully wired
to it. No mock data — every screen reflects what the backend actually found.

```
vulnix-project/
├── backend/     FastAPI API, SQLite/Postgres, real assessment engine
└── frontend/    Vite + React + Tailwind UI
```

## Run it (two terminals)

**Terminal 1 — backend**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env        # set JWT_SECRET to a real random value
uvicorn app.main:app --reload --port 8000
```

**Terminal 2 — frontend**
```bash
cd frontend
npm install
cp .env.example .env        # defaults to http://localhost:8000, fine as-is
npm run dev
```

Open `http://localhost:5173`, sign up, confirm authorization, and run a
real assessment against a target you're authorized to test (or your own
project ZIP).

## What's real vs. intentionally out of scope

**Real:** JWT auth, SSRF-guarded URL assessment (HTTP headers, TLS
handshake/version/cert expiry, `.git`/`.env` exposure, error verbosity),
zip-slip/zip-bomb-safe ZIP static analysis (hardcoded secrets, debug flags,
SQL string-concat patterns, unsafe extraction code, dependency advisories),
live progress via SSE with polling fallback, retest against the live
target, PDF/JSON/CSV export from actual stored findings, rate limiting,
audit logging.

**Out of scope by design:** active exploitation of any kind, and open-ended
port scanning across arbitrary ranges from a hosted multi-tenant API (both
legally risky and easy to abuse) — network checks are limited to the
service already under assessment. See `backend/README.md` for the full
control list and endpoint reference.

## Troubleshooting

- **"Could not reach the VULNIX API"** — backend isn't running, or
  `VITE_API_BASE_URL` / the login screen's "Backend URL" field points
  somewhere else. Check `curl http://localhost:8000/health`.
- **CORS errors in the browser console** — `CORS_ORIGINS` in `backend/.env`
  defaults to `*`, which covers this. If you've tightened it for
  deployment, make sure your frontend's real origin is included.
- **Assessment stuck on "queued"** — check the backend terminal for a
  traceback; the background job runs in a thread and logs there.
