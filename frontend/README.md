# VULNIX — Frontend

Vite + React + Tailwind. Fully wired to the FastAPI backend in `../backend`
— no mock data. Every screen (auth, target input, live progress, dashboard,
findings, retest, report export, history) reads and writes real API state.

## Setup

```bash
cd frontend
npm install
cp .env.example .env   # set VITE_API_BASE_URL if the backend isn't on :8000
npm run dev
```

Open `http://localhost:5173`. Make sure the backend (`../backend`) is
running first — the app will show a clear "could not reach the API" error
if it isn't.

## How it talks to the backend

- **Auth**: `POST /auth/signup`, `POST /auth/login`. The JWT is kept in
  React state only (not `localStorage`), so it's cleared on a full page
  reload — that's intentional for this build; add persistence if you want
  sessions to survive a refresh.
- **Start assessment**: `POST /assessments/url` (JSON) or
  `POST /assessments/zip` (multipart) — both require `authorized: true`,
  matching the checkbox on the target-input screen.
- **Live progress**: `EventSource` on `GET /assessments/{id}/stream?token=…`
  (the token goes in the query string because `EventSource` can't set an
  `Authorization` header). If the stream can't be opened, the app
  transparently falls back to polling `GET /assessments/{id}` every second —
  same UI either way.
- **Findings / dashboard / report**: all read from the `AssessmentOut`
  payload returned once `status === "completed"` — nothing is computed
  client-side.
- **Retest**: `POST /findings/{id}/retest` — this re-runs the real check
  against the live target server-side and returns the new status.
- **Export**: `GET /reports/{id}/pdf|json|csv`, fetched with the auth
  header and downloaded as a blob (can't use a plain `<a href>` since the
  route requires auth).
- **History**: `GET /assessments` on login and after each completed run.

## Build

```bash
npm run build   # outputs to dist/
npm run preview # serve the production build locally
```

## Notes

- `VITE_API_BASE_URL` is baked in at build time (standard Vite behavior).
  The login screen also has a "Backend URL" field that overrides it for
  the current session, useful when testing against a different backend
  without rebuilding.
- Protected views (Dashboard/Findings/Reports/History) redirect to the
  sign-in screen if there's no token, and any `401` from the API clears
  the session and redirects there too.
