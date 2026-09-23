import React, { useState, useEffect, useRef } from "react";
import {
  Shield, CheckCircle2, Circle, Loader2, Search, ArrowRight, AlertTriangle,
  RotateCcw, Menu, Plus, ArrowLeft, LogOut, Eye, EyeOff, WifiOff,
} from "lucide-react";

/* ---------------------------------- design tokens ---------------------------------- */
const BG = "#C5C1C1";
const CARD = "#F3F4F4";
const CARD_BORDER = "rgba(44, 44, 44, 0.15)";
const TEXT = "#2C2C2C";
const MUTED = "#5F5F5F";

const PRIMARY = "#49A4BB";
const PRIMARY_DARK = "#3C8EA3";
const SECONDARY = "#D8A2A2";
const DANGER = "#A82020";
const GOLD = "#B7791F";

const SEV = {
  critical: { label: "Critical", color: DANGER, weight: 12 },
  high: { label: "High", color: "#C1442E", weight: 6 },
  medium: { label: "Medium", color: GOLD, weight: 2 },
  low: { label: "Low", color: "#7FC2C1", weight: 0.6 },
};

const CATEGORIES = ["Web Application", "API Security", "Network Exposure", "Configuration", "Dependencies"];
const PHASES = [
  "Reconnaissance", "Technology discovery", "Web & API checks",
  "SSL / headers", "Port & service assessment", "Vulnerability correlation",
];
const TERMINAL_STATUSES = ["completed", "failed", "stopped"];

/* ---------------------------------- API client ---------------------------------- */
async function apiRequest(apiBase, path, token, opts = {}) {
  const headers = { ...(opts.headers || {}) };
  if (token) headers["Authorization"] = `Bearer ${token}`;
  let body = opts.body;
  if (body && !(body instanceof FormData)) {
    headers["Content-Type"] = "application/json";
    body = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(`${apiBase}${path}`, { ...opts, headers, body });
  } catch (e) {
    const err = new Error(
      `Could not reach the VULNIX API at ${apiBase}. Make sure the backend is running and reachable from this browser.`
    );
    err.network = true;
    throw err;
  }

  let data = null;
  const text = await res.text();
  if (text) {
    try { data = JSON.parse(text); } catch (e) { data = null; }
  }

  if (!res.ok) {
    let msg = `Request failed (${res.status})`;
    if (data?.detail) {
      msg = Array.isArray(data.detail) ? data.detail.map((d) => d.msg).join("; ") : data.detail;
    }
    const err = new Error(msg);
    err.status = res.status;
    throw err;
  }
  return data;
}

async function downloadReport(apiBase, token, assessmentId, format) {
  const res = await fetch(`${apiBase}/reports/${assessmentId}/${format}`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`Export failed (${res.status})`);
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `vulnix-report-${assessmentId}.${format}`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

/** Subscribes to live progress via SSE (token in query string, since
 *  EventSource can't set an Authorization header), falling back to
 *  polling GET /assessments/{id} if the stream can't be opened. */
function subscribeProgress(apiBase, token, assessmentId, onUpdate, onTerminal, onError) {
  let es = null;
  let pollTimer = null;
  let sseDelivered = false;
  let closed = false;

  const finishWithFullAssessment = async () => {
    try {
      const data = await apiRequest(apiBase, `/assessments/${assessmentId}`, token);
      onTerminal(data);
    } catch (e) {
      onError(e);
    }
  };

  const startPolling = () => {
    if (pollTimer || closed) return;
    pollTimer = setInterval(async () => {
      try {
        const data = await apiRequest(apiBase, `/assessments/${assessmentId}`, token);
        const counts = { critical: 0, high: 0, medium: 0, low: 0 };
        (data.findings || []).forEach((f) => counts[f.severity]++);
        onUpdate({ status: data.status, phase: data.phase, progress: data.progress, counts, error: data.error });
        if (TERMINAL_STATUSES.includes(data.status)) {
          clearInterval(pollTimer);
          onTerminal(data);
        }
      } catch (e) {
        clearInterval(pollTimer);
        onError(e);
      }
    }, 1000);
  };

  try {
    es = new EventSource(`${apiBase}/assessments/${assessmentId}/stream?token=${encodeURIComponent(token)}`);
    es.onmessage = (evt) => {
      sseDelivered = true;
      let data;
      try { data = JSON.parse(evt.data); } catch (e) { return; }
      onUpdate(data);
      if (TERMINAL_STATUSES.includes(data.status)) {
        es.close();
        finishWithFullAssessment();
      }
    };
    es.onerror = () => {
      if (es) es.close();
      if (!sseDelivered && !closed) startPolling();
    };
  } catch (e) {
    startPolling();
  }

  return () => {
    closed = true;
    if (es) es.close();
    if (pollTimer) clearInterval(pollTimer);
  };
}

/* ---------------------------------- small primitives ---------------------------------- */
function Badge({ children, style }) {
  return (
    <span className="inline-flex items-center px-2.5 py-1 rounded-full text-[11px] font-semibold tracking-wide" style={style}>
      {children}
    </span>
  );
}

function SeverityTag({ sev }) {
  const s = SEV[sev];
  if (!s) return null;
  return <span className="text-xs font-bold tracking-wide" style={{ color: s.color }}>{s.label.toUpperCase()}</span>;
}

function Card({ children, className = "", style = {} }) {
  return (
    <div className={`rounded-2xl border ${className}`} style={{ background: CARD, borderColor: CARD_BORDER, ...style }}>
      {children}
    </div>
  );
}

function Label({ children }) {
  return <div className="text-[11px] uppercase tracking-widest mb-2" style={{ color: MUTED }}>{children}</div>;
}

function PrimaryButton({ children, onClick, disabled, className = "", type = "button" }) {
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`rounded-full px-6 py-3 font-semibold text-sm transition-opacity ${disabled ? "opacity-40 cursor-not-allowed" : "hover:opacity-90"} ${className}`}
      style={{ background: PRIMARY, color: "#FFFFFF" }}
    >
      {children}
    </button>
  );
}

function DangerButton({ children, onClick, disabled, className = "" }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`rounded-full px-6 py-3 font-semibold text-sm transition-opacity ${disabled ? "opacity-40 cursor-not-allowed" : "hover:opacity-90"} ${className}`}
      style={{ background: DANGER, color: TEXT }}
    >
      {children}
    </button>
  );
}

function SecondaryButton({ children, onClick, disabled, className = "" }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`rounded-full px-5 py-2.5 font-semibold text-sm transition-opacity ${disabled ? "opacity-40 cursor-not-allowed" : "hover:opacity-90"} ${className}`}
      style={{ background: SECONDARY, color: TEXT }}
    >
      {children}
    </button>
  );
}

function GhostButton({ children, onClick, disabled, className = "" }) {
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className={`rounded-full px-5 py-2.5 font-semibold text-sm border transition-colors hover:bg-white/5 ${disabled ? "opacity-40 cursor-not-allowed" : ""} ${className}`}
      style={{ borderColor: CARD_BORDER, color: TEXT }}
    >
      {children}
    </button>
  );
}

function ErrorBanner({ message, onDismiss }) {
  if (!message) return null;
  return (
    <div
      className="rounded-xl px-4 py-3 mb-5 flex items-start gap-2 text-sm"
      style={{ background: "rgba(168,32,32,0.12)", border: `1px solid ${DANGER}`, color: "#ffd7d7" }}
    >
      <AlertTriangle size={16} className="shrink-0 mt-0.5" color={DANGER} />
      <span className="flex-1">{message}</span>
      {onDismiss && (
        <button onClick={onDismiss} className="text-xs font-semibold shrink-0" style={{ color: "#ffd7d7" }}>
          Dismiss
        </button>
      )}
    </div>
  );
}

function Spinner({ label = "Loading…" }) {
  return (
    <div className="flex items-center gap-2 text-sm py-10 justify-center" style={{ color: MUTED }}>
      <Loader2 size={16} className="animate-spin" /> {label}
    </div>
  );
}

/* ---------------------------------- nav ---------------------------------- */
function NavBar({ view, goTo, isAuthed, userEmail, onLogout }) {
  const [open, setOpen] = useState(false);
  const items = [
    { key: "dashboard", label: "Dashboard" },
    { key: "history", label: "Assessments" },
    { key: "findings", label: "Findings" },
    { key: "report", label: "Reports" },
  ];
  const initials = userEmail ? userEmail[0].toUpperCase() + (userEmail.split("@")[0][1] || "").toUpperCase() : "";

  return (
    <div className="flex items-center justify-between px-5 sm:px-8 py-5 border-b relative" style={{ borderColor: CARD_BORDER }}>
      <button className="flex items-baseline gap-2" onClick={() => goTo(isAuthed ? "landing" : "auth")}>
        <span className="font-black text-lg tracking-tight" style={{ color: TEXT }}>VULNIX</span>
        <span className="text-[10px] uppercase tracking-widest hidden sm:inline" style={{ color: MUTED }}>Security Assessment</span>
      </button>

      {isAuthed && (
        <div className="hidden md:flex items-center gap-7">
          {items.map((it) => (
            <button
              key={it.key}
              onClick={() => goTo(it.key)}
              className="text-sm transition-colors"
              style={{ color: view === it.key ? TEXT : MUTED, fontWeight: view === it.key ? 600 : 400 }}
            >
              {it.label}
            </button>
          ))}
        </div>
      )}

      <div className="flex items-center gap-3">
        {isAuthed ? (
          <>
            <div className="hidden md:flex w-9 h-9 rounded-full items-center justify-center text-xs font-bold" style={{ background: PRIMARY, color: "#FFFFFF" }} title={userEmail}>
              {initials}
            </div>
            <button className="hidden md:flex items-center gap-1 text-xs" style={{ color: MUTED }} onClick={onLogout}>
              <LogOut size={13} /> Sign out
            </button>
          </>
        ) : (
          <span className="text-xs hidden sm:inline" style={{ color: MUTED }}>Not signed in</span>
        )}
        <button className="md:hidden" onClick={() => setOpen(!open)}>
          <Menu size={22} color={TEXT} />
        </button>
      </div>

      {open && (
        <div className="absolute top-[68px] left-0 right-0 z-20 flex flex-col md:hidden border-b" style={{ background: BG, borderColor: CARD_BORDER }}>
          {isAuthed && items.map((it) => (
            <button key={it.key} onClick={() => { goTo(it.key); setOpen(false); }} className="text-left px-6 py-4 text-sm border-t" style={{ color: view === it.key ? TEXT : MUTED, borderColor: CARD_BORDER }}>
              {it.label}
            </button>
          ))}
          {isAuthed && (
            <button onClick={() => { onLogout(); setOpen(false); }} className="text-left px-6 py-4 text-sm border-t flex items-center gap-2" style={{ color: MUTED, borderColor: CARD_BORDER }}>
              <LogOut size={14} /> Sign out
            </button>
          )}
        </div>
      )}
    </div>
  );
}

/* ---------------------------------- auth ---------------------------------- */
function AuthScreen({ apiBase, setApiBase, onAuthed }) {
  const [mode, setMode] = useState("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPw, setShowPw] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [showSettings, setShowSettings] = useState(false);

  const submit = async (e) => {
    e.preventDefault();
    setError("");
    setLoading(true);
    try {
      if (mode === "signup") {
        await apiRequest(apiBase, "/auth/signup", null, {
          method: "POST",
          body: { email, password },
        });
      }
      const tokenResp = await apiRequest(apiBase, "/auth/login", null, {
        method: "POST",
        body: { email, password },
      });
      onAuthed(tokenResp.access_token, email);
    } catch (err) {
      setError(err.message || "Something went wrong.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="max-w-md mx-auto px-5 sm:px-8 py-16">
      <div className="flex items-center gap-2 mb-2">
        <Shield size={22} color={PRIMARY} />
        <span className="font-black text-2xl" style={{ color: TEXT }}>VULNIX</span>
      </div>
      <p className="text-sm mb-8" style={{ color: MUTED }}>
        {mode === "login" ? "Sign in to run and review security assessments." : "Create an account to start assessing authorized targets."}
      </p>

      <ErrorBanner message={error} onDismiss={() => setError("")} />

      <Card className="p-6 sm:p-7">
        <form onSubmit={submit}>
          <Label>Email</Label>
          <input
            type="email" required value={email} onChange={(e) => setEmail(e.target.value)}
            placeholder="you@example.com"
            className="w-full rounded-xl px-4 py-3 text-sm outline-none border mb-4"
            style={{ background: "#FFFFFF", borderColor: CARD_BORDER, color: TEXT }}
          />
          <Label>Password</Label>
          <div className="relative mb-2">
            <input
              type={showPw ? "text" : "password"} required minLength={8} value={password} onChange={(e) => setPassword(e.target.value)}
              placeholder="At least 8 characters"
              className="w-full rounded-xl px-4 py-3 text-sm outline-none border pr-11"
              style={{ background: "#FFFFFF", borderColor: CARD_BORDER, color: TEXT }}
            />
            <button type="button" onClick={() => setShowPw(!showPw)} className="absolute right-3 top-1/2 -translate-y-1/2" tabIndex={-1}>
              {showPw ? <EyeOff size={16} color={MUTED} /> : <Eye size={16} color={MUTED} />}
            </button>
          </div>

          <PrimaryButton type="submit" disabled={loading} className="w-full mt-4 text-center">
            {loading ? <span className="flex items-center justify-center gap-2"><Loader2 size={14} className="animate-spin" /> {mode === "login" ? "SIGNING IN…" : "CREATING ACCOUNT…"}</span> : mode === "login" ? "SIGN IN" : "CREATE ACCOUNT"}
          </PrimaryButton>
        </form>

        <button
          onClick={() => { setMode(mode === "login" ? "signup" : "login"); setError(""); }}
          className="w-full text-center text-xs mt-4"
          style={{ color: PRIMARY }}
        >
          {mode === "login" ? "Need an account? Sign up" : "Already have an account? Sign in"}
        </button>
      </Card>

      <button onClick={() => setShowSettings(!showSettings)} className="text-xs mt-5" style={{ color: MUTED }}>
        {showSettings ? "Hide" : "Backend URL"} — currently {apiBase}
      </button>
      {showSettings && (
        <div className="mt-3">
          <Label>API Base URL</Label>
          <input
            value={apiBase} onChange={(e) => setApiBase(e.target.value)}
            className="w-full rounded-xl px-4 py-2.5 text-sm outline-none border"
            style={{ background: "#FFFFFF", borderColor: CARD_BORDER, color: TEXT }}
          />
          <p className="text-[11px] mt-2" style={{ color: MUTED }}>
            Point this at your running VULNIX FastAPI backend (default <code>http://localhost:8000</code>).
            Defaults to <code>VITE_API_BASE_URL</code> from your <code>.env</code> file at build time;
            this field lets you override it for this session without rebuilding.
          </p>
        </div>
      )}
    </div>
  );
}

/* ---------------------------------- landing ---------------------------------- */
function Landing({ onStartUrl, onStartZip, loading }) {
  const [target, setTarget] = useState("");
  const [zipFile, setZipFile] = useState(null);
  const [confirmed, setConfirmed] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const fileRef = useRef(null);

  const canStart = confirmed && (target.trim().length > 3 || zipFile) && !loading;

  const workflow = [
    { n: 1, label: "Discover" }, { n: 2, label: "Assess" }, { n: 3, label: "Analyze" },
    { n: 4, label: "Remediate" }, { n: 5, label: "Report" },
  ];

  const handleStart = () => {
    if (zipFile) onStartZip(zipFile, confirmed);
    else onStartUrl(target.trim(), confirmed);
  };

  return (
    <div className="max-w-6xl mx-auto px-5 sm:px-8 py-10">
      <h1 className="text-3xl sm:text-5xl font-black leading-tight mb-4" style={{ color: TEXT }}>
        Full-Spectrum Security Assessment
      </h1>
      <p className="max-w-2xl text-sm sm:text-base mb-5" style={{ color: MUTED }}>
        One URL or one ZIP. Vulnix automatically discovers the attack surface, assesses security risks, explains findings, and generates a report.
      </p>
      <Badge style={{ background: "rgba(49,170,169,0.18)", color: "#bdeeed" }}>AUTHORIZED TEST</Badge>

      <div className="grid lg:grid-cols-[1fr_320px] gap-5 mt-8">
        <Card className="p-6 sm:p-7">
          <Label>Target</Label>
          <input
            value={target}
            onChange={(e) => { setTarget(e.target.value); setZipFile(null); }}
            placeholder="https://your-app.example.com"
            className="w-full rounded-xl px-4 py-3 text-sm outline-none border"
            style={{ background: "#FFFFFF", borderColor: CARD_BORDER, color: TEXT }}
          />
          <div className="text-center text-xs my-4" style={{ color: MUTED }}>OR</div>

          <input
            ref={fileRef} type="file" accept=".zip" className="hidden"
            onChange={(e) => { if (e.target.files?.[0]) { setZipFile(e.target.files[0]); setTarget(""); } }}
          />
          <button
            onClick={() => fileRef.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
            onDragLeave={() => setDragOver(false)}
            onDrop={(e) => {
              e.preventDefault(); setDragOver(false);
              const f = e.dataTransfer.files?.[0];
              if (f) { setZipFile(f); setTarget(""); }
            }}
            className="w-full rounded-xl py-4 text-sm font-semibold transition-colors"
            style={{ background: dragOver ? PRIMARY_DARK : PRIMARY, color: "#FFFFFF" }}
          >
            {zipFile ? `Selected: ${zipFile.name} (${(zipFile.size / 1024).toFixed(0)} KB)` : "Drop project ZIP here  •  Browse files"}
          </button>

          <label className="flex items-start gap-2 mt-5 cursor-pointer select-none">
            <input type="checkbox" checked={confirmed} onChange={(e) => setConfirmed(e.target.checked)} className="mt-1" />
            <span className="text-xs" style={{ color: MUTED }}>
              I confirm I am authorized to test this target and accept scope &amp; audit logging.
            </span>
          </label>

          <div className="flex flex-col sm:flex-row sm:items-center gap-3 mt-5">
            <PrimaryButton disabled={!canStart} onClick={handleStart}>
              {loading ? <span className="flex items-center gap-2"><Loader2 size={14} className="animate-spin" /> STARTING…</span> : "START ASSESSMENT"}
            </PrimaryButton>
            <span className="text-xs" style={{ color: MUTED }}>Vulnix selects applicable security tests automatically. No manual scanner setup.</span>
          </div>
        </Card>

        <Card className="p-6">
          <Label>Automatic Coverage</Label>
          <ul className="space-y-3">
            {["Web & API Security", "Network & Ports", "Source & Dependencies", "SSL / Headers / Auth", "Risk & Remediation", "Reports & Retest"].map((c) => (
              <li key={c} className="flex items-center gap-2 text-sm" style={{ color: TEXT }}>
                <CheckCircle2 size={15} color={PRIMARY} /> {c}
              </li>
            ))}
          </ul>
        </Card>
      </div>

      <Card className="p-6 mt-5">
        <Label>Vulnix Workflow</Label>
        <div className="flex flex-col sm:flex-row gap-2 sm:items-center">
          {workflow.map((w, i) => (
            <React.Fragment key={w.n}>
              <div
                className="rounded-xl px-4 py-3 text-xs font-bold tracking-wide flex-1 text-center sm:text-left"
                style={{ background: i === 0 ? PRIMARY : "rgba(44, 44, 44, 0.08)", color: i === 0 ? "#FFFFFF" : TEXT }}
              >
                {w.n} {w.label.toUpperCase()}
              </div>
              {i < workflow.length - 1 && <ArrowRight size={16} className="hidden sm:block shrink-0" color={MUTED} />}
            </React.Fragment>
          ))}
        </div>
      </Card>
    </div>
  );
}

/* ---------------------------------- progress ---------------------------------- */
function ProgressView({ target, live, onStop, stopping }) {
  const phaseIdx = Math.max(0, PHASES.indexOf(live.phase));
  const liveOrder = [["critical", "Critical"], ["high", "High"], ["medium", "Medium"], ["low", "Low"]];
  const maxLive = Math.max(1, ...Object.values(live.counts || {}));

  return (
    <div className="max-w-6xl mx-auto px-5 sm:px-8 py-10">
      <h1 className="text-2xl sm:text-3xl font-black mb-1" style={{ color: TEXT }}>Assessment in progress</h1>
      <p className="text-sm mb-8" style={{ color: MUTED }}>Scanning your authorized target and building the security model.</p>

      <div className="grid lg:grid-cols-[1fr_300px] gap-5">
        <Card className="p-6 sm:p-7">
          <Label>Current Assessment</Label>
          <div className="text-lg font-semibold mb-4 break-all" style={{ color: TEXT }}>{target}</div>
          <div className="w-full h-2 rounded-full mb-1" style={{ background: "rgba(44, 44, 44, 0.10)" }}>
            <div className="h-2 rounded-full transition-all" style={{ width: `${live.progress}%`, background: PRIMARY }} />
          </div>
          <div className="text-right text-xs font-semibold mb-6" style={{ color: TEXT }}>{live.progress}%</div>

          <div className="space-y-4">
            {PHASES.map((p, i) => {
              const status = live.status === "completed" || i < phaseIdx ? "Completed" : i === phaseIdx ? "Running" : "Queued";
              const color = status === "Completed" ? "#5FC48D" : status === "Running" ? PRIMARY : MUTED;
              return (
                <div key={p} className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    {status === "Running" ? <Loader2 size={14} className="animate-spin" color={color} /> : <Circle size={10} fill={color} color={color} />}
                    <span className="text-sm" style={{ color: TEXT }}>{p}</span>
                  </div>
                  <span className="text-xs font-semibold" style={{ color }}>{status}</span>
                </div>
              );
            })}
          </div>
        </Card>

        <Card className="p-6">
          <Label>Live Findings</Label>
          <div className="space-y-4">
            {liveOrder.map(([k, label]) => (
              <div key={k}>
                <div className="flex items-baseline gap-2 mb-1">
                  <span className="text-xl font-black" style={{ color: TEXT }}>{live.counts?.[k] || 0}</span>
                  <span className="text-xs" style={{ color: MUTED }}>{label}</span>
                </div>
                <div className="w-full h-1.5 rounded-full" style={{ background: "rgba(44, 44, 44, 0.10)" }}>
                  <div className="h-1.5 rounded-full" style={{ width: `${((live.counts?.[k] || 0) / maxLive) * 100}%`, background: SEV[k].color }} />
                </div>
              </div>
            ))}
          </div>
        </Card>
      </div>

      <GhostButton className="mt-6" onClick={onStop} disabled={stopping}>
        {stopping ? "STOPPING…" : "STOP ASSESSMENT"}
      </GhostButton>
    </div>
  );
}

/* ---------------------------------- dashboard ---------------------------------- */
function Dashboard({ assessment, onNew }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  assessment.findings.forEach((f) => counts[f.severity]++);

  const stats = [
    { label: "Security Score", value: `${assessment.score}/100`, sub: assessment.risk },
    { label: "Assets Discovered", value: assessment.assets_discovered, sub: "Endpoints + services" },
    { label: "Findings", value: assessment.findings.length, sub: `${counts.critical} critical · ${counts.high} high` },
    { label: "Tests Run", value: assessment.tests_run, sub: "Automated checks" },
  ];
  const recent = [...assessment.findings].sort((a, b) => SEV[b.severity].weight - SEV[a.severity].weight).slice(0, 4);

  return (
    <div className="max-w-6xl mx-auto px-5 sm:px-8 py-10">
      <div className="flex items-start justify-between flex-wrap gap-3 mb-8">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black mb-1" style={{ color: TEXT }}>Security posture</h1>
          <p className="text-sm" style={{ color: MUTED }}>Overview of your latest assessment — {assessment.target}</p>
        </div>
        <GhostButton onClick={onNew}><Plus size={14} className="inline mr-1 -mt-0.5" />New assessment</GhostButton>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-5">
        {stats.map((s) => (
          <Card key={s.label} className="p-5">
            <Label>{s.label}</Label>
            <div className="text-2xl sm:text-3xl font-black mb-1" style={{ color: TEXT }}>{s.value}</div>
            <div className="text-xs" style={{ color: MUTED }}>{s.sub}</div>
          </Card>
        ))}
      </div>

      <div className="grid lg:grid-cols-[1fr_300px] gap-5">
        <Card className="p-6 sm:p-7">
          <Label>Security Posture</Label>
          <div className="flex items-baseline gap-2 mb-1">
            <span className="text-5xl font-black" style={{ color: TEXT }}>{assessment.score}</span>
            <span className="text-lg" style={{ color: MUTED }}>/ 100</span>
          </div>
          <div className="text-xs font-bold uppercase tracking-wide mb-6" style={{ color: PRIMARY }}>{assessment.risk}</div>

          <div className="space-y-4">
            {CATEGORIES.map((c) => (
              <div key={c} className="flex items-center gap-4">
                <span className="text-sm w-40 shrink-0" style={{ color: TEXT }}>{c}</span>
                <div className="flex-1 h-2 rounded-full" style={{ background: "rgba(44, 44, 44, 0.10)" }}>
                  <div className="h-2 rounded-full" style={{ width: `${assessment.category_scores?.[c] ?? 100}%`, background: PRIMARY }} />
                </div>
                <span className="text-xs w-8 text-right" style={{ color: MUTED }}>{assessment.category_scores?.[c] ?? 100}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-6">
          <Label>Recent Findings</Label>
          {recent.length === 0 ? (
            <p className="text-sm" style={{ color: MUTED }}>No findings — nothing raised on this assessment.</p>
          ) : (
            <div className="space-y-4">
              {recent.map((f) => (
                <div key={f.id}>
                  <div className="text-sm font-medium mb-0.5" style={{ color: TEXT }}>{f.title}</div>
                  <SeverityTag sev={f.severity} />
                </div>
              ))}
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}

/* ---------------------------------- findings ---------------------------------- */
function Findings({ assessment, onOpen }) {
  const [q, setQ] = useState("");
  const [filter, setFilter] = useState("All");

  const filtered = assessment.findings.filter((f) => {
    const matchesFilter = filter === "All" || f.severity === filter.toLowerCase();
    const matchesQ = f.title.toLowerCase().includes(q.toLowerCase()) || f.asset.toLowerCase().includes(q.toLowerCase());
    return matchesFilter && matchesQ;
  });

  return (
    <div className="max-w-6xl mx-auto px-5 sm:px-8 py-10">
      <h1 className="text-2xl sm:text-3xl font-black mb-1" style={{ color: TEXT }}>Findings</h1>
      <p className="text-sm mb-6" style={{ color: MUTED }}>Prioritized vulnerabilities discovered during the assessment.</p>

      <Card className="p-4 sm:p-5 mb-5">
        <div className="flex flex-col sm:flex-row gap-3 sm:items-center">
          <div className="flex items-center gap-2 rounded-xl px-3 py-2 flex-1 border" style={{ borderColor: CARD_BORDER, background: "#FFFFFF" }}>
            <Search size={15} color={MUTED} />
            <input value={q} onChange={(e) => setQ(e.target.value)} placeholder="Search findings..." className="bg-transparent outline-none text-sm w-full" style={{ color: TEXT }} />
          </div>
          <div className="flex gap-2 flex-wrap">
            {["All", "Critical", "High", "Medium", "Low"].map((f) => (
              <button
                key={f} onClick={() => setFilter(f)}
                className="rounded-full px-4 py-2 text-xs font-semibold border"
                style={{ background: filter === f ? PRIMARY : "transparent", borderColor: filter === f ? PRIMARY : CARD_BORDER, color: filter === f ? "#FFFFFF" : TEXT }}
              >
                {f}
              </button>
            ))}
          </div>
        </div>
      </Card>

      <Card className="overflow-hidden">
        <div className="hidden sm:grid grid-cols-[2fr_1.4fr_0.8fr_0.6fr_0.8fr] gap-3 px-5 py-3 text-[11px] uppercase tracking-widest border-b" style={{ color: MUTED, borderColor: CARD_BORDER }}>
          <span>Finding</span><span>Asset</span><span>Severity</span><span>CVSS</span><span>Status</span>
        </div>
        {assessment.findings.length === 0 && (
          <div className="p-6 text-sm" style={{ color: MUTED }}>No findings were raised in this assessment — clean result.</div>
        )}
        {assessment.findings.length > 0 && filtered.length === 0 && (
          <div className="p-6 text-sm" style={{ color: MUTED }}>No findings match your search.</div>
        )}
        {filtered.map((f) => (
          <button
            key={f.id} onClick={() => onOpen(f.id)}
            className="w-full text-left grid sm:grid-cols-[2fr_1.4fr_0.8fr_0.6fr_0.8fr] gap-1 sm:gap-3 px-5 py-4 border-b last:border-0 hover:bg-white/5 transition-colors"
            style={{ borderColor: CARD_BORDER }}
          >
            <span className="text-sm font-medium" style={{ color: TEXT }}>{f.title}</span>
            <span className="text-sm" style={{ color: MUTED }}>{f.asset}</span>
            <span><SeverityTag sev={f.severity} /></span>
            <span className="text-sm" style={{ color: TEXT }}>{f.cvss}</span>
            <span className="text-sm" style={{ color: f.status === "Open" ? MUTED : f.status === "Fixed" ? "#5FC48D" : GOLD }}>{f.status}</span>
          </button>
        ))}
      </Card>
    </div>
  );
}

/* ---------------------------------- finding detail ---------------------------------- */
function FindingDetail({ finding, onBack, onRetest, retesting }) {
  return (
    <div className="max-w-4xl mx-auto px-5 sm:px-8 py-10">
      <button onClick={onBack} className="flex items-center gap-2 text-sm mb-6" style={{ color: MUTED }}>
        <ArrowLeft size={15} /> Back to findings
      </button>

      <div className="flex items-start justify-between flex-wrap gap-3 mb-2">
        <h1 className="text-2xl sm:text-3xl font-black" style={{ color: TEXT }}>{finding.title}</h1>
        <SeverityTag sev={finding.severity} />
      </div>
      <p className="text-sm mb-6" style={{ color: MUTED }}>{finding.asset} · CVSS {finding.cvss} · {finding.category}</p>

      <div className="grid sm:grid-cols-3 gap-4 mb-5">
        <Card className="p-4"><Label>Status</Label><div className="text-sm font-semibold" style={{ color: TEXT }}>{finding.status}</div></Card>
        <Card className="p-4"><Label>CVSS</Label><div className="text-sm font-semibold" style={{ color: TEXT }}>{finding.cvss}</div></Card>
        <Card className="p-4"><Label>Category</Label><div className="text-sm font-semibold" style={{ color: TEXT }}>{finding.category}</div></Card>
      </div>

      <Card className="p-6 mb-4">
        <Label>Description</Label>
        <p className="text-sm mb-5" style={{ color: TEXT }}>{finding.description}</p>
        <Label>Impact</Label>
        <p className="text-sm mb-5" style={{ color: TEXT }}>{finding.impact}</p>
        <Label>Evidence</Label>
        <pre className="text-xs rounded-xl p-4 overflow-x-auto whitespace-pre-wrap" style={{ background: "#232323", color: "#c9c9c9", border: `1px solid ${CARD_BORDER}` }}>
          {finding.evidence}
        </pre>
      </Card>

      <Card className="p-6 mb-6">
        <Label>Remediation</Label>
        <ul className="space-y-2">
          {finding.remediation.map((r, i) => (
            <li key={i} className="flex items-start gap-2 text-sm" style={{ color: TEXT }}>
              <CheckCircle2 size={14} color={PRIMARY} className="mt-0.5 shrink-0" /> {r}
            </li>
          ))}
        </ul>
      </Card>

      <PrimaryButton onClick={onRetest} disabled={retesting}>
        {retesting ? <span className="flex items-center gap-2"><Loader2 size={14} className="animate-spin" /> RETESTING…</span> : <span className="flex items-center gap-2"><RotateCcw size={14} /> RETEST FINDING</span>}
      </PrimaryButton>
    </div>
  );
}

/* ---------------------------------- report ---------------------------------- */
function Report({ assessment, onExport, exporting }) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0 };
  assessment.findings.forEach((f) => counts[f.severity]++);
  const fixed = assessment.findings.filter((f) => f.status === "Fixed").length;
  const retesting = assessment.findings.filter((f) => f.status === "Retesting").length;
  const open = assessment.findings.length - fixed - retesting;
  const pct = assessment.findings.length ? Math.round((fixed / assessment.findings.length) * 100) : 0;

  const summary = assessment.findings.length === 0
    ? "No findings were raised against this target. Re-run periodically to catch regressions."
    : `${assessment.findings.length} findings across ${assessment.assets_discovered} discovered assets. Prioritize ${counts.critical > 0 ? "critical issues, " : ""}${counts.high > 0 ? "high-severity findings, " : ""}and exposed services before production deployment.`;

  return (
    <div className="max-w-6xl mx-auto px-5 sm:px-8 py-10">
      <h1 className="text-2xl sm:text-3xl font-black mb-1" style={{ color: TEXT }}>Assessment report</h1>
      <p className="text-sm mb-6" style={{ color: MUTED }}>Executive summary and technical evidence for your authorized target.</p>

      <Card className="p-6 sm:p-7 mb-5">
        <Label>Executive Summary</Label>
        <div className="flex flex-col sm:flex-row sm:items-center gap-4">
          <div>
            <div className="text-4xl font-black" style={{ color: TEXT }}>{assessment.score}/100</div>
            <div className="text-xs font-bold uppercase" style={{ color: PRIMARY }}>{assessment.risk}</div>
          </div>
          <p className="text-sm sm:pl-6 sm:border-l" style={{ color: MUTED, borderColor: CARD_BORDER }}>{summary}</p>
        </div>
      </Card>

      <div className="grid sm:grid-cols-3 gap-5">
        <Card className="p-5">
          <Label>Findings by Severity</Label>
          <div className="space-y-2 mt-2">
            {["critical", "high", "medium", "low"].map((s) => (
              <div key={s} className="flex justify-between text-sm">
                <span style={{ color: TEXT }}>{SEV[s].label}</span>
                <span className="font-bold" style={{ color: TEXT }}>{counts[s]}</span>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-5">
          <Label>Remediation Progress</Label>
          <div className="text-3xl font-black mb-2" style={{ color: TEXT }}>{pct}%</div>
          <div className="w-full h-2 rounded-full mb-2" style={{ background: "rgba(44, 44, 44, 0.10)" }}>
            <div className="h-2 rounded-full" style={{ width: `${pct}%`, background: "#5FC48D" }} />
          </div>
          <div className="text-xs" style={{ color: MUTED }}>{fixed} fixed · {open} open · {retesting} retest</div>
        </Card>

        <Card className="p-5">
          <Label>Export</Label>
          <div className="flex flex-col gap-2 mt-1">
            <PrimaryButton onClick={() => onExport("pdf")} disabled={exporting === "pdf"} className="!py-2.5 text-center">
              {exporting === "pdf" ? "PREPARING…" : "DOWNLOAD PDF"}
            </PrimaryButton>
            <SecondaryButton onClick={() => onExport("json")} disabled={exporting === "json"} className="text-center">
              {exporting === "json" ? "PREPARING…" : "EXPORT JSON"}
            </SecondaryButton>
            <GhostButton onClick={() => onExport("csv")} disabled={exporting === "csv"} className="text-center">
              {exporting === "csv" ? "PREPARING…" : "EXPORT CSV"}
            </GhostButton>
          </div>
        </Card>
      </div>
    </div>
  );
}

/* ---------------------------------- history ---------------------------------- */
function History({ items, loading, onOpen, onNew }) {
  return (
    <div className="max-w-6xl mx-auto px-5 sm:px-8 py-10">
      <div className="flex items-start justify-between flex-wrap gap-3 mb-6">
        <div>
          <h1 className="text-2xl sm:text-3xl font-black mb-1" style={{ color: TEXT }}>Assessment history</h1>
          <p className="text-sm" style={{ color: MUTED }}>Previous targets, scores, and status.</p>
        </div>
        <PrimaryButton onClick={onNew}>NEW ASSESSMENT</PrimaryButton>
      </div>

      <Card className="overflow-hidden">
        <div className="hidden sm:grid grid-cols-[2fr_1.3fr_0.8fr_0.8fr_0.8fr] gap-3 px-5 py-3 text-[11px] uppercase tracking-widest border-b" style={{ color: MUTED, borderColor: CARD_BORDER }}>
          <span>Target</span><span>Date</span><span>Score</span><span>Findings</span><span>Status</span>
        </div>
        {loading && <Spinner label="Loading assessment history…" />}
        {!loading && items.length === 0 && <div className="p-6 text-sm" style={{ color: MUTED }}>No assessments yet.</div>}
        {!loading && items.map((a) => (
          <button
            key={a.id} onClick={() => onOpen(a.id)}
            className="w-full text-left grid sm:grid-cols-[2fr_1.3fr_0.8fr_0.8fr_0.8fr] gap-1 px-5 py-4 border-b last:border-0 hover:bg-white/5 transition-colors"
            style={{ borderColor: CARD_BORDER }}
          >
            <span className="text-sm font-medium break-all" style={{ color: TEXT }}>{a.target}</span>
            <span className="text-sm" style={{ color: MUTED }}>{new Date(a.created_at).toLocaleDateString()}</span>
            <span className="text-sm font-bold" style={{ color: TEXT }}>{a.score != null ? `${a.score}/100` : "—"}</span>
            <span className="text-sm" style={{ color: MUTED }}>{a.finding_count}</span>
            <span className="text-sm" style={{ color: a.status === "failed" ? DANGER : a.status === "completed" ? PRIMARY : GOLD }}>
              {a.status === "completed" ? (a.risk || "Completed") : a.status}
            </span>
          </button>
        ))}
      </Card>
    </div>
  );
}

/* ---------------------------------- empty state ---------------------------------- */
function Empty({ onNew, label }) {
  return (
    <div className="max-w-2xl mx-auto px-5 sm:px-8 py-24 text-center">
      <Shield size={36} color={PRIMARY} className="mx-auto mb-4" />
      <h2 className="text-xl font-bold mb-2" style={{ color: TEXT }}>No assessment yet</h2>
      <p className="text-sm mb-6" style={{ color: MUTED }}>Start an assessment to see {label}.</p>
      <PrimaryButton onClick={onNew}>START ASSESSMENT</PrimaryButton>
    </div>
  );
}

/* ---------------------------------- root app ---------------------------------- */
export default function App() {
  const [apiBase, setApiBase] = useState(import.meta.env.VITE_API_BASE_URL || "http://localhost:8000");
  const [token, setToken] = useState(null);
  const [userEmail, setUserEmail] = useState(null);

  const [view, setViewRaw] = useState("auth");
  const [globalError, setGlobalError] = useState("");

  const [history, setHistory] = useState([]);
  const [historyLoading, setHistoryLoading] = useState(false);

  const [current, setCurrent] = useState(null); // full AssessmentOut
  const [assessmentLoading, setAssessmentLoading] = useState(false);

  const [pendingId, setPendingId] = useState(null);
  const [pendingTarget, setPendingTarget] = useState("");
  const [live, setLive] = useState({ status: "queued", phase: "", progress: 0, counts: { critical: 0, high: 0, medium: 0, low: 0 } });
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);

  const [selectedFindingId, setSelectedFindingId] = useState(null);
  const [retestingId, setRetestingId] = useState(null);
  const [exporting, setExporting] = useState(null);

  const unsubscribeRef = useRef(null);

  const isAuthed = !!token;

  const requireAuth = (fn) => (...args) => {
    if (!token) { setViewRaw("auth"); return; }
    return fn(...args);
  };

  const handleApiError = (err) => {
    if (err.status === 401) {
      setToken(null);
      setUserEmail(null);
      setCurrent(null);
      setHistory([]);
      setViewRaw("auth");
      setGlobalError("Your session expired. Please sign in again.");
    } else {
      setGlobalError(err.message || "Something went wrong.");
    }
  };

  const goTo = (v) => {
    setGlobalError("");
    if (["dashboard", "findings", "report", "history"].includes(v) && !token) {
      setViewRaw("auth");
      return;
    }
    setSelectedFindingId(null);
    setViewRaw(v);
  };

  const fetchHistory = async (tok) => {
    setHistoryLoading(true);
    try {
      const data = await apiRequest(apiBase, "/assessments", tok);
      setHistory(data);
    } catch (err) {
      handleApiError(err);
    } finally {
      setHistoryLoading(false);
    }
  };

  const onAuthed = (tok, email) => {
    setToken(tok);
    setUserEmail(email);
    setGlobalError("");
    setViewRaw("landing");
    fetchHistory(tok);
  };

  const onLogout = () => {
    if (unsubscribeRef.current) unsubscribeRef.current();
    setToken(null);
    setUserEmail(null);
    setCurrent(null);
    setHistory([]);
    setPendingId(null);
    setViewRaw("auth");
  };

  const beginProgressTracking = (assessmentId, targetLabel, tok) => {
    setPendingId(assessmentId);
    setPendingTarget(targetLabel);
    setLive({ status: "queued", phase: "", progress: 0, counts: { critical: 0, high: 0, medium: 0, low: 0 } });
    setViewRaw("progress");

    if (unsubscribeRef.current) unsubscribeRef.current();
    unsubscribeRef.current = subscribeProgress(
      apiBase, tok, assessmentId,
      (update) => setLive((prev) => ({ ...prev, ...update })),
      (finalAssessment) => {
        setCurrent(finalAssessment);
        setPendingId(null);
        if (finalAssessment.status === "completed") {
          fetchHistory(tok);
          setViewRaw("dashboard");
        } else {
          setGlobalError(finalAssessment.error || `Assessment ${finalAssessment.status}.`);
          setViewRaw("landing");
        }
      },
      (err) => {
        handleApiError(err);
        setPendingId(null);
        setViewRaw("landing");
      }
    );
  };

  const startUrlAssessment = requireAuth(async (target, authorized) => {
    setGlobalError("");
    setStarting(true);
    try {
      const data = await apiRequest(apiBase, "/assessments/url", token, {
        method: "POST",
        body: { target, authorized },
      });
      beginProgressTracking(data.id, data.target, token);
    } catch (err) {
      handleApiError(err);
    } finally {
      setStarting(false);
    }
  });

  const startZipAssessment = requireAuth(async (file, authorized) => {
    setGlobalError("");
    setStarting(true);
    try {
      const form = new FormData();
      form.append("file", file);
      form.append("authorized", authorized ? "true" : "false");
      const data = await apiRequest(apiBase, "/assessments/zip", token, { method: "POST", body: form });
      beginProgressTracking(data.id, data.target, token);
    } catch (err) {
      handleApiError(err);
    } finally {
      setStarting(false);
    }
  });

  const stopAssessment = async () => {
    if (!pendingId) return;
    setStopping(true);
    try {
      await apiRequest(apiBase, `/assessments/${pendingId}/stop`, token, { method: "POST" });
    } catch (err) {
      handleApiError(err);
    } finally {
      setStopping(false);
    }
  };

  const openFromHistory = requireAuth(async (id) => {
    setGlobalError("");
    setAssessmentLoading(true);
    setViewRaw("dashboard");
    try {
      const data = await apiRequest(apiBase, `/assessments/${id}`, token);
      setCurrent(data);
    } catch (err) {
      handleApiError(err);
    } finally {
      setAssessmentLoading(false);
    }
  });

  const retestFinding = async (findingId) => {
    setRetestingId(findingId);
    setGlobalError("");
    try {
      const result = await apiRequest(apiBase, `/findings/${findingId}/retest`, token, { method: "POST" });
      setCurrent((c) => ({
        ...c,
        findings: c.findings.map((f) => (f.id === findingId ? { ...f, status: result.status } : f)),
      }));
    } catch (err) {
      handleApiError(err);
    } finally {
      setRetestingId(null);
    }
  };

  const exportReport = async (format) => {
    if (!current) return;
    setExporting(format);
    setGlobalError("");
    try {
      await downloadReport(apiBase, token, current.id, format);
    } catch (err) {
      setGlobalError(err.message || "Export failed.");
    } finally {
      setExporting(null);
    }
  };

  useEffect(() => () => { if (unsubscribeRef.current) unsubscribeRef.current(); }, []);

  const selectedFinding = current?.findings.find((f) => f.id === selectedFindingId);

  return (
    <div className="min-h-screen relative" style={{ background: BG, fontFamily: "Inter, system-ui, sans-serif" }}>
      <NavBar view={view} goTo={goTo} isAuthed={isAuthed} userEmail={userEmail} onLogout={onLogout} />

      <div className="max-w-6xl mx-auto px-5 sm:px-8 pt-5">
        <ErrorBanner message={globalError} onDismiss={() => setGlobalError("")} />
      </div>

      {view === "auth" && <AuthScreen apiBase={apiBase} setApiBase={setApiBase} onAuthed={onAuthed} />}

      {view === "landing" && isAuthed && (
        <Landing onStartUrl={startUrlAssessment} onStartZip={startZipAssessment} loading={starting} />
      )}

      {view === "progress" && pendingId && (
        <ProgressView target={pendingTarget} live={live} onStop={stopAssessment} stopping={stopping} />
      )}

      {view === "dashboard" && isAuthed && (
        assessmentLoading ? <Spinner label="Loading assessment…" /> :
          current ? <Dashboard assessment={current} onNew={() => goTo("landing")} /> :
            <Empty onNew={() => goTo("landing")} label="your security dashboard" />
      )}

      {view === "findings" && isAuthed && (
        assessmentLoading ? <Spinner label="Loading assessment…" /> :
          current ? (
            selectedFinding ? (
              <FindingDetail
                finding={selectedFinding}
                onBack={() => setSelectedFindingId(null)}
                onRetest={() => retestFinding(selectedFinding.id)}
                retesting={retestingId === selectedFinding.id}
              />
            ) : (
              <Findings assessment={current} onOpen={setSelectedFindingId} />
            )
          ) : <Empty onNew={() => goTo("landing")} label="findings" />
      )}

      {view === "report" && isAuthed && (
        assessmentLoading ? <Spinner label="Loading assessment…" /> :
          current ? <Report assessment={current} onExport={exportReport} exporting={exporting} /> :
            <Empty onNew={() => goTo("landing")} label="a report" />
      )}

      {view === "history" && isAuthed && (
        <History items={history} loading={historyLoading} onOpen={openFromHistory} onNew={() => goTo("landing")} />
      )}

      <div className="text-center text-[11px] py-8 flex items-center justify-center gap-2" style={{ color: MUTED }}>
        {!isAuthed && <WifiOff size={12} />}
        VULNIX runs assessments only against targets you have confirmed authorization to test.
      </div>
    </div>
  );
}
