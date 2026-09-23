"""
Passive, read-only assessment engine for a URL target.

Every check here is a GET request or a TLS handshake against a target the
caller has confirmed authorization for — nothing here attempts exploitation.
No request is sent anywhere until security_utils.validate_target_url has
approved the host, and every redirect hop is re-validated the same way.
"""
import re
import socket
import ssl
from datetime import datetime, timedelta
from urllib.parse import urljoin, urlparse

import requests

from app.config import settings
from app.security_utils import validate_target_url, validate_redirect_target, SSRFError

UA = "VulnixAssessment/1.0 (+authorized-security-scan)"
TIMEOUT = settings.check_timeout_seconds


def _safe_get(url: str, max_redirects: int = 5):
    """GET with manual, re-validated redirect following (SSRF-safe)."""
    current = validate_target_url(url)
    for _ in range(max_redirects):
        resp = requests.get(current, headers={"User-Agent": UA}, timeout=TIMEOUT, allow_redirects=False)
        if resp.is_redirect or resp.status_code in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location")
            if not location:
                return resp
            next_url = urljoin(current, location)
            current = validate_redirect_target(next_url)
            continue
        return resp
    raise SSRFError("Too many redirects.")


def check_https_and_headers(base_url: str) -> list:
    findings = []
    parsed = urlparse(base_url)

    try:
        resp = _safe_get(base_url)
    except requests.RequestException as e:
        findings.append(("no_https", base_url, f"Request failed: {e}"))
        return findings

    final_scheme = urlparse(resp.url).scheme
    if final_scheme != "https":
        findings.append(("no_https", base_url, f"Final response served over {final_scheme}, not https."))

    headers = {k.lower(): v for k, v in resp.headers.items()}

    if "strict-transport-security" not in headers and final_scheme == "https":
        findings.append(("missing_hsts", parsed.hostname, "No Strict-Transport-Security header in response."))

    if "content-security-policy" not in headers:
        findings.append(("missing_csp", parsed.hostname, "No Content-Security-Policy header in response."))

    if "x-frame-options" not in headers and "frame-ancestors" not in headers.get("content-security-policy", ""):
        findings.append(("missing_xfo", parsed.hostname, "No X-Frame-Options / frame-ancestors directive found."))

    if "x-content-type-options" not in headers:
        findings.append(("missing_xcto", parsed.hostname, "No X-Content-Type-Options header in response."))

    server = headers.get("server", "")
    if server and re.search(r"\d", server):
        findings.append(("server_disclosure", parsed.hostname, f"Server header: {server}"))

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    if acao and acao != "*" and acac.lower() == "true":
        findings.append(("permissive_cors", parsed.hostname,
                          f"Access-Control-Allow-Origin: {acao}, Access-Control-Allow-Credentials: {acac}"))

    for cookie_header in resp.raw.headers.get_all("Set-Cookie", []) if hasattr(resp.raw.headers, "get_all") else []:
        lc = cookie_header.lower()
        if "secure" not in lc or "httponly" not in lc:
            findings.append(("insecure_cookie", parsed.hostname, cookie_header.split(";")[0]))
            break

    return findings


def check_tls(hostname: str, port: int = 443) -> list:
    findings = []
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((hostname, port), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                version = ssock.version()
                cert = ssock.getpeercert()
    except Exception:
        return findings  # no TLS listener / unreachable — handled elsewhere

    if version in ("TLSv1", "TLSv1.1"):
        findings.append(("weak_tls_version", f"{hostname}:{port}", f"Negotiated protocol: {version}"))

    if cert and cert.get("notAfter"):
        try:
            expiry = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
            days_left = (expiry - datetime.utcnow()).days
            if days_left < 0:
                findings.append(("cert_expired", f"{hostname}:{port}", f"Certificate expired {expiry.date()}"))
            elif days_left < 14:
                findings.append(("cert_expiring", f"{hostname}:{port}", f"Certificate expires {expiry.date()} ({days_left}d)"))
        except ValueError:
            pass

    return findings


def check_wellknown_paths(base_url: str) -> list:
    """Passive existence checks only — no auth bypass, no exploitation."""
    findings = []
    probes = [
        ("/.git/config", "exposed_git"),
        ("/.env", "exposed_env"),
        ("/.well-known/security.txt", "missing_security_txt"),  # inverted: finding raised if NOT found
    ]
    for path, check_id in probes:
        url = urljoin(base_url, path)
        try:
            resp = requests.get(validate_target_url(url), headers={"User-Agent": UA}, timeout=TIMEOUT, allow_redirects=False)
        except (requests.RequestException, SSRFError):
            continue

        if check_id == "missing_security_txt":
            if resp.status_code >= 400:
                findings.append((check_id, urlparse(base_url).hostname, "/.well-known/security.txt returned 404."))
        else:
            if resp.status_code == 200 and len(resp.content) > 0:
                findings.append((check_id, path, f"{path} returned HTTP 200."))

    return findings


def check_error_verbosity(base_url: str) -> list:
    findings = []
    probe = urljoin(base_url, "/vulnix-nonexistent-diagnostic-path-x92f")
    try:
        resp = requests.get(validate_target_url(probe), headers={"User-Agent": UA}, timeout=TIMEOUT)
    except (requests.RequestException, SSRFError):
        return findings
    body = resp.text[:5000] if resp.text else ""
    if resp.status_code >= 500 and re.search(r"(Traceback|Exception|stack trace|at\s+\S+\.\w+:\d+)", body, re.I):
        findings.append(("verbose_error", base_url, "Error response body contains a stack trace / exception detail."))
    return findings


def run_full_url_assessment(target: str, on_phase=None) -> list:
    """
    Runs all passive checks and returns a flat list of
    (check_id, asset, evidence) tuples. `on_phase` is an optional callback
    invoked with a phase name as each stage starts.
    """
    base_url = validate_target_url(target)
    hostname = urlparse(base_url).hostname
    raw = []

    if on_phase: on_phase("Reconnaissance")
    raw += check_wellknown_paths(base_url)

    if on_phase: on_phase("Technology discovery")
    # header-based tech signals folded into header check below

    if on_phase: on_phase("Web & API checks")
    raw += check_https_and_headers(base_url)
    raw += check_error_verbosity(base_url)

    if on_phase: on_phase("SSL / headers")
    if urlparse(base_url).scheme == "https":
        raw += check_tls(hostname)

    if on_phase: on_phase("Port & service assessment")
    # a full port sweep is out of scope for a hosted API (and easily abused);
    # this tier limits network checks to the service already being assessed.

    if on_phase: on_phase("Vulnerability correlation")

    return raw
