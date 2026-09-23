"""
Catalog of checks the engine can raise, plus shared scoring math. Keeping
this in one place means the URL engine, ZIP engine, and report/score
calculations all agree on severity weights and remediation text.
"""

SEVERITY_WEIGHT = {"critical": 12, "high": 6, "medium": 2, "low": 0.6}

CATEGORIES = ["Web Application", "API Security", "Network Exposure", "Configuration", "Dependencies"]

CHECKS = {
    "missing_hsts": dict(
        title="Missing HSTS header", category="Configuration", severity="medium", cvss=5.1,
        description="Strict-Transport-Security is not set, so browsers do not enforce HTTPS on repeat visits.",
        impact="Users on hostile networks can be downgraded to plain HTTP on first connection and intercepted.",
        remediation=["Set Strict-Transport-Security with a long max-age and includeSubDomains.",
                     "Submit the domain to the HSTS preload list once stable."],
    ),
    "missing_csp": dict(
        title="Missing Content-Security-Policy", category="Configuration", severity="medium", cvss=5.4,
        description="No Content-Security-Policy header is present on responses.",
        impact="Increases the blast radius of any injected script by allowing arbitrary script/style/frame sources.",
        remediation=["Add a strict CSP with a nonce-based script-src.",
                     "Roll out in report-only mode before enforcing.",
                     "Inventory third-party scripts before allow-listing domains."],
    ),
    "missing_xfo": dict(
        title="Missing X-Frame-Options / frame-ancestors", category="Configuration", severity="low", cvss=3.4,
        description="No clickjacking protection header (X-Frame-Options or CSP frame-ancestors) is set.",
        impact="The page can be embedded in a hidden iframe on an attacker-controlled site.",
        remediation=["Set X-Frame-Options: DENY or a CSP frame-ancestors directive."],
    ),
    "missing_xcto": dict(
        title="Missing X-Content-Type-Options", category="Configuration", severity="low", cvss=2.9,
        description="X-Content-Type-Options: nosniff is not set.",
        impact="Browsers may MIME-sniff responses, enabling content-type confusion attacks.",
        remediation=["Set X-Content-Type-Options: nosniff on all responses."],
    ),
    "permissive_cors": dict(
        title="Overly permissive CORS policy", category="API Security", severity="high", cvss=7.5,
        description="Access-Control-Allow-Origin reflects the request origin while Allow-Credentials is true.",
        impact="A malicious site can make authenticated cross-origin requests on behalf of a logged-in user.",
        remediation=["Return an explicit allow-list of trusted origins.",
                     "Never combine a wildcard/reflected origin with allow-credentials.",
                     "Validate the Origin header server-side, not by reflection."],
    ),
    "server_disclosure": dict(
        title="Server version fingerprinting", category="Network Exposure", severity="low", cvss=2.7,
        description="The Server header discloses exact software and version.",
        impact="Simplifies identifying known vulnerabilities affecting that specific version.",
        remediation=["Suppress or generalize the Server header at the reverse proxy."],
    ),
    "insecure_cookie": dict(
        title="Cookie missing Secure/HttpOnly/SameSite", category="Web Application", severity="medium", cvss=4.9,
        description="A session-like cookie is set without Secure, HttpOnly, or SameSite attributes.",
        impact="The cookie can be read by client-side script or sent over an unencrypted channel.",
        remediation=["Set Secure, HttpOnly, and SameSite=Lax (or Strict) on session cookies."],
    ),
    "weak_tls_version": dict(
        title="Legacy TLS version supported", category="Network Exposure", severity="medium", cvss=5.9,
        description="The server accepted a handshake using TLS 1.0/1.1.",
        impact="Legacy protocol versions are vulnerable to known downgrade and padding-oracle style attacks.",
        remediation=["Disable TLS 1.0/1.1; support TLS 1.2+ only.",
                     "Prefer AEAD cipher suites (AES-GCM, ChaCha20-Poly1305)."],
    ),
    "cert_expiring": dict(
        title="TLS certificate expiring soon", category="Network Exposure", severity="medium", cvss=5.0,
        description="The presented certificate expires within 14 days.",
        impact="Certificate expiry will cause browser trust errors and outage for all clients.",
        remediation=["Renew the certificate and automate renewal (e.g. ACME/Let's Encrypt with auto-renew)."],
    ),
    "cert_expired": dict(
        title="TLS certificate expired", category="Network Exposure", severity="critical", cvss=9.0,
        description="The presented certificate has already expired.",
        impact="Clients will refuse or warn on every connection; some clients may allow it through with the risk of MITM.",
        remediation=["Issue and deploy a new certificate immediately."],
    ),
    "no_https": dict(
        title="Site served over plain HTTP", category="Network Exposure", severity="critical", cvss=8.9,
        description="The target does not redirect to, or serve over, HTTPS.",
        impact="All traffic, including credentials, is sent in the clear and can be intercepted or modified.",
        remediation=["Terminate TLS at the edge and redirect all HTTP to HTTPS.",
                     "Add HSTS once HTTPS is enforced."],
    ),
    "exposed_git": dict(
        title="Exposed .git directory", category="Configuration", severity="high", cvss=7.5,
        description="/.git/config is reachable over the web.",
        impact="Full source history, and potentially secrets committed in the past, can be reconstructed by an attacker.",
        remediation=["Remove .git from the web root in production.",
                     "Block access to dot-directories at the reverse proxy."],
    ),
    "exposed_env": dict(
        title="Exposed .env file", category="Configuration", severity="critical", cvss=9.1,
        description="/.env is reachable over the web.",
        impact="Environment files commonly contain database credentials, API keys, and signing secrets.",
        remediation=["Remove .env from the web root.", "Rotate any credentials that may have been exposed.",
                     "Block dotfile access at the reverse proxy."],
    ),
    "verbose_error": dict(
        title="Verbose server error / stack trace", category="Web Application", severity="medium", cvss=4.6,
        description="An error response included a stack trace or internal path.",
        impact="Leaks framework version and internal structure, aiding further targeted attacks.",
        remediation=["Return generic error responses in production; log details server-side only."],
    ),
    "missing_security_txt": dict(
        title="No security.txt disclosure policy", category="Configuration", severity="low", cvss=2.1,
        description="/.well-known/security.txt was not found.",
        impact="Security researchers have no documented channel to responsibly report vulnerabilities.",
        remediation=["Publish a security.txt per RFC 9116 with a contact and disclosure policy."],
    ),
    # --- source / ZIP checks ---
    "hardcoded_secret": dict(
        title="Hardcoded credential in source", category="Dependencies", severity="high", cvss=8.1,
        description="A string matching a known API-key/secret pattern was found committed in source.",
        impact="Anyone with repository or archive access can extract and reuse the credential.",
        remediation=["Revoke and rotate the exposed credential immediately.",
                     "Move secrets to environment variables or a secrets manager.",
                     "Add a pre-commit secret scanner to CI."],
    ),
    "debug_mode": dict(
        title="Debug mode enabled in configuration", category="Configuration", severity="high", cvss=7.2,
        description="A configuration file sets a debug/development flag to true.",
        impact="Debug mode commonly exposes stack traces, internal file paths, and interactive consoles to end users.",
        remediation=["Ensure debug flags are false in production builds.",
                     "Drive the flag from environment configuration, not a committed default."],
    ),
    "unsafe_zip_extract": dict(
        title="Unsafe archive extraction in source", category="Dependencies", severity="high", cvss=7.8,
        description="Source code extracts an archive without validating that entry paths stay inside the destination directory.",
        impact="A crafted archive (zip-slip) can write files outside the intended extraction directory during processing.",
        remediation=["Resolve each entry path and reject any that escape the destination directory.",
                     "Reject symlink entries and enforce size/file-count limits."],
    ),
    "sql_string_concat": dict(
        title="SQL query built via string concatenation", category="API Security", severity="high", cvss=8.2,
        description="A database query appears to be built by concatenating untrusted input directly into SQL text.",
        impact="If the concatenated value is user-controlled, this is a SQL injection vector.",
        remediation=["Use parameterized queries / prepared statements for all database access.",
                     "Apply least-privilege database credentials for the application account."],
    ),
    "outdated_dependency": dict(
        title="Dependency pinned to a known-vulnerable version", category="Dependencies", severity="medium", cvss=6.1,
        description="A manifest pins a package version matching a publicly known advisory.",
        impact="Exploitation could allow denial of service or, depending on usage, remote code execution.",
        remediation=["Upgrade to the patched release.", "Add automated dependency scanning to CI."],
    ),
}


def score_from_findings(findings: list) -> tuple:
    """findings: list of dicts/objects with a `.severity` (or ['severity'])"""
    def sev(f):
        return f["severity"] if isinstance(f, dict) else f.severity

    penalty = sum(SEVERITY_WEIGHT[sev(f)] for f in findings)
    score = max(12, min(98, round(100 - penalty)))
    if score >= 85:
        risk = "Low risk"
    elif score >= 65:
        risk = "Medium risk"
    elif score >= 40:
        risk = "High risk"
    else:
        risk = "Critical risk"
    return score, risk


def category_scores(findings: list) -> dict:
    def sev(f):
        return f["severity"] if isinstance(f, dict) else f.severity

    def cat(f):
        return f["category"] if isinstance(f, dict) else f.category

    out = {}
    for c in CATEGORIES:
        penalty = sum(SEVERITY_WEIGHT[sev(f)] for f in findings if cat(f) == c)
        out[c] = max(28, round(100 - penalty * 3.2))
    return out
