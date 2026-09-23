"""
Static analysis engine for an uploaded project ZIP. Nothing extracted here
is ever executed — files are only opened as text (best-effort decode) and
pattern-matched. Extraction itself goes through security_utils.safe_extract_zip
for zip-slip / zip-bomb / symlink protection before any of this runs.
"""
import os
import re

from app.config import settings

TEXT_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go", ".rb", ".php", ".c", ".cpp",
    ".json", ".yml", ".yaml", ".env", ".ini", ".cfg", ".toml", ".txt", ".md",
}
MAX_FILE_READ_BYTES = 1_000_000

SECRET_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "AWS access key"),
    (r"sk_live_[0-9a-zA-Z]{16,}", "Stripe live secret key"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Google API key"),
    (r"-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----", "Private key material"),
    (r"(?i)(api[_-]?key|secret|password|token)\s*[:=]\s*['\"][A-Za-z0-9/+_\-]{12,}['\"]", "Generic hardcoded credential"),
]

DEBUG_PATTERNS = [
    r"(?i)DEBUG\s*=\s*True",
    r"(?i)app\.run\([^)]*debug\s*=\s*True",
    r"(?i)NODE_ENV\s*=\s*['\"]?development['\"]?",
]

SQL_CONCAT_PATTERNS = [
    r"(?i)(SELECT|INSERT|UPDATE|DELETE)\b[^;\"'\n]*['\"]\s*\+\s*\w+",
    r"(?i)f['\"](SELECT|INSERT|UPDATE|DELETE)\b.*\{[\w\.]+\}",
    r"(?i)(execute|cursor\.execute)\(\s*['\"].*%s.*['\"]\s*%",
]

UNSAFE_ZIP_PATTERNS = [
    r"(?i)extractall\(\s*\)",
    r"(?i)zipfile\.extractall\((?!.*members=)(?!.*validate)",
]

# small offline advisory sample; a production build would call OSV.dev instead
KNOWN_VULNERABLE_DEPS = {
    "lodash": [("<4.17.19", "prototype pollution")],
    "minimist": [("<1.2.6", "prototype pollution")],
    "requests": [("<2.20.0", "credential leak on redirect")],
    "django": [("<3.2.14", "SQL injection in QuerySet")],
    "flask": [("<2.2.0", "cookie parsing DoS")],
    "pyyaml": [("<5.4", "arbitrary code execution via yaml.load")],
}


def _iter_text_files(root_dir: str, relative_paths: list):
    for rel in relative_paths:
        ext = os.path.splitext(rel)[1].lower()
        base = os.path.basename(rel).lower()
        if ext not in TEXT_EXTENSIONS and base not in (".env", "dockerfile"):
            continue
        full = os.path.join(root_dir, rel)
        try:
            if os.path.getsize(full) > MAX_FILE_READ_BYTES:
                continue
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                yield rel, f.read()
        except OSError:
            continue


def _parse_version_constraint(constraint: str, installed: str) -> bool:
    """Extremely small comparator for '<x.y.z' style constraints only."""
    if not constraint.startswith("<"):
        return False
    try:
        target = tuple(int(p) for p in constraint[1:].split("."))
        current = tuple(int(p) for p in re.findall(r"\d+", installed)[:len(target)])
        return current < target
    except ValueError:
        return False


def check_secrets(root_dir: str, files: list) -> list:
    findings = []
    for rel, content in _iter_text_files(root_dir, files):
        for pattern, label in SECRET_PATTERNS:
            m = re.search(pattern, content)
            if m:
                snippet = content[max(0, m.start() - 20):m.start()] + "«match redacted»"
                findings.append(("hardcoded_secret", rel, f"{label} pattern matched in {rel}."))
                break  # one finding per file is enough signal
    return findings


def check_debug_flags(root_dir: str, files: list) -> list:
    findings = []
    for rel, content in _iter_text_files(root_dir, files):
        for pattern in DEBUG_PATTERNS:
            if re.search(pattern, content):
                findings.append(("debug_mode", rel, f"Debug-enabling pattern found in {rel}."))
                break
    return findings


def check_sql_concat(root_dir: str, files: list) -> list:
    findings = []
    for rel, content in _iter_text_files(root_dir, files):
        if os.path.splitext(rel)[1] not in (".py", ".js", ".ts", ".java", ".php", ".rb"):
            continue
        for pattern in SQL_CONCAT_PATTERNS:
            if re.search(pattern, content):
                findings.append(("sql_string_concat", rel, f"String-built SQL query pattern found in {rel}."))
                break
    return findings


def check_unsafe_zip_extract(root_dir: str, files: list) -> list:
    findings = []
    for rel, content in _iter_text_files(root_dir, files):
        if os.path.splitext(rel)[1] != ".py":
            continue
        if "zipfile" in content:
            for pattern in UNSAFE_ZIP_PATTERNS:
                if re.search(pattern, content):
                    findings.append(("unsafe_zip_extract", rel, f"Unvalidated archive extraction found in {rel}."))
                    break
    return findings


def check_dependencies(root_dir: str, files: list) -> list:
    findings = []
    manifest_readers = {
        "requirements.txt": _parse_requirements_txt,
        "package.json": _parse_package_json,
    }
    for rel in files:
        base = os.path.basename(rel)
        if base in manifest_readers:
            full = os.path.join(root_dir, rel)
            try:
                with open(full, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
            except OSError:
                continue
            for name, version in manifest_readers[base](content):
                name_l = name.lower()
                if name_l in KNOWN_VULNERABLE_DEPS:
                    for constraint, advisory in KNOWN_VULNERABLE_DEPS[name_l]:
                        if version and _parse_version_constraint(constraint, version):
                            findings.append(("outdated_dependency", rel,
                                              f"{name}=={version} matches advisory ({advisory})."))
    return findings


def _parse_requirements_txt(content: str):
    for line in content.splitlines():
        line = line.strip()
        m = re.match(r"^([A-Za-z0-9_\-\.]+)\s*==\s*([\d\.]+)", line)
        if m:
            yield m.group(1), m.group(2)


def _parse_package_json(content: str):
    import json
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        return
    for section in ("dependencies", "devDependencies"):
        for name, version in data.get(section, {}).items():
            v = re.sub(r"[^\d\.]", "", version) if version else ""
            if v:
                yield name, v


def detect_project_type(files: list) -> str:
    names = {os.path.basename(f) for f in files}
    if "package.json" in names:
        return "Node.js"
    if "requirements.txt" in names or "pyproject.toml" in names:
        return "Python"
    if "pom.xml" in names:
        return "Java (Maven)"
    if "go.mod" in names:
        return "Go"
    return "Unknown"


def run_full_zip_assessment(root_dir: str, files: list, on_phase=None) -> list:
    raw = []

    if on_phase: on_phase("Reconnaissance")
    project_type = detect_project_type(files)

    if on_phase: on_phase("Technology discovery")
    raw += check_dependencies(root_dir, files)

    if on_phase: on_phase("Web & API checks")
    raw += check_sql_concat(root_dir, files)

    if on_phase: on_phase("SSL / headers")
    # not applicable to a static archive — phase kept for a consistent timeline

    if on_phase: on_phase("Port & service assessment")
    raw += check_unsafe_zip_extract(root_dir, files)

    if on_phase: on_phase("Vulnerability correlation")
    raw += check_secrets(root_dir, files)
    raw += check_debug_flags(root_dir, files)

    return raw, project_type
