"""
Security helpers: outbound-request SSRF guarding, and safe ZIP extraction
(zip-slip / zip-bomb / symlink protection). Both are defensive controls —
the assessment engine must never let a caller-supplied target or archive
make it touch anything outside its intended sandbox.
"""
import ipaddress
import os
import socket
import stat
import zipfile
from urllib.parse import urlparse

ALLOWED_SCHEMES = {"http", "https"}

BLOCKED_HOST_SUFFIXES = (".local", ".internal", ".localhost")


class SSRFError(ValueError):
    pass


class UnsafeArchiveError(ValueError):
    pass


def _is_blocked_ip(ip_str: str) -> bool:
    ip = ipaddress.ip_address(ip_str)
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or str(ip) == "169.254.169.254"  # cloud metadata, redundant with link-local but explicit
    )


def validate_target_url(url: str) -> str:
    """
    Raises SSRFError if the URL is not a safe, public HTTP(S) target.
    Returns the normalized URL on success.
    """
    parsed = urlparse(url if "://" in url else f"https://{url}")

    if parsed.scheme not in ALLOWED_SCHEMES:
        raise SSRFError("Only http/https targets are supported.")
    if not parsed.hostname:
        raise SSRFError("Target must include a hostname.")

    host = parsed.hostname.lower()
    if host in ("localhost",) or host.endswith(BLOCKED_HOST_SUFFIXES):
        raise SSRFError("Target resolves to a local/internal hostname.")

    try:
        addrs = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise SSRFError(f"Could not resolve hostname: {host}")

    for family, _, _, _, sockaddr in addrs:
        ip_str = sockaddr[0]
        try:
            blocked = _is_blocked_ip(ip_str)
        except ValueError:
            raise SSRFError("Could not parse resolved address.")
        if blocked:
            raise SSRFError(f"Target resolves to a disallowed address ({ip_str}).")

    return parsed.geturl()


def validate_redirect_target(url: str) -> str:
    """Re-validate every hop when the engine follows redirects manually."""
    return validate_target_url(url)


# ---------------------------------------------------------------------------
# Safe ZIP extraction
# ---------------------------------------------------------------------------

def safe_extract_zip(zip_path: str, dest_dir: str, max_uncompressed_bytes: int, max_files: int) -> list:
    """
    Extracts a ZIP file defensively:
      - rejects absolute paths and any entry that resolves outside dest_dir
      - rejects symlinks
      - enforces a total uncompressed-size cap (zip-bomb protection)
      - enforces a max file-count cap
    Returns the list of extracted relative file paths.
    """
    dest_real = os.path.realpath(dest_dir)
    extracted = []
    total_size = 0

    with zipfile.ZipFile(zip_path) as zf:
        infos = zf.infolist()
        if len(infos) > max_files:
            raise UnsafeArchiveError(f"Archive contains too many files ({len(infos)} > {max_files}).")

        for info in infos:
            if info.is_dir():
                continue

            # reject symlinks: unix mode is packed into the high 16 bits of external_attr
            unix_mode = info.external_attr >> 16
            if unix_mode and stat.S_ISLNK(unix_mode):
                raise UnsafeArchiveError(f"Archive entry is a symlink, rejected: {info.filename}")

            if info.filename.startswith("/") or info.filename.startswith("\\"):
                raise UnsafeArchiveError(f"Archive entry uses an absolute path: {info.filename}")

            target_path = os.path.realpath(os.path.join(dest_real, info.filename))
            if not (target_path == dest_real or target_path.startswith(dest_real + os.sep)):
                raise UnsafeArchiveError(f"Archive entry escapes extraction directory: {info.filename}")

            total_size += info.file_size
            if total_size > max_uncompressed_bytes:
                raise UnsafeArchiveError("Archive exceeds maximum allowed uncompressed size.")

            os.makedirs(os.path.dirname(target_path), exist_ok=True)
            with zf.open(info) as src, open(target_path, "wb") as dst:
                dst.write(src.read())
            extracted.append(os.path.relpath(target_path, dest_real))

    return extracted
