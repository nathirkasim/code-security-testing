import hashlib
import hmac
import os
import secrets
from pathlib import Path
from typing import List, Tuple
from urllib.parse import urlparse


def hash_password(password: str) -> Tuple[str, str]:
    """
    Hashes a password using PBKDF2-HMAC-SHA256 with a cryptographically secure salt.
    Returns (salt_hex, hash_hex).
    """
    salt = secrets.token_bytes(32)
    derived_key = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=salt,
        iterations=600_000,
    )
    return salt.hex(), derived_key.hex()


def verify_password(password: str, salt_hex: str, expected_hash_hex: str) -> bool:
    """
    Verifies a password against salt and expected hash using constant-time comparison.
    """
    try:
        salt = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(expected_hash_hex)
    except ValueError:
        return False

    derived_key = hashlib.pbkdf2_hmac(
        hash_name='sha256',
        password=password.encode('utf-8'),
        salt=salt,
        iterations=600_000,
    )
    return hmac.compare_digest(derived_key, expected_hash)


def generate_secure_token(bytes_count: int = 32) -> str:
    """
    Generates a cryptographically secure URL-safe token.
    """
    return secrets.token_urlsafe(bytes_count)


def safe_resolve_path(base_dir: Path, user_subpath: str) -> Path:
    """
    Canonicalizes path and verifies it remains strictly inside base_dir boundary.
    Prevents Path Traversal (CWE-22).
    """
    resolved_base = base_dir.resolve()
    target_path = (resolved_base / user_subpath).resolve()

    try:
        target_path.relative_to(resolved_base)
    except ValueError as err:
        raise PermissionError("Access denied: path traversal detected.") from err

    return target_path


def is_allowed_url(url_string: str, allowed_domains: List[str]) -> bool:
    """
    Validates scheme and host against a domain whitelist.
    Prevents SSRF (CWE-918).
    """
    parsed = urlparse(url_string)
    if parsed.scheme not in ("https", "http"):
        return False

    hostname = parsed.hostname
    if not hostname:
        return False

    return any(hostname == domain or hostname.endswith("." + domain) for domain in allowed_domains)
