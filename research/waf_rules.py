"""
Shared rule engine and request preprocessing.

This module extracts the EXACT deterministic detection logic used by the
deployed WAF (waf/app/main.py) so that offline experiments (ablation,
baselines, cross-dataset) evaluate the same rules that run in production.

Keeping this in one place is what makes the ablation study scientifically
valid: the "rules-only" arm and the deployed system use identical code.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus


# ---------------------------------------------------------------------------
# Preprocessing (mirrors preprocess_request in waf/app/main.py)
# ---------------------------------------------------------------------------
MAX_URI_LEN = 4096


def preprocess_request(method: str, uri: str) -> str:
    """Build the model input string: '<METHOD> <URI with digits masked>'."""
    uri = (uri or "")[:MAX_URI_LEN]
    uri_norm = re.sub(r"\d+", "{ID}", uri)
    return f"{(method or 'GET').upper()} {uri_norm}"


def double_url_decode(uri: str) -> str:
    return unquote_plus(unquote_plus(uri or ""))


# ---------------------------------------------------------------------------
# Rule / signature detectors (mirror waf/app/main.py)
# ---------------------------------------------------------------------------
SUSPICIOUS_KEYWORDS = [
    "union", "select", "drop", "insert", "delete", "update", "exec",
    "script", "eval", "alert", "onclick", "onerror", "onload", "passwd",
    "shadow", "or 1=1", "and 1=1", "../", "..\\", "%00", "--", ";", "|",
]

DIRECT_SIGNATURES = [
    "or 1=1", "and 1=1", "union select", "<script", "javascript:",
    "../", "..\\", "%00",
]

MAX_ALLOWED_SPECIAL_CHARS = 10

_INJECTION_PATTERNS = [
    r"('\s*(AND|OR)\s*'?[^']*'?\s*=|\bOR\b.*=|AND\s*\d+=\d+)",
    r"(UNION\s+SELECT|UNION\s+ALL|UNION\s*/\*)",
    r"(DROP|DELETE|INSERT|UPDATE|EXEC|SCRIPT)\s+",
    r"(' ;\s*(DROP|DELETE|TRUNCATE|INSERT))",
    r"([`;&|]|\|\||&&|\n|\r)\s*(cat|ls|wget|curl|bash|sh|cmd)",
    r"(<\s*script[^>]*>|javascript:|onerror\s*=|onclick\s*=|onload\s*=|eval\()",
]

_ENCODING_PATTERNS = [
    r"\\x[0-9a-f]{2}",
    r"%2e%2e|%252e%252e",
    r"%2f|%5c|%252f|%255c",
    r"%00|%2500",
    r"%3c|%3e|%22|%27|%3b|%2d%2d",
    r"\.\./|\.\\\\",
    r"&#[0-9]+;",
]


def detect_suspicious_keywords(uri: str):
    uri_lower = (uri or "").lower()
    matched = [k for k in SUSPICIOUS_KEYWORDS if k in uri_lower]
    return len(matched) > 0, matched


def detect_special_char_anomaly(uri: str):
    special = sum(1 for c in (uri or "") if c in "!@#$%^&*()[]{};<>|\\\"'-,./?=")
    return special > MAX_ALLOWED_SPECIAL_CHARS, special


def detect_encoding_attacks(uri: str) -> bool:
    return any(re.search(p, uri or "", re.IGNORECASE) for p in _ENCODING_PATTERNS)


def detect_injection_patterns(uri: str) -> bool:
    return any(re.search(p, uri or "", re.IGNORECASE) for p in _INJECTION_PATTERNS)


def rules_verdict(method: str, uri: str):
    """
    Deterministic rules-only verdict (no model).

    Returns (is_malicious: bool, reason: str). Mirrors the non-AI branches of
    evaluate_request() in waf/app/main.py.
    """
    decoded = double_url_decode(uri)
    normalized = decoded.lower()

    if any(sig in normalized for sig in DIRECT_SIGNATURES):
        return True, "direct_signature_match"

    kw_suspicious, _ = detect_suspicious_keywords(decoded)
    has_encoding = detect_encoding_attacks(uri)
    has_injection = detect_injection_patterns(decoded)
    is_char_anom, char_count = detect_special_char_anomaly(decoded)

    if kw_suspicious and has_injection:
        return True, "rule_based_sqli_xss"
    if has_encoding:
        return True, "encoding_attack"
    if is_char_anom and kw_suspicious:
        return True, f"char_anomaly_plus_keywords:{char_count}"

    return False, "rules_clean"


def rule_signals(method: str, uri: str) -> dict:
    """Expose individual rule signals for the fusion policy / feature analysis."""
    decoded = double_url_decode(uri)
    kw_suspicious, matched = detect_suspicious_keywords(decoded)
    is_char_anom, char_count = detect_special_char_anomaly(decoded)
    return {
        "keyword_suspicious": kw_suspicious,
        "matched_keywords": matched,
        "encoding_attack": detect_encoding_attacks(uri),
        "injection_pattern": detect_injection_patterns(decoded),
        "char_anomaly": is_char_anom,
        "char_count": char_count,
        "has_signal": kw_suspicious or is_char_anom
        or detect_encoding_attacks(uri) or detect_injection_patterns(decoded),
    }


def fuse_decision(method: str, uri: str, ai_prob: float,
                  tau_high: float = 0.98, tau_low: float = 0.90):
    """
    Full hybrid decision fusion (mirrors evaluate_request in main.py).

    Order: direct signatures -> rule combos -> AI-high+signal -> uncertainty band.
    Returns (is_malicious: bool, reason: str, prob: float).
    """
    decoded = double_url_decode(uri)
    normalized = decoded.lower()

    if any(sig in normalized for sig in DIRECT_SIGNATURES):
        return True, "direct_signature_match", 1.0

    sig = rule_signals(method, uri)
    if sig["keyword_suspicious"] and sig["injection_pattern"]:
        return True, "rule_based_sqli_xss", 1.0
    if sig["encoding_attack"]:
        return True, "encoding_attack", 1.0

    if ai_prob > tau_high and sig["has_signal"]:
        return True, f"ai_high_confidence:{ai_prob:.4f}", ai_prob

    if tau_low <= ai_prob < tau_high and (sig["keyword_suspicious"] or sig["char_anomaly"]):
        return True, f"uncertain_plus_anomaly:{ai_prob:.4f}", ai_prob

    if sig["char_anomaly"] and sig["keyword_suspicious"]:
        return True, "char_anomaly_plus_keywords", ai_prob

    return False, "safe", ai_prob
