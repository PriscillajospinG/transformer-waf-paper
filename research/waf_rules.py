"""
Shared rule engine and request preprocessing.

This module holds the deterministic detection logic used by the deployed WAF
(waf/app/main.py), so offline experiments (ablation, baselines,
cross-dataset, adversarial) evaluate the same rules that run in production.

Changes for the journal experiments
-----------------------------------
* ``prepare_model_text`` builds the model input in one of three modes:
    - ``decoded``        : METHOD + double-URL-decoded URI, digits masked.
                           This is what the live service feeds the model, so
                           it is the default for training and evaluation.
    - ``raw``            : METHOD + raw URI, digits masked (the old behaviour,
                           kept for the preprocessing ablation).
    - ``decoded_nomask`` : decoded URI without digit masking (ablation).
* ``load_rules_config`` lets a JSON file extend or replace the keyword,
  signature and pattern lists, so a "refreshed" rule set can be tested
  without editing code. The live service reads the same file through the
  ``WAF_RULES_CONFIG`` environment variable.
* ``fuse_decision`` returns the name of the branch that fired, so every
  decision can be attributed to one case of the fusion rule.
"""
from __future__ import annotations

import json
import re
from urllib.parse import unquote_plus

# ---------------------------------------------------------------------------
# Preprocessing (mirrors preprocess_request in waf/app/main.py)
# ---------------------------------------------------------------------------
MAX_URI_LEN = 4096
MODEL_INPUT_MODES = ("decoded", "raw", "decoded_nomask")


def double_url_decode(uri: str) -> str:
    return unquote_plus(unquote_plus(uri or ""))


def preprocess_request(method: str, uri: str, mask_digits: bool = True) -> str:
    """Build '<METHOD> <URI>' with digit runs masked (unless disabled)."""
    uri = (uri or "")[:MAX_URI_LEN]
    if mask_digits:
        uri = re.sub(r"\d+", "{ID}", uri)
    return f"{(method or 'GET').upper()} {uri}"


def prepare_model_text(method: str, raw_uri: str, mode: str = "decoded") -> str:
    """Model input text for a request, in the chosen preprocessing mode."""
    if mode not in MODEL_INPUT_MODES:
        raise ValueError(f"mode must be one of {MODEL_INPUT_MODES}")
    raw_uri = (raw_uri or "")[:MAX_URI_LEN]
    if mode == "raw":
        return preprocess_request(method, raw_uri, mask_digits=True)
    decoded = double_url_decode(raw_uri)
    return preprocess_request(method, decoded, mask_digits=(mode == "decoded"))


# ---------------------------------------------------------------------------
# Rule lists (mirror waf/app/main.py). Mutable so a config file can extend them.
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

SPECIAL_CHARS = "!@#$%^&*()[]{};<>|\\\"'-,./?="
MAX_ALLOWED_SPECIAL_CHARS = 10

INJECTION_PATTERNS = [
    r"('\s*(AND|OR)\s*'?[^']*'?\s*=|\bOR\b.*=|AND\s*\d+=\d+)",
    r"(UNION\s+SELECT|UNION\s+ALL|UNION\s*/\*)",
    r"(DROP|DELETE|INSERT|UPDATE|EXEC|SCRIPT)\s+",
    r"(' ;\s*(DROP|DELETE|TRUNCATE|INSERT))",
    r"([`;&|]|\|\||&&|\n|\r)\s*(cat|ls|wget|curl|bash|sh|cmd)",
    r"(<\s*script[^>]*>|javascript:|onerror\s*=|onclick\s*=|onload\s*=|eval\()",
]

ENCODING_PATTERNS = [
    r"\\x[0-9a-f]{2}",
    r"%2e%2e|%252e%252e",
    r"%2f|%5c|%252f|%255c",
    r"%00|%2500",
    r"%3c|%3e|%22|%27|%3b|%2d%2d",
    r"\.\./|\.\\\\",
    r"&#[0-9]+;",
]

# Backwards-compatible private aliases used by older scripts.
_INJECTION_PATTERNS = INJECTION_PATTERNS
_ENCODING_PATTERNS = ENCODING_PATTERNS


def load_rules_config(path: str | None) -> dict:
    """
    Extend or replace the rule lists from a JSON file.

    Format (every key optional):
      {
        "mode": "extend" | "replace",          # default "extend"
        "keywords": ["sleep(", "benchmark("],
        "direct_signatures": ["union all select"],
        "injection_patterns": ["(SLEEP|BENCHMARK)\\s*\\("],
        "encoding_patterns": ["%u00[0-9a-f]{2}"],
        "max_special_chars": 12
      }
    Returns a summary of the list sizes after loading.
    """
    global MAX_ALLOWED_SPECIAL_CHARS
    if not path:
        return rules_summary()
    with open(path) as fh:
        cfg = json.load(fh)
    replace = cfg.get("mode", "extend") == "replace"
    for key, target in (("keywords", SUSPICIOUS_KEYWORDS),
                        ("direct_signatures", DIRECT_SIGNATURES),
                        ("injection_patterns", INJECTION_PATTERNS),
                        ("encoding_patterns", ENCODING_PATTERNS)):
        if key in cfg:
            items = [str(x) for x in cfg[key]]
            if key.endswith("patterns"):
                for p in items:
                    re.compile(p)  # fail early on a bad regex
            if replace:
                target[:] = items
            else:
                target.extend(x for x in items if x not in target)
    if "max_special_chars" in cfg:
        MAX_ALLOWED_SPECIAL_CHARS = int(cfg["max_special_chars"])
    return rules_summary()


def rules_summary() -> dict:
    return {
        "keywords": len(SUSPICIOUS_KEYWORDS),
        "direct_signatures": len(DIRECT_SIGNATURES),
        "injection_patterns": len(INJECTION_PATTERNS),
        "encoding_patterns": len(ENCODING_PATTERNS),
        "max_special_chars": MAX_ALLOWED_SPECIAL_CHARS,
    }


# ---------------------------------------------------------------------------
# Signal detectors
# ---------------------------------------------------------------------------
def detect_suspicious_keywords(uri: str):
    uri_lower = (uri or "").lower()
    matched = [k for k in SUSPICIOUS_KEYWORDS if k in uri_lower]
    return len(matched) > 0, matched


def detect_special_char_anomaly(uri: str):
    special = sum(1 for c in (uri or "") if c in SPECIAL_CHARS)
    return special > MAX_ALLOWED_SPECIAL_CHARS, special


def detect_encoding_attacks(uri: str) -> bool:
    return any(re.search(p, uri or "", re.IGNORECASE) for p in ENCODING_PATTERNS)


def detect_injection_patterns(uri: str) -> bool:
    return any(re.search(p, uri or "", re.IGNORECASE) for p in INJECTION_PATTERNS)


def detect_direct_signature(uri: str) -> bool:
    normalized = double_url_decode(uri).lower()
    return any(sig in normalized for sig in DIRECT_SIGNATURES)


def rule_signals(method: str, uri: str) -> dict:
    """All rule signals for one request (raw URI in, decoding done here)."""
    decoded = double_url_decode(uri)
    kw_suspicious, matched = detect_suspicious_keywords(decoded)
    is_char_anom, char_count = detect_special_char_anomaly(decoded)
    enc = detect_encoding_attacks(uri)
    inj = detect_injection_patterns(decoded)
    direct = any(sig in decoded.lower() for sig in DIRECT_SIGNATURES)
    return {
        "direct_signature": direct,
        "keyword_suspicious": kw_suspicious,
        "matched_keywords": matched,
        "encoding_attack": enc,
        "injection_pattern": inj,
        "char_anomaly": is_char_anom,
        "char_count": char_count,
        "has_signal": kw_suspicious or is_char_anom or enc or inj,
    }


# Branch names, in the order the fusion rule tests them (Eq. fusion in the paper).
BRANCHES = (
    "direct_signature",        # case 1
    "keyword_and_injection",   # case 2
    "encoding_attack",         # case 3
    "model_high_with_signal",  # case 4
    "model_band_with_anomaly", # case 5
    "keyword_and_char_anomaly",# case 6
    "allow",                   # otherwise
)


def rules_verdict(method: str, uri: str):
    """
    Deterministic rules-only verdict (the rule-only cases of the fusion rule).
    Returns (is_malicious, branch).
    """
    sig = rule_signals(method, uri)
    if sig["direct_signature"]:
        return True, "direct_signature"
    if sig["keyword_suspicious"] and sig["injection_pattern"]:
        return True, "keyword_and_injection"
    if sig["encoding_attack"]:
        return True, "encoding_attack"
    if sig["char_anomaly"] and sig["keyword_suspicious"]:
        return True, "keyword_and_char_anomaly"
    return False, "allow"


def fuse_decision(method: str, uri: str, ai_prob: float,
                  tau_high: float = 0.98, tau_low: float = 0.90):
    """
    Full hybrid decision (mirrors evaluate_request in waf/app/main.py).
    Returns (is_malicious, branch, prob).
    """
    sig = rule_signals(method, uri)
    if sig["direct_signature"]:
        return True, "direct_signature", 1.0
    if sig["keyword_suspicious"] and sig["injection_pattern"]:
        return True, "keyword_and_injection", 1.0
    if sig["encoding_attack"]:
        return True, "encoding_attack", 1.0
    if ai_prob > tau_high and sig["has_signal"]:
        return True, "model_high_with_signal", ai_prob
    if tau_low <= ai_prob < tau_high and (sig["keyword_suspicious"] or sig["char_anomaly"]):
        return True, "model_band_with_anomaly", ai_prob
    if sig["char_anomaly"] and sig["keyword_suspicious"]:
        return True, "keyword_and_char_anomaly", ai_prob
    return False, "allow", ai_prob


def signal_vector(method: str, uri: str) -> list[int]:
    """Binary rule features in a fixed order (for the learned fusion)."""
    s = rule_signals(method, uri)
    return [int(s["direct_signature"]), int(s["keyword_suspicious"]),
            int(s["injection_pattern"]), int(s["encoding_attack"]),
            int(s["char_anomaly"])]


SIGNAL_NAMES = ["s_dir", "s_kw", "s_inj", "s_enc", "s_ca"]
