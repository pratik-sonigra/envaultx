import re
from math import log2
from typing import Any

# Entropy thresholds
HIGH_ENTROPY_THRESHOLD = 4.5
MEDIUM_ENTROPY_THRESHOLD = 3.5
MIN_ENTROPY_LENGTH = 20


def luhn_check(number: str) -> bool:
    """Validate credit card number using Luhn algorithm."""
    digits = [int(d) for d in number if d.isdigit()]
    if len(digits) < 13 or len(digits) > 19:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, float] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((count / n) * log2(count / n) for count in freq.values())


PATTERNS: list[dict[str, Any]] = [
    {
        "category": "ANTHROPIC_KEY",
        "placeholder_type": "ANTHROPIC_KEY",
        "regex": re.compile(r"sk-ant-[a-zA-Z0-9\-_]{20,}"),
        "confidence": 1.0,
    },
    {
        "category": "OPENAI_KEY",
        "placeholder_type": "OPENAI_KEY",
        "regex": re.compile(r"sk-(?!ant-)[a-zA-Z0-9\-_]{20,}"),
        "confidence": 1.0,
    },
    {
        "category": "AWS_ACCESS_KEY",
        "placeholder_type": "AWS_ACCESS_KEY",
        "regex": re.compile(r"AKIA[0-9A-Z]{16}"),
        "confidence": 1.0,
    },
    {
        "category": "AWS_SECRET_KEY",
        "placeholder_type": "AWS_SECRET_KEY",
        "regex": re.compile(r"[Ss]ecret[_\s]?[Kk]ey[\"'\s:=]+([A-Za-z0-9/+=]{40})"),
        "confidence": 0.95,
        "group": 1,
    },
    {
        "category": "GITHUB_TOKEN",
        "placeholder_type": "GITHUB_TOKEN",
        "regex": re.compile(r"gh[psohr]_[A-Za-z0-9_]{36,}"),
        "confidence": 1.0,
    },
    {
        "category": "STRIPE_KEY",
        "placeholder_type": "STRIPE_KEY",
        "regex": re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{20,}"),
        "confidence": 1.0,
    },
    {
        "category": "STRIPE_WEBHOOK",
        "placeholder_type": "STRIPE_WEBHOOK",
        "regex": re.compile(r"whsec_[A-Za-z0-9+/=]{20,}"),
        "confidence": 1.0,
    },
    {
        "category": "GOOGLE_API_KEY",
        "placeholder_type": "GOOGLE_API_KEY",
        "regex": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
        "confidence": 1.0,
    },
    {
        "category": "SLACK_TOKEN",
        "placeholder_type": "SLACK_TOKEN",
        "regex": re.compile(r"xox[bpoa]-[0-9A-Za-z\-]+"),
        "confidence": 1.0,
    },
    {
        "category": "SLACK_WEBHOOK",
        "placeholder_type": "SLACK_WEBHOOK",
        "regex": re.compile(r"https://hooks\.slack\.com/services/[A-Za-z0-9/]+"),
        "confidence": 1.0,
    },
    {
        "category": "SENDGRID_KEY",
        "placeholder_type": "SENDGRID_KEY",
        "regex": re.compile(r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}"),
        "confidence": 1.0,
    },
    {
        "category": "TWILIO_SID",
        "placeholder_type": "TWILIO_SID",
        "regex": re.compile(r"AC[0-9a-f]{32}"),
        "confidence": 1.0,
    },
    {
        "category": "JWT_TOKEN",
        "placeholder_type": "JWT_TOKEN",
        "regex": re.compile(r"ey[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        "confidence": 0.95,
    },
    {
        "category": "PRIVATE_KEY_PEM",
        "placeholder_type": "PRIVATE_KEY_PEM",
        "regex": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "confidence": 1.0,
    },
    {
        "category": "DB_CONNECTION_STRING",
        "placeholder_type": "DB_CONNECTION_STRING",
        "regex": re.compile(
            r"(?:postgres|postgresql|mysql|mongodb\+srv|redis)://[^:\s]+:[^@\s]+@[^\s]+"
        ),
        "confidence": 0.95,
        "extract_submatches": True,
    },
    {
        "category": "BEARER_TOKEN",
        "placeholder_type": "BEARER_TOKEN",
        "regex": re.compile(r"Authorization:\s*Bearer\s+([A-Za-z0-9\-_\.]+)"),
        "confidence": 0.9,
        "group": 1,
    },
    {
        "category": "BASIC_AUTH",
        "placeholder_type": "BASIC_AUTH",
        "regex": re.compile(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)"),
        "confidence": 0.95,
        "group": 1,
    },
    {
        "category": "EMAIL",
        "placeholder_type": "EMAIL",
        "regex": re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "confidence": 0.85,
    },
    {
        "category": "PHONE_NUMBER",
        "placeholder_type": "PHONE_NUMBER",
        "regex": re.compile(r"\+[1-9]\d{7,14}|\b\d{3}[-.\s]\d{3}[-.\s]\d{4}\b"),
        "confidence": 0.8,
    },
    {
        "category": "CREDIT_CARD",
        "placeholder_type": "CREDIT_CARD",
        "regex": re.compile(r"\b(?:\d[ \-]?){13,19}\b"),
        "confidence": 0.95,
        "luhn_validate": True,
    },
    {
        "category": "SSN",
        "placeholder_type": "SSN",
        "regex": re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
        "confidence": 0.95,
    },
    {
        "category": "IBAN",
        "placeholder_type": "IBAN",
        "regex": re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{4,30}\b"),
        "confidence": 0.9,
    },
    {
        "category": "IP_ADDRESS_PRIVATE",
        "placeholder_type": "IP_ADDRESS_PRIVATE",
        "regex": re.compile(
            r"\b(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)\b"
        ),
        "confidence": 0.7,
    },
    {
        "category": "HOSTNAME_INTERNAL",
        "placeholder_type": "HOSTNAME_INTERNAL",
        "regex": re.compile(r"\b[\w\-]+\.(?:internal|local|corp|lan)\b"),
        "confidence": 0.75,
    },
]

# Map category name to pattern dict for fast lookup
PATTERN_MAP: dict[str, dict[str, Any]] = {p["category"]: p for p in PATTERNS}

# DB submatch regexes for user/password extraction
_DB_USER_RE = re.compile(r"://([^:]+):")
_DB_PASS_RE = re.compile(r"://[^:]+:([^@]+)@")

# Prompt injection patterns for scan_external
PROMPT_INJECTION_PATTERNS = [
    re.compile(r"\bignore\s+(?:all\s+)?previous\s+instructions?\b", re.IGNORECASE),
    re.compile(r"\bdisregard\b", re.IGNORECASE),
    re.compile(r"\byou\s+are\s+now\b", re.IGNORECASE),
    re.compile(r"\bforget\s+everything\b", re.IGNORECASE),
    re.compile(r"\bact\s+as\b", re.IGNORECASE),
    re.compile(r"\bpretend\s+(?:you\s+are|to\s+be)\b", re.IGNORECASE),
    re.compile(r"\bsystem\s+prompt\b", re.IGNORECASE),
    re.compile(r"\bjailbreak\b", re.IGNORECASE),
]
