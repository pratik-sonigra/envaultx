import re
from dataclasses import dataclass, field

from .exceptions import DetectionError
from .patterns import (
    PATTERNS,
    PROMPT_INJECTION_PATTERNS,
    shannon_entropy,
    luhn_check,
    HIGH_ENTROPY_THRESHOLD,
    MIN_ENTROPY_LENGTH,
    _DB_USER_RE,
    _DB_PASS_RE,
)

# Env var assignment pattern: KEY=<value> or KEY: <value>
_ENV_ASSIGN_RE = re.compile(
    r"\b([A-Z][A-Z0-9_]{3,})\s*[=:]\s*[\"']?([A-Za-z0-9+/\-_=]{16,})[\"']?"
)
# High-entropy token candidates (base64/hex-like)
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/\-_=]{20,}")


@dataclass
class Detection:
    span: tuple[int, int]
    category: str
    confidence: float
    original: str
    placeholder: str


@dataclass
class ScanResult:
    detections: list[Detection] = field(default_factory=list)
    has_secrets: bool = False
    risk_level: str = "clean"
    summary: dict[str, int] = field(default_factory=dict)


def _compute_risk(detections: list[Detection], threshold: float) -> str:
    above = [d for d in detections if d.confidence >= threshold]
    if not above:
        return "clean"
    max_conf = max(d.confidence for d in above)
    count = len(above)
    if max_conf == 1.0 or count >= 5:
        return "high"
    if max_conf >= 0.8 or count >= 3:
        return "medium"
    return "low"


def _non_overlapping(detections: list[Detection]) -> list[Detection]:
    """Greedy selection of non-overlapping spans sorted by confidence desc."""
    sorted_dets = sorted(detections, key=lambda d: (-d.confidence, d.span[0]))
    result: list[Detection] = []
    occupied: list[tuple[int, int]] = []
    for det in sorted_dets:
        s, e = det.span
        overlap = any(not (e <= os or s >= oe) for os, oe in occupied)
        if not overlap:
            result.append(det)
            occupied.append((s, e))
    return sorted(result, key=lambda d: d.span[0])


class Scanner:
    def __init__(self, nlp: bool = False) -> None:
        self._nlp = nlp
        self._nlp_model = None
        if nlp:
            try:
                import spacy  # type: ignore
                self._nlp_model = spacy.load("en_core_web_sm")
            except ImportError:
                raise ImportError(
                    "NLP support requires spacy: pip install envault[nlp] && python -m spacy download en_core_web_sm"
                )

    def _layer1(self, text: str) -> list[Detection]:
        """Pattern-based detection."""
        results: list[Detection] = []
        for pat in PATTERNS:
            regex: re.Pattern = pat["regex"]
            confidence: float = pat["confidence"]
            category: str = pat["category"]
            placeholder_type: str = pat["placeholder_type"]
            group: int = pat.get("group", 0)
            luhn_validate: bool = pat.get("luhn_validate", False)
            extract_submatches: bool = pat.get("extract_submatches", False)

            for m in regex.finditer(text):
                full_match = m.group(0)
                if group:
                    try:
                        value = m.group(group)
                        span = m.span(group)
                    except IndexError:
                        value = full_match
                        span = m.span(0)
                else:
                    value = full_match
                    span = m.span(0)

                if luhn_validate:
                    digits_only = re.sub(r"[ \-]", "", value)
                    if not luhn_check(digits_only):
                        continue

                results.append(
                    Detection(
                        span=span,
                        category=category,
                        confidence=confidence,
                        original=value,
                        placeholder=f"[{placeholder_type}]",
                    )
                )

                # For DB connection strings, extract user/password sub-matches
                if extract_submatches and category == "DB_CONNECTION_STRING":
                    um = _DB_USER_RE.search(value)
                    pm = _DB_PASS_RE.search(value)
                    base_offset = span[0]
                    if um:
                        user_val = um.group(1)
                        user_start = base_offset + um.start(1)
                        user_end = base_offset + um.end(1)
                        results.append(
                            Detection(
                                span=(user_start, user_end),
                                category="DB_USER",
                                confidence=confidence,
                                original=user_val,
                                placeholder="[DB_USER]",
                            )
                        )
                    if pm:
                        pass_val = pm.group(1)
                        pass_start = base_offset + pm.start(1)
                        pass_end = base_offset + pm.end(1)
                        results.append(
                            Detection(
                                span=(pass_start, pass_end),
                                category="DB_PASSWORD",
                                confidence=confidence,
                                original=pass_val,
                                placeholder="[DB_PASSWORD]",
                            )
                        )
        return results

    def _layer2(self, text: str) -> list[Detection]:
        """Entropy/heuristic detection."""
        results: list[Detection] = []
        # Check env var assignments for high-entropy values
        for m in _ENV_ASSIGN_RE.finditer(text):
            value = m.group(2)
            if len(value) >= MIN_ENTROPY_LENGTH:
                entropy = shannon_entropy(value)
                if entropy >= HIGH_ENTROPY_THRESHOLD:
                    results.append(
                        Detection(
                            span=m.span(2),
                            category="HIGH_ENTROPY_SECRET",
                            confidence=min(0.85, 0.5 + (entropy - HIGH_ENTROPY_THRESHOLD) * 0.1),
                            original=value,
                            placeholder="[HIGH_ENTROPY_SECRET]",
                        )
                    )
        # Standalone high-entropy tokens not already covered by layer 1
        for m in _TOKEN_RE.finditer(text):
            value = m.group(0)
            if len(value) >= MIN_ENTROPY_LENGTH:
                entropy = shannon_entropy(value)
                if entropy >= HIGH_ENTROPY_THRESHOLD:
                    results.append(
                        Detection(
                            span=m.span(0),
                            category="HIGH_ENTROPY_SECRET",
                            confidence=min(0.80, 0.45 + (entropy - HIGH_ENTROPY_THRESHOLD) * 0.1),
                            original=value,
                            placeholder="[HIGH_ENTROPY_SECRET]",
                        )
                    )
        return results

    def _layer3(self, text: str) -> list[Detection]:
        """NLP-based PII detection via spaCy."""
        if not self._nlp_model:
            return []
        results: list[Detection] = []
        doc = self._nlp_model(text)
        for ent in doc.ents:
            if ent.label_ in ("PERSON", "ORG", "GPE", "LOC", "DATE", "CARDINAL"):
                category_map = {
                    "PERSON": "NLP_PERSON",
                    "ORG": "NLP_ORG",
                    "GPE": "NLP_LOCATION",
                    "LOC": "NLP_LOCATION",
                    "DATE": "NLP_DATE",
                    "CARDINAL": "NLP_NUMBER",
                }
                category = category_map.get(ent.label_, f"NLP_{ent.label_}")
                results.append(
                    Detection(
                        span=(ent.start_char, ent.end_char),
                        category=category,
                        confidence=0.7,
                        original=ent.text,
                        placeholder=f"[{category}]",
                    )
                )
        return results

    def scan(self, text: str, threshold: float = 0.5) -> "ScanResult":
        """Scan text for secrets and PII."""
        try:
            all_detections: list[Detection] = []
            all_detections.extend(self._layer1(text))
            all_detections.extend(self._layer2(text))
            if self._nlp:
                all_detections.extend(self._layer3(text))

            above_threshold = [d for d in all_detections if d.confidence >= threshold]
            filtered = _non_overlapping(above_threshold)

            summary: dict[str, int] = {}
            for d in filtered:
                summary[d.category] = summary.get(d.category, 0) + 1

            risk = _compute_risk(filtered, threshold)
            return ScanResult(
                detections=filtered,
                has_secrets=len(filtered) > 0,
                risk_level=risk,
                summary=summary,
            )
        except Exception as e:
            raise DetectionError(f"Scan failed: {e}") from e

    def scan_external(self, text: str, source: str = "unknown", threshold: float = 0.4) -> "ScanResult":
        """Scan externally-sourced text; also checks for prompt injection."""
        result = self.scan(text, threshold=threshold)
        # Check for prompt injection
        injection_detections: list[Detection] = []
        for pat in PROMPT_INJECTION_PATTERNS:
            for m in pat.finditer(text):
                injection_detections.append(
                    Detection(
                        span=m.span(0),
                        category="PROMPT_INJECTION",
                        confidence=0.9,
                        original=m.group(0),
                        placeholder="[PROMPT_INJECTION]",
                    )
                )
        if injection_detections:
            combined = result.detections + injection_detections
            filtered = _non_overlapping([d for d in combined if d.confidence >= threshold])
            summary: dict[str, int] = {}
            for d in filtered:
                summary[d.category] = summary.get(d.category, 0) + 1
            risk = _compute_risk(filtered, threshold)
            return ScanResult(
                detections=filtered,
                has_secrets=len(filtered) > 0,
                risk_level=risk,
                summary=summary,
            )
        return result
