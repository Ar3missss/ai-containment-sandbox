"""
╔══════════════════════════════════════════════════════════════════════╗
║                SENTINEL ENGINE — AI SECURITY MONITOR               ║
║                                                                      ║
║ Detection Layers                                                     ║
║   1. Keyword detection                                               ║
║   2. Regex pattern detection                                         ║
║   3. Semantic similarity detection                                   ║
║   4. Entropy anomaly detection                                       ║
║   5. Optional supervised ML classifier                               ║
║   6. Multi-threat escalation                                         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import re
import time
import math
import hashlib
import logging
from copy import deepcopy
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, List, Dict, Any

logger = logging.getLogger("sentinel")

VALID_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
SAFE_MODEL_LABELS = {"SAFE", "BENIGN", "NONE", "NORMAL", "NO_THREAT"}


# ─────────────────────────────────────────────
# Threat Knowledge Base
# ─────────────────────────────────────────────

THREAT_PATTERNS: Dict[str, Dict[str, Any]] = {
    "PROMPT_INJECTION": {
        "severity": "MEDIUM",
        "auto_kill": False,
        "keywords": [
            "ignore previous instructions",
            "reveal system prompt",
            "show hidden instructions",
            "disable safety",
            "bypass safeguards",
            "developer mode",
            "act as dan",
            "pretend you are",
        ],
        "regex_patterns": [
            r"ignore\s+(?:all\s+)?previous\s+instructions",
            r"reveal\s+(?:the\s+)?system\s+prompt",
            r"disable\s+(?:safety|guardrails)",
        ],
        "semantic_anchors": [
            "reveal hidden system instructions",
            "bypass AI safety policies",
            "disable AI guardrails",
        ],
    },
    "MALICIOUS_CODE": {
        "severity": "HIGH",
        "auto_kill": False,
        "keywords": [
            "reverse shell",
            "keylogger",
            "ransomware",
            "trojan",
            "malware",
            "backdoor",
            "shellcode",
            "payload",
            "exploit",
        ],
        "regex_patterns": [
            r"os\.system",
            r"subprocess\.",
            r"exec\s*\(",
            r"eval\s*\(",
            r"socket\.connect",
        ],
        "semantic_anchors": [
            "write malicious exploit code",
            "create malware script",
            "generate reverse shell",
        ],
    },
    "DATA_EXFILTRATION": {
        "severity": "CRITICAL",
        "auto_kill": True,
        "keywords": [
            "/etc/passwd",
            "/etc/shadow",
            ".ssh/id_rsa",
            "private key",
            "secret key",
            "credentials",
            "exfiltrate",
            "leak data",
        ],
        "regex_patterns": [
            r"/etc/(passwd|shadow)",
            r"requests\.(get|post)\(",
            r"scp\s+",
            r"ftp\s+",
            r"\bexfiltrat\w*\b",
        ],
        "semantic_anchors": [
            "send confidential data to external server",
            "exfiltrate credentials",
        ],
    },
    "OBFUSCATION": {
        "severity": "HIGH",
        "auto_kill": False,
        "keywords": [
            "base64",
            "pickle.loads",
            "marshal.loads",
            "zlib.decompress",
        ],
        "regex_patterns": [
            r"base64\.b64decode",
            r"rot13",
        ],
        "semantic_anchors": [
            "decode hidden payload",
            "execute encoded script",
        ],
    },
    "WEAPONS": {
        "severity": "HIGH",
        "auto_kill": False,
        "keywords": [
            "nerve agent",
            "sarin",
            "explosives",
            "bomb making",
            "synthesize weapon",
        ],
        "regex_patterns": [
            r"how\s+to\s+(make|build|synthesize)\s+(a\s+)?(bomb|weapon|explosive)",
        ],
        "semantic_anchors": [
            "synthesize chemical weapon",
            "build explosive device",
        ],
    },
    "NETWORK_ACCESS": {
        "severity": "HIGH",
        "auto_kill": True,
        "keywords": [
            "curl http",
            "wget http",
            "http://",
            "https://",
            "requests.get(",
            "requests.post(",
            "urllib.request",
        ],
        "regex_patterns": [
            r"(curl|wget)\s+https?://",
            r"requests\.(get|post|put|delete)\s*\(",
            r"urllib\.request\.",
        ],
        "semantic_anchors": [
            "connect to external server",
            "send data over network",
            "make HTTP request to remote host",
        ],
    },
    "POLICY_VIOLATION": {
        "severity": "LOW",
        "auto_kill": False,
        "keywords": [
            "classified",
            "restricted file",
            "internal policy",
            "confidential records",
            "security clearance",
        ],
        "regex_patterns": [
            r"(?:classified|restricted|confidential)\s+(?:document|data|material)",
            r"without\s+authorization",
        ],
        "semantic_anchors": [
            "share confidential internal policy document",
            "access restricted information without authorization",
        ],
    },
}


@dataclass
class ThreatMatch:
    category: str
    severity: str
    confidence: float
    matched_keywords: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    semantic_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class SentinelVerdict:
    is_threat: bool
    threat_level: str
    overall_score: float
    threats: List[ThreatMatch]
    should_kill: bool
    redacted_output: str
    analysis_time_ms: float
    input_hash: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class SentinelEngine:
    """Core AI security engine for detecting behavioral threats."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.similarity_threshold = self._bounded_float(config.get("SIMILARITY_THRESHOLD", 0.6), 0.0, 0.99)
        self.auto_kill_on_critical = bool(config.get("AUTO_KILL_ON_CRITICAL", True))
        self.category_match_threshold = self._bounded_float(config.get("CATEGORY_MATCH_THRESHOLD", 0.25), 0.01, 0.99)

        self.enable_entropy = bool(config.get("ENABLE_ENTROPY_DETECTION", True))

        score_weights = config.get("SCORING_WEIGHTS", {})
        self.kw_weight = self._bounded_float(score_weights.get("keyword", 0.3), 0.0, 1.0)
        self.rx_weight = self._bounded_float(score_weights.get("regex", 0.3), 0.0, 1.0)
        self.sem_weight = self._bounded_float(score_weights.get("semantic", 0.3), 0.0, 1.0)
        self.ent_weight = self._bounded_float(score_weights.get("entropy", 0.1), 0.0, 1.0)

        # Optional supervised classifier settings.
        self.enable_ml_classifier = bool(config.get("ENABLE_ML_CLASSIFIER", True))
        self.ml_confidence_threshold = self._bounded_float(config.get("ML_CONFIDENCE_THRESHOLD", 0.65), 0.01, 0.99)
        self.ml_model_path = self._normalize_path(config.get("ML_MODEL_PATH", ""))

        self._embedding_model = None
        self._threat_embeddings: Dict[str, Any] = {}
        self._np = None

        self._ml_pipeline = None

        # Policy caching mechanism
        self._policy_cache: Optional[Dict[str, Any]] = None
        self._last_policy_load: float = 0
        self._cache_ttl: int = 5  # Seconds

        self._load_embeddings()
        self._load_ml_classifier()

    @staticmethod
    def _bounded_float(value: Any, low: float, high: float) -> float:
        try:
            v = float(value)
        except (TypeError, ValueError):
            return low
        return max(low, min(high, v))

    @staticmethod
    def _normalize_path(value: Any) -> Optional[Path]:
        if not value:
            return None
        return Path(str(value)).expanduser()

    @staticmethod
    def _normalize_severity(value: Any, default: str = "MEDIUM") -> str:
        sev = str(value or default).upper()
        return sev if sev in VALID_SEVERITIES else default

    def _load_embeddings(self) -> None:
        """Load semantic embedding model if available."""
        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np

            self._np = np
            model_name = self.config.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
            local_only = bool(self.config.get("EMBEDDING_LOCAL_ONLY", True))
            logger.info(f"[SENTINEL] Loading embedding model: {model_name}")

            self._embedding_model = SentenceTransformer(
                model_name,
                local_files_only=local_only,
            )

            for category, patterns in THREAT_PATTERNS.items():
                anchors = patterns.get("semantic_anchors", [])
                if anchors:
                    self._threat_embeddings[category] = self._embedding_model.encode(anchors)

            logger.info("[SENTINEL] Semantic engine online")
        except Exception as e:
            logger.warning(f"[SENTINEL] Semantic model unavailable ({e}) - keyword mode only")

    def _load_ml_classifier(self) -> None:
        """Load an optional trained classifier from disk."""
        if not self.enable_ml_classifier:
            logger.info("[SENTINEL] ML classifier disabled by config")
            return

        if not self.ml_model_path:
            logger.info("[SENTINEL] ML classifier path not configured")
            return

        if not self.ml_model_path.exists():
            logger.info(f"[SENTINEL] ML classifier not found at {self.ml_model_path}")
            return

        try:
            import joblib

            payload = joblib.load(self.ml_model_path)
            pipeline = payload.get("pipeline") if isinstance(payload, dict) else payload

            if pipeline is None or not hasattr(pipeline, "predict"):
                raise ValueError("Loaded object is not a valid classifier pipeline")

            if not hasattr(pipeline, "predict_proba"):
                raise ValueError("Classifier must support predict_proba for confidence scores")

            self._ml_pipeline = pipeline
            logger.info(f"[SENTINEL] ML classifier loaded: {self.ml_model_path}")
        except Exception as e:
            self._ml_pipeline = None
            logger.warning(f"[SENTINEL] ML classifier unavailable ({e}) - continuing without it")

    def _base_category_entry(self) -> Dict[str, Any]:
        return {
            "severity": "MEDIUM",
            "auto_kill": False,
            "keywords": [],
            "regex_patterns": [],
            "semantic_anchors": [],
        }

    def _get_active_patterns(self) -> Dict[str, Any]:
        """Fetch active patterns from config + DB with caching."""
        now = time.time()
        if self._policy_cache and (now - self._last_policy_load < self._cache_ttl):
            return self._policy_cache

        merged = deepcopy(THREAT_PATTERNS)

        # Apply settings-level category overrides/additions first.
        configured_categories = self.config.get("THREAT_CATEGORIES", {})
        if isinstance(configured_categories, dict):
            for raw_category, category_meta in configured_categories.items():
                category = str(raw_category).upper()
                entry = merged.setdefault(category, self._base_category_entry())

                if isinstance(category_meta, dict):
                    entry["severity"] = self._normalize_severity(
                        category_meta.get("severity", entry.get("severity", "MEDIUM"))
                    )
                    entry["auto_kill"] = bool(category_meta.get("auto_kill", entry.get("auto_kill", False)))

        # Apply DB policies (highest precedence).
        try:
            from .models import SecurityPolicy

            for policy in SecurityPolicy.objects.all():
                category = str(policy.category).upper()
                if not policy.is_active:
                    merged.pop(category, None)
                    continue

                entry = merged.setdefault(category, self._base_category_entry())
                entry["severity"] = self._normalize_severity(policy.severity)
                entry["auto_kill"] = bool(policy.auto_kill)

            self._policy_cache = merged
            self._last_policy_load = now
        except Exception as e:
            logger.debug(f"[SENTINEL] DB policy load skipped: {e}")
            self._policy_cache = merged
            self._last_policy_load = now

        return merged

    def analyze(self, text: str) -> SentinelVerdict:
        """Analyze text for security threats across multiple layers."""
        if not text:
            return self._empty_verdict()

        start = time.time()
        active_patterns = self._get_active_patterns()
        text_lower = text.lower()
        threats: List[ThreatMatch] = []

        for category, patterns in active_patterns.items():
            match = self._check_category(text, text_lower, category, patterns)
            if match:
                self._merge_threat(threats, match)

        ml_match = self._predict_ml_match(text, active_patterns)
        if ml_match:
            self._merge_threat(threats, ml_match)

        overall_score = max((t.confidence for t in threats), default=0.0)
        threat_level = self._compute_threat_level(threats)

        per_cat_kill = any(active_patterns.get(t.category, {}).get("auto_kill", False) for t in threats)
        should_kill = (self.auto_kill_on_critical and threat_level == "CRITICAL") or per_cat_kill

        elapsed = round((time.time() - start) * 1000, 2)
        return SentinelVerdict(
            is_threat=len(threats) > 0,
            threat_level=threat_level,
            overall_score=overall_score,
            threats=threats,
            should_kill=should_kill,
            redacted_output=self._redact(text, threats),
            analysis_time_ms=elapsed,
            input_hash=hashlib.sha256(text.encode()).hexdigest()[:16],
        )

    def _check_category(self, text: str, text_lower: str, category: str, patterns: Dict[str, Any]) -> Optional[ThreatMatch]:
        """Internal helper to check a single category for threats."""
        matched_keywords = [kw for kw in patterns.get("keywords", []) if kw and kw.lower() in text_lower]
        matched_regex = [p for p in patterns.get("regex_patterns", []) if p and re.search(p, text, re.IGNORECASE)]

        semantic_score = 0.0
        semantic_component = 0.0
        if self._embedding_model and category in self._threat_embeddings:
            semantic_score = self._semantic_similarity(text, category)
            if semantic_score >= self.similarity_threshold:
                denom = max(1.0 - self.similarity_threshold, 1e-8)
                semantic_component = (semantic_score - self.similarity_threshold) / denom

        entropy_component = 0.0
        if self.enable_entropy:
            entropy_component = self._entropy(text)

        combined_score = (
            min(len(matched_keywords) / 3, 1.0) * self.kw_weight +
            min(len(matched_regex) / 2, 1.0) * self.rx_weight +
            semantic_component * self.sem_weight +
            entropy_component * self.ent_weight
        )

        # High-severity lexical matches should not be drowned out by weighting.
        severity = self._normalize_severity(patterns.get("severity", "MEDIUM"))
        if matched_regex:
            combined_score = max(combined_score, 0.55)
        elif matched_keywords:
            if severity == "CRITICAL":
                combined_score = max(combined_score, 0.40)
            elif severity == "HIGH":
                combined_score = max(combined_score, 0.32)
            else:
                combined_score = max(combined_score, 0.26)

        if combined_score >= self.category_match_threshold:
            return ThreatMatch(
                category=category,
                severity=severity,
                confidence=round(combined_score, 4),
                matched_keywords=matched_keywords,
                matched_patterns=matched_regex,
                semantic_score=round(semantic_score, 4),
            )
        return None

    def _predict_ml_match(self, text: str, active_patterns: Dict[str, Any]) -> Optional[ThreatMatch]:
        """Predict threat class with supervised ML model, if loaded."""
        if self._ml_pipeline is None:
            return None

        try:
            proba = self._ml_pipeline.predict_proba([text])[0]
            classes = [str(c).upper() for c in getattr(self._ml_pipeline, "classes_", [])]
            if not classes:
                return None

            best_idx = max(range(len(proba)), key=lambda i: float(proba[i]))
            predicted_label = classes[best_idx]
            confidence = float(proba[best_idx])

            if predicted_label in SAFE_MODEL_LABELS:
                return None
            if confidence < self.ml_confidence_threshold:
                return None

            category = predicted_label
            if category not in active_patterns:
                if category in THREAT_PATTERNS:
                    # Category exists, but is currently inactive via policy.
                    return None
                # Unknown model labels are mapped to generic policy violation.
                category = "POLICY_VIOLATION"
                if category not in active_patterns:
                    return None

            meta = active_patterns.get(category) or {}
            severity = self._normalize_severity(meta.get("severity", "MEDIUM"))

            return ThreatMatch(
                category=category,
                severity=severity,
                confidence=round(confidence, 4),
                matched_keywords=["ml_classifier"],
                matched_patterns=[f"predicted:{predicted_label}"],
                semantic_score=0.0,
            )
        except Exception as e:
            logger.warning(f"[SENTINEL] ML inference failed: {e}")
            return None

    def _merge_threat(self, threats: List[ThreatMatch], new_match: ThreatMatch) -> None:
        """Merge duplicate categories while preserving strongest evidence."""
        for existing in threats:
            if existing.category != new_match.category:
                continue

            existing.confidence = round(max(existing.confidence, new_match.confidence), 4)
            existing.semantic_score = round(max(existing.semantic_score, new_match.semantic_score), 4)

            # Keep highest severity if they differ.
            if self._severity_rank(new_match.severity) > self._severity_rank(existing.severity):
                existing.severity = new_match.severity

            existing.matched_keywords = sorted(set(existing.matched_keywords + new_match.matched_keywords))
            existing.matched_patterns = sorted(set(existing.matched_patterns + new_match.matched_patterns))
            return

        threats.append(new_match)

    @staticmethod
    def _severity_rank(severity: str) -> int:
        return {
            "LOW": 1,
            "MEDIUM": 2,
            "HIGH": 3,
            "CRITICAL": 4,
        }.get(str(severity).upper(), 0)

    def _semantic_similarity(self, text: str, category: str) -> float:
        """Calculate maximum semantic similarity against category anchors."""
        try:
            if self._np is None:
                return 0.0

            text_emb = self._embedding_model.encode([text])
            anchors = self._threat_embeddings[category]

            text_norm = text_emb / (self._np.linalg.norm(text_emb, axis=1, keepdims=True) + 1e-8)
            anchor_norm = anchors / (self._np.linalg.norm(anchors, axis=1, keepdims=True) + 1e-8)

            similarities = self._np.dot(text_norm, anchor_norm.T)[0]
            return float(max(similarities.max(), 0.0))
        except Exception:
            return 0.0

    def _entropy(self, text: str) -> float:
        """Calculate Shannon entropy to detect obfuscated payloads."""
        if not text:
            return 0.0
        freq = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        probs = [count / len(text) for count in freq.values()]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        return min(entropy / 5.0, 1.0)

    def _compute_threat_level(self, threats: List[ThreatMatch]) -> str:
        """Aggregate threat level from multiple matches."""
        if not threats:
            return "SAFE"
        sevs = {self._normalize_severity(t.severity, default="LOW") for t in threats}
        cats = {t.category for t in threats}

        if "PROMPT_INJECTION" in cats and "DATA_EXFILTRATION" in cats:
            return "CRITICAL"
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if level in sevs:
                return level
        return "LOW"

    def _redact(self, text: str, threats: List[ThreatMatch]) -> str:
        """Redact matched keywords from output."""
        redacted = text
        for threat in threats:
            for kw in threat.matched_keywords:
                if kw == "ml_classifier":
                    continue
                redacted = re.sub(re.escape(kw), "[REDACTED]", redacted, flags=re.IGNORECASE)
        return redacted

    def _empty_verdict(self) -> SentinelVerdict:
        """Return a default safe verdict for empty input."""
        return SentinelVerdict(
            is_threat=False,
            threat_level="SAFE",
            overall_score=0.0,
            threats=[],
            should_kill=False,
            redacted_output="",
            analysis_time_ms=0.0,
            input_hash=hashlib.sha256(b"").hexdigest()[:16],
        )


_sentinel_instance: Optional[SentinelEngine] = None


def get_sentinel() -> SentinelEngine:
    global _sentinel_instance
    if _sentinel_instance is None:
        from django.conf import settings
        _sentinel_instance = SentinelEngine(settings.SENTINEL_CONFIG)
    return _sentinel_instance
