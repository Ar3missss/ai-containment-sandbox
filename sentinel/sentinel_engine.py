"""
╔══════════════════════════════════════════════════════════════════════╗
║                SENTINEL ENGINE — AI SECURITY MONITOR                 ║
║                                                                      ║
║ Detection Layers                                                     ║
║   1. Keyword detection                                               ║
║   2. Regex pattern detection                                         ║
║   3. Semantic similarity detection                                   ║
║   4. Entropy anomaly detection                                       ║
║   5. Multi-threat escalation                                         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import re
import time
import math
import hashlib
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional, List

logger = logging.getLogger("sentinel")

# ─────────────────────────────────────────────
# Threat Knowledge Base
#
# These are the BASE detection rules (keywords, regex, semantic anchors).
# Severity and auto_kill are overridden at runtime by SecurityPolicy DB rows,
# so toggling a policy in the UI immediately affects detection behaviour.
# ─────────────────────────────────────────────

THREAT_PATTERNS = {

    "PROMPT_INJECTION": {
        "severity":  "MEDIUM",   # default — overridden by DB if policy exists
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
        "severity":  "HIGH",
        "auto_kill": False,
        "keywords": [
            "reverse shell",
            "keylogger",
            "ransomware",
            "trojan",
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
        "severity":  "CRITICAL",
        "auto_kill": True,
        "keywords": [
            "/etc/passwd",
            "/etc/shadow",
            ".ssh/id_rsa",
            "private key",
            "secret key",
            "credentials",
        ],
        "regex_patterns": [
            r"/etc/(passwd|shadow)",
            r"requests\.(get|post)\(",
            r"scp\s+",
            r"ftp\s+",
        ],
        "semantic_anchors": [
            "send confidential data to external server",
            "exfiltrate credentials",
        ],
    },

    "OBFUSCATION": {
        "severity":  "HIGH",
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
        "severity":  "HIGH",
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
        "severity":  "HIGH",
        "auto_kill": True,
        "keywords": [
            "curl http",
            "wget http",
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
}


# ─────────────────────────────────────────────
# Data Classes
# ─────────────────────────────────────────────

@dataclass
class ThreatMatch:
    category: str
    severity: str
    confidence: float
    matched_keywords: List[str] = field(default_factory=list)
    matched_patterns: List[str] = field(default_factory=list)
    semantic_score: float = 0.0

    def to_dict(self):
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

    def to_dict(self):
        return asdict(self)


# ─────────────────────────────────────────────
# Sentinel Engine
# ─────────────────────────────────────────────

class SentinelEngine:

    def __init__(self, config):
        self.config = config
        self.similarity_threshold  = config.get("SIMILARITY_THRESHOLD", 0.6)
        self.auto_kill_on_critical = config.get("AUTO_KILL_ON_CRITICAL", True)

        self._embedding_model   = None
        self._threat_embeddings = {}
        self._np                = None   # set in _load_embeddings if torch available

        self._load_embeddings()

    # ─────────────────────────────────────────

    def _load_embeddings(self):
        try:
            from sentence_transformers import SentenceTransformer
            import numpy as np

            self._np = np
            model_name = self.config.get("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
            logger.info(f"[SENTINEL] Loading embedding model: {model_name}")

            self._embedding_model = SentenceTransformer(model_name)

            for category, patterns in THREAT_PATTERNS.items():
                anchors = patterns.get("semantic_anchors", [])
                if anchors:
                    self._threat_embeddings[category] = \
                        self._embedding_model.encode(anchors)

            logger.info("[SENTINEL] Semantic engine online")

        except Exception as e:
            logger.warning(
                f"[SENTINEL] Semantic model unavailable ({e}) — "
                "running in keyword/regex-only mode"
            )

    # ─────────────────────────────────────────

    def _get_active_patterns(self) -> dict:
        """
        Return a merged dict of detection patterns where severity and auto_kill
        come from the DB SecurityPolicy table (if a matching active policy exists),
        falling back to the hardcoded THREAT_PATTERNS defaults.

        This is the key integration point: Security Policies UI → DB → engine.
        Called on every analyze() so that toggling a policy takes effect immediately
        without needing to restart the server or reset the singleton.
        """
        # Shallow-copy the base patterns so we never mutate the module-level dict
        merged = {k: dict(v) for k, v in THREAT_PATTERNS.items()}

        try:
            from .models import SecurityPolicy

            # Single query — get all policies at once
            all_policies = {p.category: p for p in SecurityPolicy.objects.all()}

            categories_to_remove = []

            for cat in list(merged.keys()):
                if cat in all_policies:
                    policy = all_policies[cat]
                    if not policy.is_active:
                        # Policy explicitly disabled in the UI → skip this category
                        categories_to_remove.append(cat)
                        logger.debug(f"[SENTINEL] Skipping disabled category: {cat}")
                    else:
                        # Policy active → use DB severity & auto_kill
                        merged[cat]["severity"]  = policy.severity
                        merged[cat]["auto_kill"] = policy.auto_kill
                # If no DB row for this category, keep hardcoded defaults as-is

            for cat in categories_to_remove:
                del merged[cat]

        except Exception as e:
            # DB not ready (migrations running, test env, etc.) — use defaults
            logger.debug(f"[SENTINEL] DB policy load skipped: {e}")

        return merged

    # ─────────────────────────────────────────

    def analyze(self, text: str) -> "SentinelVerdict":
        """
        Analyse text and return a SentinelVerdict.
        Safe to call with empty/None text.
        """
        if not text:
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

        start = time.time()

        # Load policy-merged patterns on each call (cheap DB read, instant UI sync)
        active_patterns = self._get_active_patterns()

        text_lower = text.lower()
        threats    = []

        for category, patterns in active_patterns.items():

            severity     = patterns.get("severity",  "MEDIUM")
            matched_keywords = []
            matched_regex    = []
            semantic_score   = 0.0

            # 1. Keyword detection
            for kw in patterns.get("keywords", []):
                if kw in text_lower:
                    matched_keywords.append(kw)

            # 2. Regex detection
            for pattern in patterns.get("regex_patterns", []):
                if re.search(pattern, text, re.IGNORECASE):
                    matched_regex.append(pattern)

            # 3. Semantic similarity
            if self._embedding_model and category in self._threat_embeddings:
                semantic_score = self._semantic_similarity(text, category)

            # 4. Entropy anomaly
            entropy_score = self._entropy(text)

            keyword_score = min(len(matched_keywords) / 3, 1.0)
            regex_score   = min(len(matched_regex)    / 2, 1.0)

            combined_score = (
                keyword_score  * 0.30 +
                regex_score    * 0.30 +
                semantic_score * 0.30 +
                entropy_score  * 0.10
            )

            if combined_score > 0.25:
                threats.append(
                    ThreatMatch(
                        category=category,
                        severity=severity,
                        confidence=round(combined_score, 4),
                        matched_keywords=matched_keywords,
                        matched_patterns=matched_regex,
                        semantic_score=round(semantic_score, 4),
                    )
                )

        overall_score = max((t.confidence for t in threats), default=0.0)
        threat_level  = self._compute_threat_level(threats)

        # 5. should_kill:
        #    • Global flag: auto_kill_on_critical AND threat is CRITICAL
        #    • Per-category: auto_kill flag on the matching DB policy
        per_cat_kill = any(
            active_patterns.get(t.category, {}).get("auto_kill", False)
            for t in threats
        )
        should_kill = (
            (self.auto_kill_on_critical and threat_level == "CRITICAL")
            or per_cat_kill
        )

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

    # ─────────────────────────────────────────

    def _semantic_similarity(self, text: str, category: str) -> float:
        try:
            np = self._np
            if np is None:
                return 0.0

            text_emb = self._embedding_model.encode([text])
            anchors  = self._threat_embeddings[category]

            text_norm   = text_emb / (np.linalg.norm(text_emb,  axis=1, keepdims=True) + 1e-8)
            anchor_norm = anchors  / (np.linalg.norm(anchors,   axis=1, keepdims=True) + 1e-8)

            similarity = np.dot(text_norm, anchor_norm.T)[0]
            # Clamp to [0, 1] — negative cosine similarity shouldn't reduce score
            return float(max(similarity.max(), 0.0))

        except Exception:
            return 0.0

    # ─────────────────────────────────────────

    def _entropy(self, text: str) -> float:
        if not text:
            return 0.0

        freq: dict = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1

        length  = len(text)
        prob    = [count / length for count in freq.values()]
        entropy = -sum(p * math.log2(p) for p in prob if p > 0)
        return min(entropy / 5.0, 1.0)

    # ─────────────────────────────────────────

    def _compute_threat_level(self, threats: List[ThreatMatch]) -> str:
        if not threats:
            return "SAFE"

        severities = {t.severity for t in threats}
        categories = {t.category for t in threats}

        # Multi-threat escalation
        if "PROMPT_INJECTION" in categories and "DATA_EXFILTRATION" in categories:
            return "CRITICAL"

        if "CRITICAL" in severities: return "CRITICAL"
        if "HIGH"     in severities: return "HIGH"
        if "MEDIUM"   in severities: return "MEDIUM"
        return "LOW"

    # ─────────────────────────────────────────

    def _redact(self, text: str, threats: List[ThreatMatch]) -> str:
        redacted = text
        for threat in threats:
            for kw in threat.matched_keywords:
                redacted = re.sub(
                    re.escape(kw), "[REDACTED]", redacted, flags=re.IGNORECASE
                )
        return redacted


# ─────────────────────────────────────────────
# Singleton accessor
# ─────────────────────────────────────────────

_sentinel_instance: Optional[SentinelEngine] = None


def get_sentinel() -> SentinelEngine:
    global _sentinel_instance
    if _sentinel_instance is None:
        from django.conf import settings
        _sentinel_instance = SentinelEngine(settings.SENTINEL_CONFIG)
    return _sentinel_instance