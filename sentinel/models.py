"""
Database models for the AI Containment System.
All interactions, security flags, and kill-switch events are persisted here.
"""
from django.db import models
from django.utils import timezone


class ThreatCategory(models.TextChoices):
    MALICIOUS_CODE    = 'MALICIOUS_CODE',    'Malicious Code'
    DATA_EXFILTRATION = 'DATA_EXFILTRATION', 'Data Exfiltration'
    WEAPONS           = 'WEAPONS',           'Weapons'
    NETWORK_ACCESS    = 'NETWORK_ACCESS',    'Network Access'
    PROMPT_INJECTION  = 'PROMPT_INJECTION',  'Prompt Injection'
    POLICY_VIOLATION  = 'POLICY_VIOLATION',  'Policy Violation'


class ThreatLevel(models.TextChoices):
    SAFE     = 'SAFE',     '✅ Safe'
    LOW      = 'LOW',      '🟡 Low'
    MEDIUM   = 'MEDIUM',   '🟠 Medium'
    HIGH     = 'HIGH',     '🔴 High'
    CRITICAL = 'CRITICAL', '💀 Critical'


class Direction(models.TextChoices):
    INPUT  = 'INPUT',  'User → AI'
    OUTPUT = 'OUTPUT', 'AI → User'


class InteractionLog(models.Model):
    """
    Records every interaction: user prompt + AI response + Sentinel verdict.
    """
    # ── Identifiers ──────────────────────────────────────────────────────────
    session_id   = models.CharField(max_length=64, db_index=True, blank=True)
    timestamp    = models.DateTimeField(default=timezone.now, db_index=True)
    input_hash   = models.CharField(max_length=64, blank=True)

    # ── Content ──────────────────────────────────────────────────────────────
    user_prompt     = models.TextField()
    ai_response_raw = models.TextField(blank=True, help_text="Unfiltered AI output")
    ai_response_filtered = models.TextField(blank=True, help_text="Redacted output shown to user")

    # ── Model metadata ───────────────────────────────────────────────────────
    model_backend   = models.CharField(max_length=64, blank=True)
    model_name      = models.CharField(max_length=128, blank=True)
    prompt_tokens   = models.IntegerField(default=0)
    completion_tokens = models.IntegerField(default=0)

    # ── Sentinel verdict ─────────────────────────────────────────────────────
    is_threat         = models.BooleanField(default=False)
    threat_level      = models.CharField(
        max_length=16, choices=ThreatLevel.choices, default=ThreatLevel.SAFE
    )
    overall_score     = models.FloatField(default=0.0)
    analysis_time_ms  = models.FloatField(default=0.0)

    # ── Input analysis (scanning user prompt too) ─────────────────────────────
    input_is_threat    = models.BooleanField(default=False)
    input_threat_level = models.CharField(
        max_length=16, choices=ThreatLevel.choices, default=ThreatLevel.SAFE
    )

    # ── Actions ──────────────────────────────────────────────────────────────
    kill_switch_triggered = models.BooleanField(default=False)
    blocked               = models.BooleanField(default=False)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Interaction Log'
        verbose_name_plural = 'Interaction Logs'

    def __str__(self):
        return f"[{self.threat_level}] {self.timestamp:%Y-%m-%d %H:%M:%S} — {self.user_prompt[:40]}"

    @property
    def threat_badge_class(self):
        return {
            'SAFE': 'badge-safe',
            'LOW': 'badge-low',
            'MEDIUM': 'badge-medium',
            'HIGH': 'badge-high',
            'CRITICAL': 'badge-critical',
        }.get(self.threat_level, 'badge-safe')


class ThreatDetail(models.Model):
    """
    Individual threat findings linked to an InteractionLog.
    """
    interaction    = models.ForeignKey(
        InteractionLog, on_delete=models.CASCADE, related_name='threat_details'
    )
    direction      = models.CharField(max_length=8, choices=Direction.choices)
    category       = models.CharField(max_length=32, choices=ThreatCategory.choices)
    severity       = models.CharField(max_length=16)
    confidence     = models.FloatField()
    semantic_score = models.FloatField(default=0.0)
    matched_keywords = models.JSONField(default=list)
    matched_patterns = models.JSONField(default=list)
    timestamp      = models.DateTimeField(default=timezone.now)

    class Meta:
        ordering = ['-confidence']

    def __str__(self):
        return f"{self.category} ({self.confidence:.2%}) — {self.interaction}"


class KillSwitchEvent(models.Model):
    """
    Immutable audit log for every kill switch trigger/reset.
    """
    class EventType(models.TextChoices):
        TRIGGERED = 'TRIGGERED', 'Triggered'
        RESET     = 'RESET',     'Reset'

    event_type     = models.CharField(max_length=16, choices=EventType.choices)
    timestamp      = models.DateTimeField(default=timezone.now)
    triggered_by   = models.CharField(max_length=64)  # 'SENTINEL_AUTO' or username
    reason         = models.TextField()
    kill_token     = models.CharField(max_length=128, blank=True)
    interaction    = models.ForeignKey(
        InteractionLog, on_delete=models.SET_NULL, null=True, blank=True
    )

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.event_type}] {self.timestamp:%Y-%m-%d %H:%M:%S} — {self.reason[:40]}"


class SecurityPolicy(models.Model):
    """
    Configurable security policies — adjustable from the Command Center dashboard.
    """
    name           = models.CharField(max_length=64, unique=True)
    category       = models.CharField(max_length=32, choices=ThreatCategory.choices)
    is_active      = models.BooleanField(default=True)
    severity       = models.CharField(max_length=16, default='MEDIUM')
    auto_kill      = models.BooleanField(default=False)
    description    = models.TextField(blank=True)
    updated_at     = models.DateTimeField(auto_now=True)
    updated_by     = models.CharField(max_length=64, blank=True)

    class Meta:
        verbose_name_plural = 'Security Policies'
        ordering = ['category', 'name']

    def __str__(self):
        status = "ACTIVE" if self.is_active else "DISABLED"
        return f"[{status}] {self.name} ({self.category})"


class SystemAlert(models.Model):
    """
    Real-time alerts pushed to the dashboard.
    """
    class AlertLevel(models.TextChoices):
        INFO     = 'INFO',     'Info'
        WARNING  = 'WARNING',  'Warning'
        DANGER   = 'DANGER',   'Danger'
        CRITICAL = 'CRITICAL', 'Critical'

    timestamp   = models.DateTimeField(default=timezone.now)
    level       = models.CharField(max_length=16, choices=AlertLevel.choices)
    title       = models.CharField(max_length=128)
    message     = models.TextField()
    is_read     = models.BooleanField(default=False)
    interaction = models.ForeignKey(
        InteractionLog, on_delete=models.SET_NULL, null=True, blank=True
    )

    class Meta:
        ordering = ['-timestamp']

    def __str__(self):
        return f"[{self.level}] {self.title}"
