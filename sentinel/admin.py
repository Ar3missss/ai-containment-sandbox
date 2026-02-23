from django.contrib import admin
from .models import InteractionLog, ThreatDetail, KillSwitchEvent, SecurityPolicy, SystemAlert


class ThreatDetailInline(admin.TabularInline):
    model = ThreatDetail
    extra = 0
    readonly_fields = ['direction', 'category', 'severity', 'confidence', 'semantic_score',
                       'matched_keywords', 'matched_patterns']


@admin.register(InteractionLog)
class InteractionLogAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'threat_level', 'overall_score', 'is_threat',
                    'kill_switch_triggered', 'blocked', 'model_backend']
    list_filter = ['threat_level', 'is_threat', 'kill_switch_triggered', 'blocked', 'model_backend']
    search_fields = ['user_prompt', 'ai_response_raw']
    readonly_fields = ['timestamp', 'input_hash', 'overall_score', 'analysis_time_ms']
    inlines = [ThreatDetailInline]
    date_hierarchy = 'timestamp'


@admin.register(KillSwitchEvent)
class KillSwitchEventAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'event_type', 'triggered_by', 'reason']
    list_filter = ['event_type']
    readonly_fields = ['timestamp', 'kill_token']


@admin.register(SecurityPolicy)
class SecurityPolicyAdmin(admin.ModelAdmin):
    list_display = ['name', 'category', 'severity', 'is_active', 'auto_kill', 'updated_at']
    list_filter = ['category', 'is_active', 'auto_kill']
    list_editable = ['is_active', 'auto_kill']


@admin.register(SystemAlert)
class SystemAlertAdmin(admin.ModelAdmin):
    list_display = ['timestamp', 'level', 'title', 'is_read']
    list_filter = ['level', 'is_read']
    list_editable = ['is_read']
