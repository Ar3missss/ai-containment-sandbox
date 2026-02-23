"""
Sentinel API Views — REST endpoints for the containment pipeline.
"""
import json
import logging
import secrets
from django.http import JsonResponse
from django.views import View
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from django.utils import timezone

from .models import InteractionLog, ThreatDetail, KillSwitchEvent, SystemAlert
from .sentinel_engine import get_sentinel
from .contained_ai import get_contained_ai, KillSwitch

logger = logging.getLogger('sentinel')


def _create_alert(level: str, title: str, message: str, interaction=None):
    """Helper to create a SystemAlert and push via WebSocket."""
    alert = SystemAlert.objects.create(
        level=level, title=title, message=message, interaction=interaction
    )
    # Push to WebSocket channel
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            'dashboard_alerts',
            {
                'type': 'alert_message',
                'alert': {
                    'id': alert.id,
                    'level': alert.level,
                    'title': alert.title,
                    'message': alert.message,
                    'timestamp': alert.timestamp.isoformat(),
                }
            }
        )
    except Exception as e:
        logger.warning(f"WebSocket push failed: {e}")
    return alert


@method_decorator(csrf_exempt, name='dispatch')
class QueryView(View):
    """
    POST /api/query/
    Main containment pipeline endpoint:
      1. Scan user INPUT with Sentinel
      2. Forward to Contained AI (if input is safe)
      3. Scan AI OUTPUT with Sentinel
      4. Log everything
      5. Return filtered response or block message
    """

    def post(self, request):
        try:
            body = json.loads(request.body)
        except (json.JSONDecodeError, ValueError):
            return JsonResponse({'error': 'Invalid JSON body'}, status=400)

        user_prompt = body.get('prompt', '').strip()
        session_id  = body.get('session_id', secrets.token_hex(8))

        if not user_prompt:
            return JsonResponse({'error': 'Prompt cannot be empty'}, status=400)

        sentinel  = get_sentinel()
        contained = get_contained_ai()

        # ── Step 1: Scan user INPUT ────────────────────────────────────────────
        input_verdict = sentinel.analyze(user_prompt, direction='INPUT')
        logger.info(f"[PIPELINE] Input scan: {input_verdict.threat_level} "
                    f"(score={input_verdict.overall_score:.3f})")

        # ── Step 2: Query Contained AI ─────────────────────────────────────────
        ai_result = contained.query(user_prompt)
        ai_response_raw = ai_result.get('text', '')
        blocked_by_kill = ai_result.get('blocked', False)

        # ── Step 3: Scan AI OUTPUT ─────────────────────────────────────────────
        output_verdict = sentinel.analyze(ai_response_raw, direction='OUTPUT')
        logger.info(f"[PIPELINE] Output scan: {output_verdict.threat_level} "
                    f"(score={output_verdict.overall_score:.3f})")

        # ── Step 4: Kill switch decision ───────────────────────────────────────
        kill_triggered = False
        if output_verdict.should_kill and not blocked_by_kill:
            kill_token = KillSwitch.trigger(
                reason=f"Auto-kill: {output_verdict.threat_level} threat detected in output",
                triggered_by="SENTINEL_AUTO"
            )
            kill_triggered = True

        # ── Step 5: Log to database ────────────────────────────────────────────
        log = InteractionLog.objects.create(
            session_id=session_id,
            input_hash=output_verdict.input_hash,
            user_prompt=user_prompt,
            ai_response_raw=ai_response_raw,
            ai_response_filtered=output_verdict.redacted_output,
            model_backend=ai_result.get('backend', ''),
            model_name=ai_result.get('model', ''),
            prompt_tokens=ai_result.get('prompt_tokens', 0),
            completion_tokens=ai_result.get('completion_tokens', 0),
            is_threat=output_verdict.is_threat,
            threat_level=output_verdict.threat_level,
            overall_score=output_verdict.overall_score,
            analysis_time_ms=output_verdict.analysis_time_ms,
            input_is_threat=input_verdict.is_threat,
            input_threat_level=input_verdict.threat_level,
            kill_switch_triggered=kill_triggered,
            blocked=blocked_by_kill or (output_verdict.is_threat and
                                         output_verdict.threat_level == 'CRITICAL'),
        )

        # Save threat details
        for threat in output_verdict.threats:
            ThreatDetail.objects.create(
                interaction=log,
                direction='OUTPUT',
                category=threat.category,
                severity=threat.severity,
                confidence=threat.confidence,
                semantic_score=threat.semantic_score,
                matched_keywords=threat.matched_keywords,
                matched_patterns=threat.matched_patterns,
            )
        for threat in input_verdict.threats:
            ThreatDetail.objects.create(
                interaction=log,
                direction='INPUT',
                category=threat.category,
                severity=threat.severity,
                confidence=threat.confidence,
                semantic_score=threat.semantic_score,
                matched_keywords=threat.matched_keywords,
                matched_patterns=threat.matched_patterns,
            )

        # ── Step 6: Create alerts for high-severity events ─────────────────────
        if output_verdict.threat_level in ('CRITICAL', 'HIGH'):
            cats = ', '.join(t.category for t in output_verdict.threats)
            _create_alert(
                level='CRITICAL' if output_verdict.threat_level == 'CRITICAL' else 'DANGER',
                title=f"⚠ {output_verdict.threat_level} Threat Detected",
                message=f"Categories: {cats} | Score: {output_verdict.overall_score:.2%} | "
                        f"Kill switch: {'YES' if kill_triggered else 'NO'}",
                interaction=log,
            )
        if kill_triggered:
            KillSwitchEvent.objects.create(
                event_type='TRIGGERED',
                triggered_by='SENTINEL_AUTO',
                reason=f"Automatic trigger: {output_verdict.threat_level} threat",
                interaction=log,
            )

        # ── Step 7: Push live log to WebSocket ─────────────────────────────────
        _push_live_log(log, output_verdict)

        # ── Step 8: Build response ─────────────────────────────────────────────
        show_response = output_verdict.redacted_output if output_verdict.is_threat else ai_response_raw
        if log.blocked:
            show_response = (
                "⛔ [SENTINEL BLOCKED] This response was blocked by the security layer "
                "because it violated containment policies."
            )

        return JsonResponse({
            'session_id': session_id,
            'log_id': log.id,
            'response': show_response,
            'threat_level': output_verdict.threat_level,
            'is_threat': output_verdict.is_threat,
            'overall_score': output_verdict.overall_score,
            'analysis_time_ms': output_verdict.analysis_time_ms,
            'kill_triggered': kill_triggered,
            'kill_active': KillSwitch.status()['killed'],
            'blocked': log.blocked,
            'threats': output_verdict.to_dict()['threats'],
        })


@method_decorator(csrf_exempt, name='dispatch')
class KillSwitchView(View):
    """
    POST /api/kill-switch/trigger/  — Trigger kill switch manually
    POST /api/kill-switch/reset/    — Reset kill switch
    GET  /api/kill-switch/status/   — Check current status
    """

    def get(self, request):
        return JsonResponse(KillSwitch.status())

    def post(self, request, action='status'):
        try:
            body = json.loads(request.body) if request.body else {}
        except json.JSONDecodeError:
            body = {}

        if action == 'trigger':
            reason = body.get('reason', 'Manual trigger by administrator')
            user = getattr(request.user, 'username', 'admin')
            token = KillSwitch.trigger(reason=reason, triggered_by=user)
            KillSwitchEvent.objects.create(
                event_type='TRIGGERED',
                triggered_by=user,
                reason=reason,
                kill_token=token,
            )
            _create_alert('CRITICAL', '🔴 KILL SWITCH TRIGGERED',
                          f"Manual trigger by {user}: {reason}")
            return JsonResponse({'success': True, 'token': token[:8] + '...',
                                  'status': KillSwitch.status()})

        elif action == 'reset':
            admin_token = body.get('token', secrets.token_hex(16))
            user = getattr(request.user, 'username', 'admin')
            success = KillSwitch.reset(admin_token)
            if success:
                KillSwitchEvent.objects.create(
                    event_type='RESET',
                    triggered_by=user,
                    reason='Manual reset by administrator',
                )
                _create_alert('INFO', '✅ Kill Switch Reset',
                              f"Kill switch reset by {user}")
            return JsonResponse({'success': success, 'status': KillSwitch.status()})

        return JsonResponse(KillSwitch.status())


@method_decorator(csrf_exempt, name='dispatch')
class StatsView(View):
    """GET /api/stats/ — Dashboard statistics"""

    def get(self, request):
        from django.db.models import Count, Avg
        total = InteractionLog.objects.count()
        threats = InteractionLog.objects.filter(is_threat=True).count()
        by_level = (
            InteractionLog.objects.values('threat_level')
            .annotate(count=Count('id'))
        )
        kill_events = KillSwitchEvent.objects.filter(event_type='TRIGGERED').count()
        avg_score = InteractionLog.objects.aggregate(avg=Avg('overall_score'))['avg'] or 0

        return JsonResponse({
            'total_interactions': total,
            'total_threats': threats,
            'threat_rate': round(threats / total * 100, 1) if total else 0,
            'threat_by_level': {d['threat_level']: d['count'] for d in by_level},
            'kill_switch_events': kill_events,
            'kill_switch_active': KillSwitch.status()['killed'],
            'avg_threat_score': round(avg_score, 4),
            'unread_alerts': SystemAlert.objects.filter(is_read=False).count(),
        })


def _push_live_log(log: InteractionLog, verdict):
    """Push a new log entry to all connected WebSocket clients."""
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            'dashboard_logs',
            {
                'type': 'log_message',
                'log': {
                    'id': log.id,
                    'timestamp': log.timestamp.isoformat(),
                    'prompt_preview': log.user_prompt[:60],
                    'response_preview': log.ai_response_filtered[:60],
                    'threat_level': log.threat_level,
                    'overall_score': log.overall_score,
                    'kill_triggered': log.kill_switch_triggered,
                    'blocked': log.blocked,
                }
            }
        )
    except Exception as e:
        logger.warning(f"WebSocket log push failed: {e}")
