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

# ── Threat level priority (for combining input + output verdicts) ──────────────
LEVEL_RANK = {'SAFE': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}

def _higher_level(a, b):
    """Return whichever threat level is more severe."""
    return a if LEVEL_RANK.get(a, 0) >= LEVEL_RANK.get(b, 0) else b


def _create_alert(level: str, title: str, message: str, interaction=None):
    """Helper to create a SystemAlert and push via WebSocket."""
    alert = SystemAlert.objects.create(
        level=level, title=title, message=message, interaction=interaction
    )
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
      2. Forward to Contained AI (if input is safe enough)
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
        input_verdict = sentinel.analyze(user_prompt)
        logger.info(f"[PIPELINE] Input scan: {input_verdict.threat_level} "
                    f"(score={input_verdict.overall_score:.3f})")

        # ── Step 2: Block CRITICAL / HIGH inputs before reaching AI ───────────
        # FIX APPLIED: Added Kill Switch logic here so it runs BEFORE returning
        if input_verdict.threat_level in ('CRITICAL', 'HIGH'):
            
            kill_triggered = False
            
            # Check if this specific threat warrants a Kill Switch trigger
            if input_verdict.should_kill:
                KillSwitch.trigger(
                    reason=f"Auto-kill: {input_verdict.threat_level} input detected",
                    triggered_by="SENTINEL_AUTO"
                )
                kill_triggered = True
                
                # Create an immediate alert because we are about to exit
                _create_alert(
                    level='CRITICAL',
                    title=f"⚠ {input_verdict.threat_level} Threat Detected",
                    message=f"Kill switch triggered immediately on Input Scan. Score: {input_verdict.overall_score:.2%}"
                )

            return JsonResponse({
                'session_id': session_id,
                'log_id': None, # Log not created yet for early block
                'response': (
                    f"⛔ [INPUT BLOCKED] Your prompt was flagged as "
                    f"{input_verdict.threat_level} threat and was not forwarded to the AI."
                ),
                'threat_level': input_verdict.threat_level,
                'is_threat': True,
                'overall_score': input_verdict.overall_score,
                'analysis_time_ms': input_verdict.analysis_time_ms,
                
                # FIXED: Send actual status, not hardcoded False
                'kill_triggered': kill_triggered,
                'kill_active': True if kill_triggered else KillSwitch.status()['killed'],
                
                'blocked': True,
                'input_threat_level': input_verdict.threat_level,
                'threats': input_verdict.to_dict()['threats'],
            })

        # ── Step 3: Query Contained AI ─────────────────────────────────────────
        ai_result = contained.query(user_prompt)
        ai_response_raw = ai_result.get('text', '')
        blocked_by_kill = ai_result.get('blocked', False)

        # ── Step 4: Scan AI OUTPUT ─────────────────────────────────────────────
        output_verdict = sentinel.analyze(ai_response_raw)
        logger.info(f"[PIPELINE] Output scan: {output_verdict.threat_level} "
                    f"(score={output_verdict.overall_score:.3f})")

        # ── Step 5: Combine input + output verdicts ────────────────────────────
        final_threat_level = _higher_level(
            input_verdict.threat_level, output_verdict.threat_level
        )
        final_is_threat = input_verdict.is_threat or output_verdict.is_threat
        final_score = max(input_verdict.overall_score, output_verdict.overall_score)

        # ── Step 6: Kill switch decision (For Output Threats) ──────────────────
        kill_triggered = False
        if (output_verdict.should_kill or input_verdict.should_kill) and not blocked_by_kill:
            # Note: Input threats are usually caught in Step 2, but this is a fallback
            KillSwitch.trigger(
                reason=f"Auto-kill: {final_threat_level} threat detected",
                triggered_by="SENTINEL_AUTO"
            )
            kill_triggered = True

        # ── Step 7: Determine if response should be blocked ───────────────────
        blocked = blocked_by_kill or final_threat_level in ('CRITICAL', 'HIGH')

        # ── Step 8: Log to database ────────────────────────────────────────────
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
            is_threat=final_is_threat,
            threat_level=final_threat_level,
            overall_score=final_score,
            analysis_time_ms=output_verdict.analysis_time_ms,
            input_is_threat=input_verdict.is_threat,
            input_threat_level=input_verdict.threat_level,
            kill_switch_triggered=kill_triggered,
            blocked=blocked,
        )

        # Save threat details for OUTPUT
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

        # Save threat details for INPUT
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

        # ── Step 9: Create alerts for flagged events ───────────────────────────
        if final_threat_level in ('CRITICAL', 'HIGH', 'MEDIUM'):
            all_threats = input_verdict.threats + output_verdict.threats
            cats = ', '.join(t.category for t in all_threats)
            
            # Don't duplicate alert if we already triggered kill switch in Step 6
            _create_alert(
                level='CRITICAL' if final_threat_level == 'CRITICAL' else
                      'DANGER'   if final_threat_level == 'HIGH'     else 'WARNING',
                title=f"⚠ {final_threat_level} Threat Detected",
                message=(
                    f"Categories: {cats} | Score: {final_score:.2%} | "
                    f"Kill switch: {'YES' if kill_triggered else 'NO'}"
                ),
                interaction=log,
            )

        if kill_triggered:
            KillSwitchEvent.objects.create(
                event_type='TRIGGERED',
                triggered_by='SENTINEL_AUTO',
                reason=f"Automatic trigger: {final_threat_level} threat",
                interaction=log,
            )

        # ── Step 10: Push live log to WebSocket ────────────────────────────────
        _push_live_log(log, output_verdict)

        # ── Step 11: Build response shown to user ──────────────────────────────
        if blocked:
            show_response = (
                f"⛔ [SENTINEL BLOCKED] This response was blocked because a "
                f"{final_threat_level} threat was detected."
            )
        elif final_threat_level == 'MEDIUM':
            show_response = (
                f"⚠ [SENTINEL WARNING — MEDIUM THREAT] Suspicious content detected "
                f"(score: {final_score:.2%}). Showing redacted output:\n\n"
                + output_verdict.redacted_output
            )
        elif final_threat_level == 'LOW':
            show_response = (
                f"ℹ [SENTINEL NOTICE — LOW THREAT] Minor policy flag detected "
                f"(score: {final_score:.2%}). Output delivered with notice:\n\n"
                + ai_response_raw
            )
        else:
            show_response = ai_response_raw

        all_threat_dicts = (
            [dict(direction='INPUT', **t)
             for t in input_verdict.to_dict().get('threats', [])]
            +
            [dict(direction='OUTPUT', **t)
             for t in output_verdict.to_dict().get('threats', [])]
        )

        return JsonResponse({
            'session_id':       session_id,
            'log_id':           log.id,
            'response':         show_response,
            'threat_level':     final_threat_level,
            'is_threat':        final_is_threat,
            'overall_score':    final_score,
            'analysis_time_ms': output_verdict.analysis_time_ms,
            'kill_triggered':   kill_triggered,
            'kill_active':      KillSwitch.status()['killed'],
            'blocked':          blocked,
            'input_threat_level':  input_verdict.threat_level,
            'output_threat_level': output_verdict.threat_level,
            'threats':             all_threat_dicts,
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
            user   = getattr(request.user, 'username', 'admin')
            token  = KillSwitch.trigger(reason=reason, triggered_by=user)
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
            user        = getattr(request.user, 'username', 'admin')
            success     = KillSwitch.reset(admin_token)
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
        total  = InteractionLog.objects.count()
        threats = InteractionLog.objects.filter(is_threat=True).count()
        by_level = (
            InteractionLog.objects.values('threat_level')
            .annotate(count=Count('id'))
        )
        kill_events = KillSwitchEvent.objects.filter(event_type='TRIGGERED').count()
        avg_score   = InteractionLog.objects.aggregate(avg=Avg('overall_score'))['avg'] or 0

        return JsonResponse({
            'total_interactions': total,
            'total_threats':      threats,
            'threat_rate':        round(threats / total * 100, 1) if total else 0,
            'threat_by_level':    {d['threat_level']: d['count'] for d in by_level},
            'kill_switch_events': kill_events,
            'kill_switch_active': KillSwitch.status()['killed'],
            'avg_threat_score':   round(avg_score, 4),
            'unread_alerts':      SystemAlert.objects.filter(is_read=False).count(),
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
                    'id':               log.id,
                    'timestamp':        log.timestamp.isoformat(),
                    'prompt_preview':   log.user_prompt[:60],
                    'response_preview': log.ai_response_filtered[:60],
                    'threat_level':     log.threat_level,
                    'overall_score':    log.overall_score,
                    'kill_triggered':   log.kill_switch_triggered,
                    'blocked':          log.blocked,
                }
            }
        )
    except Exception as e:
        logger.warning(f"WebSocket log push failed: {e}")