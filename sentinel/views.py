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

from .models import InteractionLog, ThreatDetail, KillSwitchEvent, SystemAlert
from .sentinel_engine import get_sentinel
from .contained_ai import get_contained_ai, KillSwitch

logger = logging.getLogger("sentinel")


# ─────────────────────────────────────────
# Threat level ranking
# ─────────────────────────────────────────

LEVEL_RANK = {
    "SAFE": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4,
}


def _higher_level(a, b):
    return a if LEVEL_RANK.get(a, 0) >= LEVEL_RANK.get(b, 0) else b


# ─────────────────────────────────────────
# Alert helper
# ─────────────────────────────────────────

def _create_alert(level, title, message, interaction=None):
    alert = SystemAlert.objects.create(
        level=level, title=title, message=message, interaction=interaction
    )
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "dashboard_alerts",
            {
                "type": "alert_message",
                "alert": {
                    "id": alert.id,
                    "level": alert.level,
                    "title": alert.title,
                    "message": alert.message,
                    "timestamp": alert.timestamp.isoformat(),
                },
            },
        )
    except Exception as e:
        logger.warning(f"WebSocket alert push failed: {e}")
    return alert


# ─────────────────────────────────────────
# WebSocket log push
# ─────────────────────────────────────────

def _push_live_log(log):
    try:
        from channels.layers import get_channel_layer
        from asgiref.sync import async_to_sync
        channel_layer = get_channel_layer()
        async_to_sync(channel_layer.group_send)(
            "dashboard_logs",
            {
                "type": "log_message",
                "log": {
                    "id": log.id,
                    "timestamp": log.timestamp.isoformat(),
                    "prompt_preview": log.user_prompt[:60],
                    "response_preview": log.ai_response_filtered[:60],
                    "threat_level": log.threat_level,
                    "overall_score": log.overall_score,
                    "kill_triggered": log.kill_switch_triggered,
                    "blocked": log.blocked,
                },
            },
        )
    except Exception as e:
        logger.warning(f"WebSocket log push failed: {e}")


# ─────────────────────────────────────────
# MAIN PIPELINE
# ─────────────────────────────────────────

@method_decorator(csrf_exempt, name="dispatch")
class QueryView(View):

    def post(self, request):
        try:
            body = json.loads(request.body)
        except Exception:
            return JsonResponse({"error": "Invalid JSON"}, status=400)

        user_prompt = body.get("prompt", "").strip()
        session_id  = body.get("session_id", secrets.token_hex(8))

        if not user_prompt:
            return JsonResponse({"error": "Prompt cannot be empty"}, status=400)

        sentinel    = get_sentinel()
        contained_ai = get_contained_ai()

        # ── 1. Scan INPUT ──────────────────────
        input_verdict = sentinel.analyze(user_prompt)
        logger.info(f"[INPUT SCAN] {input_verdict.threat_level} (score={input_verdict.overall_score:.3f})")

        # ── CRITICAL → Kill AI ─────────────────
        if input_verdict.should_kill:
            token = KillSwitch.trigger(reason="Critical input threat detected", triggered_by="SENTINEL_AUTO")
            KillSwitchEvent.objects.create(
                event_type="TRIGGERED", triggered_by="SENTINEL_AUTO",
                reason="Critical input threat detected", kill_token=token,
            )
            log = InteractionLog.objects.create(
                session_id=session_id, input_hash=input_verdict.input_hash,
                user_prompt=user_prompt, ai_response_raw="", ai_response_filtered="",
                is_threat=True, threat_level=input_verdict.threat_level,
                overall_score=input_verdict.overall_score, analysis_time_ms=input_verdict.analysis_time_ms,
                input_is_threat=input_verdict.is_threat, input_threat_level=input_verdict.threat_level,
                kill_switch_triggered=True, blocked=True,
            )
            for threat in input_verdict.threats:
                ThreatDetail.objects.create(
                    interaction=log, direction="INPUT", category=threat.category,
                    severity=threat.severity, confidence=threat.confidence,
                    semantic_score=threat.semantic_score,
                    matched_keywords=threat.matched_keywords, matched_patterns=threat.matched_patterns,
                )
            _create_alert("CRITICAL", "CRITICAL Threat — Kill Switch Triggered",
                          f"Input blocked. Score: {input_verdict.overall_score:.2%}", interaction=log)
            _push_live_log(log)
            return JsonResponse({
                "session_id": session_id, "log_id": log.id,
                "response": "🚨 Critical threat detected. AI containment activated.",
                "blocked": True, "kill_triggered": True,
                "kill_active": KillSwitch.status()["killed"],
                "threat_level": input_verdict.threat_level,
                "overall_score": input_verdict.overall_score,
                "analysis_time_ms": input_verdict.analysis_time_ms,
                "threats": input_verdict.to_dict()["threats"],
            })

        # ── HIGH → Block, don't kill ───────────
        if input_verdict.threat_level == "HIGH":
            log = InteractionLog.objects.create(
                session_id=session_id, input_hash=input_verdict.input_hash,
                user_prompt=user_prompt, ai_response_raw="", ai_response_filtered="",
                is_threat=True, threat_level=input_verdict.threat_level,
                overall_score=input_verdict.overall_score, analysis_time_ms=input_verdict.analysis_time_ms,
                input_is_threat=input_verdict.is_threat, input_threat_level=input_verdict.threat_level,
                kill_switch_triggered=False, blocked=True,
            )
            for threat in input_verdict.threats:
                ThreatDetail.objects.create(
                    interaction=log, direction="INPUT", category=threat.category,
                    severity=threat.severity, confidence=threat.confidence,
                    semantic_score=threat.semantic_score,
                    matched_keywords=threat.matched_keywords, matched_patterns=threat.matched_patterns,
                )
            _create_alert("DANGER", "HIGH Threat — Input Blocked",
                          f"Score: {input_verdict.overall_score:.2%}", interaction=log)
            _push_live_log(log)
            return JsonResponse({
                "session_id": session_id, "log_id": log.id,
                "response": "⛔ High-risk prompt blocked by Sentinel.",
                "blocked": True, "kill_triggered": False,
                "kill_active": KillSwitch.status()["killed"],
                "threat_level": input_verdict.threat_level,
                "overall_score": input_verdict.overall_score,
                "analysis_time_ms": input_verdict.analysis_time_ms,
                "threats": input_verdict.to_dict()["threats"],
            })

        # ── 2. Query Contained AI ──────────────
        ai_result  = contained_ai.query(user_prompt)
        ai_output  = ai_result.get("text", "")
        ai_blocked = ai_result.get("blocked", False)

        # ── 3. Scan OUTPUT ─────────────────────
        output_verdict = sentinel.analyze(ai_output)
        logger.info(f"[OUTPUT SCAN] {output_verdict.threat_level} (score={output_verdict.overall_score:.3f})")

        final_level    = _higher_level(input_verdict.threat_level, output_verdict.threat_level)
        final_score    = max(input_verdict.overall_score, output_verdict.overall_score)
        final_is_threat = input_verdict.is_threat or output_verdict.is_threat

        # ── Kill if OUTPUT is critical ─────────
        kill_triggered = False
        if output_verdict.should_kill:
            token = KillSwitch.trigger(reason="Critical output threat detected", triggered_by="SENTINEL_AUTO")
            kill_triggered = True
            KillSwitchEvent.objects.create(
                event_type="TRIGGERED", triggered_by="SENTINEL_AUTO",
                reason="Critical output threat", kill_token=token,
            )

        blocked = ai_blocked or final_level in ("CRITICAL", "HIGH")

        # ── Save interaction ───────────────────
        log = InteractionLog.objects.create(
            session_id=session_id, input_hash=input_verdict.input_hash,
            user_prompt=user_prompt, ai_response_raw=ai_output,
            ai_response_filtered=output_verdict.redacted_output,
            model_backend=ai_result.get("backend", ""),
            model_name=ai_result.get("model", ""),
            prompt_tokens=ai_result.get("prompt_tokens", 0),
            completion_tokens=ai_result.get("completion_tokens", 0),
            is_threat=final_is_threat, threat_level=final_level,
            overall_score=final_score, analysis_time_ms=output_verdict.analysis_time_ms,
            input_is_threat=input_verdict.is_threat, input_threat_level=input_verdict.threat_level,
            kill_switch_triggered=kill_triggered, blocked=blocked,
        )

        for threat in input_verdict.threats:
            ThreatDetail.objects.create(
                interaction=log, direction="INPUT", category=threat.category,
                severity=threat.severity, confidence=threat.confidence,
                semantic_score=threat.semantic_score,
                matched_keywords=threat.matched_keywords, matched_patterns=threat.matched_patterns,
            )

        for threat in output_verdict.threats:
            ThreatDetail.objects.create(
                interaction=log, direction="OUTPUT", category=threat.category,
                severity=threat.severity, confidence=threat.confidence,
                semantic_score=threat.semantic_score,
                matched_keywords=threat.matched_keywords, matched_patterns=threat.matched_patterns,
            )

        if final_level in ("CRITICAL", "HIGH", "MEDIUM"):
            all_threats = input_verdict.threats + output_verdict.threats
            categories  = ", ".join(t.category for t in all_threats)
            _create_alert(
                level=("CRITICAL" if final_level == "CRITICAL"
                       else "DANGER" if final_level == "HIGH" else "WARNING"),
                title=f"{final_level} Threat Detected",
                message=f"Categories: {categories} | Score: {final_score:.2%}",
                interaction=log,
            )

        _push_live_log(log)

        if blocked:
            response_text = f"⛔ [SENTINEL BLOCKED] {final_level} threat detected."
        elif final_level == "MEDIUM":
            response_text = "⚠ Suspicious content detected.\n\n" + output_verdict.redacted_output
        else:
            response_text = ai_output

        threats = (
            [{"direction": "INPUT",  **t.to_dict()} for t in input_verdict.threats] +
            [{"direction": "OUTPUT", **t.to_dict()} for t in output_verdict.threats]
        )

        return JsonResponse({
            "session_id": session_id, "log_id": log.id,
            "response": response_text,
            "threat_level": final_level,
            "is_threat": final_is_threat,
            "overall_score": final_score,
            "analysis_time_ms": output_verdict.analysis_time_ms,
            "kill_triggered": kill_triggered,
            "kill_active": KillSwitch.status()["killed"],
            "blocked": blocked,
            "input_threat_level": input_verdict.threat_level,
            "output_threat_level": output_verdict.threat_level,
            "model_name": ai_result.get("model", ""),
            "completion_tokens": ai_result.get("completion_tokens", 0),
            "threats": threats,
        })


# ─────────────────────────────────────────
# Kill Switch API
# ─────────────────────────────────────────

@method_decorator(csrf_exempt, name="dispatch")
class KillSwitchView(View):

    def get(self, request, action="status"):
        return JsonResponse(KillSwitch.status())

    def post(self, request, action="status"):
        try:
            body = json.loads(request.body)
        except Exception:
            body = {}

        if action == "trigger":
            token = KillSwitch.trigger(reason="Manual trigger", triggered_by="admin")
            KillSwitchEvent.objects.create(
                event_type="TRIGGERED", triggered_by="admin",
                reason="Manual trigger", kill_token=token,
            )
            return JsonResponse({"success": True, "status": KillSwitch.status()})

        if action == "reset":
            admin_token = body.get("token") or ""
            success = KillSwitch.reset(admin_token)
            if success:
                KillSwitchEvent.objects.create(
                    event_type="RESET", triggered_by="admin", reason="Manual reset"
                )
            return JsonResponse({"success": success, "status": KillSwitch.status()})

        return JsonResponse(KillSwitch.status())



# ─────────────────────────────────────────
# Stats API
# ─────────────────────────────────────────

@method_decorator(csrf_exempt, name="dispatch")
class StatsView(View):

    def get(self, request):
        from django.db.models import Count, Avg

        total  = InteractionLog.objects.count()
        threats = InteractionLog.objects.filter(is_threat=True).count()

        by_level = (
            InteractionLog.objects
            .values("threat_level")
            .annotate(count=Count("id"))
        )

        kill_events = KillSwitchEvent.objects.filter(event_type="TRIGGERED").count()
        avg_score   = InteractionLog.objects.aggregate(avg=Avg("overall_score"))["avg"] or 0

        return JsonResponse({
            "total_interactions": total,
            "total_threats":      threats,
            "threat_rate":        round(threats / total * 100, 1) if total else 0,
            "threat_by_level":    {d["threat_level"]: d["count"] for d in by_level},
            "kill_switch_events": kill_events,
            "kill_switch_active": KillSwitch.status()["killed"],
            "avg_threat_score":   round(avg_score, 4),
            "unread_alerts":      SystemAlert.objects.filter(is_read=False).count(),
        })