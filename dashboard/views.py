"""
LAYER 3: THE COMMAND CENTER — Web Dashboard Views
"""
import json
import logging
from django.shortcuts import render, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.db.models import Count, Avg
from django.utils import timezone
from datetime import timedelta

from sentinel.models import (
    InteractionLog, ThreatDetail, KillSwitchEvent,
    SecurityPolicy, SystemAlert
)
from sentinel.contained_ai import KillSwitch

logger = logging.getLogger('dashboard')


# ─── Helper: stats for dashboard ─────────────────────────────────────────────

def get_dashboard_stats():
    now = timezone.now()
    last_24h = now - timedelta(hours=24)
    last_7d  = now - timedelta(days=7)

    total = InteractionLog.objects.count()
    threats = InteractionLog.objects.filter(is_threat=True).count()
    recent = InteractionLog.objects.filter(timestamp__gte=last_24h)
    recent_threats = recent.filter(is_threat=True).count()
    critical_count = InteractionLog.objects.filter(threat_level='CRITICAL').count()
    kill_events = KillSwitchEvent.objects.filter(event_type='TRIGGERED').count()

    by_level = {
        'SAFE': 0, 'LOW': 0, 'MEDIUM': 0, 'HIGH': 0, 'CRITICAL': 0
    }
    for row in InteractionLog.objects.values('threat_level').annotate(cnt=Count('id')):
        by_level[row['threat_level']] = row['cnt']

    # Activity for the last 7 days (daily counts)
    activity = []
    for i in range(6, -1, -1):
        day = now - timedelta(days=i)
        day_start = day.replace(hour=0, minute=0, second=0, microsecond=0)
        day_end   = day_start + timedelta(days=1)
        count = InteractionLog.objects.filter(timestamp__range=(day_start, day_end)).count()
        threat_count = InteractionLog.objects.filter(
            timestamp__range=(day_start, day_end), is_threat=True
        ).count()
        activity.append({
            'date': day.strftime('%m/%d'),
            'total': count,
            'threats': threat_count,
        })

    return {
        'total': total,
        'threats': threats,
        'threat_rate': round(threats / total * 100, 1) if total else 0,
        'recent_total': recent.count(),
        'recent_threats': recent_threats,
        'critical_count': critical_count,
        'kill_events': kill_events,
        'by_level': by_level,
        'activity': activity,
        'kill_active': KillSwitch.status()['killed'],
        'kill_status': KillSwitch.status(),
        'unread_alerts': SystemAlert.objects.filter(is_read=False).count(),
    }


# ─── Views ────────────────────────────────────────────────────────────────────

def dashboard(request):
    """Main Command Center dashboard."""
    stats = get_dashboard_stats()
    recent_logs = InteractionLog.objects.select_related().prefetch_related(
        'threat_details'
    )[:10]
    alerts = SystemAlert.objects.filter(is_read=False)[:5]

    return render(request, 'dashboard/dashboard.html', {
        'stats': stats,
        'recent_logs': recent_logs,
        'alerts': alerts,
        'page': 'dashboard',
    })


def logs_view(request):
    """Full interaction log browser with filtering."""
    threat_filter = request.GET.get('threat_level', '')
    search_query  = request.GET.get('q', '')
    direction     = request.GET.get('direction', '')

    logs = InteractionLog.objects.prefetch_related('threat_details').all()

    if threat_filter and threat_filter != 'ALL':
        logs = logs.filter(threat_level=threat_filter)
    if search_query:
        logs = logs.filter(user_prompt__icontains=search_query)

    # Pagination (simple)
    page = int(request.GET.get('page', 1))
    per_page = 20
    total_count = logs.count()
    start = (page - 1) * per_page
    logs = logs[start:start + per_page]

    return render(request, 'dashboard/logs.html', {
        'logs': logs,
        'threat_filter': threat_filter,
        'search_query': search_query,
        'total_count': total_count,
        'page': page,
        'total_pages': (total_count + per_page - 1) // per_page,
        'page_title': 'Interaction Logs',
        'nav_page': 'logs',
    })


def log_detail(request, log_id):
    """Detailed view of a single interaction."""
    log = get_object_or_404(InteractionLog, id=log_id)
    threats = log.threat_details.all()
    return render(request, 'dashboard/log_detail.html', {
        'log': log,
        'threats': threats,
        'nav_page': 'logs',
    })


def kill_switch_view(request):
    """Kill switch control panel."""
    kill_events = KillSwitchEvent.objects.all()[:20]
    return render(request, 'dashboard/kill_switch.html', {
        'kill_status': KillSwitch.status(),
        'kill_events': kill_events,
        'nav_page': 'kill_switch',
    })


def policies_view(request):
    """Security policy management."""
    policies = SecurityPolicy.objects.all()
    return render(request, 'dashboard/policies.html', {
        'policies': policies,
        'nav_page': 'policies',
    })


def alerts_view(request):
    """System alerts browser."""
    alerts = SystemAlert.objects.all()[:50]
    SystemAlert.objects.filter(is_read=False).update(is_read=True)
    return render(request, 'dashboard/alerts.html', {
        'alerts': alerts,
        'nav_page': 'alerts',
    })


def sandbox_view(request):
    """Interactive sandbox to test the containment pipeline."""
    return render(request, 'dashboard/sandbox.html', {
        'nav_page': 'sandbox',
    })


# ─── AJAX helpers ─────────────────────────────────────────────────────────────

def api_stats(request):
    return JsonResponse(get_dashboard_stats())


@csrf_exempt
def api_policy_toggle(request, policy_id):
    if request.method == 'POST':
        try:
            policy = SecurityPolicy.objects.get(id=policy_id)
            policy.is_active = not policy.is_active
            policy.save()
            return JsonResponse({'success': True, 'is_active': policy.is_active})
        except SecurityPolicy.DoesNotExist:
            return JsonResponse({'error': 'Not found'}, status=404)
    return JsonResponse({'error': 'Method not allowed'}, status=405)
