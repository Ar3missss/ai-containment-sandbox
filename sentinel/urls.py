from django.urls import path
from . import views

urlpatterns = [
    path('query/', views.QueryView.as_view(), name='api_query'),
    path('kill-switch/', views.KillSwitchView.as_view(), name='kill_switch_status'),
    path('kill-switch/trigger/', views.KillSwitchView.as_view(), {'action': 'trigger'}, name='kill_switch_trigger'),
    path('kill-switch/reset/', views.KillSwitchView.as_view(), {'action': 'reset'}, name='kill_switch_reset'),
    path('stats/', views.StatsView.as_view(), name='api_stats'),
]
