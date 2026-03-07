from django.urls import path
from . import views

urlpatterns = [
    path('', views.dashboard, name='dashboard'),
    path('logs/', views.logs_view, name='logs'),
    path('logs/<int:log_id>/', views.log_detail, name='log_detail'),
    path('kill-switch/', views.kill_switch_view, name='kill_switch'),
    path('policies/', views.policies_view, name='policies'),
    path('alerts/', views.alerts_view, name='alerts'),
    path('sandbox/', views.sandbox_view, name='sandbox'),
    path('ajax/stats/', views.api_stats, name='ajax_stats'),
    path('ajax/policy/<int:policy_id>/toggle/', views.api_policy_toggle, name='policy_toggle'),
    
]
