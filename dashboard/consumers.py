"""
Django Channels WebSocket consumers for real-time dashboard updates.
"""
import json
from channels.generic.websocket import AsyncWebsocketConsumer


class DashboardConsumer(AsyncWebsocketConsumer):
    """Sends real-time log and alert events to the dashboard."""

    async def connect(self):
        await self.channel_layer.group_add('dashboard_logs', self.channel_name)
        await self.channel_layer.group_add('dashboard_alerts', self.channel_name)
        await self.accept()
        await self.send(text_data=json.dumps({
            'type': 'connected',
            'message': 'Sentinel WebSocket connection established'
        }))

    async def disconnect(self, close_code):
        await self.channel_layer.group_discard('dashboard_logs', self.channel_name)
        await self.channel_layer.group_discard('dashboard_alerts', self.channel_name)

    async def log_message(self, event):
        """Receive log event from channel layer and forward to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'new_log',
            'data': event['log']
        }))

    async def alert_message(self, event):
        """Receive alert event from channel layer and forward to WebSocket."""
        await self.send(text_data=json.dumps({
            'type': 'new_alert',
            'data': event['alert']
        }))
