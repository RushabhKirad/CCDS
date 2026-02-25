import redis
import json
import os
from typing import Dict, Any
import logging

logger = logging.getLogger(__name__)

class RedisClient:
    def __init__(self):
        redis_url = os.getenv("REDIS_URL", "redis://localhost:6379")
        try:
            self.client = redis.from_url(redis_url, decode_responses=True)
            # Test connection
            self.client.ping()
        except:
            # Fallback to in-memory queue for free hosting
            self.client = None
        self.event_queue = "network_events"
        self.alert_channel = "anomaly_alerts"
    
    def publish_event(self, event: Dict[str, Any]) -> bool:
        if not self.client:
            return True  # Skip Redis for free hosting
        try:
            self.client.lpush(self.event_queue, json.dumps(event, default=str))
            return True
        except Exception as e:
            logger.error(f"Failed to publish event: {e}")
            return False
    
    def get_event(self) -> Dict[str, Any]:
        if not self.client:
            return None  # Skip Redis for free hosting
        try:
            event_data = self.client.brpop(self.event_queue, timeout=1)
            if event_data:
                return json.loads(event_data[1])
            return None
        except Exception as e:
            logger.error(f"Failed to get event: {e}")
            return None
    
    def publish_alert(self, alert: Dict[str, Any]) -> bool:
        if not self.client:
            return True  # Skip Redis for free hosting
        try:
            self.client.publish(self.alert_channel, json.dumps(alert, default=str))
            return True
        except Exception as e:
            logger.error(f"Failed to publish alert: {e}")
            return False
    
    def subscribe_alerts(self):
        pubsub = self.client.pubsub()
        pubsub.subscribe(self.alert_channel)
        return pubsub

redis_client = RedisClient()