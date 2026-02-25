import numpy as np
from typing import List, Dict, Any, Tuple
from datetime import datetime, timedelta
import pandas as pd

class TimeWindowProcessor:
    def __init__(self, window_size_seconds: int = 60, overlap_ratio: float = 0.5):
        self.window_size = window_size_seconds
        self.overlap_ratio = overlap_ratio
        self.step_size = int(window_size_seconds * (1 - overlap_ratio))
    
    def create_time_windows(self, events: List[Dict[str, Any]]) -> List[List[Dict[str, Any]]]:
        """Create overlapping time windows from events"""
        if not events:
            return []
        
        # Sort events by timestamp
        sorted_events = sorted(events, key=lambda x: self._parse_timestamp(x.get('timestamp')))
        
        windows = []
        start_time = self._parse_timestamp(sorted_events[0]['timestamp'])
        
        while True:
            end_time = start_time + timedelta(seconds=self.window_size)
            
            # Get events in current window
            window_events = [
                event for event in sorted_events
                if start_time <= self._parse_timestamp(event.get('timestamp')) < end_time
            ]
            
            if not window_events:
                break
            
            windows.append(window_events)
            
            # Move to next window
            start_time += timedelta(seconds=self.step_size)
            
            # Stop if we've processed all events
            if start_time >= self._parse_timestamp(sorted_events[-1]['timestamp']):
                break
        
        return windows
    
    def _parse_timestamp(self, timestamp: Any) -> datetime:
        """Parse various timestamp formats"""
        if isinstance(timestamp, datetime):
            return timestamp
        elif isinstance(timestamp, str):
            return pd.to_datetime(timestamp)
        elif isinstance(timestamp, (int, float)):
            return datetime.fromtimestamp(timestamp)
        else:
            return datetime.now()
    
    def aggregate_window_stats(self, window_events: List[Dict[str, Any]]) -> Dict[str, float]:
        """Aggregate statistics for a time window"""
        if not window_events:
            return {}
        
        stats = {
            'event_count': len(window_events),
            'total_bytes': sum(event.get('byte_count', 0) for event in window_events),
            'total_packets': sum(event.get('packet_count', 0) for event in window_events),
            'unique_src_ips': len(set(event.get('src_ip', '') for event in window_events)),
            'unique_dst_ips': len(set(event.get('dst_ip', '') for event in window_events)),
            'unique_ports': len(set(str(event.get('src_port', '')) + str(event.get('dst_port', '')) 
                                  for event in window_events)),
            'avg_packet_size': 0,
            'window_duration': self.window_size
        }
        
        if stats['total_packets'] > 0:
            stats['avg_packet_size'] = stats['total_bytes'] / stats['total_packets']
        
        return stats