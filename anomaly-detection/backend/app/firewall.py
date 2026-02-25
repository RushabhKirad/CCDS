import time
import threading
from datetime import datetime, timedelta

class Firewall:
    def __init__(self):
        # Dictionary to store blocked IPs: {ip: timestamp_when_unblocked}
        self.blocked_ips = {}
        self.lock = threading.Lock()
        
    def is_blocked(self, ip: str) -> bool:
        """Check if an IP is currently blocked"""
        with self.lock:
            if ip in self.blocked_ips:
                expiry = self.blocked_ips[ip]
                if datetime.now() < expiry:
                    return True
                else:
                    # Expired, remove from list
                    del self.blocked_ips[ip]
        return False
        
    def block_ip(self, ip: str, duration_seconds: int = 300, reason: str = "High Risk"):
        """Block an IP for a specific duration"""
        with self.lock:
            expiry = datetime.now() + timedelta(seconds=duration_seconds)
            # Only update if new expiry is longer than existing
            if ip not in self.blocked_ips or expiry > self.blocked_ips[ip]:
                self.blocked_ips[ip] = expiry
                print(f"⛔ ACTIVE DEFENSE: Blocking IP {ip} for {duration_seconds}s. Reason: {reason}")
                
    def get_blocked_ips(self):
        """Get list of currently blocked IPs"""
        active_blocks = {}
        with self.lock:
            now = datetime.now()
            # Clean up expired
            self.blocked_ips = {ip: exp for ip, exp in self.blocked_ips.items() if exp > now}
            
            for ip, expiry in self.blocked_ips.items():
                remaining = int((expiry - now).total_seconds())
                active_blocks[ip] = remaining
        return active_blocks

# Global firewall instance
firewall = Firewall()
