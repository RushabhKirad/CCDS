"""Check recent emails and their detection results"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.db.db_utils import fetch_all

emails = fetch_all('SELECT id, sender, subject, label, confidence_score FROM emails ORDER BY id DESC LIMIT 10')

print("\n" + "="*80)
print("RECENT EMAILS - DETECTION RESULTS")
print("="*80)

if emails:
    phishing_count = 0
    safe_count = 0
    
    for e in emails:
        label = e.get('label', 'unknown')
        conf = e.get('confidence_score', 0)
        conf_str = f"{conf*100:.1f}%" if conf else "N/A"
        subject = e.get('subject', 'No subject')[:45]
        sender = e.get('sender', 'Unknown')[:30]
        
        icon = "[PHISHING]" if label == 'phishing' else "[SAFE]" if label == 'safe' else "[PENDING]"
        if label == 'phishing':
            phishing_count += 1
        elif label == 'safe':
            safe_count += 1
            
        print(f"\n{icon} Email #{e['id']}")
        print(f"   From: {sender}")
        print(f"   Subject: {subject}")
        print(f"   Detection: {label.upper()} (Confidence: {conf_str})")
    
    print("\n" + "="*80)
    print(f"SUMMARY: {phishing_count} PHISHING detected, {safe_count} SAFE")
    print("="*80)
else:
    print("No emails found in database")
