"""Check detection results with proper formatting"""
import sys
sys.path.insert(0, '.')
from backend.db.db_utils import fetch_all

# Get all test emails with their predictions
emails = fetch_all('''
    SELECT id, sender, subject, label, confidence 
    FROM emails 
    ORDER BY id DESC 
    LIMIT 15
''')

print('=' * 70)
print('EMAIL DETECTION RESULTS')
print('=' * 70)

phishing_count = 0
safe_count = 0

for email in emails:
    label = email['label'] or 'unknown'
    conf = email.get('confidence', 0) or 0
    status = '[PHISHING]' if label == 'phishing' else '[SAFE]'
    
    if label == 'phishing':
        phishing_count += 1
    else:
        safe_count += 1
    
    sender_short = str(email['sender'])[:25]
    subject_short = str(email['subject'])[:35]
    print(f"{status:12} {conf*100:.0f}% | {sender_short:25} | {subject_short}")

print()
print(f'TOTAL: {phishing_count} PHISHING, {safe_count} SAFE')
