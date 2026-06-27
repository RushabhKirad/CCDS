"""
Test Script: Inject Phishing Emails for Testing Detection System
Adds 4 phishing emails + 1 normal email directly to database
Uses the existing ModelLoader from backend
"""
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from backend.db.db_utils import execute_query, fetch_one, fetch_all
from backend.analyzers.model_loader import ModelLoader
from hybrid_analysis import hybrid_analyze_email

print("Loading ML models...")
try:
    model_loader = ModelLoader()
    print("[OK] All models loaded successfully!")
except Exception as e:
    print(f"[!] Model loading error: {e}")
    model_loader = None
print()

def inject_test_emails():
    """Inject test emails and run ML analysis"""
    
    user_email = "rushabhkirad@gmail.com"
    existing_user = fetch_one("SELECT email FROM users WHERE email IS NOT NULL LIMIT 1")
    if existing_user and existing_user.get('email'):
        user_email = existing_user['email']
    print(f"Using user email: {user_email}")
    
    # 4 Phishing + 1 Normal
    test_emails = [
        {
            'sender': 'security@bankofamerica-secure.xyz',
            'subject': 'URGENT: Your Account Has Been Compromised!',
            'body': '''Dear Valued Customer,
We have detected suspicious activity on your Bank of America account. 
IMMEDIATE ACTION REQUIRED: Click the link below to verify your identity:
http://bankofamerica-secure.xyz/verify?user=1234
Enter your Social Security Number, Account Number, PIN.
Your account will be permanently suspended in 24 hours.
Bank of America Security Team''',
            'expected': 'phishing'
        },
        {
            'sender': 'support@paypal-verification.tk',
            'subject': 'Your PayPal Account is Limited - Verify Now',
            'body': '''Hello,
We've noticed unusual sign-in activity on your PayPal account. 
To restore your account, please confirm your information:
http://paypal-verification.tk/confirm
Required: Credit Card Number, CVV Code, Billing Address.
Failure to verify will result in permanent account closure.''',
            'expected': 'phishing'
        },
        {
            'sender': 'admin@microsoft-365-alert.com',
            'subject': 'Microsoft 365: Password Expires in 24 Hours',
            'body': '''Your Microsoft 365 password will expire in 24 hours.
CLICK HERE TO KEEP YOUR PASSWORD: http://microsoft-365-alert.com/reset
If you don't update your password immediately, all emails will be deleted.
Enter your current password and new password at the link above.''',
            'expected': 'phishing'
        },
        {
            'sender': 'winner@international-lottery.ml',
            'subject': 'CONGRATULATIONS! You Won $5,000,000 USD!!!',
            'body': '''CONGRATULATIONS!!!
Your email was selected as the WINNER of the International Email Lottery!
You have won: $5,000,000.00 USD
To claim your prize, send the following to claim@lottery.ml:
- Bank Account Number
- Routing Number
- $500 processing fee via Western Union
Reply within 48 hours or your prize goes to another winner!''',
            'expected': 'phishing'
        },
        {
            'sender': 'newsletter@techcrunch.com',
            'subject': 'TechCrunch Daily: Top Tech News for January 29, 2026',
            'body': '''Good morning!
Here are today's top stories from TechCrunch:
1. Apple announces new AI-powered features for iPhone 18
2. Google Cloud introduces quantum computing services
3. Tesla's new Robotaxi service launches in 5 more cities
Read more at techcrunch.com
Unsubscribe: https://techcrunch.com/preferences''',
            'expected': 'safe'
        }
    ]
    
    print("="*70)
    print("EMAIL SECURITY SYSTEM - PHISHING DETECTION TEST")
    print("="*70)
    print(f"Injecting {len(test_emails)} test emails (4 phishing + 1 normal)\n")
    
    results = []
    correct = 0
    
    for i, email in enumerate(test_emails, 1):
        print(f"\n--- Email {i}/{len(test_emails)} ---")
        print(f"From: {email['sender']}")
        print(f"Subject: {email['subject'][:50]}")
        print(f"Expected: {email['expected'].upper()}")
        
        # Insert into database
        query = """INSERT INTO emails (sender, subject, body, user_email, is_read, created_at, label) 
                   VALUES (%s, %s, %s, %s, 0, NOW(), 'pending')"""
        result = execute_query(query, (email['sender'], email['subject'], email['body'], user_email))
        
        if result:
            email_record = fetch_one(
                "SELECT id FROM emails WHERE sender = %s AND user_email = %s ORDER BY id DESC LIMIT 1",
                (email['sender'], user_email)
            )
            
            if email_record:
                email_id = email_record['id']
                
                print("Running ML analysis...")
                try:
                    predicted, confidence = hybrid_analyze_email(email_id, email['body'], email['subject'], model_loader)
                except Exception as e:
                    print(f"Analysis error: {e}")
                    predicted = 'pending'
                    confidence = 0
                
                is_correct = predicted == email['expected']
                if is_correct:
                    correct += 1
                
                status = "CORRECT" if is_correct else "WRONG"
                print(f"Predicted: {predicted.upper()} (Confidence: {confidence*100:.1f}%)")
                print(f"Result: {status}")
                
                results.append({
                    'id': email_id,
                    'expected': email['expected'],
                    'predicted': predicted,
                    'confidence': confidence,
                    'correct': is_correct
                })
    
    # Summary
    print("\n" + "="*70)
    print("DETECTION TEST RESULTS SUMMARY")
    print("="*70)
    accuracy = (correct/len(test_emails))*100
    
    print(f"\nTotal Emails: {len(test_emails)}")
    print(f"Correct Predictions: {correct}/{len(test_emails)}")
    print(f"Accuracy: {accuracy:.1f}%\n")
    
    print("Detailed Results:")
    print("-" * 70)
    for r in results:
        status = "[OK]" if r['correct'] else "[X]"
        print(f"{status} Email #{r['id']}: Expected {r['expected'].upper():8} | Predicted {r['predicted'].upper():8} | Conf: {r['confidence']*100:.1f}%")
    
    print("\n" + "="*70)
    print("Test complete! Check your dashboard: http://localhost:5000/dashboard")
    print("="*70)

if __name__ == "__main__":
    inject_test_emails()
