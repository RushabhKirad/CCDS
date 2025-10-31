#!/usr/bin/env python3
"""
Add Test Phishing Emails to Database
Run this script to add sample phishing emails for testing
"""

from backend.db.db_utils import execute_query, fetch_one
from app import analyze_email_content
import datetime

# Your email (change if needed)
USER_EMAIL = "rushabhkirad@gmail.com"

# Test phishing emails
phishing_emails = [
    {
        'sender': 'security@paypa1-verify.tk',
        'subject': 'URGENT: Your PayPal Account Has Been Suspended',
        'body': '''Dear Customer,

Your PayPal account has been locked due to suspicious activity detected on your account.

Click here immediately to verify your account: http://bit.ly/verify-paypal-now

If you don't act now within 24 hours, your account will be permanently suspended and all funds will be frozen.

Verify Your Account Now: http://185.234.56.78/paypal-login

Best regards,
PayPal Security Team'''
    },
    {
        'sender': 'no-reply@amazon-security.ml',
        'subject': 'Your Amazon Order #12345 - Payment Failed',
        'body': '''Hello,

Your recent Amazon order could not be processed due to payment failure.

Order Details:
- iPhone 15 Pro Max - $1,299
- Delivery Address: [Your Address]

Update your payment method immediately: http://amzn-update.tk/payment

If you don't update within 12 hours, your order will be cancelled.

Amazon Customer Service'''
    },
    {
        'sender': 'alert@bank-security.cf',
        'subject': 'ALERT: Unusual Activity Detected on Your Account',
        'body': '''SECURITY ALERT

We have detected unusual activity on your bank account ending in ****4567.

Suspicious transactions:
- $2,500 - International Wire Transfer
- $1,800 - Online Purchase

If this wasn't you, verify your identity immediately:
http://secure-bank-verify.tk/login

Your account will be locked in 2 hours for your protection.

Security Department
Customer Protection Team'''
    },
    {
        'sender': 'winner@lottery-international.ga',
        'subject': 'Congratulations! You Won $5,000,000 in International Lottery',
        'body': '''CONGRATULATIONS!!!

You have been selected as the WINNER of the International Email Lottery!

Prize Amount: $5,000,000 USD
Ticket Number: LT-2024-789456
Draw Date: October 30, 2024

To claim your prize, send the following information:
- Full Name
- Bank Account Number
- Phone Number
- Copy of ID

Send to: claims@lottery-international.ga

Act fast! Claim expires in 48 hours.

International Lottery Commission'''
    },
    {
        'sender': 'support@microsoft-security.tk',
        'subject': 'Your Microsoft Account Will Be Closed',
        'body': '''Microsoft Account Security Alert

Your Microsoft account will be permanently closed due to violation of terms of service.

Account: rushabhkirad@gmail.com
Reason: Suspicious login attempts detected

To prevent account closure, verify your identity:
http://microsoft-verify.tk/account

You have 6 hours to respond or your account will be deleted along with:
- All emails
- OneDrive files
- Office documents

Microsoft Security Team
Do not reply to this email'''
    },
    {
        'sender': 'hr@job-offer.ml',
        'subject': 'Job Offer - $15,000/month - Work From Home',
        'body': '''Dear Job Seeker,

Congratulations! You have been selected for a high-paying remote position.

Position: Data Entry Specialist
Salary: $15,000 per month
Hours: Flexible (2-3 hours/day)
Location: Work from home

No experience required! Start immediately!

To accept this offer, click here: http://job-offer.ml/accept

You will need to pay a one-time registration fee of $99 to process your employment documents.

Apply now before this opportunity expires!

HR Department
Global Recruitment Services'''
    },
    {
        'sender': 'tax-refund@irs-gov.tk',
        'subject': 'IRS Tax Refund Notification - $3,847.00',
        'body': '''Internal Revenue Service
Tax Refund Department

Dear Taxpayer,

You are eligible for a tax refund of $3,847.00 for the fiscal year 2024.

Refund Amount: $3,847.00
Reference Number: IRS-2024-REF-89456

To receive your refund, verify your information:
http://irs-refund.tk/claim

Required Information:
- Social Security Number
- Bank Account Details
- Date of Birth

Process your refund within 72 hours or it will be forfeited.

IRS Refund Processing Center
Department of Treasury'''
    },
    {
        'sender': 'ceo@urgent-request.cf',
        'subject': 'URGENT: CEO Request - Immediate Action Required',
        'body': '''Hi,

I'm currently in a meeting and need your immediate help.

I need you to purchase 10 gift cards ($500 each) for client gifts. This is urgent and confidential.

Buy iTunes or Amazon gift cards and send me the codes via email.

I'll reimburse you tomorrow. Don't discuss this with anyone.

Thanks,
CEO
Sent from my iPhone'''
    },
    {
        'sender': 'delivery@fedex-tracking.ml',
        'subject': 'FedEx Package Delivery Failed - Action Required',
        'body': '''FedEx Delivery Notification

Your package delivery failed due to incorrect address.

Tracking Number: FX789456123
Package: 1 item (2.5 kg)
Delivery Attempts: 3

Update your delivery address: http://fedex-redelivery.ml/update

Additional delivery fee: $4.99

If not updated within 24 hours, package will be returned to sender.

FedEx Customer Service
Track your package: http://fedex-tracking.ml/track'''
    },
    {
        'sender': 'security@google-account.tk',
        'subject': 'Google Security Alert: New Sign-in from Unknown Device',
        'body': '''Google Security Alert

We detected a new sign-in to your Google Account from an unknown device.

Device: Windows PC
Location: Nigeria
IP Address: 197.234.56.78
Time: October 30, 2024 10:30 AM

If this wasn't you, secure your account immediately:
http://google-secure.tk/verify

Your account will be locked in 1 hour for security.

Click here to review activity: http://google-secure.tk/activity

Google Security Team
This is an automated message'''
    }
]

def add_phishing_emails():
    """Add test phishing emails to database"""
    print(f"\n{'='*60}")
    print("ADDING TEST PHISHING EMAILS")
    print(f"{'='*60}\n")
    
    added_count = 0
    
    for i, email_data in enumerate(phishing_emails, 1):
        try:
            print(f"[{i}/{len(phishing_emails)}] Adding: {email_data['subject'][:50]}...")
            
            # Check if email already exists
            existing = fetch_one(
                "SELECT id FROM emails WHERE sender = %s AND subject = %s AND user_email = %s",
                (email_data['sender'], email_data['subject'], USER_EMAIL)
            )
            
            if existing:
                print(f"  ⚠️  Already exists (ID: {existing['id']})")
                continue
            
            # Insert email
            insert_query = """
                INSERT INTO emails (sender, subject, body, user_email, receiver, is_read, created_at) 
                VALUES (%s, %s, %s, %s, %s, 0, %s)
            """
            result = execute_query(
                insert_query,
                (email_data['sender'], email_data['subject'], email_data['body'], 
                 USER_EMAIL, USER_EMAIL, datetime.datetime.now())
            )
            
            if result:
                # Get the inserted email ID
                email_record = fetch_one(
                    "SELECT id FROM emails WHERE sender = %s AND subject = %s ORDER BY id DESC LIMIT 1",
                    (email_data['sender'], email_data['subject'])
                )
                
                if email_record:
                    email_id = email_record['id']
                    print(f"  ✅ Added (ID: {email_id})")
                    
                    # Analyze the email
                    print(f"  🤖 Analyzing...")
                    try:
                        label, confidence = analyze_email_content(
                            email_id, 
                            email_data['body'], 
                            email_data['subject']
                        )
                        print(f"  📊 Result: {label.upper()} ({confidence:.1%} confidence)")
                        added_count += 1
                    except Exception as e:
                        print(f"  ⚠️  Analysis error: {e}")
                else:
                    print(f"  ❌ Could not retrieve email ID")
            else:
                print(f"  ❌ Failed to insert")
                
        except Exception as e:
            print(f"  ❌ Error: {e}")
    
    print(f"\n{'='*60}")
    print(f"✅ Successfully added {added_count}/{len(phishing_emails)} phishing emails")
    print(f"{'='*60}\n")
    print(f"📧 Check your dashboard: http://localhost:5000/dashboard")
    print(f"👤 User: {USER_EMAIL}\n")

if __name__ == "__main__":
    add_phishing_emails()
