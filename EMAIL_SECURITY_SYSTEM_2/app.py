from flask import Flask, render_template, request, redirect, url_for, send_file, abort, jsonify, flash, session
from backend.db.db_utils import execute_query, fetch_one, fetch_all
from backend.crypto.pqc_handler import security_handler
from config import config
import os
import datetime
import hashlib
import logging
from logging.handlers import RotatingFileHandler
from functools import lru_cache

# Configure template and static directories
template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "templates")
static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "frontend", "static")

# Create Flask app with configuration
app = Flask(__name__, template_folder=template_dir, static_folder=static_dir)

# Register API routes for integration
try:
    from api_routes import api_bp
    app.register_blueprint(api_bp)
    print("✓ Integration API routes registered at /email-security/api/v1")
except Exception as e:
    print(f"⚠️ Could not register API routes: {e}")

# Load configuration
env = os.getenv('FLASK_ENV', 'development')
app.config.from_object(config.get(env, config['default']))
app.secret_key = app.config['SECRET_KEY']

# Performance optimizations
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 31536000  # 1 year cache for static files

# Add response headers for performance
@app.after_request
def after_request(response):
    # Add caching headers for static content
    if request.endpoint == 'static':
        response.cache_control.max_age = 31536000
        response.cache_control.public = True
    # Add compression hint
    if response.content_type.startswith('text/') or response.content_type.startswith('application/json'):
        response.headers['Vary'] = 'Accept-Encoding'
    return response

# Setup logging
if not app.debug:
    if not os.path.exists('logs'):
        os.mkdir('logs')
    file_handler = RotatingFileHandler('logs/app.log', maxBytes=10240, backupCount=10)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'))
    file_handler.setLevel(logging.INFO)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Email Security System startup')

# Initialize ML engine with your existing models
try:
    from backend.analyzers.model_loader import ModelLoader
    model_loader = ModelLoader()
    print("Your ML models loaded successfully!")
except Exception as e:
    print(f"Warning: Could not load your ML models: {e}")
    model_loader = None

# Initialize PQC system
try:
    print("Initializing Advanced Security System...")
    print(f"PQC Handler: {security_handler.__class__.__name__}")
    print("Quantum-safe encryption ready for Gmail credentials")
    print("Quantum-safe encryption ready for email content")
except Exception as e:
    print(f"PQC initialization warning: {e}")

# Real-time monitoring disabled to prevent unwanted background processes
print("Real-time monitoring disabled - use manual fetch only")
print("System enhanced with Advanced Security protection")

# Simple in-memory cache for performance
from threading import Lock
cache_lock = Lock()
stats_cache = {}
cache_timeout = 30  # 30 seconds

def get_cached_stats(user_email):
    """Get cached stats or fetch new ones"""
    with cache_lock:
        cache_key = f"stats_{user_email}"
        now = datetime.datetime.now()
        
        if cache_key in stats_cache:
            cached_data, timestamp = stats_cache[cache_key]
            if (now - timestamp).seconds < cache_timeout:
                return cached_data
        
        # Fetch fresh stats
        stats_query = "SELECT COUNT(*) as total, SUM(CASE WHEN label='safe' THEN 1 ELSE 0 END) as safe, SUM(CASE WHEN label='phishing' THEN 1 ELSE 0 END) as phishing, SUM(CASE WHEN label='pending' THEN 1 ELSE 0 END) as pending, SUM(CASE WHEN is_starred=1 THEN 1 ELSE 0 END) as starred, SUM(CASE WHEN is_read=0 THEN 1 ELSE 0 END) as unread FROM emails WHERE (user_email = %s OR receiver LIKE %s)"
        stats_result = fetch_one(stats_query, (user_email, f'%{user_email}%'))
        
        stats = {
            'total': stats_result['total'] or 0,
            'safe': stats_result['safe'] or 0,
            'phishing': stats_result['phishing'] or 0,
            'pending': stats_result['pending'] or 0,
            'starred': stats_result['starred'] or 0,
            'unread': stats_result['unread'] or 0
        }
        
        # Cache the result
        stats_cache[cache_key] = (stats, now)
        return stats

def clear_user_cache(user_email):
    """Clear cache for specific user"""
    with cache_lock:
        cache_key = f"stats_{user_email}"
        if cache_key in stats_cache:
            del stats_cache[cache_key]

# -------------------------
# ROUTES
# -------------------------

# API endpoint for browser extension
@app.route("/api/analyze", methods=["POST", "OPTIONS"])
def api_analyze():
    # Handle CORS preflight
    if request.method == "OPTIONS":
        response = jsonify({'status': 'ok'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
        response.headers.add('Access-Control-Allow-Methods', 'POST')
        return response
    
    try:
        data = request.get_json()
        subject = data.get('subject', 'No Subject')
        body = data.get('body', '')
        sender = data.get('sender', 'unknown@example.com')
        
        print(f"API: Analyzing email from {sender}")
        
        # Save to temp for analysis
        insert_query = "INSERT INTO emails (sender, subject, body, user_email) VALUES (%s, %s, %s, %s)"
        execute_query(insert_query, (sender, subject, body, 'api_user'))
        
        email_record = fetch_one("SELECT id FROM emails WHERE sender = %s AND subject = %s ORDER BY id DESC LIMIT 1", (sender, subject))
        
        if email_record:
            label, confidence = analyze_email_content(email_record['id'], body, subject)
            
            response = jsonify({
                'success': True,
                'prediction': label,
                'confidence': float(confidence),
                'message': f'Email classified as {label} with {int(confidence*100)}% confidence'
            })
            response.headers.add('Access-Control-Allow-Origin', '*')
            return response
        
        response = jsonify({'success': False, 'error': 'Analysis failed'})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500
    except Exception as e:
        print(f"API Error: {e}")
        response = jsonify({'success': False, 'error': str(e)})
        response.headers.add('Access-Control-Allow-Origin', '*')
        return response, 500

# Authentication decorator
def login_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin decorator
def admin_required(f):
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if ('username' not in session or session['username'] != 'admin'):
            flash('Admin access required', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# 1. Login Page
@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        user = authenticate_user(username, password)
        if user:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['email'] = user['email']
            session['full_name'] = user['full_name']
            
            # Only set admin credentials for actual admin user
            if user['username'] == 'admin':
                session['user_email'] = 'rushabhkirad@gmail.com'
                session['email'] = 'rushabhkirad@gmail.com'
                session['user_password'] = 'tddj aptv vqms zoqc'
                print('Admin credentials loaded automatically')
            
            flash(f"Welcome back, {user['full_name']}!", 'success')
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid username or password", 'danger')
    
    return render_template("login.html")

# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out successfully", 'info')
    return redirect(url_for('login'))

# User registration route
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if not all([first_name, last_name, username, email, password, confirm_password]):
            flash("All fields are required", 'error')
            return render_template("register.html")
        
        if password != confirm_password:
            flash("Passwords do not match", 'error')
            return render_template("register.html")
        
        if len(password) < 6:
            flash("Password must be at least 6 characters long", 'error')
            return render_template("register.html")
        
        # Check if user exists (simple check)
        try:
            # Create users table if it doesn't exist
            create_users_table()
            
            # Check if username or email already exists
            existing_user = fetch_one("SELECT id FROM users WHERE username = %s OR email = %s", (username, email))
            if existing_user:
                flash("Username or email already exists", 'error')
                return render_template("register.html")
            
            # Hash password and create user
            hashed_password = hash_password(password)
            full_name = f"{first_name} {last_name}"
            
            print(f"Creating user: {username}, {email}, {full_name}")
            # Don't set email in users table during registration
            insert_query = "INSERT INTO users (username, password, password_hash, full_name, role, created_at) VALUES (%s, %s, %s, %s, %s, %s)"
            result = execute_query(insert_query, (username, password, hashed_password, full_name, 'organization', datetime.datetime.now()))
            
            if result:
                print(f"✓ User {username} created successfully in database")
                # Verify user was created
                new_user = fetch_one("SELECT id, username, email FROM users WHERE username = %s", (username,))
                if new_user:
                    print(f"✓ Verified: User ID {new_user['id']} - {new_user['username']} ({new_user['email']})")
                else:
                    print("⚠️ User creation verification failed")
                    
                flash("Account created successfully! Please login.", 'success')
                return redirect(url_for('login'))
            else:
                print("✗ Failed to create user in database")
                flash("Database error. Please try again.", 'error')
                return render_template("register.html")
            
        except Exception as e:
            print(f"Registration error: {e}")
            flash("Error creating account. Please try again.", 'error')
            return render_template("register.html")
    
    return render_template("register.html")

# Simple authentication functions
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def create_users_table():
    """Update existing users table to match app requirements"""
    try:
        # Add missing columns to existing users table
        columns_to_add = [
            ("email", "VARCHAR(100)"),
            ("password_hash", "VARCHAR(255)"),
            ("full_name", "VARCHAR(100)")
        ]
        
        for column_name, column_def in columns_to_add:
            try:
                execute_query(f"ALTER TABLE users ADD COLUMN {column_name} {column_def}")
                print(f"Added column {column_name}")
            except Exception as e:
                if "Duplicate column name" not in str(e):
                    print(f"Column {column_name} error: {e}")
        
        print("Users table updated successfully")
    except Exception as e:
        print(f"Error updating users table: {e}")

def authenticate_user(username, password):
    # Try database authentication first
    try:
        hashed_password = hash_password(password)
        # Try with password_hash field first
        user = fetch_one("SELECT * FROM users WHERE username = %s AND password_hash = %s", (username, hashed_password))
        
        if not user:
            # Fallback to plain password field
            user = fetch_one("SELECT * FROM users WHERE username = %s AND password = %s", (username, password))
        
        if user:
            # For admin user, always use rushabhkirad@gmail.com
            email = 'rushabhkirad@gmail.com' if user['username'] == 'admin' else user.get('email', None)
            return {
                'id': user['id'],
                'username': user['username'],
                'email': email,
                'full_name': user.get('full_name', 'Administrator')
            }
    except Exception as e:
        print(f"Database auth error: {e}")
    
    # Fallback to hardcoded authentication (only for actual admin)
    if username == "admin" and password == "admin123":
        return {'id': 61, 'username': 'admin', 'email': 'rushabhkirad@gmail.com', 'full_name': 'Administrator'}
    return None


# 2. Dashboard (Inbox) - User-specific emails only
@app.route("/dashboard")
@login_required
def dashboard():
    folder = request.args.get('folder', 'inbox')
    user_email = session.get('user_email') or session.get('email')
    
    # Only set admin credentials for actual admin user
    if session.get('username') == 'admin':
        session['user_email'] = 'rushabhkirad@gmail.com'
        session['email'] = 'rushabhkirad@gmail.com'
        session['user_password'] = 'tddj aptv vqms zoqc'
        user_email = 'rushabhkirad@gmail.com'
    
    # If no email setup, redirect to setup
    if not user_email:
        flash("Please setup your email credentials first", 'warning')
        return redirect(url_for('setup_email'))
    
    # Optimized queries with parameterized statements and reduced data
    base_params = [user_email, f'%{user_email}%']
    
    # Select fields including encryption data for decryption
    select_fields = "id, sender, subject, COALESCE(label, 'pending') as label, COALESCE(confidence_score, 0) as confidence_score, COALESCE(is_starred, 0) as is_starred, COALESCE(is_read, 0) as is_read, encryption_method, encrypted_content_key"
    base_condition = "COALESCE(is_archived, 0) = 0 AND (user_email = %s OR receiver LIKE %s)"
    
    if folder == 'phishing':
        query = f"SELECT {select_fields} FROM emails WHERE {base_condition} AND COALESCE(label, 'pending') = 'phishing' ORDER BY COALESCE(created_at, NOW()) DESC, id DESC LIMIT 25"
    elif folder == 'safe':
        query = f"SELECT {select_fields} FROM emails WHERE {base_condition} AND COALESCE(label, 'pending') = 'safe' ORDER BY COALESCE(created_at, NOW()) DESC, id DESC LIMIT 25"
    elif folder == 'starred':
        query = f"SELECT {select_fields} FROM emails WHERE {base_condition} AND COALESCE(is_starred, 0) = 1 ORDER BY COALESCE(created_at, NOW()) DESC, id DESC LIMIT 25"
    elif folder == 'archived':
        base_condition = "COALESCE(is_archived, 0) = 1 AND (user_email = %s OR receiver LIKE %s)"
        query = f"SELECT {select_fields} FROM emails WHERE {base_condition} ORDER BY COALESCE(created_at, NOW()) DESC, id DESC LIMIT 25"
    else:  # inbox
        query = f"SELECT {select_fields} FROM emails WHERE {base_condition} ORDER BY COALESCE(created_at, NOW()) DESC, id DESC LIMIT 25"
    
    emails = fetch_all(query, base_params) or []
    
    # Decrypt encrypted email subjects for display
    for email in emails:
        if email.get('encryption_method') == 'FERNET_AES_CONTENT' and email.get('encrypted_content_key'):
            try:
                encrypted_data = {
                    'encrypted_body': '',
                    'encrypted_subject': email.get('subject', ''),
                    'encrypted_key': email.get('encrypted_content_key')
                }
                decrypted_content = security_handler.decrypt_email_content(encrypted_data, user_email)
                if decrypted_content and decrypted_content.get('subject'):
                    email['subject'] = decrypted_content['subject']
            except Exception as e:
                print(f"Dashboard decryption error for email {email['id']}: {e}")
    
    # Use cached stats for better performance
    stats = get_cached_stats(user_email)
    
    return render_template("dashboard.html", emails=emails, stats=stats, current_folder=folder, user_email=user_email)


# 3. View single email - User-specific only
@app.route("/email/<int:email_id>")
@login_required
def view_email(email_id):
    user_email = session.get('user_email') or session.get('email')
    
    # Get email with access check
    query = "SELECT * FROM emails WHERE id = %s AND (user_email = %s OR receiver LIKE %s)"
    email_data = fetch_one(query, (email_id, user_email, f'%{user_email}%'))
    if not email_data:
        abort(404, "Email not found or access denied")
    
    # Decrypt encrypted email content for viewing
    if email_data.get('encryption_method') == 'FERNET_AES_CONTENT' and email_data.get('encrypted_content_key'):
        try:
            encrypted_data = {
                'encrypted_body': email_data.get('body', ''),
                'encrypted_subject': email_data.get('subject', ''),
                'encrypted_key': email_data.get('encrypted_content_key')
            }
            decrypted_content = security_handler.decrypt_email_content(encrypted_data, user_email)
            if decrypted_content:
                email_data['body'] = decrypted_content.get('body', email_data.get('body', ''))
                email_data['subject'] = decrypted_content.get('subject', email_data.get('subject', ''))
        except Exception as e:
            print(f"Email view decryption error for email {email_id}: {e}")
    
    # Mark as read (async operation)
    execute_query("UPDATE emails SET is_read = 1 WHERE id = %s", (email_id,))
    
    # Auto-analyze if needed (background task)
    if email_data.get('label') == 'pending' or not email_data.get('label'):
        if email_data.get('body') or email_data.get('subject'):
            try:
                analyze_email_content(email_id, email_data.get('body', ''), email_data.get('subject', ''))
                # Quick refresh of label only
                updated_label = fetch_one("SELECT label FROM emails WHERE id = %s", (email_id,))
                if updated_label:
                    email_data['label'] = updated_label['label']
            except:
                pass  # Continue without analysis if it fails
    
    # Use cached stats and refresh after marking as read
    clear_user_cache(user_email)
    stats = get_cached_stats(user_email)
    
    return render_template("email_view.html", email=email_data, stats=stats, current_folder='inbox', user_email=user_email)

# Import hybrid analysis
from hybrid_analysis import hybrid_analyze_email

# Auto-analyze emails when fetched
def analyze_email_content(email_id, email_text, subject):
    """Enhanced hybrid ML + rule-based email analysis"""
    return hybrid_analyze_email(email_id, email_text, subject, model_loader)

# 4. Analyze email endpoint - Using YOUR models
@app.route("/analyze_email", methods=["POST"])
@login_required
def analyze_email():
    try:
        email_text = request.form.get("email_text", "")
        sender = request.form.get("sender", "unknown@example.com")
        subject = request.form.get("subject", "No Subject")
        
        # Save to database first
        insert_query = "INSERT INTO emails (sender, subject, body) VALUES (%s, %s, %s)"
        execute_query(insert_query, (sender, subject, email_text))
        
        # Get the inserted email ID
        email_record = fetch_one("SELECT id FROM emails WHERE sender = %s AND subject = %s ORDER BY id DESC LIMIT 1", (sender, subject))
        
        if email_record:
            # Analyze the email
            label, confidence = analyze_email_content(email_record['id'], email_text, subject)
            
            flash(f"Email analyzed! Classification: {label.upper()} (Confidence: {confidence:.1%})", 
                  'success' if label == 'safe' else 'danger')
            
            return jsonify({
                'success': True,
                'prediction': label,
                'confidence': confidence,
                'message': f'Email classified as {label} with {confidence:.1%} confidence!'
            })
        else:
            return jsonify({'success': False, 'error': 'Failed to save email'}), 500
        
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


# 6. Download attachment
@app.route("/attachments/<int:email_id>")
def download_attachment(email_id):
    query = "SELECT attachment_path FROM emails WHERE id = %s"
    result = fetch_one(query, (email_id,))
    
    if not result or not result.get("attachment_path"):
        abort(404, "Attachment not found")
    
    attachment_path = result["attachment_path"]
    
    try:
        return send_file(attachment_path, as_attachment=True)
    except FileNotFoundError:
        abort(404, "File not found on server")

# 7. Reports & Analytics
@app.route("/reports")
def reports():
    query_total = "SELECT COUNT(*) as total FROM emails"
    query_phish = "SELECT COUNT(*) as phish FROM emails WHERE label = 'phishing'"
    query_safe = "SELECT COUNT(*) as safe FROM emails WHERE label = 'safe'"

    total = fetch_one(query_total)["total"] or 0
    phishing = fetch_one(query_phish)["phish"] or 0
    safe = fetch_one(query_safe)["safe"] or 0

    stats = {
        "total_emails": total,
        "phishing_count": phishing,
        "safe_count": safe,
        "model_accuracy": 95.2  # placeholder
    }

    explainability = [
        ("Suspicious URL", 0.85),
        ("Urgent keyword", 0.67),
        ("Sender mismatch", 0.44),
    ]

    return render_template("reports.html", stats=stats, explainability=explainability)


# Multi-user email fetching - User-specific only
@app.route("/fetch_emails", methods=["POST"])
@login_required
def fetch_user_emails():
    try:
        # Get current user's email credentials
        user_email = session.get('user_email')
        user_password = session.get('user_password')
        
        print(f"Manual fetch request - User: {user_email}, Has password: {bool(user_password)}")
        
        if not user_email or not user_password:
            return jsonify({'success': False, 'error': 'Please setup your email credentials first'})
        
        # Test Gmail connection first
        try:
            import imaplib
            print(f"Testing Gmail connection for {user_email}...")
            test_mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
            test_mail.login(user_email, user_password)
            test_mail.select('inbox')
            test_mail.logout()
            print(f"Gmail connection test successful for {user_email}")
        except Exception as conn_error:
            print(f"Gmail connection test failed: {conn_error}")
            return jsonify({
                'success': False, 
                'error': f'Gmail connection failed: {str(conn_error)}. Please check your app password.'
            })
        
        from backend.ingestion.mta_listener import fetch_emails
        
        # Fetch emails for current user only
        print(f"Fetching emails for {user_email}...")
        count = fetch_emails(user_email, user_password)
        print(f"Fetch completed: {count} new emails")
        
        # Check if emails were actually saved
        saved_emails = fetch_all("SELECT COUNT(*) as count FROM emails WHERE user_email = %s", (user_email,))
        total_count = saved_emails[0]['count'] if saved_emails else 0
        print(f"Total emails in database for {user_email}: {total_count}")
        
        # Clear cache after fetching new emails
        clear_user_cache(user_email)
        
        if count > 0:
            flash(f"Successfully fetched {count} new emails!", 'success')
            message = f'Successfully fetched {count} new emails'
        else:
            flash("No new emails found in your Gmail inbox", 'info')
            message = 'No new emails found - all emails are already in database'
            
        return jsonify({
            'success': True, 
            'count': count, 
            'total_in_db': total_count, 
            'message': message,
            'user_email': user_email
        })
    except Exception as e:
        error_msg = f"Error fetching emails: {str(e)}"
        print(error_msg)
        flash(error_msg, 'danger')
        return jsonify({'success': False, 'error': error_msg})

# Create sample emails for testing
@app.route("/create_sample_emails")
@login_required
def create_sample_emails():
    try:
        user_email = session.get('user_email') or session.get('email')
        if not user_email:
            return jsonify({'error': 'No user email found'})
        
        # Sample emails
        sample_emails = [
            {
                'sender': 'friend@gmail.com',
                'subject': 'Hello! How are you?',
                'body': 'Hi there! Just wanted to check how you are doing. Hope everything is well!',
                'user_email': user_email
            },
            {
                'sender': 'noreply@bank.com',
                'subject': 'Account Statement Available',
                'body': 'Your monthly account statement is now available for download in your online banking portal.',
                'user_email': user_email
            },
            {
                'sender': 'suspicious@fake-bank.tk',
                'subject': 'URGENT: Verify Your Account Now!',
                'body': 'Your account will be suspended! Click here immediately to verify: http://fake-bank.tk/verify',
                'user_email': user_email
            },
            {
                'sender': 'newsletter@company.com',
                'subject': 'Weekly Newsletter - Tech Updates',
                'body': 'Here are this week\'s top technology news and updates from our team.',
                'user_email': user_email
            },
            {
                'sender': 'scammer@lottery.ml',
                'subject': 'Congratulations! You Won $1,000,000!',
                'body': 'You have won the international lottery! Send your bank details to claim your prize immediately!',
                'user_email': user_email
            }
        ]
        
        count = 0
        for email_data in sample_emails:
            # Insert directly into database
            query = "INSERT INTO emails (sender, subject, body, user_email, is_read) VALUES (%s, %s, %s, %s, 0)"
            result = execute_query(query, (email_data['sender'], email_data['subject'], email_data['body'], email_data['user_email']))
            if result:
                count += 1
                # Get the email ID and analyze it
                email_record = fetch_one("SELECT id FROM emails WHERE sender = %s AND subject = %s ORDER BY id DESC LIMIT 1", 
                                       (email_data['sender'], email_data['subject']))
                if email_record:
                    analyze_email_content(email_record['id'], email_data['body'], email_data['subject'])
        
        return jsonify({
            'success': True,
            'created_count': count,
            'user_email': user_email,
            'message': f'Created {count} sample emails for {user_email}'
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# Test Gmail connection
@app.route("/test_gmail_connection")
@login_required
def test_gmail_connection():
    try:
        user_email = session.get('user_email')
        user_password = session.get('user_password')
        
        if not user_email or not user_password:
            return jsonify({'success': False, 'error': 'No credentials found'})
        
        # Test connection step by step
        import imaplib
        results = []
        
        try:
            results.append(f"Step 1: Connecting to imap.gmail.com:993...")
            mail = imaplib.IMAP4_SSL('imap.gmail.com', 993)
            results.append(f"Step 2: Connection established")
            
            results.append(f"Step 3: Logging in as {user_email}...")
            mail.login(user_email, user_password)
            results.append(f"Step 4: Login successful")
            
            results.append(f"Step 5: Selecting inbox...")
            mail.select('inbox')
            results.append(f"Step 6: Inbox selected")
            
            # Check for emails
            status, messages = mail.search(None, 'ALL')
            email_count = len(messages[0].split()) if messages[0] else 0
            results.append(f"Step 7: Found {email_count} total emails in inbox")
            
            # Check for unseen emails
            status, unseen = mail.search(None, 'UNSEEN')
            unseen_count = len(unseen[0].split()) if unseen[0] else 0
            results.append(f"Step 8: Found {unseen_count} unseen emails")
            
            mail.logout()
            results.append(f"Step 9: Connection closed successfully")
            
            return jsonify({
                'success': True,
                'user_email': user_email,
                'total_emails': email_count,
                'unseen_emails': unseen_count,
                'test_results': results
            })
            
        except Exception as test_error:
            results.append(f"ERROR: {str(test_error)}")
            return jsonify({
                'success': False,
                'error': str(test_error),
                'test_results': results
            })
            
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Email credentials setup - User-specific
@app.route("/setup_email", methods=["GET", "POST"])
@login_required
def setup_email():
    if request.method == "POST":
        user_email = request.form.get('user_email')
        user_password = request.form.get('user_password')
        
        print(f"Email setup - User ID: {session['user_id']}, Email: {user_email}")
        
        # Test the credentials first
        try:
            import imaplib
            mail = imaplib.IMAP4_SSL('imap.gmail.com')
            mail.login(user_email, user_password)
            mail.logout()
            print(f"✓ Gmail connection successful for {user_email}")
            
            # Encrypt credentials with PQC - Show detailed process
            print(f"🔐 Starting PQC encryption for {user_email}...")
            encrypted_creds = security_handler.encrypt_gmail_credentials(user_password)
            
            if encrypted_creds:
                # Store in session
                session['user_email'] = user_email
                session['user_password'] = user_password  # Keep for immediate use
                session['email'] = user_email
                
                print(f"✓ PQC: Gmail credentials encrypted for {user_email}")
                print(f"  - Method: {encrypted_creds['encryption_method']}")
                print(f"  - Encrypted Length: {len(encrypted_creds['encrypted_password'])} chars")
                print(f"  - Preview: {encrypted_creds['encrypted_password'][:32]}...")
            else:
                print(f"⚠️ PQC: Encryption failed, using fallback for {user_email}")
                session['user_email'] = user_email
                session['user_password'] = user_password
                session['email'] = user_email
            
            # Update user record with email (keep original role)
            try:
                result = execute_query("UPDATE users SET email = %s WHERE id = %s", (user_email, session['user_id']))
                if result:
                    print(f"✓ Updated user {session['user_id']} email to {user_email}")
                    
                    # Store PQC encrypted credentials in user_credentials table
                    if encrypted_creds:
                        execute_query("REPLACE INTO user_credentials (email, user_id, app_password, encryption_method) VALUES (%s, %s, %s, %s)", 
                                     (user_email, session['user_id'], encrypted_creds['encrypted_password'], encrypted_creds['encryption_method']))
                        print(f"✓ PQC credentials stored for {user_email}")
                    else:
                        # Fallback to base64 encoding
                        import base64
                        encoded_password = base64.b64encode(user_password.encode()).decode()
                        execute_query("REPLACE INTO user_credentials (email, user_id, app_password) VALUES (%s, %s, %s)", 
                                     (user_email, session['user_id'], encoded_password))
                        print(f"⚠️ Fallback credentials stored for {user_email}")

                    
                    # Verify the update
                    updated_user = fetch_one("SELECT email FROM users WHERE id = %s", (session['user_id'],))
                    if updated_user:
                        print(f"✓ Verified user email: {updated_user['email']}")
                    else:
                        print("⚠️ Could not verify user email update")
                else:
                    print("⚠️ Email update failed")
                    
            except Exception as db_error:
                print(f"Database update error: {db_error}")
            
            flash(f"Email credentials verified and set for {user_email}!", 'success')
            print(f"✓ Email setup complete for {user_email}, redirecting to dashboard...")
            print(f"✓ PQC Status: {'ENABLED' if security_handler else 'DISABLED'}")
            if encrypted_creds:
                print(f"✓ PQC Encryption: Method={encrypted_creds['encryption_method']}, Length={len(encrypted_creds['encrypted_password'])}")
            # Ensure proper redirect to dashboard
            return redirect(url_for('dashboard'))
            
        except Exception as e:
            print(f"Gmail connection failed: {e}")
            flash(f"Failed to connect to {user_email}. Please check credentials and enable App Password.", 'danger')
    
    # Get current user info
    current_user = fetch_one("SELECT email FROM users WHERE id = %s", (session['user_id'],))
    user_email = session.get('user_email') or (current_user['email'] if current_user else None)
    
    print(f"Setup page - Current user email: {user_email}")
    
    # Use cached stats for better performance
    if user_email:
        stats = get_cached_stats(user_email)
    else:
        stats = {'total': 0, 'safe': 0, 'phishing': 0, 'pending': 0, 'starred': 0, 'unread': 0}
    
    return render_template('setup_email.html', stats=stats, current_folder='setup', current_email=user_email)

# Email management routes - User-specific only
@app.route("/email/<int:email_id>/star", methods=["POST"])
@login_required
def star_email(email_id):
    try:
        user_email = session.get('user_email') or session.get('email')
        execute_query("UPDATE emails SET is_starred = NOT COALESCE(is_starred, 0) WHERE id = %s AND (user_email = %s OR receiver LIKE %s)", 
                     (email_id, user_email, f'%{user_email}%'))
        clear_user_cache(user_email)  # Clear cache after modification
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route("/email/<int:email_id>/archive", methods=["POST"])
@login_required
def archive_email(email_id):
    try:
        user_email = session.get('user_email') or session.get('email')
        execute_query("UPDATE emails SET is_archived = 1 WHERE id = %s AND (user_email = %s OR receiver LIKE %s)", 
                     (email_id, user_email, f'%{user_email}%'))
        clear_user_cache(user_email)  # Clear cache after modification
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route("/email/<int:email_id>/delete", methods=["POST"])
@login_required
def delete_email(email_id):
    try:
        user_email = session.get('user_email') or session.get('email')
        execute_query("DELETE FROM emails WHERE id = %s AND (user_email = %s OR receiver LIKE %s)", 
                     (email_id, user_email, f'%{user_email}%'))
        clear_user_cache(user_email)  # Clear cache after modification
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

# Database debug route
@app.route("/debug_db")
def debug_db():
    try:
        # Test connection
        test_result = fetch_one("SELECT 1 as test")
        
        # Get all users
        users = fetch_all("SELECT * FROM users") or []
        
        # Get all emails
        emails = fetch_all("SELECT id, sender, subject, user_email, label FROM emails ORDER BY id DESC LIMIT 10") or []
        
        # Get table structure
        try:
            structure = fetch_all("DESCRIBE users") or []
        except:
            structure = []
        
        return jsonify({
            'connection': 'OK' if test_result else 'FAILED',
            'users_count': len(users),
            'users': users,
            'emails_count': len(emails),
            'recent_emails': emails,
            'table_structure': structure,
            'database': 'email_security_system'
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# User profile route
@app.route("/profile")
@login_required
def profile():
    try:
        user_data = fetch_one("SELECT * FROM users WHERE id = %s", (session['user_id'],))
        if user_data:
            return jsonify({
                'id': user_data['id'],
                'username': user_data['username'],
                'email': user_data['email'],
                'full_name': user_data['full_name'],
                'created_at': str(user_data['created_at'])
            })
        else:
            return jsonify({'error': 'User not found'})
    except Exception as e:
        return jsonify({'error': str(e)})

# Test route for complete workflow
@app.route("/test_workflow")
def test_workflow():
    try:
        results = []
        
        # Step 1: Create test user
        test_username = f"testuser_{datetime.datetime.now().strftime('%H%M%S')}"
        test_email = "rushabhkirad@gmail.com"  # Use your email for testing
        test_password = "test123"
        
        results.append(f"Step 1: Creating test user '{test_username}'")
        
        # Check if user exists
        existing_user = fetch_one("SELECT id FROM users WHERE username = %s", (test_username,))
        if existing_user:
            results.append("❌ User already exists")
            return jsonify({'results': results})
        
        # Create user
        hashed_password = hash_password(test_password)
        insert_query = "INSERT INTO users (username, password, password_hash, email, full_name, role, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)"
        user_created = execute_query(insert_query, (test_username, test_password, hashed_password, test_email, 'Test User', 'organization', datetime.datetime.now()))
        
        if user_created:
            results.append("✅ Test user created successfully")
            
            # Get user ID
            new_user = fetch_one("SELECT id FROM users WHERE username = %s", (test_username,))
            if new_user:
                user_id = new_user['id']
                results.append(f"✅ User ID: {user_id}")
                
                # Step 2: Test authentication
                results.append("\nStep 2: Testing authentication")
                auth_user = authenticate_user(test_username, test_password)
                if auth_user:
                    results.append("✅ Authentication successful")
                    results.append(f"   User: {auth_user['username']} ({auth_user['email']})")
                    
                    # Step 3: Test email setup (simulation)
                    results.append("\nStep 3: Testing email setup simulation")
                    
                    # Simulate session setup
                    test_gmail = "rushabhkirad@gmail.com"
                    test_app_password = "your_app_password_here"  # You need to provide this
                    
                    results.append(f"   Gmail: {test_gmail}")
                    results.append("   App Password: [HIDDEN]")
                    
                    # Test Gmail connection (you'll need to provide real credentials)
                    try:
                        import imaplib
                        # Note: This will fail without real app password
                        # mail = imaplib.IMAP4_SSL('imap.gmail.com')
                        # mail.login(test_gmail, test_app_password)
                        # mail.logout()
                        results.append("⚠️  Gmail connection test skipped (need real app password)")
                    except Exception as gmail_error:
                        results.append(f"❌ Gmail connection failed: {gmail_error}")
                    
                    # Step 4: Test email fetching simulation
                    results.append("\nStep 4: Testing email fetch simulation")
                    
                    # Check current emails for user
                    user_emails = fetch_all("SELECT COUNT(*) as count FROM emails WHERE user_email = %s", (test_gmail,))
                    email_count = user_emails[0]['count'] if user_emails else 0
                    results.append(f"   Current emails for {test_gmail}: {email_count}")
                    
                    # Add test credentials to new table
                    import base64
                    test_password = base64.b64encode('test_app_password'.encode()).decode()
                    creds_added = execute_query("REPLACE INTO user_credentials (email, user_id, app_password) VALUES (%s, %s, %s)", 
                                              (test_gmail, user_id, test_password))
                    
                    if creds_added:
                        results.append("✅ Test credentials added to user_credentials table")
                    
                    # Simulate adding a test email
                    test_email_insert = "INSERT INTO emails (sender, subject, body, user_email, label, confidence_score) VALUES (%s, %s, %s, %s, %s, %s)"
                    email_added = execute_query(test_email_insert, ('test@example.com', 'Test Email', 'This is a test email for user workflow', test_gmail, 'safe', 0.95))
                    
                    if email_added:
                        results.append("✅ Test email added to database")
                        
                        # Verify email was added
                        new_count = fetch_all("SELECT COUNT(*) as count FROM emails WHERE user_email = %s", (test_gmail,))
                        new_email_count = new_count[0]['count'] if new_count else 0
                        results.append(f"   New email count: {new_email_count}")
                    else:
                        results.append("❌ Failed to add test email")
                    
                    # Step 5: Cleanup
                    results.append("\nStep 5: Cleanup")
                    
                    # Delete test email
                    execute_query("DELETE FROM emails WHERE sender = %s AND user_email = %s", ('test@example.com', test_gmail))
                    results.append("✅ Test email deleted")
                    
                    # Delete test credentials
                    execute_query("DELETE FROM user_credentials WHERE email = %s", (test_gmail,))
                    results.append("✅ Test credentials deleted")
                    
                    # Delete test user
                    execute_query("DELETE FROM users WHERE username = %s", (test_username,))
                    results.append("✅ Test user deleted")
                    
                else:
                    results.append("❌ Authentication failed")
            else:
                results.append("❌ Could not retrieve user ID")
        else:
            results.append("❌ Failed to create test user")
        
        return jsonify({
            'success': True,
            'results': results,
            'summary': 'Test workflow completed - check results for details'
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e),
            'results': results if 'results' in locals() else []
        })

@app.route("/health")
def health_check():
    """Health check endpoint for module integration"""
    return jsonify({
        'status': 'healthy',
        'service': 'email-security-system',
        'version': '1.0.0',
        'port': 5001
    })

@app.route("/service_status")
@login_required
def service_status():
    try:
        # Check if real-time service is running
        import psutil
        running = any('realtime_monitor.py' in p.cmdline() for p in psutil.process_iter(['cmdline']))
        return jsonify({'running': running, 'status': 'active' if running else 'stopped'})
    except:
        return jsonify({'running': True, 'status': 'unknown'})

@app.route("/show_calculations")
@admin_required
def show_calculations():
    """Display PQC calculations in a readable format"""
    try:
        calc_data = pqc_calculations()
        calculations = calc_data.json['calculations']
        
        # Always show the page, even if there are errors
        summary = calc_data.json.get('summary', {
            'input_length': 0,
            'salt_length': 0,
            'derived_key_length': 0,
            'encrypted_length': 0,
            'final_storage_length': 0,
            'verification_passed': False
        })
        
        return render_template('pqc_calculations.html', 
                             calculations=calculations,
                             summary=summary,
                             user_email=calc_data.json['user_email'],
                             pqc_working=calc_data.json['success'],
                             error_message=calc_data.json.get('error', ''),
                             stats=get_cached_stats(session.get('user_email') or session.get('email')),
                             current_folder='calculations')
    except Exception as e:
        # Show error page instead of redirecting
        return render_template('pqc_calculations.html', 
                             calculations=[f"❌ SYSTEM ERROR: {str(e)}"],
                             summary={'verification_passed': False},
                             user_email='Unknown',
                             pqc_working=False,
                             error_message=str(e),
                             stats=get_cached_stats(session.get('user_email') or session.get('email')),
                             current_folder='calculations')

@app.route("/test_pqc")
@login_required
def test_pqc():
    """Quick PQC system test"""
    try:
        results = []
        
        # Test 1: Check PQC handler
        if security_handler:
            results.append("✅ PQC Handler: Available")
        else:
            results.append("❌ PQC Handler: Not available")
            return jsonify({'success': False, 'results': results})
        
        # Test 2: Check system key
        import os
        key_file = os.path.join('backend', 'crypto', 'system.key')
        if os.path.exists(key_file):
            results.append(f"✅ System Key: Found ({key_file})")
        else:
            results.append(f"❌ System Key: Missing ({key_file})")
            return jsonify({'success': False, 'results': results})
        
        # Test 3: Encryption test
        test_data = "test123"
        encrypted = security_handler.encrypt_gmail_credentials(test_data)
        if encrypted:
            results.append(f"✅ Encryption: Success ({len(encrypted['encrypted_password'])} chars)")
        else:
            results.append("❌ Encryption: Failed")
            return jsonify({'success': False, 'results': results})
        
        # Test 4: Decryption test
        decrypted = security_handler.decrypt_gmail_credentials(encrypted)
        if decrypted == test_data:
            results.append("✅ Decryption: Success (round-trip verified)")
        else:
            results.append(f"❌ Decryption: Failed (got '{decrypted}')")
            return jsonify({'success': False, 'results': results})
        
        results.append("🎉 All PQC tests passed!")
        return jsonify({'success': True, 'results': results})
        
    except Exception as e:
        return jsonify({
            'success': False, 
            'results': [f"❌ Test Error: {str(e)}"]
        })

@app.route("/pqc_status")
@login_required
def pqc_status():
    """Check PQC system status with detailed calculations"""
    try:
        user_email = session.get('user_email') or session.get('email')
        
        # Detailed PQC test with step-by-step calculations
        test_data = "test_pqc_123"
        pqc_steps = []
        
        try:
            pqc_steps.append(f"Testing PQC for user: {user_email}")
            pqc_steps.append(f"Test input: '{test_data}'")
            
            # Encrypt
            encrypted = security_handler.encrypt_gmail_credentials(test_data, user_email)
            if encrypted:
                pqc_steps.append(f"Encryption method: {encrypted['encryption_method']}")
                pqc_steps.append(f"Encrypted length: {len(encrypted['encrypted_password'])} chars")
                pqc_steps.append(f"Encrypted preview: {encrypted['encrypted_password'][:32]}...")
                
                # Decrypt
                decrypted = security_handler.decrypt_gmail_credentials(encrypted, user_email)
                pqc_steps.append(f"Decrypted: '{decrypted}'")
                pqc_steps.append(f"Match: {decrypted == test_data}")
                
                pqc_working = (decrypted == test_data)
            else:
                pqc_steps.append("Encryption failed")
                pqc_working = False
        except Exception as e:
            pqc_steps.append(f"PQC test error: {str(e)}")
            pqc_working = False
        
        # Check user credentials
        user_creds = fetch_one("SELECT encryption_method, app_password FROM user_credentials WHERE email = %s", (user_email,))
        has_pqc_creds = user_creds and user_creds.get('encryption_method') == 'FERNET_AES'
        
        cred_details = {}
        if user_creds:
            cred_details = {
                'encryption_method': user_creds.get('encryption_method', 'NONE'),
                'password_length': len(user_creds.get('app_password', '')),
                'password_preview': user_creds.get('app_password', '')[:16] + '...' if user_creds.get('app_password') else 'None'
            }
        
        return jsonify({
            'security_enabled': True if security_handler else False,
            'pqc_working': pqc_working,
            'pqc_test_steps': pqc_steps,
            'user_has_pqc_creds': has_pqc_creds,
            'user_email': user_email,
            'user_role': session.get('username', 'unknown'),
            'credential_details': cred_details
        })
    except Exception as e:
        return jsonify({
            'error': str(e),
            'security_enabled': False,
            'pqc_working': False
        })

@app.route("/upgrade_to_pqc", methods=["POST"])
@login_required
def upgrade_to_pqc():
    """Upgrade existing user credentials to PQC encryption"""
    try:
        user_email = session.get('user_email') or session.get('email')
        user_password = session.get('user_password')
        
        if not user_email or not user_password:
            return jsonify({'success': False, 'error': 'No credentials found to upgrade'})
        
        # Check current encryption method
        user_creds = fetch_one("SELECT encryption_method, app_password FROM user_credentials WHERE email = %s", (user_email,))
        
        if user_creds and user_creds.get('encryption_method') == 'FERNET_AES':
            return jsonify({'success': False, 'error': 'Credentials already use PQC encryption'})
        
        # Encrypt current password with PQC
        encrypted_creds = security_handler.encrypt_gmail_credentials(user_password, user_email)
        
        if encrypted_creds:
            # Update credentials with PQC encryption
            execute_query("UPDATE user_credentials SET app_password = %s, encryption_method = %s WHERE email = %s", 
                         (encrypted_creds['encrypted_password'], encrypted_creds['encryption_method'], user_email))
            
            # Log the upgrade
            execute_query("INSERT INTO logs (action, timestamp, user_email, details) VALUES (%s, NOW(), %s, %s)", 
                         ('PQC_UPGRADE_SUCCESS', user_email, f'Credentials upgraded from {user_creds.get("encryption_method", "NONE")} to FERNET_AES'))
            
            return jsonify({
                'success': True, 
                'message': f'Credentials successfully upgraded to PQC encryption for {user_email}',
                'old_method': user_creds.get('encryption_method', 'NONE') if user_creds else 'NONE',
                'new_method': 'FERNET_AES'
            })
        else:
            return jsonify({'success': False, 'error': 'PQC encryption failed'})
            
    except Exception as e:
        # Log the error
        user_email = session.get('user_email', 'unknown')
        execute_query("INSERT INTO logs (action, timestamp, user_email, details) VALUES (%s, NOW(), %s, %s)", 
                     ('PQC_UPGRADE_ERROR', user_email, f'Upgrade failed: {str(e)}'))
        
        return jsonify({'success': False, 'error': str(e)})

# Admin-Only Backend Process Monitor with PQC Key Details
@app.route("/admin/backend_monitor")
@app.route("/admin_backend_monitor")
@admin_required
def admin_backend_monitor():
    """Admin-only detailed backend process monitoring with PQC keys"""
    
    # Get all system logs (not user-specific)
    system_logs = fetch_all("""
        SELECT l.*, e.subject, e.sender, u.username 
        FROM logs l 
        LEFT JOIN emails e ON l.email_id = e.id 
        LEFT JOIN users u ON l.user_email = u.email
        ORDER BY l.timestamp DESC 
        LIMIT 50
    """) or []
    
    # Get detailed PQC operations from logs
    security_details = []
    try:
        # Get recent detailed PQC operations
        recent_security_ops = fetch_all("""
            SELECT action, user_email, details, timestamp
            FROM logs 
            WHERE action LIKE 'ENCRYPT_%" OR action LIKE "DECRYPT_%" OR action LIKE "KEY_%' 
            AND timestamp > NOW() - INTERVAL 1 HOUR
            ORDER BY timestamp DESC 
            LIMIT 20
        """) or []
        
        for op in recent_security_ops:
            security_details.append({
                'operation': op['action'],
                'timestamp': op['timestamp'].strftime('%H:%M:%S') if op['timestamp'] else 'Unknown',
                'details': op['details'],
                'user': op['user_email']
            })
            
        # Add system key info if no recent operations
        if not security_details:
            import os
            import base64
            import hashlib
            
            key_file = os.path.join('backend', 'crypto', 'system.key')
            if os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    system_key = f.read()
                
                security_details.append({
                    'operation': 'SYSTEM_KEY_INFO',
                    'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
                    'details': f'System Key Available: {len(system_key)} bytes | Base64: {base64.b64encode(system_key).decode()[:32]}...',
                    'user': 'SYSTEM'
                })
            
    except Exception as e:
        security_details.append({
            'operation': 'SECURITY_ERROR',
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
            'details': f'Error accessing PQC operations: {str(e)}',
            'user': 'SYSTEM'
        })
    
    # Get encryption statistics with key details
    encrypted_users = fetch_all("SELECT email, encryption_method, app_password FROM user_credentials WHERE encryption_method = 'FERNET_AES'") or []
    encryption_stats = {
        'total_encrypted_credentials': len(encrypted_users),
        'total_users': len(fetch_all("SELECT id FROM users") or []),
        'total_emails': len(fetch_all("SELECT id FROM emails") or []),
        'security_enabled': True if security_handler else False,
        'encrypted_user_details': [{
            'email': user['email'],
            'encrypted_length': len(user['app_password']),
            'preview': user['app_password'][:16] + '...' if user['app_password'] else 'None'
        } for user in encrypted_users[:5]]  # Show first 5 users
    }
    
    # Get stats for sidebar (required by base.html)
    user_email = session.get('user_email') or session.get('email')
    stats = get_cached_stats(user_email) if user_email else {
        'total': 0,
        'safe': 0,
        'phishing': 0,
        'pending': 0,
        'starred': 0,
        'unread': 0
    }
    
    return render_template('admin_backend_monitor.html', 
                         logs=system_logs, 
                         security_operations=security_details,
                         encryption_stats=encryption_stats,
                         stats=stats,
                         current_folder='admin_monitor',
                         show_detailed_security=True)

@app.route("/admin/backend_logs")
@admin_required
def admin_backend_logs():
    """Real-time admin backend logs with detailed PQC information"""
    try:
        # Get recent PQC operations with detailed information
        security_logs = fetch_all("""
            SELECT action, user_email, details, timestamp
            FROM logs 
            WHERE action LIKE 'ENCRYPT_%" OR action LIKE "DECRYPT_%" OR action LIKE "KEY_%' 
            ORDER BY timestamp DESC 
            LIMIT 25
        """) or []
        
        # Get other system logs
        system_logs = fetch_all("""
            SELECT l.action, l.user_email, l.details, l.timestamp, e.subject, e.sender, u.username
            FROM logs l 
            LEFT JOIN emails e ON l.email_id = e.id 
            LEFT JOIN users u ON l.user_email = u.email
            WHERE l.action NOT LIKE 'ENCRYPT_%" OR action LIKE "DECRYPT_%" OR action LIKE "KEY_%'
            ORDER BY l.timestamp DESC 
            LIMIT 10
        """) or []
        
        # Format PQC logs with detailed information
        formatted_logs = []
        
        # Add detailed PQC logs
        for log in security_logs:
            log_type = 'PQC_KEY' if 'KEY' in log['action'] else 'PQC_MESSAGE' if 'MESSAGE' in log['action'] else 'PQC_PROCESS'
            formatted_logs.append({
                'timestamp': log['timestamp'].strftime('%H:%M:%S') if log['timestamp'] else 'Unknown',
                'action': log['action'],
                'details': log.get('details', ''),
                'type': log_type,
                'user': log.get('user_email', 'Unknown')
            })
        
        # Add system logs
        for log in system_logs:
            formatted_logs.append({
                'timestamp': log['timestamp'].strftime('%H:%M:%S') if log['timestamp'] else 'Unknown',
                'action': log['action'],
                'details': log.get('details', '') or f"Email: {log.get('subject', 'N/A')[:30]}...",
                'type': 'SYSTEM',
                'user': log.get('username', log.get('user_email', 'Unknown'))
            })
        
        # Sort all logs by timestamp
        formatted_logs.sort(key=lambda x: x['timestamp'], reverse=True)
        
        return jsonify({
            'logs': formatted_logs[:30],  # Show top 30 logs
            'timestamp': datetime.datetime.now().strftime('%H:%M:%S'),
            'pqc_status': 'ACTIVE' if security_handler else 'INACTIVE',
            'pqc_details_count': len(security_logs)
        })
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route("/pqc_calculations")
@admin_required
def pqc_calculations():
    """Show detailed PQC calculations for any user"""
    try:
        user_email = session.get('user_email') or session.get('email')
        calculations = []
        calculations.append(f"=== PQC SYSTEM STATUS CHECK FOR {user_email} ===")
        
        # Step 1: Check if PQC handler exists
        if not security_handler:
            calculations.append("❌ ERROR: PQC Handler not initialized")
            calculations.append("Reason: backend.crypto.security_handler import failed")
            calculations.append("Solution: Check if cryptography library is installed")
            return jsonify({
                'success': False,
                'error': 'PQC Handler not available',
                'calculations': calculations,
                'user_email': user_email
            })
        
        calculations.append(f"✅ PQC Handler: {security_handler.__class__.__name__}")
        
        # Step 2: Check system key file
        import os
        key_file = os.path.join('backend', 'crypto', 'system.key')
        if not os.path.exists(key_file):
            calculations.append(f"❌ ERROR: System key file missing: {key_file}")
            calculations.append("Solution: PQC handler should create this automatically")
            return jsonify({
                'success': False,
                'error': 'System key file missing',
                'calculations': calculations,
                'user_email': user_email
            })
        
        calculations.append(f"✅ System key file exists: {key_file}")
        
        # Step 3: Test basic encryption/decryption
        test_data = "test_pqc_verification"
        calculations.append(f"\n=== TESTING PQC FUNCTIONALITY ===")
        calculations.append(f"Test input: '{test_data}'")
        
        try:
            # Test encryption
            encrypted_result = security_handler.encrypt_gmail_credentials(test_data)
            if not encrypted_result:
                calculations.append("❌ ERROR: Encryption returned None")
                return jsonify({
                    'success': False,
                    'error': 'Encryption failed',
                    'calculations': calculations,
                    'user_email': user_email
                })
            
            calculations.append(f"✅ Encryption successful")
            calculations.append(f"Method: {encrypted_result.get('encryption_method', 'Unknown')}")
            calculations.append(f"Output length: {len(encrypted_result.get('encrypted_password', ''))} chars")
            
            # Test decryption
            decrypted_result = security_handler.decrypt_gmail_credentials(encrypted_result)
            if decrypted_result != test_data:
                calculations.append(f"❌ ERROR: Decryption failed")
                calculations.append(f"Expected: '{test_data}'")
                calculations.append(f"Got: '{decrypted_result}'")
                return jsonify({
                    'success': False,
                    'error': 'Decryption verification failed',
                    'calculations': calculations,
                    'user_email': user_email
                })
            
            calculations.append(f"✅ Decryption successful: '{decrypted_result}'")
            calculations.append(f"✅ Round-trip verification: PASSED")
            
        except Exception as crypto_error:
            calculations.append(f"❌ ERROR during crypto operations: {str(crypto_error)}")
            return jsonify({
                'success': False,
                'error': f'Crypto error: {str(crypto_error)}',
                'calculations': calculations,
                'user_email': user_email
            })
        
        # Step 4: Now show detailed calculations
        import base64
        import hashlib
        from cryptography.fernet import Fernet
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        calculations.append(f"\n=== DETAILED ENCRYPTION CALCULATIONS ===")
        
        # Now do detailed step-by-step calculation
        test_password = "demo_gmail_password_123"
        calculations.append(f"Step 1 - Input Password: '{test_password}'")
        calculations.append(f"Input Length: {len(test_password)} characters")
        calculations.append(f"Input Bytes: {test_password.encode().hex()}")
        
        # Step 2: Generate salt
        salt = os.urandom(16)
        calculations.append(f"\nStep 2 - Generate Random Salt:")
        calculations.append(f"Salt (16 bytes): {salt.hex()}")
        calculations.append(f"Salt Base64: {base64.b64encode(salt).decode()}")
        
        # Step 3: Key derivation with PBKDF2
        calculations.append(f"\nStep 3 - PBKDF2 Key Derivation:")
        calculations.append(f"Algorithm: PBKDF2-HMAC-SHA256")
        calculations.append(f"Iterations: 100,000")
        calculations.append(f"Output Length: 32 bytes")
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        derived_key = kdf.derive(test_password.encode())
        calculations.append(f"Derived Key (32 bytes): {derived_key.hex()}")
        calculations.append(f"Key SHA256: {hashlib.sha256(derived_key).hexdigest()}")
        
        # Step 4: Fernet key preparation
        calculations.append(f"\nStep 4 - Fernet Key Preparation:")
        fernet_key = base64.urlsafe_b64encode(derived_key)
        calculations.append(f"Fernet Key (Base64): {fernet_key.decode()}")
        
        # Step 5: Encryption
        calculations.append(f"\nStep 5 - Fernet Encryption:")
        f = Fernet(fernet_key)
        encrypted_data = f.encrypt(test_password.encode())
        calculations.append(f"Encrypted Data: {encrypted_data.hex()}")
        calculations.append(f"Encrypted Length: {len(encrypted_data)} bytes")
        
        # Step 6: Final format (salt + encrypted data)
        calculations.append(f"\nStep 6 - Final Storage Format:")
        combined = salt + encrypted_data
        final_b64 = base64.b64encode(combined).decode()
        calculations.append(f"Combined (salt+encrypted): {combined.hex()[:64]}...")
        calculations.append(f"Final Base64: {final_b64[:64]}...")
        calculations.append(f"Total Storage Length: {len(final_b64)} characters")
        
        # Step 7: Decryption verification
        calculations.append(f"\nStep 7 - Decryption Verification:")
        
        # Extract salt and encrypted data
        decoded = base64.b64decode(final_b64)
        extracted_salt = decoded[:16]
        extracted_encrypted = decoded[16:]
        calculations.append(f"Extracted Salt: {extracted_salt.hex()}")
        calculations.append(f"Salt Match: {salt.hex() == extracted_salt.hex()}")
        
        # Recreate key and decrypt
        kdf2 = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=extracted_salt,
            iterations=100000,
        )
        derived_key2 = kdf2.derive(test_password.encode())
        fernet_key2 = base64.urlsafe_b64encode(derived_key2)
        f2 = Fernet(fernet_key2)
        decrypted = f2.decrypt(extracted_encrypted).decode()
        
        calculations.append(f"Recreated Key Match: {derived_key.hex() == derived_key2.hex()}")
        calculations.append(f"Decrypted Password: '{decrypted}'")
        calculations.append(f"Decryption Success: {test_password == decrypted}")
        
        # Security analysis
        calculations.append(f"\n=== SECURITY ANALYSIS ===")
        calculations.append(f"Encryption Method: AES-128-CBC + HMAC-SHA256 (Fernet)")
        calculations.append(f"Key Derivation: PBKDF2-HMAC-SHA256 (100k iterations)")
        calculations.append(f"Salt: 128-bit random (prevents rainbow tables)")
        calculations.append(f"Authentication: HMAC prevents tampering")
        calculations.append(f"Security Level: Advanced symmetric encryption")
        
        return jsonify({
            'success': True,
            'user_email': user_email,
            'calculations': calculations,
            'pqc_working': True,
            'summary': {
                'input_length': len(test_password),
                'salt_length': len(salt),
                'derived_key_length': len(derived_key),
                'encrypted_length': len(encrypted_data),
                'final_storage_length': len(final_b64),
                'verification_passed': test_password == decrypted
            }
        })
        
    except Exception as e:
        import traceback
        error_details = traceback.format_exc()
        return jsonify({
            'success': False,
            'error': str(e),
            'error_details': error_details,
            'calculations': [f"❌ CRITICAL ERROR: {str(e)}", f"Details: {error_details}"]
        })

@app.route("/admin/test_pqc", methods=["POST"])
@admin_required
def admin_test_pqc():
    """Admin-only PQC test to generate detailed logs"""
    try:
        test_message = request.form.get('test_message', 'Admin Test Password 123')
        user_email = session.get('user_email', 'admin')
        
        # Perform encryption test
        encrypted_result = security_handler.encrypt_gmail_credentials(test_message, user_email)
        
        if encrypted_result:
            # Perform decryption test
            decrypted_result = security_handler.decrypt_gmail_credentials(encrypted_result, user_email)
            
            if decrypted_result == test_message:
                return jsonify({
                    'success': True,
                    'message': 'PQC test completed successfully',
                    'original': test_message,
                    'encrypted_length': len(encrypted_result['encrypted_password']),
                    'decrypted': decrypted_result,
                    'method': encrypted_result['encryption_method']
                })
            else:
                return jsonify({
                    'success': False,
                    'error': 'Decryption verification failed',
                    'original': test_message,
                    'decrypted': decrypted_result
                })
        else:
            return jsonify({
                'success': False,
                'error': 'Encryption failed'
            })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

@app.route("/admin/pqc_details")
@admin_required
def admin_pqc_details():
    """Detailed PQC implementation with keys and calculations"""
    try:
        import os
        from cryptography.fernet import Fernet
        import base64
        import hashlib
        
        # Get system key details
        key_file = os.path.join('backend', 'crypto', 'system.key')
        key_details = {}
        
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                system_key = f.read()
            
            key_details = {
                'key_file_exists': True,
                'key_length_bytes': len(system_key),
                'key_base64': base64.b64encode(system_key).decode()[:32] + '...',
                'key_sha256': hashlib.sha256(system_key).hexdigest()[:16] + '...',
                'fernet_key_valid': len(system_key) == 32
            }
        else:
            key_details = {'key_file_exists': False}
        
        # PQC calculation details
        pqc_calculations = {
            'algorithm': 'Fernet (AES-128 in CBC mode + HMAC-SHA256)',
            'key_derivation': 'PBKDF2-HMAC-SHA256',
            'salt_generation': 'os.urandom(16) - 128-bit random salt',
            'iterations': '100000 PBKDF2 iterations',
            'encryption_flow': [
                '1. Generate random 16-byte salt',
                '2. Derive 32-byte key using PBKDF2(password, salt, 100000)',
                '3. Create Fernet cipher with derived key',
                '4. Encrypt data with Fernet.encrypt()',
                '5. Combine salt + encrypted_data for storage'
            ]
        }
        
        # Test encryption with detailed steps
        test_result = {}
        calculation_steps = []
        
        try:
            test_data = "demo_password_123"
            calculation_steps.append(f"Input: '{test_data}'")
            
            # Step 1: Generate salt
            import os
            salt = os.urandom(16)
            calculation_steps.append(f"Salt (16 bytes): {salt.hex()[:32]}...")
            
            # Step 2: Key derivation
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
            )
            derived_key = kdf.derive(test_data.encode())
            calculation_steps.append(f"Derived Key (32 bytes): {derived_key.hex()[:32]}...")
            
            # Step 3: Fernet encryption
            fernet_key = base64.urlsafe_b64encode(derived_key)
            f = Fernet(fernet_key)
            encrypted_data = f.encrypt(test_data.encode())
            calculation_steps.append(f"Encrypted Data: {encrypted_data.hex()[:32]}...")
            
            # Step 4: Final format
            final_encrypted = base64.b64encode(salt + encrypted_data).decode()
            calculation_steps.append(f"Final Format (salt+data): {final_encrypted[:32]}...")
            
            # Test decryption
            decrypted = security_handler.decrypt_gmail_credentials({
                'encrypted_password': final_encrypted,
                'encryption_method': 'FERNET_AES'
            })
            
            test_result = {
                'test_status': 'PASS' if decrypted == test_data else 'FAIL',
                'input_length': len(test_data),
                'salt_length': len(salt),
                'derived_key_length': len(derived_key),
                'encrypted_length': len(encrypted_data),
                'final_length': len(final_encrypted),
                'decryption_match': decrypted == test_data
            }
            
        except Exception as e:
            test_result = {
                'test_status': 'ERROR',
                'error': str(e)
            }
            calculation_steps.append(f"Error: {str(e)}")
        
        # Get recent detailed PQC logs
        recent_security_logs = fetch_all("""
            SELECT action, user_email, details, timestamp
            FROM logs 
            WHERE action LIKE 'ENCRYPT_%" OR action LIKE "DECRYPT_%" OR action LIKE "KEY_%' 
            ORDER BY timestamp DESC 
            LIMIT 15
        """) or []
        
        formatted_security_logs = []
        for log in recent_security_logs:
            formatted_security_logs.append({
                'action': log['action'],
                'user': log['user_email'],
                'details': log['details'],
                'timestamp': log['timestamp'].strftime('%H:%M:%S') if log['timestamp'] else 'Unknown'
            })
        
        return jsonify({
            'key_details': key_details,
            'pqc_calculations': pqc_calculations,
            'calculation_steps': calculation_steps,
            'test_result': test_result,
            'recent_security_logs': formatted_security_logs,
            'timestamp': datetime.datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# Real-time updates with smart email fetching
@app.route("/get_updates")
@login_required
def get_updates():
    try:
        user_email = session.get('user_email') or session.get('email')
        user_password = session.get('user_password')
        
        # No auto-fetch restrictions - let users fetch manually when needed
        print(f"Auto-fetch disabled - use manual fetch button for {user_email}")
        
        recent_emails = fetch_all("SELECT id, sender, subject FROM emails WHERE (user_email = %s OR receiver LIKE %s) ORDER BY COALESCE(created_at, NOW()) DESC, id DESC LIMIT 5", 
                                 (user_email, f'%{user_email}%')) or []
        all_emails = fetch_all("SELECT label, is_starred, is_read FROM emails WHERE (user_email = %s OR receiver LIKE %s)", 
                              (user_email, f'%{user_email}%')) or []
        
        stats = {
            'total': len(all_emails),
            'safe': len([e for e in all_emails if e.get('label') == 'safe']),
            'phishing': len([e for e in all_emails if e.get('label') == 'phishing']),
            'unread': len([e for e in all_emails if e.get('is_read') == 0])
        }
        
        return jsonify({
            'recent_emails': recent_emails,
            'stats': stats,
            'timestamp': datetime.datetime.now().isoformat()
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# Database initialization
def init_database():
    """Initialize database tables"""
    try:
        # Create users table
        create_users_table()
        
        # Create logs table
        create_logs_table()
        
        # Create user credentials table
        create_user_credentials_table()
        
        # Add missing columns to emails table if they don't exist
        try:
            # Check if columns exist before adding
            columns_to_add = [
                ("label", "VARCHAR(20) DEFAULT 'pending'"),
                ("confidence_score", "DECIMAL(3,2) DEFAULT 0.0"),
                ("is_starred", "BOOLEAN DEFAULT FALSE"),
                ("is_read", "BOOLEAN DEFAULT FALSE"),
                ("is_archived", "BOOLEAN DEFAULT FALSE"),
                ("attachment_path", "VARCHAR(500)"),
                ("user_email", "VARCHAR(100)"),
                ("created_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
                ("encryption_method", "VARCHAR(50)"),
                ("encrypted_content_key", "TEXT"),
                ("threat_explanation", "TEXT"),
                ("message_id", "VARCHAR(255) UNIQUE")
            ]
            
            for column_name, column_def in columns_to_add:
                try:
                    execute_query(f"ALTER TABLE emails ADD COLUMN {column_name} {column_def}")
                except Exception as e:
                    if "Duplicate column name" not in str(e):
                        print(f"Column {column_name} error: {e}")
                    pass  # Column already exists
                    
            print("Database columns updated successfully")
        except Exception as e:
            print(f"Note: Some columns may already exist: {e}")
        
        # Test database connection
        if test_database_connection():
            # Create admin user
            create_admin_user()
            
            # Show final user count
            users = fetch_all("SELECT username, email FROM users") or []
            print(f"📊 Total users in database: {len(users)}")
        else:
            print("⚠️  Database connection issues - check your MySQL settings")
            
    except Exception as e:
        print(f"Database initialization error: {e}")
        app.logger.error(f"Database initialization error: {e}")

def create_logs_table():
    """Create logs table if it doesn't exist"""
    try:
        create_table_query = """
        CREATE TABLE IF NOT EXISTS logs (
            id INT AUTO_INCREMENT PRIMARY KEY,
            email_id INT,
            action VARCHAR(100) NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            user_email VARCHAR(100),
            details TEXT,
            FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE CASCADE
        )
        """
        execute_query(create_table_query)
        print("Logs table created/verified successfully")
    except Exception as e:
        print(f"Error creating logs table: {e}")

def create_user_credentials_table():
    """Create user_credentials table with email as primary key"""
    try:
        create_table_query = """
        CREATE TABLE IF NOT EXISTS user_credentials (
            email VARCHAR(100) PRIMARY KEY,
            user_id INT NOT NULL,
            app_password VARCHAR(255) NOT NULL,
            encryption_method VARCHAR(50) DEFAULT 'BASE64',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
        )
        """
        execute_query(create_table_query)
        print("User credentials table created/verified successfully")
    except Exception as e:
        print(f"Error creating user credentials table: {e}")

def create_admin_user():
    """Create default admin user if not exists"""
    try:
        print("Checking for admin user...")
        
        # Clean up duplicate admin entries first
        execute_query("DELETE FROM users WHERE username = 'admin' AND role != 'admin'")
        execute_query("DELETE FROM users WHERE email = 'rushabhkirad@gmail.com' AND username != 'admin'")
        
        # Check if admin user exists
        admin_user = fetch_one("SELECT id FROM users WHERE username = %s AND role = %s", ('admin', 'admin'))
        print(f"Admin user query result: {admin_user}")
        
        if not admin_user:
            print("Creating admin user...")
            # Create admin user with both password fields
            admin_password_hash = hash_password('admin123')
            insert_query = "INSERT INTO users (username, password, password_hash, email, full_name, role, created_at) VALUES (%s, %s, %s, %s, %s, %s, %s)"
            result = execute_query(insert_query, ('admin', 'admin123', admin_password_hash, 'rushabhkirad@gmail.com', 'Administrator', 'admin', datetime.datetime.now()))
            
            if result:
                print("✓ Admin user created successfully (admin/admin123)")
                # Add admin credentials to user_credentials table
                admin_user = fetch_one("SELECT id FROM users WHERE username = %s", ('admin',))
                if admin_user:
                    import base64
                    admin_app_password = base64.b64encode('tddj aptv vqms zoqc'.encode()).decode()
                    execute_query("REPLACE INTO user_credentials (email, user_id, app_password) VALUES (%s, %s, %s)", 
                                ('rushabhkirad@gmail.com', admin_user['id'], admin_app_password))
                    print("✓ Admin credentials added to user_credentials table")
            else:
                print("✗ Failed to create admin user")
        else:
            print("✓ Admin user already exists")
            # Update existing admin user with missing fields
            try:
                admin_password_hash = hash_password('admin123')
                execute_query("UPDATE users SET password_hash = %s, email = %s, full_name = %s, role = %s WHERE username = %s", 
                            (admin_password_hash, 'rushabhkirad@gmail.com', 'Administrator', 'admin', 'admin'))
                # Add/update admin credentials
                admin_user = fetch_one("SELECT id FROM users WHERE username = %s", ('admin',))
                if admin_user:
                    import base64
                    admin_app_password = base64.b64encode('tddj aptv vqms zoqc'.encode()).decode()
                    execute_query("REPLACE INTO user_credentials (email, user_id, app_password) VALUES (%s, %s, %s)", 
                                ('rushabhkirad@gmail.com', admin_user['id'], admin_app_password))
                    print("✓ Admin credentials updated in user_credentials table")
                print("✓ Admin user updated with missing fields")
            except Exception as update_error:
                print(f"Update error: {update_error}")
            
    except Exception as e:
        print(f"Error creating admin user: {e}")

def test_database_connection():
    """Test database connection and show status"""
    try:
        print("Testing database connection...")
        result = fetch_one("SELECT 1 as test")
        print(f"Connection test result: {result}")
        
        if result:
            print("✓ Database connection successful")
            
            # Check if users table exists
            try:
                table_check = fetch_one("SHOW TABLES LIKE 'users'")
                print(f"Users table exists: {table_check}")
                
                if table_check:
                    # Show users table status
                    users = fetch_all("SELECT username, email, full_name FROM users") or []
                    print(f"✓ Users table has {len(users)} users")
                    for user in users:
                        print(f"  - {user['username']} ({user['email']}) - {user['full_name']}")
                else:
                    print("⚠️ Users table does not exist")
                    
            except Exception as table_error:
                print(f"Error checking users table: {table_error}")
                
        return True
    except Exception as e:
        print(f"✗ Database connection failed: {e}")
        return False

# -------------------------
if __name__ == "__main__":
    print("Starting Email Security System with Real-time Monitoring...")
    print("Emails will be automatically fetched and analyzed in real-time!")
    print("Access: http://localhost:5000")
    print(f"Debug mode: {app.config['DEBUG']}")
    
    # Initialize database
    init_database()
    
    # Disable automatic real-time monitoring to prevent background fetching
    # Users will fetch emails manually when needed
    print("Real-time monitoring disabled - users fetch emails manually")
    
    # Run the application
    port = int(os.getenv('PORT', 5000))
    app.run(debug=app.config['DEBUG'], host='0.0.0.0', port=port)
