import re
import os
from backend.db.db_utils import execute_query, fetch_one
from backend.analyzers.vision_analyzer import VisionAnalyzer
from backend.analyzers.url_deep_analyzer import URLDeepAnalyzer
from backend.analyzers.attachment_analyzer import extract_features
from backend.analyzers.auth_header_analyzer import AuthHeaderAnalyzer
from backend.analyzers.advanced_phishing_detector import get_advanced_phishing_score
# from backend.analyzers.bert_analyzer import BertAnalyzer # Commented out to prevent slow load on dev

# Initialize analyzers
vision_analyzer = VisionAnalyzer()
url_deep_analyzer = URLDeepAnalyzer()
auth_analyzer = AuthHeaderAnalyzer()
# bert_analyzer = BertAnalyzer() # Initialize lazily or if enabled

class HybridAnalyzer:
    """Hybrid ML + Rule-based email analyzer class"""
    
    def __init__(self, model_loader=None):
        self.model_loader = model_loader
    
    def analyze_email(self, email_id, email_text, subject):
        """Analyze email using hybrid approach"""
        return hybrid_analyze_email(email_id, email_text, subject, self.model_loader)

def hybrid_analyze_email(email_id, email_text, subject, model_loader):
    """Hybrid ML + Rule-based email analysis for maximum accuracy"""
    try:
        # Get email details
        email_data = fetch_one("SELECT user_email, sender, attachment_path FROM emails WHERE id = %s", (email_id,))
        user_email = email_data['user_email'] if email_data else 'unknown'
        sender = email_data['sender'].lower() if email_data and email_data['sender'] else ''
        attachment_path = email_data['attachment_path'] if email_data else None
        
        text_content = (email_text + " " + subject).lower()
        
        # STEP 0a: AUTHENTICATION CHECKS (SPF/DKIM)
        # We need headers for this. If not available, we skip.
        # Assuming email_data might have headers in future.
        auth_score_penalty = 0
        if email_data and 'headers' in email_data and email_data['headers']:
             auth_results = auth_analyzer.analyze_headers(email_data['headers'], sender.split('@')[-1])
             auth_score_penalty = auth_results['score_penalty']
             if auth_results['auth_warnings']:
                 print(f"Auth Warnings: {auth_results['auth_warnings']}")

        # STEP 0b: VISION ANALYSIS (OCR)
        # If there are images in the email (not implemented in ingestion yet) or if attachment is an image
        vision_text = ""
        if attachment_path and os.path.exists(attachment_path):
            ext = os.path.splitext(attachment_path)[1].lower()
            if ext in ['.jpg', '.jpeg', '.png', '.bmp', '.tiff']:
                print(f"Performing OCR on {os.path.basename(attachment_path)}...")
                vision_result = vision_analyzer.analyze_image(attachment_path)
                if vision_result['has_text']:
                    vision_text = vision_result['extracted_text']
                    print(f"OCR extracted {len(vision_text)} chars")
                    # Append to text content for analysis
                    text_content += " " + vision_text.lower()

        # STEP 1: HYBRID TEXT ANALYSIS (ML + Rules)
        text_ml_score = 0
        text_rule_score = 0
        ml_available = False  # Track if ML is working
        
        # 1a. Text ML Analysis
        if model_loader and len(text_content.strip()) > 10:
            try:
                text_vector = model_loader.text_vect.transform([email_text + " " + subject])
                text_prediction = model_loader.text_model.predict_proba(text_vector)[0]
                if len(text_prediction) > 1:
                    text_ml_score = text_prediction[1]
                ml_available = True
                print(f"Text ML Score: {text_ml_score:.3f}")
            except Exception as e:
                print(f"Text ML error: {e}")
                ml_available = False
        
        # 1b. Text Rule-based Analysis
        high_risk_patterns = [
            r'(verify|confirm|update).*(account|password|payment)',
            r'(suspended|locked|blocked).*(account|access)',
            r'(click here|act now).*(urgent|immediately)',
            r'(winner|won|prize).*(lottery|million|inheritance)',
            r'(transfer|claim).*(money|funds|prize)',
            r'(urgent|immediately|expires|suspended).*24.*hours',
            r'(ssn|social security|pin|cvv|credit card)',
            r'(bank account|routing number|wire transfer)'
        ]
        
        for pattern in high_risk_patterns:
            if re.search(pattern, text_content):
                text_rule_score += 0.20
        text_rule_score = min(1.0, text_rule_score)
        print(f"Text Rule Score: {text_rule_score:.3f}")
        
        # 1c. BERT Analysis (Optional/Advanced)
        bert_score = 0
        
        # 1d. Combine Text Scores - FALLBACK to rules if ML fails
        if ml_available:
            # ML 60% + Rules 40%
            text_final_score = (text_ml_score * 0.6) + (text_rule_score * 0.4)
        else:
            # Rules only when ML fails
            text_final_score = text_rule_score
        print(f"Text Combined: {text_final_score:.3f}")
        
        # STEP 2: HYBRID URL ANALYSIS (ML + Rules)
        url_ml_score = 0
        url_rule_score = 0
        url_final_score = 0
        url_ml_available = False
        # BUG FIX #1 & #5: Initialize deep_risks and deep_url_score BEFORE the if-urls block
        # so they are always defined even when no HTTP URLs are present.
        deep_risks = []
        deep_url_score = 0

        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text_content)

        # BUG FIX #3 & #4: Score the SENDER domain TLD and also extract domains
        # from email addresses embedded in the body (e.g. claim@lottery.ml).
        suspicious_tlds = ('.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.pw', '.click', '.gq')

        # Check sender domain
        sender_domain_part = sender.split('@')[-1] if '@' in sender else sender
        if any(sender_domain_part.endswith(tld) for tld in suspicious_tlds):
            url_rule_score = min(1.0, url_rule_score + 0.50)
            deep_risks.append(f"Suspicious sender TLD: .{sender_domain_part.split('.')[-1]}")
            print(f"Sender TLD risk: {sender_domain_part}")

        # Extract bare domains from email addresses in body (e.g. reply@lottery.ml)
        body_email_domains = re.findall(
            r'[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', text_content
        )
        for domain in body_email_domains:
            if any(domain.endswith(tld) for tld in suspicious_tlds):
                url_rule_score = min(1.0, url_rule_score + 0.35)
                deep_risks.append(f"Suspicious email domain in body: {domain}")
                print(f"Body email domain risk: {domain}")
        
        if urls:
            # 2a. URL ML Analysis
            try:
                if model_loader and hasattr(model_loader, 'url_model') and hasattr(model_loader, 'url_vect'):
                    for url in urls:
                        url_vector = model_loader.url_vect.transform([url])
                        url_prediction = model_loader.url_model.predict_proba(url_vector)[0]
                        if len(url_prediction) > 1:
                            url_ml_score = max(url_ml_score, url_prediction[1])
                    url_ml_available = True
                    print(f"URL ML Score: {url_ml_score:.3f}")
            except Exception as e:
                print(f"URL ML error: {e}")
                url_ml_available = False
            
            # 2b. URL Rule-based Analysis (EXPANDED PATTERNS)
            dangerous_patterns = [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IP addresses
                r'(bit\.ly|tinyurl|short\.link|t\.co)',  # URL shorteners
                r'(login|verify|secure|account|update|confirm).*\.(tk|ml|ga|cf|xyz|top|pw)',  # Suspicious TLDs
                r'(paypal|bank|amazon|microsoft|apple|google).*(?!\.(com|org|net))',  # Fake brand domains
                r'(fake|phish|scam|hack|verify|secure)[^/]*\.',  # Suspicious subdomains
                r'\-verify|verify\-|\-secure|secure\-|\-login|login\-',  # Hyphened suspicious words
                r'\@[^\s]+\.(tk|ml|ga|cf|xyz)',  # Email-like URLs with bad TLDs
            ]
            
            for url in urls:
                url_lower = url.lower()
                for pattern in dangerous_patterns:
                    if re.search(pattern, url_lower):
                        url_rule_score += 0.35
                        break
            url_rule_score = min(1.0, url_rule_score)
            print(f"URL Rule Score: {url_rule_score:.3f}")
            
            # 2c. Deep URL Analysis (New) - wrapped in try-except
            # (deep_url_score and deep_risks already initialized above)
            try:
                for url in urls[:3]: # Analyze top 3 URLs to save time
                    deep_analysis = url_deep_analyzer.analyze_url(url)
                    if deep_analysis['score'] > 0:
                        deep_url_score = max(deep_url_score, deep_analysis['score'])
                        deep_risks.extend(deep_analysis['risk_factors'])
                
                if deep_risks:
                    print(f"Deep URL Risks: {', '.join(deep_risks)}")
                    # Boost rule score if deep analysis finds risks
                    url_rule_score = min(1.0, url_rule_score + (deep_url_score * 0.5))
            except Exception as e:
                print(f"Deep URL analysis error: {e}")

            # 2d. Combine URL Scores - FALLBACK to rules if ML fails
            if url_ml_available:
                url_final_score = (url_ml_score * 0.5) + (url_rule_score * 0.3) + (deep_url_score * 0.2)
            else:
                # Rules + Deep when ML fails
                url_final_score = (url_rule_score * 0.7) + (deep_url_score * 0.3)
            print(f"URL Combined: {url_final_score:.3f}")
        
        # STEP 3: HYBRID ATTACHMENT ANALYSIS (ML + Rules)
        attachment_ml_score = 0
        attachment_rule_score = 0
        attachment_final_score = 0
        
        if attachment_path:
            # 3a. Attachment ML Analysis (simplified)
            try:
                if model_loader and hasattr(model_loader, 'attachment_model'):
                    if os.path.exists(attachment_path):
                        file_size = os.path.getsize(attachment_path)
                        # Extract real features if PDF
                        if attachment_path.lower().endswith('.pdf'):
                            features = extract_features(attachment_path)
                            print(f"Extracted PDF features: {features}")
                        else:
                            # Fallback for non-PDFs (simplified)
                            features = [
                                file_size, 0, 1, 0, len(os.path.basename(attachment_path)),
                                0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
                            ]
                        
                        attachment_prediction = model_loader.attachment_model.predict_proba([features])[0]
                        if len(attachment_prediction) > 1:
                            attachment_ml_score = attachment_prediction[1]
                        print(f"Attachment ML Score: {attachment_ml_score:.3f}")
                    else:
                        attachment_ml_score = 0.1
                else:
                    attachment_ml_score = 0.1
            except Exception as e:
                print(f"Attachment ML error: {e}")
                attachment_ml_score = 0.1
            
            # 3b. Attachment Rule-based Analysis
            try:
                dangerous_extensions = ['.exe', '.scr', '.bat', '.com', '.pif', '.vbs', '.js', '.jar']
                suspicious_extensions = ['.zip', '.rar', '.7z', '.doc', '.docx', '.xls', '.xlsx']
                
                file_ext = os.path.splitext(attachment_path)[1].lower()
                
                if file_ext in dangerous_extensions:
                    attachment_rule_score = 0.8
                elif file_ext in suspicious_extensions:
                    attachment_rule_score = 0.4
                else:
                    attachment_rule_score = 0.1
                
                print(f"Attachment Rule Score: {attachment_rule_score:.3f}")
            except Exception as e:
                print(f"Attachment rule error: {e}")
                attachment_rule_score = 0.3
            
            # 3c. Combine Attachment Scores (ML 80% + Rules 20%)
            attachment_final_score = (attachment_ml_score * 0.8) + (attachment_rule_score * 0.2)
            print(f"Attachment Combined: {attachment_final_score:.3f}")

        # STEP 1.5: ADVANCED PHISHING DETECTION
        # Catches what Google misses: display-name spoofing, lookalike domains,
        # homoglyphs, BEC fraud, callback phishing, Reply-To mismatch, legit-service abuse
        adv_result = {'score': 0.0, 'signals': [], 'override_phishing': False}
        try:
            # Pull reply_to from email headers if stored
            reply_to = ''
            if email_data:
                reply_to = (email_data.get('reply_to') or '').lower()

            adv_result = get_advanced_phishing_score(
                sender=sender,
                subject=subject,
                body=email_text,
                reply_to=reply_to,
                urls=urls,
                domain_age_days=-1,  # Will be filled by url_deep_analyzer when available
            )
            if adv_result['score'] > 0:
                print(f"Advanced Phishing Score: {adv_result['score']:.3f}")
                for sig in adv_result['signals']:
                    print(f"  [ADV SIGNAL] {sig}")
        except Exception as adv_err:
            print(f"Advanced phishing check error: {adv_err}")

        adv_score    = adv_result['score']
        adv_signals  = adv_result['signals']
        adv_override = adv_result['override_phishing']
        
        # STEP 4: ENSEMBLE SCORING WITH ADAPTIVE WEIGHTS
        # Weights: Text 50%, URL 25%, Advanced 20%, Attachment 5%
        # (Advanced layer added to catch Google-bypassing phishing)
        text_weight       = 0.50
        url_weight        = 0.25 if urls else 0
        adv_weight        = 0.20
        attachment_weight = 0.05 if attachment_path else 0

        # Redistribute when components are missing
        if not urls and not attachment_path:
            text_weight = 0.80
            adv_weight  = 0.20
        elif not urls:
            text_weight       = 0.70
            adv_weight        = 0.20
            attachment_weight = 0.10
        elif not attachment_path:
            text_weight = 0.55
            url_weight  = 0.25
            adv_weight  = 0.20

        # Calculate ensemble score
        ensemble_score = (
            text_final_score       * text_weight +
            url_final_score        * url_weight +
            adv_score              * adv_weight +
            attachment_final_score * attachment_weight
        )

        # Apply Auth Penalty
        ensemble_score += auth_score_penalty
        ensemble_score = min(1.0, ensemble_score)

        print(f"Ensemble Score: {ensemble_score:.3f} (T:{text_weight}, U:{url_weight}, ADV:{adv_weight}, A:{attachment_weight})")

        # ADVANCED OVERRIDE: If a single advanced signal is very high-confidence,
        # classify as phishing regardless of the ML ensemble.
        # (Catches spear phishing, BEC, homoglyph attacks that ML models may under-score)
        if adv_override and ensemble_score < 0.35:
            print(f"Advanced override: high-confidence signal forces PHISHING classification")
            ensemble_score = 0.75
        
        # STEP 5: TRUST AND SAFETY ADJUSTMENTS
        trusted_domains = ['gmail.com', 'google.com', 'microsoft.com', 'github.com', 'naukri.com', 'naukrigulf.com', 'infoedge.com']
        trusted_contacts = ['samyakbhongade2019@gmail.com', 'rushabhkirad@gmail.com']

        # BUG FIX #6: Use exact domain match (sender ends with @trusted_domain)
        # Prevents spoofed domains like paypal-gmail.tk from getting a trust boost.
        is_trusted = (
            any(sender.endswith('@' + domain) or sender == domain for domain in trusted_domains)
            or any(contact in sender for contact in trusted_contacts)
        )

        safe_patterns = ['unsubscribe', 'newsletter', 'notification', 'receipt', 'invoice']
        has_safe_indicators = any(pattern in text_content for pattern in safe_patterns)

        # Apply trust adjustments — only reduce if NOT already high-confidence phishing
        if is_trusted and len(text_content.strip()) < 100 and ensemble_score < 0.60:
            ensemble_score *= 0.3
            print(f"Trusted sender adjustment: {ensemble_score:.3f}")

        # Safe-content indicators only reduce if score is borderline (not clearly phishing)
        if has_safe_indicators and ensemble_score < 0.50:
            ensemble_score *= 0.6
            print(f"Safe content adjustment: {ensemble_score:.3f}")

        # FALSE-POSITIVE GUARD: If the score is in a borderline range (0.35–0.68)
        # AND there are no rule-based threat indicators at all, don't flag as phishing.
        # High-confidence ML scores (>=0.68) always pass regardless.
        # This prevents the text ML model from over-scoring innocent short emails.
        has_rule_threats = (text_rule_score > 0.05 or url_rule_score > 0.05 or bool(deep_risks))
        if 0.35 <= ensemble_score < 0.68 and not has_rule_threats:
            print(f"False-positive guard: no rule signals at score {ensemble_score:.3f} — treating as safe")
            ensemble_score = 0.30  # push below threshold

        # STEP 6: FINAL CLASSIFICATION WITH ADJUSTED THRESHOLDS
        # Lowered threshold to 0.35 for better phishing detection when ML is unavailable
        if ensemble_score >= 0.35:
            label = 'phishing'
            confidence = min(0.95, 0.70 + (ensemble_score * 0.25))
        else:
            label = 'safe'
            confidence = min(0.95, 0.70 + ((1 - ensemble_score) * 0.25))
        
        # STEP 7: MULTI-LAYER VALIDATION (Reduce False Negatives)
        # Override if any component has high score (lowered from 0.65 to 0.50)
        max_component_score = max(text_final_score, url_final_score, attachment_final_score)
        if max_component_score >= 0.50 and ensemble_score < 0.35:
            label = 'phishing'
            confidence = 0.80
            print(f"High component override: {max_component_score:.3f}")
        
        # STEP 8: GENERATE DETAILED THREAT EXPLANATION
        threat_explanation = ""
        if label == 'phishing':
            threats = []
            
            if text_ml_score > 0.7:
                threats.append(f"ML Model: High phishing probability ({text_ml_score:.2f})")
            
            threat_words = []
            for pattern in high_risk_patterns:
                matches = re.findall(pattern, text_content)
                if matches:
                    threat_words.extend([str(m) for m in matches[:2]])
            
            if threat_words:
                threats.append(f"Threat patterns: {', '.join(set(threat_words))}")
            
            if urls and url_final_score > 0.5:
                suspicious_urls = []
                dangerous_patterns = [
                    r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
                    r'(bit\.ly|tinyurl|short\.link|t\.co)',
                    r'(login|verify|secure|account).*\.(tk|ml|ga|cf)'
                ]
                for url in urls[:2]:
                    if any(re.search(p, url) for p in dangerous_patterns):
                        suspicious_urls.append(url)
                if suspicious_urls:
                    threats.append(f"Suspicious URLs: {', '.join(suspicious_urls)}")
            
            if deep_risks:
                threats.append(f"Deep URL Analysis: {', '.join(set(deep_risks))}")
            
            if attachment_path and attachment_final_score > 0.5:
                threats.append(f"Suspicious attachment: {os.path.basename(attachment_path)}")
            
            urgency_words = re.findall(r'(urgent|immediately|act now|expires|suspended)', text_content)
            if urgency_words:
                threats.append(f"Urgency tactics: {', '.join(set(urgency_words))}")

            # Advanced detection signals (display spoofing, BEC, lookalike, etc.)
            if adv_signals:
                threats.append(f"Advanced Detection: {'; '.join(adv_signals[:3])}")

            threat_explanation = " | ".join(threats) if threats else "Multiple risk indicators detected"
        
        # STEP 9: UPDATE DATABASE AND LOG
        execute_query("UPDATE emails SET label = %s, confidence_score = %s, threat_explanation = %s WHERE id = %s", 
                     (label, float(confidence), threat_explanation, email_id))
        
        execute_query("INSERT INTO logs (email_id, action, timestamp, user_email, details) VALUES (%s, %s, NOW(), %s, %s)", 
                     (email_id, f'hybrid_analysis_{label}', user_email, f'Ensemble:{ensemble_score:.3f}, Components:T{text_final_score:.2f}|U{url_final_score:.2f}|A{attachment_final_score:.2f}'))
        
        print(f"Email {email_id}: {label.upper()} ({confidence:.2f}) - Ensemble: {ensemble_score:.3f}")
        if threat_explanation:
            print(f"  Threats: {threat_explanation}")
        
        return label, confidence
        
    except Exception as e:
        # BUG FIX #2: Fail-safe toward PHISHING, not safe.
        # A crash in the pipeline must NEVER silently pass a phishing email.
        import traceback
        print(f"Hybrid analysis error: {e}")
        traceback.print_exc()
        execute_query("UPDATE emails SET label = %s, confidence_score = %s, threat_explanation = %s WHERE id = %s",
                     ('phishing', 0.60, f'Analysis error — flagged for safety: {str(e)[:200]}', email_id))
        return 'phishing', 0.60