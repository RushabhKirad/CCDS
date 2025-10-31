import re
import os
from backend.db.db_utils import execute_query, fetch_one

def hybrid_analyze_email(email_id, email_text, subject, model_loader):
    """Hybrid ML + Rule-based email analysis for maximum accuracy"""
    try:
        # Get email details
        email_data = fetch_one("SELECT user_email, sender, attachment_path FROM emails WHERE id = %s", (email_id,))
        user_email = email_data['user_email'] if email_data else 'unknown'
        sender = email_data['sender'].lower() if email_data and email_data['sender'] else ''
        attachment_path = email_data['attachment_path'] if email_data else None
        
        text_content = (email_text + " " + subject).lower()
        
        # STEP 1: HYBRID TEXT ANALYSIS (ML + Rules)
        text_ml_score = 0
        text_rule_score = 0
        
        # 1a. Text ML Analysis
        if model_loader and len(text_content.strip()) > 10:
            try:
                text_vector = model_loader.text_vect.transform([email_text + " " + subject])
                text_prediction = model_loader.text_model.predict_proba(text_vector)[0]
                if len(text_prediction) > 1:
                    text_ml_score = text_prediction[1]
                print(f"Text ML Score: {text_ml_score:.3f}")
            except Exception as e:
                print(f"Text ML error: {e}")
                text_ml_score = 0.1
        
        # 1b. Text Rule-based Analysis
        high_risk_patterns = [
            r'(verify|confirm|update).*(account|password|payment)',
            r'(suspended|locked|blocked).*(account|access)',
            r'(click here|act now).*(urgent|immediately)',
            r'(winner|won|prize).*(lottery|million|inheritance)',
            r'(transfer|claim).*(money|funds|prize)'
        ]
        
        for pattern in high_risk_patterns:
            if re.search(pattern, text_content):
                text_rule_score += 0.25
        text_rule_score = min(1.0, text_rule_score)
        print(f"Text Rule Score: {text_rule_score:.3f}")
        
        # 1c. Combine Text Scores (ML 70% + Rules 30%)
        text_final_score = (text_ml_score * 0.7) + (text_rule_score * 0.3)
        print(f"Text Combined: {text_final_score:.3f}")
        
        # STEP 2: HYBRID URL ANALYSIS (ML + Rules)
        url_ml_score = 0
        url_rule_score = 0
        url_final_score = 0
        
        urls = re.findall(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text_content)
        
        if urls:
            # 2a. URL ML Analysis
            try:
                if model_loader and hasattr(model_loader, 'url_model') and hasattr(model_loader, 'url_vect'):
                    for url in urls:
                        url_vector = model_loader.url_vect.transform([url])
                        url_prediction = model_loader.url_model.predict_proba(url_vector)[0]
                        if len(url_prediction) > 1:
                            url_ml_score = max(url_ml_score, url_prediction[1])
                    print(f"URL ML Score: {url_ml_score:.3f}")
                else:
                    url_ml_score = 0.1
            except Exception as e:
                print(f"URL ML error: {e}")
                url_ml_score = 0.1
            
            # 2b. URL Rule-based Analysis
            dangerous_patterns = [
                r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',  # IP addresses
                r'(bit\.ly|tinyurl|short\.link|t\.co)',  # URL shorteners
                r'(login|verify|secure|account).*\.(tk|ml|ga|cf)',  # Suspicious TLDs
            ]
            
            for url in urls:
                for pattern in dangerous_patterns:
                    if re.search(pattern, url):
                        url_rule_score += 0.4
                        break
            url_rule_score = min(1.0, url_rule_score)
            print(f"URL Rule Score: {url_rule_score:.3f}")
            
            # 2c. Combine URL Scores (ML 60% + Rules 40%)
            url_final_score = (url_ml_score * 0.6) + (url_rule_score * 0.4)
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
                        # Simplified feature vector for attachment model
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
        
        # STEP 4: ENSEMBLE SCORING WITH ADAPTIVE WEIGHTS
        text_weight = 0.5
        url_weight = 0.3 if urls else 0
        attachment_weight = 0.2 if attachment_path else 0
        
        # Redistribute weights if components are missing
        if not urls and not attachment_path:
            text_weight = 1.0
        elif not urls:
            text_weight = 0.8
            attachment_weight = 0.2
        elif not attachment_path:
            text_weight = 0.7
            url_weight = 0.3
        
        # Calculate ensemble score
        ensemble_score = (text_final_score * text_weight + 
                         url_final_score * url_weight + 
                         attachment_final_score * attachment_weight)
        
        print(f"Ensemble Score: {ensemble_score:.3f} (T:{text_weight}, U:{url_weight}, A:{attachment_weight})")
        
        # STEP 5: TRUST AND SAFETY ADJUSTMENTS
        trusted_domains = ['gmail.com', 'google.com', 'microsoft.com', 'github.com', 'naukri.com', 'naukrigulf.com', 'infoedge.com']
        trusted_contacts = ['samyakbhongade2019@gmail.com', 'rushabhkirad@gmail.com']
        
        is_trusted = any(domain in sender for domain in trusted_domains) or any(contact in sender for contact in trusted_contacts)
        
        safe_patterns = ['unsubscribe', 'newsletter', 'notification', 'receipt', 'invoice']
        has_safe_indicators = any(pattern in text_content for pattern in safe_patterns)
        
        # Apply trust adjustments
        if is_trusted and len(text_content.strip()) < 100:
            ensemble_score *= 0.3
            print(f"Trusted sender adjustment: {ensemble_score:.3f}")
        
        if has_safe_indicators:
            ensemble_score *= 0.6
            print(f"Safe content adjustment: {ensemble_score:.3f}")
        
        # STEP 6: FINAL CLASSIFICATION WITH CONSERVATIVE THRESHOLDS
        if ensemble_score >= 0.6:
            label = 'phishing'
            confidence = min(0.95, 0.75 + (ensemble_score * 0.20))
        else:
            label = 'safe'
            confidence = min(0.95, 0.75 + ((1 - ensemble_score) * 0.20))
        
        # STEP 7: MULTI-LAYER VALIDATION (Reduce False Negatives)
        max_component_score = max(text_final_score, url_final_score, attachment_final_score)
        if max_component_score >= 0.9 and ensemble_score < 0.6:
            label = 'phishing'
            confidence = 0.75
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
            
            if attachment_path and attachment_final_score > 0.5:
                threats.append(f"Suspicious attachment: {os.path.basename(attachment_path)}")
            
            urgency_words = re.findall(r'(urgent|immediately|act now|expires|suspended)', text_content)
            if urgency_words:
                threats.append(f"Urgency tactics: {', '.join(set(urgency_words))}")
            
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
        print(f"Hybrid analysis error: {e}")
        execute_query("UPDATE emails SET label = %s, confidence_score = %s WHERE id = %s", 
                     ('safe', 0.75, email_id))
        return 'safe', 0.75