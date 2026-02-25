import re
import urllib.parse

def hybrid_analyze_email(email_id, email_text, subject, model_loader=None):
    try:
        rule_score, indicators = rule_based_analysis(email_text, subject)
        ml_confidence = 0.5
        
        if model_loader:
            try:
                ml_confidence = model_loader.predict_text(f"{subject} {email_text}")
            except:
                ml_confidence = 0.5
        
        final_confidence = (rule_score * 0.4) + (ml_confidence * 0.6)
        
        if final_confidence > 0.7:
            label = 'phishing'
        elif final_confidence < 0.3:
            label = 'safe'
        else:
            label = 'pending'
        
        return label, final_confidence
    except Exception as e:
        return 'pending', 0.5

def rule_based_analysis(email_text, subject):
    phishing_score = 0
    indicators = []
    
    full_text = f"{subject} {email_text}".lower()
    
    suspicious_keywords = [
        'urgent', 'verify', 'suspend', 'click here', 'act now',
        'congratulations', 'winner', 'prize', 'lottery',
        'bank account', 'credit card', 'password'
    ]
    
    keyword_matches = sum(1 for keyword in suspicious_keywords if keyword in full_text)
    if keyword_matches > 2:
        phishing_score += 0.3
    
    urls = re.findall(r'http[s]?://[^\s]+', full_text)
    for url in urls:
        if is_suspicious_url(url):
            phishing_score += 0.4
    
    urgency_words = ['urgent', 'immediate', 'asap', 'expire']
    if sum(1 for word in urgency_words if word in full_text) > 1:
        phishing_score += 0.2
    
    return min(phishing_score, 1.0), indicators

def is_suspicious_url(url):
    try:
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            return True
        
        if re.match(r'\d+\.\d+\.\d+\.\d+', domain):
            return True
        
        return False
    except:
        return False