import re
import math
import socket
import ssl
import whois
import datetime
import requests
import logging
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class URLDeepAnalyzer:
    """
    Deep URL Analyzer for Phishing Detection.
    Features: Lexical, Entropy, Homograph, Network (SSL, WHOIS).
    """
    
    def __init__(self):
        pass

    def calculate_entropy(self, text):
        """Calculates Shannon entropy of a string."""
        if not text:
            return 0
        prob = [float(text.count(c)) / len(text) for c in dict.fromkeys(list(text))]
        entropy = - sum([p * math.log(p) / math.log(2.0) for p in prob])
        return entropy

    def is_homograph(self, domain):
        """Checks for potential homograph attacks (non-ASCII characters)."""
        try:
            domain.encode('ascii')
            return False
        except UnicodeEncodeError:
            return True

    def check_ssl(self, domain):
        """Checks SSL certificate validity."""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    # Check if expired
                    not_after = datetime.datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    if not_after < datetime.datetime.now():
                        return False, "Expired Certificate"
                    return True, "Valid Certificate"
        except Exception as e:
            return False, str(e)

    def check_whois(self, domain):
        """Checks domain age via WHOIS."""
        try:
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if creation_date:
                age_days = (datetime.datetime.now() - creation_date).days
                return age_days
            return -1
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return -1

    def analyze_url(self, url):
        """
        Performs deep analysis on a URL.
        
        Returns:
            dict: Analysis results and risk score (0.0 - 1.0).
        """
        result = {
            "url": url,
            "score": 0.0,
            "features": {},
            "risk_factors": []
        }
        
        try:
            parsed = urlparse(url)
            domain = parsed.netloc
            if not domain:
                return result
            
            # 1. Lexical Features
            result['features']['length'] = len(url)
            result['features']['digits'] = sum(c.isdigit() for c in url)
            result['features']['special_chars'] = sum(not c.isalnum() for c in url)
            result['features']['entropy'] = self.calculate_entropy(domain)
            
            # Risk scoring based on lexical features
            if result['features']['entropy'] > 4.5:
                result['score'] += 0.2
                result['risk_factors'].append("High Entropy Domain")
            
            if '@' in url:
                result['score'] += 0.3
                result['risk_factors'].append("Obfuscated URL (@ symbol)")
                
            # 2. Homograph Attack
            if self.is_homograph(domain):
                result['score'] += 0.4
                result['risk_factors'].append("Potential Homograph Attack")
                
            # 3. Network Features (Timeboxed)
            # SSL Check
            is_ssl_valid, ssl_msg = self.check_ssl(domain)
            if not is_ssl_valid:
                result['score'] += 0.3
                result['risk_factors'].append(f"SSL Issue: {ssl_msg}")
            
            # WHOIS (Domain Age) - Skip for common domains to save time
            common_domains = ['google.com', 'gmail.com', 'microsoft.com', 'yahoo.com']
            if domain not in common_domains:
                age = self.check_whois(domain)
                if age != -1 and age < 30: # Less than 30 days old
                    result['score'] += 0.4
                    result['risk_factors'].append(f"Newly Created Domain ({age} days)")
            
            # Normalize score
            result['score'] = min(1.0, result['score'])
            
        except Exception as e:
            logger.error(f"Deep URL analysis failed: {e}")
            
        return result
