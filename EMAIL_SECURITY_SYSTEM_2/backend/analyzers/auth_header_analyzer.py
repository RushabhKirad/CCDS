import re
import logging
import dns.resolver

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthHeaderAnalyzer:
    """
    Analyzes email headers for SPF, DKIM, and DMARC authentication results.
    """
    
    def __init__(self):
        pass

    def analyze_headers(self, headers_dict, sender_domain):
        """
        Analyzes authentication headers.
        
        Args:
            headers_dict (dict): Dictionary of email headers.
            sender_domain (str): Domain of the sender.
            
        Returns:
            dict: Authentication results and score penalty.
        """
        results = {
            "spf": "none",
            "dkim": "none",
            "dmarc": "none",
            "score_penalty": 0.0,
            "auth_warnings": []
        }
        
        # 1. Parse Authentication-Results header (Standard)
        auth_results = headers_dict.get("Authentication-Results", "")
        if auth_results:
            # Simple parsing for common patterns
            if "spf=pass" in auth_results.lower():
                results["spf"] = "pass"
            elif "spf=fail" in auth_results.lower() or "spf=softfail" in auth_results.lower():
                results["spf"] = "fail"
                
            if "dkim=pass" in auth_results.lower():
                results["dkim"] = "pass"
            elif "dkim=fail" in auth_results.lower():
                results["dkim"] = "fail"
                
            if "dmarc=pass" in auth_results.lower():
                results["dmarc"] = "pass"
            elif "dmarc=fail" in auth_results.lower():
                results["dmarc"] = "fail"
        
        # 2. Check Received-SPF header (Legacy)
        if results["spf"] == "none":
            spf_header = headers_dict.get("Received-SPF", "")
            if spf_header:
                if "pass" in spf_header.lower():
                    results["spf"] = "pass"
                elif "fail" in spf_header.lower() or "softfail" in spf_header.lower():
                    results["spf"] = "fail"

        # 3. Scoring Logic
        # SPF Fail is suspicious
        if results["spf"] == "fail":
            results["score_penalty"] += 0.3
            results["auth_warnings"].append("SPF Check Failed (Sender IP not authorized)")
            
        # DKIM Fail is very suspicious (content modified or spoofed)
        if results["dkim"] == "fail":
            results["score_penalty"] += 0.4
            results["auth_warnings"].append("DKIM Signature Invalid (Possible spoofing)")
            
        # DMARC Fail is critical
        if results["dmarc"] == "fail":
            results["score_penalty"] += 0.5
            results["auth_warnings"].append("DMARC Policy Violation")
            
        # Bonus for passing everything
        if results["spf"] == "pass" and results["dkim"] == "pass" and results["dmarc"] == "pass":
            results["score_penalty"] = -0.2 # Trust boost
            
        return results

    def check_mx_record(self, domain):
        """Verify if domain has valid MX records."""
        try:
            dns.resolver.resolve(domain, 'MX')
            return True
        except:
            return False
