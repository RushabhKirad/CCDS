"""
backend/analyzers/domain_credibility.py

Domain Credibility Analyzer
============================
Scores a sender domain on 0.0 (unknown/suspicious) → 1.0 (highly trusted)
using purely structural and DNS-based signals — NOT a whitelist.

Any domain can score well by having:
  - A reputable TLD
  - An old registration age
  - No suspicious keywords or structure
  - Valid SSL
  - A known service category (optional boost)

The score is used in hybrid_analysis.py to dampen the phishing probability
for emails from established senders where the ML text model produces a
false positive due to marketing/notification language.
"""

import re
import socket
import ssl
import datetime
import logging
from functools import lru_cache
from typing import Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# REPUTABLE TLDs — established TLDs used by real businesses
# Phishing sites predominantly use free/cheap/new TLDs (.tk, .ml, .ga, .cf,
# .xyz, .top, .pw, .click, .gq, .icu, .cyou, etc.)
# ---------------------------------------------------------------------------
REPUTABLE_TLDS = {
    # Classic
    'com', 'org', 'net', 'edu', 'gov', 'mil',
    # Country codes used by major businesses
    'co', 'io', 'ai', 'app', 'dev',
    'in', 'uk', 'us', 'ca', 'au', 'de', 'fr', 'jp', 'br', 'eu',
    # Compound country codes
    'co.in', 'co.uk', 'com.au', 'co.jp', 'co.za', 'co.nz',
    # Established gTLDs with good reputation
    'ac', 'info', 'biz', 'mobi', 'name',
    # Tech sector gTLDs
    'tech', 'cloud', 'digital',
}

# TLDs that are almost exclusively used by phishing/spam (free registration)
SUSPICIOUS_TLDS = {
    'tk', 'ml', 'ga', 'cf', 'gq',          # Freenom free TLDs
    'xyz', 'top', 'pw', 'click', 'icu',    # Cheap gTLDs heavily abused
    'cyou', 'buzz', 'fun', 'rest',
    'loan', 'bid', 'win', 'review',
    'download', 'stream', 'cricket',
    'party', 'trade', 'racing', 'date',
}

# Suspicious keywords in domain names (attackers add these to look legit)
SUSPICIOUS_DOMAIN_KEYWORDS = [
    'verify', 'secure', 'login', 'account', 'update', 'confirm',
    'password', 'reset', 'alert', 'billing', 'payment', 'bank',
    'helpdesk', 'support-team', 'suspended', 'unlock', 'validate',
]

# ---------------------------------------------------------------------------
# KNOWN DOMAIN CATEGORIES
# Maps domain roots to a credibility category. This is NOT a whitelist —
# it is a categorical signal. A new unknown domain simply won't match here
# and will rely purely on structural scoring.
# ---------------------------------------------------------------------------
_CATEGORY_MAP = {
    # Job portals & career platforms
    'job_portal': [
        'naukri', 'indeed', 'glassdoor', 'linkedin', 'internshala',
        'monster', 'shine', 'timesjobs', 'foundit', 'instahyre',
        'angellist', 'wellfound', 'hirist', 'iimjobs',
    ],
    # Cloud & AI platforms
    'cloud_ai': [
        'openai', 'anthropic', 'google', 'microsoft', 'amazon', 'aws',
        'azure', 'gcp', 'cloudflare', 'digitalocean', 'heroku',
        'vercel', 'netlify', 'firebase', 'supabase', 'railway',
    ],
    # Education & e-learning
    'education': [
        'coursera', 'udemy', 'edx', 'udacity', 'skillshare', 'pluralsight',
        'khanacademy', 'duolingo', 'codecademy', 'leetcode', 'hackerrank',
        'geeksforgeeks', 'w3schools',
    ],
    # Developer tools & communities
    'developer': [
        'github', 'gitlab', 'bitbucket', 'stackoverflow', 'npm',
        'pypi', 'docker', 'kubernetes', 'atlassian', 'jira',
        'confluence', 'notion', 'airtable', 'figma',
    ],
    # Communication & productivity
    'productivity': [
        'slack', 'zoom', 'teams', 'meet', 'webex', 'discord',
        'trello', 'asana', 'basecamp', 'monday', 'clickup', 'todoist',
    ],
    # Email & identity providers
    'email_identity': [
        'gmail', 'googlemail', 'yahoo', 'outlook', 'hotmail', 'live',
        'icloud', 'protonmail', 'zoho', 'fastmail',
    ],
    # E-commerce & payments
    'ecommerce': [
        'amazon', 'flipkart', 'myntra', 'meesho', 'shopify', 'woocommerce',
        'paypal', 'stripe', 'razorpay', 'paytm', 'phonepe', 'gpay',
    ],
    # News & media
    'media': [
        'bbc', 'cnn', 'nytimes', 'guardian', 'reuters', 'techcrunch',
        'theverge', 'wired', 'forbes', 'bloomberg', 'wsj', 'ndtv',
        'timesofindia', 'hindustantimes', 'indianexpress',
    ],
    # Security & antivirus
    'security': [
        'kaspersky', 'norton', 'mcafee', 'avast', 'bitdefender',
        'malwarebytes', 'crowdstrike', 'paloalto', 'fortinet',
    ],
}

# Invert category map: 'naukri' → 'job_portal', etc.
_DOMAIN_ROOT_TO_CATEGORY = {
    root: cat
    for cat, roots in _CATEGORY_MAP.items()
    for root in roots
}

# Category credibility bonus (some categories are more reliable to classify)
_CATEGORY_BONUS = {
    'job_portal':     0.20,
    'cloud_ai':       0.20,
    'education':      0.18,
    'developer':      0.20,
    'productivity':   0.18,
    'email_identity': 0.15,
    'ecommerce':      0.15,
    'media':          0.12,
    'security':       0.18,
}


# ---------------------------------------------------------------------------
# HELPERS
# ---------------------------------------------------------------------------

def _parse_domain_parts(domain: str):
    """
    Given 'mail.naukri.com' or 'internshala.com', return:
      tld       = 'com'
      root      = 'naukri'  (second-to-last label, before TLD)
      subdomain = 'mail'    (everything before root.tld)
    Handles compound TLDs like .co.in, .co.uk
    """
    domain = domain.lower().strip().lstrip('www.').lstrip('www2.')
    parts = domain.split('.')

    # Detect compound TLDs (e.g., co.in, co.uk, com.au)
    if len(parts) >= 3 and f"{parts[-2]}.{parts[-1]}" in REPUTABLE_TLDS:
        tld = f"{parts[-2]}.{parts[-1]}"
        root = parts[-3] if len(parts) >= 3 else ''
        subdomain = '.'.join(parts[:-3]) if len(parts) > 3 else ''
    elif len(parts) >= 2:
        tld = parts[-1]
        root = parts[-2]
        subdomain = '.'.join(parts[:-2]) if len(parts) > 2 else ''
    else:
        tld = ''
        root = domain
        subdomain = ''

    return tld, root, subdomain


@lru_cache(maxsize=256)
def _check_ssl_quick(domain: str) -> bool:
    """
    Tries a quick SSL handshake (3-second timeout).
    Returns True if a valid certificate is found.
    Cached per session to avoid repeated network calls.
    """
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain):
                return True
    except Exception:
        return False


@lru_cache(maxsize=256)
def _get_domain_age_days(domain: str) -> int:
    """
    Returns domain age in days via WHOIS. Returns -1 if lookup fails.
    Cached per session.
    """
    try:
        import whois  # type: ignore
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if creation_date:
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            return (datetime.datetime.now() - creation_date).days
    except Exception as e:
        logger.debug(f"WHOIS failed for {domain}: {e}")
    return -1


# ---------------------------------------------------------------------------
# MAIN ANALYZER CLASS
# ---------------------------------------------------------------------------

class DomainCredibilityAnalyzer:
    """
    Scores a sender domain on how credible/established it is.

    Score breakdown (max 1.0):
      TLD reputation          0.00 – 0.20
      Domain structure        0.00 – 0.20
      No suspicious keywords  0.00 – 0.15
      SSL validity            0.00 – 0.10
      Domain age              0.00 – 0.20
      Category match          0.00 – 0.20
      ─────────────────────────────────
      TOTAL                   0.00 – 1.05 (capped at 1.0)
    """

    def score(self, domain: str) -> float:
        """
        Returns a credibility score 0.0 → 1.0 for the given sender domain.
        Higher = more trustworthy / established.
        """
        if not domain or '.' not in domain:
            return 0.0

        try:
            tld, root, subdomain = _parse_domain_parts(domain)
            total = 0.0

            # ── 1. TLD REPUTATION ──────────────────────────────────────────
            if tld in SUSPICIOUS_TLDS:
                # Immediately suspicious — cap at 0.0 (no credibility boost)
                return 0.0
            elif tld in REPUTABLE_TLDS or any(tld.endswith('.' + r) for r in REPUTABLE_TLDS):
                total += 0.20
            else:
                # Unknown TLD — neutral, give partial credit
                total += 0.08

            # ── 2. DOMAIN STRUCTURE ────────────────────────────────────────
            # Short root name = established brand (not a freshly-generated name)
            if len(root) <= 12:
                total += 0.10
            elif len(root) <= 20:
                total += 0.05

            # No hyphens in root (phishing: pay-pal-secure, verify-account)
            if '-' not in root:
                total += 0.10
            elif root.count('-') == 1:
                # Single hyphen is OK for some brands (e.g., google-mail)
                total += 0.04

            # ── 3. SUSPICIOUS KEYWORDS IN DOMAIN ──────────────────────────
            full_domain_lower = domain.lower()
            has_suspicious_keyword = any(
                kw in full_domain_lower for kw in SUSPICIOUS_DOMAIN_KEYWORDS
            )
            if not has_suspicious_keyword:
                total += 0.15
            # If suspicious keyword found → no bonus, and no penalty
            # (penalty is already handled by the rule engine in hybrid_analysis)

            # ── 4. SSL VALIDITY ────────────────────────────────────────────
            # Only check for reputable TLDs to save time
            if tld in REPUTABLE_TLDS and _check_ssl_quick(domain):
                total += 0.10

            # ── 5. DOMAIN AGE (WHOIS) ──────────────────────────────────────
            # Skip for known compound TLDs that are slow to WHOIS
            # Only run if structural score is already reasonable (> 0.3)
            # to avoid wasting time on clearly suspicious domains
            if total > 0.30:
                age_days = _get_domain_age_days(domain)
                if age_days >= 730:       # 2+ years — well-established
                    total += 0.20
                elif age_days >= 180:     # 6 months – 2 years — maturing
                    total += 0.12
                elif age_days >= 30:      # 1–6 months — new but exists
                    total += 0.04
                elif age_days >= 0:       # < 30 days — very new = suspicious
                    total += 0.0
                # age_days == -1 means WHOIS failed → no bonus, no penalty

            # ── 6. CATEGORY MATCH ──────────────────────────────────────────
            category = _DOMAIN_ROOT_TO_CATEGORY.get(root)
            if category:
                bonus = _CATEGORY_BONUS.get(category, 0.10)
                total += bonus

            return min(1.0, round(total, 4))

        except Exception as e:
            logger.warning(f"Domain credibility scoring failed for '{domain}': {e}")
            return 0.0

    def get_detail(self, domain: str) -> dict:
        """
        Returns a detailed breakdown of the credibility score.
        Used for internal logging only — NOT shown to users.
        """
        if not domain or '.' not in domain:
            return {'score': 0.0, 'reason': 'Invalid domain'}

        try:
            tld, root, subdomain = _parse_domain_parts(domain)
            breakdown = {}
            total = 0.0

            # TLD
            if tld in SUSPICIOUS_TLDS:
                breakdown['tld'] = 0.0
                breakdown['reason'] = f'Suspicious TLD: .{tld}'
                return {'score': 0.0, 'breakdown': breakdown}
            elif tld in REPUTABLE_TLDS:
                breakdown['tld'] = 0.20; total += 0.20
            else:
                breakdown['tld'] = 0.08; total += 0.08

            # Structure
            struct = 0.0
            if len(root) <= 12: struct += 0.10
            elif len(root) <= 20: struct += 0.05
            if '-' not in root: struct += 0.10
            elif root.count('-') == 1: struct += 0.04
            breakdown['structure'] = round(struct, 3); total += struct

            # Keywords
            kw_score = 0.15 if not any(k in domain.lower() for k in SUSPICIOUS_DOMAIN_KEYWORDS) else 0.0
            breakdown['no_suspicious_keywords'] = kw_score; total += kw_score

            # SSL
            ssl_ok = tld in REPUTABLE_TLDS and _check_ssl_quick(domain)
            breakdown['ssl'] = 0.10 if ssl_ok else 0.0; total += breakdown['ssl']

            # Age
            if total > 0.30:
                age = _get_domain_age_days(domain)
                if age >= 730: age_score = 0.20
                elif age >= 180: age_score = 0.12
                elif age >= 30: age_score = 0.04
                elif age >= 0: age_score = 0.0
                else: age_score = 0.0
                breakdown['age_days'] = age
                breakdown['age_score'] = age_score
                total += age_score

            # Category
            cat = _DOMAIN_ROOT_TO_CATEGORY.get(root)
            cat_score = _CATEGORY_BONUS.get(cat, 0.0) if cat else 0.0
            breakdown['category'] = cat or 'unknown'
            breakdown['category_score'] = cat_score
            total += cat_score

            final = min(1.0, round(total, 4))
            breakdown['total'] = final
            return {'score': final, 'breakdown': breakdown}

        except Exception as e:
            return {'score': 0.0, 'reason': str(e)}


# Module-level singleton — import and reuse
domain_credibility_analyzer = DomainCredibilityAnalyzer()
