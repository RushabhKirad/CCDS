"""
backend/analyzers/advanced_phishing_detector.py

Advanced Phishing Detection Engine
===================================
Catches phishing emails that BYPASS Google's spam filter by targeting attack
patterns that evade reputation-based and volume-based detection.

Detection layers:
  1. Display Name Spoofing   — "PayPal" <attacker@gmail.com>
  2. Lookalike/Typosquatting — paypa1.com, pay-pal-secure.com
  3. Homoglyph Attacks       — pаypal.com (Cyrillic 'а' looks identical)
  4. BEC / No-Link Phishing  — Wire transfer / gift card requests
  5. Callback Phishing       — Phone number + urgency, zero URLs
  6. Reply-To Mismatch       — Reply-To != From address
  7. Legitimate Service Abuse— Google Forms, Dropbox, OneDrive used as phishing vector
  8. New-Domain + Urgency    — Fresh domain with high-pressure language
"""

import re
import unicodedata
from typing import Dict, List, Tuple

# ──────────────────────────────────────────────────────────────────────────────
# BRAND MASTER LIST  (display name + legitimate sending domains)
# ──────────────────────────────────────────────────────────────────────────────
KNOWN_BRANDS: Dict[str, List[str]] = {
    'paypal':        ['paypal.com'],
    'google':        ['google.com', 'gmail.com', 'accounts.google.com'],
    'microsoft':     ['microsoft.com', 'outlook.com', 'live.com', 'hotmail.com', 'office.com'],
    'apple':         ['apple.com', 'icloud.com'],
    'amazon':        ['amazon.com', 'amazon.in', 'amazon.co.uk'],
    'facebook':      ['facebook.com', 'facebookmail.com'],
    'instagram':     ['instagram.com'],
    'netflix':       ['netflix.com'],
    'linkedin':      ['linkedin.com', 'e.linkedin.com'],
    'twitter':       ['twitter.com', 'x.com'],
    'dropbox':       ['dropbox.com'],
    'bank of america': ['bankofamerica.com'],
    'wells fargo':   ['wellsfargo.com'],
    'chase':         ['chase.com'],
    'citibank':      ['citi.com', 'citibank.com'],
    'ups':           ['ups.com'],
    'fedex':         ['fedex.com'],
    'dhl':           ['dhl.com'],
    'usps':          ['usps.com'],
    'irs':           ['irs.gov'],
    'docusign':      ['docusign.com', 'docusign.net'],
    'zoom':          ['zoom.us'],
    'slack':         ['slack.com'],
    'github':        ['github.com'],
    'adobe':         ['adobe.com'],
    'norton':        ['nortonlifelock.com'],
    'mcafee':        ['mcafee.com'],
    'coinbase':      ['coinbase.com'],
    'binance':       ['binance.com'],
}

# Homoglyph map: confusable Unicode chars → ASCII equivalent
HOMOGLYPHS: Dict[str, str] = {
    'а': 'a',  # Cyrillic
    'е': 'e',  # Cyrillic
    'о': 'o',  # Cyrillic
    'р': 'p',  # Cyrillic
    'с': 'c',  # Cyrillic
    'і': 'i',  # Cyrillic
    'х': 'x',  # Cyrillic
    'у': 'y',  # Cyrillic
    'ο': 'o',  # Greek omicron
    'ρ': 'p',  # Greek rho
    'α': 'a',  # Greek alpha
    '0': 'o',  # Digit zero → letter o
    '1': 'l',  # Digit one → letter l
    '3': 'e',  # Digit three → letter e
    '5': 's',  # Digit five → letter s
    '\u2019': "'",  # Right single quote
    '\u00e9': 'e',  # é
}

# Legitimate services that can be abused to host phishing pages
ABUSABLE_SERVICES = [
    'forms.gle', 'docs.google.com', 'drive.google.com',
    'onedrive.live.com', 'sharepoint.com',
    'dropbox.com', 'dropboxusercontent.com',
    'wetransfer.com', 'we.tl',
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
    'sites.google.com',
]

# BEC / Social engineering patterns
BEC_PATTERNS = [
    # Wire / bank transfer fraud
    (r'(wire\s*transfer|bank\s*transfer|ach\s*transfer)', 0.45),
    (r'(send|transfer|move).{0,30}(funds|money|payment)', 0.35),
    (r'(vendor|supplier|account).{0,30}(changed|updated|new)\s*(bank|account|routing)', 0.55),
    # Gift card fraud
    (r'(buy|purchase|get|send).{0,30}(amazon|itunes|google play|steam|gift).{0,20}(card|code|voucher)', 0.60),
    (r'gift\s*card.{0,50}(immediately|urgent|asap|right now)', 0.55),
    # CEO / impersonation
    (r'(ceo|president|director|executive|boss|manager).{0,30}(asking|request|need)', 0.35),
    (r'(do not|don\'t).{0,20}(discuss|tell|share).{0,30}(anyone|team|staff)', 0.40),
    (r'(confidential|private|discreet).{0,30}(transaction|payment|transfer)', 0.40),
    # Invoice / payment fraud
    (r'(invoice|bill|payment).{0,30}(overdue|past due|outstanding|immediate)', 0.35),
    (r'(updated|new|changed).{0,20}(banking|payment|account)\s*(details|information)', 0.55),
]

# Urgency amplifiers (when combined with other signals)
URGENCY_MARKERS = [
    r'\burgent\b', r'\bimmediately\b', r'\baction required\b',
    r'\bwithin 24 hours\b', r'\bwithin \d+ hours\b', r'\btoday only\b',
    r'\bdeadline\b', r'\bexpires\b', r'\bfinal notice\b',
    r'\blast chance\b', r'\bdo not ignore\b', r'\bact now\b',
]

# Callback phishing: phone number patterns
PHONE_PATTERN = re.compile(
    r'(?:'
    r'\+?1?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}'  # US format
    r'|'
    r'\+\d{1,3}[-.\s]\d{4,14}'                            # International
    r')'
)


# ──────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

def _extract_display_name_and_domain(sender: str) -> Tuple[str, str]:
    """
    Parse sender header like:
      'PayPal Security <spammer@evil.com>'
      'support@paypal.com'
    Returns (display_name_lower, sender_domain_lower)
    """
    sender = sender.strip()
    display_name = ''
    email_addr = sender

    # "Display Name <email@domain.com>"
    m = re.match(r'^(.*?)\s*<([^>]+)>', sender)
    if m:
        display_name = m.group(1).strip().strip('"\'').lower()
        email_addr   = m.group(2).strip().lower()
    else:
        email_addr = sender.lower()

    domain = email_addr.split('@')[-1] if '@' in email_addr else email_addr
    return display_name, domain


def _levenshtein(s1: str, s2: str) -> int:
    """Compute Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return _levenshtein(s2, s1)
    if not s2:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            curr.append(min(prev[j + 1] + 1, curr[j] + 1,
                            prev[j] + (c1 != c2)))
        prev = curr
    return prev[-1]


def _normalize_homoglyphs(text: str) -> str:
    """Replace confusable Unicode chars with their ASCII equivalents."""
    result = []
    for ch in unicodedata.normalize('NFC', text):
        result.append(HOMOGLYPHS.get(ch, ch))
    return ''.join(result)


def _count_urgency(text: str) -> int:
    """Return count of urgency markers present in text."""
    text_lower = text.lower()
    return sum(1 for p in URGENCY_MARKERS if re.search(p, text_lower))


# ──────────────────────────────────────────────────────────────────────────────
# DETECTION FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────

def check_display_name_spoofing(sender: str) -> Tuple[float, str]:
    """
    Detects 'PayPal <attacker@gmail.com>' style spoofing.
    Returns (score_boost, reason).
    """
    display_name, domain = _extract_display_name_and_domain(sender)
    if not display_name:
        return 0.0, ''

    for brand, legit_domains in KNOWN_BRANDS.items():
        # Display name contains the brand name
        if brand in display_name:
            # But the sending domain is NOT a legitimate domain for that brand
            if not any(domain == ld or domain.endswith('.' + ld) for ld in legit_domains):
                reason = (f"Display name spoofing: '{display_name}' "
                          f"claims to be {brand.title()} but sent from @{domain}")
                return 0.65, reason

    return 0.0, ''


def check_lookalike_domain(sender: str) -> Tuple[float, str]:
    """
    Detects typosquatting / lookalike domains.
    E.g. paypa1.com, pay-pal.com, microsoft-account.com
    """
    _, domain = _extract_display_name_and_domain(sender)
    domain_root = domain.split('.')[0] if '.' in domain else domain
    # Strip common prefixes that attackers add
    cleaned = re.sub(r'[-_](secure|login|verify|account|update|support|help|service|mail|noreply)', '', domain_root)

    for brand, legit_domains in KNOWN_BRANDS.items():
        for ld in legit_domains:
            brand_root = ld.split('.')[0]
            # Exact match is fine
            if domain == ld or domain.endswith('.' + ld):
                return 0.0, ''
            # Levenshtein distance 1–2 from a brand root → lookalike
            dist = _levenshtein(cleaned, brand_root)
            if 0 < dist <= 2 and len(brand_root) >= 4:
                reason = (f"Lookalike domain: '{domain}' is {dist} character(s) "
                          f"away from legitimate '{ld}'")
                return 0.60, reason
            # Brand name is substring of a different domain (pay-pal-secure.com)
            # Require the brand root to make up >=60% of the cleaned domain root
            # to prevent false positives (e.g. 'in' from 'linkedin' matching 'techcrunch')
            if (brand_root in cleaned and cleaned != brand_root
                    and len(brand_root) >= 5
                    and len(brand_root) / max(len(cleaned), 1) >= 0.60):
                reason = f"Brand name '{brand}' embedded in suspicious domain '{domain}'"
                return 0.50, reason

    return 0.0, ''


def check_homoglyphs(sender: str) -> Tuple[float, str]:
    """
    Detects Unicode homoglyph substitution in sender domain.
    E.g. pаypal.com where 'а' is Cyrillic.
    """
    _, domain = _extract_display_name_and_domain(sender)

    # Check if domain contains non-ASCII
    try:
        domain.encode('ascii')
    except UnicodeEncodeError:
        pass  # Definitely has non-ASCII — proceed to check
    else:
        # Fast path: pure ASCII, no homoglyphs
        return 0.0, ''

    normalized = _normalize_homoglyphs(domain)
    if normalized == domain:
        return 0.0, ''

    # Check if the normalized version matches a known brand domain
    for brand, legit_domains in KNOWN_BRANDS.items():
        for ld in legit_domains:
            if normalized == ld or _levenshtein(normalized, ld) <= 1:
                reason = (f"Homoglyph attack: '{domain}' uses look-alike Unicode "
                          f"characters to impersonate '{ld}'")
                return 0.75, reason

    return 0.0, ''


def check_bec_patterns(subject: str, body: str) -> Tuple[float, List[str]]:
    """
    Detects Business Email Compromise (wire transfer, gift card fraud, CEO fraud).
    These emails often have NO URLs and pass all reputation checks.
    """
    combined = (subject + ' ' + body).lower()
    total_score = 0.0
    signals = []

    for pattern, weight in BEC_PATTERNS:
        if re.search(pattern, combined):
            total_score += weight
            # Get a short excerpt for the reason
            m = re.search(pattern, combined)
            signals.append(f"BEC pattern: '{combined[max(0,m.start()-10):m.end()+10].strip()}'")

    urgency = _count_urgency(combined)
    if signals and urgency >= 2:
        total_score += 0.15 * urgency
        signals.append(f"High urgency ({urgency} urgency markers with BEC content)")

    return min(1.0, total_score), signals


def check_callback_phishing(body: str) -> Tuple[float, str]:
    """
    Detects 'callback phishing': email contains a phone number + urgency text
    but NO clickable links. Google cannot scan phone numbers for reputation.
    """
    body_lower = body.lower()
    has_http = bool(re.search(r'https?://', body_lower))
    phone_matches = PHONE_PATTERN.findall(body)
    urgency_count = _count_urgency(body_lower)

    if phone_matches and urgency_count >= 1 and not has_http:
        # Classic callback phishing: phone + urgency + no links
        reason = (f"Callback phishing: {len(phone_matches)} phone number(s) "
                  f"+ {urgency_count} urgency signal(s), no clickable links")
        return 0.55, reason

    if phone_matches and urgency_count >= 2:
        # Has links but also very urgent + phone — still suspicious
        reason = (f"Possible callback phishing: {len(phone_matches)} phone number(s) "
                  f"with high urgency ({urgency_count} signals)")
        return 0.35, reason

    return 0.0, ''


def check_reply_to_mismatch(sender: str, reply_to: str) -> Tuple[float, str]:
    """
    Detects Reply-To header mismatch — attacker sends from a legitimate-looking
    address but wants replies to go to their own address.
    """
    if not reply_to or not sender:
        return 0.0, ''

    _, from_domain  = _extract_display_name_and_domain(sender)
    _, reply_domain = _extract_display_name_and_domain(reply_to)

    if not from_domain or not reply_domain:
        return 0.0, ''

    if from_domain != reply_domain:
        # Check if one of them is a known brand while the other is not
        from_is_legit  = any(from_domain == ld or from_domain.endswith('.' + ld)
                             for domains in KNOWN_BRANDS.values() for ld in domains)
        reply_is_legit = any(reply_domain == ld or reply_domain.endswith('.' + ld)
                             for domains in KNOWN_BRANDS.values() for ld in domains)

        if from_is_legit and not reply_is_legit:
            reason = (f"Reply-To mismatch: From @{from_domain} (trusted) "
                      f"but Reply-To @{reply_domain} (unknown/suspicious)")
            return 0.55, reason

        if from_domain != reply_domain:
            reason = f"Reply-To mismatch: From @{from_domain} ≠ Reply-To @{reply_domain}"
            return 0.30, reason

    return 0.0, ''


def check_legitimate_service_abuse(body: str, urls: List[str]) -> Tuple[float, List[str]]:
    """
    Detects phishing links hosted on legitimate services (Google Forms,
    Dropbox, OneDrive) which have clean reputation and bypass URL scanners.
    """
    if not urls:
        return 0.0, []

    signals = []
    total_score = 0.0
    body_lower = body.lower()

    # Urgency combined with legitimate-service link = suspicious
    urgency = _count_urgency(body_lower)

    for url in urls:
        url_lower = url.lower()
        for service in ABUSABLE_SERVICES:
            if service in url_lower:
                if urgency >= 1:
                    signals.append(
                        f"Legitimate-service phishing: urgent email links to "
                        f"'{service}' (commonly abused for phishing)")
                    total_score += 0.35
                break

        # URL shortener — always suspicious in email context
        shortener_match = re.search(r'(bit\.ly|tinyurl\.com|goo\.gl|ow\.ly|t\.co|buff\.ly|short\.link)/', url_lower)
        if shortener_match:
            signals.append(f"URL shortener detected: '{shortener_match.group(0)}' (hides destination)")
            total_score += 0.30

    return min(1.0, total_score), signals


def check_new_domain_urgency(domain_age_days: int, body: str) -> Tuple[float, str]:
    """
    A domain created < 30 days ago sending an urgent email is a major red flag.
    Google's reputation database may not have flagged it yet (zero-day phishing).
    """
    if domain_age_days < 0:  # Unknown age
        return 0.0, ''

    urgency = _count_urgency(body.lower())

    if domain_age_days < 7:
        score = 0.55 if urgency >= 1 else 0.30
        reason = f"Zero-day phishing risk: domain only {domain_age_days} day(s) old"
        return score, reason

    if domain_age_days < 30:
        score = 0.40 if urgency >= 2 else 0.20
        reason = f"New domain ({domain_age_days} days old) sending urgent email"
        return score, reason

    return 0.0, ''


# ──────────────────────────────────────────────────────────────────────────────
# MASTER FUNCTION
# ──────────────────────────────────────────────────────────────────────────────

def get_advanced_phishing_score(
    sender: str,
    subject: str,
    body: str,
    reply_to: str = '',
    urls: List[str] = None,
    domain_age_days: int = -1,
) -> Dict:
    """
    Run all advanced detection checks and return an aggregated result.

    Returns:
        {
            'score': float,          # 0.0 – 1.0
            'signals': List[str],    # Human-readable explanation
            'override_phishing': bool  # True = classify as phishing regardless of ML
        }
    """
    if urls is None:
        urls = []

    signals: List[str] = []
    component_scores: List[float] = []

    # 1. Display name spoofing
    score, reason = check_display_name_spoofing(sender)
    if score:
        component_scores.append(score)
        signals.append(reason)
        print(f"  [ADV] Display name spoofing: +{score:.2f}")

    # 2. Lookalike domain
    score, reason = check_lookalike_domain(sender)
    if score:
        component_scores.append(score)
        signals.append(reason)
        print(f"  [ADV] Lookalike domain: +{score:.2f}")

    # 3. Homoglyphs
    score, reason = check_homoglyphs(sender)
    if score:
        component_scores.append(score)
        signals.append(reason)
        print(f"  [ADV] Homoglyph attack: +{score:.2f}")

    # 4. BEC patterns
    score, bec_signals = check_bec_patterns(subject, body)
    if score:
        component_scores.append(score)
        signals.extend(bec_signals)
        print(f"  [ADV] BEC patterns: +{score:.2f}")

    # 5. Callback phishing
    score, reason = check_callback_phishing(body)
    if score:
        component_scores.append(score)
        signals.append(reason)
        print(f"  [ADV] Callback phishing: +{score:.2f}")

    # 6. Reply-To mismatch
    score, reason = check_reply_to_mismatch(sender, reply_to)
    if score:
        component_scores.append(score)
        signals.append(reason)
        print(f"  [ADV] Reply-To mismatch: +{score:.2f}")

    # 7. Legitimate service abuse
    score, abuse_signals = check_legitimate_service_abuse(body, urls)
    if score:
        component_scores.append(score)
        signals.extend(abuse_signals)
        print(f"  [ADV] Legit-service abuse: +{score:.2f}")

    # 8. New domain + urgency
    score, reason = check_new_domain_urgency(domain_age_days, body)
    if score:
        component_scores.append(score)
        signals.append(reason)
        print(f"  [ADV] New domain risk: +{score:.2f}")

    # Aggregate: use max of top-2 scores to avoid over-stacking
    component_scores.sort(reverse=True)
    if len(component_scores) >= 2:
        final_score = component_scores[0] * 0.7 + component_scores[1] * 0.3
    elif component_scores:
        final_score = component_scores[0]
    else:
        final_score = 0.0

    final_score = min(1.0, final_score)

    # Override flag: if any single check is very high-confidence, classify as phishing
    override = any(s >= 0.65 for s in component_scores)

    return {
        'score':             final_score,
        'signals':           signals,
        'override_phishing': override,
    }
