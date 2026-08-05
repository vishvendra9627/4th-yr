import re
import urllib.parse
from urllib.parse import urlparse


SUSPICIOUS_TLDS = {
    'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'pw', 'top', 'click', 'loan',
    'work', 'party', 'date', 'faith', 'win', 'racing', 'stream', 'download',
    'bid', 'trade', 'science', 'accountant', 'review', 'men', 'country',
    'cricket', 'webcam', 'space'
}

BRAND_KEYWORDS = [
    'paypal', 'amazon', 'google', 'apple', 'microsoft', 'facebook', 'netflix',
    'instagram', 'twitter', 'linkedin', 'ebay', 'chase', 'wellsfargo',
    'bankofamerica', 'citibank', 'barclays', 'hsbc', 'lloyds', 'natwest',
    'halifax', 'dhl', 'fedex', 'ups', 'usps', 'hmrc', 'irs'
]

URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly',
    'adf.ly', 'is.gd', 'short.link', 'rebrand.ly', 'cutt.ly', 'shorturl.at'
]

URGENT_WORDS = [
    'urgent', 'immediately', 'expire', 'suspended', 'verify', 'confirm',
    'update', 'limited', 'warning', 'alert', 'important', 'action required',
    'account locked', 'unauthorized', 'click here', 'winner', 'prize',
    'congratulations', 'selected', 'claim'
]

CREDENTIAL_WORDS = [
    'password', 'passwd', 'pin', 'credit card', 'card number', 'cvv',
    'social security', 'ssn', 'bank account', 'routing number', 'login',
    'sign in', 'signin', 'account number'
]

STOPWORDS = {
    'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you',
    'your', 'yours', 'he', 'him', 'his', 'she', 'her', 'hers', 'it', 'its',
    'they', 'them', 'their', 'what', 'which', 'who', 'whom', 'this', 'that',
    'these', 'those', 'am', 'is', 'are', 'was', 'were', 'be', 'been', 'being',
    'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could',
    'should', 'may', 'might', 'shall', 'can', 'a', 'an', 'the', 'and', 'but',
    'if', 'or', 'because', 'as', 'of', 'at', 'by', 'for', 'with', 'about',
    'against', 'between', 'into', 'through', 'during', 'to', 'from', 'in',
    'out', 'on', 'off', 'over', 'under', 'then', 'once', 'so', 'than', 'too',
    'very', 'just', 'not', 'no', 'nor', 'up', 'down', 'over', 'under', 'again', 'further', 'here', 'there', 'when',
    'where', 'why', 'how', 'all', 'any', 'both', 'each', 'few', 'more',
    'most', 'other', 'some', 'such', 'only', 'own',
}

# URL feature extraction functions
def extract_url_features(url):
    features = []
    try: 
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        path = parsed.path or ''
        query = parsed.query or ''
    except Exception:
        hostname = ''
        path = ''
        query = ''

    features.append(len(url))
    features.append(url.count('.'))
    features.append(url.count('-'))
    features.append(url.count('_'))
    features.append(url.count('/'))
    features.append(url.count('?'))
    features.append(url.count('='))
    features.append(url.count('@'))
    features.append(url.count('!'))
    features.append(url.count('%'))
    features.append(url.count('#'))
    features.append(url.count('~'))
    features.append(url.count(','))
    features.append(len(hostname))
    features.append(sum(c.isdigit() for c in hostname))
    features.append(1 if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', hostname) else 0)

    parts = hostname.split('.')
    tld = parts[-1].lower()if parts else '' 
    features.append(1 if tld in SUSPICIOUS_TLDS else 0)
    features.append(1 if any(s in url.lower() for s in URL_SHORTENERS) else 0)
    features.append(1 if (urlparse(url).scheme if url.startswith('http') else '') == 'http' else 0)
    features.append(1 if any(brand in hostname.lower() for brand in BRAND_KEYWORDS) else 0)
    subdomains = len(hostname.split('.')) - 2
    features.append(max(0, subdomains))
    features.append(1 if '-' in hostname else 0)
    features.append(1 if 'https' in hostname.lower() else 0)
    features.append(len(path))
    features.append(len(query))
    features.append(1 if re.search(r'secure|login|signin|account|update|verify|confirm|bank|pay', url.lower()) else 0)
    features.append(1 if re.search(r'\.php|\.html|\.asp|\.exe', path.lower()) else 0)
    features.append(1 if re.search(r'redirect|redirect_to|url=|link=|goto=', query.lower()) else 0)
    features.append(len(parts) if parts else 0)
    features.append(len(re.findall(r'[!@#$%^&*()+=\[\]{}|\\;:<>?]', url)))
    return features


def get_url_feature_names() -> list:
    return [
        'url_length', 'num_dots', 'num_hyphens', 'num_underscores', 'num_slashes',
        'num_question_marks', 'num_equals', 'num_at', 'num_exclamation',
        'num_percent', 'num_hash', 'num_tilde', 'num_comma',
        'hostname_length', 'digits_in_domain', 'is_ip_address', 'suspicious_tld',
        'is_url_shortener', 'is_http', 'contains_brand', 'num_subdomains',
        'hyphen_in_domain', 'https_in_hostname', 'path_length', 'query_length',
        'sensitive_words', 'suspicious_extension', 'redirect_param',
        'num_domain_parts', 'num_special_chars'
    ]

#email feature (8) - matching the name of the CSV columns used for training the ML model
def extract_email_ml_features(email_text: str) -> list:
    """
    Extracts the same 8 features present in the email_phishing_data.csv dataset.
    This ensures training and inference use an identical feature space.
    """
    words = email_text.split()
    lower_words = [w.lower().strip('.,!?;:') for w in words]

    num_words = len(words)
    num_unique_words = len(set(lower_words))
    num_stopwords = sum(1 for w in lower_words if w in STOPWORDS)

    urls = re.findall(r'https?://[^\s<>"]+', email_text)
    num_links = len(urls)

    domains = set()
    for url in urls:
        try:
            d = urlparse(url).hostname
            if d:
                domains.add(d.lower())
        except Exception:
            pass
    num_unique_domains = len(domains)

    num_email_addresses = len(re.findall(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', email_text))

    typo_pattern = r'\b(recieve|occured|verifiy|acount|acouunt|suspicous|plesae|pleasee|pasword|passord|informaton|accout|acces|securty|acheive|recievd|seperate|wierd|definately|neccessary)\b'
    num_spelling_errors = len(re.findall(typo_pattern, email_text.lower()))

    text_lower = email_text.lower()
    num_urgent_keywords = sum(1 for w in URGENT_WORDS if w in text_lower)

    return [
        num_words,
        num_unique_words,
        num_stopwords,
        num_links,
        num_unique_domains,
        num_email_addresses,
        num_spelling_errors,
        num_urgent_keywords,
    ]


def get_email_ml_feature_names() -> list:
    return [
        'num_words', 'num_unique_words', 'num_stopwords', 'num_links',
        'num_unique_domains', 'num_email_addresses', 'num_spelling_errors',
        'num_urgent_keywords'
    ]
# ── EMAIL HEURISTIC FEATURES (18) — for rule-based scoring & user indicators ──

def extract_email_heuristic_features(email_text: str) -> list:
    features = []
    text_lower = email_text.lower()

    features.append(len(email_text))
    urgent_count = sum(1 for w in URGENT_WORDS if w in text_lower)
    features.append(urgent_count)
    cred_count = sum(1 for w in CREDENTIAL_WORDS if w in text_lower)
    features.append(cred_count)
    brand_count = sum(1 for b in BRAND_KEYWORDS if b in text_lower)
    features.append(brand_count)
    features.append(1 if re.search(r'dear (customer|user|valued|account holder|member|sir|madam|client)', text_lower) else 0)
    words = email_text.split()
    total_words = max(len(words), 1)
    caps_words = sum(1 for w in words if w.isupper() and len(w) > 2)
    features.append(caps_words / total_words)
    typos = len(re.findall(r'\b(recieve|occured|verifiy|acount|suspicous|plesae|pleasee|pasword|passord|informaton|accout|acces|securty)\b', text_lower))
    features.append(typos)
    url_count = len(re.findall(r'https?://', email_text))
    features.append(url_count)
    features.append(1 if re.search(r'https?://(\d{1,3}\.){3}\d{1,3}', email_text) else 0)
    features.append(1 if re.search(r'\.(html?|exe|js|vbs|bat|cmd|ps1|docm|xlsm|zip|rar)\b', text_lower) else 0)
    sender_match = re.search(r'from:\s*([^\n]+)', text_lower)
    if sender_match:
        sender = sender_match.group(1)
        features.append(1 if any(brand in sender for brand in BRAND_KEYWORDS) else 0)
        features.append(1 if re.search(r'@[a-z0-9.-]+\.(xyz|tk|ml|ga|cf|top|click)', sender) else 0)
    else:
        features.append(0)
        features.append(0)
    features.append(1 if re.search(r'click (here|now|below|link)|follow (this|the) link|tap here', text_lower) else 0)
    features.append(1 if re.search(r'within \d+ (hour|day|minute)|expires?( in| soon)|limited time', text_lower) else 0)
    features.append(email_text.count('!'))
    features.append(1 if re.search(r'\$[\d,]+|free|win|prize|gift|reward|offer|discount', text_lower) else 0)
    features.append(1 if any(s in email_text.lower() for s in URL_SHORTENERS) else 0)
    features.append(email_text.count('?'))
    return features


def get_email_heuristic_feature_names() -> list:
    return [
        'email_length', 'urgent_word_count', 'credential_word_count', 'brand_mention_count',
        'generic_greeting', 'capital_ratio', 'typo_count', 'url_count',
        'ip_url', 'suspicious_attachment', 'sender_brand_impersonation',
        'sender_suspicious_tld', 'action_link', 'time_pressure',
        'exclamation_count', 'financial_incentive', 'url_shortener',
        'question_count'
    ]
# Keep backward-compatible alias
def extract_email_features(email_text: str) -> list:
    return extract_email_heuristic_features(email_text)


def get_email_feature_names() -> list:
    return get_email_heuristic_feature_names()


# ── HEURISTIC RISK SCORING (for user-facing indicators) ───────────────────────

def compute_risk_score(features: list, feature_type: str) -> dict:
    if feature_type == 'url':
        names = get_url_feature_names()
    else:
        names = get_email_heuristic_feature_names()

    score = 0
    flags = []
    feature_map = dict(zip(names, features))

    if feature_type == 'url':
        if feature_map.get('is_ip_address', 0):
            score += 35
            flags.append(('IP Address as Domain', 'high',
                'Using an IP address instead of a domain name is a classic phishing indicator. Real websites use domain names, not raw IPs.'))
        if feature_map.get('suspicious_tld', 0):
            score += 20
            flags.append(('Suspicious Top-Level Domain', 'medium',
                'Free/cheap TLDs like .xyz, .tk, .ml are heavily abused by phishers due to low cost and minimal verification.'))
        if feature_map.get('is_url_shortener', 0):
            score += 20
            flags.append(('URL Shortener Detected', 'medium',
                'Shorteners hide the real destination. Attackers use them to disguise malicious links and bypass email filters.'))
        if feature_map.get('num_at', 0):
            score += 30
            flags.append(('@ Symbol in URL', 'high',
                'Browsers treat everything before "@" as credentials — e.g. http://paypal.com@evil.com actually visits evil.com.'))
        if feature_map.get('is_http', 0):
            score += 15
            flags.append(('No HTTPS Encryption', 'medium',
                'HTTP connections are unencrypted. Legitimate services handling personal data always use HTTPS.'))
        if feature_map.get('url_length', 0) > 100:
            score += 10
            flags.append(('Excessively Long URL', 'low',
                'Long URLs are used to bury a suspicious domain in a wall of text, making it hard to spot.'))
        if feature_map.get('digits_in_domain', 0) > 2:
            score += 15
            flags.append(('Numbers in Domain Name', 'medium',
                'Digits like "paypa1.com" mimic real brands while evading exact-match detection.'))
        if feature_map.get('hyphen_in_domain', 0) and feature_map.get('contains_brand', 0):
            score += 25
            flags.append(('Brand Impersonation via Hyphen', 'high',
                'Domains like "paypal-secure.com" look official but lead to attacker-controlled sites.'))
        elif feature_map.get('contains_brand', 0):
            score += 15
            flags.append(('Brand Name in URL', 'medium',
                'Brand names appearing in URLs of non-official domains are a common impersonation technique.'))
        if feature_map.get('sensitive_words', 0):
            score += 10
            flags.append(('Sensitive Action Words in URL', 'low',
                'Words like "login", "verify", or "secure" in phishing URLs create false credibility.'))
        if feature_map.get('redirect_param', 0):
            score += 15
            flags.append(('Redirect Parameter', 'medium',
                'URLs with redirect parameters can bounce you through multiple sites, landing on a malicious page.'))
        if feature_map.get('num_subdomains', 0) > 2:
            score += 15
            flags.append(('Excessive Subdomains', 'medium',
                'Deep nesting like "login.account.paypal.fake.com" tricks users into thinking it\'s legitimate.'))
        if feature_map.get('https_in_hostname', 0):
            score += 20
            flags.append(('HTTPS Trick in Hostname', 'medium',
                '"https" appearing in the domain itself (not the scheme) makes http:// URLs look secure to the untrained eye.'))
    else:
        if feature_map.get('urgent_word_count', 0) >= 2:
            score += 30
            flags.append(('Urgency / Pressure Language', 'high',
                'Creating panic ("Your account will be suspended!") bypasses rational thinking — a core social engineering tactic.'))
        if feature_map.get('credential_word_count', 0) >= 1:
            score += 35
            flags.append(('Credential Request Detected', 'high',
                'No legitimate organisation asks for passwords, PINs, or card numbers via email. This is always phishing.'))
        if feature_map.get('generic_greeting', 0):
            score += 10
            flags.append(('Generic Greeting', 'low',
                '"Dear Customer" instead of your name means the email was sent in bulk — a hallmark of phishing campaigns.'))
        if feature_map.get('typo_count', 0) >= 1:
            score += 15
            flags.append(('Spelling Errors Detected', 'medium',
                'Errors may be intentional to bypass spam filters or indicate non-native speakers running phishing operations.'))
        if feature_map.get('ip_url', 0):
            score += 35
            flags.append(('IP Address Link in Email', 'high',
                'Links using raw IP addresses hide the real domain and are almost exclusively used in phishing.'))
        if feature_map.get('suspicious_attachment', 0):
            score += 30
            flags.append(('Suspicious Attachment Type', 'high',
                '.html, .exe, .zip, .js attachments can deliver malware or harvest credentials through fake login pages.'))
        if feature_map.get('sender_brand_impersonation', 0) or feature_map.get('sender_suspicious_tld', 0):
            score += 25
            flags.append(('Suspicious Sender Address', 'high',
                'The sender claims to be a known brand but the actual email domain doesn\'t match. Always check the full From address.'))
        if feature_map.get('time_pressure', 0):
            score += 20
            flags.append(('Time Pressure Tactics', 'medium',
                '"Within 24 hours" or "expires today" creates panic. Legitimate services give reasonable time for account issues.'))
        if feature_map.get('action_link', 0):
            score += 15
            flags.append(('Action Link Manipulation', 'medium',
                '"Click here" links hide the real URL — visible text can differ completely from the actual destination.'))
        if feature_map.get('url_shortener', 0):
            score += 20
            flags.append(('URL Shortener in Email', 'medium',
                'Shortened links in emails disguise malicious destinations and make link preview useless.'))
        if feature_map.get('capital_ratio', 0) > 0.3:
            score += 10
            flags.append(('Excessive Capitalisation', 'low',
                'Excessive ALL CAPS is used to create alarm and draw attention — a classic manipulation technique.'))
        if feature_map.get('financial_incentive', 0):
            score += 15
            flags.append(('Financial Incentive / Prize Lure', 'medium',
                'Fake prizes or monetary rewards are used to lure victims into clicking links or submitting personal data.'))

    return {'score': min(score, 100), 'flags': flags}