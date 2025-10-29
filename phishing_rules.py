import re

def check_suspicious_patterns(text):
    """
    Check for phishing patterns in text
    Returns: (status, reasons)
    """
    reasons = []
    suspicious_keywords = [
        'verify your account', 'suspend', 'confirm your identity',
        'click here', 'urgent', 'security alert', 'login now',
        'password', 'account', 'bank', 'paypal', 'social security',
        'irs', 'tax', 'lottery', 'prize', 'winner', 'free', 'limited time',
        'act now', 'immediately', 'dear customer', 'dear user'
    ]
    
    # Check for suspicious keywords
    for keyword in suspicious_keywords:
        if keyword.lower() in text.lower():
            reasons.append(f"Suspicious keyword: '{keyword}'")
    
    # Check for URL mismatches
    urls = re.findall(r'https?://[^\s]+', text)
    for url in urls:
        if 'bit.ly' in url or 'tinyurl' in url:
            reasons.append(f"URL shortener used: {url}")
    
    # Check for excessive urgency
    urgency_words = ['urgent', 'immediately', 'act now', 'limited time']
    urgency_count = sum(1 for word in urgency_words if word in text.lower())
    if urgency_count >= 2:
        reasons.append("Excessive urgency detected")
    
    # Determine status
    status = "Risky" if reasons else "Safe"
    
    return status, reasons