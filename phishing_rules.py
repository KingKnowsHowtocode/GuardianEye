import re
from urllib.parse import urlparse
from typing import List, Tuple

class PhishingRules:
    def __init__(self):
        self.suspicious_keywords = [
            'verify', 'account', 'suspended', 'security', 'login', 
            'confirm', 'banking', 'password', 'urgent', 'immediately'
        ]
        
        self.suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.xyz', '.top', '.club']
        self.trusted_domains = ['github.com', 'google.com', 'microsoft.com', 'apple.com', 'python.org']
    
    def check_url(self, url: str) -> Tuple[bool, List[str], float]:
        """Check URL for phishing indicators"""
        rules_matched = []
        
        # Check if it's a trusted domain first
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        if any(trusted in domain for trusted in self.trusted_domains):
            return False, ["Trusted domain"], 0.05  # 5% chance it's phishing
        
        # Traditional rule-based checks
        if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
            rules_matched.append("Uses IP address instead of domain")
        
        for tld in self.suspicious_tlds:
            if domain.endswith(tld):
                rules_matched.append(f"Suspicious TLD: {tld}")
                break
        
        if domain.count('.') > 3:
            rules_matched.append("Excessive subdomains")
        
        if '--' in domain or domain.count('-') > 3:
            rules_matched.append("Suspicious hyphen usage")
        
        # Check for brand mimicking
        if any(brand in domain for brand in ['paypal', 'facebook', 'amazon', 'netflix']):
            if not any(trusted in domain for trusted in ['paypal.com', 'facebook.com', 'amazon.com', 'netflix.com']):
                rules_matched.append("Brand name mimicking detected")
        
        # Calculate confidence score - FIXED
        if len(rules_matched) > 0:
            confidence = min(len(rules_matched) * 0.25, 0.95)  # 25% per rule, max 95%
        else:
            confidence = 0.05  # 5% baseline for safe sites
            
        is_phishing = len(rules_matched) > 0
        
        return is_phishing, rules_matched, confidence
    
    def check_email_content(self, text: str) -> Tuple[bool, List[str]]:
        """Check email content for phishing indicators"""
        rules_matched = []
        text_lower = text.lower()
        
        # Check for urgency keywords
        urgency_words = ['urgent', 'immediately', 'asap', 'right away', 'act now']
        for word in urgency_words:
            if word in text_lower:
                rules_matched.append(f"Urgency keyword: {word}")
        
        # Check for suspicious requests
        if any(keyword in text_lower for keyword in ['click here', 'verify now', 'reset password', 'confirm your account']):
            rules_matched.append("Suspicious action request")
        
        # Check for personal information requests
        if any(keyword in text_lower for keyword in ['password', 'social security', 'credit card', 'bank account']):
            rules_matched.append("Requests personal information")
        
        return len(rules_matched) > 1, rules_matched

# Create a global instance
phishing_checker = PhishingRules()

# Create the functions that backend.py is expecting
def check_url(url: str) -> Tuple[bool, List[str], float]:
    return phishing_checker.check_url(url)

def check_email_content(text: str) -> Tuple[bool, List[str]]:
    return phishing_checker.check_email_content(text)