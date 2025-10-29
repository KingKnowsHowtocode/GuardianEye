import requests
import time
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class GoogleSafeBrowsing:
    def __init__(self):
        self.api_key = os.getenv('GOOGLE_SAFEBROWSING_API_KEY')
        if not self.api_key:
            raise ValueError("Google Safe Browsing API key not found in environment variables")
        
        self.api_url = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
        self.last_call_time = 0
        self.call_delay = 1  # 1 second between calls
    
    def check_url(self, url):
        """Check URL using Google Safe Browsing API"""
        # Rate limiting
        current_time = time.time()
        if current_time - self.last_call_time < self.call_delay:
            time.sleep(self.call_delay)
        
        self.last_call_time = time.time()
        
        payload = {
            "client": {
                "clientId": "guardianeye",
                "clientVersion": "1.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        try:
            response = requests.post(
                f"{self.api_url}?key={self.api_key}",
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"🔍 Google API Response: {result}")  # Debug line
                
                # ✅ FIXED: Check if 'matches' key exists and has items
                if 'matches' in result and result['matches']:
                    # ❌ MALICIOUS: Matches found
                    threat_types = [match['threatType'] for match in result['matches']]
                    return {
                        'is_phishing': True,
                        'confidence': 0.95,
                        'source': 'google_safe_browsing',
                        'threat_types': threat_types,
                        'message': f"Flagged by Google Safe Browsing: {', '.join(threat_types)}"
                    }
                else:
                    # ✅ SAFE: No matches found
                    return {
                        'is_phishing': False,
                        'confidence': 0.05,
                        'source': 'google_safe_browsing',
                        'threat_types': [],
                        'message': 'No threats found by Google Safe Browsing'
                    }
            else:
                return {
                    'is_phishing': False,
                    'confidence': 0.0,
                    'source': 'google_safe_browsing',
                    'error': f"API error: {response.status_code}",
                    'message': 'Safe Browsing API unavailable'
                }
                
        except Exception as e:
            return {
                'is_phishing': False,
                'confidence': 0.0,
                'source': 'google_safe_browsing',
                'error': str(e),
                'message': 'Error connecting to Safe Browsing API'
            }

# Global instance
safebrowsing = None

def init_safebrowsing(api_key):
    global safebrowsing
    safebrowsing = GoogleSafeBrowsing()
    return safebrowsing