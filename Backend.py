from fastapi import FastAPI
from pydantic import BaseModel
from phishing_rules import check_suspicious_patterns
from phishing_bert import bert_score
from fastapi.middleware.cors import CORSMiddleware
import requests
import os
import re
from dotenv import load_dotenv

# Load environment variables
load_dotenv('.env')
GOOGLE_API_KEY = os.getenv('GOOGLE_SAFE_BROWSING_API_KEY')

app = FastAPI()

# Allow frontend to access backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

class InputText(BaseModel):
    text: str

def check_url_safe_browsing(url):
    """Check URL with Google Safe Browsing API"""
    try:
        api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}"
        
        request_body = {
            "client": {
                "clientId": "guardianeye-phishing-detector",
                "clientVersion": "1.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(api_url, json=request_body)
        result = response.json()
        
        # If matches exist, URL is malicious
        return bool(result.get('matches'))
    
    except Exception as e:
        print(f"Safe Browsing API error: {e}")
        return False

def extract_urls(text):
    """Simple URL extraction from text"""
    url_pattern = r'https?://[^\s]+'
    return re.findall(url_pattern, text)

@app.post("/analyze")
def analyze(input: InputText):
    # 1. Check for URLs and verify with Safe Browsing
    urls = extract_urls(input.text)
    safe_browsing_results = []
    
    for url in urls:
        is_malicious = check_url_safe_browsing(url)
        safe_browsing_results.append({
            "url": url,
            "is_malicious": is_malicious
        })
    
    # 2. Your existing rule-based check
    rule_status, reasons = check_suspicious_patterns(input.text)
    
    # 3. Your existing BERT analysis
    ai_status, ai_reason = bert_score(input.text)
    
    # 4. Combine all results
    malicious_urls = [result for result in safe_browsing_results if result['is_malicious']]
    safe_browsing_risky = len(malicious_urls) > 0
    
    # Final decision - risky if any method detects risk
    final_status = "Risky" if any([
        "Risky" in [rule_status, ai_status],
        safe_browsing_risky
    ]) else "Safe"
    
    # Add Safe Browsing reasons if malicious URLs found
    if safe_browsing_risky:
        for result in malicious_urls:
            reasons.append(f"Malicious URL detected: {result['url']}")
    
    return {
        "result": final_status,
        "rule_reasons": reasons,
        "ai_reason": ai_reason,
        "url_checks": safe_browsing_results
    }