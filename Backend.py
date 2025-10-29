from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Optional
import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Import your modules
import phishing_rules
try:
    from google_safebrowsing import init_safebrowsing, safebrowsing
    HAS_GOOGLE_API = True
except ImportError:
    HAS_GOOGLE_API = False
    print("❌ Google Safe Browsing module not found")

app = FastAPI(title="GuardianEye API", version="1.0.0")

# Initialize Safe Browsing only if API key exists
GOOGLE_API_KEY = os.getenv('GOOGLE_SAFEBROWSING_API_KEY')
if GOOGLE_API_KEY and HAS_GOOGLE_API:
    try:
        init_safebrowsing(GOOGLE_API_KEY)
        print("✅ Google Safe Browsing initialized")
    except Exception as e:
        print(f"❌ Google Safe Browsing init failed: {e}")
        safebrowsing = None
else:
    print("⚠️  Google Safe Browsing disabled - using rule-based only")
    safebrowsing = None

class AnalysisRequest(BaseModel):
    url: Optional[str] = None
    email_text: Optional[str] = None

class AnalysisResponse(BaseModel):
    is_phishing: bool
    confidence: float
    detection_method: str
    reasons: list
    message: str

@app.get("/")
async def root():
    return {"message": "GuardianEye API is running", "status": "active"}

@app.post("/analyze", response_model=AnalysisResponse)
async def analyze_content(request: AnalysisRequest):
    try:
        if request.url:
            print(f"🔍 User submitted URL: {request.url}")
            
            # Use Google Safe Browsing API if available
            if safebrowsing is not None:
                google_result = safebrowsing.check_url(request.url)
                print(f"📊 Google API said: {google_result}")
                
                if google_result['is_phishing']:
                    print("🚨 Google flagged as PHISHING")
                    return AnalysisResponse(
                        is_phishing=True,
                        confidence=google_result['confidence'],
                        detection_method="google_safe_browsing",
                        reasons=google_result.get('threat_types', ['Unknown threat']),
                        message=google_result['message']
                    )
                else:
                    print("✅ Google said SAFE - checking with our rules...")
            
            # Use our rule-based system (fallback or primary)
            rule_phishing, rule_reasons, rule_confidence = phishing_rules.check_url(request.url)
            
            return AnalysisResponse(
                is_phishing=rule_phishing,
                confidence=rule_confidence,
                detection_method="rule_based",
                reasons=rule_reasons,
                message="Analyzed with custom rules"
            )
        
        elif request.email_text:
            # For email text, use your existing rule-based system
            rule_phishing, rule_reasons = phishing_rules.check_email_content(request.email_text)
            
            return AnalysisResponse(
                is_phishing=rule_phishing,
                confidence=0.7 if rule_phishing else 0.3,
                detection_method="rule_based",
                reasons=rule_reasons,
                message="Analyzed email content with rules"
            )
        
        else:
            raise HTTPException(status_code=400, detail="No URL or email text provided")
            
    except Exception as e:
        print(f"❌ Error: {str(e)}")
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)