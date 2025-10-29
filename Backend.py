from fastapi import FastAPI
from pydantic import BaseModel
from phishing_rules import check_suspicious_patterns
from phishing_bert import bert_score
from fastapi.middleware.cors import CORSMiddleware

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

@app.post("/analyze")
def analyze(input: InputText):
    rule_status, reasons = check_suspicious_patterns(input.text)
    ai_status, ai_reason = bert_score(input.text)
    final_status = "Risky" if "Risky" in [rule_status, ai_status] else "Safe"
    return {
        "result": final_status,
        "rule_reasons": reasons,
        "ai_reason": ai_reason
    }
