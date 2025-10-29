from transformers import AutoTokenizer, AutoModelForSequenceClassification
import torch

MODEL_ID = "cybersectony/phishing-email-detection-distilbert_v2.4.1"
tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_ID)

def bert_score(text):
    inputs = tokenizer(text, return_tensors="pt")
    with torch.no_grad():
        logits = model(**inputs).logits
    predicted_id = logits.argmax().item()
    label = model.config.id2label[predicted_id]
    score = torch.softmax(logits, dim=-1)[0][predicted_id].item()
    return ("Risky" if label.lower() == "phishing" or score > 0.7 else "Safe",
            f"AI confidence: {score:.2f}, label: {label}")
