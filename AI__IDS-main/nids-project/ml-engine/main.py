from fastapi import FastAPI
from pydantic import BaseModel
import joblib
import numpy as np
import pandas as pd

app = FastAPI(title="NIDS - Network Intrusion Detection API")

model = joblib.load("random_forest_model.pkl")
le = joblib.load("label_encoder.pkl")
feature_names = joblib.load("feature_names.pkl")

print(f"Model loaded — {len(model.estimators_)} trees ready")
print(f"Detecting {len(le.classes_)} attack types: {list(le.classes_)}")

class TrafficFlow(BaseModel):
    features: list[float]

@app.get("/")
def root():
    return {
        "status": "running",
        "model": "Random Forest",
        "attack_types": list(le.classes_)
    }

@app.get("/health")
def health():
    return {"status": "healthy", "trees": len(model.estimators_)}

@app.post("/predict")
def predict(flow: TrafficFlow):
    if len(flow.features) != len(feature_names):
        return {
            "error": f"Expected {len(feature_names)} features, got {len(flow.features)}"
        }

    input_df = pd.DataFrame([flow.features], columns=feature_names)
    prediction = model.predict(input_df)[0]
    probabilities = model.predict_proba(input_df)[0]
    confidence = round(float(np.max(probabilities)) * 100, 2)
    attack_label = le.inverse_transform([prediction])[0]
    is_attack = attack_label != "BENIGN"

    return {
        "prediction": attack_label,
        "is_attack": is_attack,
        "confidence": confidence,
        "severity": "HIGH" if confidence > 90 and is_attack else
                    "MEDIUM" if confidence > 70 and is_attack else
                    "LOW" if is_attack else "NONE"
    }

@app.get("/stats")
def stats():
    return {
        "model": "Random Forest",
        "trees": len(model.estimators_),
        "features": len(feature_names),
        "attack_types": list(le.classes_),
        "f1_score": "99.8%"
    }