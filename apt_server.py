from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from datetime import datetime
from typing import Optional
import json
import os
import traceback
from fastapi import BackgroundTasks
import subprocess

from apt_sdk import (
    predict as sdk_predict,
    load_models,
)

# ======================================================
# APP INIT (BANK INTEGRATION MODE)
# ======================================================
app = FastAPI(title="Bank APT Detection Gateway", version="2.0")

# ======================================================
# LOAD MODELS
# ======================================================
print("Loading APT models for banking security layer...")

event_model, event_tokenizer, seq_model, seq_tokenizer = load_models()

print("Models loaded successfully.")

# ======================================================
# REQUEST SCHEMA (BANK TRANSACTION EVENTS)
# ======================================================
class EventRequest(BaseModel):
    user_id: str
    endpoint: str
    method: str
    payload_size: int
    user_role: str

    source_path: str = "N/A"
    destination_path: str = "N/A"
    ip_address: str = "N/A"
    time_stamp: str = ""

    # optional human feedback (SOC analyst labeling)
    label: Optional[str] = None

# ======================================================
# LOG CONFIG
# ======================================================
LOG_FILE = "event_log.jsonl"
MODEL_VERSION = "BANK-APT-v2.0"

# ======================================================
# RISK ENGINE (BANK TIERING)
# ======================================================
def risk_tier(score: float):
    if score < 25:
        return "LOW"
    elif score < 50:
        return "MEDIUM"
    elif score < 75:
        return "HIGH"
    return "CRITICAL"

# ======================================================
# EVENT LOGGER (AUDIT TRAIL)
# ======================================================
def log_event(event_dict, result):
    entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "model_version": MODEL_VERSION,
        "event": event_dict,
        "result": result
    }

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(entry) + "\n")

# ======================================================
# MAIN SECURITY PREDICTION ENDPOINT
# ======================================================
@app.post("/predicts")
def predict(event: EventRequest):

    event_dict = event.model_dump()

    try:
        print("Incoming bank event:", event_dict)

        # ==================================================
        # CALL SDK PIPELINE (EVENT + SEQUENCE MODEL)
        # ==================================================
        result = sdk_predict(
            event_dict,
            event_model,
            event_tokenizer,
            seq_model,
            seq_tokenizer,
        )

        # ==================================================
        # SAFELY EXTRACT RESULTS
        # ==================================================
        risk_score = result.get("risk_score", 0)

        response = {
            "status": "success",

            "eventPrediction": result["event"]["label"],
            "eventConfidence": result["event"]["confidence"],

            "sequenceAlert": result["sequence"]["sequence_label"],
            "sequenceConfidence": result["sequence"]["confidence"],

            "riskScore": risk_score,
            "riskTier": risk_tier(risk_score),

            "ipReputation": result.get("ip_reputation", "unknown"),
        
            "risk_score": risk_score,
            "risk_tier": risk_tier(risk_score),

            # ---------------- META INFO ----------------
            "model_version": MODEL_VERSION,
            "timestamp": datetime.utcnow().isoformat() + "Z"
        }

        # audit log (VERY IMPORTANT FOR BANKING)
        log_event(event_dict, result)

        return response

    except Exception as e:
        print("ERROR in /predict:", e)
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Internal APT detection error")

# ======================================================
# LOG VIEWER (SOC / AUDIT)
# ======================================================
@app.get("/logs")
def get_logs():
    if not os.path.exists(LOG_FILE):
        return {"logs": []}

    with open(LOG_FILE, "r") as f:
        logs = [json.loads(line) for line in f.readlines()]

    return {"logs": logs}

# ======================================================
# FINE-TUNE FROM LIVE BANK LOGS
# ======================================================
@app.post("/finetune_logs")
def finetune_logs(background_tasks: BackgroundTasks):
    """
    Fine-tune APT models from live logs asynchronously
    to avoid blocking live requests.
    """
    try:
        # launch finetune_worker.py as separate process
        background_tasks.add_task(
            subprocess.Popen, ["python", "finetune_worker.py"]
        )

        return {
            "status": "success",
            "message": "Fine-tuning started in background. Models will update after completion."
        }

    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=500, detail="Fine-tuning failed")

# ======================================================
# HEALTH CHECK (BANK MONITORING)
# ======================================================
@app.get("/health")
def health():
    return {
        "status": "running",
        "service": "bank-apt-gateway",
        "model_version": MODEL_VERSION
    }

# ======================================================
# RUN COMMAND
# uvicorn apt_server:app --reload --host 0.0.0.0 --port 8000