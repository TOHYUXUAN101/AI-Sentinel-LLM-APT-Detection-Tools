import os
import csv
import json
import torch
import subprocess
from collections import defaultdict, deque

from transformers import (
    GPT2Tokenizer,
    GPT2ForSequenceClassification,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding
)
from datasets import Dataset

# ---------------- CONFIG ----------------
MODEL_DIR = "./apt_model"
SEQ_MODEL_DIR = "./apt_seq_model"
TRAIN_FILE = "apt_training_large.txt"
SEQ_TRAIN_FILE = "apt_sequence_training.txt"
CSV_FILE = "apt_events.csv"
LOG_FILE = "event_log.jsonl"

DEVICE = torch.device("cuda")
print("Using device:", DEVICE)

MODEL_VERSION = "APT-LMM-v3.0"

# ---------------- LABELS ----------------
action_types = [
    "login_attempt",
    "failed_login",
    "data_read",
    "data_write",
    "data_exfiltration",
    "config_change",
    "suspicious_endpoint"
]

label2id = {l: i for i, l in enumerate(action_types)}
id2label = {i: l for l, i in label2id.items()}

sequence_labels = [
    "Normal",
    "Credential_Attack",
    "Exfiltration_Attack",
    "Beaconing_Attack",
    "Suspicious_Attack"
]

seq_label2id = {l: i for i, l in enumerate(sequence_labels)}
seq_id2label = {i: l for l, i in seq_label2id.items()}

# ---------------- MEMORY ----------------
user_sequences = defaultdict(lambda: deque(maxlen=10))

# ======================================================
# IP REPUTATION
# ======================================================
def get_ip_reputation(ip):
    if ip.startswith(("10.", "192.168.", "172.","13.")):
        return "trusted"
    if ip.startswith(("45.", "185.", "91.", "103.", "250.")):
        return "suspicious"
    if ip.startswith(("123.", "77.", "80.")):
        return "malicious"
    return "normal"

# ======================================================
# FORMAT EVENT
# ======================================================
def format_event(event):
    return (
        f"Endpoint: {event['endpoint']}, Method: {event['method']}, "
        f"PayloadSize: {event['payload_size']}, UserRole: {event['user_role']}, "
        f"Source: {event['source_path']}, Destination: {event['destination_path']}, "
        f"IP: {event['ip_address']}, IPReputation: {event.get('ip_reputation','unknown')}, "
        f"UserID: {event['user_id']}, TimeStamp: {event['time_stamp']}"
    )

# ======================================================
# LOAD EVENT DATA (STATIC)
# ======================================================
def load_dataset():
    if not os.path.exists(TRAIN_FILE):
        return None

    texts, labels = [], []

    with open(TRAIN_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line.startswith("Input:"):
                current = line.replace("Input:", "").strip()

            elif line.startswith("Output:"):
                label = line.replace("Output:", "").strip()

                if label in label2id:
                    texts.append(current)
                    labels.append(label2id[label])

    if len(texts) == 0:
        return None

    return Dataset.from_dict({"text": texts, "label": labels})

# ======================================================
# LOAD SEQUENCE DATA (STATIC)
# ======================================================
def load_sequence_dataset():
    if not os.path.exists(SEQ_TRAIN_FILE):
        return None

    texts, labels = [], []

    with open(SEQ_TRAIN_FILE, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if "||" not in line:
                continue

            seq, label = line.split("||")

            if label in seq_label2id:
                texts.append(seq)
                labels.append(seq_label2id[label])

    if len(texts) == 0:
        return None

    return Dataset.from_dict({"text": texts, "label": labels})

# ======================================================
# LOAD LOGS DATASET (SAFE)
# ======================================================
def load_logs_dataset():
    if not os.path.exists(LOG_FILE):
        return None, None

    event_texts, event_labels = [], []
    seq_texts, seq_labels = [], []

    with open(LOG_FILE, "r", encoding="utf-8") as f:
        for line in f:
            try:
                data = json.loads(line)

                event = data.get("event", {})
                result = data.get("result", {})

                # ---------------- EVENT ----------------
                if event and "event" in result:
                    event_text = format_event(event)
                    event_label = result["event"].get("label")

                    if event_label in label2id:
                        event_texts.append(event_text)
                        event_labels.append(label2id[event_label])

                # ---------------- SEQUENCE ----------------
                user_seq = result.get("user_sequence", [])
                seq_label = result.get("sequence", {}).get("sequence_label")

                if len(user_seq) > 0 and seq_label in seq_label2id:
                    seq_texts.append(" [SEP] ".join(user_seq))
                    seq_labels.append(seq_label2id[seq_label])

            except:
                continue

    event_ds = None
    seq_ds = None

    if len(event_texts) > 0:
        event_ds = Dataset.from_dict({"text": event_texts, "label": event_labels})

    if len(seq_texts) > 0:
        seq_ds = Dataset.from_dict({"text": seq_texts, "label": seq_labels})

    return event_ds, seq_ds

# ======================================================
# TRAIN EVENT MODEL
# ======================================================
def train_model():
    dataset = load_dataset()
    if dataset is None:
        print("No event training data.")
        return

    tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
    tokenizer.pad_token = tokenizer.eos_token

    model = GPT2ForSequenceClassification.from_pretrained(
        "gpt2",
        num_labels=len(action_types),
        pad_token_id=tokenizer.eos_token_id
    )

    def tokenize(x):
        return tokenizer(x["text"], truncation=True, padding="max_length", max_length=128)

    dataset = dataset.map(tokenize, batched=True)

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=MODEL_DIR,
            num_train_epochs=3,
            per_device_train_batch_size=4,
            logging_steps=10,
            save_strategy="epoch",
            report_to="none"
        ),
        train_dataset=dataset,
        data_collator=DataCollatorWithPadding(tokenizer)
    )

    print("Training EVENT model...")
    trainer.train()
    trainer.save_model(MODEL_DIR)
    tokenizer.save_pretrained(MODEL_DIR)

# ======================================================
# TRAIN SEQUENCE MODEL
# ======================================================
def train_sequence_model():
    dataset = load_sequence_dataset()
    if dataset is None:
        print("No sequence training data.")
        return

    tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
    tokenizer.pad_token = tokenizer.eos_token

    model = GPT2ForSequenceClassification.from_pretrained(
        "gpt2",
        num_labels=len(sequence_labels),
        pad_token_id=tokenizer.eos_token_id
    )

    def tokenize(x):
        return tokenizer(x["text"], truncation=True, padding="max_length", max_length=256)

    dataset = dataset.map(tokenize, batched=True)

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=SEQ_MODEL_DIR,
            num_train_epochs=3,
            per_device_train_batch_size=4,
            logging_steps=10,
            save_strategy="epoch",
            report_to="none"
        ),
        train_dataset=dataset,
        data_collator=DataCollatorWithPadding(tokenizer)
    )

    print("Training SEQUENCE model...")
    trainer.train()
    trainer.save_model(SEQ_MODEL_DIR)
    tokenizer.save_pretrained(SEQ_MODEL_DIR)

# ======================================================
# LOAD MODELS
# ======================================================
def load_models():
    event_tokenizer = GPT2Tokenizer.from_pretrained(MODEL_DIR)
    event_model = GPT2ForSequenceClassification.from_pretrained(MODEL_DIR).to(DEVICE)

    seq_tokenizer = GPT2Tokenizer.from_pretrained(SEQ_MODEL_DIR)
    seq_model = GPT2ForSequenceClassification.from_pretrained(SEQ_MODEL_DIR).to(DEVICE)

    return event_model, event_tokenizer, seq_model, seq_tokenizer

# ======================================================
# PREDICT EVENT
# ======================================================
def predict_event(model, tokenizer, event):
    event["ip_reputation"] = get_ip_reputation(event["ip_address"])
    print("DEBUG IP REP:", event.get("ip_reputation"))
    text = format_event(event)

    inputs = tokenizer(text, return_tensors="pt", truncation=True, padding=True).to(DEVICE)

    with torch.no_grad():
        logits = model(**inputs).logits
        probs = torch.softmax(logits, dim=-1)[0]

    confidence, idx = torch.max(probs, dim=-1)

    return {
        "label": action_types[idx.item()],
        "confidence": confidence.item(),
    }

# ======================================================
# PREDICT SEQUENCE
# ======================================================
def predict_sequence(seq_model, seq_tokenizer, user_id):
    seq_text = " [SEP] ".join(user_sequences[user_id])

    inputs = seq_tokenizer(seq_text, return_tensors="pt", truncation=True, padding=True).to(DEVICE)

    with torch.no_grad():
        logits = seq_model(**inputs).logits
        probs = torch.softmax(logits, dim=-1)[0]

    conf, idx = torch.max(probs, dim=-1)

    return {
        "sequence_label": sequence_labels[idx.item()],
        "confidence": conf.item()
    }

# ======================================================
# RISK SCORE
# ======================================================
def compute_risk(event_pred, seq_pred):
    base = event_pred["confidence"] * 50

    if seq_pred["sequence_label"] == "Credential_Attack":
        base += 30
    elif seq_pred["sequence_label"] == "Exfiltration_Attack":
        base += 40
    elif seq_pred["sequence_label"] == "Beaconing_Attack":
        base += 35
    elif seq_pred["sequence_label"] == "Suspicious_Attack":
        base += 20

    return min(100, round(base, 2))

# ======================================================
# LOGGING
# ======================================================
def log_event(event, event_pred, seq_pred, risk):
    file_exists = os.path.exists(CSV_FILE)

    with open(CSV_FILE, "a", newline="") as f:
        writer = csv.writer(f)

        if not file_exists:
            writer.writerow([
                "timestamp", "user_id", "endpoint", "ip",
                "event_label", "event_confidence",
                "sequence_label", "sequence_confidence",
                "risk_score", "model_version"
            ])

        writer.writerow([
            event["time_stamp"],
            event["user_id"],
            event["endpoint"],
            event["ip_address"],
            event_pred["label"],
            event_pred["confidence"],
            seq_pred["sequence_label"],
            seq_pred["confidence"],
            risk,
            MODEL_VERSION
        ])

# ======================================================
# PIPELINE
# ======================================================
def predict(event, event_model, event_tokenizer, seq_model, seq_tokenizer):
    
    event["ip_reputation"] = get_ip_reputation(event["ip_address"])

    event_pred = predict_event(event_model, event_tokenizer, event)

    user_sequences[event["user_id"]].append(event_pred["label"])

    seq_pred = predict_sequence(seq_model, seq_tokenizer, event["user_id"])

    risk = compute_risk(event_pred, seq_pred)

    log_event(event, event_pred, seq_pred, risk)

    return {
        "event": event_pred,
        "sequence": seq_pred,
        "risk_score": risk,
        "ip_reputation": event["ip_reputation"]
    }

# ======================================================
# RUN
# ======================================================
if __name__ == "__main__":
    train_model()
    train_sequence_model()