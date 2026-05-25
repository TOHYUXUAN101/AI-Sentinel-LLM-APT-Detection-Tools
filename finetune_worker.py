import torch
from transformers import (
    GPT2Tokenizer,
    GPT2ForSequenceClassification,
    Trainer,
    TrainingArguments,
    DataCollatorWithPadding
)
from datasets import Dataset
import os
import json

MODEL_DIR = "./apt_model"
SEQ_MODEL_DIR = "./apt_seq_model"
LOG_FILE = "event_log.jsonl"

DEVICE = torch.device("cpu")
print("Worker using device:", DEVICE)

# ---------------- SAME LABELS ----------------
action_types = [
    "login_attempt",
    "failed_login",
    "data_read",
    "data_write",
    "data_exfiltration",
    "config_change",
    "suspicious_endpoint"
]

sequence_labels = [
    "Normal",
    "Credential_Attack",
    "Exfiltration_Attack",
    "Beaconing_Attack",
    "Suspicious_Attack"
]

label2id = {l: i for i, l in enumerate(action_types)}
seq_label2id = {l: i for i, l in enumerate(sequence_labels)}

# ---------------- FORMAT ----------------
def format_event(event):
    return (
        f"Endpoint: {event['endpoint']}, Method: {event['method']}, "
        f"PayloadSize: {event['payload_size']}, UserRole: {event['user_role']}, "
        f"Source: {event['source_path']}, Destination: {event['destination_path']}, "
        f"IP: {event['ip_address']}, "
        f"UserID: {event['user_id']}, TimeStamp: {event['time_stamp']}"
    )

# ---------------- LOAD LOGS ----------------
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

                if event and "event" in result:
                    label = result["event"].get("label")
                    if label in label2id:
                        event_texts.append(format_event(event))
                        event_labels.append(label2id[label])

                user_seq = result.get("user_sequence", [])
                seq_label = result.get("sequence", {}).get("sequence_label")

                if user_seq and seq_label in seq_label2id:
                    seq_texts.append(" [SEP] ".join(user_seq))
                    seq_labels.append(seq_label2id[seq_label])

            except:
                continue

    event_ds = Dataset.from_dict({"text": event_texts, "label": event_labels}) if event_texts else None
    seq_ds = Dataset.from_dict({"text": seq_texts, "label": seq_labels}) if seq_texts else None

    return event_ds, seq_ds

# ---------------- MAIN TRAIN ----------------
def run():
    print("Worker: loading logs...")

    event_ds, seq_ds = load_logs_dataset()

    if event_ds is None:
        print("No logs found.")
        return

    # ===== EVENT =====
    print("Worker: training EVENT model...")

    tokenizer = GPT2Tokenizer.from_pretrained(MODEL_DIR)
    tokenizer.pad_token = tokenizer.eos_token

    model = GPT2ForSequenceClassification.from_pretrained(MODEL_DIR).to(DEVICE)

    def tok(x):
        return tokenizer(x["text"], truncation=True, padding="max_length", max_length=128)

    event_ds = event_ds.map(tok, batched=True)

    trainer = Trainer(
        model=model,
        args=TrainingArguments(
            output_dir=MODEL_DIR,
            num_train_epochs=1,
            per_device_train_batch_size=1,
            report_to="none"
        ),
        train_dataset=event_ds,
        data_collator=DataCollatorWithPadding(tokenizer)
    )

    trainer.train()

    model.save_pretrained(MODEL_DIR)
    tokenizer.save_pretrained(MODEL_DIR)

    # ===== SEQUENCE =====
    if seq_ds is not None:
        print("Worker: training SEQUENCE model...")

        seq_tokenizer = GPT2Tokenizer.from_pretrained(SEQ_MODEL_DIR)
        seq_tokenizer.pad_token = seq_tokenizer.eos_token

        seq_model = GPT2ForSequenceClassification.from_pretrained(SEQ_MODEL_DIR).to(DEVICE)

        def tok2(x):
            return seq_tokenizer(x["text"], truncation=True, padding="max_length", max_length=256)

        seq_ds = seq_ds.map(tok2, batched=True)

        trainer = Trainer(
            model=seq_model,
            args=TrainingArguments(
                output_dir=SEQ_MODEL_DIR,
                num_train_epochs=1,
                per_device_train_batch_size=1,
                report_to="none"
            ),
            train_dataset=seq_ds,
            data_collator=DataCollatorWithPadding(seq_tokenizer)
        )

        trainer.train()

        seq_model.save_pretrained(SEQ_MODEL_DIR)
        seq_tokenizer.save_pretrained(SEQ_MODEL_DIR)

    print("Worker: training complete.")

if __name__ == "__main__":
    run()