import random
import datetime

# ======================================================
# CONFIG
# ======================================================
user_ids = [f"user_{i}" for i in range(10)]
roles = ["user", "admin", "superuser"]

ATTACK_MODES = [
    "normal",
    "exfiltration",
    "beacon",
    "suspicious",
    "bruteforce"
]

# ======================================================
# ACTION TYPES
# ======================================================
action_types = {
    "login_attempt": ["/auth/login", "/auth/signin"],
    "failed_login": ["/auth/login"],
    "data_read": ["/user/profile", "/transactions/view"],
    "data_write": ["/user/update", "/transfer/initiate"],
    "data_exfiltration": ["/export", "/download", "/report/export"],
    "config_change": ["/settings/update", "/account/config"],
    "suspicious_endpoint": ["/admin/override", "/debug/execute"]
}

methods_map = {
    "login_attempt": "POST",
    "failed_login": "POST",
    "data_read": "GET",
    "data_write": "POST",
    "data_exfiltration": "GET",
    "config_change": "POST",
    "suspicious_endpoint": "POST"
}

# ======================================================
# IP GENERATION (IMPROVED DISTRIBUTION)
# ======================================================
def random_ip():
    r = random.random()

    if r < 0.15:
        return f"45.33.{random.randint(1,255)}.{random.randint(1,255)}"
    elif r < 0.25:
        return f"185.{random.randint(1,255)}.{random.randint(1,255)}.{random.randint(1,255)}"
    else:
        return f"192.168.{random.randint(0,255)}.{random.randint(0,255)}"

# ======================================================
# PAYLOAD SIZE (MORE REALISTIC SEPARATION)
# ======================================================
def generate_payload_size(action):
    if action in ["login_attempt", "failed_login"]:
        return random.randint(20, 400)

    if action == "data_read":
        return random.randint(100, 1500)

    if action == "data_write":
        return random.randint(500, 3000)

    if action == "data_exfiltration":
        return random.randint(3000, 25000)

    if action == "config_change":
        return random.randint(200, 2000)

    if action == "suspicious_endpoint":
        return random.randint(2000, 8000)

    return random.randint(100, 1000)

# ======================================================
# TIMESTAMP
# ======================================================
def generate_timestamp(base_time, step):
    return (base_time + datetime.timedelta(seconds=step)).isoformat()

# ======================================================
# EVENT GENERATOR
# ======================================================
def generate_event(action, user_id, base_time, step, campaign_id):
    return {
        "endpoint": random.choice(action_types[action]),
        "method": methods_map[action],
        "payload_size": generate_payload_size(action),
        "user_role": random.choice(roles),
        "ip_address": random_ip(),
        "user_id": user_id,
        "campaign_id": campaign_id,
        "time_stamp": generate_timestamp(base_time, step),
        "session_id": f"{user_id}_{campaign_id}"
    }

# ======================================================
# FORMAT EVENT (FOR EVENT MODEL)
# ======================================================
def format_event(event):
    return (
        f"Endpoint: {event['endpoint']}, "
        f"Method: {event['method']}, "
        f"PayloadSize: {event['payload_size']}, "
        f"UserRole: {event['user_role']}, "
        f"IP: {event['ip_address']}, "
        f"UserID: {event['user_id']}, "
        f"SessionID: {event['session_id']}, "
        f"TimeStamp: {event['time_stamp']}"
    )

# ======================================================
# FORMAT SEQUENCE (FOR SEQUENCE MODEL)
# ======================================================
def format_sequence(seq):
    return " [SEP] ".join([e["label"] for e in seq])

# ======================================================
# ATTACK CAMPAIGN GENERATORS (IMPROVED)
# ======================================================

def generate_normal(user_id, campaign):
    base = datetime.datetime.utcnow()
    actions = ["login_attempt", "data_read", "data_read", "data_write"]

    return [
        {"event": generate_event(a, user_id, base, i * 12, campaign), "label": a}
        for i, a in enumerate(actions)
    ]


def generate_exfiltration(user_id, campaign):
    base = datetime.datetime.utcnow()

    actions = [
        "login_attempt",
        "data_read",
        "config_change",
        "data_read",
        "data_exfiltration",
        "data_exfiltration"
    ]

    return [
        {"event": generate_event(a, user_id, base, i * 8, campaign), "label": a}
        for i, a in enumerate(actions)
    ]


def generate_beaconing(user_id, campaign):
    base = datetime.datetime.utcnow()

    seq = []
    for i in range(random.randint(6, 12)):
        seq.append({
            "event": generate_event(
                "data_read",
                user_id,
                base,
                i * random.randint(40, 90),
                campaign
            ),
            "label": "data_read"
        })

    return seq


def generate_bruteforce(user_id, campaign):
    base = datetime.datetime.utcnow()

    actions = ["failed_login"] * 6 + ["login_attempt"]

    return [
        {"event": generate_event(a, user_id, base, i * 6, campaign), "label": a}
        for i, a in enumerate(actions)
    ]


def generate_suspicious(user_id, campaign):
    base = datetime.datetime.utcnow()

    actions = [
        "login_attempt",
        "suspicious_endpoint",
        "suspicious_endpoint",
        "config_change"
    ]

    return [
        {"event": generate_event(a, user_id, base, i * 10, campaign), "label": a}
        for i, a in enumerate(actions)
    ]

# ======================================================
# DATASET GENERATION
# ======================================================
training_examples = []
sequence_training = []

num_sequences = 80

for user_id in user_ids:
    for _ in range(num_sequences):

        campaign_id = f"camp_{random.randint(1000,9999)}"

        scenario = random.choice(ATTACK_MODES)

        if scenario == "normal":
            seq = generate_normal(user_id, campaign_id)
            label = "Normal"

        elif scenario == "exfiltration":
            seq = generate_exfiltration(user_id, campaign_id)
            label = "Exfiltration_Attack"

        elif scenario == "beacon":
            seq = generate_beaconing(user_id, campaign_id)
            label = "Beaconing_Attack"

        elif scenario == "bruteforce":
            seq = generate_bruteforce(user_id, campaign_id)
            label = "Credential_Attack"

        else:
            seq = generate_suspicious(user_id, campaign_id)
            label = "Suspicious_Attack"

        # EVENT dataset
        training_examples.extend(seq)

        # SEQUENCE dataset
        sequence_training.append((format_sequence(seq), label))

# ======================================================
# WRITE EVENT DATASET
# ======================================================
with open("apt_training_large.txt", "w", encoding="utf-8") as f:
    for ex in training_examples:
        f.write(f"Input: {format_event(ex['event'])}\nOutput: {ex['label']}\n\n")

# ======================================================
# WRITE SEQUENCE DATASET
# ======================================================
with open("apt_sequence_training.txt", "w", encoding="utf-8") as f:
    for seq, label in sequence_training:
        f.write(f"{seq}||{label}\n")

print("===================================")
print(f"EVENT samples: {len(training_examples)}")
print(f"SEQUENCE samples: {len(sequence_training)}")
print("Saved datasets successfully.")
print("===================================")