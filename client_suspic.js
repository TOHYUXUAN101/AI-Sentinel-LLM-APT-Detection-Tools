import fetch from "node-fetch";

// ---------- CONFIG ----------
const API_BASE = "http://127.0.0.1:8000";
let newEventsCount = 0;
let firstfewdemo = 1;
const FINE_TUNE_THRESHOLD = 15;

// ---------- USERS ----------
const users = Array.from({ length: 10 }, (_, i) => `user_${i}`);

// ---------- ATTACK ENDPOINTS ----------
const attack_endpoints = [
  "/auth/login",
  "/user/export",
  "/transactions/export",
  "/admin/override",
  "/server/config",
  "/client/device"
];

// ---------- NORMAL ENDPOINTS ----------
const normal_endpoints = [
  "/dashboard",
  "/home",
  "/user/profile",
  "/products/list",
  "/search",
  "/notifications",
  "/health"
];

// ---------- METHODS ----------
const methods = ["GET", "POST", "PUT", "DELETE"];

// ---------- FILE PATHS ----------
const source_paths = [
  "/user/data/profile.csv",
  "/user/data/report.csv",
  "/client/device",
  "/admin/console"
];

const destination_paths = [
  "/external/storage/",
  "/user/database/profile",
  "/server/config"
];

// ---------- HELPERS ----------
function randomIp() {
  return Array.from({ length: 4 }, () =>
    Math.floor(Math.random() * 256)
  ).join(".");
}

function randomPayload() {
  return Math.floor(Math.random() * (5000 - 200 + 1)) + 200;
}

function formatMYT(date) {
  const MYT_OFFSET = 8 * 60 * 60 * 1000;
  const myt = new Date(date.getTime() + MYT_OFFSET);

  const pad = (n) => n.toString().padStart(2, "0");

  return `${myt.getUTCFullYear()}-${pad(myt.getUTCMonth() + 1)}-${pad(
    myt.getUTCDate()
  )} ${pad(myt.getUTCHours())}:${pad(myt.getUTCMinutes())}:${pad(
    myt.getUTCSeconds()
  )}`;
}

// ---------- SEND EVENT ----------
async function sendEvent(event) {
  try {
    const res = await fetch(`${API_BASE}/predicts`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event)
    });

    const data = await res.json();

    console.log("\n==============================");
    console.log("👤 User:", event.user_id);
    console.log("➡ Endpoint:", event.endpoint);
    console.log("🏷 Label:", event.label);
    console.log("🧠 Event Prediction:", data.eventPrediction);
    console.log("📊 Event Confidence:", data.eventConfidence);
    console.log("🔁 Sequence Alert:", data.sequenceAlert);
    console.log("📊 Sequence Confidence:", data.sequenceConfidence);
    console.log("📈 Risk Score:", data.riskScore);
    console.log("🚨 Risk Tier:", data.riskTier);
    console.log("🌐 IP Reputation:", data.ipReputation);

    console.log("==============================\n");

    // OPTIONAL: fine-tune only for new 20 traffic
    newEventsCount++;
    console.log(newEventsCount);
    if(firstfewdemo <= 2){
      if (newEventsCount >= FINE_TUNE_THRESHOLD) {
        console.log(`📌 ${newEventsCount} new events → triggering fine-tune...`);
        await fetch(`${API_BASE}/finetune_logs`, { method: "POST" });
        newEventsCount = 0; // reset
        firstfewdemo++
      }
    }
  } catch (err) {
    console.error("❌ Error:", err.message);
  }
}

const startTime = new Date(); // use real current time as base
let runCount = 0;   

// ---------- SIMULATION LOOP ----------
setInterval(() => {
  runCount++;

  // increment 1 hour per event from current real time
  const simulatedTime = new Date(startTime.getTime() + runCount * 60 * 60 * 1000);
  const user = users[Math.floor(Math.random() * users.length)];

  // 🔥 REALISTIC TRAFFIC MIX
  const is_attack = Math.random() < 0.3; // 30% attack, 70% normal

  const endpoint = is_attack
    ? attack_endpoints[Math.floor(Math.random() * attack_endpoints.length)]
    : normal_endpoints[Math.floor(Math.random() * normal_endpoints.length)];

  const event = {
    user_id: user,

    endpoint,
    method: methods[Math.floor(Math.random() * methods.length)],
    payload_size: randomPayload(),

    // user roles (cleaned up)
    user_role:
      user.endsWith("0") || user.endsWith("1")
        ? "admin"
        : user.endsWith("2")
        ? "superuser"
        : "user",

    source_path: source_paths[Math.floor(Math.random() * source_paths.length)],
    destination_path: destination_paths[Math.floor(Math.random() * destination_paths.length)],

    ip_address: randomIp(),
    time_stamp: formatMYT(simulatedTime),

    // REALISTIC LABELS
    label: is_attack
      ? Math.random() < 0.5
        ? "data_exfiltration"
        : Math.random() < 0.5
        ? "credential_attack"
        : "privilege_escalation"
      : "normal"
  };

  sendEvent(event);

}, 3000);