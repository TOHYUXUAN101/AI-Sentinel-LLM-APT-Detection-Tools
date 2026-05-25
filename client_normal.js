import fetch from "node-fetch";

// ---------- Randomization options ----------
const endpoints = [
  "/auth/login",
  "/user/profile",
  "/user/update",
  "/transactions/update"
];

const methods = ["GET", "POST", "PUT"];
const user_roles = ["user"];
const source_paths = [
  "/user/data/profile.csv",
  "/user/data/report.csv",
  "/client/device"
];
const destination_paths = [
  "/user/database/profile",
  "/user/config",
  "/server/config"
];

// ---------- Random generators ----------
function randomIp() {
  return `${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}.${Math.floor(Math.random() * 256)}`;
}

function randomPayload(min = 128, max = 2000) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

// ---------- Logical pseudo-label generator ----------
function generateLabelFlexible(probNormal = 0.5, probSuspicious = 0.4) {
  const actions = [
    "login_attempt",
    "data_read",
    "data_write",
    "data_exfiltration",
    "config_change"
  ];

  const rand = Math.random();
  if (rand < probSuspicious) {
    return "suspicious_endpoint"; // mark suspicious event
  } else if (rand < probSuspicious + probNormal) {
    // pick a normal action randomly
    return actions[Math.floor(Math.random() * actions.length)];
  } else {
    return null; // unlabeled / ignored event
  }
}

// ---------- Send event to FastAPI ----------
async function handleApiEvent(event) {
  try {
    console.log("Sending event:", JSON.stringify(event, null, 2));
    const response = await fetch("http://127.0.0.1:8000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(event)
    });
    const data = await response.json();
    //console.log("Full response:", data);
    //console.log("Normal Event sent:", event.endpoint, "Predicted:", data.action_type);

    // Pick the action with the highest probability
    const predictions = data.action_type;
    let maxAction = null;
    let maxScore = -Infinity;
    for (const [action, score] of Object.entries(predictions)) {
      if (score > maxScore) {
        maxScore = score;
        maxAction = action;
      }
    }

    console.log("Normal Event sent:", event.endpoint);
    console.log("Most likely action:", maxAction, "with score:", maxScore.toFixed(6));

    // Optional: auto fine-tune if the event has a label
    if (event.label) {
      await fetch("http://127.0.0.1:8000/finetune_logs?epochs=1", {
        method: "POST",
        headers: { "Content-Type": "application/json" }
      });
      console.log("Fine-tune triggered for new labeled event.");
    }

  } catch (err) {
    console.error("Error sending event:", err);
  }
}

// ---------- Simulate non-suspicious events every 5 sec ----------
setInterval(() => {
  const newEvent = {
    endpoint: endpoints[Math.floor(Math.random() * endpoints.length)],
    method: methods[Math.floor(Math.random() * methods.length)] || "GET",
    payload_size: randomPayload(),
    user_role: user_roles[0] || "user",
    source_path: source_paths[Math.floor(Math.random() * source_paths.length)] || "N/A",
    destination_path: destination_paths[Math.floor(Math.random() * destination_paths.length)] || "N/A",
    ip_address: randomIp() || "0.0.0.0",
    time_stamp: new Date().toISOString(),
    label: null
  };

  // Assign pseudo-label logically
  newEvent.label = generateLabelFlexible(0.5, 0.4);
  
  handleApiEvent(newEvent);
}, 5000);