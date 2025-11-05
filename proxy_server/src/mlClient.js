
//const DEFAULT_URL = "http://ml_server:7001/predict";
const DEFAULT_URL = "http://localhost:7001/predict";

const ML_SERVER_URL = process.env.ML_SERVER_URL || DEFAULT_URL;
const TIMEOUT_MS = Number(process.env.ML_TIMEOUT_MS || 1500);

async function postJSON(url, payload) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload || {}),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.json();
  } finally {
    clearTimeout(timer);
  }
}

async function predict(features) {
  const payload = features && typeof features === "object" ? features : {};
  return await postJSON(ML_SERVER_URL, payload);
}

module.exports = { predict };