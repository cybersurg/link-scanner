// ---- Context menu setup (duplicate-safe) ----
function createMenus() {
  chrome.contextMenus.create({
    id: "scan-link",
    title: "Scan link with Link Scanner",
    contexts: ["link"]
  });
  chrome.contextMenus.create({
    id: "scan-selection",
    title: "Scan selected text as URL",
    contexts: ["selection"]
  });
}

async function resetMenus() {
  try { await chrome.contextMenus.removeAll(); } catch (_) {}
  createMenus();
}

// Recreate menus on install/update and on browser start
chrome.runtime.onInstalled.addListener(() => { resetMenus(); });
chrome.runtime.onStartup.addListener(() => { resetMenus(); });

// Also do it once when the service worker wakes (covers SW restarts/hot reload)
resetMenus();


// Utility: sleep
const wait = (ms) => new Promise(r => setTimeout(r, ms));

// VT API helpers
async function getApiKey() {
  const { vtApiKey } = await chrome.storage.sync.get("vtApiKey");
  if (!vtApiKey) throw new Error("Missing VirusTotal API key. Set it in Options.");
  return vtApiKey;
}

async function vtSubmitUrl(url, apiKey) {
  const form = new FormData();
  form.append("url", url);
  const res = await fetch("https://www.virustotal.com/api/v3/urls", {
    method: "POST",
    headers: { "x-apikey": apiKey },
    body: form
  });
  if (!res.ok) throw new Error(`VT submit failed: ${res.status}`);
  const json = await res.json();
  return json.data.id; // analysis id
}

async function vtPollAnalysis(analysisId, apiKey, maxTries = 8) {
  for (let i = 0; i < maxTries; i++) {
    const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
      headers: { "x-apikey": apiKey }
    });
    if (!res.ok) throw new Error(`VT poll failed: ${res.status}`);
    const json = await res.json();
    const status = json.data.attributes.status;
    if (status === "completed") return json.data.attributes;
    await wait(1000 * (i + 1)); // simple backoff
  }
  throw new Error("VT analysis timed out.");
}

function deriveVerdict(stats) {
  const malicious = stats.malicious || 0;
  const suspicious = stats.suspicious || 0;
  if (malicious >= 1) return { verdict: "Malicious", color: "#d93025" };
  if (suspicious >= 1) return { verdict: "Suspicious", color: "#f9ab00" };
  return { verdict: "Safe", color: "#188038" };
}

async function scanUrl(url) {
  const apiKey = await getApiKey();
  // Basic sanity
  try { new URL(url); } catch {
    throw new Error("Selected text isn’t a valid URL.");
  }
  // Submit & poll VT
  const analysisId = await vtSubmitUrl(url, apiKey);
  const attrs = await vtPollAnalysis(analysisId, apiKey);
  const stats = attrs.stats || {};
  const { verdict, color } = deriveVerdict(stats);

  // Save last result for popup
  const result = {
    url,
    when: new Date().toISOString(),
    stats,
    verdict
  };
  await chrome.storage.local.set({ lastScanResult: result });

  // Set badge
  const text = verdict === "Safe" ? "OK" : verdict === "Suspicious" ? "??" : "!!";
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });

  // Optional notification
  try {
    await chrome.notifications.create({
      type: "basic",
      iconUrl: "icon128.png",
      title: `Link Scanner: ${verdict}`,
      message: `${url}\nEngines → malicious:${stats.malicious || 0}, suspicious:${stats.suspicious || 0}`
    });
  } catch (_) {}

  return result;
}

// Handle context menu clicks
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  try {
    let targetUrl = null;
    if (info.menuItemId === "scan-link" && info.linkUrl) {
      targetUrl = info.linkUrl;
    } else if (info.menuItemId === "scan-selection" && info.selectionText) {
      targetUrl = info.selectionText.trim();
    }
    if (!targetUrl) return;

    await scanUrl(targetUrl);
  } catch (err) {
    chrome.action.setBadgeText({ text: "ERR" });
    chrome.action.setBadgeBackgroundColor({ color: "#5f6368" });
    await chrome.storage.local.set({ lastScanError: err.message });
  }
});

// Expose scan to popup
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "scanNow" && msg.url) {
    scanUrl(msg.url)
      .then((r) => sendResponse({ ok: true, result: r }))
      .catch((e) => sendResponse({ ok: false, error: e.message }));
    return true; // async
  }
});
