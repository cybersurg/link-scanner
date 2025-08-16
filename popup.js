const urlInput = document.getElementById("url");
const out = document.getElementById("out");

function verdictClass(verdict) {
  if (verdict === "Malicious") return "malicious";
  if (verdict === "Suspicious") return "suspicious";
  return "safe";
}

function pct(n, total) {
  if (!total) return 0;
  return Math.round((n / total) * 100);
}

function renderResult(r) {
  const s = r.stats || {};
  const malicious = s.malicious || 0;
  const suspicious = s.suspicious || 0;
  const harmless  = s.harmless  || 0;
  const undetected = s.undetected || 0;
  const total = malicious + suspicious + harmless + undetected;

  const vc = verdictClass(r.verdict);

  out.innerHTML = `
    <div class="row">
      <span class="chip ${vc}">Verdict: ${r.verdict}</span>
      <span class="muted" style="margin-left:8px;">${r.source ? r.source : ""}</span>
    </div>
    <div class="row">URL: <code title="${r.url}">${r.url}</code></div>
    <div class="row bars">
      <div class="bar">
        <div class="label">Malicious</div>
        <div class="track"><div class="fill malicious" style="width:${pct(malicious, total)}%"></div></div>
        <div>${malicious}</div>
      </div>
      <div class="bar">
        <div class="label">Suspicious</div>
        <div class="track"><div class="fill suspicious" style="width:${pct(suspicious, total)}%"></div></div>
        <div>${suspicious}</div>
      </div>
      <div class="bar">
        <div class="label">Harmless</div>
        <div class="track"><div class="fill harmless" style="width:${pct(harmless, total)}%"></div></div>
        <div>${harmless}</div>
      </div>
    </div>
    <div class="row muted">${new Date(r.when).toLocaleString()}</div>
    <div class="row">
      <a id="openVT" class="link" href="#" title="Open full VirusTotal report">Open full VirusTotal report</a>
    </div>
  `;

  // Build VT URL report link (from b64url of normalized URL)
  try {
    const id = b64url(r.url);
    const a = document.getElementById("openVT");
    a.href = "https://www.virustotal.com/gui/url/" + id;
    a.target = "_blank";
  } catch (_) {}
}

// Base64url for the VT GUI link (same transform VT uses)
function b64url(str) {
  return btoa(str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/,"");
}

async function doScan() {
  const url = urlInput.value.trim();
  if (!url) { out.textContent = "Enter a URL."; return; }
  out.textContent = "Scanning…";
  try {
    const res = await chrome.runtime.sendMessage({ type: "scanNow", url });
    if (!res?.ok) throw new Error(res?.error || "Unknown error");
    renderResult(res.result);
  } catch (e) {
    const msg = String(e.message || e);
    const hint = msg.includes("Receiving end does not exist")
      ? "Background worker was asleep or crashed. Reload the extension."
      : "If this persists, you may be rate-limited or offline.";
    out.innerHTML = `<b>Error:</b> ${msg}<br><span class="muted">${hint}</span>`;
  }
}

document.getElementById("scan").onclick = doScan;

document.getElementById("openOptions").onclick = () => chrome.runtime.openOptionsPage();

// Load last result or error on open
(async () => {
  const { lastScanResult, lastScanError } = await chrome.storage.local.get(["lastScanResult","lastScanError"]);
  if (lastScanError) out.textContent = "Last error: " + lastScanError;
  if (lastScanResult) {
    urlInput.value = lastScanResult.url;
    renderResult(lastScanResult);
  }
})();
