const keyEl = document.getElementById("key");
const statusEl = document.getElementById("status");

(async () => {
  const { vtApiKey } = await chrome.storage.sync.get("vtApiKey");
  if (vtApiKey) keyEl.value = vtApiKey;
})();

document.getElementById("save").onclick = async () => {
  const vtApiKey = keyEl.value.trim();
  await chrome.storage.sync.set({ vtApiKey });
  statusEl.textContent = "Saved.";
  setTimeout(() => statusEl.textContent = "", 1500);
};
