// popup.js — toolbar-action popup.
// Fires a "ping" request through the background worker → native host
// and prints the result.  Useful as a post-install liveness check.

const btn = document.getElementById("pingBtn");
const status = document.getElementById("status");

btn.addEventListener("click", async () => {
  btn.disabled = true;
  status.className = "";
  status.textContent = "pinging…";
  try {
    const resp = await chrome.runtime.sendMessage({ type: "ping" });
    if (resp && resp.ok) {
      status.className = "ok";
      status.textContent = resp.result || "(empty response)";
    } else {
      status.className = "err";
      status.textContent =
        "ERROR: " + ((resp && resp.error) || "no response") +
        "\n\nCheck:\n  1. WSL installed: wsl --status\n" +
        "  2. mqc installed in WSL: wsl mqc --help\n" +
        "  3. Native host registered: re-run install.ps1\n" +
        "  4. Host log: %LOCALAPPDATA%\\postwolf-mqc\\host.log";
    }
  } catch (e) {
    status.className = "err";
    status.textContent = "exception: " + (e.message || String(e));
  } finally {
    btn.disabled = false;
  }
});
