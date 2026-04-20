// content_script.js — injected into every mail.google.com page.
//
// Exposes window.__postwolfMqcShowOverlay(text, kind) for the
// background worker to call via chrome.scripting.executeScript.
// No Gmail-DOM hacking; we just add a top-layer overlay when asked.

(function () {
  "use strict";

  if (window.__postwolfMqcShowOverlay) return; // already installed

  function closeOverlay() {
    const el = document.getElementById("postwolf-mqc-overlay");
    if (el) el.remove();
  }

  function showOverlay(text, kind) {
    closeOverlay();

    const wrap = document.createElement("div");
    wrap.id = "postwolf-mqc-overlay";
    wrap.className = "postwolf-mqc-overlay";

    const card = document.createElement("div");
    card.className = "postwolf-mqc-card";

    const header = document.createElement("div");
    header.className = "postwolf-mqc-header";
    header.textContent =
      kind === "encode" ? "mqc — encoded" : "mqc — decoded";

    const close = document.createElement("button");
    close.className = "postwolf-mqc-close";
    close.textContent = "×";
    close.title = "Close (Esc)";
    close.addEventListener("click", closeOverlay);

    header.appendChild(close);

    const ta = document.createElement("textarea");
    ta.className = "postwolf-mqc-text";
    ta.value = text;
    ta.readOnly = true;
    ta.rows = 10;
    // Select on focus so Ctrl-C is one keystroke away.
    ta.addEventListener("focus", () => ta.select());

    const row = document.createElement("div");
    row.className = "postwolf-mqc-row";

    const copyBtn = document.createElement("button");
    copyBtn.className = "postwolf-mqc-btn";
    copyBtn.textContent = "Copy to clipboard";
    copyBtn.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(text);
        copyBtn.textContent = "Copied ✓";
        setTimeout(() => (copyBtn.textContent = "Copy to clipboard"), 1200);
      } catch (e) {
        copyBtn.textContent = "Copy failed";
      }
    });

    const dismiss = document.createElement("button");
    dismiss.className = "postwolf-mqc-btn";
    dismiss.textContent = "Close";
    dismiss.addEventListener("click", closeOverlay);

    row.appendChild(copyBtn);
    row.appendChild(dismiss);

    card.appendChild(header);
    card.appendChild(ta);
    card.appendChild(row);
    wrap.appendChild(card);
    document.body.appendChild(wrap);

    // Esc to close.
    const escHandler = (e) => {
      if (e.key === "Escape") {
        closeOverlay();
        document.removeEventListener("keydown", escHandler);
      }
    };
    document.addEventListener("keydown", escHandler);

    // Autofocus the textarea for easy manual select-all.
    setTimeout(() => ta.focus(), 0);
  }

  window.__postwolfMqcShowOverlay = showOverlay;
})();
