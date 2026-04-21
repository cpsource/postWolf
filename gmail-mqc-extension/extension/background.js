// background.js — MV3 service worker.
//
// Owns the two context-menu items (Encode / Decode) and the
// native-messaging bridge to the "com.postwolf.mqc" host (the shim
// in gmail-mqc-extension/host/).  No persistent state between calls.

const HOST = "com.postwolf.mqc";

// --- Install: register context-menu items on both "selection" ----------
// contexts (right-clicking selected text) and "editable" (right-click
// inside a compose textarea with nothing selected yet — useful, though
// selection-less operation will error out downstream).
chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.removeAll(() => {
    chrome.contextMenus.create({
      id: "mqc-encode",
      title: "Encode with mqc",
      contexts: ["selection", "editable"],
      documentUrlPatterns: ["https://mail.google.com/*"],
    });
    chrome.contextMenus.create({
      id: "mqc-decode",
      title: "Decode with mqc",
      contexts: ["selection", "editable"],
      documentUrlPatterns: ["https://mail.google.com/*"],
    });
  });
});

// --- Click handler ------------------------------------------------------
chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  const op = info.menuItemId === "mqc-encode" ? "encode" : "decode";
  const body = info.selectionText;

  if (!body || !body.trim()) {
    await notify("mqc: no selection", "Select some text first.");
    return;
  }

  let response;
  try {
    response = await sendToHost({ op, body });
  } catch (e) {
    await notify("mqc: host unreachable", String(e.message || e));
    return;
  }

  if (!response || !response.ok) {
    await notify("mqc: operation failed", (response && response.error) || "unknown error");
    return;
  }

  const result = stripTrailingNewline(response.result);

  if (op === "encode") {
    // Try to replace selection in-place (works in compose).  If the
    // selection is in a non-editable node, fall back to the overlay.
    await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [info.frameId] },
      func: replaceSelectionOrOverlay,
      args: [result, "encode"],
    });
  } else {
    // Decode: show in overlay (read-only context is the common case).
    await chrome.scripting.executeScript({
      target: { tabId: tab.id, frameIds: [info.frameId] },
      func: showOverlay,
      args: [result, "decode"],
    });
  }
});

// --- Popup message bridge (popup.js → host ping) -----------------------
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === "ping") {
    sendToHost({ op: "ping" })
      .then(sendResponse)
      .catch((e) => sendResponse({ ok: false, error: String(e.message || e) }));
    return true; // async
  }
});

// --- Native-messaging helper -------------------------------------------
function sendToHost(request) {
  return new Promise((resolve, reject) => {
    let port;
    try {
      port = chrome.runtime.connectNative(HOST);
    } catch (e) {
      reject(new Error(`connectNative(${HOST}) threw: ${e}`));
      return;
    }
    let settled = false;
    port.onMessage.addListener((msg) => {
      settled = true;
      resolve(msg);
      try { port.disconnect(); } catch {}
    });
    port.onDisconnect.addListener(() => {
      if (settled) return;
      const err = chrome.runtime.lastError;
      resolve({
        ok: false,
        error: err ? err.message : "host disconnected before replying",
      });
    });
    try {
      port.postMessage(request);
    } catch (e) {
      reject(new Error(`postMessage failed: ${e}`));
    }
  });
}

// --- Small UI utilities ------------------------------------------------
async function notify(title, message) {
  try {
    await chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/icon48.png",
      title,
      message: message.slice(0, 400),
    });
  } catch {
    // Notifications permission may be off; fall back to console.
    console.warn("[mqc]", title, message);
  }
}

function stripTrailingNewline(s) {
  return typeof s === "string" && s.endsWith("\n") ? s.slice(0, -1) : s;
}

// --- Injected into the Gmail page ---------------------------------------
// These run in the page context via chrome.scripting.executeScript, so
// they must be self-contained (no closure over background state).

function replaceSelectionOrOverlay(text, kind) {
  const sel = window.getSelection();
  if (sel && sel.rangeCount > 0) {
    const range = sel.getRangeAt(0);
    const container = range.commonAncestorContainer;
    // contenteditable ancestor test
    let editable = false;
    let n = container.nodeType === 1 ? container : container.parentElement;
    while (n) {
      if (n.isContentEditable || n.contentEditable === "true") {
        editable = true; break;
      }
      if (n.tagName === "BODY") break;
      n = n.parentElement;
    }
    if (editable) {
      range.deleteContents();
      range.insertNode(document.createTextNode(text));
      sel.removeAllRanges();
      return;
    }
  }
  // Non-editable: show in overlay instead.
  window.__postwolfMqcShowOverlay && window.__postwolfMqcShowOverlay(text, kind);
}

function showOverlay(text, kind) {
  if (window.__postwolfMqcShowOverlay) {
    window.__postwolfMqcShowOverlay(text, kind);
  } else {
    // Content script hasn't initialised yet — fallback to alert().
    window.alert(`[mqc ${kind}] ${text}`);
  }
}
