// Bridge content script (runs in ISOLATED world)
// Connects content.js (running in MAIN world) to background.js (Service Worker)

function forwardToBackground(payload) {
    if (!payload || !payload.file_name) return;
    if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({
            type: "REPORT_INCIDENT",
            payload: payload
        }, (response) => {
            if (chrome.runtime.lastError) {
                console.error("DLP Bridge: Error sending message to background script:", chrome.runtime.lastError);
            } else {
                console.log("DLP Bridge: Successfully reported incident to background service worker.", response);
            }
        });
    }
}

document.addEventListener("ANTIGRAVITY_DLP_INCIDENT", (event) => {
    if (event && event.detail) {
        forwardToBackground(event.detail);
    }
});

window.addEventListener("message", (event) => {
    if (event && event.data && event.data.type === "ANTIGRAVITY_DLP_INCIDENT") {
        forwardToBackground(event.data.payload);
    }
});
