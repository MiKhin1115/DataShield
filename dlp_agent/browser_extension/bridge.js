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

function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    const chunkSize = 0x8000;
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + chunkSize));
    }
    return btoa(binary);
}

function returnScanResult(requestId, result) {
    window.postMessage({
        type: "ANTIGRAVITY_DLP_SCAN_RESPONSE",
        request_id: requestId,
        result: result
    }, "*");
}

async function scanWithLocalAgent(message) {
    const response = await fetch("http://127.0.0.1:8080/api/scan_file", {
        method: "POST",
        headers: {
            "Content-Type": String(message.file_type || "application/octet-stream"),
            "X-File-Name": encodeURIComponent(String(message.file_name || "unknown"))
        },
        body: new Uint8Array(message.file_data)
    });
    let result;
    try {
        result = await response.json();
    } catch (error) {
        throw new Error("Deep inspection service returned an invalid response.");
    }
    if (!response.ok) result.blocked = true;
    return result;
}

function fallbackToLocalAgent(message, relayError) {
    scanWithLocalAgent(message)
        .then(result => returnScanResult(message.request_id, result))
        .catch(() => returnScanResult(message.request_id, {
            blocked: true,
            error: relayError
        }));
}

function forwardScanToBackground(message) {
    if (!message.request_id || !message.file_data || typeof message.file_data.byteLength !== "number") {
        if (message.request_id) {
            returnScanResult(message.request_id, {
                blocked: true,
                error: "Deep inspection received invalid file data."
            });
        }
        return;
    }
    try {
        chrome.runtime.sendMessage({
            type: "SCAN_FILE",
            payload: {
                file_name: String(message.file_name || "unknown"),
                file_type: String(message.file_type || "application/octet-stream"),
                file_data_base64: arrayBufferToBase64(message.file_data)
            }
        }, (response) => {
            if (chrome.runtime.lastError || !response || !response.success) {
                fallbackToLocalAgent(message, "Deep inspection service is unavailable.");
                return;
            }
            returnScanResult(message.request_id, response.data);
        });
    } catch (error) {
        fallbackToLocalAgent(message, "Deep inspection request could not be relayed.");
    }
}

document.addEventListener("ANTIGRAVITY_DLP_INCIDENT", (event) => {
    if (event && event.detail) {
        forwardToBackground(event.detail);
    }
});

window.addEventListener("message", (event) => {
    if (!event || event.source !== window || !event.data) return;
    if (event.data.type === "ANTIGRAVITY_DLP_INCIDENT") {
        forwardToBackground(event.data.payload);
    } else if (event.data.type === "ANTIGRAVITY_DLP_SCAN_REQUEST") {
        forwardScanToBackground(event.data);
    }
});

chrome.runtime.onMessage.addListener((message) => {
    if (!message || message.type !== "SOC_DECISION") return;
    window.postMessage({
        type: "ANTIGRAVITY_DLP_SOC_DECISION",
        action: message.action,
        file_name: message.file_name || ""
    }, "*");
});

// A visible upload page keeps the service worker awake long enough to receive
// prompt SOC decisions. The worker also performs its own best-effort polling.
setInterval(() => {
    try {
        chrome.runtime.sendMessage({ type: "POLL_BROWSER_COMMANDS" }, () => {
            void chrome.runtime.lastError;
        });
    } catch (error) {}
}, 2000);
