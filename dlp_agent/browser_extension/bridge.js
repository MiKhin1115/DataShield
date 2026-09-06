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

const SCAN_CHUNK_BYTES = 256 * 1024;

function bytesToBase64(bytes) {
    const stringChunkSize = 0x8000;
    let binary = "";
    for (let offset = 0; offset < bytes.length; offset += stringChunkSize) {
        binary += String.fromCharCode(...bytes.subarray(offset, offset + stringChunkSize));
    }
    return btoa(binary);
}

function sendRuntimeMessage(message) {
    return new Promise((resolve, reject) => {
        try {
            chrome.runtime.sendMessage(message, (response) => {
                const runtimeError = chrome.runtime.lastError;
                if (runtimeError) {
                    reject(new Error(runtimeError.message));
                    return;
                }
                if (!response || !response.success) {
                    reject(new Error(response && response.error
                        ? response.error
                        : "Extension service worker did not accept the request."));
                    return;
                }
                resolve(response);
            });
        } catch (error) {
            reject(error);
        }
    });
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

async function forwardScanToBackground(message) {
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
        const bytes = new Uint8Array(message.file_data);
        const totalChunks = Math.max(1, Math.ceil(bytes.byteLength / SCAN_CHUNK_BYTES));
        await sendRuntimeMessage({
            type: "SCAN_FILE_START",
            payload: {
                request_id: message.request_id,
                file_name: String(message.file_name || "unknown"),
                file_type: String(message.file_type || "application/octet-stream"),
                total_size: bytes.byteLength,
                total_chunks: totalChunks
            }
        });

        for (let index = 0; index < totalChunks; index++) {
            const start = index * SCAN_CHUNK_BYTES;
            await sendRuntimeMessage({
                type: "SCAN_FILE_CHUNK",
                payload: {
                    request_id: message.request_id,
                    index: index,
                    file_data_base64: bytesToBase64(bytes.subarray(start, start + SCAN_CHUNK_BYTES))
                }
            });
        }

        const response = await sendRuntimeMessage({
            type: "SCAN_FILE_FINISH",
            payload: { request_id: message.request_id }
        });
        returnScanResult(message.request_id, response.data);
    } catch (error) {
        console.error("DLP Bridge: Chunked deep inspection relay failed:", error);
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
