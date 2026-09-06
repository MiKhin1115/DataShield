// Background service worker for Antigravity Enterprise DLP Extension
// Handles network reporting to localhost dashboard without HTTPS Mixed-Content errors.

let commandPollActive = false;
const pendingScanUploads = new Map();
const MAX_SCAN_BYTES = 10 * 1024 * 1024;
const MAX_SCAN_CHUNKS = 64;
const MAX_SCAN_CHUNK_BASE64 = 512 * 1024;

function decodeBase64Bytes(encoded) {
    const binary = atob(encoded || "");
    const result = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index++) {
        result[index] = binary.charCodeAt(index);
    }
    return result;
}

async function scanFileBytes(payload, fileData) {
    const response = await fetch("http://127.0.0.1:8080/api/scan_file", {
        method: "POST",
        headers: {
            "Content-Type": payload.file_type || "application/octet-stream",
            "X-File-Name": encodeURIComponent(payload.file_name || "unknown")
        },
        body: fileData
    });
    let data;
    try {
        data = await response.json();
    } catch (error) {
        data = {
            blocked: true,
            error: "Deep inspection service returned an invalid response."
        };
    }
    if (!response.ok) data.blocked = true;
    return data;
}

async function finishChunkedScan(requestId) {
    const session = pendingScanUploads.get(requestId);
    if (!session) throw new Error("Deep inspection upload session was not found.");
    try {
        if (session.chunks.some(chunk => typeof chunk !== "string")) {
            throw new Error("Deep inspection upload is incomplete.");
        }
        const decodedChunks = session.chunks.map(decodeBase64Bytes);
        const actualSize = decodedChunks.reduce((total, chunk) => total + chunk.byteLength, 0);
        if (actualSize !== session.total_size) {
            throw new Error("Deep inspection upload size did not match the source file.");
        }
        const fileData = new Uint8Array(actualSize);
        let offset = 0;
        for (const chunk of decodedChunks) {
            fileData.set(chunk, offset);
            offset += chunk.byteLength;
        }
        return await scanFileBytes(session, fileData);
    } finally {
        pendingScanUploads.delete(requestId);
    }
}

function getClientId() {
    return new Promise((resolve) => {
        chrome.storage.local.get("dlpClientId", (stored) => {
            if (stored && stored.dlpClientId) {
                resolve(stored.dlpClientId);
                return;
            }
            const clientId = crypto.randomUUID();
            chrome.storage.local.set({ dlpClientId: clientId }, () => resolve(clientId));
        });
    });
}

async function executeBrowserCommand(command) {
    const tabId = Number(command.browser_tab_id);
    const windowId = Number(command.browser_window_id);
    if (command.action === "allow") {
        if (Number.isInteger(tabId) && tabId >= 0) {
            try {
                await chrome.tabs.sendMessage(tabId, {
                    type: "SOC_DECISION",
                    action: "allow",
                    file_name: command.file_name || ""
                });
            } catch (error) {}
        }
        return;
    }
    if (command.action !== "block") return;

    // Close the browser window that originated the DLP incident. This avoids
    // terminating unrelated browser sessions or manipulating OS processes.
    if (Number.isInteger(windowId) && windowId >= 0) {
        try {
            await chrome.windows.remove(windowId);
            return;
        } catch (error) {}
    }
    if (Number.isInteger(tabId) && tabId >= 0) {
        try {
            await chrome.tabs.remove(tabId);
        } catch (error) {}
    }
}

async function pollBrowserCommands() {
    if (commandPollActive) return;
    commandPollActive = true;
    try {
        const clientId = await getClientId();
        const response = await fetch(
            "http://127.0.0.1:8080/api/browser_commands?client_id=" + encodeURIComponent(clientId),
            { cache: "no-store" }
        );
        if (!response.ok) return;
        const payload = await response.json();
        const commands = Array.isArray(payload.commands) ? payload.commands : [];
        for (const command of commands) {
            await executeBrowserCommand(command);
        }
    } catch (error) {
        // The local dashboard may not be running yet; the next poll retries.
    } finally {
        commandPollActive = false;
    }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === "REPORT_INCIDENT") {
        getClientId()
        .then((clientId) => {
            const payload = {
                ...(message.payload || {}),
                browser_client_id: clientId,
                browser_tab_id: sender.tab && Number.isInteger(sender.tab.id) ? sender.tab.id : null,
                browser_window_id: sender.tab && Number.isInteger(sender.tab.windowId) ? sender.tab.windowId : null
            };
            return fetch("http://127.0.0.1:8080/api/browser_incident", {
                method: "POST",
                headers: {
                    "Content-Type": "application/json"
                },
                body: JSON.stringify(payload)
            });
        })
        .then(response => response.json())
        .then(data => {
            sendResponse({ success: true, data });
            pollBrowserCommands();
        })
        .catch(error => {
            console.error("DLP Background Service Worker: Failed to report incident", error);
            sendResponse({ success: false, error: String(error) });
        });
        return true; // Keep message channel open for async fetch
    }

    if (message && message.type === "POLL_BROWSER_COMMANDS") {
        pollBrowserCommands().then(() => sendResponse({ success: true }));
        return true;
    }

    if (message && message.type === "SCAN_FILE_START") {
        const payload = message.payload || {};
        const requestId = String(payload.request_id || "");
        const totalSize = Number(payload.total_size);
        const totalChunks = Number(payload.total_chunks);
        if (!requestId || !Number.isInteger(totalSize) || totalSize < 0 || totalSize > MAX_SCAN_BYTES ||
            !Number.isInteger(totalChunks) || totalChunks < 1 || totalChunks > MAX_SCAN_CHUNKS) {
            sendResponse({ success: false, error: "Invalid deep inspection upload metadata." });
            return false;
        }
        pendingScanUploads.set(requestId, {
            file_name: String(payload.file_name || "unknown"),
            file_type: String(payload.file_type || "application/octet-stream"),
            total_size: totalSize,
            chunks: new Array(totalChunks),
            created_at: Date.now()
        });
        sendResponse({ success: true });
        return false;
    }

    if (message && message.type === "SCAN_FILE_CHUNK") {
        const payload = message.payload || {};
        const requestId = String(payload.request_id || "");
        const session = pendingScanUploads.get(requestId);
        const index = Number(payload.index);
        const encoded = payload.file_data_base64;
        if (!session || !Number.isInteger(index) || index < 0 || index >= session.chunks.length ||
            typeof encoded !== "string" || encoded.length > MAX_SCAN_CHUNK_BASE64) {
            sendResponse({ success: false, error: "Invalid deep inspection upload chunk." });
            return false;
        }
        session.chunks[index] = encoded;
        sendResponse({ success: true });
        return false;
    }

    if (message && message.type === "SCAN_FILE_FINISH") {
        const requestId = String((message.payload && message.payload.request_id) || "");
        finishChunkedScan(requestId)
            .then(data => sendResponse({ success: true, data }))
            .catch(error => sendResponse({ success: false, error: String(error) }));
        return true;
    }

    if (message && message.type === "SCAN_FILE") {
        try {
            const payload = message.payload || {};
            const fileData = decodeBase64Bytes(payload.file_data_base64);
            scanFileBytes(payload, fileData)
            .then(data => sendResponse({ success: true, data }))
            .catch(error => {
                sendResponse({ success: false, error: String(error) });
            });
        } catch (error) {
            sendResponse({ success: false, error: String(error) });
        }
        return true;
    }
});

pollBrowserCommands();
setInterval(pollBrowserCommands, 2000);
setInterval(() => {
    const cutoff = Date.now() - 60_000;
    for (const [requestId, session] of pendingScanUploads.entries()) {
        if (session.created_at < cutoff) pendingScanUploads.delete(requestId);
    }
}, 30_000);
