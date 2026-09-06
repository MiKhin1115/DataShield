// Background service worker for Antigravity Enterprise DLP Extension
// Handles network reporting to localhost dashboard without HTTPS Mixed-Content errors.

let commandPollActive = false;

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

    if (message && message.type === "SCAN_FILE") {
        try {
            const payload = message.payload || {};
            const binary = atob(payload.file_data_base64 || "");
            const fileData = new Uint8Array(binary.length);
            for (let index = 0; index < binary.length; index++) {
                fileData[index] = binary.charCodeAt(index);
            }

            fetch("http://127.0.0.1:8080/api/scan_file", {
                method: "POST",
                headers: {
                    "Content-Type": payload.file_type || "application/octet-stream",
                    "X-File-Name": encodeURIComponent(payload.file_name || "unknown")
                },
                body: fileData
            })
            .then(async response => {
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
                sendResponse({ success: true, data });
            })
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
