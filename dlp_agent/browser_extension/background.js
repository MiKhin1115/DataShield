// Background service worker for Antigravity Enterprise DLP Extension
// Handles network reporting to localhost dashboard without HTTPS Mixed-Content errors.

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message && message.type === "REPORT_INCIDENT") {
        fetch("http://127.0.0.1:8080/api/browser_incident", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify(message.payload)
        })
        .then(response => response.json())
        .then(data => sendResponse({ success: true, data }))
        .catch(error => {
            console.error("DLP Background Service Worker: Failed to report incident", error);
            sendResponse({ success: false, error: String(error) });
        });
        return true; // Keep message channel open for async fetch
    }
});
