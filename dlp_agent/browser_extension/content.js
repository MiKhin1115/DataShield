(function() {
    const recentlyReported = new Map();

    function reportToDashboard(url, fileName, sampleText = "", scanResult = null, action = "Blocked by Enterprise Browser Extension") {
        const now = Date.now();
        if (recentlyReported.has(fileName) && (now - recentlyReported.get(fileName)) < 3000) {
            console.log("DLP Extension: Skipping duplicate report for", fileName);
            return;
        }
        recentlyReported.set(fileName, now);
        const blocked = Boolean((scanResult && scanResult.blocked) || action.toLowerCase().startsWith("blocked"));
        console.log("DLP Extension: Reporting upload decision to dashboard:", fileName, url, blocked ? "blocked" : "allowed");
        const payload = {
            url: url,
            file_name: fileName,
            sample_text: sampleText,
            action: action,
            blocked: blocked,
            sensitive_findings: scanResult && Array.isArray(scanResult.findings) ? scanResult.findings : [],
            classification: scanResult && scanResult.classification ? scanResult.classification : "",
            risk_score: scanResult && Number.isFinite(Number(scanResult.risk_score)) ? Number(scanResult.risk_score) : null,
            scan_error: scanResult && scanResult.error ? scanResult.error : ""
        };
        // The isolated bridge forwards this report with the originating tab and
        // window identity so a later SOC decision can be enforced in-browser.
        try {
            window.postMessage({
                type: "ANTIGRAVITY_DLP_INCIDENT",
                payload: payload
            }, "*");
        } catch (e) {
            console.error("DLP Extension: Failed postMessage bridge", e);
        }
    }

    function blockAndAlert(url, fileName, sampleText = "", scanResult = null) {
        console.error("DLP BLOCK: Attempted to exfiltrate sensitive data to " + url);
        reportToDashboard(url, fileName, sampleText, scanResult);
        const message = scanResult && scanResult.error
            ? "Upload of '" + fileName + "' was blocked because DLP inspection could not complete safely.\n\n" + scanResult.error
            : "Upload of sensitive file '" + fileName + "' blocked automatically by Enterprise Policy!";
        setTimeout(() => {
            alert("ANTIGRAVITY DLP WARNING:\\n\\n" + message);
        }, 100);
    }

    // 1. Hook Fetch API
    window.dlpActiveScans = 0;
    async function waitForScan() {
        while (window.dlpActiveScans > 0) {
            await new Promise(r => setTimeout(r, 50));
        }
    }

    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        let url = args[0] ? args[0].toString() : "";
        let options = args[1];

        if (!url.includes("127.0.0.1:8080")) {
            await waitForScan();
        }

        if (options && options.body && url !== "http://127.0.0.1:8080/api/browser_incident") {
            let fileObj = null;

            if (options.body instanceof FormData) {
                try {
                    for (let [key, value] of options.body.entries()) {
                        if (value instanceof File || value instanceof Blob) {
                            fileObj = value;
                        }
                    }
                } catch(e) {}
            } else if (options.body instanceof File || options.body instanceof Blob) {
                fileObj = options.body;
            }
            
            if (fileObj) {
                const scanResult = await scanFileBackend(fileObj);
                if (scanResult && scanResult.blocked) {
                    blockAndAlert(url, fileObj.name || "chunk.bin", "", scanResult);
                    return Promise.reject(new Error("ERR_BLOCKED_BY_ENTERPRISE_DLP"));
                }
                reportToDashboard(
                    url,
                    fileObj.name || "chunk.bin",
                    "",
                    scanResult,
                    "Allowed by Enterprise Browser Extension"
                );
            }
        }
        if (url !== "http://127.0.0.1:8080/api/browser_incident" && (url.includes("upload") || url.includes("resumable") || url.includes("googleapis.com"))) {
            if (window.lastBlockedFile) {
                console.error("DLP BLOCK: Blocking resumable fetch upload for " + window.lastBlockedFile);
                return Promise.reject(new Error("ERR_BLOCKED_BY_ENTERPRISE_DLP"));
            }
        }
        return originalFetch.apply(this, args);
    };

    // 2. Hook XMLHttpRequest
    const originalXHRSend = XMLHttpRequest.prototype.send;

    function requestBodyContainsFile(body) {
        if (body instanceof File || body instanceof Blob) return true;
        if (!(body instanceof FormData)) return false;
        try {
            for (const value of body.values()) {
                if (value instanceof File || value instanceof Blob) return true;
            }
        } catch (error) {}
        return false;
    }

    XMLHttpRequest.prototype.send = function(body) {
        const url = this._url || window.location.href;
        const xhrInstance = this;

        if (!url.includes("127.0.0.1:8080") && window.dlpActiveScans > 0) {
            waitForScan().then(() => {
                if (window.lastBlockedFile && requestBodyContainsFile(body)) {
                    try { xhrInstance.abort(); } catch(e) {}
                    return;
                }
                originalXHRSend.apply(xhrInstance, [body]);
            });
            return;
        }

        if (body && !url.includes("127.0.0.1:8080")) {
            let fileObj = null;

            if (body instanceof FormData) {
                try {
                    for (let [key, value] of body.entries()) {
                        if (value instanceof File || value instanceof Blob) {
                            fileObj = value;
                        }
                    }
                } catch(e) {}
            } else if (body instanceof File || body instanceof Blob) {
                fileObj = body;
            }
            
            if (fileObj) {
                const xhrInstance = this;
                scanFileBackend(fileObj).then(scanResult => {
                    if (scanResult && scanResult.blocked) {
                        try { xhrInstance.abort(); } catch(e) {}
                        window.lastBlockedFile = fileObj.name || "chunk.bin";
                        blockAndAlert(url, fileObj.name || "chunk.bin", "", scanResult);
                    } else {
                        reportToDashboard(
                            url,
                            fileObj.name || "chunk.bin",
                            "",
                            scanResult,
                            "Allowed by Enterprise Browser Extension"
                        );
                        originalXHRSend.apply(xhrInstance, [body]);
                    }
                });
                return; // DEFER SEND UNTIL SCAN COMPLETES!
            }
        }

        if (!url.includes("127.0.0.1:8080") && (url.includes("upload") || url.includes("resumable") || url.includes("googleapis.com"))) {
            if (window.lastBlockedFile) {
                console.error("DLP BLOCK: Blocking resumable XHR upload for " + window.lastBlockedFile);
                throw new Error("ERR_BLOCKED_BY_ENTERPRISE_DLP");
            }
        }
        return originalXHRSend.apply(this, arguments);
    };

    // Keep track of url for XHR
    const originalXHROpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
        this._url = url;
        return originalXHROpen.apply(this, arguments);
    };

    // Deep scans are relayed through the extension service worker. Google Drive's
    // page security policy can block page-origin requests to localhost.
    const pendingDeepScans = new Map();
    window.addEventListener("message", (event) => {
        const message = event && event.data;
        if (!message) return;
        if (message.type === "ANTIGRAVITY_DLP_SOC_DECISION") {
            if (message.action === "allow") {
                window.lastBlockedFile = null;
                window.lastBlockedTime = 0;
            }
            return;
        }
        if (message.type !== "ANTIGRAVITY_DLP_SCAN_RESPONSE") return;
        const pending = pendingDeepScans.get(message.request_id);
        if (!pending) return;
        clearTimeout(pending.timer);
        pendingDeepScans.delete(message.request_id);
        pending.resolve(message.result || {
            blocked: true,
            error: "Deep inspection returned no result."
        });
    });

    async function scanFileThroughBridge(file) {
        if (!file) return { blocked: true, error: "No file was available for inspection." };
        if (file.size > 10 * 1024 * 1024) {
            return { blocked: true, error: "File is too large to inspect safely." };
        }
        try {
            const fileData = await file.arrayBuffer();
            const requestId = `${Date.now()}-${Math.random().toString(16).slice(2)}`;
            return await new Promise((resolve) => {
                const timer = setTimeout(() => {
                    pendingDeepScans.delete(requestId);
                    resolve({
                        blocked: true,
                        error: "Deep inspection service timed out."
                    });
                }, 5000);
                pendingDeepScans.set(requestId, { resolve, timer });
                window.postMessage({
                    type: "ANTIGRAVITY_DLP_SCAN_REQUEST",
                    request_id: requestId,
                    file_name: file.name || "unknown",
                    file_type: file.type || "application/octet-stream",
                    file_data: fileData
                }, "*");
            });
        } catch (e) {
            return { blocked: true, error: "Deep inspection service is unavailable." };
        }
    }

    async function scanFileDirect(file) {
        const response = await originalFetch("http://127.0.0.1:8080/api/scan_file", {
            method: "POST",
            headers: {
                "Content-Type": file.type || "application/octet-stream",
                "X-File-Name": encodeURIComponent(file.name || "unknown")
            },
            body: file
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

    async function scanFileBackend(file) {
        if (!file) return { blocked: true, error: "No file was available for inspection." };
        // An empty file has no content to exfiltrate. Avoid turning a stale or
        // unavailable extension relay into a false sensitive-data detection.
        if (file.size === 0) {
            return {
                blocked: false,
                findings: [],
                finding_count: 0,
                classification: "Public",
                risk_score: 0,
                error: null
            };
        }
        if (file.size > 10 * 1024 * 1024) {
            return { blocked: true, error: "File is too large to inspect safely." };
        }
        try {
            // Normal HTTP upload pages can call the local agent directly. This
            // remains functional if an extension reload invalidated an old tab.
            if (window.location.protocol === "http:") {
                try {
                    return await scanFileDirect(file);
                } catch (error) {
                    // Continue through the privileged extension bridge.
                }
            }

            const bridgedResult = await scanFileThroughBridge(file);
            if (!bridgedResult.error) return bridgedResult;

            // CORS/PNA-enabled pages get one final direct fallback when the
            // extension bridge is unavailable.
            try {
                return await scanFileDirect(file);
            } catch (error) {
                return bridgedResult;
            }
        } catch (error) {
            return { blocked: true, error: "Deep inspection service is unavailable." };
        }
    }

    // 3. Hook standard HTML Forms & File Input selection (Deep Content Inspection)
    document.addEventListener("change", async function(e) {
        if (e.target && e.target.type === "file" && e.target.files && e.target.files.length > 0) {
            const file = e.target.files[0];
            const uploadTarget = (e.target.form && e.target.form.action) || window.location.href;
            window.lastUploadCandidate = file.name;
            // Start the gate synchronously, before the page can begin its upload.
            window.dlpActiveScans++;

            // The local agent is the single source of truth. ZIP files must be
            // decompressed, not interpreted as raw text in the page.
            scanFileBackend(file).then(scanResult => {
                if (scanResult && scanResult.blocked) {
                    try {
                        e.target.value = "";
                    } catch(err) {}
                    window.lastBlockedFile = file.name;
                    window.lastBlockedTime = Date.now();
                    blockAndAlert(uploadTarget, file.name, "", scanResult);
                } else {
                    window.lastBlockedFile = null;
                    reportToDashboard(
                        uploadTarget,
                        file.name,
                        "",
                        scanResult,
                        "Allowed by Enterprise Browser Extension"
                    );
                }
            }).finally(() => {
                window.dlpActiveScans--;
            });
        }
    }, true);

    // 4. Hook Drag & Drop to capture the FULL file before web apps slice it into chunks
    document.addEventListener("drop", async function(e) {
        if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
            const file = e.dataTransfer.files[0];
            window.lastUploadCandidate = file.name;
            window.dlpActiveScans++;

            // Agent handoff scans the complete file before the web app slices it.
            scanFileBackend(file).then(scanResult => {
                if (scanResult && scanResult.blocked) {
                    window.lastBlockedFile = file.name;
                    window.lastBlockedTime = Date.now();
                    blockAndAlert(window.location.href, file.name, "", scanResult);
                } else {
                    window.lastBlockedFile = null;
                    reportToDashboard(
                        window.location.href,
                        file.name,
                        "",
                        scanResult,
                        "Allowed by Enterprise Browser Extension"
                    );
                }
            }).finally(() => {
                window.dlpActiveScans--;
            });
        }
    }, true);

    // Surface Google Drive's own security/upload rejection in the incident dashboard.
    function installGoogleDriveFailureObserver() {
        if (window.location.hostname !== "drive.google.com" || !document.documentElement) return;
        const rejectionPattern = /virus|malware|malicious|blocked.{0,30}security|upload failed|unable to upload|could(?:n|'|’)t upload/i;
        const observer = new MutationObserver((mutations) => {
            for (const mutation of mutations) {
                for (const node of mutation.addedNodes) {
                    const text = String(node.textContent || "").trim().slice(0, 1000);
                    if (!text || !rejectionPattern.test(text)) continue;
                    const fileName = window.lastUploadCandidate || window.lastBlockedFile;
                    if (!fileName) continue;
                    reportToDashboard(
                        window.location.href,
                        fileName,
                        text.slice(0, 500),
                        { findings: [], classification: "Restricted", error: "" },
                        "Blocked by Google Drive security"
                    );
                    return;
                }
            }
        });
        observer.observe(document.documentElement, { childList: true, subtree: true });
    }

    if (document.documentElement) {
        installGoogleDriveFailureObserver();
    } else {
        document.addEventListener("DOMContentLoaded", installGoogleDriveFailureObserver, { once: true });
    }

    document.addEventListener("submit", function(e) {
        const form = e.target;
        const fileInputs = form.querySelectorAll('input[type="file"]');
        for (let input of fileInputs) {
            if (input.files && input.files.length > 0) {
                const fileName = input.files[0].name;
                if (window.lastBlockedFile === fileName) {
                    e.preventDefault();
                    e.stopPropagation();
                    const url = form.action || window.location.href;
                    reportToDashboard(url, fileName);
                    setTimeout(() => {
                        alert("ANTIGRAVITY DLP WARNING:\\n\\nUpload of sensitive file '" + fileName + "' blocked automatically by Enterprise Policy!");
                    }, 100);
                    return false;
                }
            }
        }
    }, true);
})();
