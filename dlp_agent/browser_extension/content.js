(function() {
    const recentlyReported = new Map();
    const socAllowedFiles = new Map();
    const cleanScanCache = new WeakMap();

    function reportToDashboard(url, fileName, sampleText = "", scanResult = null, action = "Blocked by Enterprise Browser Extension") {
        if (scanResult && scanResult.soc_override) return;
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
                if (message.file_name) {
                    socAllowedFiles.set(message.file_name, Date.now() + 120000);
                }
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
                }, 20000);
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
        const cachedScan = cleanScanCache.get(file);
        if (cachedScan && cachedScan.expires_at > Date.now()) {
            return cachedScan.result;
        }
        const approvalExpires = socAllowedFiles.get(file.name || "");
        if (approvalExpires && approvalExpires > Date.now()) {
            return {
                blocked: false,
                findings: [],
                classification: "Public",
                risk_score: 0,
                error: null,
                soc_override: true
            };
        }
        if (approvalExpires) socAllowedFiles.delete(file.name || "");
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

    // 3. Gate standard file inputs before apps such as Telegram can read the
    // FileList. The original event is never allowed to reach the application;
    // a clean selection is restored and replayed only after inspection passes.
    const replayingFileInputs = new WeakSet();

    async function inspectFiles(files) {
        const inspected = [];
        for (const file of files) {
            window.lastUploadCandidate = file.name;
            const scanResult = await scanFileBackend(file);
            if (!scanResult || scanResult.blocked) {
                return { blocked: true, file, scanResult: scanResult || { blocked: true, error: "Deep inspection returned no result." } };
            }
            cleanScanCache.set(file, {
                result: scanResult,
                expires_at: Date.now() + 60_000
            });
            inspected.push({ file, scanResult });
        }
        return { blocked: false, inspected };
    }

    function releaseActiveScan() {
        window.dlpActiveScans = Math.max(0, window.dlpActiveScans - 1);
    }

    function reportInspectedFiles(uploadTarget, inspected) {
        for (const item of inspected) {
            reportToDashboard(
                uploadTarget,
                item.file.name,
                "",
                item.scanResult,
                "Allowed by Enterprise Browser Extension"
            );
        }
    }

    function allowEmptyFilesWithoutReplay(uploadTarget, files) {
        const emptyResult = {
            blocked: false,
            findings: [],
            finding_count: 0,
            classification: "Public",
            risk_score: 0,
            error: null
        };
        window.lastBlockedFile = null;
        for (const file of files) {
            window.lastUploadCandidate = file.name;
            cleanScanCache.set(file, {
                result: emptyResult,
                expires_at: Date.now() + 60_000
            });
            reportToDashboard(
                uploadTarget,
                file.name,
                "",
                emptyResult,
                "Allowed by Enterprise Browser Extension"
            );
        }
    }

    function restoreFileSelection(input, files) {
        const transfer = new DataTransfer();
        for (const file of files) transfer.items.add(file);
        input.files = transfer.files;
    }

    document.addEventListener("change", function(e) {
        const input = e.target;
        if (!input || input.type !== "file" || replayingFileInputs.has(input)) return;
        const files = input.files ? Array.from(input.files) : [];
        if (!files.length) return;
        const uploadTarget = (input.form && input.form.action) || window.location.href;

        // Empty files contain no data to inspect. Preserve the browser's original
        // trusted event so Telegram can handle the selection natively.
        if (files.every(file => file.size === 0)) {
            allowEmptyFilesWithoutReplay(uploadTarget, files);
            return;
        }

        // This must happen synchronously in the capture phase. Telegram attaches
        // its own handlers after document_start and otherwise queues the file
        // while the asynchronous scanner is still running.
        e.preventDefault();
        e.stopImmediatePropagation();
        input.value = "";
        window.dlpActiveScans++;

        inspectFiles(files).then(result => {
            // Release the network gate before Telegram receives the replayed
            // event. Otherwise its upload request can remain queued indefinitely.
            releaseActiveScan();
            if (result.blocked) {
                window.lastBlockedFile = result.file.name;
                window.lastBlockedTime = Date.now();
                input.value = "";
                blockAndAlert(uploadTarget, result.file.name, "", result.scanResult);
                return;
            }

            window.lastBlockedFile = null;
            try {
                restoreFileSelection(input, files);
                replayingFileInputs.add(input);
                input.dispatchEvent(new Event("change", { bubbles: true, cancelable: true }));
                reportInspectedFiles(uploadTarget, result.inspected);
            } catch (error) {
                input.value = "";
                blockAndAlert(uploadTarget, files[0].name, "", {
                    blocked: true,
                    error: "The inspected file could not be safely handed back to the upload page."
                });
            } finally {
                replayingFileInputs.delete(input);
            }
        }).catch(() => {
            releaseActiveScan();
            input.value = "";
            blockAndAlert(uploadTarget, files[0].name, "", {
                blocked: true,
                error: "Deep inspection could not complete safely."
            });
        });
    }, true);

    // 4. Apply the same hold-and-replay gate to drag-and-drop uploads.
    let replayingDrop = false;
    document.addEventListener("drop", function(e) {
        if (replayingDrop || !e.dataTransfer || !e.dataTransfer.files || !e.dataTransfer.files.length) return;
        const files = Array.from(e.dataTransfer.files);
        const dropTarget = e.target;
        if (files.every(file => file.size === 0)) {
            allowEmptyFilesWithoutReplay(window.location.href, files);
            return;
        }
        e.preventDefault();
        e.stopImmediatePropagation();
        window.dlpActiveScans++;

        inspectFiles(files).then(result => {
            releaseActiveScan();
            if (result.blocked) {
                window.lastBlockedFile = result.file.name;
                window.lastBlockedTime = Date.now();
                blockAndAlert(window.location.href, result.file.name, "", result.scanResult);
                return;
            }

            window.lastBlockedFile = null;
            try {
                const transfer = new DataTransfer();
                for (const file of files) transfer.items.add(file);
                replayingDrop = true;
                dropTarget.dispatchEvent(new DragEvent("drop", {
                    bubbles: true,
                    cancelable: true,
                    dataTransfer: transfer
                }));
                reportInspectedFiles(window.location.href, result.inspected);
            } catch (error) {
                blockAndAlert(window.location.href, files[0].name, "", {
                    blocked: true,
                    error: "The inspected files could not be safely handed back to the upload page."
                });
            } finally {
                replayingDrop = false;
            }
        }).catch(() => {
            releaseActiveScan();
            blockAndAlert(window.location.href, files[0].name, "", {
                blocked: true,
                error: "Deep inspection could not complete safely."
            });
        });
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
