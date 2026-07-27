(function() {
    const recentlyReported = new Map();

    function reportToDashboard(url, fileName, sampleText = "") {
        const now = Date.now();
        if (recentlyReported.has(fileName) && (now - recentlyReported.get(fileName)) < 3000) {
            console.log("DLP Extension: Skipping duplicate report for", fileName);
            return;
        }
        recentlyReported.set(fileName, now);
        console.log("DLP Extension: Reporting blocked upload to dashboard:", fileName, url);
        const payload = {
            url: url,
            file_name: fileName,
            sample_text: sampleText,
            action: "Blocked by Enterprise Browser Extension"
        };
        try {
            document.dispatchEvent(new CustomEvent("ANTIGRAVITY_DLP_INCIDENT", { detail: payload }));
        } catch (e) {
            console.error("DLP Extension: Failed CustomEvent bridge", e);
        }
        try {
            if (navigator && navigator.sendBeacon) {
                const blob = new Blob([JSON.stringify(payload)], { type: 'application/json' });
                navigator.sendBeacon("http://127.0.0.1:8080/api/browser_incident", blob);
            }
        } catch (e) {}

        try {
            window.postMessage({
                type: "ANTIGRAVITY_DLP_INCIDENT",
                payload: payload
            }, "*");
        } catch (e) {
            console.error("DLP Extension: Failed postMessage bridge", e);
        }

        try {
            if (typeof chrome !== "undefined" && chrome.runtime && chrome.runtime.sendMessage) {
                chrome.runtime.sendMessage({
                    type: "REPORT_INCIDENT",
                    payload: {
                        url: url,
                        file_name: fileName,
                        sample_text: sampleText,
                        action: "Blocked by Enterprise Browser Extension"
                    }
                }, (response) => {
                    if (chrome.runtime.lastError || !response || !response.success) {
                        sendViaXHR(url, fileName, sampleText);
                    }
                });
            } else {
                sendViaXHR(url, fileName, sampleText);
            }
        } catch (e) {
            sendViaXHR(url, fileName, sampleText);
        }
    }

    function sendViaXHR(url, fileName, sampleText = "") {
        try {
            const xhr = new XMLHttpRequest();
            xhr.open("POST", "http://127.0.0.1:8080/api/browser_incident", true);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send(JSON.stringify({
                url: url,
                file_name: fileName,
                sample_text: sampleText,
                action: "Blocked by Enterprise Browser Extension"
            }));
        } catch(err) {
            console.error("DLP Extension: XHR fallback error:", err);
        }
    }

    function checkSensitivity(str) {
        if (!str) return false;
        const keywords = [
            "payroll", "confidential", "financial_report", "password",
            "synthetic_test_data", "credential", "employee_directory",
            "customer_records", "salary", "ssn", "api_key", "secret_key"
        ];
        const lowerStr = str.toLowerCase();
        return keywords.some(kw => lowerStr.includes(kw));
    }

    function blockAndAlert(url, fileName, sampleText = "") {
        console.error("DLP BLOCK: Attempted to exfiltrate sensitive data to " + url);
        reportToDashboard(url, fileName, sampleText);
        setTimeout(() => {
            alert("ANTIGRAVITY DLP WARNING:\\n\\nUpload of sensitive file '" + fileName + "' blocked automatically by Enterprise Policy!");
        }, 100);
    }

    // 1. Hook Fetch API
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        let url = args[0] ? args[0].toString() : "";
        let options = args[1];
        
        if (options && options.body instanceof FormData && url !== "http://127.0.0.1:8080/api/browser_incident") {
            let bodyStr = "";
            let fileName = "";
            try {
                for (let [key, value] of options.body.entries()) {
                    if (value instanceof File) {
                        bodyStr += value.name + " ";
                        fileName = value.name;
                    } else {
                        bodyStr += value + " ";
                    }
                }
            } catch(e) {}
            
            if (fileName && checkSensitivity(bodyStr)) {
                blockAndAlert(url, fileName);
                return Promise.reject(new Error("ERR_BLOCKED_BY_ENTERPRISE_DLP"));
            }
        }
        if (url !== "http://127.0.0.1:8080/api/browser_incident" && (url.includes("upload") || url.includes("resumable") || url.includes("googleapis.com"))) {
            if (window.lastBlockedFile && (Date.now() - (window.lastBlockedTime || 0)) < 15000) {
                console.error("DLP BLOCK: Blocking resumable fetch upload for " + window.lastBlockedFile);
                return Promise.reject(new Error("ERR_BLOCKED_BY_ENTERPRISE_DLP"));
            }
        }
        return originalFetch.apply(this, args);
    };

    // 2. Hook XMLHttpRequest
    const originalXHRSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
        const url = this._url || window.location.href;
        if (body && body instanceof FormData && !url.includes("127.0.0.1:8080")) {
            let bodyStr = "";
            let fileName = "";
            try {
                for (let [key, value] of body.entries()) {
                    if (value instanceof File) {
                        bodyStr += value.name + " ";
                        fileName = value.name;
                    } else {
                        bodyStr += value + " ";
                    }
                }
            } catch(e) {}
            
            if (fileName && checkSensitivity(bodyStr)) {
                blockAndAlert(url, fileName);
                throw new Error("ERR_BLOCKED_BY_ENTERPRISE_DLP");
            }
        }
        if (!url.includes("127.0.0.1:8080") && (url.includes("upload") || url.includes("resumable") || url.includes("googleapis.com"))) {
            if (window.lastBlockedFile && (Date.now() - (window.lastBlockedTime || 0)) < 15000) {
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

    // 3. Hook standard HTML Forms & File Input selection (Deep Content Inspection)
    document.addEventListener("change", async function(e) {
        if (e.target && e.target.type === "file" && e.target.files && e.target.files.length > 0) {
            const file = e.target.files[0];
            let contentStr = file.name;
            let sampleText = "";
            try {
                const text = await file.text();
                sampleText = text.slice(0, 5000);
                contentStr += " " + sampleText;
            } catch(err) {}
            if (checkSensitivity(contentStr)) {
                try {
                    e.preventDefault();
                    e.stopPropagation();
                    e.stopImmediatePropagation();
                    e.target.value = "";
                } catch(err) {}
                window.lastBlockedFile = file.name;
                window.lastBlockedTime = Date.now();
                reportToDashboard(window.location.href, file.name, sampleText);
                setTimeout(() => {
                    alert("ANTIGRAVITY DLP WARNING:\\n\\nThe file '" + file.name + "' contains restricted/confidential corporate data! Uploading this file is prohibited.");
                }, 100);
            }
        }
    }, true);

    document.addEventListener("submit", function(e) {
        const form = e.target;
        const fileInputs = form.querySelectorAll('input[type="file"]');
        for (let input of fileInputs) {
            if (input.files && input.files.length > 0) {
                const fileName = input.files[0].name;
                if (checkSensitivity(fileName)) {
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
