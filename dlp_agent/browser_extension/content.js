(function() {
    function reportToDashboard(url, fileName) {
        try {
            const xhr = new XMLHttpRequest();
            xhr.open("POST", "http://127.0.0.1:8080/api/browser_incident", true);
            xhr.setRequestHeader("Content-Type", "application/json");
            xhr.send(JSON.stringify({
                url: url,
                file_name: fileName,
                action: "Blocked by Enterprise Browser Extension"
            }));
        } catch (e) {
            console.error("DLP Extension: Failed to report to dashboard", e);
        }
    }

    function checkSensitivity(str) {
        if (!str) return false;
        const keywords = ["payroll", "confidential", "financial_report", "password", "synthetic_test_data", "credential"];
        const lowerStr = str.toLowerCase();
        return keywords.some(kw => lowerStr.includes(kw));
    }

    function blockAndAlert(url, fileName) {
        console.error("DLP BLOCK: Attempted to exfiltrate sensitive data to " + url);
        alert("ANTIGRAVITY DLP WARNING:\\n\\nUpload of sensitive file '" + fileName + "' blocked automatically by Enterprise Policy!");
        reportToDashboard(url, fileName);
    }

    // 1. Hook Fetch API
    const originalFetch = window.fetch;
    window.fetch = async function(...args) {
        let url = args[0] ? args[0].toString() : "";
        let options = args[1];
        
        if (options && options.body && url !== "http://127.0.0.1:8080/api/browser_incident") {
            let bodyStr = "";
            let fileName = "Unknown File";
            try {
                if (options.body instanceof FormData) {
                    for (let [key, value] of options.body.entries()) {
                        if (value instanceof File) {
                            bodyStr += value.name + " ";
                            fileName = value.name;
                        } else {
                            bodyStr += value + " ";
                        }
                    }
                } else if (typeof options.body === 'string') {
                    bodyStr = options.body;
                    fileName = "Raw Payload Data";
                }
            } catch(e) {}
            
            if (checkSensitivity(bodyStr)) {
                blockAndAlert(url, fileName);
                return Promise.reject(new Error("ERR_BLOCKED_BY_ENTERPRISE_DLP"));
            }
        }
        return originalFetch.apply(this, args);
    };

    // 2. Hook XMLHttpRequest
    const originalXHRSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function(body) {
        const url = this._url || window.location.href;
        if (body && !url.includes("127.0.0.1:8080")) {
            let bodyStr = "";
            let fileName = "Unknown File";
            try {
                if (body instanceof FormData) {
                    for (let [key, value] of body.entries()) {
                        if (value instanceof File) {
                            bodyStr += value.name + " ";
                            fileName = value.name;
                        } else {
                            bodyStr += value + " ";
                        }
                    }
                } else if (typeof body === 'string') {
                    bodyStr = body;
                    fileName = "Raw Payload Data";
                }
            } catch(e) {}
            
            if (checkSensitivity(bodyStr)) {
                blockAndAlert(url, fileName);
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

    // 3. Hook standard HTML Forms
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
                    blockAndAlert(url, fileName);
                    return false;
                }
            }
        }
    }, true);
})();
