// @ts-nocheck
console.log("WVS Content Script (Listener) Injected.");

// Listen to messages from the injected script
window.addEventListener("message", (event) => {
    if (event.source !== window || !event.data || event.data.source !== 'WVS_INJECT') {
        return;
    }

    if (event.data.type === 'VULNERABILITY_FOUND') {
        console.log("[WVS] Content script received alert form page!", event.data);

        const host = window.location.hostname;

        // Store finding in chrome.storage
        chrome.storage.local.get({ DOMFindings: {} }, (result) => {
            const DOMFindings = result.DOMFindings;
            if (!DOMFindings[host]) {
                DOMFindings[host] = [];
            }

            const newFinding = {
                type: event.data.vulnType,
                payload: event.data.payload,
                url: window.location.href,
                timestamp: Date.now()
            };

            DOMFindings[host].push(newFinding);
            chrome.storage.local.set({ DOMFindings });
        });
    }
});

// Storage Analysis for Secrets/JWTs
(function analyzeStorage() {
    try {
        const sensitiveRegex = /token|jwt|auth|secret|key|passwd|password|credential/i;
        const jwtRegex = /^eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*$/;

        const host = window.location.hostname;
        const storageFindings = [];

        const checkStorage = (storageObject, storageType) => {
            for (let i = 0; i < storageObject.length; i++) {
                const key = storageObject.key(i);
                const value = storageObject.getItem(key) || '';

                let issue = null;
                if (sensitiveRegex.test(key)) {
                    issue = `Suspicious key name: ${key}`;
                } else if (jwtRegex.test(value)) {
                    issue = `Value resembles a JWT for key: ${key}`;
                }

                if (issue) {
                    storageFindings.push({
                        type: storageType,
                        key: key,
                        issue: issue,
                        valuePreview: value.length > 50 ? value.substring(0, 50) + "..." : value
                    });
                }
            }
        };

        checkStorage(window.localStorage, 'localStorage');
        checkStorage(window.sessionStorage, 'sessionStorage');

        if (storageFindings.length > 0) {
            console.warn("[WVS] Sensitive data found in storage!", storageFindings);
            chrome.storage.local.get({ StorageFindings: {} }, (result) => {
                const findingsMap = result.StorageFindings;
                // Replace entirely or merge? Let's replace for the current host on scan.
                findingsMap[host] = storageFindings;
                chrome.storage.local.set({ StorageFindings: findingsMap });
            });
        }
    } catch (e) {
        console.error("[WVS] Failed to analyze storage:", e);
    }
})();
