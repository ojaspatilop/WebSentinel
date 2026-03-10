// @ts-nocheck
console.log("[WVS] Injected script running in main world with Taint Tracking.");

(function () {
    try {
        // --- 1. Source Taint Tracking ---
        // We monitor common user-controllable sources for data
        const taintedSources = new Set();

        function addTaint(val) {
            if (val && typeof val === 'string' && val.length > 3) {
                // Decode URI components to catch raw payloads
                try { taintedSources.add(decodeURIComponent(val)); } catch (e) { }
                taintedSources.add(val);
            }
        }

        // Initialize with current URL parameters. 
        // We do this immediately to catch anything currently in the URL.
        function captureInitialSources() {
            try { addTaint(window.location.hash.slice(1)); } catch (e) { }
            try { addTaint(window.location.search.slice(1)); } catch (e) { }
            try { addTaint(window.name); } catch (e) { }
            try { addTaint(document.referrer); } catch (e) { }
        }
        captureInitialSources();

        // Also explicitly listen to hashchange to be extra sure
        window.addEventListener('hashchange', () => {
            try { addTaint(window.location.hash.slice(1)); } catch (e) { }
        });

        // Hook location.hash
        const hashDesc = Object.getOwnPropertyDescriptor(Location.prototype, 'hash') || Object.getOwnPropertyDescriptor(window.location, 'hash');
        if (hashDesc && hashDesc.set && hashDesc.get) {
            Object.defineProperty(window.location, 'hash', {
                get: function () { return hashDesc.get.call(this); },
                set: function (val) {
                    addTaint(val);
                    return hashDesc.set.call(this, val);
                }
            });
        }

        // --- 2. Sink Hooking ---
        const originalEval = window.eval;
        window.eval = function (string) {
            const strVal = string ? string.toString() : '';
            // Match exactly or via URL decoding
            const isTainted = [...taintedSources].some(taint => {
                if (strVal.includes(taint)) return true;
                try { if (strVal.includes(decodeURIComponent(taint))) return true; } catch (e) { }
                try { if (decodeURIComponent(strVal).includes(taint)) return true; } catch (e) { }
                return false;
            });

            if (isTainted) {
                console.warn("[WVS] TAINTED Sink called: window.eval", string);
                window.postMessage({
                    source: 'WVS_INJECT',
                    type: 'VULNERABILITY_FOUND',
                    vulnType: 'DOM_XSS_EVAL',
                    payload: strVal
                }, '*');
            }
            return originalEval.apply(this, arguments);
        };

        // Hook innerHTML
        let innerHTMLDescriptor = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML') || Object.getOwnPropertyDescriptor(HTMLElement.prototype, 'innerHTML');
        let targetPrototype = innerHTMLDescriptor ? (Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML') ? Element.prototype : HTMLElement.prototype) : null;

        if (innerHTMLDescriptor && innerHTMLDescriptor.set) {
            const originalSet = innerHTMLDescriptor.set;
            Object.defineProperty(targetPrototype, 'innerHTML', {
                set: function (value) {
                    const strValue = value?.toString() || '';

                    // Step A: Check if the value contains any known tainted source
                    const isTainted = [...taintedSources].some(taint => {
                        if (strValue.includes(taint)) return true;
                        try { if (strValue.includes(decodeURIComponent(taint))) return true; } catch (e) { }
                        try { if (decodeURIComponent(strValue).includes(taint)) return true; } catch (e) { }
                        return false;
                    });

                    // Step B: Structural heuristic filter (finding execution sinks)
                    let isSuspicious = false;
                    try {
                        const parser = new DOMParser();
                        const doc = parser.parseFromString(strValue, 'text/html');

                        if (doc.getElementsByTagName('script').length > 0) isSuspicious = true;

                        if (!isSuspicious) {
                            const walker = document.createTreeWalker(doc.body, NodeFilter.SHOW_ELEMENT, null, false);
                            let node;
                            while ((node = walker.nextNode())) {
                                if (node.tagName === 'A' && (node.href.toLowerCase().startsWith('javascript:') || node.href.toLowerCase().startsWith('data:text/html'))) {
                                    isSuspicious = true; break;
                                }
                                if (node.tagName === 'IFRAME' && node.src.toLowerCase().startsWith('javascript:')) {
                                    isSuspicious = true; break;
                                }
                                for (let i = 0; i < node.attributes.length; i++) {
                                    if (node.attributes[i].name.toLowerCase().startsWith('on')) {
                                        isSuspicious = true; break;
                                    }
                                }
                                if (isSuspicious) break;
                            }
                        }
                    } catch (e) {
                        isSuspicious = /<script\b[^>]*>|href\s*=\s*['"]?javascript:|href\s*=\s*['"]?data:text\/html|\bon\w+\s*=/i.test(strValue);
                    }

                    console.log("[WVS Debug] innerHTML called.");
                    console.log("[WVS Debug] Payload:", strValue);
                    console.log("[WVS Debug] Tainted Sources:", [...taintedSources]);
                    console.log("[WVS Debug] isSuspicious:", isSuspicious);
                    console.log("[WVS Debug] isTainted:", isTainted);

                    // 🚨 ONLY FLAG IF BOTH SUSPICIOUS AND TAINTED 🚨
                    if (isSuspicious && isTainted) {
                        console.warn("[WVS] TRUE POSITIVE: Tainted Sink innerHTML", strValue);
                        window.postMessage({
                            source: 'WVS_INJECT',
                            type: 'VULNERABILITY_FOUND',
                            vulnType: 'DOM_XSS_INNERHTML',
                            payload: strValue
                        }, '*');
                    }

                    return originalSet.call(this, value);
                }
            });
        }
    } catch (e) {
        console.error("[WVS] Error setting up hooks:", e);
    }
})();

