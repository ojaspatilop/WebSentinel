// @ts-nocheck
console.log("WVS Background Service Worker v2.0 Initialized.");

// ---- Unified Finding Type ----
// { title, severity, cvss, details, owasp_category }

// Trigger a full scan when a tab finishes loading
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.status === 'complete' && tab.url && tab.url.startsWith('http')) {
        runPassiveScan(tabId, tab.url);
    }
});

// Listen for rescan requests from the popup
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === 'rescanSite') {
        const { tabId, url } = request;
        runPassiveScan(tabId, url).then(() => {
            chrome.storage.local.get(['findings'], (data) => {
                const host = new URL(url).hostname;
                sendResponse({ findings: (data.findings || {})[host] || {} });
            });
        });
        return true; // async response
    }
});

// ---- Main Scan Orchestrator ----
async function runPassiveScan(tabId, url) {
    try {
        const pageUrl = new URL(url);
        const host = pageUrl.hostname;
        let allFindings = [];

        // 1. Fetch headers for the URL
        const response = await fetch(url, { method: 'GET', cache: 'no-store', redirect: 'follow' });
        const headers = response.headers;
        allFindings.push(...checkSecurityHeaders(headers));

        // 2. Use cookies API for accurate cookie checks
        allFindings.push(...(await checkCookies(pageUrl)));

        // 3. Inject script to get raw HTML for DOM-based checks
        const scriptResult = await chrome.scripting.executeScript({
            target: { tabId },
            func: () => document.documentElement.outerHTML
        });
        if (scriptResult && scriptResult[0]?.result) {
            const html = scriptResult[0].result;
            allFindings.push(...(await checkVulnerableLibraries(html)));
            allFindings.push(...checkDangerousJsUrls(html));
            allFindings.push(...checkSqlErrors(html));
            allFindings.push(...checkInsecureForms(html, pageUrl));
        }

        // 4. Deduplicate
        allFindings = dedupeFindings(allFindings);

        // 5. Save to storage and history
        chrome.storage.local.get({ findings: {} }, (result) => {
            const findings = result.findings;
            findings[host] = {
                ...(findings[host] || { missingHeaders: [], insecureCookies: [] }),
                passive: allFindings
            };
            chrome.storage.local.set({ findings });
        });

        saveToHistory(host, allFindings);
    } catch (e) {
        console.error('[WVS] Scan error:', e);
    }
}

// ---- Security Headers Check ----
// OWASP: A05:2021 - Security Misconfiguration
function checkSecurityHeaders(headers) {
    const findings = [];
    const cat = 'A05:2021 – Security Misconfiguration';
    const checks = [
        {
            header: 'content-security-policy',
            title: 'Missing Header: Content-Security-Policy',
            severity: 'High', cvss: '7.2',
            details: 'CSP prevents XSS by defining which resources the browser may load.'
        },
        {
            header: 'strict-transport-security',
            title: 'Missing Header: Strict-Transport-Security (HSTS)',
            severity: 'Medium', cvss: '6.5',
            details: 'HSTS forces HTTPS connections, preventing protocol downgrade attacks.'
        },
        {
            header: 'x-frame-options',
            title: 'Missing Header: X-Frame-Options',
            severity: 'Medium', cvss: '5.4',
            details: 'Prevents clickjacking by stopping this page from being embedded in iframes.'
        },
        {
            header: 'x-content-type-options',
            title: 'Missing Header: X-Content-Type-Options',
            severity: 'Low', cvss: '3.7',
            details: 'Prevents MIME-sniffing attacks. Should be set to "nosniff".'
        },
        {
            header: 'referrer-policy',
            title: 'Missing Header: Referrer-Policy',
            severity: 'Low', cvss: '3.1',
            details: 'Controls how much referrer information is included in requests.'
        },
        {
            header: 'permissions-policy',
            title: 'Missing Header: Permissions-Policy',
            severity: 'Info', cvss: '0.0',
            details: 'Defines which browser features this site is allowed to use.'
        }
    ];

    checks.forEach(({ header, title, severity, cvss, details }) => {
        if (!headers.has(header)) {
            findings.push({ title, severity, cvss, details, owasp_category: cat });
        }
    });

    // Server technology disclosure
    if (headers.has('server')) {
        findings.push({
            title: 'Server Technology Disclosed',
            severity: 'Info', cvss: '0.0',
            details: `The "Server" header reveals: <strong>${headers.get('server')}</strong>. This aids attacker reconnaissance.`,
            owasp_category: 'A05:2021 – Security Misconfiguration'
        });
    }

    return findings;
}

// ---- Cookie Checks (using chrome.cookies API) ----
// OWASP: A07:2021 - Identification and Authentication Failures
async function checkCookies(pageUrl) {
    const findings = [];
    const cat = 'A07:2021 – Identification and Authentication Failures';
    try {
        const cookies = await chrome.cookies.getAll({ domain: pageUrl.hostname });
        cookies.forEach(cookie => {
            if (!cookie.httpOnly) {
                findings.push({
                    title: 'Cookie Missing HttpOnly Flag',
                    severity: 'Medium', cvss: '4.3',
                    details: `Cookie "<strong>${cookie.name}</strong>" is accessible to JS, amplifying XSS impact.`,
                    owasp_category: cat
                });
            }
            if (!cookie.secure && pageUrl.protocol === 'https:') {
                findings.push({
                    title: 'Cookie Missing Secure Flag',
                    severity: 'Medium', cvss: '4.3',
                    details: `Cookie "<strong>${cookie.name}</strong>" may be transmitted over unencrypted connections.`,
                    owasp_category: cat
                });
            }
            if (!cookie.sameSite || cookie.sameSite === 'no_restriction') {
                findings.push({
                    title: 'Cookie Weak SameSite Policy',
                    severity: 'Low', cvss: '3.1',
                    details: `Cookie "<strong>${cookie.name}</strong>" has no SameSite restriction, making it vulnerable to CSRF.`,
                    owasp_category: cat
                });
            }
        });
    } catch (e) {
        console.warn('[WVS] Cookie check failed:', e);
    }
    return findings;
}

// ---- Vulnerable Library Detection ----
// OWASP: A06:2021 - Vulnerable and Outdated Components
async function checkVulnerableLibraries(html) {
    try {
        const dbUrl = chrome.runtime.getURL('vuln_db.json');
        const db = await fetch(dbUrl).then(r => r.json());
        const findings = [];
        const scriptTagRegex = /<script[^>]+src="([^"]+)"/gi;
        let match;
        while ((match = scriptTagRegex.exec(html)) !== null) {
            const src = match[1];
            db.javascript_libraries.forEach(lib => {
                lib.versions.forEach(vuln => {
                    const re = new RegExp(`${lib.name}[._-]${vuln.version}(\\.min)?\\.js`, 'i');
                    if (re.test(src)) {
                        findings.push({
                            title: `Outdated Library: ${lib.name} ${vuln.version}`,
                            severity: vuln.severity,
                            cvss: vuln.cvss,
                            details: `Vulnerable script loaded from: <strong>${src}</strong>. ${vuln.vulnerability}. <strong>Fix:</strong> ${vuln.remediation}`,
                            owasp_category: 'A06:2021 – Vulnerable and Outdated Components'
                        });
                    }
                });
            });
        }
        return findings;
    } catch (e) {
        console.warn('[WVS] Library check failed:', e);
        return [];
    }
}

// ---- Dangerous javascript: URL Detection ----
// OWASP: A03:2021 - Injection
function checkDangerousJsUrls(html) {
    const findings = [];
    const jsHref = /<(a|area)[^>]+href\s*=\s*(["'])javascript:/gi;
    const jsSrc = /<iframe[^>]+src\s*=\s*(["'])javascript:/gi;
    if (jsHref.test(html) || jsSrc.test(html)) {
        findings.push({
            title: 'javascript: URL Detected in HTML',
            severity: 'High', cvss: '7.5',
            details: 'Links or iframes using the <code>javascript:</code> protocol were found in the page source, which can enable XSS.',
            owasp_category: 'A03:2021 – Injection'
        });
    }
    return findings;
}

// ---- SQL Error Exposure Detection ----
// OWASP: A03:2021 - Injection
function checkSqlErrors(html) {
    const text = html.toLowerCase();
    const patterns = [
        'you have an error in your sql syntax',
        'warning: mysql',
        'unclosed quotation mark after the character string',
        'microsoft oledb provider for sql server',
        'pg_query():',
        'postgresql error',
        'ora-00933', 'ora-00936', 'ora-01756'
    ];
    if (patterns.some(p => text.includes(p))) {
        return [{
            title: 'Database Error Message Exposed',
            severity: 'High', cvss: '7.5',
            details: 'The page reveals SQL error details, indicating possible SQL injection or poor server-side error handling.',
            owasp_category: 'A03:2021 – Injection'
        }];
    }
    return [];
}

// ---- Insecure Password Form Detection ----
// OWASP: A02:2021 - Cryptographic Failures
function checkInsecureForms(html, pageUrl) {
    const findings = [];
    if (pageUrl.protocol !== 'http:') return findings;
    const formRegex = /<form[^>]*>([\s\S]*?)<\/form>/gi;
    const pwdRegex = /<input[^>]+type=["']password["'][^>]*>/i;
    const actionRegex = /action=["']([^"']+)["']/i;
    let m;
    while ((m = formRegex.exec(html)) !== null) {
        if (pwdRegex.test(m[1])) {
            const actionMatch = m[0].match(actionRegex);
            const isSecure = actionMatch?.[1]?.toLowerCase().startsWith('https://');
            if (!isSecure) {
                findings.push({
                    title: 'Insecure Password Form (HTTP)',
                    severity: 'High', cvss: '7.5',
                    details: 'A login form on an HTTP page could expose credentials to network interception.',
                    owasp_category: 'A02:2021 – Cryptographic Failures'
                });
                break;
            }
        }
    }
    return findings;
}

// ---- Deduplicate Findings ----
function dedupeFindings(findings) {
    const seen = new Set();
    return findings.filter(f => {
        const key = `${(f.title || '').trim()}__${(f.owasp_category || '').trim()}`.toLowerCase();
        if (seen.has(key)) return false;
        seen.add(key);
        return true;
    });
}

// ---- Scan History ----
async function saveToHistory(host, findings) {
    if (findings.length === 0) return;
    const entry = { domain: host, scanDate: new Date().toISOString(), findings };
    const data = await chrome.storage.local.get(['scanHistory']);
    let history = data.scanHistory || [];
    const recentIdx = history.findIndex(e => e.domain === host && (Date.now() - new Date(e.scanDate).getTime()) < 300000);
    if (recentIdx !== -1) {
        history[recentIdx] = entry;
    } else {
        history.push(entry);
    }
    if (history.length > 100) history = history.slice(history.length - 100);
    await chrome.storage.local.set({ scanHistory: history });
}
