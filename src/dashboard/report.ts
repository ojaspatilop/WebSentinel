// report.ts — Shared utilities for PDF/HTML report generation + plain-English explanations

export interface Finding {
    title: string;
    severity: string;
    cvss: string | number;
    details: string;
    owasp_category: string;
}

export interface DOMFinding { type: string; payload?: string; url?: string; }
export interface StorageFinding { type: string; key: string; issue: string; valuePreview: string; }

// ─── Plain-English risk level labels ─────────────────────────────────
export function riskLabel(cvss: string | number): { label: string; color: string } {
    const v = parseFloat(String(cvss));
    if (v >= 9.0) return { label: '🔴 Critical Risk — Immediate action required', color: '#ef4444' };
    if (v >= 7.0) return { label: '🟠 High Risk — Should be fixed soon', color: '#f97316' };
    if (v >= 4.0) return { label: '🟡 Medium Risk — Worth reviewing', color: '#eab308' };
    if (v > 0) return { label: '🟢 Low Risk — Minor concern', color: '#22c55e' };
    return { label: '🔵 Info — No direct risk, good to know', color: '#3b82f6' };
}

// ─── User-friendly explanations for OWASP categories ─────────────────
export function owaspExplain(category: string): string {
    if (category.includes('A01')) return 'Someone may be able to view or change data they shouldn\'t have access to.';
    if (category.includes('A02')) return 'Sensitive data (like passwords or personal info) may not be properly encrypted or protected.';
    if (category.includes('A03')) return 'Attackers may be able to inject malicious code or commands into this website.';
    if (category.includes('A04')) return 'The website\'s design may allow attackers to bypass security controls.';
    if (category.includes('A05')) return 'The website is not configured securely — like leaving windows unlocked.';
    if (category.includes('A06')) return 'Outdated software with known security flaws is being used on this site.';
    if (category.includes('A07')) return 'User login or session management may be weak, making accounts easier to compromise.';
    if (category.includes('A08')) return 'The website may be vulnerable to data manipulation attacks.';
    if (category.includes('A09')) return 'The website may not track suspicious activity, making it harder to detect attacks.';
    if (category.includes('A10')) return 'The server is being used to make requests on behalf of attackers to internal systems.';
    return 'A security issue was detected that could affect the safety of this website.';
}

// ─── What a regular user should DO about each finding ─────────────────
export function remediationHint(title: string): string {
    const t = title.toLowerCase();
    if (t.includes('content-security-policy')) return 'Tell the website owner to add a Content-Security-Policy header to prevent script injection.';
    if (t.includes('hsts') || t.includes('strict-transport')) return 'The site should enforce HTTPS-only connections. Contact the site owner.';
    if (t.includes('x-frame-options')) return 'This site could be embedded in a malicious page. Be cautious of unexpected popups.';
    if (t.includes('cookie') && t.includes('httponly')) return 'Cookies can be stolen by scripts. Avoid this site for sensitive activities.';
    if (t.includes('cookie') && t.includes('secure')) return 'Avoid using this site on public Wi-Fi — cookies could be intercepted.';
    if (t.includes('cookie') && t.includes('samesite')) return 'This site\'s cookies may be vulnerable to cross-site request forgery. Avoid clicking links to this site from emails.';
    if (t.includes('outdated') || t.includes('vulnerable')) return 'The site uses old software with known vulnerabilities. Avoid entering sensitive information.';
    if (t.includes('sql') || t.includes('database error')) return 'The site is leaking internal error details. Report this to the website owner immediately.';
    if (t.includes('dom_xss') || t.includes('injection')) return 'Someone may be able to inject malicious scripts via the page URL. Be careful with links sent to you for this site.';
    if (t.includes('exposed secret') || t.includes('jwt')) return 'A login token or sensitive key is stored insecurely. Do not use this site on shared devices.';
    if (t.includes('insecure password') || t.includes('http')) return 'Your password could be intercepted when logging in. Only use this site over a secure HTTPS connection.';
    if (t.includes('server technology')) return 'The server is revealing what software it uses. This helps attackers target known vulnerabilities.';
    if (t.includes('javascript:')) return 'A dangerous type of link was found on the page. Do not click unknown links on this site.';
    return 'Contact the website owner or IT team with this report to get it fixed.';
}

// ─── Generate a full, printable HTML report ───────────────────────────
export function generateHTMLReport(params: {
    domain: string;
    passive: Finding[];
    dom: DOMFinding[];
    storage: StorageFinding[];
}): string {
    const { domain, passive, dom, storage } = params;
    const date = new Date().toLocaleString();
    const total = passive.length + dom.length + storage.length;

    const allFindings: Array<{ title: string; category: string; cvss: number; details: string; source: string }> = [
        ...passive.map(f => ({ title: f.title, category: f.owasp_category, cvss: parseFloat(String(f.cvss)), details: f.details, source: 'Passive Scan' })),
        ...dom.map(f => ({ title: f.type, category: 'A03:2021 – Injection (DOM XSS)', cvss: 7.5, details: `Payload: ${f.payload || 'N/A'}`, source: 'DOM XSS Hook' })),
        ...storage.map(f => ({ title: `Exposed Secret: ${f.key}`, category: 'A07:2021 – Auth Failures', cvss: 5.3, details: f.issue, source: 'Storage Analysis' })),
    ].sort((a, b) => b.cvss - a.cvss);

    const getCvssColor = (v: number) => v >= 9 ? '#ef4444' : v >= 7 ? '#f97316' : v >= 4 ? '#eab308' : v > 0 ? '#22c55e' : '#3b82f6';

    const rows = allFindings.map(f => {
        const risk = riskLabel(f.cvss);
        const oTip = owaspExplain(f.category);
        const hint = remediationHint(f.title);
        const details = f.details.replace(/<[^>]+>/g, '');
        return `
      <div class="finding">
        <div class="finding-header">
          <span class="finding-title">${f.title}</span>
          <span class="badge" style="background:${getCvssColor(f.cvss)}">${risk.label}</span>
        </div>
        <div class="meta">
          <span class="tag">${f.category}</span>
          <span class="tag source">${f.source}</span>
          <span class="tag cvss">CVSS ${f.cvss}</span>
        </div>
        <div class="explain-box">
          <p class="explain-title">🗣 What does this mean?</p>
          <p class="explain-text">${oTip}</p>
        </div>
        ${details ? `<p class="detail-text"><strong>Technical detail:</strong> ${details}</p>` : ''}
        <div class="action-box">
          <p class="action-title">✅ What should you do?</p>
          <p class="action-text">${hint}</p>
        </div>
      </div>`;
    }).join('');

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8"/>
  <title>WebSentinel Security Report — ${domain}</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Segoe UI', Arial, sans-serif; background: #f8fafc; color: #1e293b; padding: 40px; }
    .header { background: linear-gradient(135deg, #0f172a, #1e3a5f); color: white; border-radius: 12px; padding: 32px 36px; margin-bottom: 28px; }
    .header h1 { font-size: 26px; font-weight: 800; letter-spacing: -0.5px; }
    .header .sub { font-size: 13px; opacity: 0.7; margin-top: 6px; }
    .header .domain { font-family: monospace; font-size: 18px; color: #38bdf8; margin-top: 10px; }
    .stats { display: flex; gap: 16px; margin-bottom: 28px; flex-wrap: wrap; }
    .stat { flex: 1; min-width: 120px; background: white; border-radius: 10px; padding: 18px 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.08); border: 1px solid #e2e8f0; }
    .stat .num { font-size: 32px; font-weight: 900; color: #0f172a; }
    .stat .lbl { font-size: 11px; color: #64748b; text-transform: uppercase; letter-spacing: 0.5px; margin-top: 4px; }
    .section-title { font-size: 15px; font-weight: 700; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 8px; margin-bottom: 16px; }
    .finding { background: white; border-radius: 10px; border: 1px solid #e2e8f0; padding: 20px 22px; margin-bottom: 16px; page-break-inside: avoid; }
    .finding-header { display: flex; justify-content: space-between; align-items: flex-start; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }
    .finding-title { font-weight: 700; font-size: 14px; flex: 1; }
    .badge { font-size: 10px; font-weight: 700; color: white; padding: 4px 10px; border-radius: 999px; white-space: nowrap; }
    .meta { display: flex; gap: 8px; flex-wrap: wrap; margin-bottom: 12px; }
    .tag { font-size: 10px; padding: 2px 8px; border-radius: 999px; background: #f1f5f9; color: #475569; border: 1px solid #e2e8f0; }
    .tag.source { background: #eff6ff; color: #3b82f6; border-color: #bfdbfe; }
    .tag.cvss { background: #fef3c7; color: #92400e; border-color: #fde68a; font-family: monospace; }
    .explain-box { background: #f0f9ff; border-left: 3px solid #38bdf8; padding: 10px 14px; border-radius: 0 6px 6px 0; margin-bottom: 10px; }
    .explain-title { font-size: 11px; font-weight: 700; color: #0369a1; margin-bottom: 4px; }
    .explain-text { font-size: 12px; color: #0c4a6e; line-height: 1.5; }
    .detail-text { font-size: 11px; color: #64748b; font-family: monospace; margin-bottom: 10px; background: #f8fafc; padding: 8px; border-radius: 6px; }
    .action-box { background: #f0fdf4; border-left: 3px solid #22c55e; padding: 10px 14px; border-radius: 0 6px 6px 0; }
    .action-title { font-size: 11px; font-weight: 700; color: #15803d; margin-bottom: 4px; }
    .action-text { font-size: 12px; color: #14532d; line-height: 1.5; }
    .footer { margin-top: 40px; text-align: center; font-size: 11px; color: #94a3b8; border-top: 1px solid #e2e8f0; padding-top: 20px; }
    .clean { background: #f0fdf4; border: 2px dashed #86efac; border-radius: 10px; padding: 32px; text-align: center; color: #15803d; font-weight: 600; }
    @media print {
      body { background: white; padding: 20px; }
      .finding { box-shadow: none; }
    }
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ WebSentinel Security Report</h1>
    <div class="domain">${domain}</div>
    <div class="sub">Generated ${date} · OWASP Top 10 (2021) Aligned · CVSS 3.1 Scoring</div>
  </div>

  <div class="stats">
    <div class="stat"><div class="num">${total}</div><div class="lbl">Total Issues</div></div>
    <div class="stat"><div class="num">${allFindings.filter(f => f.cvss >= 7).length}</div><div class="lbl">High / Critical</div></div>
    <div class="stat"><div class="num">${allFindings.filter(f => f.cvss >= 4 && f.cvss < 7).length}</div><div class="lbl">Medium</div></div>
    <div class="stat"><div class="num">${allFindings.filter(f => f.cvss < 4).length}</div><div class="lbl">Low / Info</div></div>
  </div>

  <div class="section-title">Security Findings</div>
  ${allFindings.length === 0
            ? '<div class="clean">✅ No vulnerabilities detected on this domain.</div>'
            : rows}

  <div class="footer">
    WebSentinel v2.0 · This report is for informational purposes only · Passive scan only, no active exploitation
  </div>
</body>
</html>`;
}

// ─── Open report in new window and trigger print dialog (Save as PDF) ──
export function exportAsPDF(params: Parameters<typeof generateHTMLReport>[0]) {
    const html = generateHTMLReport(params);
    const win = window.open('', '_blank');
    if (!win) { alert('Please allow popups to export PDF.'); return; }
    win.document.write(html);
    win.document.close();
    setTimeout(() => win.print(), 400);
}
