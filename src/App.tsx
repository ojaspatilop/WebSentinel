// @ts-nocheck
import { useEffect, useState, useCallback } from 'react';
import './index.css';

// ---- Types ----
interface Finding {
  title: string;
  severity: string;
  cvss: string | number;
  details: string;
  owasp_category: string;
}

interface HostFindings {
  passive?: Finding[];
  missingHeaders?: string[];
  insecureCookies?: string[];
}

interface DOMFinding {
  type: string;
  payload?: string;
  url?: string;
  timestamp?: number;
}

interface StorageFinding {
  type: string;
  key: string;
  issue: string;
  valuePreview: string;
}

interface HistoryEntry {
  domain: string;
  scanDate: string;
  findings: Finding[];
}

// ---- Helpers ----
function getCvssClass(cvss: string | number) {
  const v = parseFloat(String(cvss));
  if (v >= 9.0) return 'critical';
  if (v >= 7.0) return 'high';
  if (v >= 4.0) return 'medium';
  if (v > 0) return 'low';
  return 'info';
}

const SEVERITY_COLORS = {
  critical: 'bg-[#7b0000] border-red-900 text-red-200',
  high: 'bg-[#441111] border-red-700 text-red-300',
  medium: 'bg-[#3d2a00] border-yellow-700 text-yellow-200',
  low: 'bg-[#1a2d00] border-green-800 text-green-300',
  info: 'bg-[#001533] border-blue-800 text-blue-300',
};

const BADGE_COLORS = {
  critical: 'bg-red-900 text-red-200',
  high: 'bg-red-700 text-white',
  medium: 'bg-yellow-700 text-white',
  low: 'bg-green-800 text-white',
  info: 'bg-blue-800 text-white',
};

function CvssBadge({ cvss }: { cvss: string | number }) {
  const cls = getCvssClass(cvss);
  return (
    <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded ${BADGE_COLORS[cls]}`}>
      {cvss || 'N/A'}
    </span>
  );
}

function FindingCard({ finding }: { finding: Finding }) {
  const [open, setOpen] = useState(false);
  const cls = getCvssClass(finding.cvss);
  return (
    <div className={`rounded border p-2 ${SEVERITY_COLORS[cls]} cursor-pointer`} onClick={() => setOpen(o => !o)}>
      <div className="flex justify-between items-center gap-2">
        <p className="text-xs font-semibold leading-tight flex-1">{finding.title}</p>
        <CvssBadge cvss={finding.cvss} />
      </div>
      {open && (
        <p
          className="text-[10px] mt-2 font-mono opacity-80 leading-relaxed"
          dangerouslySetInnerHTML={{ __html: finding.details }}
        />
      )}
    </div>
  );
}

function OWASPSection({ category, findings }: { category: string; findings: Finding[] }) {
  const [open, setOpen] = useState(true);
  const sorted = [...findings].sort((a, b) => parseFloat(String(b.cvss)) - parseFloat(String(a.cvss)));
  return (
    <div className="mb-3">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex justify-between items-center text-left text-xs font-bold text-[var(--color-wvs-accent)] border-b border-[var(--color-wvs-panel)] pb-1 mb-2"
      >
        <span>{category}</span>
        <span className="text-gray-500 font-normal">{findings.length} finding{findings.length !== 1 ? 's' : ''} {open ? '▾' : '▸'}</span>
      </button>
      {open && (
        <div className="flex flex-col gap-1.5">
          {sorted.map((f, i) => <FindingCard key={i} finding={f} />)}
        </div>
      )}
    </div>
  );
}

// ---- Main App ----
function App() {
  const [activeTab, setActiveTab] = useState<'scan' | 'dom' | 'history'>('scan');
  const [activeHost, setActiveHost] = useState('');
  const [activeTabId, setActiveTabId] = useState<number | null>(null);
  const [activeTabUrl, setActiveTabUrl] = useState('');
  const [passiveFindings, setPassiveFindings] = useState<Finding[]>([]);
  const [domFindings, setDomFindings] = useState<DOMFinding[]>([]);
  const [storageFindings, setStorageFindings] = useState<StorageFinding[]>([]);
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [scanning, setScanning] = useState(false);

  const loadFindings = useCallback((host: string) => {
    chrome.storage.local.get(['findings', 'DOMFindings', 'StorageFindings', 'scanHistory'], (result) => {
      const h = result.findings?.[host];
      setPassiveFindings(h?.passive || []);
      setDomFindings(result.DOMFindings?.[host] || []);
      setStorageFindings(result.StorageFindings?.[host] || []);
      setHistory((result.scanHistory || []).slice().sort(
        (a, b) => new Date(b.scanDate).getTime() - new Date(a.scanDate).getTime()
      ));
    });
  }, []);

  useEffect(() => {
    if (!chrome?.tabs) return;
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tab = tabs[0];
      if (tab?.url && !tab.url.startsWith('chrome://')) {
        const host = new URL(tab.url).hostname;
        setActiveHost(host);
        setActiveTabId(tab.id ?? null);
        setActiveTabUrl(tab.url);
        loadFindings(host);
      } else {
        setActiveHost('N/A (System Page)');
      }
    });

    const interval = setInterval(() => {
      if (activeHost && activeHost !== 'N/A (System Page)') loadFindings(activeHost);
    }, 1500);
    return () => clearInterval(interval);
  }, [activeHost, loadFindings]);

  const handleRescan = () => {
    if (!activeTabId || !activeTabUrl) return;
    setScanning(true);
    chrome.runtime.sendMessage({ action: 'rescanSite', tabId: activeTabId, url: activeTabUrl }, () => {
      setTimeout(() => {
        loadFindings(activeHost);
        setScanning(false);
      }, 1500);
    });
  };

  const handleClear = () => {
    if (!activeHost) return;
    chrome.storage.local.get(['findings', 'DOMFindings', 'StorageFindings'], (result) => {
      const f = { ...(result.findings || {}) };
      const d = { ...(result.DOMFindings || {}) };
      const s = { ...(result.StorageFindings || {}) };
      delete f[activeHost]; delete d[activeHost]; delete s[activeHost];
      chrome.storage.local.set({ findings: f, DOMFindings: d, StorageFindings: s }, () => {
        setPassiveFindings([]); setDomFindings([]); setStorageFindings([]);
      });
    });
  };

  const handleExport = () => {
    if (!activeHost) return;
    const report = {
      reportTitle: 'WVS Security Report',
      domain: activeHost,
      scanDate: new Date().toISOString(),
      passiveFindings,
      domFindings,
      storageFindings,
    };
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `WVS-Report-${activeHost}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // Group passive findings by OWASP category
  const groupedPassive = passiveFindings.reduce<Record<string, Finding[]>>((acc, f) => {
    const cat = f.owasp_category || 'Other';
    acc[cat] = acc[cat] ? [...acc[cat], f] : [f];
    return acc;
  }, {});

  // Group DOM + storage findings into synthetic OWASP groups for the DOM tab
  const domOwaspGroup = domFindings.map(f => ({
    title: f.type,
    severity: 'High',
    cvss: '7.5',
    details: `<strong>Payload:</strong> ${f.payload || ''}`,
    owasp_category: 'A03:2021 – Injection',
  }));
  const storageOwaspGroup = storageFindings.map(f => ({
    title: `Exposed Secret in ${f.type}`,
    severity: 'Medium',
    cvss: '5.3',
    details: `<strong>Issue:</strong> ${f.issue}<br/><strong>Key:</strong> ${f.key}<br/><strong>Value:</strong> ${f.valuePreview}`,
    owasp_category: 'A07:2021 – Identification and Authentication Failures',
  }));

  const TAB = 'px-3 py-1 text-xs rounded-full transition font-semibold';
  const ACTIVE_TAB = `${TAB} bg-[var(--color-wvs-accent)] text-black`;
  const INACTIVE_TAB = `${TAB} text-gray-400 hover:text-white`;

  const totalIssues = passiveFindings.length + domFindings.length + storageFindings.length;

  return (
    <div className="w-[360px] p-4 font-sans bg-[var(--color-wvs-bg)] text-[var(--color-wvs-text)] text-sm flex flex-col gap-3 shadow-lg min-h-[480px]">
      {/* Header */}
      <header className="flex justify-between items-center border-b border-[var(--color-wvs-panel)] pb-2">
        <h1 className="text-lg font-bold flex items-center gap-2">
          <span className="text-[var(--color-wvs-accent)]">🛡️</span> WVS
          <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ml-1 ${totalIssues > 0 ? 'bg-red-800 text-red-200' : 'bg-green-900 text-green-300'}`}>
            {totalIssues} issue{totalIssues !== 1 ? 's' : ''}
          </span>
        </h1>
        <div className="flex gap-1">
          <button
            title="Open Full Dashboard"
            onClick={() => chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') })}
            className="text-[10px] px-2 py-1 bg-[var(--color-wvs-panel)] hover:bg-cyan-900/60 hover:text-cyan-400 rounded transition font-bold"
          >↗ Dashboard</button>
          <button onClick={handleRescan} disabled={scanning} className="text-[10px] px-2 py-1 bg-[var(--color-wvs-accent)] text-black font-bold rounded hover:opacity-80 transition disabled:opacity-50">{scanning ? '...' : '↺ Rescan'}</button>
          <button onClick={handleExport} className="text-[10px] px-2 py-1 bg-[var(--color-wvs-panel)] hover:bg-gray-700 rounded transition">⬇ Export</button>
          <button onClick={handleClear} className="text-[10px] px-2 py-1 bg-[var(--color-wvs-panel)] hover:bg-gray-700 rounded transition">✕ Clear</button>
        </div>
      </header>

      {/* Target */}
      <div className="bg-[var(--color-wvs-panel)] rounded px-3 py-1.5">
        <p className="text-[10px] text-gray-400">Target</p>
        <p className="font-mono text-[var(--color-wvs-accent)] text-xs truncate">{activeHost || '...'}</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[var(--color-wvs-panel)] rounded-full p-0.5">
        <button className={activeTab === 'scan' ? ACTIVE_TAB : INACTIVE_TAB} onClick={() => setActiveTab('scan')}>Passive</button>
        <button className={activeTab === 'dom' ? ACTIVE_TAB : INACTIVE_TAB} onClick={() => setActiveTab('dom')}>DOM &amp; Storage</button>
        <button className={activeTab === 'history' ? ACTIVE_TAB : INACTIVE_TAB} onClick={() => setActiveTab('history')}>History</button>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto pr-1 flex flex-col gap-2">

        {/* ---- Passive Scan Tab ---- */}
        {activeTab === 'scan' && (
          <>
            {Object.keys(groupedPassive).length === 0 ? (
              <p className="text-xs text-[var(--color-wvs-success)]">✓ No passive vulnerabilities detected</p>
            ) : (
              Object.entries(groupedPassive).map(([cat, findings]) => (
                <OWASPSection key={cat} category={cat} findings={findings} />
              ))
            )}
          </>
        )}

        {/* ---- DOM & Storage Tab ---- */}
        {activeTab === 'dom' && (
          <>
            {domOwaspGroup.length > 0 && (
              <OWASPSection category="A03:2021 – Injection (DOM XSS)" findings={domOwaspGroup} />
            )}
            {storageOwaspGroup.length > 0 && (
              <OWASPSection category="A07:2021 – Identification & Auth Failures (Storage)" findings={storageOwaspGroup} />
            )}
            {domOwaspGroup.length === 0 && storageOwaspGroup.length === 0 && (
              <p className="text-xs text-[var(--color-wvs-success)]">✓ No DOM or storage vulnerabilities detected</p>
            )}
          </>
        )}

        {/* ---- History Tab ---- */}
        {activeTab === 'history' && (
          <>
            {history.length === 0 ? (
              <p className="text-xs text-gray-400">No scan history yet. Browse some websites!</p>
            ) : (
              <div className="flex flex-col gap-3">
                {history.slice(0, 20).map((entry, i) => {
                  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                  entry.findings.forEach(f => { const c = getCvssClass(f.cvss); if (counts[c] !== undefined) counts[c]++; });
                  return (
                    <div key={i} className="bg-[var(--color-wvs-panel)] rounded p-2">
                      <div className="flex justify-between items-center mb-1">
                        <p className="text-xs font-semibold text-[var(--color-wvs-accent)] truncate max-w-[180px]">{entry.domain}</p>
                        <p className="text-[9px] text-gray-500">{new Date(entry.scanDate).toLocaleString()}</p>
                      </div>
                      <div className="flex gap-1 flex-wrap">
                        {(Object.entries(counts) as [string, number][]).filter(([, v]) => v > 0).map(([sev, count]) => (
                          <span key={sev} className={`text-[9px] px-1.5 py-0.5 rounded font-bold ${BADGE_COLORS[sev]}`}>{sev.toUpperCase()} ×{count}</span>
                        ))}
                        {entry.findings.length === 0 && <span className="text-[9px] text-green-400">✓ Clean</span>}
                      </div>
                    </div>
                  );
                })}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

export default App;
