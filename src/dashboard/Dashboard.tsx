// @ts-nocheck
import { useState, useEffect } from 'react';
import {
    Shield, Activity, Clock, Database, BookOpen, Home,
    Download, Search, ExternalLink, AlertTriangle,
    CheckCircle, Info, XCircle, FileText
} from 'lucide-react';
import {
    ResponsiveContainer, PieChart, Pie, Cell, Tooltip,
    BarChart, Bar, XAxis, YAxis, CartesianGrid, Legend
} from 'recharts';
import { exportAsPDF, riskLabel, owaspExplain, remediationHint } from './report';

// ─── Types ───────────────────────────────────────────────────────────
interface Finding {
    title: string; severity: string; cvss: string | number;
    details: string; owasp_category: string;
}
interface DOMFinding { type: string; payload?: string; url?: string; timestamp?: number; }
interface StorageFinding { type: string; key: string; issue: string; valuePreview: string; }
interface HistoryEntry { domain: string; scanDate: string; findings: Finding[]; }

// ─── Helpers ─────────────────────────────────────────────────────────
function cvssClass(v: number) {
    if (v >= 9) return 'critical'; if (v >= 7) return 'high';
    if (v >= 4) return 'medium'; if (v > 0) return 'low'; return 'info';
}
const SEV = {
    critical: { bg: 'bg-red-900/60', text: 'text-red-300', dot: '#ef4444', border: 'border-red-800/50' },
    high: { bg: 'bg-orange-900/60', text: 'text-orange-300', dot: '#f97316', border: 'border-orange-800/50' },
    medium: { bg: 'bg-yellow-900/60', text: 'text-yellow-300', dot: '#eab308', border: 'border-yellow-800/50' },
    low: { bg: 'bg-green-900/60', text: 'text-green-300', dot: '#22c55e', border: 'border-green-800/50' },
    info: { bg: 'bg-blue-900/60', text: 'text-blue-300', dot: '#3b82f6', border: 'border-blue-800/50' },
};

function Badge({ sev }: { sev: string }) {
    const s = SEV[sev] ?? SEV.info;
    return <span className={`text-[9px] font-bold px-2 py-0.5 rounded-full border ${s.bg} ${s.text} ${s.border}`}>{sev.toUpperCase()}</span>;
}

const PIE_COLORS: Record<string, string> = {
    critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#3b82f6',
};

// ─── Top-level data aggregation ──────────────────────────────────────
function useStorageData() {
    const [all, setAll] = useState<{
        passive: Finding[]; dom: DOMFinding[]; storage: StorageFinding[]; history: HistoryEntry[];
    }>({ passive: [], dom: [], storage: [], history: [] });

    useEffect(() => {
        function load() {
            chrome.storage.local.get(['findings', 'DOMFindings', 'StorageFindings', 'scanHistory'], (r) => {
                const passive: Finding[] = [];
                const dom: DOMFinding[] = [];
                const storage: StorageFinding[] = [];
                Object.values(r.findings || {}).forEach((hf: any) => { (hf?.passive || []).forEach(f => passive.push(f)); });
                Object.values(r.DOMFindings || {}).forEach((arr: any) => { arr.forEach(f => dom.push(f)); });
                Object.values(r.StorageFindings || {}).forEach((arr: any) => { arr.forEach(f => storage.push(f)); });
                const history = ((r.scanHistory || []) as HistoryEntry[]).sort(
                    (a, b) => new Date(b.scanDate).getTime() - new Date(a.scanDate).getTime()
                );
                setAll({ passive, dom, storage, history });
            });
        }
        load();
        const t = setInterval(load, 3000);
        return () => clearInterval(t);
    }, []);

    return all;
}

// ─── Sidebar ─────────────────────────────────────────────────────────
const NAV = [
    { id: 'overview', label: 'Overview', icon: Home },
    { id: 'findings', label: 'All Findings', icon: Activity },
    { id: 'history', label: 'Scan History', icon: Clock },
    { id: 'vulndb', label: 'Vuln Database', icon: BookOpen },
];

function Sidebar({ active, onChange }: { active: string; onChange: (v: string) => void }) {
    return (
        <aside className="w-56 shrink-0 h-screen sticky top-0 border-r border-white/5 bg-[#080d14] flex flex-col">
            <div className="flex items-center gap-2.5 px-5 py-5 border-b border-white/5">
                <Shield className="text-cyan-400" size={20} />
                <span className="font-bold text-sm tracking-tight">WebSentinel</span>
                <span className="ml-auto text-[9px] px-1.5 py-0.5 bg-cyan-900/50 text-cyan-400 rounded-full font-mono border border-cyan-800/40">v2.0</span>
            </div>
            <nav className="flex-1 px-3 py-4 space-y-0.5">
                {NAV.map(({ id, label, icon: Icon }) => (
                    <button
                        key={id}
                        onClick={() => onChange(id)}
                        className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-xl text-xs font-medium transition-all ${active === id
                            ? 'bg-cyan-900/40 text-cyan-400 border border-cyan-800/40'
                            : 'text-gray-500 hover:text-white hover:bg-white/5'
                            }`}
                    >
                        <Icon size={15} />
                        {label}
                    </button>
                ))}
            </nav>
            <div className="px-4 pb-5">
                <p className="text-[10px] text-gray-700 text-center">OWASP Top 10 (2021)</p>
            </div>
        </aside>
    );
}

// ─── Overview Tab ────────────────────────────────────────────────────
function Overview({ passive, dom, storage, history }: any) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    passive.forEach(f => { const c = cvssClass(parseFloat(String(f.cvss))); if (c in counts) counts[c]++; });
    dom.forEach(() => counts.high++);
    storage.forEach(() => counts.medium++);

    const pieData = Object.entries(counts).filter(([, v]) => v > 0).map(([name, value]) => ({ name, value }));

    const topDomains = history.slice(0, 6).map((h: HistoryEntry) => ({
        domain: h.domain.length > 16 ? h.domain.slice(0, 16) + '…' : h.domain,
        findings: h.findings.length,
    }));

    const total = Object.values(counts).reduce((a, b) => a + b, 0);

    return (
        <div className="space-y-6">
            <div>
                <h1 className="text-xl font-bold mb-0.5">Overview</h1>
                <p className="text-gray-500 text-xs">Live summary of all findings across all scanned domains.</p>
            </div>

            {/* Stat Cards */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                {[
                    { label: 'Total Issues', value: total, icon: AlertTriangle, color: 'text-red-400' },
                    { label: 'Domains Scanned', value: history.length, icon: Activity, color: 'text-cyan-400' },
                    { label: 'Critical / High', value: counts.critical + counts.high, icon: XCircle, color: 'text-orange-400' },
                    { label: 'Info Findings', value: counts.info + counts.low, icon: Info, color: 'text-blue-400' },
                ].map(({ label, value, icon: Icon, color }) => (
                    <div key={label} className="rounded-xl border border-white/8 bg-white/3 p-4 hover:border-white/15 transition">
                        <div className="flex items-center justify-between mb-3">
                            <p className="text-[11px] text-gray-500">{label}</p>
                            <Icon size={14} className={color} />
                        </div>
                        <p className="text-3xl font-black">{value}</p>
                    </div>
                ))}
            </div>

            {/* Charts Row */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {/* Severity Donut */}
                <div className="rounded-xl border border-white/8 bg-white/3 p-5">
                    <h2 className="text-xs font-bold mb-4 text-gray-300">Severity Distribution</h2>
                    {pieData.length === 0
                        ? <p className="text-xs text-green-400 flex items-center gap-2"><CheckCircle size={13} /> No findings yet — browse some sites!</p>
                        : (
                            <ResponsiveContainer width="100%" height={220}>
                                <PieChart>
                                    <Pie data={pieData} cx="35%" cy="50%" innerRadius={55} outerRadius={80} paddingAngle={3} dataKey="value">
                                        {pieData.map(entry => <Cell key={entry.name} fill={PIE_COLORS[entry.name] ?? '#666'} />)}
                                    </Pie>
                                    <Tooltip
                                        contentStyle={{ background: '#0d1520', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 11 }}
                                        formatter={(v, name) => [v, name.toUpperCase()]}
                                    />
                                    <Legend
                                        layout="vertical" align="right" verticalAlign="middle"
                                        formatter={(v) => <span className="text-[10px] text-gray-400">{v.toUpperCase()}</span>}
                                    />
                                </PieChart>
                            </ResponsiveContainer>
                        )}
                </div>

                {/* Findings per Domain Bar Chart */}
                <div className="rounded-xl border border-white/8 bg-white/3 p-5">
                    <h2 className="text-xs font-bold mb-4 text-gray-300">Top Scanned Domains</h2>
                    {topDomains.length === 0
                        ? <p className="text-xs text-gray-600 mt-8 text-center">No history yet.</p>
                        : (
                            <ResponsiveContainer width="100%" height={220}>
                                <BarChart data={topDomains} margin={{ top: 0, right: 0, left: -20, bottom: 0 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
                                    <XAxis dataKey="domain" tick={{ fill: '#6b7280', fontSize: 9 }} />
                                    <YAxis tick={{ fill: '#6b7280', fontSize: 9 }} allowDecimals={false} />
                                    <Tooltip
                                        contentStyle={{ background: '#0d1520', border: '1px solid rgba(255,255,255,0.1)', borderRadius: 8, fontSize: 11 }}
                                    />
                                    <Bar dataKey="findings" fill="#22d3ee" radius={[4, 4, 0, 0]} />
                                </BarChart>
                            </ResponsiveContainer>
                        )}
                </div>
            </div>
        </div>
    );
}

// ─── All Findings Tab ─────────────────────────────────────────────────
function FindingsTab({ passive, dom, storage }: any) {
    const [search, setSearch] = useState('');
    const [severityFilter, setSeverityFilter] = useState('all');

    const allFindings = [
        ...passive.map(f => ({ ...f, source: 'Passive' })),
        ...dom.map(f => ({
            title: f.type, severity: 'High', cvss: '7.5',
            details: f.payload || '', owasp_category: 'A03:2021 – Injection',
            source: 'DOM XSS', url: f.url,
        })),
        ...storage.map(f => ({
            title: `Exposed Secret: ${f.key}`, severity: 'Medium', cvss: '5.3',
            details: f.issue, owasp_category: 'A07:2021 – Auth Failures',
            source: 'Storage',
        })),
    ];

    const filtered = allFindings.filter(f => {
        const matchSearch = !search || f.title?.toLowerCase().includes(search.toLowerCase()) || f.owasp_category?.toLowerCase().includes(search.toLowerCase());
        const matchSev = severityFilter === 'all' || f.severity?.toLowerCase() === severityFilter;
        return matchSearch && matchSev;
    });

    return (
        <div className="space-y-4">
            <div className="flex items-end justify-between">
                <div>
                    <h1 className="text-xl font-bold mb-0.5">All Findings</h1>
                    <p className="text-gray-500 text-xs">{filtered.length} findings across all domains</p>
                </div>
                <button
                    onClick={() => exportAsPDF({ domain: 'all scanned domains', passive, dom, storage })}
                    className="flex items-center gap-1.5 text-xs px-3 py-2 bg-gradient-to-r from-rose-900/60 to-orange-900/60 hover:from-rose-800/80 hover:to-orange-800/80 border border-rose-800/40 rounded-xl transition text-orange-200 font-semibold"
                >
                    <FileText size={12} /> Export PDF Report
                </button>
            </div>

            <div className="flex gap-3 flex-wrap">
                <div className="relative flex-1 min-w-[200px]">
                    <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                    <input
                        className="w-full pl-8 pr-3 py-2 rounded-xl bg-white/5 border border-white/8 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-cyan-700"
                        placeholder="Search findings by title or OWASP category…"
                        value={search}
                        onChange={e => setSearch(e.target.value)}
                    />
                </div>
                <select
                    value={severityFilter}
                    onChange={e => setSeverityFilter(e.target.value)}
                    className="px-3 py-2 bg-white/5 border border-white/8 rounded-xl text-xs text-gray-300 focus:outline-none focus:border-cyan-700"
                >
                    {['all', 'critical', 'high', 'medium', 'low', 'info'].map(s => (
                        <option key={s} value={s}>{s.charAt(0).toUpperCase() + s.slice(1)}</option>
                    ))}
                </select>
            </div>

            {filtered.length === 0
                ? <p className="text-xs text-green-400 flex items-center gap-2 py-8"><CheckCircle size={13} /> No findings match your filters.</p>
                : (
                    <div className="rounded-xl border border-white/8 overflow-hidden">
                        <table className="w-full text-xs">
                            <thead>
                                <tr className="border-b border-white/8 bg-white/3">
                                    <th className="text-left px-4 py-3 text-gray-500 font-semibold">Title</th>
                                    <th className="text-left px-4 py-3 text-gray-500 font-semibold">OWASP</th>
                                    <th className="text-center px-4 py-3 text-gray-500 font-semibold">Severity</th>
                                    <th className="text-center px-4 py-3 text-gray-500 font-semibold">CVSS</th>
                                    <th className="text-center px-4 py-3 text-gray-500 font-semibold">Source</th>
                                </tr>
                            </thead>
                            <tbody>
                                {filtered.map((f, i) => {
                                    const cl = cvssClass(parseFloat(String(f.cvss)));
                                    const risk = riskLabel(f.cvss);
                                    const oTip = owaspExplain(f.owasp_category || '');
                                    const hint = remediationHint(f.title || '');
                                    const [expanded, setExpanded] = useState(false);
                                    return (
                                        <>
                                            <tr key={i} className="border-b border-white/5 hover:bg-white/3 transition cursor-pointer" onClick={() => setExpanded(e => !e)}>
                                                <td className="px-4 py-3 max-w-[260px]">
                                                    <p className="font-medium truncate" title={f.title}>{f.title}</p>
                                                    {f.details && (
                                                        <p className="text-gray-600 text-[10px] truncate" title={f.details}
                                                            dangerouslySetInnerHTML={{ __html: f.details.replace(/<[^>]+>/g, '') }} />
                                                    )}
                                                </td>
                                                <td className="px-4 py-3 text-gray-500 text-[10px]">{f.owasp_category}</td>
                                                <td className="px-4 py-3 text-center"><Badge sev={cl} /></td>
                                                <td className="px-4 py-3 text-center font-mono text-[11px]" style={{ color: PIE_COLORS[cl] }}>{f.cvss}</td>
                                                <td className="px-4 py-3 text-center">
                                                    <span className="px-2 py-0.5 text-[9px] rounded bg-white/8 text-gray-400 font-mono">{f.source}</span>
                                                </td>
                                            </tr>
                                            {expanded && (
                                                <tr className="bg-white/2 border-b border-white/5">
                                                    <td colSpan={5} className="px-4 py-3">
                                                        <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                                            <div className="rounded-lg bg-blue-950/40 border border-blue-900/40 p-3">
                                                                <p className="text-[10px] font-bold text-cyan-400 mb-1">🗣 What does this mean?</p>
                                                                <p className="text-[11px] text-gray-300 leading-relaxed">{oTip}</p>
                                                            </div>
                                                            <div className="rounded-lg bg-green-950/40 border border-green-900/40 p-3">
                                                                <p className="text-[10px] font-bold text-green-400 mb-1">✅ What should you do?</p>
                                                                <p className="text-[11px] text-gray-300 leading-relaxed">{hint}</p>
                                                            </div>
                                                        </div>
                                                    </td>
                                                </tr>
                                            )}
                                        </>
                                    );
                                })}
                            </tbody>
                        </table>
                    </div>
                )}
        </div>
    );
}

// ─── History Tab ─────────────────────────────────────────────────────
function HistoryTab({ history }: { history: HistoryEntry[] }) {
    const [search, setSearch] = useState('');
    const filtered = history.filter(h => !search || h.domain.includes(search));

    function exportCSV() {
        const rows = [['Domain', 'Scan Date', 'Total Findings', 'Critical', 'High', 'Medium', 'Low', 'Info']];
        filtered.forEach(h => {
            const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
            h.findings.forEach(f => { const cl = cvssClass(parseFloat(String(f.cvss))); if (cl in c) c[cl]++; });
            rows.push([h.domain, h.scanDate, h.findings.length, c.critical, c.high, c.medium, c.low, c.info]);
        });
        const csv = rows.map(r => r.join(',')).join('\n');
        const blob = new Blob([csv], { type: 'text/csv' });
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
        a.download = 'WVS-History.csv'; a.click();
    }

    return (
        <div className="space-y-4">
            <div className="flex items-end justify-between">
                <div>
                    <h1 className="text-xl font-bold mb-0.5">Scan History</h1>
                    <p className="text-gray-500 text-xs">{history.length} domains scanned</p>
                </div>
                <button onClick={exportCSV} className="flex items-center gap-1.5 text-xs px-3 py-2 bg-white/5 hover:bg-white/10 border border-white/8 rounded-xl transition">
                    <Download size={12} /> Export CSV
                </button>
            </div>
            <div className="relative">
                <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                    className="w-full pl-8 pr-3 py-2 rounded-xl bg-white/5 border border-white/8 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-cyan-700"
                    placeholder="Search domains…"
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                />
            </div>
            {filtered.length === 0
                ? <p className="text-xs text-gray-500 py-8 text-center">No history yet — browse websites with the extension active.</p>
                : (
                    <div className="space-y-2">
                        {filtered.map((h, i) => {
                            const c = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
                            h.findings.forEach(f => { const cl = cvssClass(parseFloat(String(f.cvss))); if (cl in c) c[cl]++; });
                            return (
                                <div key={i} className="rounded-xl border border-white/8 bg-white/3 p-4 hover:border-white/15 transition">
                                    <div className="flex justify-between items-start mb-2">
                                        <div>
                                            <a href={`https://${h.domain}`} target="_blank" rel="noreferrer"
                                                className="text-sm font-semibold text-cyan-400 hover:underline flex items-center gap-1">
                                                {h.domain} <ExternalLink size={10} />
                                            </a>
                                            <p className="text-[10px] text-gray-600">{new Date(h.scanDate).toLocaleString()}</p>
                                        </div>
                                        <span className="text-[10px] text-gray-500">{h.findings.length} findings</span>
                                    </div>
                                    <div className="flex gap-1.5 flex-wrap">
                                        {Object.entries(c).filter(([, v]) => v > 0).map(([sev, cnt]) => (
                                            <span key={sev} className={`text-[9px] px-2 py-0.5 rounded-full border font-bold ${SEV[sev].bg} ${SEV[sev].text} ${SEV[sev].border}`}>
                                                {sev.toUpperCase()} ×{cnt}
                                            </span>
                                        ))}
                                        {h.findings.length === 0 && <span className="text-[9px] text-green-400">✓ Clean</span>}
                                    </div>
                                </div>
                            );
                        })}
                    </div>
                )}
        </div>
    );
}

// ─── Vuln DB Tab ─────────────────────────────────────────────────────
function VulnDBTab() {
    const [db, setDb] = useState<any>(null);
    const [search, setSearch] = useState('');
    useEffect(() => {
        fetch(chrome.runtime.getURL('vuln_db.json')).then(r => r.json()).then(setDb);
    }, []);

    const libs = db?.javascript_libraries ?? [];
    const filtered = libs.filter(l => !search || l.name.toLowerCase().includes(search.toLowerCase()));

    return (
        <div className="space-y-4">
            <div>
                <h1 className="text-xl font-bold mb-0.5">Vulnerability Database</h1>
                <p className="text-gray-500 text-xs">Built-in library CVE database used for passive detection.</p>
            </div>
            <div className="relative">
                <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
                <input
                    className="w-full pl-8 pr-3 py-2 rounded-xl bg-white/5 border border-white/8 text-xs text-white placeholder-gray-600 focus:outline-none focus:border-cyan-700"
                    placeholder="Search library name…"
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                />
            </div>
            {!db ? <p className="text-xs text-gray-500">Loading database…</p> :
                <div className="space-y-3">
                    {filtered.map(lib => (
                        <div key={lib.name} className="rounded-xl border border-white/8 bg-white/3 p-4 hover:border-white/15 transition">
                            <h3 className="text-sm font-bold text-white mb-1">{lib.name}</h3>
                            <div className="space-y-1.5 mt-2">
                                {lib.versions.map((v: any) => (
                                    <div key={v.version} className="flex items-start gap-3 p-2.5 rounded-lg bg-white/3 border border-white/5">
                                        <div className="shrink-0 pt-0.5">
                                            <Badge sev={cvssClass(parseFloat(v.cvss))} />
                                        </div>
                                        <div className="min-w-0">
                                            <p className="text-[11px] font-mono text-cyan-400 mb-0.5">{lib.name}@{v.version}</p>
                                            <p className="text-[10px] text-gray-500 leading-relaxed">{v.vulnerability}</p>
                                            <p className="text-[10px] text-gray-600 mt-1"><span className="text-green-500">Fix:</span> {v.remediation}</p>
                                        </div>
                                        <span className="shrink-0 font-mono text-[10px] text-gray-500 pt-0.5">CVSS {v.cvss}</span>
                                    </div>
                                ))}
                            </div>
                        </div>
                    ))}
                </div>
            }
        </div>
    );
}

// ─── Main Dashboard ───────────────────────────────────────────────────
export default function Dashboard() {
    const [activeTab, setActiveTab] = useState('overview');
    const { passive, dom, storage, history } = useStorageData();

    return (
        <div className="flex h-screen bg-[#050a10] text-white overflow-hidden font-sans">
            {/* Sidebar */}
            <Sidebar active={activeTab} onChange={setActiveTab} />

            {/* Main area */}
            <main className="flex-1 overflow-y-auto">
                {/* Header */}
                <header className="sticky top-0 z-10 flex items-center justify-between px-8 py-4 border-b border-white/5 bg-[#050a10]/80 backdrop-blur">
                    <p className="text-xs text-gray-500 font-mono">websentinel / command center</p>
                    <div className="flex items-center gap-2">
                        <span className="text-[10px] px-2 py-1 rounded-full bg-green-900/50 text-green-400 border border-green-800/40 flex items-center gap-1">
                            <span className="w-1.5 h-1.5 rounded-full bg-green-400 inline-block animate-pulse" />
                            Live
                        </span>
                        <span className="text-[10px] text-gray-600 font-mono">{passive.length + dom.length + storage.length} total issues</span>
                    </div>
                </header>

                <div className="px-8 py-6 max-w-6xl">
                    {activeTab === 'overview' && <Overview passive={passive} dom={dom} storage={storage} history={history} />}
                    {activeTab === 'findings' && <FindingsTab passive={passive} dom={dom} storage={storage} />}
                    {activeTab === 'history' && <HistoryTab history={history} />}
                    {activeTab === 'vulndb' && <VulnDBTab />}
                </div>
            </main>
        </div>
    );
}
