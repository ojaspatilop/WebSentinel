// @ts-nocheck
import { Shield, Zap, Eye, Database, ChevronRight, Lock, Activity, Globe } from 'lucide-react';

const FEATURES = [
    {
        icon: Eye,
        title: 'Passive Scanning',
        desc: 'Silently analyses security headers, cookies, server banners, and outdated JS libraries on every page — without sending a single malicious request.',
        color: 'from-cyan-500 to-blue-600',
    },
    {
        icon: Zap,
        title: 'DOM XSS Hooking',
        desc: 'Injects a taint-tracking engine into the MAIN JavaScript world to intercept innerHTML, eval and other dangerous sinks as they execute.',
        color: 'from-yellow-400 to-orange-500',
    },
    {
        icon: Shield,
        title: 'OWASP Top 10 (2021)',
        desc: 'Every finding is mapped to an OWASP category and a CVSS 3.1 score — giving you industry-standard severity ratings at a glance.',
        color: 'from-purple-500 to-pink-600',
    },
    {
        icon: Database,
        title: 'Vulnerable Libraries',
        desc: 'Detects known-vulnerable versions of jQuery, Bootstrap, AngularJS, lodash, moment.js, and more, using a built-in CVE database.',
        color: 'from-green-400 to-emerald-600',
    },
    {
        icon: Lock,
        title: 'Cookie & Auth Analysis',
        desc: 'Uses the chrome.cookies API to accurately flag every cookie missing HttpOnly, Secure, or SameSite — not just what the headers say.',
        color: 'from-red-400 to-rose-600',
    },
    {
        icon: Activity,
        title: 'Scan History',
        desc: 'Persists scan history for every domain you visit with severity breakdowns, timestamps, and one-click JSON export.',
        color: 'from-indigo-400 to-violet-600',
    },
];

const OWASP = [
    { id: 'A01', label: 'Broken Access Control' },
    { id: 'A02', label: 'Cryptographic Failures' },
    { id: 'A03', label: 'Injection (XSS)' },
    { id: 'A05', label: 'Security Misconfiguration' },
    { id: 'A06', label: 'Vulnerable Components' },
    { id: 'A07', label: 'Auth Failures' },
];

export default function Landing({ onEnter }: { onEnter: () => void }) {
    return (
        <div className="min-h-screen bg-[#050a10] text-white overflow-x-hidden font-sans">
            {/* ── Ambient glow background ── */}
            <div className="pointer-events-none fixed inset-0 overflow-hidden">
                <div className="absolute -top-40 -left-40 w-[600px] h-[600px] rounded-full bg-cyan-600/10 blur-[120px]" />
                <div className="absolute top-1/2 -right-40 w-[500px] h-[500px] rounded-full bg-purple-600/10 blur-[120px]" />
                <div className="absolute bottom-0 left-1/3 w-[400px] h-[400px] rounded-full bg-blue-600/8 blur-[120px]" />
            </div>

            {/* ── Nav ── */}
            <nav className="relative z-10 flex items-center justify-between px-8 py-5 border-b border-white/5">
                <div className="flex items-center gap-2.5">
                    <Shield className="text-cyan-400" size={22} />
                    <span className="text-lg font-bold tracking-tight">WebSentinel</span>
                    <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-900/60 text-cyan-400 font-mono border border-cyan-800/50">v2.0</span>
                </div>
                <div className="flex items-center gap-3">
                    <a href="https://owasp.org/Top10/" target="_blank" rel="noreferrer" className="text-xs text-gray-400 hover:text-white transition flex items-center gap-1"><Globe size={13} /> OWASP Top 10</a>
                    <button
                        onClick={onEnter}
                        className="text-xs px-4 py-2 bg-cyan-500 hover:bg-cyan-400 text-black font-bold rounded-full transition-all shadow-lg shadow-cyan-500/20"
                    >
                        Launch Dashboard
                    </button>
                </div>
            </nav>

            {/* ── Hero ── */}
            <section className="relative z-10 flex flex-col items-center justify-center text-center px-6 pt-28 pb-20">
                <div className="inline-flex items-center gap-2 text-[10px] font-mono px-3 py-1.5 rounded-full border border-cyan-800/60 bg-cyan-950/40 text-cyan-400 mb-8 animate-pulse">
                    <span className="w-1.5 h-1.5 rounded-full bg-cyan-400 inline-block" />
                    OWASP Top 10 (2021) Aligned · Passive + DOM XSS · CVSS 3.1 Scored
                </div>
                <h1 className="text-5xl md:text-7xl font-black leading-tight tracking-tighter max-w-4xl mb-6">
                    <span className="bg-gradient-to-r from-cyan-400 via-blue-400 to-purple-400 bg-clip-text text-transparent">
                        WebSentinel
                    </span>{' '}—{' '}Browser-Native{' '}Web Vulnerability Scanner
                </h1>
                <p className="text-gray-400 max-w-xl text-base md:text-lg leading-relaxed mb-10">
                    WebSentinel is a Chrome extension acting as your personal security analyst — passively scanning every page you visit for OWASP Top 10 vulnerabilities using CVSS 3.1 scoring, DOM taint tracking, and a built-in CVE database.
                </p>
                <div className="flex items-center gap-4">
                    <button
                        onClick={onEnter}
                        className="group flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-bold rounded-full text-sm shadow-xl shadow-cyan-500/30 hover:shadow-cyan-500/50 transition-all hover:scale-105"
                    >
                        Open Command Center
                        <ChevronRight size={15} className="group-hover:translate-x-1 transition-transform" />
                    </button>
                    <a
                        href="https://owasp.org/Top10/"
                        target="_blank"
                        rel="noreferrer"
                        className="text-sm text-gray-400 hover:text-white transition"
                    >
                        Learn about OWASP →
                    </a>
                </div>

                {/* OWASP pills */}
                <div className="flex flex-wrap justify-center gap-2 mt-14 max-w-2xl">
                    {OWASP.map(o => (
                        <span key={o.id} className="text-[11px] font-mono px-3 py-1 rounded-full border border-white/10 bg-white/5 text-gray-400">
                            <span className="text-cyan-400">{o.id}</span> {o.label}
                        </span>
                    ))}
                </div>
            </section>

            {/* ── Feature Grid ── */}
            <section className="relative z-10 max-w-6xl mx-auto px-6 py-16">
                <h2 className="text-2xl md:text-3xl font-bold text-center mb-2">Six Detection Engines. Zero Configuration.</h2>
                <p className="text-gray-500 text-center text-sm mb-12">WebSentinel runs all checks passively in the background as you browse.</p>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
                    {FEATURES.map(({ icon: Icon, title, desc, color }) => (
                        <div
                            key={title}
                            className="group relative rounded-2xl border border-white/8 bg-white/3 p-6 hover:border-white/20 hover:bg-white/6 transition-all duration-300 overflow-hidden"
                        >
                            <div className={`absolute inset-0 opacity-0 group-hover:opacity-100 transition-opacity bg-gradient-to-br ${color} blur-3xl`} style={{ opacity: 0.04 }} />
                            <div className={`w-10 h-10 rounded-xl bg-gradient-to-br ${color} flex items-center justify-center mb-4 shadow-lg`}>
                                <Icon size={18} className="text-white" />
                            </div>
                            <h3 className="font-bold text-sm mb-2">{title}</h3>
                            <p className="text-gray-500 text-xs leading-relaxed">{desc}</p>
                        </div>
                    ))}
                </div>
            </section>

            {/* ── CTA Banner ── */}
            <section className="relative z-10 max-w-3xl mx-auto px-6 py-10 mb-16">
                <div className="rounded-2xl border border-cyan-800/40 bg-gradient-to-br from-cyan-950/60 to-blue-950/60 p-10 text-center shadow-2xl shadow-cyan-900/20">
                    <h2 className="text-2xl font-bold mb-3">Ready to Explore Your Results?</h2>
                    <p className="text-gray-400 text-sm mb-6">All WebSentinel findings, OWASP-grouped charts, and scan history are waiting in the Command Center.</p>
                    <button
                        onClick={onEnter}
                        className="inline-flex items-center gap-2 px-7 py-3 bg-gradient-to-r from-cyan-500 to-blue-600 text-black font-bold rounded-full text-sm shadow-lg hover:scale-105 transition-all"
                    >
                        Launch Command Center <ChevronRight size={15} />
                    </button>
                </div>
            </section>

            {/* ── Footer ── */}
            <footer className="relative z-10 border-t border-white/5 py-6 text-center text-xs text-gray-600">
                WebSentinel — Browser-Native Web Vulnerability Scanner · OWASP Top 10 (2021) Aligned · CVSS 3.1 Scored
            </footer>
        </div>
    );
}
