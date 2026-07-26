import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  User,
  LogOut,
  Lock,
  LayoutDashboard,
  History,
  PlusCircle,
  FileCheck2,
  TrendingUp,
  ChevronDown,
} from 'lucide-react';
import AuthModal from './components/AuthModal';
import ScanLauncher from './components/ScanLauncher';
import SecurityDashboard from './components/SecurityDashboard';
import ScanHistory from './components/ScanHistory';
import ComplianceSummary from './components/ComplianceSummary';
import TrendView from './components/TrendView';

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('sentinel_token'));
  const [currentUser, setCurrentUser] = useState(null);
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('launch');
  const [activeScanId, setActiveScanId] = useState(null);
  const [userMenuOpen, setUserMenuOpen] = useState(false);

  // Validate token and fetch current user on mount / token change
  useEffect(() => {
    if (token) {
      fetch('/auth/me', { headers: { Authorization: `Bearer ${token}` } })
        .then((res) => {
          if (res.ok) return res.json();
          throw new Error('Token invalid or expired');
        })
        .then((data) => setCurrentUser(data))
        .catch(() => {
          localStorage.removeItem('sentinel_token');
          setToken(null);
          setCurrentUser(null);
        });
    } else {
      setCurrentUser(null);
    }
  }, [token]);

  const handleAuthSuccess = (newToken) => {
    localStorage.setItem('sentinel_token', newToken);
    setToken(newToken);
  };

  const handleLogout = () => {
    localStorage.removeItem('sentinel_token');
    setToken(null);
    setCurrentUser(null);
    setActiveTab('launch');
    setActiveScanId(null);
    setUserMenuOpen(false);
  };

  const handleSelectScan = (scanId) => {
    setActiveScanId(scanId);
    setActiveTab('dashboard');
  };

  const navItems = [
    { id: 'launch', label: 'New Scan', icon: PlusCircle },
    { id: 'dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { id: 'compliance', label: 'Compliance', icon: FileCheck2 },
    { id: 'trends', label: 'Trends', icon: TrendingUp },
    { id: 'history', label: 'History', icon: History },
  ];

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex flex-col">
      {/* ── Header ── */}
      <header className="border-b border-slate-800 bg-slate-950/70 backdrop-blur-md px-6 py-3.5 flex items-center justify-between sticky top-0 z-40">
        {/* Logo + Nav */}
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <div className="p-1.5 rounded-lg bg-emerald-500/10 ring-1 ring-emerald-500/20">
              <ShieldCheck className="w-6 h-6 text-emerald-400" />
            </div>
            <div>
              <h1 className="text-base font-bold tracking-tight text-white leading-none">Sentinel</h1>
              <span className="text-[10px] text-emerald-400/70 font-medium">AI Security Platform</span>
            </div>
          </div>

          {currentUser && (
            <nav className="flex items-center gap-0.5 bg-slate-900/80 border border-slate-800 p-1 rounded-xl">
              {navItems.map(({ id, label, icon: Icon }) => (
                <button
                  key={id}
                  onClick={() => setActiveTab(id)}
                  className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-semibold transition-all ${
                    activeTab === id
                      ? 'bg-emerald-500 text-slate-950 shadow-sm shadow-emerald-500/30'
                      : 'text-slate-400 hover:text-white hover:bg-slate-800/60'
                  }`}
                >
                  <Icon className="w-3.5 h-3.5" />
                  {label}
                </button>
              ))}
            </nav>
          )}
        </div>

        {/* Right: User or Sign In */}
        <div className="flex items-center gap-3">
          {currentUser ? (
            <div className="relative">
              <button
                onClick={() => setUserMenuOpen(!userMenuOpen)}
                className="flex items-center gap-2.5 px-3 py-2 rounded-xl bg-slate-900 border border-slate-800 hover:border-slate-700 transition-all text-sm"
              >
                <div className="w-7 h-7 rounded-lg bg-emerald-500/20 flex items-center justify-center ring-1 ring-emerald-500/30">
                  <User className="w-4 h-4 text-emerald-400" />
                </div>
                <div className="text-left hidden sm:block">
                  <p className="text-xs font-semibold text-white leading-none truncate max-w-[140px]">
                    {currentUser.email}
                  </p>
                  <p className="text-[10px] text-slate-500 mt-0.5 uppercase tracking-wider">
                    {currentUser.role}
                  </p>
                </div>
                <ChevronDown className={`w-3.5 h-3.5 text-slate-500 transition-transform ${userMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              {/* Dropdown */}
              {userMenuOpen && (
                <div
                  className="absolute right-0 top-full mt-2 w-52 rounded-xl shadow-xl py-1 z-50"
                  style={{ background: '#0f172a', border: '1px solid rgba(100,116,139,0.3)' }}
                >
                  <div className="px-4 py-3 border-b border-slate-800">
                    <p className="text-xs text-slate-400">Signed in as</p>
                    <p className="text-sm font-semibold text-white truncate">{currentUser.email}</p>
                  </div>
                  <button
                    onClick={handleLogout}
                    className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-slate-400 hover:text-rose-400 hover:bg-rose-500/5 transition-colors"
                  >
                    <LogOut className="w-4 h-4" />
                    Sign out
                  </button>
                </div>
              )}
            </div>
          ) : (
            <button
              onClick={() => setIsAuthOpen(true)}
              className="flex items-center gap-2 px-4 py-2.5 rounded-xl font-semibold text-slate-950 text-sm transition-all hover:scale-105 active:scale-95"
              style={{
                background: 'linear-gradient(135deg, #10b981, #059669)',
                boxShadow: '0 4px 20px rgba(16,185,129,0.3)',
              }}
            >
              <Lock className="w-3.5 h-3.5" />
              Sign In
            </button>
          )}
        </div>
      </header>

      {/* ── Main Content ── */}
      <main className="flex-1 max-w-6xl mx-auto w-full p-8">
        {currentUser ? (
          <div>
            {activeTab === 'launch' && (
              <ScanLauncher
                token={token}
                onScanLaunched={(scanId) => handleSelectScan(scanId)}
              />
            )}
            {activeTab === 'dashboard' && (
              <SecurityDashboard scanId={activeScanId || 1} token={token} />
            )}
            {activeTab === 'compliance' && (
              <ComplianceSummary scanId={activeScanId || 1} token={token} />
            )}
            {activeTab === 'trends' && <TrendView token={token} />}
            {activeTab === 'history' && (
              <ScanHistory
                token={token}
                onSelectScan={(scanId) => handleSelectScan(scanId)}
              />
            )}
          </div>
        ) : (
          /* ── Landing / Hero ── */
          <div className="flex flex-col items-center justify-center py-24 text-center">
            {/* Animated glow */}
            <div className="relative mb-8">
              <div className="absolute inset-0 rounded-full blur-3xl opacity-30 bg-emerald-500 scale-150" />
              <div className="relative inline-flex items-center justify-center w-24 h-24 rounded-3xl bg-gradient-to-br from-emerald-500/20 to-emerald-500/5 ring-1 ring-emerald-500/30">
                <ShieldCheck className="w-12 h-12 text-emerald-400" />
              </div>
            </div>

            <h2 className="text-4xl sm:text-5xl font-extrabold tracking-tight text-white mb-4">
              AI-Native Application
              <br />
              <span className="text-transparent bg-clip-text bg-gradient-to-r from-emerald-400 to-cyan-400">
                Security Scanner
              </span>
            </h2>
            <p className="text-slate-400 max-w-xl mb-3 text-lg">
              SAST · DAST · IDOR · Secret Detection · Dependency Analysis
            </p>
            <p className="text-slate-500 max-w-lg mb-10 text-sm">
              Powered by OWASP ZAP + AI remediation. Sign in with the demo account to explore all features instantly.
            </p>

            {/* Feature pills */}
            <div className="flex flex-wrap justify-center gap-2 mb-10">
              {['Zero-config DAST', 'AI Fix Suggestions', 'OWASP Compliance', 'GitHub Remediation', 'CVE Scoring'].map((f) => (
                <span
                  key={f}
                  className="text-xs px-3 py-1.5 rounded-full font-medium"
                  style={{
                    background: 'rgba(52,211,153,0.08)',
                    border: '1px solid rgba(52,211,153,0.2)',
                    color: '#6ee7b7',
                  }}
                >
                  {f}
                </span>
              ))}
            </div>

            {/* Demo credentials preview */}
            <div
              className="mb-8 px-6 py-4 rounded-2xl text-left w-full max-w-sm"
              style={{ background: 'rgba(251,191,36,0.06)', border: '1px solid rgba(251,191,36,0.2)' }}
            >
              <p className="text-amber-400 text-xs font-bold uppercase tracking-widest mb-3 flex items-center gap-1.5">
                ⚡ Instant Demo Access
              </p>
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Email</span>
                  <code className="text-slate-200">demo@sentinel.io</code>
                </div>
                <div className="flex justify-between text-xs">
                  <span className="text-slate-500">Password</span>
                  <code className="text-slate-200">SentinelDemo@2026</code>
                </div>
              </div>
            </div>

            <button
              onClick={() => setIsAuthOpen(true)}
              className="px-8 py-4 rounded-2xl font-bold text-slate-950 text-base transition-all hover:scale-105 active:scale-95"
              style={{
                background: 'linear-gradient(135deg, #10b981, #059669)',
                boxShadow: '0 8px 32px rgba(16,185,129,0.4)',
              }}
            >
              🚀 Get Started — It's Free
            </button>
          </div>
        )}
      </main>

      {/* Overlay to close user menu */}
      {userMenuOpen && (
        <div className="fixed inset-0 z-30" onClick={() => setUserMenuOpen(false)} />
      )}

      <AuthModal
        isOpen={isAuthOpen}
        onClose={() => setIsAuthOpen(false)}
        onAuthSuccess={handleAuthSuccess}
      />

      <footer className="border-t border-slate-800/60 py-4 px-6 text-center text-xs text-slate-600">
        Sentinel Platform © 2026 · AI-powered security for modern applications
      </footer>
    </div>
  );
}
