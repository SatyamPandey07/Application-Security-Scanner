import React, { useState, useEffect } from 'react';
import { ShieldCheck, User, LogOut, Lock, LayoutDashboard, History, PlusCircle } from 'lucide-react';
import AuthModal from './components/AuthModal';
import ScanLauncher from './components/ScanLauncher';
import SecurityDashboard from './components/SecurityDashboard';
import ScanHistory from './components/ScanHistory';

export default function App() {
  const [token, setToken] = useState(localStorage.getItem('sentinel_token'));
  const [currentUser, setCurrentUser] = useState(null);
  const [isAuthOpen, setIsAuthOpen] = useState(false);
  const [activeTab, setActiveTab] = useState('launch'); // 'launch', 'dashboard', 'history'
  const [activeScanId, setActiveScanId] = useState(null);

  useEffect(() => {
    if (token) {
      fetch('/auth/me', {
        headers: { Authorization: `Bearer ${token}` },
      })
        .then((res) => {
          if (res.ok) return res.json();
          throw new Error('Token invalid');
        })
        .then((data) => setCurrentUser(data))
        .catch(() => {
          localStorage.removeItem('sentinel_token');
          setToken(null);
          setCurrentUser(null);
        });
    }
  }, [token]);

  const handleLogout = () => {
    localStorage.removeItem('sentinel_token');
    setToken(null);
    setCurrentUser(null);
  };

  const handleSelectScan = (scanId) => {
    setActiveScanId(scanId);
    setActiveTab('dashboard');
  };

  return (
    <div className="min-h-screen bg-slate-900 text-slate-100 flex flex-col">
      {/* Header */}
      <header className="border-b border-slate-800 bg-slate-950/50 backdrop-blur px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-6">
          <div className="flex items-center gap-3">
            <ShieldCheck className="w-8 h-8 text-emerald-400" />
            <h1 className="text-xl font-bold tracking-tight text-white">Sentinel</h1>
            <span className="text-xs px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
              v0.1.0 PR9 Report UI
            </span>
          </div>

          {currentUser && (
            <nav className="flex items-center gap-1 bg-slate-950 border border-slate-800 p-1 rounded-xl text-xs font-semibold">
              <button
                onClick={() => setActiveTab('launch')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors ${
                  activeTab === 'launch' ? 'bg-emerald-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                <PlusCircle className="w-3.5 h-3.5" />
                <span>New Scan</span>
              </button>
              <button
                onClick={() => setActiveTab('dashboard')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors ${
                  activeTab === 'dashboard' ? 'bg-emerald-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                <LayoutDashboard className="w-3.5 h-3.5" />
                <span>Dashboard</span>
              </button>
              <button
                onClick={() => setActiveTab('history')}
                className={`flex items-center gap-2 px-3 py-1.5 rounded-lg transition-colors ${
                  activeTab === 'history' ? 'bg-emerald-500 text-slate-950 font-bold' : 'text-slate-400 hover:text-white'
                }`}
              >
                <History className="w-3.5 h-3.5" />
                <span>History</span>
              </button>
            </nav>
          )}
        </div>

        <div>
          {currentUser ? (
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-900 border border-slate-800 text-xs">
                <User className="w-4 h-4 text-emerald-400" />
                <span className="text-slate-200 font-medium">{currentUser.email}</span>
                <span className="px-1.5 py-0.2 rounded bg-slate-800 text-slate-400 uppercase text-[10px]">
                  {currentUser.role}
                </span>
              </div>
              <button
                onClick={handleLogout}
                className="flex items-center gap-1.5 text-xs text-slate-400 hover:text-rose-400 transition-colors"
              >
                <LogOut className="w-4 h-4" />
                <span>Logout</span>
              </button>
            </div>
          ) : (
            <button
              onClick={() => setIsAuthOpen(true)}
              className="flex items-center gap-2 px-4 py-2 bg-emerald-500 hover:bg-emerald-600 font-semibold text-slate-950 rounded-lg text-xs transition-all"
            >
              <Lock className="w-3.5 h-3.5" />
              <span>Sign In / Register</span>
            </button>
          )}
        </div>
      </header>

      {/* Main Content */}
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
              <SecurityDashboard
                scanId={activeScanId || 1}
                token={token}
              />
            )}
            {activeTab === 'history' && (
              <ScanHistory
                token={token}
                onSelectScan={(scanId) => handleSelectScan(scanId)}
              />
            )}
          </div>
        ) : (
          <div className="flex flex-col items-center justify-center py-16 text-center">
            <div className="inline-flex items-center justify-center p-4 bg-emerald-500/10 text-emerald-400 rounded-full mb-6 ring-1 ring-emerald-500/20">
              <ShieldCheck className="w-12 h-12" />
            </div>
            <h2 className="text-3xl font-extrabold tracking-tight sm:text-4xl text-white mb-4">
              AI-Native Application Security Platform
            </h2>
            <p className="text-slate-400 max-w-2xl mb-8 text-lg">
              Sign in to run SAST, DAST, dependency, and secret scans with AI-remediated priority reports.
            </p>
            <button
              onClick={() => setIsAuthOpen(true)}
              className="px-6 py-3 bg-emerald-500 hover:bg-emerald-600 font-bold text-slate-950 rounded-xl text-sm transition-all"
            >
              Sign In / Create Account
            </button>
          </div>
        )}
      </main>

      <AuthModal
        isOpen={isAuthOpen}
        onClose={() => setIsAuthOpen(false)}
        onAuthSuccess={(newToken) => setToken(newToken)}
      />

      <footer className="border-t border-slate-800 py-4 px-6 text-center text-xs text-slate-500">
        Sentinel Platform &copy; 2026
      </footer>
    </div>
  );
}
