import React, { useState, useEffect } from 'react';
import {
  ShieldCheck,
  X,
  Mail,
  Lock,
  Eye,
  EyeOff,
  Zap,
  LogIn,
  UserPlus,
  Copy,
  CheckCheck,
  AlertCircle,
  Loader2,
} from 'lucide-react';

const DEMO_EMAIL = 'demo@sentinel.io';
const DEMO_PASSWORD = 'SentinelDemo@2026';

export default function AuthModal({ isOpen, onClose, onAuthSuccess }) {
  const [mode, setMode] = useState('login'); // 'login' | 'register'
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [copiedField, setCopiedField] = useState(null); // 'email' | 'password'

  // Reset form when modal opens
  useEffect(() => {
    if (isOpen) {
      setEmail('');
      setPassword('');
      setError('');
      setMode('login');
      setShowPassword(false);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const copyToClipboard = (text, field) => {
    navigator.clipboard.writeText(text);
    setCopiedField(field);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const fillDemo = () => {
    setEmail(DEMO_EMAIL);
    setPassword(DEMO_PASSWORD);
    setError('');
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      if (mode === 'register') {
        const res = await fetch('/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password }),
        });
        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.detail || 'Registration failed');
        }
        // After successful register, auto-login
        setMode('login');
      }

      // Login
      const params = new URLSearchParams();
      params.append('username', email);
      params.append('password', password);
      const loginRes = await fetch('/auth/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: params,
      });

      if (!loginRes.ok) {
        const data = await loginRes.json();
        throw new Error(data.detail || 'Login failed. Check your credentials.');
      }

      const { access_token } = await loginRes.json();
      localStorage.setItem('sentinel_token', access_token);
      onAuthSuccess(access_token);
      onClose();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
      style={{ background: 'rgba(0,0,0,0.75)', backdropFilter: 'blur(6px)' }}
      onClick={(e) => e.target === e.currentTarget && onClose()}
    >
      <div
        className="relative w-full max-w-md rounded-2xl overflow-hidden shadow-2xl"
        style={{
          background: 'linear-gradient(145deg, #0f172a 0%, #1e293b 100%)',
          border: '1px solid rgba(100,116,139,0.3)',
        }}
      >
        {/* Header */}
        <div className="px-8 pt-8 pb-6 text-center relative">
          <button
            onClick={onClose}
            className="absolute right-4 top-4 p-2 rounded-lg text-slate-500 hover:text-white hover:bg-slate-800 transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
          <div className="inline-flex items-center justify-center w-14 h-14 rounded-2xl bg-emerald-500/10 ring-1 ring-emerald-500/30 mb-4">
            <ShieldCheck className="w-8 h-8 text-emerald-400" />
          </div>
          <h2 className="text-2xl font-bold text-white tracking-tight">Sentinel Platform</h2>
          <p className="text-slate-400 text-sm mt-1">AI-Native Application Security Scanner</p>
        </div>

        {/* Demo Credentials Banner */}
        <div className="mx-6 mb-5 rounded-xl overflow-hidden" style={{ border: '1px solid rgba(251,191,36,0.3)' }}>
          <div
            className="flex items-center gap-2 px-4 py-2"
            style={{ background: 'rgba(251,191,36,0.1)' }}
          >
            <Zap className="w-4 h-4 text-amber-400 flex-shrink-0" />
            <span className="text-amber-300 text-xs font-bold uppercase tracking-widest">Demo Access</span>
            <button
              onClick={fillDemo}
              className="ml-auto text-xs px-3 py-1 rounded-lg font-semibold transition-all"
              style={{ background: 'rgba(251,191,36,0.2)', color: '#fbbf24', border: '1px solid rgba(251,191,36,0.4)' }}
            >
              Auto-fill ↗
            </button>
          </div>
          <div className="px-4 py-3 space-y-2" style={{ background: 'rgba(15,23,42,0.7)' }}>
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 min-w-0">
                <Mail className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                <code className="text-xs text-slate-200 truncate">{DEMO_EMAIL}</code>
              </div>
              <button
                onClick={() => copyToClipboard(DEMO_EMAIL, 'email')}
                className="p-1.5 rounded-md text-slate-500 hover:text-emerald-400 hover:bg-slate-800 transition-colors flex-shrink-0"
              >
                {copiedField === 'email' ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
            <div className="flex items-center justify-between gap-3">
              <div className="flex items-center gap-2 min-w-0">
                <Lock className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                <code className="text-xs text-slate-200 truncate">{DEMO_PASSWORD}</code>
              </div>
              <button
                onClick={() => copyToClipboard(DEMO_PASSWORD, 'password')}
                className="p-1.5 rounded-md text-slate-500 hover:text-emerald-400 hover:bg-slate-800 transition-colors flex-shrink-0"
              >
                {copiedField === 'password' ? <CheckCheck className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              </button>
            </div>
          </div>
        </div>

        {/* Tab Switcher */}
        <div className="mx-6 mb-6 grid grid-cols-2 gap-1 p-1 rounded-xl" style={{ background: 'rgba(15,23,42,0.8)', border: '1px solid rgba(100,116,139,0.2)' }}>
          <button
            onClick={() => { setMode('login'); setError(''); }}
            className={`flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold transition-all ${
              mode === 'login'
                ? 'bg-emerald-500 text-slate-950 shadow-lg'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <LogIn className="w-4 h-4" />
            Sign In
          </button>
          <button
            onClick={() => { setMode('register'); setError(''); }}
            className={`flex items-center justify-center gap-2 py-2.5 rounded-lg text-sm font-semibold transition-all ${
              mode === 'register'
                ? 'bg-emerald-500 text-slate-950 shadow-lg'
                : 'text-slate-400 hover:text-white'
            }`}
          >
            <UserPlus className="w-4 h-4" />
            Register
          </button>
        </div>

        {/* Form */}
        <form onSubmit={handleSubmit} className="px-6 pb-8 space-y-4">
          {/* Email */}
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-widest mb-2">
              Email Address
            </label>
            <div className="relative">
              <Mail className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type="email"
                required
                value={email}
                onChange={(e) => { setEmail(e.target.value); setError(''); }}
                placeholder="you@example.com"
                className="w-full pl-10 pr-4 py-3 rounded-xl text-sm text-white placeholder-slate-600 outline-none transition-all"
                style={{
                  background: 'rgba(15,23,42,0.8)',
                  border: '1px solid rgba(100,116,139,0.3)',
                }}
                onFocus={(e) => { e.target.style.borderColor = 'rgba(52,211,153,0.6)'; e.target.style.boxShadow = '0 0 0 3px rgba(52,211,153,0.1)'; }}
                onBlur={(e) => { e.target.style.borderColor = 'rgba(100,116,139,0.3)'; e.target.style.boxShadow = 'none'; }}
              />
            </div>
          </div>

          {/* Password */}
          <div>
            <label className="block text-xs font-semibold text-slate-400 uppercase tracking-widest mb-2">
              Password
            </label>
            <div className="relative">
              <Lock className="absolute left-3.5 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" />
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => { setPassword(e.target.value); setError(''); }}
                placeholder={mode === 'register' ? 'Min. 8 characters' : '••••••••••'}
                className="w-full pl-10 pr-12 py-3 rounded-xl text-sm text-white placeholder-slate-600 outline-none transition-all"
                style={{
                  background: 'rgba(15,23,42,0.8)',
                  border: '1px solid rgba(100,116,139,0.3)',
                }}
                onFocus={(e) => { e.target.style.borderColor = 'rgba(52,211,153,0.6)'; e.target.style.boxShadow = '0 0 0 3px rgba(52,211,153,0.1)'; }}
                onBlur={(e) => { e.target.style.borderColor = 'rgba(100,116,139,0.3)'; e.target.style.boxShadow = 'none'; }}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                className="absolute right-3.5 top-1/2 -translate-y-1/2 p-1 text-slate-500 hover:text-slate-300 transition-colors"
              >
                {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
              </button>
            </div>
          </div>

          {/* Error Message */}
          {error && (
            <div className="flex items-start gap-2.5 p-3 rounded-xl" style={{ background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)' }}>
              <AlertCircle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <p className="text-xs text-red-300">{error}</p>
            </div>
          )}

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full py-3.5 rounded-xl font-bold text-sm transition-all flex items-center justify-center gap-2 mt-2"
            style={{
              background: loading ? 'rgba(52,211,153,0.5)' : 'linear-gradient(135deg, #10b981, #059669)',
              color: '#0f172a',
              boxShadow: loading ? 'none' : '0 4px 24px rgba(16,185,129,0.35)',
            }}
          >
            {loading ? (
              <>
                <Loader2 className="w-4 h-4 animate-spin" />
                {mode === 'login' ? 'Signing in…' : 'Creating account…'}
              </>
            ) : mode === 'login' ? (
              <>
                <LogIn className="w-4 h-4" />
                Sign In to Sentinel
              </>
            ) : (
              <>
                <UserPlus className="w-4 h-4" />
                Create Account
              </>
            )}
          </button>

          {/* Footer toggle */}
          <p className="text-center text-xs text-slate-500 pt-1">
            {mode === 'login' ? (
              <>
                Don't have an account?{' '}
                <button
                  type="button"
                  onClick={() => { setMode('register'); setError(''); }}
                  className="text-emerald-400 hover:text-emerald-300 font-semibold transition-colors"
                >
                  Register here
                </button>
              </>
            ) : (
              <>
                Already have an account?{' '}
                <button
                  type="button"
                  onClick={() => { setMode('login'); setError(''); }}
                  className="text-emerald-400 hover:text-emerald-300 font-semibold transition-colors"
                >
                  Sign in
                </button>
              </>
            )}
          </p>
        </form>
      </div>
    </div>
  );
}
