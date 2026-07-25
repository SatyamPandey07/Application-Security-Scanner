import React, { useState, useEffect } from 'react';
import { ShieldCheck, Play, Globe, GitBranch, CheckSquare, Square, RefreshCw, Clock, CheckCircle2, AlertCircle } from 'lucide-react';

export default function ScanLauncher({ token }) {
  const [target, setTarget] = useState('');
  const [targetType, setTargetType] = useState('url');
  const [authorized, setAuthorized] = useState(false);
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  const fetchScans = async () => {
    if (!token) return;
    try {
      const res = await fetch('/scans', {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (res.ok) {
        const data = await res.json();
        setScans(data);
      }
    } catch (err) {
      console.error('Failed to fetch scans', err);
    }
  };

  useEffect(() => {
    fetchScans();
    const interval = setInterval(fetchScans, 3000);
    return () => clearInterval(interval);
  }, [token]);

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (!authorized) {
      setError('You must confirm explicit authorization before launching a scan.');
      return;
    }

    setLoading(true);
    try {
      const res = await fetch('/scans', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({
          target,
          target_type: targetType,
          authorized: true,
        }),
      });

      if (!res.ok) {
        const errData = await res.json();
        throw new Error(errData.detail || 'Scan submission failed');
      }

      const newScan = await res.json();
      setSuccess(`Scan #${newScan.id} enqueued successfully. Explicit consent logged.`);
      setTarget('');
      setAuthorized(false);
      fetchScans();
    } catch (err) {
      setError(err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full max-w-4xl mx-auto space-y-8">
      {/* Scan Submission Card */}
      <div className="p-6 bg-slate-950/60 border border-slate-800 rounded-2xl shadow-xl">
        <div className="flex items-center gap-3 mb-6">
          <div className="p-2.5 bg-emerald-500/10 text-emerald-400 rounded-xl border border-emerald-500/20">
            <ShieldCheck className="w-6 h-6" />
          </div>
          <div>
            <h2 className="text-lg font-bold text-white">Target Audit Submission</h2>
            <p className="text-xs text-slate-400">Specify web application URL or Git repository for security analysis</p>
          </div>
        </div>

        {error && (
          <div className="mb-4 p-3 rounded-lg bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs flex items-center gap-2">
            <AlertCircle className="w-4 h-4 shrink-0" />
            <span>{error}</span>
          </div>
        )}

        {success && (
          <div className="mb-4 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4 shrink-0" />
            <span>{success}</span>
          </div>
        )}

        <form onSubmit={handleSubmit} className="space-y-5">
          <div className="flex items-center gap-4">
            <button
              type="button"
              onClick={() => setTargetType('url')}
              className={`flex-1 py-2.5 px-4 rounded-xl border text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
                targetType === 'url'
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 ring-1 ring-emerald-500/20'
                  : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-700'
              }`}
            >
              <Globe className="w-4 h-4" />
              <span>Web URL Target</span>
            </button>
            <button
              type="button"
              onClick={() => setTargetType('repo')}
              className={`flex-1 py-2.5 px-4 rounded-xl border text-xs font-semibold flex items-center justify-center gap-2 transition-all ${
                targetType === 'repo'
                  ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30 ring-1 ring-emerald-500/20'
                  : 'bg-slate-900 text-slate-400 border-slate-800 hover:border-slate-700'
              }`}
            >
              <GitBranch className="w-4 h-4" />
              <span>Git Repository</span>
            </button>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1.5">
              {targetType === 'url' ? 'Target Web Application URL' : 'Git Repository URL / Path'}
            </label>
            <input
              type="text"
              required
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              placeholder={targetType === 'url' ? 'https://myapp.example.com' : 'https://github.com/org/repo.git'}
              className="w-full px-4 py-2.5 bg-slate-900 border border-slate-800 rounded-xl text-sm text-white placeholder-slate-500 focus:outline-none focus:border-emerald-500"
            />
          </div>

          {/* Authorization Checkbox Gate */}
          <div
            onClick={() => setAuthorized(!authorized)}
            className={`p-4 rounded-xl border cursor-pointer select-none transition-all flex items-start gap-3 ${
              authorized
                ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300'
                : 'bg-slate-900/60 border-slate-800 text-slate-400 hover:border-slate-700'
            }`}
          >
            <div className="mt-0.5 shrink-0">
              {authorized ? (
                <CheckSquare className="w-5 h-5 text-emerald-400" />
              ) : (
                <Square className="w-5 h-5 text-slate-500" />
              )}
            </div>
            <div className="text-xs">
              <span className="font-semibold text-slate-200 block mb-0.5">
                Explicit Authorization Confirmation
              </span>
              <p>
                I confirm I own or have explicit, documented authorization to audit and test this target. This consent will be logged immutably before scan execution.
              </p>
            </div>
          </div>

          <button
            type="submit"
            disabled={!authorized || loading || !target.trim()}
            className="w-full py-3 px-4 bg-emerald-500 hover:bg-emerald-600 font-bold text-slate-950 rounded-xl text-sm transition-all flex items-center justify-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
          >
            <Play className="w-4 h-4 fill-slate-950" />
            <span>{loading ? 'Submitting Scan Job...' : 'Authorize & Launch Scan'}</span>
          </button>
        </form>
      </div>

      {/* Submitted Scans Status Card */}
      <div className="p-6 bg-slate-950/60 border border-slate-800 rounded-2xl">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-bold text-white flex items-center gap-2">
            <Clock className="w-4 h-4 text-slate-400" />
            <span>Recent Audits & Task Queue</span>
          </h3>
          <button
            onClick={fetchScans}
            className="text-xs text-slate-400 hover:text-white flex items-center gap-1"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            <span>Refresh</span>
          </button>
        </div>

        {scans.length === 0 ? (
          <p className="text-xs text-slate-500 text-center py-6">No scan jobs submitted yet.</p>
        ) : (
          <div className="space-y-3">
            {scans.map((s) => (
              <div
                key={s.id}
                className="p-3.5 rounded-xl border border-slate-800/80 bg-slate-900/40 flex items-center justify-between text-xs"
              >
                <div className="flex items-center gap-3">
                  <span className="font-mono text-slate-500">#{s.id}</span>
                  <div>
                    <span className="font-semibold text-white block">{s.target}</span>
                    <span className="text-[10px] text-slate-400 uppercase tracking-wider">{s.target_type}</span>
                  </div>
                </div>

                <div className="flex items-center gap-2">
                  <span
                    className={`px-2.5 py-1 rounded-full text-[10px] font-bold uppercase tracking-wider border ${
                      s.status === 'completed'
                        ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
                        : s.status === 'running'
                        ? 'bg-cyan-500/10 text-cyan-400 border-cyan-500/20 animate-pulse'
                        : 'bg-amber-500/10 text-amber-400 border-amber-500/20'
                    }`}
                  >
                    {s.status}
                  </span>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
