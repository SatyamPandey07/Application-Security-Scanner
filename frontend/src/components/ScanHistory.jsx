import React, { useState, useEffect } from 'react';
import { History, Shield, ExternalLink, Calendar, RefreshCw } from 'lucide-react';

export default function ScanHistory({ token, onSelectScan }) {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchScans = () => {
    if (!token) return;
    setLoading(true);
    fetch('/scans', {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.ok ? res.json() : [])
      .then((data) => {
        setScans(data);
        setLoading(false);
      })
      .catch(() => {
        setScans([]);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchScans();
  }, [token]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <h2 className="text-xl font-bold text-white flex items-center gap-2">
          <History className="w-5 h-5 text-emerald-400" />
          Scan History
        </h2>
        <button
          onClick={fetchScans}
          className="p-2 text-slate-400 hover:text-white rounded-lg bg-slate-900 border border-slate-800 transition-colors"
        >
          <RefreshCw className="w-4 h-4" />
        </button>
      </div>

      <div className="bg-slate-950 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-800">
            <tr>
              <th className="px-5 py-3.5">ID</th>
              <th className="px-5 py-3.5">Target</th>
              <th className="px-5 py-3.5">Type</th>
              <th className="px-5 py-3.5">Status</th>
              <th className="px-5 py-3.5">Started At</th>
              <th className="px-5 py-3.5 text-right">Report</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {scans.length === 0 ? (
              <tr>
                <td colSpan="6" className="text-center py-8 text-slate-500">
                  {loading ? 'Loading scan history...' : 'No security scans executed yet.'}
                </td>
              </tr>
            ) : (
              scans.map((s) => (
                <tr key={s.id} className="hover:bg-slate-900/50 transition-colors">
                  <td className="px-5 py-4 font-mono font-bold text-slate-200">#{s.id}</td>
                  <td className="px-5 py-4 font-mono text-slate-300 max-w-xs truncate">{s.target}</td>
                  <td className="px-5 py-4 uppercase font-semibold text-slate-400">{s.target_type}</td>
                  <td className="px-5 py-4">
                    <span className={`px-2 py-0.5 rounded text-[10px] uppercase font-bold ${
                      s.status === 'completed' ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30' :
                      s.status === 'running' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30 animate-pulse' :
                      s.status === 'failed' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                      'bg-slate-800 text-slate-400'
                    }`}>
                      {s.status}
                    </span>
                  </td>
                  <td className="px-5 py-4 text-slate-400">{new Date(s.started_at).toLocaleString()}</td>
                  <td className="px-5 py-4 text-right">
                    <button
                      onClick={() => onSelectScan(s.id)}
                      className="px-3 py-1.5 bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/30 rounded-lg font-semibold transition-colors inline-flex items-center gap-1"
                    >
                      <span>View Findings</span>
                      <ExternalLink className="w-3 h-3" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
