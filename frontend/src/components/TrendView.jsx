import React, { useState, useEffect } from 'react';
import { TrendingUp, Calendar, ShieldCheck, Activity } from 'lucide-react';

export default function TrendView({ token }) {
  const [targetInput, setTargetInput] = useState('https://example.com');
  const [trendData, setTrendData] = useState(null);
  const [loading, setLoading] = useState(false);

  const fetchTrends = (targetStr) => {
    if (!token || !targetStr) return;
    setLoading(true);
    fetch(`/scans/trends?target=${encodeURIComponent(targetStr)}`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.ok ? res.json() : null)
      .then((data) => {
        setTrendData(data);
        setLoading(false);
      })
      .catch(() => {
        setTrendData(null);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchTrends(targetInput);
  }, [token]);

  return (
    <div className="space-y-6">
      {/* Header & Target Input */}
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <TrendingUp className="w-5 h-5 text-emerald-400" />
            Security Trend Analytics
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Track vulnerability discovery and remediation velocity over repeat scans against the same target.
          </p>
        </div>

        <form
          onSubmit={(e) => {
            e.preventDefault();
            fetchTrends(targetInput);
          }}
          className="flex items-center gap-2"
        >
          <input
            type="text"
            required
            value={targetInput}
            onChange={(e) => setTargetInput(e.target.value)}
            placeholder="Target URL or repo path"
            className="px-3 py-1.5 bg-slate-950 border border-slate-800 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-emerald-500 w-64 font-mono"
          />
          <button
            type="submit"
            className="px-3 py-1.5 bg-emerald-500 hover:bg-emerald-600 font-bold text-slate-950 rounded-lg text-xs transition-all"
          >
            Fetch Trend
          </button>
        </form>
      </div>

      {loading ? (
        <div className="p-8 text-center text-slate-500 text-xs">Loading trend analytics...</div>
      ) : !trendData || !trendData.trend_history || trendData.trend_history.length === 0 ? (
        <div className="p-8 text-center text-slate-500 text-xs bg-slate-950 border border-slate-800 rounded-2xl">
          No historical scan trend data found for target <strong>{targetInput}</strong>.
        </div>
      ) : (
        <div className="space-y-6">
          {/* Trend Summary Cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-2xl">
              <span className="text-xs text-slate-500 font-medium">Scans Executed</span>
              <div className="text-3xl font-extrabold text-white mt-1">{trendData.total_scans_conducted}</div>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-2xl">
              <span className="text-xs text-slate-500 font-medium">Latest Total Findings</span>
              <div className="text-3xl font-extrabold text-amber-400 mt-1">
                {trendData.trend_history[trendData.trend_history.length - 1].total_findings}
              </div>
            </div>
            <div className="bg-slate-950 border border-slate-800 p-5 rounded-2xl">
              <span className="text-xs text-slate-500 font-medium">Latest Avg CVSS Rating</span>
              <div className="text-3xl font-extrabold text-emerald-400 mt-1">
                {trendData.trend_history[trendData.trend_history.length - 1].average_cvss} / 10.0
              </div>
            </div>
          </div>

          {/* Historical Trend Timeline Table */}
          <div className="bg-slate-950 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
            <table className="w-full text-left text-xs text-slate-300">
              <thead className="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-800">
                <tr>
                  <th className="px-5 py-3.5">Scan ID</th>
                  <th className="px-5 py-3.5">Date & Time</th>
                  <th className="px-5 py-3.5">Total Findings</th>
                  <th className="px-5 py-3.5">Confirmed</th>
                  <th className="px-5 py-3.5">Critical / High</th>
                  <th className="px-5 py-3.5">Avg CVSS</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-800/60 font-mono">
                {trendData.trend_history.map((item) => (
                  <tr key={item.scan_id} className="hover:bg-slate-900/50 transition-colors">
                    <td className="px-5 py-4 font-bold text-slate-200">#{item.scan_id}</td>
                    <td className="px-5 py-4 text-slate-400">{new Date(item.started_at).toLocaleString()}</td>
                    <td className="px-5 py-4 font-bold text-white">{item.total_findings}</td>
                    <td className="px-5 py-4 text-emerald-400 font-bold">{item.confirmed_findings}</td>
                    <td className="px-5 py-4 text-rose-400 font-bold">{item.critical_high_findings}</td>
                    <td className="px-5 py-4 font-bold text-amber-400">{item.average_cvss}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
