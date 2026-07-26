import React, { useState, useEffect } from 'react';
import { TrendingUp, Calendar, ShieldCheck, Activity, BarChart2 } from 'lucide-react';

function TrendLineChart({ data }) {
  if (!data || data.length === 0) return null;

  const width = 600;
  const height = 180;
  const padding = 30;

  const maxVal = Math.max(...data.map(d => d.total_findings), 10);
  const minVal = 0;

  const points = data.map((d, i) => {
    const x = data.length === 1 ? width / 2 : padding + (i / (data.length - 1)) * (width - padding * 2);
    const y = height - padding - ((d.total_findings - minVal) / (maxVal - minVal)) * (height - padding * 2);
    return { x, y, val: d.total_findings, scanId: d.scan_id, date: new Date(d.started_at).toLocaleDateString() };
  });

  const pathD = points.length === 1
    ? `M ${points[0].x - 40} ${points[0].y} L ${points[0].x + 40} ${points[0].y}`
    : points.reduce((acc, p, i) => i === 0 ? `M ${p.x} ${p.y}` : `${acc} L ${p.x} ${p.y}`, '');

  const areaD = points.length === 1
    ? `M ${points[0].x - 40} ${height - padding} L ${points[0].x - 40} ${points[0].y} L ${points[0].x + 40} ${points[0].y} L ${points[0].x + 40} ${height - padding} Z`
    : `${pathD} L ${points[points.length - 1].x} ${height - padding} L ${points[0].x} ${height - padding} Z`;

  return (
    <div className="bg-slate-950 border border-slate-800 p-5 rounded-2xl space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-slate-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
          <BarChart2 className="w-4 h-4 text-emerald-400" />
          Vulnerability Remediation Velocity (Findings per Scan)
        </span>
        <span className="text-[11px] text-slate-500 font-mono">Target Trend Curve</span>
      </div>

      <div className="w-full overflow-x-auto">
        <svg viewBox={`0 0 ${width} ${height}`} className="w-full h-44 overflow-visible">
          <defs>
            <linearGradient id="trendGradient" x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#10b981" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#10b981" stopOpacity="0.0" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          <line x1={padding} y1={padding} x2={width - padding} y2={padding} stroke="#1e293b" strokeDasharray="4 4" />
          <line x1={padding} y1={height / 2} x2={width - padding} y2={height / 2} stroke="#1e293b" strokeDasharray="4 4" />
          <line x1={padding} y1={height - padding} x2={width - padding} y2={height - padding} stroke="#334155" />

          {/* Area fill */}
          <path d={areaD} fill="url(#trendGradient)" />

          {/* Trend line */}
          <path d={pathD} fill="none" stroke="#10b981" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" />

          {/* Data Points */}
          {points.map((p, i) => (
            <g key={i} className="group cursor-pointer">
              <circle cx={p.x} cy={p.y} r="5" fill="#10b981" stroke="#020617" strokeWidth="2" />
              <circle cx={p.x} cy={p.y} r="8" fill="#10b981" opacity="0.3" className="group-hover:opacity-60 transition-opacity" />
              <text x={p.x} y={p.y - 12} textAnchor="middle" fill="#e2e8f0" fontSize="10" fontWeight="bold">
                {p.val}
              </text>
              <text x={p.x} y={height - 10} textAnchor="middle" fill="#64748b" fontSize="9" fontFamily="monospace">
                #{p.scanId}
              </text>
            </g>
          ))}
        </svg>
      </div>
    </div>
  );
}

export default function TrendView({ token }) {
  const [targetInput, setTargetInput] = useState('https://satyampandey.online');
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

          {/* Visual SVG Trend Line Chart */}
          <TrendLineChart data={trendData.trend_history} />

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
