import React, { useState, useEffect } from 'react';
import { ShieldAlert, Filter, ArrowUpDown, ChevronRight, Sparkles, BarChart2 } from 'lucide-react';
import FindingDetailModal from './FindingDetailModal';

export default function SecurityDashboard({ scanId, token }) {
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState('priority');

  useEffect(() => {
    if (!scanId || !token) return;

    let url = `/scans/${scanId}/findings?sort_by=${sortBy}`;
    if (sourceFilter !== 'ALL') url += `&source=${sourceFilter.toLowerCase()}`;
    if (severityFilter !== 'ALL') url += `&severity=${severityFilter.toUpperCase()}`;
    if (statusFilter !== 'ALL') url += `&status=${statusFilter.toLowerCase()}`;

    fetch(url, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.ok ? res.json() : [])
      .then((data) => setFindings(data))
      .catch(() => setFindings([]));
  }, [scanId, token, sourceFilter, severityFilter, statusFilter, sortBy]);

  // Aggregate Counts for Bar Chart
  const counts = {
    CRITICAL: findings.filter(f => f.severity_raw === 'CRITICAL').length,
    HIGH: findings.filter(f => f.severity_raw === 'HIGH' || f.severity_raw === 'ERROR').length,
    MEDIUM: findings.filter(f => f.severity_raw === 'MEDIUM' || f.severity_raw === 'WARNING').length,
    LOW: findings.filter(f => f.severity_raw === 'LOW' || f.severity_raw === 'INFO').length,
  };

  const total = findings.length || 1;

  return (
    <div className="space-y-6">
      {/* Overview Metrics & Bar Chart */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="bg-slate-950 border border-slate-800 p-5 rounded-2xl">
          <span className="text-xs text-slate-500 font-medium">Total Findings</span>
          <div className="text-3xl font-extrabold text-white mt-1">{findings.length}</div>
        </div>

        <div className="bg-slate-950 border border-slate-800 p-5 rounded-2xl md:col-span-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs text-slate-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
              <BarChart2 className="w-4 h-4 text-emerald-400" />
              Severity Distribution Bar Chart
            </span>
          </div>

          {/* Simple Visual Bar Chart */}
          <div className="h-6 w-full bg-slate-900 rounded-lg overflow-hidden flex">
            {counts.CRITICAL > 0 && (
              <div
                style={{ width: `${(counts.CRITICAL / total) * 100}%` }}
                className="bg-rose-500 h-full title='Critical'"
              />
            )}
            {counts.HIGH > 0 && (
              <div
                style={{ width: `${(counts.HIGH / total) * 100}%` }}
                className="bg-amber-500 h-full title='High'"
              />
            )}
            {counts.MEDIUM > 0 && (
              <div
                style={{ width: `${(counts.MEDIUM / total) * 100}%` }}
                className="bg-blue-500 h-full title='Medium'"
              />
            )}
            {counts.LOW > 0 && (
              <div
                style={{ width: `${(counts.LOW / total) * 100}%` }}
                className="bg-slate-600 h-full title='Low'"
              />
            )}
          </div>

          <div className="flex items-center gap-4 mt-3 text-xs text-slate-400">
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-rose-500" /> Critical ({counts.CRITICAL})</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> High ({counts.HIGH})</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500" /> Medium ({counts.MEDIUM})</span>
            <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-slate-600" /> Low ({counts.LOW})</span>
          </div>
        </div>
      </div>

      {/* Filters Toolbar */}
      <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-3">
          <Filter className="w-4 h-4 text-slate-400" />
          <select
            value={sourceFilter}
            onChange={(e) => setSourceFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-200 px-3 py-1.5 rounded-lg font-medium"
          >
            <option value="ALL">All Sources</option>
            <option value="sast">SAST (Semgrep)</option>
            <option value="dast">DAST (ZAP)</option>
            <option value="dependency">Dependencies</option>
            <option value="secret">Secrets</option>
            <option value="access_control">Access Control (IDOR)</option>
          </select>

          <select
            value={severityFilter}
            onChange={(e) => setSeverityFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-200 px-3 py-1.5 rounded-lg font-medium"
          >
            <option value="ALL">All Severities</option>
            <option value="CRITICAL">Critical</option>
            <option value="HIGH">High</option>
            <option value="MEDIUM">Medium</option>
            <option value="LOW">Low</option>
          </select>

          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-200 px-3 py-1.5 rounded-lg font-medium"
          >
            <option value="ALL">All Statuses</option>
            <option value="confirmed">Confirmed</option>
            <option value="low_confidence">Low Confidence</option>
          </select>
        </div>

        <div className="flex items-center gap-2">
          <ArrowUpDown className="w-4 h-4 text-slate-400" />
          <span className="text-slate-400">Sort by:</span>
          <select
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-200 px-3 py-1.5 rounded-lg font-medium"
          >
            <option value="priority">Priority Score</option>
            <option value="cvss">CVSS Score</option>
            <option value="severity">Raw Severity</option>
          </select>
        </div>
      </div>

      {/* Findings List Table */}
      <div className="bg-slate-950 border border-slate-800 rounded-2xl overflow-hidden shadow-xl">
        <table className="w-full text-left text-xs text-slate-300">
          <thead className="bg-slate-900/60 text-slate-400 uppercase font-semibold border-b border-slate-800">
            <tr>
              <th className="px-5 py-3.5">Severity</th>
              <th className="px-5 py-3.5">Rule / Source</th>
              <th className="px-5 py-3.5">Location</th>
              <th className="px-5 py-3.5">CVSS</th>
              <th className="px-5 py-3.5">AI Conf.</th>
              <th className="px-5 py-3.5">Priority</th>
              <th className="px-5 py-3.5 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-800/60">
            {findings.length === 0 ? (
              <tr>
                <td colSpan="7" className="text-center py-8 text-slate-500">
                  No security findings match the selected filters.
                </td>
              </tr>
            ) : (
              findings.map((f) => (
                <tr
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className="hover:bg-slate-900/50 cursor-pointer transition-colors"
                >
                  <td className="px-5 py-4 font-bold">
                    <span className={`px-2 py-0.5 rounded ${
                      f.severity_raw === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
                      f.severity_raw === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                      'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                    }`}>
                      {f.severity_raw}
                    </span>
                  </td>
                  <td className="px-5 py-4 font-mono font-semibold text-slate-200">
                    <div>{f.rule_id}</div>
                    <span className="text-[10px] uppercase text-slate-500 tracking-wider">{f.source}</span>
                  </td>
                  <td className="px-5 py-4 font-mono text-slate-400 max-w-xs truncate">
                    {f.file_path || 'Target URL'}:{f.line_number || 1}
                  </td>
                  <td className="px-5 py-4 font-bold text-slate-200">{f.cvss_score || 'N/A'}</td>
                  <td className="px-5 py-4 font-bold text-emerald-400">
                    {f.ai_confidence ? `${Math.round(parseFloat(f.ai_confidence) * 100)}%` : 'N/A'}
                  </td>
                  <td className="px-5 py-4 font-extrabold text-amber-400">{f.priority_score || 'N/A'}</td>
                  <td className="px-5 py-4 text-right">
                    <button className="text-emerald-400 hover:text-emerald-300 font-semibold inline-flex items-center gap-1">
                      View <ChevronRight className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      {/* Finding Detail Modal */}
      <FindingDetailModal
        finding={selectedFinding}
        token={token}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
