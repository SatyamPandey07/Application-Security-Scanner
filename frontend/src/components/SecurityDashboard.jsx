import React, { useState, useEffect, useCallback } from 'react';
import {
  ShieldAlert, Filter, ArrowUpDown, ChevronRight,
  Sparkles, BarChart2, ToggleLeft, ToggleRight,
  MapPin, AlertTriangle, CheckCircle2, Clock, Info,
  Layers
} from 'lucide-react';
import FindingDetailModal from './FindingDetailModal';

// ── Risk level helpers ────────────────────────────────────────────────────────
const RISK_ORDER = ['Fix this now', 'Fix this soon', 'Worth fixing', 'Minor'];

function riskLabel(plain_risk_level) {
  if (!plain_risk_level) return 'Worth fixing';
  const label = RISK_ORDER.find(r => plain_risk_level.startsWith(r));
  return label || 'Worth fixing';
}

function riskReason(plain_risk_level) {
  if (!plain_risk_level) return '';
  const label = riskLabel(plain_risk_level);
  const afterDash = plain_risk_level.slice(label.length).replace(/^\s*[-–—]\s*/, '');
  return afterDash;
}

const RISK_STYLES = {
  'Fix this now':  { dot: 'bg-rose-500',   badge: 'bg-rose-500/15 text-rose-400 border-rose-500/30',   icon: AlertTriangle },
  'Fix this soon': { dot: 'bg-amber-500',  badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30', icon: Clock },
  'Worth fixing':  { dot: 'bg-blue-500',   badge: 'bg-blue-500/15 text-blue-400 border-blue-500/30',    icon: Info },
  'Minor':         { dot: 'bg-slate-500',  badge: 'bg-slate-700/60 text-slate-400 border-slate-600/40', icon: CheckCircle2 },
};

function RiskBadge({ plain_risk_level, size = 'sm' }) {
  const label = riskLabel(plain_risk_level);
  const { badge, icon: Icon } = RISK_STYLES[label] || RISK_STYLES['Worth fixing'];
  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full font-semibold border ${
        size === 'lg' ? 'text-sm px-3 py-1' : 'text-[11px]'
      } ${badge}`}
      data-testid="risk-badge"
    >
      <Icon className={size === 'lg' ? 'w-4 h-4' : 'w-3 h-3'} />
      {label}
    </span>
  );
}

// ── Feature area grouping ────────────────────────────────────────────────────
const AREA_ORDER = [
  'Login & Accounts', 'Payments & Checkout', 'Customer Data & Privacy',
  'Search & Browsing', 'Contact & Forms', 'Admin & Backend', 'Other',
];

function groupByArea(findings) {
  const groups = {};
  for (const f of findings) {
    const area = f.feature_area || 'Other';
    if (!groups[area]) groups[area] = [];
    groups[area].push(f);
  }
  // Sort groups by defined area order
  return AREA_ORDER.filter(a => groups[a]).map(a => ({ area: a, findings: groups[a] }));
}

// ── Plain summary sentence ───────────────────────────────────────────────────
function buildSummary(findings) {
  const total = findings.length;
  if (total === 0) return 'No issues found. Your site looks clean.';
  const urgent = findings.filter(f => riskLabel(f.plain_risk_level) === 'Fix this now').length;
  const soon   = findings.filter(f => riskLabel(f.plain_risk_level) === 'Fix this soon').length;
  let msg = `We found ${total} thing${total !== 1 ? 's' : ''} worth looking at on your website.`;
  if (urgent > 0)
    msg += ` ${urgent} need${urgent !== 1 ? '' : 's'} attention right away.`;
  else if (soon > 0)
    msg += ` ${soon} should be fixed soon.`;
  return msg;
}

// ── Simple finding card ──────────────────────────────────────────────────────
function SimpleFindingCard({ finding, onShowTechnical, onClick }) {
  const label = riskLabel(finding.plain_risk_level);
  const { dot } = RISK_STYLES[label] || RISK_STYLES['Worth fixing'];

  return (
    <div
      className="group bg-slate-950 border border-slate-800 rounded-xl p-5 hover:border-slate-700 transition-all cursor-pointer"
      onClick={onClick}
      data-testid="simple-finding-card"
      data-finding-id={finding.id}
    >
      <div className="flex items-start justify-between gap-3 mb-3">
        <div className="flex items-start gap-2.5">
          <div className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${dot}`} />
          <h3 className="text-sm font-bold text-white leading-snug" data-testid="plain-title">
            {finding.plain_title || finding.rule_id}
          </h3>
        </div>
        <RiskBadge plain_risk_level={finding.plain_risk_level} />
      </div>

      {finding.plain_location && (
        <p className="text-xs text-slate-500 flex items-center gap-1.5 mb-3" data-testid="plain-location">
          <MapPin className="w-3 h-3 flex-shrink-0 text-slate-600" />
          <span className="font-medium text-slate-400">Where:</span>{' '}
          {finding.plain_location}
        </p>
      )}

      {finding.plain_whats_wrong && (
        <p className="text-sm text-slate-300 leading-relaxed mb-4" data-testid="plain-whats-wrong">
          {finding.plain_whats_wrong}
        </p>
      )}

      <div className="flex items-center justify-between">
        <button
          onClick={(e) => { e.stopPropagation(); onShowTechnical(finding); }}
          className="text-xs text-slate-500 hover:text-emerald-400 transition-colors font-medium underline underline-offset-2"
          data-testid="show-technical-btn"
        >
          Show technical details →
        </button>
        <ChevronRight className="w-4 h-4 text-slate-700 group-hover:text-slate-500 transition-colors" />
      </div>
    </div>
  );
}

// ── Technical finding row (existing table row) ───────────────────────────────
function TechnicalRow({ finding, onClick }) {
  return (
    <tr
      onClick={onClick}
      className="hover:bg-slate-900/50 cursor-pointer transition-colors"
      data-testid="technical-finding-row"
      data-finding-id={finding.id}
    >
      <td className="px-5 py-4 font-bold">
        <span className={`px-2 py-0.5 rounded text-xs ${
          finding.severity_raw === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
          finding.severity_raw === 'HIGH'     ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
          'bg-blue-500/20 text-blue-400 border border-blue-500/30'
        }`}>
          {finding.severity_raw}
        </span>
      </td>
      <td className="px-5 py-4 font-mono font-semibold text-slate-200">
        <div data-testid="rule-id">{finding.rule_id}</div>
        <span className="text-[10px] uppercase text-slate-500 tracking-wider">{finding.source}</span>
      </td>
      <td className="px-5 py-4 font-mono text-slate-400 max-w-xs truncate" data-testid="file-path">
        {finding.file_path || 'Target URL'}:{finding.line_number || 1}
      </td>
      <td className="px-5 py-4 font-bold text-slate-200" data-testid="cvss-score">
        {finding.cvss_score || 'N/A'}
      </td>
      <td className="px-5 py-4 font-bold text-emerald-400">
        {finding.ai_confidence ? `${Math.round(parseFloat(finding.ai_confidence) * 100)}%` : 'N/A'}
      </td>
      <td className="px-5 py-4 font-extrabold text-amber-400">{finding.priority_score || 'N/A'}</td>
      <td className="px-5 py-4 text-right">
        <button className="text-emerald-400 hover:text-emerald-300 font-semibold inline-flex items-center gap-1 text-xs">
          View <ChevronRight className="w-3.5 h-3.5" />
        </button>
      </td>
    </tr>
  );
}

// ── View toggle ──────────────────────────────────────────────────────────────
const VIEW_PREF_KEY = 'sentinel_view_mode';

function ViewToggle({ simpleMode, onToggle }) {
  return (
    <button
      onClick={onToggle}
      className={`flex items-center gap-2 px-3 py-1.5 rounded-xl border text-xs font-semibold transition-all ${
        simpleMode
          ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-400'
          : 'bg-slate-900 border-slate-700 text-slate-400 hover:text-white'
      }`}
      data-testid="view-toggle"
      aria-pressed={simpleMode}
    >
      {simpleMode
        ? <><ToggleRight className="w-4 h-4" /> Simple view</>
        : <><ToggleLeft className="w-4 h-4" /> Technical view</>}
    </button>
  );
}

// ── Main component ───────────────────────────────────────────────────────────
export default function SecurityDashboard({ scanId, token }) {
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [sourceFilter, setSourceFilter] = useState('ALL');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [statusFilter, setStatusFilter] = useState('ALL');
  const [sortBy, setSortBy] = useState('priority');
  const [simpleMode, setSimpleMode] = useState(
    () => (localStorage.getItem(VIEW_PREF_KEY) ?? 'simple') === 'simple'
  );

  const toggleView = useCallback(() => {
    setSimpleMode(prev => {
      const next = !prev;
      localStorage.setItem(VIEW_PREF_KEY, next ? 'simple' : 'technical');
      return next;
    });
  }, []);

  useEffect(() => {
    if (!scanId || !token) return;
    let url = `/scans/${scanId}/findings?sort_by=${sortBy}`;
    if (sourceFilter !== 'ALL') url += `&source=${sourceFilter.toLowerCase()}`;
    if (severityFilter !== 'ALL') url += `&severity=${severityFilter.toUpperCase()}`;
    if (statusFilter !== 'ALL') url += `&status=${statusFilter.toLowerCase()}`;

    fetch(url, { headers: { Authorization: `Bearer ${token}` } })
      .then(res => res.ok ? res.json() : [])
      .then(data => setFindings(data))
      .catch(() => setFindings([]));
  }, [scanId, token, sourceFilter, severityFilter, statusFilter, sortBy]);

  // Severity counts (still shown in technical bar)
  const counts = {
    CRITICAL: findings.filter(f => f.severity_raw === 'CRITICAL').length,
    HIGH:     findings.filter(f => ['HIGH','ERROR'].includes(f.severity_raw)).length,
    MEDIUM:   findings.filter(f => ['MEDIUM','WARNING'].includes(f.severity_raw)).length,
    LOW:      findings.filter(f => ['LOW','INFO'].includes(f.severity_raw)).length,
  };
  const total = findings.length || 1;

  // Simple mode: sort by risk level priority
  const sortedFindings = simpleMode
    ? [...findings].sort((a, b) =>
        RISK_ORDER.indexOf(riskLabel(a.plain_risk_level)) -
        RISK_ORDER.indexOf(riskLabel(b.plain_risk_level))
      )
    : findings;

  const grouped = groupByArea(sortedFindings);

  return (
    <div className="space-y-6">
      {/* ── Header row with toggle ── */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-lg font-bold text-white">Security Report</h2>
          {simpleMode && findings.length > 0 && (
            <p className="text-sm text-slate-400 mt-0.5" data-testid="plain-summary">
              {buildSummary(findings)}
            </p>
          )}
        </div>
        <ViewToggle simpleMode={simpleMode} onToggle={toggleView} />
      </div>

      {/* ── Overview row ── */}
      {!simpleMode && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="bg-slate-950 border border-slate-800 p-5 rounded-2xl">
            <span className="text-xs text-slate-500 font-medium">Total Findings</span>
            <div className="text-3xl font-extrabold text-white mt-1">{findings.length}</div>
          </div>

          <div className="bg-slate-950 border border-slate-800 p-5 rounded-2xl md:col-span-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-slate-400 font-bold uppercase tracking-wider flex items-center gap-1.5">
                <BarChart2 className="w-4 h-4 text-emerald-400" />
                Severity Distribution
              </span>
            </div>
            <div className="h-6 w-full bg-slate-900 rounded-lg overflow-hidden flex" data-testid="severity-bar">
              {counts.CRITICAL > 0 && <div style={{ width: `${(counts.CRITICAL/total)*100}%` }} className="bg-rose-500 h-full" />}
              {counts.HIGH > 0    && <div style={{ width: `${(counts.HIGH/total)*100}%` }} className="bg-amber-500 h-full" />}
              {counts.MEDIUM > 0  && <div style={{ width: `${(counts.MEDIUM/total)*100}%` }} className="bg-blue-500 h-full" />}
              {counts.LOW > 0     && <div style={{ width: `${(counts.LOW/total)*100}%` }} className="bg-slate-600 h-full" />}
            </div>
            <div className="flex items-center gap-4 mt-3 text-xs text-slate-400">
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-rose-500" /> Critical ({counts.CRITICAL})</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-amber-500" /> High ({counts.HIGH})</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-blue-500" /> Medium ({counts.MEDIUM})</span>
              <span className="flex items-center gap-1.5"><span className="w-2.5 h-2.5 rounded-full bg-slate-600" /> Low ({counts.LOW})</span>
            </div>
          </div>
        </div>
      )}

      {/* Simple mode: risk-level summary pills */}
      {simpleMode && findings.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {RISK_ORDER.map(label => {
            const count = sortedFindings.filter(f => riskLabel(f.plain_risk_level) === label).length;
            if (count === 0) return null;
            const { dot, badge } = RISK_STYLES[label];
            return (
              <div key={label} className={`p-4 rounded-xl border ${badge} flex items-center gap-3`}>
                <div className={`w-3 h-3 rounded-full flex-shrink-0 ${dot}`} />
                <div>
                  <div className="text-lg font-extrabold">{count}</div>
                  <div className="text-[11px] font-semibold leading-tight">{label}</div>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ── Filters toolbar ── */}
      <div className="bg-slate-950 border border-slate-800 p-4 rounded-xl flex flex-wrap items-center justify-between gap-4 text-xs">
        <div className="flex items-center gap-3">
          <Filter className="w-4 h-4 text-slate-400" />
          {!simpleMode && (
            <>
              <select value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}
                className="bg-slate-900 border border-slate-800 text-slate-200 px-3 py-1.5 rounded-lg font-medium">
                <option value="ALL">All Sources</option>
                <option value="sast">SAST (Semgrep)</option>
                <option value="dast">DAST (ZAP)</option>
                <option value="dependency">Dependencies</option>
                <option value="secret">Secrets</option>
                <option value="access_control">Access Control (IDOR)</option>
              </select>
              <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}
                className="bg-slate-900 border border-slate-800 text-slate-200 px-3 py-1.5 rounded-lg font-medium">
                <option value="ALL">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="LOW">Low</option>
              </select>
            </>
          )}
          <select value={statusFilter} onChange={e => setStatusFilter(e.target.value)}
            className="bg-slate-900 border border-slate-800 text-slate-200 px-3 py-1.5 rounded-lg font-medium">
            <option value="ALL">All Statuses</option>
            <option value="confirmed">Confirmed</option>
            <option value="low_confidence">Low Confidence</option>
          </select>
        </div>
        {!simpleMode && (
          <div className="flex items-center gap-2">
            <ArrowUpDown className="w-4 h-4 text-slate-400" />
            <span className="text-slate-400">Sort by:</span>
            <select value={sortBy} onChange={e => setSortBy(e.target.value)}
              className="bg-slate-900 border border-slate-800 text-slate-200 px-3 py-1.5 rounded-lg font-medium">
              <option value="priority">Priority Score</option>
              <option value="cvss">CVSS Score</option>
              <option value="severity">Raw Severity</option>
            </select>
          </div>
        )}
      </div>

      {/* ── SIMPLE MODE: Grouped cards ── */}
      {simpleMode ? (
        <div className="space-y-8" data-testid="simple-view">
          {findings.length === 0 ? (
            <div className="text-center py-12 text-slate-500">No security findings match the selected filters.</div>
          ) : grouped.length === 0 ? (
            <div className="text-center py-12 text-slate-500">No security findings match the selected filters.</div>
          ) : (
            grouped.map(({ area, findings: areaFindings }) => (
              <div key={area}>
                <div className="flex items-center gap-2 mb-3">
                  <Layers className="w-4 h-4 text-slate-500" />
                  <h3 className="text-sm font-bold text-slate-300">{area}</h3>
                  <span className="text-xs text-slate-600 font-medium">
                    {areaFindings.length} finding{areaFindings.length !== 1 ? 's' : ''}
                  </span>
                </div>
                <div className="space-y-3">
                  {areaFindings.map(f => (
                    <SimpleFindingCard
                      key={f.id}
                      finding={f}
                      onShowTechnical={finding => setSelectedFinding({ ...finding, _openInTechnical: true })}
                      onClick={() => setSelectedFinding(f)}
                    />
                  ))}
                </div>
              </div>
            ))
          )}
        </div>
      ) : (
        /* ── TECHNICAL MODE: Table ── */
        <div className="bg-slate-950 border border-slate-800 rounded-2xl overflow-hidden shadow-xl" data-testid="technical-view">
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
                findings.map(f => (
                  <TechnicalRow key={f.id} finding={f} onClick={() => setSelectedFinding(f)} />
                ))
              )}
            </tbody>
          </table>
        </div>
      )}

      {/* ── Finding Detail Modal ── */}
      <FindingDetailModal
        finding={selectedFinding}
        token={token}
        simpleDefault={simpleMode && !selectedFinding?._openInTechnical}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}
