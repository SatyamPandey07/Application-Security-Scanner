import React, { useState, useEffect } from 'react';
import {
  AlertTriangle, Code, ShieldAlert, Cpu, Sparkles, GitPullRequest,
  CheckCircle2, AlertCircle, MapPin, ChevronDown, ChevronUp,
  Clock, Info, X, Eye
} from 'lucide-react';

// ── Risk helpers (mirrored from SecurityDashboard) ────────────────────────────
const RISK_ORDER = ['Fix this now', 'Fix this soon', 'Worth fixing', 'Minor'];
function riskLabel(plain_risk_level) {
  if (!plain_risk_level) return 'Worth fixing';
  return RISK_ORDER.find(r => plain_risk_level.startsWith(r)) || 'Worth fixing';
}

const RISK_STYLES = {
  'Fix this now':  { badge: 'bg-rose-500/15 text-rose-400 border-rose-500/30',   icon: AlertTriangle },
  'Fix this soon': { badge: 'bg-amber-500/15 text-amber-400 border-amber-500/30', icon: Clock },
  'Worth fixing':  { badge: 'bg-blue-500/15 text-blue-400 border-blue-500/30',    icon: Info },
  'Minor':         { badge: 'bg-slate-700/60 text-slate-400 border-slate-600/40', icon: CheckCircle2 },
};

// ── Severity colour ───────────────────────────────────────────────────────────
function severityClass(sev) {
  if (sev === 'CRITICAL') return 'bg-rose-500/20 text-rose-400 border border-rose-500/30';
  if (sev === 'HIGH' || sev === 'ERROR') return 'bg-amber-500/20 text-amber-400 border border-amber-500/30';
  return 'bg-blue-500/20 text-blue-400 border border-blue-500/30';
}

// ── Section label ─────────────────────────────────────────────────────────────
function SectionLabel({ icon: Icon, label, color = 'text-slate-400' }) {
  return (
    <h3 className={`text-xs font-bold uppercase tracking-wider flex items-center gap-2 mb-2 ${color}`}>
      <Icon className="w-4 h-4" />
      {label}
    </h3>
  );
}

// ── Collapsible panel used for "plain-language context" in Technical mode ────
function CollapsiblePanel({ title, children, defaultOpen = false, testId }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="border border-slate-800 rounded-xl overflow-hidden" data-testid={testId}>
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between px-4 py-3 bg-slate-900/60 text-xs font-bold text-slate-300 hover:bg-slate-900 transition-colors"
      >
        <span>{title}</span>
        {open ? <ChevronUp className="w-4 h-4 text-slate-500" /> : <ChevronDown className="w-4 h-4 text-slate-500" />}
      </button>
      {open && <div className="px-4 py-4 bg-slate-950/40 space-y-3 text-sm text-slate-300">{children}</div>}
    </div>
  );
}

// ── Plain-language panel (used in Simple mode and as collapsible in Technical) 
function PlainLanguagePanel({ finding }) {
  const label = riskLabel(finding.plain_risk_level);
  const { badge, icon: RiskIcon } = RISK_STYLES[label];

  return (
    <div className="space-y-5" data-testid="plain-language-panel">
      {/* Risk level */}
      <div>
        <SectionLabel icon={RiskIcon} label="Priority Rating" color="text-slate-400" />
        <span className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-sm font-semibold ${badge}`}
          data-testid="modal-risk-badge">
          <RiskIcon className="w-4 h-4" />
          {finding.plain_risk_level || label}
        </span>
      </div>

      {/* What is this bug? (2-3 Line Layman Explanation) */}
      {finding.plain_whats_wrong && (
        <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-2">
          <SectionLabel icon={AlertTriangle} label="What is this bug in simple terms?" color="text-amber-400" />
          <p className="text-slate-100 text-sm leading-relaxed font-medium" data-testid="modal-plain-whats-wrong">
            {finding.plain_whats_wrong}
          </p>
        </div>
      )}

      {/* Why does this issue exist? */}
      {finding.plain_why_it_exists && (
        <div className="p-4 rounded-xl bg-slate-950/80 border border-slate-800/80 space-y-2">
          <SectionLabel icon={Info} label="Why does this issue exist?" color="text-blue-400" />
          <p className="text-slate-300 text-sm leading-relaxed" data-testid="modal-plain-why-it-exists">
            {finding.plain_why_it_exists}
          </p>
        </div>
      )}

      {/* Where */}
      {finding.plain_location && (
        <div>
          <SectionLabel icon={MapPin} label="Where it is found" color="text-slate-400" />
          <p className="text-slate-200 text-sm font-medium" data-testid="modal-plain-location">
            {finding.plain_location}
          </p>
        </div>
      )}

      {/* Real-world impact */}
      {finding.plain_real_world_impact && (
        <div className="p-4 rounded-xl bg-rose-950/10 border border-rose-900/20">
          <SectionLabel icon={ShieldAlert} label="What could go wrong if unassigned" color="text-rose-400" />
          <p className="text-slate-200 leading-relaxed text-sm" data-testid="modal-plain-impact">
            {finding.plain_real_world_impact}
          </p>
        </div>
      )}

      {/* What to do */}
      {finding.plain_what_to_do && (
        <div className="p-4 rounded-xl bg-emerald-950/10 border border-emerald-900/20">
          <SectionLabel icon={CheckCircle2} label="Recommended action for your team" color="text-emerald-400" />
          <p className="text-slate-200 leading-relaxed text-sm" data-testid="modal-plain-what-to-do">
            {finding.plain_what_to_do}
          </p>
        </div>
      )}
    </div>
  );
}

// ── Technical detail panel ────────────────────────────────────────────────────
function TechnicalPanel({ finding, token }) {
  const [githubToken, setGithubToken] = useState(localStorage.getItem('sentinel_gh_token') || '');
  const [repoName, setRepoName] = useState('SatyamPandey07/Application-Security-Scanner');
  const [isPrLoading, setIsPrLoading] = useState(false);
  const [prResult, setPrResult] = useState(null);
  const [prError, setPrError] = useState(null);

  const handleCreatePR = (e) => {
    e.preventDefault();
    if (!githubToken || !repoName) return;
    localStorage.setItem('sentinel_gh_token', githubToken);
    setIsPrLoading(true);
    setPrError(null);
    setPrResult(null);

    fetch(`/findings/${finding.id}/create-pr`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
      body: JSON.stringify({ github_token: githubToken, repo_name: repoName }),
    })
      .then(res => {
        if (!res.ok) return res.json().then(err => { throw new Error(err.detail || 'PR creation failed'); });
        return res.json();
      })
      .then(data => { setPrResult(data); setIsPrLoading(false); })
      .catch(err => { setPrError(err.message); setIsPrLoading(false); });
  };

  return (
    <div className="space-y-5" data-testid="technical-panel">
      {/* Metadata grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
        <div>
          <span className="text-xs text-slate-500 block font-medium">CVSS v3.1 Score</span>
          <span className="text-base font-bold text-slate-100" data-testid="tech-cvss">
            {finding.cvss_score || 'N/A'} / 10.0
          </span>
        </div>
        <div>
          <span className="text-xs text-slate-500 block font-medium">Rule ID</span>
          <span className="text-base font-bold text-slate-100 font-mono" data-testid="tech-rule-id">
            {finding.rule_id}
          </span>
        </div>
        <div>
          <span className="text-xs text-slate-500 block font-medium">AI Confidence</span>
          <span className="text-base font-bold text-emerald-400">
            {finding.ai_confidence ? `${Math.round(parseFloat(finding.ai_confidence) * 100)}%` : 'N/A'}
          </span>
        </div>
        <div>
          <span className="text-xs text-slate-500 block font-medium">Status</span>
          <span className={`text-base font-semibold capitalize ${finding.status === 'confirmed' ? 'text-emerald-400' : 'text-amber-400'}`}>
            {finding.status}
          </span>
        </div>
      </div>

      {/* File location & code snippet */}
      <div>
        <SectionLabel icon={Code} label="File Location & Flagged Snippet" />
        <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-slate-400 mb-2" data-testid="tech-file-path">
          {finding.file_path || 'Target URL'}:{finding.line_number || 1}
        </div>
        <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs overflow-x-auto text-rose-300 bg-rose-950/10 border-rose-900/30">
          <pre>{finding.code_snippet || 'No code snippet available.'}</pre>
        </div>
      </div>

      {/* AI technical explanation */}
      <div className="p-4 rounded-xl bg-emerald-950/10 border border-emerald-900/30 space-y-3">
        <SectionLabel icon={Sparkles} label="AI Technical Analysis" color="text-emerald-400" />
        <p className="text-slate-200 leading-relaxed">
          {finding.ai_explanation || 'No AI explanation generated.'}
        </p>
      </div>

      {/* Fix diff + GitHub PR */}
      {finding.ai_fix_diff && (
        <div className="space-y-3">
          <SectionLabel icon={Cpu} label="AI-Suggested Patch Diff" />
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs overflow-x-auto text-emerald-300">
            <pre>{finding.ai_fix_diff}</pre>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 space-y-3">
            <h4 className="text-xs font-bold text-white flex items-center gap-2">
              <GitPullRequest className="w-4 h-4 text-emerald-400" />
              Automated GitHub Remediation Pull Request
            </h4>

            {prError && (
              <div className="p-3 bg-rose-500/10 border border-rose-500/20 text-rose-400 text-xs rounded-lg flex items-center gap-2">
                <AlertCircle className="w-4 h-4 shrink-0" />
                <span>{prError}</span>
              </div>
            )}

            {prResult ? (
              <div className="p-3 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs rounded-lg flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400" />
                  <span>PR opened on branch <strong>{prResult.branch_name}</strong></span>
                </div>
                <a href={prResult.pr_url} target="_blank" rel="noreferrer"
                  className="px-3 py-1 bg-emerald-500 text-slate-950 font-bold rounded-lg hover:bg-emerald-400 transition-colors">
                  View PR ↗
                </a>
              </div>
            ) : (
              <form onSubmit={handleCreatePR} className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-[11px] text-slate-400 font-medium mb-1">GitHub Target Repo (owner/repo)</label>
                    <input type="text" required value={repoName} onChange={e => setRepoName(e.target.value)}
                      placeholder="e.g. owner/repository"
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-emerald-500" />
                  </div>
                  <div>
                    <label className="block text-[11px] text-slate-400 font-medium mb-1">GitHub Personal Access Token</label>
                    <input type="password" required value={githubToken} onChange={e => setGithubToken(e.target.value)}
                      placeholder="ghp_... or OAuth token"
                      className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-emerald-500" />
                  </div>
                </div>
                <button type="submit" disabled={isPrLoading}
                  className="w-full py-2 bg-emerald-500 hover:bg-emerald-600 font-bold text-slate-950 rounded-lg text-xs transition-all flex items-center justify-center gap-2">
                  <GitPullRequest className="w-3.5 h-3.5" />
                  <span>{isPrLoading ? 'Applying Patch & Opening PR...' : 'Create GitHub Pull Request'}</span>
                </button>
              </form>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

// ── Main modal ────────────────────────────────────────────────────────────────
export default function FindingDetailModal({ finding, token, simpleDefault = true, onClose }) {
  // Each card independently tracks whether it's showing technical view
  const [showTechnical, setShowTechnical] = useState(!simpleDefault);

  // Reset per-card mode whenever the finding changes
  useEffect(() => {
    setShowTechnical(!simpleDefault);
  }, [finding?.id, simpleDefault]);

  if (!finding) return null;

  const hasPlainFields = !!(finding.plain_title || finding.plain_whats_wrong);
  const label = riskLabel(finding.plain_risk_level);
  const { badge: rBadge, icon: RIcon } = RISK_STYLES[label];

  return (
    <div
      className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto"
      onClick={e => e.target === e.currentTarget && onClose()}
    >
      <div
        className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden"
        data-testid="finding-modal"
        data-finding-id={finding.id}
      >
        {/* ── Modal header ── */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/40 flex-shrink-0">
          <div className="flex items-center gap-3">
            {/* Simple mode header: plain title + risk badge */}
            {!showTechnical && hasPlainFields ? (
              <>
                <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full border text-xs font-bold ${rBadge}`}>
                  <RIcon className="w-3.5 h-3.5" />
                  {label}
                </span>
                <h2 className="text-base font-bold text-white leading-snug max-w-md" data-testid="modal-plain-title">
                  {finding.plain_title || finding.rule_id}
                </h2>
              </>
            ) : (
              /* Technical mode header: severity + rule_id */
              <>
                <span className={`px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wide ${severityClass(finding.severity_raw)}`}>
                  {finding.severity_raw}
                </span>
                <h2 className="text-lg font-bold text-white font-mono" data-testid="modal-rule-id">
                  {finding.rule_id}
                </h2>
              </>
            )}
          </div>

          <div className="flex items-center gap-2">
            {/* Per-card technical toggle */}
            {hasPlainFields && (
              <button
                onClick={() => setShowTechnical(t => !t)}
                className="flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border border-slate-700 text-slate-400 hover:text-white hover:border-slate-600 transition-colors font-medium"
                data-testid="card-tech-toggle"
              >
                <Eye className="w-3.5 h-3.5" />
                {showTechnical ? 'Show simple view' : 'Show technical details'}
              </button>
            )}
            <button
              onClick={onClose}
              className="p-1.5 rounded-lg text-slate-400 hover:text-white hover:bg-slate-800 transition-colors"
              data-testid="modal-close"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* ── Modal content ── */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm text-slate-300">
          {!showTechnical && hasPlainFields ? (
            /* ── SIMPLE VIEW ── */
            <PlainLanguagePanel finding={finding} />
          ) : (
            /* ── TECHNICAL VIEW + collapsed plain panel ── */
            <>
              <TechnicalPanel finding={finding} token={token} />

              {/* Plain-language context, collapsed, for handoff to non-technical stakeholders */}
              {hasPlainFields && (
                <CollapsiblePanel
                  title="Plain-language summary (for sharing with non-technical stakeholders)"
                  testId="plain-context-collapsible"
                >
                  <PlainLanguagePanel finding={finding} />
                </CollapsiblePanel>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  );
}
