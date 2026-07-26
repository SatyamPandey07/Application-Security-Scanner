import React, { useState } from 'react';
import { AlertTriangle, Code, ShieldAlert, Cpu, Sparkles, GitPullRequest, CheckCircle2, AlertCircle } from 'lucide-react';

export default function FindingDetailModal({ finding, token, onClose }) {
  const [githubToken, setGithubToken] = useState(localStorage.getItem('sentinel_gh_token') || '');
  const [repoName, setRepoName] = useState('SatyamPandey07/Application-Security-Scanner');
  const [isPrLoading, setIsPrLoading] = useState(false);
  const [prResult, setPrResult] = useState(null);
  const [prError, setPrError] = useState(null);

  if (!finding) return null;

  const handleCreatePR = (e) => {
    e.preventDefault();
    if (!githubToken || !repoName) return;

    localStorage.setItem('sentinel_gh_token', githubToken);
    setIsPrLoading(true);
    setPrError(null);
    setPrResult(null);

    fetch(`/findings/${finding.id}/create-pr`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        github_token: githubToken,
        repo_name: repoName,
      }),
    })
      .then((res) => {
        if (!res.ok) return res.json().then((err) => { throw new Error(err.detail || 'PR creation failed'); });
        return res.json();
      })
      .then((data) => {
        setPrResult(data);
        setIsPrLoading(false);
      })
      .catch((err) => {
        setPrError(err.message);
        setIsPrLoading(false);
      });
  };

  return (
    <div className="fixed inset-0 z-50 bg-slate-950/80 backdrop-blur-sm flex items-center justify-center p-4 overflow-y-auto">
      <div className="bg-slate-900 border border-slate-800 rounded-2xl max-w-4xl w-full max-h-[90vh] flex flex-col shadow-2xl overflow-hidden">
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-800 flex items-center justify-between bg-slate-950/40">
          <div className="flex items-center gap-3">
            <span className={`px-2.5 py-1 rounded text-xs font-bold uppercase tracking-wide ${
              finding.severity_raw === 'CRITICAL' ? 'bg-rose-500/20 text-rose-400 border border-rose-500/30' :
              finding.severity_raw === 'HIGH' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
              'bg-blue-500/20 text-blue-400 border border-blue-500/30'
            }`}>
              {finding.severity_raw}
            </span>
            <h2 className="text-lg font-bold text-white font-mono">{finding.rule_id}</h2>
          </div>
          <button
            onClick={onClose}
            className="text-slate-400 hover:text-white px-3 py-1 rounded-lg border border-slate-800 text-xs font-semibold hover:bg-slate-800 transition-colors"
          >
            Close ✕
          </button>
        </div>

        {/* Modal Content Scroll */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1 text-sm text-slate-300">
          {/* Metadata Grid */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 p-4 rounded-xl bg-slate-950/60 border border-slate-800/80">
            <div>
              <span className="text-xs text-slate-500 block font-medium">CVSS v3.1 Score</span>
              <span className="text-base font-bold text-slate-100">{finding.cvss_score || 'N/A'} / 10.0</span>
            </div>
            <div>
              <span className="text-xs text-slate-500 block font-medium">AI Confidence</span>
              <span className="text-base font-bold text-emerald-400">
                {finding.ai_confidence ? `${Math.round(parseFloat(finding.ai_confidence) * 100)}%` : 'N/A'}
              </span>
            </div>
            <div>
              <span className="text-xs text-slate-500 block font-medium">Priority Score</span>
              <span className="text-base font-bold text-amber-400">{finding.priority_score || 'N/A'}</span>
            </div>
            <div>
              <span className="text-xs text-slate-500 block font-medium">Status</span>
              <span className={`text-base font-semibold capitalize ${
                finding.status === 'confirmed' ? 'text-emerald-400' : 'text-amber-400'
              }`}>
                {finding.status}
              </span>
            </div>
          </div>

          {/* Location & Vulnerable Code Snippet */}
          <div>
            <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider mb-2 flex items-center gap-2">
              <Code className="w-4 h-4 text-emerald-400" />
              File Location & Flagged Snippet
            </h3>
            <div className="p-3 bg-slate-950 rounded-lg border border-slate-800 font-mono text-xs text-slate-400 mb-2">
              {finding.file_path || 'Target URL'}:{finding.line_number || 1}
            </div>
            <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs overflow-x-auto text-rose-300 bg-rose-950/10 border-rose-900/30">
              <pre>{finding.code_snippet}</pre>
            </div>
          </div>

          {/* AI Explanation & Exploit Scenario */}
          <div className="p-4 rounded-xl bg-emerald-950/10 border border-emerald-900/30 space-y-3">
            <h3 className="text-xs font-bold text-emerald-400 uppercase tracking-wider flex items-center gap-2">
              <Sparkles className="w-4 h-4" />
              AI Plain-English Analysis
            </h3>
            <p className="text-slate-200 leading-relaxed">
              {finding.ai_explanation || 'No AI explanation generated.'}
            </p>
          </div>

          {/* Suggested Fix Diff */}
          {finding.ai_fix_diff && (
            <div className="space-y-3">
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wider flex items-center gap-2">
                <Cpu className="w-4 h-4 text-blue-400" />
                AI-Suggested Patch Diff
              </h3>
              <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs overflow-x-auto text-emerald-300">
                <pre>{finding.ai_fix_diff}</pre>
              </div>

              {/* GitHub PR Remediation Action Form */}
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
                      <span>Pull Request opened on branch <strong>{prResult.branch_name}</strong></span>
                    </div>
                    <a
                      href={prResult.pr_url}
                      target="_blank"
                      rel="noreferrer"
                      className="px-3 py-1 bg-emerald-500 text-slate-950 font-bold rounded-lg hover:bg-emerald-400 transition-colors"
                    >
                      View PR ↗
                    </a>
                  </div>
                ) : (
                  <form onSubmit={handleCreatePR} className="space-y-3">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div>
                        <label className="block text-[11px] text-slate-400 font-medium mb-1">GitHub Target Repo (owner/repo)</label>
                        <input
                          type="text"
                          required
                          value={repoName}
                          onChange={(e) => setRepoName(e.target.value)}
                          placeholder="e.g. owner/repository"
                          className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                        />
                      </div>
                      <div>
                        <label className="block text-[11px] text-slate-400 font-medium mb-1">GitHub Personal Access Token</label>
                        <input
                          type="password"
                          required
                          value={githubToken}
                          onChange={(e) => setGithubToken(e.target.value)}
                          placeholder="ghp_... or OAuth token"
                          className="w-full px-3 py-1.5 bg-slate-900 border border-slate-800 rounded-lg text-slate-200 text-xs focus:outline-none focus:border-emerald-500"
                        />
                      </div>
                    </div>
                    <button
                      type="submit"
                      disabled={isPrLoading}
                      className="w-full py-2 bg-emerald-500 hover:bg-emerald-600 font-bold text-slate-950 rounded-lg text-xs transition-all flex items-center justify-center gap-2"
                    >
                      <GitPullRequest className="w-3.5 h-3.5" />
                      <span>{isPrLoading ? 'Applying Patch & Opening PR...' : 'Create GitHub Pull Request'}</span>
                    </button>
                  </form>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
