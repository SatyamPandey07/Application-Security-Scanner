import React, { useState, useEffect } from 'react';
import { ShieldCheck, CheckCircle2, XCircle, Download, FileText } from 'lucide-react';

export default function ComplianceSummary({ scanId, token }) {
  const [complianceData, setComplianceData] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!scanId || !token) return;
    setLoading(true);

    fetch(`/scans/${scanId}/compliance`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.ok ? res.json() : null)
      .then((data) => {
        setComplianceData(data);
        setLoading(false);
      })
      .catch(() => {
        setComplianceData(null);
        setLoading(false);
      });
  }, [scanId, token]);

  const handleExportCSV = () => {
    fetch(`/scans/${scanId}/compliance/export`, {
      headers: { Authorization: `Bearer ${token}` },
    })
      .then((res) => res.blob())
      .then((blob) => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `sentinel_compliance_scan_${scanId}.csv`;
        document.body.appendChild(a);
        a.click();
        a.remove();
      });
  };

  if (loading) {
    return <div className="p-8 text-center text-slate-500 text-xs">Loading compliance audit report...</div>;
  }

  if (!complianceData) {
    return <div className="p-8 text-center text-slate-500 text-xs">No compliance data available for scan #{scanId}.</div>;
  }

  return (
    <div className="space-y-8">
      {/* Page Header */}
      <div className="flex items-center justify-between">
        <div>
          <h2 className="text-xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-emerald-400" />
            Compliance Framework Mapping
          </h2>
          <p className="text-xs text-slate-400 mt-1">
            Audit pass/fail status mapped to SOC 2, PCI DSS v4.0, and OWASP ASVS v4.0 controls.
          </p>
        </div>

        <button
          onClick={handleExportCSV}
          className="px-4 py-2 bg-emerald-500 hover:bg-emerald-600 text-slate-950 font-bold rounded-xl text-xs flex items-center gap-2 transition-all shadow-lg"
        >
          <Download className="w-4 h-4" />
          <span>Export CSV Report</span>
        </button>
      </div>

      {/* Framework Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {Object.entries(complianceData).map(([fwName, fwInfo]) => (
          <div key={fwName} className="bg-slate-950 border border-slate-800 rounded-2xl p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-base font-bold text-white">{fwName}</h3>
              <span className={`px-2.5 py-1 rounded text-xs font-extrabold uppercase ${
                fwInfo.overall_status === 'PASS'
                  ? 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/30'
                  : 'bg-rose-500/20 text-rose-400 border border-rose-500/30'
              }`}>
                {fwInfo.overall_status}
              </span>
            </div>

            <div className="flex items-center justify-between text-xs text-slate-400 pt-2 border-t border-slate-800/80">
              <span>Passed Controls: <strong>{fwInfo.passed_controls}</strong> / {fwInfo.total_controls}</span>
              <span>Failed Controls: <strong className="text-rose-400">{fwInfo.failed_controls}</strong></span>
            </div>

            {/* Controls List */}
            <div className="space-y-3 pt-2">
              {fwInfo.controls.map((ctrl) => (
                <div key={ctrl.control_id} className="p-3 bg-slate-900/60 border border-slate-800 rounded-xl space-y-1.5 text-xs">
                  <div className="flex items-center justify-between">
                    <span className="font-mono font-bold text-slate-200">{ctrl.control_id}</span>
                    {ctrl.status === 'PASS' ? (
                      <span className="text-emerald-400 flex items-center gap-1 font-semibold text-[11px]">
                        <CheckCircle2 className="w-3.5 h-3.5" /> PASS
                      </span>
                    ) : (
                      <span className="text-rose-400 flex items-center gap-1 font-semibold text-[11px]">
                        <XCircle className="w-3.5 h-3.5" /> FAIL ({ctrl.blocking_count} blocking)
                      </span>
                    )}
                  </div>
                  <div className="text-slate-300 font-medium">{ctrl.control_name}</div>
                  <p className="text-slate-500 text-[11px]">{ctrl.description}</p>
                </div>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
