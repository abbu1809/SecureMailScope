import React from 'react';
import { ShieldCheck, AlertCircle, CheckCircle2 } from 'lucide-react';
import { ComplianceStandardPosture } from '../../types/api';

interface ComplianceMatrixProps {
  complianceMatrix: ComplianceStandardPosture[];
}

export const ComplianceMatrix: React.FC<ComplianceMatrixProps> = ({ complianceMatrix }) => {
  return (
    <div className="bg-canvas border border-hairline/80 rounded-2xl p-6 sm:p-7 shadow-subtle space-y-6">
      <div className="pb-4 border-b border-hairline-soft">
        <h3 className="font-bold text-ink text-base font-sans">Cryptographic Compliance Matrix</h3>
        <p className="text-xs text-text-muted mt-0.5">
          Formal evaluation against National and International Security Standards
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {complianceMatrix.map((std) => {
          const isPassed = std.compliance_percentage >= 90;
          return (
            <div
              key={std.standard_id}
              className="p-5 rounded-xl border border-hairline/80 bg-canvas flex flex-col justify-between space-y-3.5 shadow-xs"
            >
              <div>
                <div className="flex items-center justify-between mb-2">
                  <span className="font-mono text-xs font-bold text-ink bg-field px-2.5 py-1 rounded-full">
                    {std.standard_id}
                  </span>
                  <span
                    className={`text-xs font-bold font-mono px-2.5 py-0.5 rounded-full ${
                      isPassed
                        ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                        : 'bg-red-50 text-red-700 border border-red-200'
                    }`}
                  >
                    {std.compliance_percentage}% Compliant
                  </span>
                </div>

                <h4 className="font-bold text-sm text-ink mb-2 font-sans">{std.title}</h4>

                {/* Progress bar */}
                <div className="w-full bg-field h-2 rounded-full overflow-hidden mb-3">
                  <div
                    className={`h-full transition-all duration-500 rounded-full ${
                      isPassed ? 'bg-emerald-500' : std.compliance_percentage >= 60 ? 'bg-amber-500' : 'bg-red-500'
                    }`}
                    style={{ width: `${std.compliance_percentage}%` }}
                  />
                </div>

                {std.violations.length > 0 ? (
                  <div className="space-y-1.5 pt-1">
                    <span className="text-[10px] uppercase font-bold text-text-muted block">
                      Violations Identified ({std.violations.length}):
                    </span>
                    <ul className="space-y-1 text-xs text-red-700">
                      {std.violations.slice(0, 3).map((v, i) => (
                        <li key={i} className="flex items-start gap-1.5 line-clamp-1">
                          <AlertCircle className="w-3.5 h-3.5 shrink-0 mt-0.5 text-red-500" />
                          <span className="truncate">{v}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                ) : (
                  <div className="text-xs text-emerald-700 font-semibold flex items-center gap-1.5 pt-1">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span>All standard baseline checks satisfied</span>
                  </div>
                )}
              </div>

              <div className="pt-3 border-t border-hairline-soft text-[11px] text-text-muted flex items-center justify-between font-mono">
                <span>Checks: {std.passed_checks}/{std.total_checks}</span>
                <span className={`font-bold ${isPassed ? 'text-emerald-600' : 'text-amber-600'}`}>
                  {isPassed ? 'Baseline Met' : 'Action Required'}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
};
