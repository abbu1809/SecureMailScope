import React, { useState } from 'react';
import { CheckCircle2, Copy, Check, Terminal, ArrowUpRight } from 'lucide-react';
import { RemediationItem } from '../../types/api';
import { SeverityBadge } from '../common/SeverityBadge';

interface RemediationQueueProps {
  remediations: RemediationItem[];
}

export const RemediationQueue: React.FC<RemediationQueueProps> = ({ remediations }) => {
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="bg-canvas border border-hairline/80 rounded-2xl p-6 sm:p-7 shadow-subtle space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 pb-4 border-b border-hairline-soft">
        <div>
          <h3 className="font-bold text-ink text-base font-sans">Prioritized Remediation Roadmap</h3>
          <p className="text-xs text-text-muted mt-0.5">
            Ranked by impact: <code className="font-mono text-accent font-semibold">Priority = Severity × Exposure × (1 / Fix Effort)</code>
          </p>
        </div>
        <span className="text-xs font-bold font-mono px-3 py-1 bg-field rounded-full text-text-muted self-start sm:self-auto">
          {remediations.length} Action Items
        </span>
      </div>

      {remediations.length === 0 ? (
        <div className="py-12 text-center text-text-muted text-sm bg-canvas-soft/40 rounded-xl border border-dashed border-hairline">
          No critical remediation steps needed for this capture.
        </div>
      ) : (
        <div className="space-y-4">
          {remediations.map((rem, idx) => (
            <div key={rem.rule_id} className="p-5 rounded-xl border border-hairline/80 bg-canvas space-y-3.5 shadow-xs">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                <div className="flex items-center gap-3">
                  <span className="w-7 h-7 rounded-[30%] bg-ink text-white text-xs font-bold flex items-center justify-center shrink-0 shadow-xs">
                    {idx + 1}
                  </span>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-xs font-bold text-ink">{rem.rule_id}</span>
                      <SeverityBadge severity={rem.severity} size="sm" />
                    </div>
                    <h4 className="font-bold text-sm text-ink font-sans mt-0.5">{rem.title}</h4>
                  </div>
                </div>

                <div className="flex items-center gap-2 text-xs text-text-muted self-start sm:self-auto">
                  <span className="bg-field px-2.5 py-1 rounded-full font-mono text-[11px] font-semibold">
                    {rem.affected_sessions_count} host{rem.affected_sessions_count > 1 ? 's' : ''}
                  </span>
                  <span className="bg-blue-50 text-accent font-bold px-2.5 py-1 rounded-full border border-blue-200 font-mono text-[11px]">
                    Score: {rem.priority_score}
                  </span>
                </div>
              </div>

              {/* Target Service & Snippet */}
              <div className="pt-2">
                <div className="flex items-center justify-between text-[11px] font-bold text-text-muted mb-1.5 uppercase tracking-wider">
                  <span className="flex items-center gap-1.5">
                    <Terminal className="w-3.5 h-3.5 text-accent" />
                    Target Config ({rem.service_target})
                  </span>
                  <button
                    onClick={() => handleCopy(rem.remediation_snippet, rem.rule_id)}
                    className="flex items-center gap-1 text-accent hover:underline lowercase font-sans font-semibold text-xs"
                  >
                    {copiedId === rem.rule_id ? (
                      <>
                        <Check className="w-3.5 h-3.5 text-emerald-600" />
                        <span className="text-emerald-600 font-bold">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="w-3.5 h-3.5" />
                        <span>Copy snippet</span>
                      </>
                    )}
                  </button>
                </div>
                <pre className="bg-neutral-900 text-neutral-200 p-3.5 rounded-xl font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-sm">
                  {rem.remediation_snippet}
                </pre>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
