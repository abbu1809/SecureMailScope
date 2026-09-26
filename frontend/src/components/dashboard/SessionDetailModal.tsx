import React, { useState } from 'react';
import { X, Shield, Lock, Terminal, FileCode, Check, Copy, AlertTriangle, Fingerprint, Calendar, ShieldCheck, ChevronRight } from 'lucide-react';
import { Session } from '../../types/api';
import { ScoreGauge } from '../common/ScoreGauge';
import { SeverityBadge } from '../common/SeverityBadge';

interface SessionDetailModalProps {
  session: Session | null;
  onClose: () => void;
}

export const SessionDetailModal: React.FC<SessionDetailModalProps> = ({ session, onClose }) => {
  const [activeTab, setActiveTab] = useState<'score' | 'findings' | 'crypto' | 'frames'>('score');
  const [copiedRuleId, setCopiedRuleId] = useState<string | null>(null);

  if (!session) return null;

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRuleId(id);
    setTimeout(() => setCopiedRuleId(null), 2000);
  };

  const isStripping = session.starttls_state === 'STRIPPING_SUSPECTED';

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 sm:p-6 bg-black/50 backdrop-blur-sm animate-fadeIn">
      <div className="bg-canvas w-full max-w-4xl max-h-[90vh] rounded-2xl border border-hairline shadow-2xl flex flex-col overflow-hidden">
        {/* Header */}
        <div className="p-5 sm:p-6 border-b border-hairline flex items-center justify-between bg-canvas-soft/60">
          <div className="flex items-center gap-3.5">
            <div className={`w-9 h-9 rounded-[30%] flex items-center justify-center shadow-xs ${
              session.score_trace.score < 40 ? 'bg-red-600 text-white' : 'bg-ink text-white'
            }`}>
              <Shield className="w-4 h-4" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="font-bold text-base text-ink font-mono">{session.id}</h3>
                <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-white border border-hairline shadow-xs">
                  {session.protocol}
                </span>
                <SeverityBadge severity={session.score_trace.risk_class} size="sm" />
              </div>
              <p className="text-xs text-text-muted font-mono mt-0.5">
                {session.src_ip}:{session.src_port} &rarr; {session.dst_ip}:{session.dst_port}
              </p>
            </div>
          </div>

          <button
            onClick={onClose}
            className="p-2 rounded-full hover:bg-canvas text-text-muted hover:text-ink transition-colors border border-transparent hover:border-hairline"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="px-6 border-b border-hairline flex items-center gap-2 bg-canvas overflow-x-auto">
          {[
            { id: 'score', label: 'SCoRE Algorithm Trace' },
            { id: 'findings', label: `Findings & Remediation (${session.findings.length})` },
            { id: 'crypto', label: 'TLS & Certificate Hierarchy' },
            { id: 'frames', label: `Evidence Frames (${session.evidence_frames.length})` },
          ].map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as any)}
              className={`py-3.5 px-3 text-xs font-bold border-b-2 transition-all shrink-0 ${
                activeTab === tab.id
                  ? 'border-ink text-ink'
                  : 'border-transparent text-text-muted hover:text-ink'
              }`}
            >
              {tab.label}
            </button>
          ))}
        </div>

        {/* Modal Body */}
        <div className="p-6 overflow-y-auto space-y-6 flex-1">
          {/* TAB 1: SCoRE TRACE */}
          {activeTab === 'score' && (
            <div className="space-y-6">
              {/* Score breakdown banner */}
              <div className="bg-canvas-soft rounded-md p-6 border border-hairline-soft grid grid-cols-1 sm:grid-cols-3 gap-6 items-center">
                <div className="flex flex-col items-center justify-center">
                  <ScoreGauge score={session.score_trace.score} grade={session.score_trace.risk_class} size={130} />
                </div>
                <div className="sm:col-span-2 space-y-2">
                  <span className="text-xs font-bold uppercase tracking-wider text-accent">
                    SCoRE Mathematical Evaluation Trace
                  </span>
                  <div className="font-mono text-xs bg-ink text-white p-3 rounded-sm leading-relaxed overflow-x-auto">
                    {session.score_trace.formula_trace}
                  </div>
                  <p className="text-xs text-text-muted">
                    SCoRE (§4.1) combines expert-assigned deterministic rule penalties (DP), machine learning risk confidence (p_ml),
                    JA3 rarity anomaly penalties (AB), and certificate urgency boosts (UB).
                  </p>
                </div>
              </div>

              {/* Formula Components Breakdown Cards */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                <div className="p-4 rounded-sm bg-field border border-hairline-soft">
                  <span className="text-[10px] uppercase font-bold text-text-muted block">Deterministic Penalty (DP)</span>
                  <span className="text-xl font-bold text-red-600 font-mono block mt-1">
                    -{session.score_trace.deterministic_penalty_dp}
                  </span>
                  <span className="text-[10px] text-text-muted block mt-0.5">Sum of rule weights with scope scaling</span>
                </div>

                <div className="p-4 rounded-sm bg-field border border-hairline-soft">
                  <span className="text-[10px] uppercase font-bold text-text-muted block">ML Confidence Fusion</span>
                  <span className="text-xl font-bold text-ink font-mono block mt-1">
                    p_ml={session.score_trace.ml_probability_pml}
                  </span>
                  <span className="text-[10px] text-text-muted block mt-0.5">Blend = {session.score_trace.ml_confidence_blend}</span>
                </div>

                <div className="p-4 rounded-sm bg-field border border-hairline-soft">
                  <span className="text-[10px] uppercase font-bold text-text-muted block">Anomaly Boost (AB)</span>
                  <span className="text-xl font-bold text-accent font-mono block mt-1">
                    -{session.score_trace.anomaly_boost_ab}
                  </span>
                  <span className="text-[10px] text-text-muted block mt-0.5">Isolation Forest JA3 outlier penalty</span>
                </div>

                <div className="p-4 rounded-sm bg-field border border-hairline-soft">
                  <span className="text-[10px] uppercase font-bold text-text-muted block">Urgency Boost (UB)</span>
                  <span className="text-xl font-bold text-orange-600 font-mono block mt-1">
                    -{session.score_trace.urgency_boost_ub}
                  </span>
                  <span className="text-[10px] text-text-muted block mt-0.5">Cert expiry proximity time-decay</span>
                </div>
              </div>

              {/* SHAP Factors */}
              {session.score_trace.top_contributing_factors.length > 0 && (
                <div className="p-4 rounded-md border border-hairline-soft bg-canvas">
                  <span className="text-xs font-bold uppercase tracking-wider text-text-muted block mb-3">
                    SHAP Factor Attribution (ML Layer)
                  </span>
                  <div className="space-y-2">
                    {session.score_trace.top_contributing_factors.map((f, i) => (
                      <div key={i} className="flex items-center justify-between text-xs py-1.5 border-b border-hairline-soft last:border-none">
                        <span className="font-medium text-ink">{f.factor}</span>
                        <span className={`font-mono font-bold ${f.impact.startsWith('+') ? 'text-red-600' : 'text-emerald-600'}`}>
                          {f.impact}
                        </span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 2: FINDINGS & REMEDIATION */}
          {activeTab === 'findings' && (
            <div className="space-y-4">
              {session.findings.length === 0 ? (
                <div className="py-12 text-center text-emerald-600 font-semibold text-sm bg-emerald-50/50 rounded-sm border border-emerald-200">
                  Zero cryptographic weaknesses detected. This session complies with NIST SP 800-52r2 and RFC 8314.
                </div>
              ) : (
                session.findings.map((f) => (
                  <div key={f.id} className="p-4 rounded-md border border-hairline bg-canvas space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-xs font-bold text-ink bg-field px-2 py-0.5 rounded">
                          {f.rule_id}
                        </span>
                        <h4 className="font-bold text-sm text-ink">{f.title}</h4>
                      </div>
                      <SeverityBadge severity={f.severity} size="sm" />
                    </div>

                    <p className="text-xs text-text-muted leading-relaxed">
                      {f.evidence}
                    </p>

                    {f.compliance_refs.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {f.compliance_refs.map((ref, idx) => (
                          <span key={idx} className="text-[10px] px-2 py-0.5 rounded-full bg-canvas-soft border border-hairline text-text-muted font-medium">
                            {ref}
                          </span>
                        ))}
                      </div>
                    )}

                    {/* Copyable Server Config Snippet */}
                    <div className="relative pt-2">
                      <div className="flex items-center justify-between text-[11px] font-bold text-text-muted mb-1 uppercase tracking-wider">
                        <span>Remediation Configuration Snippet</span>
                        <button
                          onClick={() => handleCopy(f.remediation, f.id)}
                          className="flex items-center gap-1 text-accent hover:underline lowercase font-sans font-normal"
                        >
                          {copiedRuleId === f.id ? (
                            <>
                              <Check className="w-3.5 h-3.5 text-emerald-600" />
                              <span className="text-emerald-600 font-semibold">Copied!</span>
                            </>
                          ) : (
                            <>
                              <Copy className="w-3.5 h-3.5" />
                              <span>Copy config</span>
                            </>
                          )}
                        </button>
                      </div>
                      <pre className="bg-neutral-900 text-neutral-200 p-3 rounded-sm font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed">
                        {f.remediation}
                      </pre>
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {/* TAB 3: TLS & CERTIFICATE HIERARCHY */}
          {activeTab === 'crypto' && (
            <div className="space-y-6">
              {/* TLS Handshake Facts */}
              <div className="p-4 rounded-md border border-hairline-soft bg-canvas space-y-3">
                <h4 className="font-bold text-xs uppercase tracking-wider text-text-muted flex items-center gap-2">
                  <Lock className="w-3.5 h-3.5" /> TLS Handshake Metadata
                </h4>

                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4 text-xs font-mono">
                  <div>
                    <span className="text-text-muted block text-[10px] uppercase font-bold">Negotiated Version</span>
                    <span className="font-semibold text-ink text-sm">
                      {session.tls_summary?.negotiated_version || 'None (Cleartext)'}
                    </span>
                  </div>
                  <div>
                    <span className="text-text-muted block text-[10px] uppercase font-bold">Negotiated Cipher</span>
                    <span className="font-semibold text-ink text-sm truncate block">
                      {session.tls_summary?.negotiated_cipher || 'None'}
                    </span>
                  </div>
                  <div>
                    <span className="text-text-muted block text-[10px] uppercase font-bold">Key Exchange (PFS)</span>
                    <span className="font-semibold text-ink">
                      {session.tls_summary?.key_exchange || 'None'}
                    </span>
                  </div>
                  <div>
                    <span className="text-text-muted block text-[10px] uppercase font-bold">SNI Server Name</span>
                    <span className="font-semibold text-ink">
                      {session.tls_summary?.sni || 'None provided'}
                    </span>
                  </div>
                </div>

                {session.tls_summary?.ja3 && (
                  <div className="pt-2 border-t border-hairline-soft text-xs space-y-1 font-mono">
                    <div className="flex items-center justify-between text-text-muted">
                      <span>JA3 Hash (Client):</span>
                      <span className="font-semibold text-ink">{session.tls_summary.ja3}</span>
                    </div>
                    {session.tls_summary.ja3s && (
                      <div className="flex items-center justify-between text-text-muted">
                        <span>JA3S Hash (Server):</span>
                        <span className="font-semibold text-ink">{session.tls_summary.ja3s}</span>
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* X.509 Certificate Chain */}
              <div className="p-4 rounded-md border border-hairline-soft bg-canvas space-y-3">
                <h4 className="font-bold text-xs uppercase tracking-wider text-text-muted flex items-center gap-2">
                  <FileCode className="w-3.5 h-3.5" /> X.509 Certificate Chain
                </h4>

                {session.certificate ? (
                  <div className="space-y-3 text-xs">
                    {!session.certificate.observable ? (
                      <div className="p-3 bg-blue-50 text-blue-900 rounded-sm border border-blue-200">
                        <strong>TLS 1.3 Handshake Encryption Active:</strong> Certificate exchange is encrypted at the record layer per RFC 8446. Marked <code className="font-mono">observable: false</code> per IEEE 830 specification.
                      </div>
                    ) : (
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div className="p-3 bg-field rounded-sm">
                          <span className="text-[10px] uppercase font-bold text-text-muted block">Subject</span>
                          <span className="font-semibold text-ink text-xs block break-all">{session.certificate.subject}</span>
                        </div>
                        <div className="p-3 bg-field rounded-sm">
                          <span className="text-[10px] uppercase font-bold text-text-muted block">Issuer</span>
                          <span className="font-semibold text-ink text-xs block break-all">{session.certificate.issuer}</span>
                        </div>
                        <div className="p-3 bg-field rounded-sm">
                          <span className="text-[10px] uppercase font-bold text-text-muted block">Public Key</span>
                          <span className="font-semibold text-ink text-xs block">
                            {session.certificate.key_algo} · {session.certificate.key_bits} bits
                          </span>
                        </div>
                        <div className="p-3 bg-field rounded-sm">
                          <span className="text-[10px] uppercase font-bold text-text-muted block">Signature Algorithm</span>
                          <span className="font-semibold text-ink text-xs block">{session.certificate.sig_algo}</span>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-xs text-text-muted py-3">
                    No certificate extracted for this cleartext session.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 4: EVIDENCE FRAMES */}
          {activeTab === 'frames' && (
            <div className="space-y-3">
              <span className="text-xs text-text-muted block">
                Byte-level frame evidence references captured during TCP stream reassembly.
              </span>
              <div className="space-y-2">
                {session.evidence_frames.map((frame, idx) => (
                  <div key={idx} className="p-3 rounded-sm bg-neutral-900 text-neutral-200 font-mono text-xs flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                    <div className="flex items-center gap-3">
                      <span className="text-accent font-bold">#{frame.frame_number}</span>
                      <span className="text-neutral-400 text-[11px]">{frame.direction}</span>
                      <span className="text-neutral-300 truncate max-w-md">{frame.summary}</span>
                    </div>
                    <span className="text-[10px] text-neutral-500 shrink-0">{frame.length} Bytes</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 bg-canvas-soft/80 border-t border-hairline flex items-center justify-between text-xs text-text-muted">
          <span>Session Duration: {session.duration_ms}ms · {session.packet_count} Packets</span>
          <button onClick={onClose} className="btn-primary text-xs py-1.5 px-4">
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
