import React from 'react';
import { ShieldAlert, ShieldCheck, AlertTriangle, Radio, Activity, CheckCircle2, Lock, Zap } from 'lucide-react';
import { PostureSummary } from '../../types/api';
import { ScoreGauge } from '../common/ScoreGauge';
import { StatCard } from '../common/StatCard';

interface ExecutiveSummaryProps {
  summary: PostureSummary;
}

export const ExecutiveSummary: React.FC<ExecutiveSummaryProps> = ({ summary }) => {
  return (
    <div className="space-y-6">
      {/* Hero Posture Card */}
      <div className="bg-canvas-soft rounded-2xl p-6 sm:p-8 border border-hairline/80 shadow-subtle grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
        {/* Score Gauge */}
        <div className="lg:col-span-4 flex flex-col items-center justify-center p-6 bg-white rounded-xl border border-hairline/80 shadow-sm">
          <ScoreGauge score={summary.overall_score} grade={summary.overall_grade} size={150} />
          <div className="mt-4 text-center">
            <span className="text-xs font-bold text-ink block">
              Cryptographic Posture Score
            </span>
            <span className="text-[11px] text-text-muted font-mono block mt-0.5">
              SCoRE Algorithm §4.1
            </span>
          </div>
        </div>

        {/* Posture Rationale & Risk Tiers */}
        <div className="lg:col-span-8 flex flex-col justify-between space-y-5">
          <div className="space-y-2">
            <div className="flex flex-wrap items-center gap-2">
              <span className="text-xs font-bold uppercase tracking-wider text-accent bg-blue-50 px-3 py-1 rounded-full border border-blue-200">
                SIH PS 26159 Assessment
              </span>
              <span className="text-xs font-semibold text-text-muted bg-white px-3 py-1 rounded-full border border-hairline/80 font-mono">
                {summary.total_sessions} Sessions Analyzed
              </span>
            </div>
            <h2 className="text-2xl sm:text-3xl font-bold text-ink tracking-tight font-sans">
              Passive Cryptographic Posture Audit.
            </h2>
            <p className="text-sm text-text-muted font-light leading-relaxed">
              Posture evaluated across 35 deterministic protocol rules, X.509 certificate validation,
              and in-process Isolation Forest AI models without runtime server scanning or payload decryption.
            </p>
          </div>

          {/* Session Classification Pills */}
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 pt-3 border-t border-hairline/80">
            <div className="p-3 rounded-xl bg-white border border-hairline/80 shadow-xs">
              <span className="text-[11px] font-bold text-red-600 block uppercase tracking-wider">Critical</span>
              <span className="text-2xl font-bold text-ink font-sans">{summary.risk_distribution.Critical || 0}</span>
              <span className="text-[10px] text-text-muted block font-mono">Score 0 - 39</span>
            </div>
            <div className="p-3 rounded-xl bg-white border border-hairline/80 shadow-xs">
              <span className="text-[11px] font-bold text-orange-600 block uppercase tracking-wider">High Risk</span>
              <span className="text-2xl font-bold text-ink font-sans">{summary.risk_distribution.High || 0}</span>
              <span className="text-[10px] text-text-muted block font-mono">Score 40 - 69</span>
            </div>
            <div className="p-3 rounded-xl bg-white border border-hairline/80 shadow-xs">
              <span className="text-[11px] font-bold text-amber-600 block uppercase tracking-wider">Medium</span>
              <span className="text-2xl font-bold text-ink font-sans">{summary.risk_distribution.Medium || 0}</span>
              <span className="text-[10px] text-text-muted block font-mono">Score 70 - 89</span>
            </div>
            <div className="p-3 rounded-xl bg-white border border-hairline/80 shadow-xs">
              <span className="text-[11px] font-bold text-emerald-600 block uppercase tracking-wider">Secure</span>
              <span className="text-2xl font-bold text-ink font-sans">{summary.risk_distribution.Secure || 0}</span>
              <span className="text-[10px] text-text-muted block font-mono">Score 90 - 100</span>
            </div>
          </div>
        </div>
      </div>

      {/* 4 Executive KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          label="Total Captured Sessions"
          value={summary.total_sessions}
          subtitle={`${summary.total_packets} Ethernet/TCP Packets`}
          icon={Activity}
          variant="default"
        />
        <StatCard
          label="STARTTLS Stripping"
          value={summary.starttls_stripping_count}
          subtitle={summary.starttls_stripping_count > 0 ? "Adversary MitM Interception" : "Zero stripping detected"}
          icon={ShieldAlert}
          variant={summary.starttls_stripping_count > 0 ? "critical" : "default"}
        />
        <StatCard
          label="Weak / Expired Certs"
          value={summary.weak_cert_count}
          subtitle="< 2048-bit RSA, SHA-1, or Expired"
          icon={AlertTriangle}
          variant={summary.weak_cert_count > 0 ? "high" : "default"}
        />
        <StatCard
          label="AI Anomalies Flagged"
          value={summary.anomalies_count}
          subtitle="Isolation Forest JA3 Outliers"
          icon={Zap}
          variant={summary.anomalies_count > 0 ? "accent" : "default"}
        />
      </div>
    </div>
  );
};
