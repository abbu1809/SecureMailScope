import React, { useState } from 'react';
import { Link } from 'react-router-dom';
import { ArrowRight, CheckCircle2, Fingerprint, ShieldCheck, Zap, FileText } from 'lucide-react';
import { BackgroundAnimation } from '../components/landing/BackgroundAnimation';
import { ScoreGauge } from '../components/common/ScoreGauge';

export const LandingPage: React.FC = () => {
  const [simVersion, setSimVersion] = useState<'TLS13' | 'TLS10' | 'STRIPPED'>('TLS13');

  const getSimData = () => {
    switch (simVersion) {
      case 'TLS13':
        return {
          score: 97,
          grade: 'A+',
          title: 'Hardened TLS 1.3 Submission',
          verdict: 'Compliant with NIST SP 800-52r2 & RFC 8314',
          ciphers: 'TLS_AES_128_GCM_SHA256 (PFS)',
          issues: 0,
        };
      case 'TLS10':
        return {
          score: 18,
          grade: 'F',
          title: 'Deprecated TLS 1.0 with 3DES',
          verdict: 'Violates RFC 8996 & Vulnerable to Sweet32',
          ciphers: 'TLS_RSA_WITH_3DES_EDE_CBC_SHA',
          issues: 4,
        };
      case 'STRIPPED':
        return {
          score: 0,
          grade: 'F',
          title: 'STARTTLS Stripping Attack',
          verdict: 'Adversary MitM Interception & Cleartext Leak',
          ciphers: 'None (Plaintext AUTH Credentials)',
          issues: 3,
        };
    }
  };

  const sim = getSimData();

  return (
    <div className="relative space-y-24 md:space-y-32 py-10 md:py-16 overflow-hidden">
      {/* High-Quality Anime.js SVG Background Animation (30% opacity) */}
      <BackgroundAnimation />

      {/* ─── ACT 1: HERO ──────────────────────────────────────────────────────── */}
      <section className="relative z-10 max-w-4xl mx-auto text-center px-4 sm:px-6 space-y-6 pt-6">
        <div className="inline-flex items-center gap-2 bg-canvas-soft border border-hairline/80 px-4 py-1.5 rounded-full text-xs font-semibold text-ink shadow-xs">
          <span className="w-2 h-2 rounded-full bg-accent" />
          <span>Smart India Hackathon · PS 26159</span>
        </div>

        <h1 className="text-4xl sm:text-6xl lg:text-7xl font-bold tracking-tight text-ink font-sans leading-[1.06]">
          Passive Cryptographic Security Posture Assessment.
        </h1>

        <p className="text-base sm:text-lg lg:text-xl text-text-muted font-light max-w-2xl mx-auto leading-relaxed">
          SecureMailScope analyzes captured email network traffic offline to verify encryption strength,
          detect active STARTTLS stripping attacks, flag AI anomalies, and score posture explainably.
        </p>

        <div className="flex flex-wrap items-center justify-center gap-3 pt-4">
          <Link to="/dashboard" className="btn-primary text-sm sm:text-base py-3 px-8 flex items-center gap-2 shadow-sm">
            <span>Launch SOC Dashboard</span>
            <ArrowRight className="w-4 h-4" />
          </Link>
          <Link to="/rules" className="btn-outline text-sm sm:text-base py-3 px-6 shadow-sm">
            <span>Explore 35 Security Rules</span>
          </Link>
        </div>
      </section>

      {/* ─── ACT 2: INTERACTIVE POSTURE SIMULATOR ──────────────────────────────── */}
      <section className="max-w-5xl mx-auto px-4 sm:px-6">
        <div className="bg-canvas border border-hairline/80 rounded-2xl p-6 sm:p-10 shadow-subtle">
          <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 mb-8 pb-6 border-b border-hairline-soft">
            <div>
              <span className="text-xs font-bold uppercase tracking-wider text-accent font-mono">
                Interactive SCoRE Engine Demo
              </span>
              <h3 className="text-2xl font-bold text-ink tracking-tight font-sans mt-0.5">
                Simulate Traffic Posture Evaluation.
              </h3>
            </div>

            {/* Segmented Control */}
            <div className="flex bg-canvas-soft p-1.5 rounded-full text-xs font-semibold border border-hairline-soft self-start md:self-auto shadow-xs">
              {[
                { id: 'TLS13', label: 'Modern TLS 1.3' },
                { id: 'TLS10', label: 'Legacy TLS 1.0 (3DES)' },
                { id: 'STRIPPED', label: 'Stripped STARTTLS' },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setSimVersion(tab.id as any)}
                  className={`px-4 py-1.5 rounded-full transition-all ${
                    simVersion === tab.id
                      ? 'bg-canvas text-ink shadow-subtle font-bold'
                      : 'text-text-muted hover:text-ink'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-center">
            <div className="lg:col-span-4 flex flex-col items-center justify-center p-6 bg-canvas-soft rounded-2xl border border-hairline-soft">
              <ScoreGauge score={sim.score} grade={sim.grade} size={150} />
              <span className="text-xs font-mono font-bold text-text-muted mt-3">
                Verdict: Grade {sim.grade}
              </span>
            </div>

            <div className="lg:col-span-8 space-y-4">
              <div className="p-5 rounded-xl bg-canvas-soft border border-hairline-soft space-y-2.5">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-base text-ink font-sans">{sim.title}</span>
                  <span className={`text-xs font-bold px-2.5 py-0.5 rounded-full ${
                    sim.score >= 80 ? 'bg-emerald-100 text-emerald-800' : 'bg-red-100 text-red-800'
                  }`}>
                    {sim.issues} Vulnerabilities
                  </span>
                </div>
                <p className="text-xs text-text-muted">{sim.verdict}</p>
                <div className="font-mono text-xs text-ink bg-white p-3 rounded-lg border border-hairline truncate">
                  Cipher: {sim.ciphers}
                </div>
              </div>

              <div className="grid grid-cols-2 gap-3 text-xs text-text-muted">
                <div className="p-3 bg-white rounded-xl border border-hairline-soft flex items-center gap-2 shadow-xs">
                  <CheckCircle2 className="w-4 h-4 text-accent" />
                  <span>SCoRE Algorithm §4.1</span>
                </div>
                <div className="p-3 bg-white rounded-xl border border-hairline-soft flex items-center gap-2 shadow-xs">
                  <Fingerprint className="w-4 h-4 text-accent" />
                  <span>JA3 Isolation Forest AI</span>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* ─── ACT 3: THREE KEY PILLARS ─────────────────────────────────────────── */}
      <section className="max-w-6xl mx-auto px-4 sm:px-6 space-y-12">
        <div className="text-center max-w-2xl mx-auto space-y-3">
          <span className="text-xs font-bold uppercase tracking-wider text-accent font-mono">Core Capabilities</span>
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight text-ink font-sans">
            Engineered for High-Assurance SOC Teams.
          </h2>
          <p className="text-sm text-text-muted font-light leading-relaxed">
            Where existing tools simply display raw packets or require intrusive live server active scans,
            SecureMailScope extracts forensic metadata and maps it to actionable remediations.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* Card 1 */}
          <div className="card-container rounded-2xl flex flex-col justify-between space-y-4 shadow-subtle hover:shadow-md transition-all">
            <div className="space-y-3">
              <div className="w-10 h-10 rounded-[30%] bg-canvas-soft flex items-center justify-center text-ink shadow-xs">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-lg text-ink font-sans">SCoRE Fusion Algorithm §4.1</h3>
              <p className="text-xs text-text-muted leading-relaxed">
                Computes a mathematically sound 0-100 risk score per session by fusing expert-assigned deterministic rule penalties with ML risk probability and time-decay boosts.
              </p>
            </div>
            <div className="font-mono text-[11px] bg-canvas-soft p-3 rounded-xl text-text-muted border border-hairline-soft">
              DP = &Sigma; w_i &times; min(1 + log2(scope+1)/4, 1.5)
            </div>
          </div>

          {/* Card 2 */}
          <div className="card-container rounded-2xl flex flex-col justify-between space-y-4 shadow-subtle hover:shadow-md transition-all">
            <div className="space-y-3">
              <div className="w-10 h-10 rounded-[30%] bg-canvas-soft flex items-center justify-center text-ink shadow-xs">
                <Zap className="w-5 h-5 text-accent" />
              </div>
              <h3 className="font-bold text-lg text-ink font-sans">JA3/JA3S Isolation Forest AI</h3>
              <p className="text-xs text-text-muted leading-relaxed">
                Surfaces zero-day anomalies, rare extension permutations, and rogue mailers that slip past deterministic rules using in-process unsupervised anomaly detection.
              </p>
            </div>
            <div className="font-mono text-[11px] bg-canvas-soft p-3 rounded-xl text-text-muted border border-hairline-soft">
              Isolation Forest + SHAP attribution trace
            </div>
          </div>

          {/* Card 3 */}
          <div className="card-container rounded-2xl flex flex-col justify-between space-y-4 shadow-subtle hover:shadow-md transition-all">
            <div className="space-y-3">
              <div className="w-10 h-10 rounded-[30%] bg-canvas-soft flex items-center justify-center text-ink shadow-xs">
                <FileText className="w-5 h-5" />
              </div>
              <h3 className="font-bold text-lg text-ink font-sans">Actionable Remediation Queue</h3>
              <p className="text-xs text-text-muted leading-relaxed">
                Ranked triage using <code className="text-ink font-semibold">Priority = Severity &times; Exposure &times; (1/Fix Effort)</code> with copy-paste Postfix, Dovecot, and Exim configs.
              </p>
            </div>
            <div className="font-mono text-[11px] bg-canvas-soft p-3 rounded-xl text-text-muted border border-hairline-soft">
              NIST SP 800-52r2 &bull; RFC 8996 &bull; RFC 8314
            </div>
          </div>
        </div>
      </section>

      {/* ─── ACT 4: ARCHITECTURE PIPELINE ─────────────────────────────────────── */}
      <section className="max-w-6xl mx-auto px-4 sm:px-6">
        <div className="bg-canvas-soft rounded-2xl p-8 sm:p-12 border border-hairline/80 shadow-subtle space-y-8">
          <div className="text-center max-w-xl mx-auto space-y-2">
            <span className="text-xs font-bold uppercase tracking-wider text-accent font-mono">Under The Hood</span>
            <h3 className="text-2xl sm:text-3xl font-bold text-ink font-sans">End-to-End Processing Architecture.</h3>
            <p className="text-xs text-text-muted">
              Strictly offline single-node pipeline consuming standard PCAP/PCAPNG formats.
            </p>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { step: '01', title: 'Stream Ingest', desc: 'Binary PCAP reading & TCP conversation reassembly.' },
              { step: '02', title: 'Protocol State Machine', desc: 'Banner classification & STARTTLS stripping detection.' },
              { step: '03', title: 'Crypto & X.509 Intel', desc: 'Handshake parsing, JA3 hashing & cert chain validation.' },
              { step: '04', title: 'SCoRE & Report Export', desc: 'Deterministic rules, AI scoring & JSON/PDF generation.' },
            ].map((st) => (
              <div key={st.step} className="p-5 rounded-xl bg-canvas border border-hairline/80 space-y-2 shadow-xs">
                <span className="text-xl font-bold font-mono text-accent">{st.step}</span>
                <h4 className="font-bold text-sm text-ink font-sans">{st.title}</h4>
                <p className="text-xs text-text-muted leading-relaxed font-normal">{st.desc}</p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* ─── ACT 5: BOTTOM CTA ────────────────────────────────────────────────── */}
      <section className="max-w-4xl mx-auto px-4 sm:px-6 text-center space-y-6">
        <h2 className="text-3xl sm:text-5xl font-bold tracking-tight text-ink font-sans">
          Inspect Your Mail Encryption Posture Today.
        </h2>
        <p className="text-base text-text-muted max-w-xl mx-auto font-light">
          Run end-to-end evaluation using 8 pre-loaded enterprise scenarios or upload custom network packet captures.
        </p>
        <div>
          <Link to="/dashboard" className="btn-primary text-base py-3.5 px-10 shadow-sm">
            Open Interactive Dashboard ↗
          </Link>
        </div>
      </section>
    </div>
  );
};
