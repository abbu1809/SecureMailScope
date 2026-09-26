import React, { useState } from 'react';
import { Terminal } from 'lucide-react';
import { ScoreGauge } from '../components/common/ScoreGauge';
import { SeverityBadge } from '../components/common/SeverityBadge';
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select';

export const LivePlaygroundPage: React.FC = () => {
  const [protocol, setProtocol] = useState<'SMTP' | 'IMAP' | 'POP3'>('SMTP');
  const [starttlsState, setStarttlsState] = useState<'COMPLETED' | 'STRIPPING_SUSPECTED' | 'NOT_APPLICABLE' | 'OFFERED'>('COMPLETED');
  const [tlsVersion, setTlsVersion] = useState<'TLS 1.3' | 'TLS 1.2' | 'TLS 1.1' | 'TLS 1.0' | 'SSL 3.0' | 'None'>('TLS 1.3');
  const [cipherSuite, setCipherSuite] = useState<'AES_GCM' | 'CHACHA20' | 'AES_CBC' | '3DES' | 'RC4' | 'NULL'>('AES_GCM');
  const [keyBits, setKeyBits] = useState<number>(2048);
  const [isCertExpired, setIsCertExpired] = useState<boolean>(false);
  const [isSelfSigned, setIsSelfSigned] = useState<boolean>(false);
  const [enableML, setEnableML] = useState<boolean>(true);

  // Dynamic SCoRE calculation simulation
  const calculateSimScore = () => {
    let dp = 0.0;
    const findings: { title: string; severity: string; ruleId: string }[] = [];

    // Protocol & STARTTLS
    if (starttlsState === 'STRIPPING_SUSPECTED') {
      dp += 35.0;
      findings.push({ title: 'Active STARTTLS Stripping Attack Suspected', severity: 'CRITICAL', ruleId: 'RULE-STARTTLS-001' });
    } else if (tlsVersion === 'None') {
      dp += 20.0;
      findings.push({ title: 'Cleartext Email Submission Without Encryption', severity: 'HIGH', ruleId: 'RULE-STARTTLS-002' });
    }

    // TLS Version
    if (tlsVersion === 'SSL 3.0') {
      dp += 35.0;
      findings.push({ title: 'Obsolete SSLv3 Protocol Negotiated', severity: 'CRITICAL', ruleId: 'RULE-TLS-002' });
    } else if (tlsVersion === 'TLS 1.0') {
      dp += 20.0;
      findings.push({ title: 'Deprecated TLS 1.0 Protocol Negotiated', severity: 'HIGH', ruleId: 'RULE-TLS-003' });
    } else if (tlsVersion === 'TLS 1.1') {
      dp += 20.0;
      findings.push({ title: 'Deprecated TLS 1.1 Protocol Negotiated', severity: 'HIGH', ruleId: 'RULE-TLS-004' });
    }

    // Cipher
    if (cipherSuite === 'NULL') {
      dp += 35.0;
      findings.push({ title: 'NULL Cipher Suite Negotiated (No Encryption)', severity: 'CRITICAL', ruleId: 'RULE-CIPHER-001' });
    } else if (cipherSuite === 'RC4') {
      dp += 35.0;
      findings.push({ title: 'RC4 Stream Cipher Negotiated', severity: 'CRITICAL', ruleId: 'RULE-CIPHER-003' });
    } else if (cipherSuite === '3DES') {
      dp += 20.0;
      findings.push({ title: 'DES / 3DES Cipher Suite Negotiated', severity: 'HIGH', ruleId: 'RULE-CIPHER-004' });
    } else if (cipherSuite === 'AES_CBC') {
      dp += 10.0;
      findings.push({ title: 'CBC Mode Cipher Negotiated', severity: 'MEDIUM', ruleId: 'RULE-CIPHER-006' });
    }

    // Certificate
    if (isCertExpired) {
      dp += 35.0;
      findings.push({ title: 'X.509 Certificate Has Expired', severity: 'CRITICAL', ruleId: 'RULE-CERT-001' });
    }
    if (isSelfSigned) {
      dp += 20.0;
      findings.push({ title: 'Untrusted Self-Signed Certificate Detected', severity: 'HIGH', ruleId: 'RULE-CERT-003' });
    }
    if (keyBits < 2048 && tlsVersion !== 'None') {
      dp += 35.0;
      findings.push({ title: `Weak Asymmetric RSA Key Size (${keyBits}-bit)`, severity: 'CRITICAL', ruleId: 'RULE-CERT-004' });
    }

    // ML fusion
    let p_ml = 0.5;
    let ab = 0.0;
    if (enableML) {
      if (starttlsState === 'STRIPPING_SUSPECTED' || cipherSuite === 'RC4' || cipherSuite === 'NULL') {
        p_ml = 0.95;
      } else if (tlsVersion === 'TLS 1.3' && cipherSuite === 'AES_GCM' && keyBits >= 2048 && !isCertExpired) {
        p_ml = 0.08;
      } else if (tlsVersion === 'TLS 1.0' || tlsVersion === 'SSL 3.0') {
        p_ml = 0.85;
      }
    }

    const blend = dp * (1.0 + 0.4 * (p_ml - 0.5));
    const ub = isCertExpired ? 10.0 : 0.0;
    const rawScore = 100.0 - blend - ab - ub;
    const clampedScore = Math.max(0, Math.min(100, Math.round(rawScore)));

    let riskClass: 'Critical' | 'High' | 'Medium' | 'Secure' = 'Secure';
    if (clampedScore <= 39) riskClass = 'Critical';
    else if (clampedScore <= 69) riskClass = 'High';
    else if (clampedScore <= 89) riskClass = 'Medium';

    return {
      score: clampedScore,
      riskClass,
      dp: Math.round(dp * 10) / 10,
      blend: Math.round(blend * 10) / 10,
      p_ml: Math.round(p_ml * 100) / 100,
      ub,
      findings,
    };
  };

  const sim = calculateSimScore();

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="space-y-2">
        <div className="inline-flex items-center gap-2 bg-canvas-soft border border-hairline/80 px-3 py-1 rounded-full text-xs font-semibold text-ink">
          <Terminal className="w-3.5 h-3.5 text-accent" />
          <span>Interactive Cryptographic Simulator</span>
        </div>
        <h1 className="text-3xl font-bold tracking-tight text-ink font-sans">
          Live SCoRE Parameter Playground.
        </h1>
        <p className="text-sm text-text-muted font-light max-w-3xl leading-relaxed">
          Tweak cryptographic parameters, toggle STARTTLS states, adjust asymmetric key lengths,
          and witness the mathematical SCoRE engine recalculate deterministic penalties and ML confidence in real time.
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-12 gap-8 items-start">
        {/* Left Column: Parameter Controls */}
        <div className="lg:col-span-7 bg-canvas border border-hairline/80 rounded-2xl p-6 sm:p-7 shadow-subtle space-y-6">
          <h3 className="font-bold text-base text-ink pb-3 border-b border-hairline-soft font-sans">
            Session Configuration Parameters
          </h3>

          {/* Protocol & STARTTLS */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-[11px] uppercase font-bold text-text-muted block mb-1.5">
                Mail Protocol
              </label>
              <Select value={protocol} onValueChange={(val) => setProtocol(val as any)}>
                <SelectTrigger className="h-11 rounded-xl bg-field border-hairline/80">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="SMTP">SMTP (Port 25/587)</SelectItem>
                  <SelectItem value="IMAP">IMAP (Port 143/993)</SelectItem>
                  <SelectItem value="POP3">POP3 (Port 110/995)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="text-[11px] uppercase font-bold text-text-muted block mb-1.5">
                STARTTLS State Machine
              </label>
              <Select value={starttlsState} onValueChange={(val) => setStarttlsState(val as any)}>
                <SelectTrigger className="h-11 rounded-xl bg-field border-hairline/80">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="COMPLETED">COMPLETED (Handshake OK)</SelectItem>
                  <SelectItem value="STRIPPING_SUSPECTED">STRIPPING_SUSPECTED (MitM)</SelectItem>
                  <SelectItem value="NOT_APPLICABLE">NOT_APPLICABLE (Implicit TLS)</SelectItem>
                  <SelectItem value="OFFERED">OFFERED (Client Ignored)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* TLS Version & Cipher Suite */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="text-[11px] uppercase font-bold text-text-muted block mb-1.5">
                TLS Protocol Version
              </label>
              <Select value={tlsVersion} onValueChange={(val) => setTlsVersion(val as any)}>
                <SelectTrigger className="h-11 rounded-xl bg-field border-hairline/80">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="TLS 1.3">TLS 1.3 (RFC 8446 - Hardened)</SelectItem>
                  <SelectItem value="TLS 1.2">TLS 1.2 (NIST Approved)</SelectItem>
                  <SelectItem value="TLS 1.1">TLS 1.1 (RFC 8996 Deprecated)</SelectItem>
                  <SelectItem value="TLS 1.0">TLS 1.0 (RFC 8996 Deprecated)</SelectItem>
                  <SelectItem value="SSL 3.0">SSL 3.0 (POODLE Insecure)</SelectItem>
                  <SelectItem value="None">None (Cleartext)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <label className="text-[11px] uppercase font-bold text-text-muted block mb-1.5">
                Negotiated Cipher Suite
              </label>
              <Select value={cipherSuite} onValueChange={(val) => setCipherSuite(val as any)}>
                <SelectTrigger className="h-11 rounded-xl bg-field border-hairline/80">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="AES_GCM">AES-128-GCM-SHA256 (AEAD / PFS)</SelectItem>
                  <SelectItem value="CHACHA20">CHACHA20-POLY1305 (AEAD / PFS)</SelectItem>
                  <SelectItem value="AES_CBC">AES-128-CBC-SHA256 (CBC Mode)</SelectItem>
                  <SelectItem value="3DES">3DES-EDE-CBC (Sweet32 Risk)</SelectItem>
                  <SelectItem value="RC4">RC4-128-MD5 (Broken Stream)</SelectItem>
                  <SelectItem value="NULL">NULL Cipher (No Encryption)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          {/* Certificate Parameters */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4 pt-3 border-t border-hairline-soft">
            <div>
              <label className="text-[11px] uppercase font-bold text-text-muted block mb-1.5">
                RSA Public Key Size
              </label>
              <Select value={String(keyBits)} onValueChange={(val) => setKeyBits(Number(val))}>
                <SelectTrigger className="h-11 rounded-xl bg-field border-hairline/80">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="4096">4096 bits (High Security)</SelectItem>
                  <SelectItem value="2048">2048 bits (NIST Baseline)</SelectItem>
                  <SelectItem value="1024">1024 bits (Weak / Insecure)</SelectItem>
                  <SelectItem value="512">512 bits (Broken)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="flex flex-col justify-end">
              <label className="flex items-center gap-2.5 text-xs font-semibold text-ink cursor-pointer p-3 bg-field rounded-xl border border-transparent hover:border-hairline transition-all">
                <input
                  type="checkbox"
                  checked={isCertExpired}
                  onChange={(e) => setIsCertExpired(e.target.checked)}
                  className="rounded text-ink focus:ring-ink w-4 h-4"
                />
                <span>Cert Expired</span>
              </label>
            </div>

            <div className="flex flex-col justify-end">
              <label className="flex items-center gap-2.5 text-xs font-semibold text-ink cursor-pointer p-3 bg-field rounded-xl border border-transparent hover:border-hairline transition-all">
                <input
                  type="checkbox"
                  checked={isSelfSigned}
                  onChange={(e) => setIsSelfSigned(e.target.checked)}
                  className="rounded text-ink focus:ring-ink w-4 h-4"
                />
                <span>Self-Signed</span>
              </label>
            </div>
          </div>

          {/* ML Toggle */}
          <div className="pt-3 border-t border-hairline-soft flex items-center justify-between">
            <div>
              <span className="text-xs font-bold text-ink block font-sans">Enable ML Risk & Anomaly Layer</span>
              <span className="text-[11px] text-text-muted">Graceful fallback to pure deterministic scoring when disabled (§4.1)</span>
            </div>
            <input
              type="checkbox"
              checked={enableML}
              onChange={(e) => setEnableML(e.target.checked)}
              className="w-5 h-5 rounded text-accent cursor-pointer"
            />
          </div>
        </div>

        {/* Right Column: Computed SCoRE Output */}
        <div className="lg:col-span-5 bg-canvas-soft border border-hairline/80 rounded-2xl p-6 sm:p-7 shadow-subtle space-y-6">
          <div className="flex flex-col items-center justify-center p-6 bg-white rounded-xl border border-hairline/80 shadow-sm">
            <ScoreGauge score={sim.score} grade={sim.riskClass} size={150} />
            <div className="mt-3 text-center">
              <span className="text-xs font-bold text-ink block font-sans">Simulated Session Posture</span>
              <span className="text-[11px] text-text-muted font-mono mt-0.5 block">
                Score: {sim.score}/100 ({sim.riskClass})
              </span>
            </div>
          </div>

          {/* Math breakdown */}
          <div className="grid grid-cols-2 gap-3 text-xs">
            <div className="p-3.5 bg-white rounded-xl border border-hairline/80 shadow-xs">
              <span className="text-[10px] text-text-muted block uppercase font-bold">DP Penalty</span>
              <span className="text-lg font-bold text-red-600 font-mono mt-0.5 block">-{sim.dp}</span>
            </div>
            <div className="p-3.5 bg-white rounded-xl border border-hairline/80 shadow-xs">
              <span className="text-[10px] text-text-muted block uppercase font-bold">ML Probability</span>
              <span className="text-lg font-bold text-ink font-mono mt-0.5 block">p_ml={sim.p_ml}</span>
            </div>
          </div>

          {/* Triggered Rules in Simulation */}
          <div className="space-y-2">
            <span className="text-xs font-bold uppercase tracking-wider text-text-muted block">
              Triggered Rules ({sim.findings.length})
            </span>
            {sim.findings.length === 0 ? (
              <div className="p-4 bg-emerald-50 text-emerald-800 text-xs rounded-xl border border-emerald-200 font-medium">
                Compliant configuration. Zero deterministic violations.
              </div>
            ) : (
              sim.findings.map((f, i) => (
                <div key={i} className="p-3 bg-white rounded-xl border border-hairline/80 text-xs flex items-center justify-between shadow-xs">
                  <div className="truncate pr-2">
                    <span className="font-mono text-[10px] font-bold text-text-muted block">{f.ruleId}</span>
                    <span className="font-semibold text-ink block truncate mt-0.5 font-sans">{f.title}</span>
                  </div>
                  <SeverityBadge severity={f.severity} size="sm" />
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
