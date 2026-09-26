import React from 'react';
import { Shield, Lock, CheckCircle2, ArrowUpRight } from 'lucide-react';
import { Link } from 'react-router-dom';

export const Footer: React.FC = () => {
  return (
    <footer className="mt-24 w-full bg-ink text-white rounded-t-[32px] pt-16 pb-12 px-6 sm:px-12">
      <div className="max-w-7xl mx-auto grid grid-cols-1 md:grid-cols-4 gap-12 border-b border-neutral-800 pb-12">
        {/* Col 1: Brand & Vision */}
        <div className="md:col-span-2 space-y-4">
          <div className="flex items-center gap-2.5">
            <div className="w-8 h-8 rounded-squircle bg-white flex items-center justify-center text-ink">
              <Shield className="w-4 h-4" />
            </div>
            <span className="font-bold text-xl tracking-tight">SecureMailScope.</span>
          </div>
          <p className="text-text-faint text-sm leading-relaxed max-w-md font-light">
            AI-Assisted Cryptographic Security Posture Assessment for Secure Email Communications.
            Passive, offline, zero-network-scanning evaluation of SMTP, IMAP, and POP3 infrastructure.
          </p>
          <div className="flex items-center gap-4 text-xs text-text-faint pt-2">
            <span className="flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-accent" /> NIST SP 800-52r2
            </span>
            <span className="flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-accent" /> RFC 8996
            </span>
            <span className="flex items-center gap-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-accent" /> RFC 8314
            </span>
          </div>
        </div>

        {/* Col 2: Navigation */}
        <div className="space-y-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-text-faint">Platform</div>
          <ul className="space-y-2 text-sm text-neutral-300">
            <li>
              <Link to="/dashboard" className="hover:text-white transition-colors">
                SOC Posture Dashboard
              </Link>
            </li>
            <li>
              <Link to="/rules" className="hover:text-white transition-colors">
                Cryptographic Rules (35)
              </Link>
            </li>
            <li>
              <Link to="/reports" className="hover:text-white transition-colors">
                Audit Export Center
              </Link>
            </li>
            <li>
              <Link to="/playground" className="hover:text-white transition-colors">
                Live Scenario Tester
              </Link>
            </li>
          </ul>
        </div>

        {/* Col 3: Specifications */}
        <div className="space-y-3">
          <div className="text-xs font-semibold uppercase tracking-wider text-text-faint">SIH PS 26159</div>
          <ul className="space-y-2 text-sm text-text-faint">
            <li>SCoRE Scoring Engine §4.1</li>
            <li>JA3/JA3S Isolation Forest AI</li>
            <li>STARTTLS Stripping Detector</li>
            <li>Offline Single-node Runtime</li>
          </ul>
        </div>
      </div>

      <div className="max-w-7xl mx-auto pt-8 flex flex-col sm:flex-row items-center justify-between gap-4 text-xs text-text-faint">
        <div>© 2026 SecureMailScope · Smart India Hackathon Prototype (PS 26159).</div>
        <div className="flex items-center gap-6">
          <span className="text-text-muted">Zero Cloud Dependency</span>
          <span className="text-text-muted">No Payload Decryption</span>
          <span className="text-white font-medium">IEEE 830 Specification</span>
        </div>
      </div>
    </footer>
  );
};
