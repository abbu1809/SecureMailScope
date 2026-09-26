import React from 'react';
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend
} from 'recharts';
import { ShieldCheck, ShieldAlert, Key, Calendar } from 'lucide-react';
import { PostureSummary } from '../../types/api';

interface ChartsSectionProps {
  summary: PostureSummary;
}

const COLORS = ['#141414', '#0066ff', '#ea580c', '#dc2626', '#707070', '#16a34a'];

export const ChartsSection: React.FC<ChartsSectionProps> = ({ summary }) => {
  // TLS Version Chart Data
  const tlsData = Object.entries(summary.tls_version_distribution).map(([version, count]) => ({
    name: version,
    count,
  }));

  // Protocol Distribution Data
  const protocolData = Object.entries(summary.protocol_distribution).map(([proto, count]) => ({
    name: proto,
    value: count,
  }));

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
      {/* 1. TLS Version Distribution */}
      <div className="bg-canvas border border-hairline/80 rounded-2xl p-6 shadow-subtle flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-bold text-ink text-sm font-sans">TLS Protocol Versions</h3>
              <p className="text-xs text-text-muted mt-0.5">RFC 8996 Deprecation Audit</p>
            </div>
            <div className="w-8 h-8 rounded-[30%] bg-field flex items-center justify-center text-ink text-xs font-bold font-mono">
              TLS
            </div>
          </div>

          <div className="h-[210px] w-full">
            {tlsData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={tlsData} layout="vertical" margin={{ top: 5, right: 20, left: 30, bottom: 5 }}>
                  <XAxis type="number" allowDecimals={false} stroke="#a3a3a3" fontSize={11} />
                  <YAxis type="category" dataKey="name" stroke="#141414" fontSize={11} width={80} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#141414', borderRadius: '12px', color: '#fff', fontSize: '12px', border: 'none', boxShadow: '0 4px 12px rgba(0,0,0,0.15)' }}
                  />
                  <Bar dataKey="count" fill="#141414" radius={[0, 6, 6, 0]} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-text-muted bg-canvas-soft/40 rounded-xl border border-dashed border-hairline">
                No TLS handshakes in capture
              </div>
            )}
          </div>
        </div>

        <div className="pt-4 border-t border-hairline-soft text-[11px] text-text-muted flex items-center justify-between">
          <span>Deprecated Protocols:</span>
          <span className={`font-bold font-mono px-2 py-0.5 rounded-full ${summary.deprecated_tls_count > 0 ? 'bg-red-50 text-red-700' : 'bg-field text-ink'}`}>
            {summary.deprecated_tls_count} Flagged
          </span>
        </div>
      </div>

      {/* 2. Cipher Suite Security Heatmap */}
      <div className="bg-canvas border border-hairline/80 rounded-2xl p-6 shadow-subtle flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-bold text-ink text-sm font-sans">Cipher Suite Security</h3>
              <p className="text-xs text-text-muted mt-0.5">AEAD vs Legacy Ciphers</p>
            </div>
            <div className="w-8 h-8 rounded-[30%] bg-field flex items-center justify-center text-ink">
              <Key className="w-4 h-4" />
            </div>
          </div>

          <div className="space-y-2 max-h-[210px] overflow-y-auto pr-1">
            {summary.cipher_heatmap.length > 0 ? (
              summary.cipher_heatmap.map((item, idx) => (
                <div
                  key={idx}
                  className={`p-2.5 rounded-xl border text-xs flex items-center justify-between transition-all ${
                    item.is_secure
                      ? 'bg-emerald-50/40 border-emerald-200 text-ink'
                      : 'bg-red-50/40 border-red-200 text-red-900'
                  }`}
                >
                  <div className="truncate pr-2">
                    <span className="font-mono font-bold block truncate text-[11px]">
                      {item.cipher}
                    </span>
                    <span className="text-[10px] text-text-muted block mt-0.5">
                      {item.is_secure ? 'Approved AEAD / Modern' : 'Insecure / Prohibited'}
                    </span>
                  </div>
                  <span className="text-xs font-bold px-2 py-0.5 rounded-full bg-white border border-hairline shrink-0 font-mono shadow-xs">
                    {item.count}x
                  </span>
                </div>
              ))
            ) : (
              <div className="h-[210px] flex items-center justify-center text-xs text-text-muted bg-canvas-soft/40 rounded-xl border border-dashed border-hairline">
                No encrypted cipher suites observed
              </div>
            )}
          </div>
        </div>

        <div className="pt-4 border-t border-hairline-soft text-[11px] text-text-muted flex items-center justify-between">
          <span>Distinct Ciphers Active:</span>
          <span className="font-bold text-ink font-mono bg-field px-2 py-0.5 rounded-full">{summary.cipher_heatmap.length}</span>
        </div>
      </div>

      {/* 3. Certificate Expiry Timeline */}
      <div className="bg-canvas border border-hairline/80 rounded-2xl p-6 shadow-subtle flex flex-col justify-between">
        <div>
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="font-bold text-ink text-sm font-sans">Certificate Expiration</h3>
              <p className="text-xs text-text-muted mt-0.5">X.509 Chain Health & Keys</p>
            </div>
            <div className="w-8 h-8 rounded-[30%] bg-field flex items-center justify-center text-ink">
              <Calendar className="w-4 h-4" />
            </div>
          </div>

          <div className="space-y-2 max-h-[210px] overflow-y-auto pr-1">
            {summary.cert_expiry_timeline.length > 0 ? (
              summary.cert_expiry_timeline.map((cert, idx) => (
                <div
                  key={idx}
                  className={`p-2.5 rounded-xl border text-xs flex items-center justify-between transition-all ${
                    cert.is_expired
                      ? 'bg-red-50 border-red-200 text-red-900'
                      : cert.days_until_expiry <= 14
                      ? 'bg-amber-50 border-amber-200 text-amber-900'
                      : 'bg-canvas-soft/80 border-hairline/80 text-ink'
                  }`}
                >
                  <div className="truncate pr-2">
                    <span className="font-semibold block truncate text-[11px]">
                      {cert.subject}
                    </span>
                    <span className="text-[10px] text-text-muted block mt-0.5 font-mono">
                      {cert.key_algo} {cert.key_bits}b
                    </span>
                  </div>
                  <div className="text-right shrink-0">
                    <span className={`text-[11px] font-bold font-mono px-2 py-0.5 rounded-full ${cert.is_expired ? 'bg-red-100 text-red-700' : 'bg-white border border-hairline'}`}>
                      {cert.is_expired ? 'EXPIRED' : `${cert.days_until_expiry}d left`}
                    </span>
                  </div>
                </div>
              ))
            ) : (
              <div className="h-[210px] flex items-center justify-center text-xs text-text-muted bg-canvas-soft/40 rounded-xl border border-dashed border-hairline">
                No X.509 certificates in cleartext
              </div>
            )}
          </div>
        </div>

        <div className="pt-4 border-t border-hairline-soft text-[11px] text-text-muted flex items-center justify-between">
          <span>Weak Key or Expired:</span>
          <span className={`font-bold font-mono px-2 py-0.5 rounded-full ${summary.weak_cert_count > 0 ? 'bg-red-50 text-red-700' : 'bg-field text-ink'}`}>
            {summary.weak_cert_count} Flagged
          </span>
        </div>
      </div>
    </div>
  );
};
