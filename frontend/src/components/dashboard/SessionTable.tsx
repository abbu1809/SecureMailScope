import React, { useState } from 'react';
import { Search, Filter, ArrowUpDown, ChevronRight, ShieldAlert, Lock, CheckCircle2 } from 'lucide-react';
import { Session } from '../../types/api';
import { SeverityBadge } from '../common/SeverityBadge';

interface SessionTableProps {
  sessions: Session[];
  onSelectSession: (sessionId: string) => void;
  selectedSessionId?: string | null;
}

export const SessionTable: React.FC<SessionTableProps> = ({
  sessions,
  onSelectSession,
  selectedSessionId,
}) => {
  const [search, setSearch] = useState('');
  const [protocolFilter, setProtocolFilter] = useState('ALL');
  const [riskFilter, setRiskFilter] = useState('ALL');
  const [sortField, setSortField] = useState<'score' | 'packet_count' | 'protocol'>('score');
  const [sortAsc, setSortAsc] = useState(true);

  // Filter sessions
  const filteredSessions = sessions.filter((s) => {
    if (protocolFilter !== 'ALL' && s.protocol !== protocolFilter) return false;
    if (riskFilter !== 'ALL' && s.score_trace.risk_class.toUpperCase() !== riskFilter) return false;
    if (search) {
      const q = search.toLowerCase();
      const matchIp = s.src_ip.toLowerCase().includes(q) || s.dst_ip.toLowerCase().includes(q);
      const matchId = s.id.toLowerCase().includes(q);
      const matchCipher = s.tls_summary?.negotiated_cipher?.toLowerCase().includes(q);
      const matchBanner = s.banner?.toLowerCase().includes(q);
      if (!matchIp && !matchId && !matchCipher && !matchBanner) return false;
    }
    return true;
  });

  // Sort sessions
  const sortedSessions = [...filteredSessions].sort((a, b) => {
    let diff = 0;
    if (sortField === 'score') {
      diff = a.score_trace.score - b.score_trace.score;
    } else if (sortField === 'packet_count') {
      diff = a.packet_count - b.packet_count;
    } else if (sortField === 'protocol') {
      diff = a.protocol.localeCompare(b.protocol);
    }
    return sortAsc ? diff : -diff;
  });

  const handleSort = (field: 'score' | 'packet_count' | 'protocol') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(true);
    }
  };

  return (
    <div className="bg-canvas border border-hairline/80 rounded-2xl overflow-hidden shadow-subtle">
      {/* Controls Bar */}
      <div className="p-4 sm:p-5 border-b border-hairline-soft flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
        {/* Search */}
        <div className="relative flex-1 max-w-lg">
          <Search className="w-4 h-4 text-text-muted absolute left-3.5 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search IP, session ID, cipher, or banner..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input-field w-full pl-10 rounded-xl bg-field h-11 text-xs sm:text-sm"
          />
        </div>

        {/* Filter Badges & Segmented Controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Protocol Filter */}
          <div className="flex items-center bg-canvas-soft p-1 rounded-full text-xs font-semibold border border-hairline-soft">
            {['ALL', 'SMTP', 'IMAP', 'POP3'].map((p) => (
              <button
                key={p}
                onClick={() => setProtocolFilter(p)}
                className={`px-3 py-1 rounded-full transition-all ${
                  protocolFilter === p
                    ? 'bg-canvas text-ink shadow-subtle font-bold'
                    : 'text-text-muted hover:text-ink'
                }`}
              >
                {p}
              </button>
            ))}
          </div>

          {/* Risk Tier Filter */}
          <div className="flex items-center bg-canvas-soft p-1 rounded-full text-xs font-semibold border border-hairline-soft">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'SECURE'].map((r) => (
              <button
                key={r}
                onClick={() => setRiskFilter(r)}
                className={`px-3 py-1 rounded-full transition-all ${
                  riskFilter === r
                    ? 'bg-canvas text-ink shadow-subtle font-bold'
                    : 'text-text-muted hover:text-ink'
                }`}
              >
                {r}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="overflow-x-auto">
        <table className="w-full text-left border-collapse text-sm">
          <thead>
            <tr className="bg-canvas-soft/70 border-b border-hairline text-text-muted text-[11px] uppercase tracking-wider font-bold">
              <th className="py-3.5 px-4 sm:px-5">Session ID</th>
              <th className="py-3.5 px-4 sm:px-5">Endpoints (Client &rarr; Server)</th>
              <th className="py-3.5 px-4 cursor-pointer hover:text-ink" onClick={() => handleSort('protocol')}>
                <div className="flex items-center gap-1">
                  <span>Protocol</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3.5 px-4">STARTTLS State</th>
              <th className="py-3.5 px-4">TLS Version & Cipher</th>
              <th className="py-3.5 px-4 cursor-pointer hover:text-ink" onClick={() => handleSort('score')}>
                <div className="flex items-center gap-1">
                  <span>SCoRE</span>
                  <ArrowUpDown className="w-3 h-3" />
                </div>
              </th>
              <th className="py-3.5 px-4">Findings</th>
              <th className="py-3.5 px-4 text-right">Action</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-hairline-soft">
            {sortedSessions.length === 0 ? (
              <tr>
                <td colSpan={8} className="py-12 text-center text-text-muted text-sm">
                  No sessions match current filter criteria.
                </td>
              </tr>
            ) : (
              sortedSessions.map((s) => {
                const isSelected = s.id === selectedSessionId;
                const isStripped = s.starttls_state === 'STRIPPING_SUSPECTED';

                return (
                  <tr
                    key={s.id}
                    onClick={() => onSelectSession(s.id)}
                    className={`cursor-pointer transition-colors duration-100 ${
                      isSelected
                        ? 'bg-blue-50/40'
                        : isStripped
                        ? 'bg-red-50/20 hover:bg-red-50/40'
                        : 'hover:bg-canvas-soft/60'
                    }`}
                  >
                    <td className="py-3.5 px-4 font-mono font-bold text-xs text-ink">
                      {s.id}
                    </td>

                    <td className="py-3.5 px-4 font-mono text-xs text-text-muted">
                      <span className="text-ink font-semibold">{s.src_ip}</span>:{s.src_port}
                      <span className="mx-1 text-text-faint">&rarr;</span>
                      <span className="text-ink font-semibold">{s.dst_ip}</span>:{s.dst_port}
                    </td>

                    <td className="py-3.5 px-4">
                      <span className="px-2.5 py-0.5 rounded-full text-xs font-bold bg-field text-ink">
                        {s.protocol}
                      </span>
                    </td>

                    <td className="py-3.5 px-4">
                      <span
                        className={`text-xs font-semibold px-2 py-0.5 rounded-full ${
                          isStripped
                            ? 'bg-red-100 text-red-700 font-bold border border-red-200 animate-pulse'
                            : s.starttls_state === 'COMPLETED'
                            ? 'bg-emerald-50 text-emerald-700'
                            : 'bg-neutral-100 text-neutral-600'
                        }`}
                      >
                        {s.starttls_state}
                      </span>
                    </td>

                    <td className="py-3.5 px-4 text-xs">
                      {s.tls_summary?.negotiated_version ? (
                        <div className="truncate max-w-[200px]">
                          <span className="font-semibold text-ink block">
                            {s.tls_summary.negotiated_version}
                          </span>
                          <span className="text-[11px] text-text-muted font-mono block truncate">
                            {s.tls_summary.negotiated_cipher}
                          </span>
                        </div>
                      ) : (
                        <span className="text-red-600 font-semibold text-xs">Cleartext</span>
                      )}
                    </td>

                    <td className="py-3.5 px-4">
                      <div className="flex items-center gap-2">
                        <span className="font-bold font-sans text-sm text-ink">
                          {s.score_trace.score}
                        </span>
                        <SeverityBadge severity={s.score_trace.risk_class} size="sm" />
                      </div>
                    </td>

                    <td className="py-3.5 px-4">
                      {s.findings.length > 0 ? (
                        <span className="px-2 py-0.5 rounded-full text-xs font-bold bg-red-50 text-red-700 border border-red-200">
                          {s.findings.length} Issue{s.findings.length > 1 ? 's' : ''}
                        </span>
                      ) : (
                        <span className="text-xs text-emerald-600 font-semibold flex items-center gap-1">
                          <CheckCircle2 className="w-3.5 h-3.5" /> Clean
                        </span>
                      )}
                    </td>

                    <td className="py-3.5 px-4 text-right">
                      <button className="p-1 rounded-full hover:bg-canvas-soft text-text-muted hover:text-ink">
                        <ChevronRight className="w-4 h-4" />
                      </button>
                    </td>
                  </tr>
                );
              })
            )}
          </tbody>
        </table>
      </div>

      {/* Footer Info */}
      <div className="p-3 bg-canvas-soft/40 border-t border-hairline-soft text-xs text-text-muted flex items-center justify-between">
        <span>Showing {filteredSessions.length} of {sessions.length} sessions</span>
        <span className="font-mono text-[11px]">Click any row for SCoRE Trace & Evidence</span>
      </div>
    </div>
  );
};
