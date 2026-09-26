import React from 'react';
import { Zap, ShieldAlert, Cpu, Fingerprint, ArrowRight } from 'lucide-react';
import { AnomalyItem } from '../../types/api';
import { SeverityBadge } from '../common/SeverityBadge';

interface AnomalyRadarProps {
  anomalies: AnomalyItem[];
  onSelectSession: (sessionId: string) => void;
}

export const AnomalyRadar: React.FC<AnomalyRadarProps> = ({ anomalies, onSelectSession }) => {
  return (
    <div className="bg-canvas border border-hairline/80 rounded-2xl p-6 sm:p-7 shadow-subtle space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-5 border-b border-hairline-soft">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-[30%] bg-accent text-white flex items-center justify-center shadow-xs">
            <Zap className="w-4 h-4" />
          </div>
          <div>
            <h3 className="font-bold text-ink text-base font-sans">AI Anomaly Detection Radar</h3>
            <p className="text-xs text-text-muted mt-0.5">
              Isolation Forest model flagging outlier JA3/JA3S fingerprints and rare cipher permutations
            </p>
          </div>
        </div>
        <span className="text-xs font-bold font-mono px-3 py-1 bg-blue-50 text-accent rounded-full border border-blue-200 self-start sm:self-auto shadow-xs">
          {anomalies.length} Flagged Anomalies
        </span>
      </div>

      {anomalies.length === 0 ? (
        <div className="py-12 text-center text-text-muted text-sm bg-canvas-soft/40 rounded-xl border border-dashed border-hairline">
          No statistical anomalies detected in this network capture. Handshake features fall within normal baseline distributions.
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {anomalies.map((anom) => (
            <div
              key={anom.session_id}
              onClick={() => onSelectSession(anom.session_id)}
              className="group cursor-pointer bg-canvas hover:bg-canvas-soft/80 border border-hairline/80 hover:border-hairline rounded-xl p-5 transition-all duration-150 flex flex-col justify-between shadow-xs hover:shadow-subtle"
            >
              <div>
                <div className="flex items-center justify-between mb-2.5">
                  <div className="flex items-center gap-2">
                    <span className="font-mono font-bold text-xs text-ink">{anom.session_id}</span>
                    <span className="text-[10px] uppercase font-bold text-text-muted px-2 py-0.5 bg-field rounded-full">
                      {anom.protocol}
                    </span>
                  </div>
                  <SeverityBadge severity={anom.risk_class} size="sm" />
                </div>

                <div className="text-xs text-text-muted font-mono mb-2.5 truncate bg-field p-1.5 rounded-lg">
                  {anom.src_dst}
                </div>

                <p className="text-xs text-ink font-semibold mb-3 leading-snug">
                  {anom.reason}
                </p>

                {anom.ja3 && (
                  <div className="bg-canvas-soft p-2.5 rounded-lg mb-3 flex items-center gap-2 text-[11px] font-mono text-text-muted border border-hairline-soft">
                    <Fingerprint className="w-3.5 h-3.5 text-accent shrink-0" />
                    <span className="truncate">JA3: {anom.ja3}</span>
                  </div>
                )}

                {anom.shap_factors.length > 0 && (
                  <div className="space-y-1.5 pt-1">
                    <span className="text-[10px] uppercase tracking-wider font-bold text-text-muted block">
                      Top ML Contributing Signals:
                    </span>
                    <div className="flex flex-wrap gap-1.5">
                      {anom.shap_factors.map((factor, idx) => (
                        <span
                          key={idx}
                          className="text-[10px] bg-white border border-hairline/80 px-2.5 py-0.5 rounded-full text-text-muted font-medium"
                        >
                          {factor}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>

              <div className="pt-3.5 mt-3.5 border-t border-hairline-soft flex items-center justify-between text-xs text-accent font-semibold group-hover:translate-x-0.5 transition-transform">
                <span>Investigate Session Trace</span>
                <ArrowRight className="w-3.5 h-3.5" />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
