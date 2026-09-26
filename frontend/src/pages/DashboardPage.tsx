import React, { useState, useEffect } from 'react';
import { Download, FileCode, Layers, ShieldCheck, RefreshCw, AlertCircle } from 'lucide-react';
import { useCaptures } from '../hooks/useCaptures';
import { usePostureSummary, useSessions, useAnomalies, useSessionDetail } from '../hooks/useAnalytics';
import { apiClient } from '../services/api';
import { CaptureSelector } from '../components/dashboard/CaptureSelector';
import { ExecutiveSummary } from '../components/dashboard/ExecutiveSummary';
import { ChartsSection } from '../components/dashboard/ChartsSection';
import { AnomalyRadar } from '../components/dashboard/AnomalyRadar';
import { SessionTable } from '../components/dashboard/SessionTable';
import { RemediationQueue } from '../components/dashboard/RemediationQueue';
import { ComplianceMatrix } from '../components/dashboard/ComplianceMatrix';
import { SessionDetailModal } from '../components/dashboard/SessionDetailModal';

export const DashboardPage: React.FC = () => {
  const { data: captures = [], isLoading: capturesLoading, isError, error, refetch: refetchCaptures } = useCaptures();
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>('');
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);

  // Set default capture once loaded
  useEffect(() => {
    if (captures.length > 0 && !selectedCaptureId) {
      setSelectedCaptureId(captures[0].id);
    }
  }, [captures, selectedCaptureId]);

  const { data: summary, isLoading: summaryLoading } = usePostureSummary(selectedCaptureId);
  const { data: sessions = [], isLoading: sessionsLoading } = useSessions(selectedCaptureId);
  const { data: anomalies = [] } = useAnomalies(selectedCaptureId);
  const { data: activeSessionDetail } = useSessionDetail(selectedCaptureId, selectedSessionId || undefined);

  if (capturesLoading) {
    return (
      <div className="max-w-7xl mx-auto py-24 px-4 text-center space-y-4">
        <RefreshCw className="w-8 h-8 animate-spin mx-auto text-accent" />
        <div className="space-y-1">
          <p className="text-sm font-semibold text-ink">Loading network capture records...</p>
          <p className="text-xs text-text-muted font-mono">Connecting to: {apiClient.getBaseUrl()}</p>
        </div>
      </div>
    );
  }

  if (isError || captures.length === 0) {
    return (
      <div className="max-w-3xl mx-auto py-16 px-4">
        <div className="bg-canvas border border-red-200/80 rounded-2xl p-6 sm:p-8 shadow-subtle space-y-5 text-center">
          <div className="w-12 h-12 rounded-2xl bg-red-50 text-red-600 flex items-center justify-center mx-auto">
            <AlertCircle className="w-6 h-6" />
          </div>
          <div className="space-y-2">
            <h2 className="text-lg font-bold text-ink font-sans">Unable to Reach Backend API</h2>
            <p className="text-xs sm:text-sm text-text-muted max-w-md mx-auto">
              {error instanceof Error ? error.message : 'The frontend could not retrieve capture records from the backend server.'}
            </p>
          </div>

          <div className="bg-field p-3.5 rounded-xl border border-hairline/60 font-mono text-xs text-text-muted break-all text-left">
            <span className="font-bold text-ink block mb-1">Target API Base URL:</span>
            <span>{apiClient.getBaseUrl()}</span>
          </div>

          <div className="flex flex-col sm:flex-row items-center justify-center gap-3 pt-2">
            <button
              onClick={() => refetchCaptures()}
              className="btn-primary w-full sm:w-auto px-5 py-2.5 text-xs font-semibold flex items-center justify-center gap-2"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              <span>Retry Connection</span>
            </button>
            <a
              href={`${apiClient.getBaseUrl()}/health`}
              target="_blank"
              rel="noopener noreferrer"
              className="btn-outline w-full sm:w-auto px-5 py-2.5 text-xs font-semibold flex items-center justify-center gap-2 text-ink"
            >
              <span>Test /api/health</span>
            </a>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 space-y-10">
      {/* Top Bar: Capture Selector & Report Downloader */}
      <div className="space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold tracking-tight text-ink font-sans">
              Cryptographic Posture Dashboard.
            </h1>
            <p className="text-xs sm:text-sm text-text-muted mt-1 font-light">
              Triage email conversations, inspect STARTTLS stripping incidents, and audit NIST compliance.
            </p>
          </div>

          {/* Quick Report Download Links */}
          {selectedCaptureId && (
            <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
              <a
                href={apiClient.getJsonReportUrl(selectedCaptureId)}
                target="_blank"
                rel="noreferrer"
                className="btn-outline h-9 text-xs px-3 flex items-center gap-1.5 shadow-xs font-semibold"
                title="Download Schema-versioned JSON Audit"
              >
                <Download className="w-3.5 h-3.5" />
                <span>JSON</span>
              </a>
              <a
                href={apiClient.getHtmlReportUrl(selectedCaptureId)}
                target="_blank"
                rel="noreferrer"
                className="btn-outline h-9 text-xs px-3 flex items-center gap-1.5 shadow-xs font-semibold"
                title="Open Standalone HTML Audit Report"
              >
                <FileCode className="w-3.5 h-3.5" />
                <span>HTML</span>
              </a>
              <a
                href={apiClient.getPdfReportUrl(selectedCaptureId)}
                target="_blank"
                rel="noreferrer"
                className="btn-primary h-9 text-xs px-4 flex items-center gap-1.5 shadow-xs font-semibold"
                title="Print or Export PDF Audit Report"
              >
                <Download className="w-3.5 h-3.5" />
                <span>PDF Report</span>
              </a>
            </div>
          )}
        </div>

        {/* Capture Selector */}
        <CaptureSelector
          selectedCaptureId={selectedCaptureId}
          onSelectCapture={(id) => {
            setSelectedCaptureId(id);
            setSelectedSessionId(null);
          }}
        />
      </div>

      {summaryLoading || !summary ? (
        <div className="py-16 text-center space-y-3 bg-canvas-soft rounded-md">
          <RefreshCw className="w-6 h-6 animate-spin mx-auto text-ink" />
          <p className="text-xs text-text-muted">Analyzing capture cryptographic artifacts...</p>
        </div>
      ) : (
        <div className="space-y-10">
          {/* Executive Posture & Score */}
          <ExecutiveSummary summary={summary} />

          {/* Visualization Charts */}
          <ChartsSection summary={summary} />

          {/* AI Anomaly Radar */}
          <AnomalyRadar
            anomalies={anomalies}
            onSelectSession={(sessId) => setSelectedSessionId(sessId)}
          />

          {/* Interactive Reconstructed Sessions Table */}
          <div className="space-y-3">
            <div>
              <h2 className="text-xl font-bold tracking-tight text-ink">
                Reconstructed Mail Sessions ({sessions.length})
              </h2>
              <p className="text-xs text-text-muted">
                Passive TCP flow reassembly with STARTTLS state and certificate chain extraction.
              </p>
            </div>
            <SessionTable
              sessions={sessions}
              onSelectSession={(sessId) => setSelectedSessionId(sessId)}
              selectedSessionId={selectedSessionId}
            />
          </div>

          {/* Remediation Roadmap & Compliance Matrix */}
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-8">
            <div className="lg:col-span-7">
              <RemediationQueue remediations={summary.top_remediations} />
            </div>
            <div className="lg:col-span-5">
              <ComplianceMatrix complianceMatrix={summary.compliance_matrix} />
            </div>
          </div>
        </div>
      )}

      {/* Session Deep-Dive Inspector Modal */}
      {selectedSessionId && (
        <SessionDetailModal
          session={activeSessionDetail || sessions.find((s) => s.id === selectedSessionId) || null}
          onClose={() => setSelectedSessionId(null)}
        />
      )}
    </div>
  );
};
