import React, { useState, useEffect } from 'react';
import { Download, FileText, FileCode, RefreshCw, Printer, ExternalLink, Shield } from 'lucide-react';
import { useCaptures } from '../hooks/useCaptures';
import { apiClient } from '../services/api';
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '../components/ui/select';

export const ReportsPage: React.FC = () => {
  const { data: captures = [] } = useCaptures();
  const [selectedCaptureId, setSelectedCaptureId] = useState<string>('');

  useEffect(() => {
    if (captures.length > 0 && !selectedCaptureId) {
      setSelectedCaptureId(captures[0].id);
    }
  }, [captures, selectedCaptureId]);

  const selectedCapture = captures.find((c) => c.id === selectedCaptureId);

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="space-y-2">
        <div className="inline-flex items-center gap-2 bg-canvas-soft border border-hairline/80 px-3 py-1 rounded-full text-xs font-semibold text-ink">
          <FileText className="w-3.5 h-3.5 text-accent" />
          <span>Multi-Format Audit Export Center §3.6</span>
        </div>
        <h1 className="text-3xl font-bold tracking-tight text-ink font-sans">
          Audit Reports & Forensic Evidence Export.
        </h1>
        <p className="text-sm text-text-muted font-light max-w-3xl leading-relaxed">
          Export formal cryptographic posture assessment reports in schema-versioned JSON (v1.1.0),
          standalone self-contained HTML, or printable PDF documents.
        </p>
      </div>

      {/* Capture Selector & Action Bar */}
      <div className="bg-canvas border border-hairline/80 rounded-2xl p-5 sm:p-6 shadow-subtle flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
        <div className="w-full lg:w-auto flex-1 max-w-lg">
          <label className="text-[11px] uppercase tracking-wider font-bold text-text-muted mb-1.5 block">
            Select Capture for Report Generation
          </label>

          <Select
            value={selectedCaptureId || selectedCapture?.id}
            onValueChange={(val) => setSelectedCaptureId(val)}
          >
            <SelectTrigger className="w-full h-11 bg-field hover:bg-canvas-soft rounded-xl border-hairline/80">
              <span className="font-bold text-xs truncate">
                {selectedCapture?.filename} ({selectedCapture?.overall_score}/100 - Grade {selectedCapture?.overall_grade})
              </span>
            </SelectTrigger>
            <SelectContent className="w-[320px] sm:w-[460px]">
              <SelectGroup>
                <SelectLabel className="px-3 py-2 text-xs font-bold text-text-muted border-b border-hairline-soft">
                  Target PCAP Capture
                </SelectLabel>
                {captures.map((c) => (
                  <SelectItem key={c.id} value={c.id} className="py-2.5 px-3 border-b border-hairline-soft/60 last:border-none">
                    <div className="flex items-center justify-between w-full gap-2 pr-2">
                      <span className="font-mono font-bold truncate text-xs">{c.filename}</span>
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-field font-bold font-mono">
                        {c.overall_score}/100 ({c.overall_grade})
                      </span>
                    </div>
                  </SelectItem>
                ))}
              </SelectGroup>
            </SelectContent>
          </Select>
        </div>

        {selectedCaptureId && (
          <div className="flex flex-wrap items-center gap-2.5 justify-start lg:justify-end pt-1 lg:pt-5">
            <a
              href={apiClient.getJsonReportUrl(selectedCaptureId)}
              target="_blank"
              rel="noreferrer"
              className="btn-outline h-11 px-4 text-xs font-semibold flex items-center gap-2 shadow-sm"
            >
              <Download className="w-3.5 h-3.5" />
              <span>Export JSON (v1.1)</span>
            </a>

            <a
              href={apiClient.getHtmlReportUrl(selectedCaptureId)}
              target="_blank"
              rel="noreferrer"
              className="btn-outline h-11 px-4 text-xs font-semibold flex items-center gap-2 shadow-sm"
            >
              <FileCode className="w-3.5 h-3.5" />
              <span>Open HTML</span>
            </a>

            <a
              href={apiClient.getPdfReportUrl(selectedCaptureId)}
              target="_blank"
              rel="noreferrer"
              className="btn-primary h-11 px-5 text-xs font-semibold flex items-center gap-2 shadow-sm"
            >
              <Printer className="w-3.5 h-3.5" />
              <span>Print / Save PDF</span>
            </a>
          </div>
        )}
      </div>

      {/* Embedded Live Report Preview Frame */}
      {selectedCaptureId ? (
        <div className="bg-canvas border border-hairline/80 rounded-2xl overflow-hidden shadow-subtle space-y-2">
          <div className="p-4 bg-canvas-soft/80 border-b border-hairline flex items-center justify-between text-xs text-text-muted">
            <span className="font-mono font-bold text-ink">Live Interactive Report Preview: {selectedCapture?.filename}</span>
            <a
              href={apiClient.getHtmlReportUrl(selectedCaptureId)}
              target="_blank"
              rel="noreferrer"
              className="flex items-center gap-1.5 text-accent font-semibold hover:underline"
            >
              <span>Open Standalone Report</span>
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          </div>
          <div className="w-full h-[750px] bg-white">
            <iframe
              src={apiClient.getHtmlReportUrl(selectedCaptureId)}
              title="Report Preview"
              className="w-full h-full border-none"
            />
          </div>
        </div>
      ) : (
        <div className="py-24 text-center text-text-muted text-sm bg-canvas-soft rounded-2xl border border-dashed border-hairline">
          Select a capture above to view and export the security report.
        </div>
      )}
    </div>
  );
};
