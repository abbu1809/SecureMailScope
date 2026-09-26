import React, { useState } from 'react';
import { Upload, Download, RefreshCw, FileCode, ShieldAlert, Sparkles } from 'lucide-react';
import { useCaptures, useUploadPCAP, useResetDemoSamples } from '../../hooks/useCaptures';
import { apiClient } from '../../services/api';
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectLabel,
  SelectTrigger,
  SelectValue,
} from '../ui/select';

interface CaptureSelectorProps {
  selectedCaptureId: string;
  onSelectCapture: (id: string) => void;
}

export const CaptureSelector: React.FC<CaptureSelectorProps> = ({
  selectedCaptureId,
  onSelectCapture,
}) => {
  const { data: captures = [] } = useCaptures();
  const uploadMutation = useUploadPCAP();
  const resetMutation = useResetDemoSamples();
  const [uploadError, setUploadError] = useState<string | null>(null);

  const selectedCapture = captures.find((c) => c.id === selectedCaptureId) || captures[0];

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploadError(null);
    try {
      const newCap = await uploadMutation.mutateAsync({ file, useML: true });
      onSelectCapture(newCap.id);
    } catch (err: any) {
      setUploadError(err.message || 'Upload failed');
    }
  };

  const handleReset = async () => {
    await resetMutation.mutateAsync();
    if (captures.length > 0) {
      onSelectCapture(captures[0].id);
    }
  };

  return (
    <div className="bg-canvas border border-hairline/80 rounded-2xl p-4 sm:p-5 shadow-subtle flex flex-col lg:flex-row items-stretch lg:items-center justify-between gap-4">
      {/* Active Capture Display & Radix Select */}
      <div className="w-full lg:w-auto flex-1 max-w-2xl">
        <label className="text-[11px] uppercase tracking-wider font-bold text-text-muted mb-1.5 flex items-center justify-between">
          <span>Active Network Capture Target</span>
          <span className="text-[10px] font-mono text-accent">{captures.length} Scenarios Ready</span>
        </label>

        <Select
          value={selectedCaptureId || selectedCapture?.id}
          onValueChange={(val) => onSelectCapture(val)}
        >
          <SelectTrigger className="w-full h-12 bg-field hover:bg-canvas-soft border-hairline/80 px-4 rounded-xl transition-all">
            <div className="flex items-center gap-3 truncate text-left">
              <div className="w-7 h-7 rounded-[30%] bg-ink text-white flex items-center justify-center shrink-0 shadow-sm">
                <FileCode className="w-3.5 h-3.5" />
              </div>
              <div className="truncate">
                <span className="font-bold text-xs sm:text-sm text-ink block truncate">
                  {selectedCapture?.filename || 'Select Target Capture...'}
                </span>
                <span className="text-[11px] text-text-muted font-mono block truncate">
                  {selectedCapture?.session_count} Sessions · SCoRE: {selectedCapture?.overall_score}/100 ({selectedCapture?.overall_grade})
                </span>
              </div>
            </div>
          </SelectTrigger>

          <SelectContent className="w-[340px] sm:w-[500px]">
            <SelectGroup>
              <SelectLabel className="flex items-center justify-between px-3 py-2 text-xs font-bold text-text-muted border-b border-hairline-soft">
                <span>Synthetic Test Scenarios & Captures</span>
                <span className="text-accent font-mono text-[10px]">{captures.length} Available</span>
              </SelectLabel>

              {captures.map((cap) => {
                const isGood = cap.overall_score >= 80;
                const isMed = cap.overall_score >= 50;

                return (
                  <SelectItem
                    key={cap.id}
                    value={cap.id}
                    className="py-2.5 px-3 border-b border-hairline-soft/60 last:border-none cursor-pointer"
                  >
                    <div className="flex items-start gap-3 w-full pr-4">
                      <span
                        className={`w-2.5 h-2.5 rounded-full mt-1 shrink-0 ${
                          isGood ? 'bg-emerald-500' : isMed ? 'bg-amber-500' : 'bg-red-500'
                        }`}
                      />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center justify-between gap-2">
                          <span className="font-bold text-xs text-ink truncate font-mono">
                            {cap.filename}
                          </span>
                          <span className="font-mono text-[10px] px-2 py-0.5 rounded-full bg-field shrink-0 font-bold">
                            {cap.overall_score} ({cap.overall_grade})
                          </span>
                        </div>
                        {cap.scenario_description && (
                          <p className="text-[11px] text-text-muted line-clamp-1 mt-0.5 font-normal leading-snug">
                            {cap.scenario_description}
                          </p>
                        )}
                      </div>
                    </div>
                  </SelectItem>
                );
              })}
            </SelectGroup>
          </SelectContent>
        </Select>
      </div>

      {/* Upload PCAP, Download Raw PCAP, and Quick Reset actions */}
      <div className="flex flex-wrap items-center gap-2.5 justify-start lg:justify-end pt-1 lg:pt-5">
        {selectedCapture && (
          <a
            href={apiClient.getDownloadUrl(selectedCapture.id)}
            download={selectedCapture.filename}
            className="btn-outline h-11 px-4 text-xs font-semibold flex items-center gap-2 text-ink hover:bg-canvas-soft border-hairline/80 shadow-sm"
            title={`Download ${selectedCapture.filename} binary PCAP`}
          >
            <Download className="w-3.5 h-3.5 text-accent" />
            <span>Download .pcap</span>
          </a>
        )}

        <label className="btn-primary h-11 px-4.5 text-xs font-semibold cursor-pointer flex items-center gap-2 shadow-sm">
          <Upload className="w-3.5 h-3.5" />
          <span>Upload PCAP</span>
          <input
            type="file"
            accept=".pcap,.pcapng,.cap"
            onChange={handleFileUpload}
            className="hidden"
            disabled={uploadMutation.isPending}
          />
        </label>

        <button
          onClick={handleReset}
          disabled={resetMutation.isPending}
          className="btn-outline h-11 px-3 text-xs font-semibold flex items-center gap-1.5 text-text-muted hover:text-ink border-hairline/80 shadow-sm"
          title="Reload synthetic scenarios"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${resetMutation.isPending ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">Reset</span>
        </button>
      </div>

      {uploadError && (
        <div className="w-full text-xs text-red-600 bg-red-50 p-3 rounded-xl border border-red-200 flex items-center gap-2">
          <ShieldAlert className="w-4 h-4 shrink-0" />
          <span>{uploadError}</span>
        </div>
      )}
    </div>
  );
};
