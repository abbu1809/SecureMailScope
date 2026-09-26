import { Capture, Session, PostureSummary, AnomalyItem, RuleDefinition } from '../types/api';

const API_BASE = (import.meta.env.VITE_API_BASE as string) || 'http://127.0.0.1:8000/api';

export const apiClient = {
  // Base URL helper
  getBaseUrl(): string {
    return API_BASE;
  },

  getDownloadUrl(captureId: string): string {
    return `${API_BASE}/captures/${captureId}/download`;
  },
  // Captures
  async listCaptures(): Promise<Capture[]> {
    const res = await fetch(`${API_BASE}/captures`);
    if (!res.ok) throw new Error('Failed to fetch captures');
    return res.json();
  },

  async getCapture(id: string): Promise<Capture> {
    const res = await fetch(`${API_BASE}/captures/${id}`);
    if (!res.ok) throw new Error('Failed to fetch capture metadata');
    return res.json();
  },

  async uploadPCAP(file: File, useML = true): Promise<Capture> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/captures/upload?use_ml=${useML}`, {
      method: 'POST',
      body: formData,
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ detail: 'Upload failed' }));
      throw new Error(err.detail || 'Failed to upload PCAP');
    }
    return res.json();
  },

  async resetDemoSamples(): Promise<void> {
    const res = await fetch(`${API_BASE}/captures/reset-samples`, { method: 'POST' });
    if (!res.ok) throw new Error('Failed to reset demo samples');
  },

  // Sessions
  async getSessions(captureId: string, params?: { protocol?: string; risk_class?: string; starttls_state?: string; search?: string }): Promise<Session[]> {
    const query = new URLSearchParams();
    if (params?.protocol) query.set('protocol', params.protocol);
    if (params?.risk_class) query.set('risk_class', params.risk_class);
    if (params?.starttls_state) query.set('starttls_state', params.starttls_state);
    if (params?.search) query.set('search', params.search);

    const url = `${API_BASE}/captures/${captureId}/sessions${query.toString() ? `?${query.toString()}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch sessions');
    return res.json();
  },

  async getSessionDetail(captureId: string, sessionId: string): Promise<Session> {
    const res = await fetch(`${API_BASE}/captures/${captureId}/sessions/${sessionId}`);
    if (!res.ok) throw new Error('Failed to fetch session detail');
    return res.json();
  },

  // Analytics
  async getPostureSummary(captureId: string): Promise<PostureSummary> {
    const res = await fetch(`${API_BASE}/captures/${captureId}/analytics/summary`);
    if (!res.ok) throw new Error('Failed to fetch posture summary');
    return res.json();
  },

  async getAnomalies(captureId: string): Promise<AnomalyItem[]> {
    const res = await fetch(`${API_BASE}/captures/${captureId}/analytics/anomalies`);
    if (!res.ok) throw new Error('Failed to fetch anomalies');
    return res.json();
  },

  // Rules
  async listRules(params?: { category?: string; severity?: string }): Promise<RuleDefinition[]> {
    const query = new URLSearchParams();
    if (params?.category) query.set('category', params.category);
    if (params?.severity) query.set('severity', params.severity);

    const url = `${API_BASE}/rules${query.toString() ? `?${query.toString()}` : ''}`;
    const res = await fetch(url);
    if (!res.ok) throw new Error('Failed to fetch rules');
    return res.json();
  },

  // Reports
  getJsonReportUrl(captureId: string): string {
    return `${API_BASE}/captures/${captureId}/report.json`;
  },
  getHtmlReportUrl(captureId: string): string {
    return `${API_BASE}/captures/${captureId}/report.html`;
  },
  getPdfReportUrl(captureId: string): string {
    return `${API_BASE}/captures/${captureId}/report.pdf`;
  }
};
