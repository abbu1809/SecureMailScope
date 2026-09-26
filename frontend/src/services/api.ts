import { Capture, Session, PostureSummary, AnomalyItem, RuleDefinition } from '../types/api';

function normalizeApiBase(rawUrl?: string): string {
  let base = (rawUrl || '').trim();
  if (!base) {
    return 'http://127.0.0.1:8000/api';
  }
  // Remove trailing slashes
  base = base.replace(/\/+$/, '');

  // Auto-prepend https:// if domain provided without protocol
  if (!base.startsWith('http://') && !base.startsWith('https://') && !base.startsWith('/')) {
    base = `https://${base}`;
  }

  // Ensure /api suffix is present
  if (!base.endsWith('/api') && !base.includes('/api/')) {
    base = `${base}/api`;
  }

  return base;
}

const API_BASE = normalizeApiBase(import.meta.env.VITE_API_BASE as string);

async function handleResponse<T>(res: Response, fallbackError: string): Promise<T> {
  const contentType = res.headers.get('content-type') || '';
  if (!res.ok) {
    if (contentType.includes('application/json')) {
      const err = await res.json().catch(() => ({ detail: fallbackError }));
      throw new Error(err.detail || fallbackError);
    }
    const text = await res.text().catch(() => fallbackError);
    if (text.includes('<!doctype') || text.includes('<!DOCTYPE') || text.includes('<html')) {
      throw new Error(`Received HTML instead of JSON from "${res.url}". Verify backend is active and API URL is configured with https://`);
    }
    throw new Error(text || fallbackError);
  }

  if (!contentType.includes('application/json')) {
    const text = await res.text().catch(() => '');
    if (text.includes('<!doctype') || text.includes('<!DOCTYPE') || text.includes('<html')) {
      throw new Error(`Received HTML from "${res.url}". Check that the API Base URL is pointing directly to the Railway backend.`);
    }
  }

  return res.json();
}

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
    return handleResponse<Capture[]>(res, 'Failed to fetch captures');
  },

  async getCapture(id: string): Promise<Capture> {
    const res = await fetch(`${API_BASE}/captures/${id}`);
    return handleResponse<Capture>(res, 'Failed to fetch capture metadata');
  },

  async uploadPCAP(file: File, useML = true): Promise<Capture> {
    const formData = new FormData();
    formData.append('file', file);
    const res = await fetch(`${API_BASE}/captures/upload?use_ml=${useML}`, {
      method: 'POST',
      body: formData,
    });
    return handleResponse<Capture>(res, 'Failed to upload PCAP');
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
    return handleResponse<Session[]>(res, 'Failed to fetch sessions');
  },

  async getSessionDetail(captureId: string, sessionId: string): Promise<Session> {
    const res = await fetch(`${API_BASE}/captures/${captureId}/sessions/${sessionId}`);
    return handleResponse<Session>(res, 'Failed to fetch session detail');
  },

  // Analytics
  async getPostureSummary(captureId: string): Promise<PostureSummary> {
    const res = await fetch(`${API_BASE}/captures/${captureId}/analytics/summary`);
    return handleResponse<PostureSummary>(res, 'Failed to fetch posture summary');
  },

  async getAnomalies(captureId: string): Promise<AnomalyItem[]> {
    const res = await fetch(`${API_BASE}/captures/${captureId}/analytics/anomalies`);
    return handleResponse<AnomalyItem[]>(res, 'Failed to fetch anomalies');
  },

  // Rules
  async listRules(params?: { category?: string; severity?: string }): Promise<RuleDefinition[]> {
    const query = new URLSearchParams();
    if (params?.category) query.set('category', params.category);
    if (params?.severity) query.set('severity', params.severity);

    const url = `${API_BASE}/rules${query.toString() ? `?${query.toString()}` : ''}`;
    const res = await fetch(url);
    return handleResponse<RuleDefinition[]>(res, 'Failed to fetch rules');
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
