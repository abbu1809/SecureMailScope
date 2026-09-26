import { useQuery } from '@tanstack/react-query';
import { apiClient } from '../services/api';

export function usePostureSummary(captureId: string | undefined) {
  return useQuery({
    queryKey: ['posture-summary', captureId],
    queryFn: () => (captureId ? apiClient.getPostureSummary(captureId) : null),
    enabled: !!captureId,
  });
}

export function useSessions(captureId: string | undefined, filters?: { protocol?: string; risk_class?: string; starttls_state?: string; search?: string }) {
  return useQuery({
    queryKey: ['sessions', captureId, filters],
    queryFn: () => (captureId ? apiClient.getSessions(captureId, filters) : []),
    enabled: !!captureId,
  });
}

export function useSessionDetail(captureId: string | undefined, sessionId: string | undefined) {
  return useQuery({
    queryKey: ['session-detail', captureId, sessionId],
    queryFn: () => (captureId && sessionId ? apiClient.getSessionDetail(captureId, sessionId) : null),
    enabled: !!captureId && !!sessionId,
  });
}

export function useAnomalies(captureId: string | undefined) {
  return useQuery({
    queryKey: ['anomalies', captureId],
    queryFn: () => (captureId ? apiClient.getAnomalies(captureId) : []),
    enabled: !!captureId,
  });
}

export function useRules(params?: { category?: string; severity?: string }) {
  return useQuery({
    queryKey: ['rules', params],
    queryFn: () => apiClient.listRules(params),
  });
}
