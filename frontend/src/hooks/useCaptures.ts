import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { apiClient } from '../services/api';

export function useCaptures() {
  return useQuery({
    queryKey: ['captures'],
    queryFn: () => apiClient.listCaptures(),
    staleTime: 1000 * 30, // 30 seconds
  });
}

export function useCapture(captureId: string | undefined) {
  return useQuery({
    queryKey: ['capture', captureId],
    queryFn: () => (captureId ? apiClient.getCapture(captureId) : null),
    enabled: !!captureId,
  });
}

export function useUploadPCAP() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ file, useML }: { file: File; useML?: boolean }) =>
      apiClient.uploadPCAP(file, useML),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['captures'] });
    },
  });
}

export function useResetDemoSamples() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: () => apiClient.resetDemoSamples(),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['captures'] });
    },
  });
}
