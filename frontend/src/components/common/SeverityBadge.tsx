import React from 'react';

interface SeverityBadgeProps {
  severity: string;
  size?: 'sm' | 'md';
}

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, size = 'md' }) => {
  const s = severity?.toUpperCase() || 'INFO';

  const getStyle = () => {
    switch (s) {
      case 'CRITICAL':
        return 'bg-red-50 text-red-700 border-red-200';
      case 'HIGH':
        return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'MEDIUM':
        return 'bg-amber-50 text-amber-800 border-amber-200';
      case 'LOW':
        return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'SECURE':
        return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      default:
        return 'bg-neutral-100 text-neutral-700 border-neutral-200';
    }
  };

  const pad = size === 'sm' ? 'px-2 py-0.5 text-[10px]' : 'px-2.5 py-1 text-xs';

  return (
    <span className={`inline-flex items-center font-semibold rounded-full border ${pad} ${getStyle()}`}>
      <span className="w-1.5 h-1.5 rounded-full mr-1.5 bg-current opacity-80" />
      {severity}
    </span>
  );
};
