import React from 'react';
import { LucideIcon } from 'lucide-react';

interface StatCardProps {
  label: string;
  value: string | number;
  subtitle?: string;
  icon?: LucideIcon;
  variant?: 'default' | 'critical' | 'high' | 'accent' | 'secure';
}

export const StatCard: React.FC<StatCardProps> = ({
  label,
  value,
  subtitle,
  icon: Icon,
  variant = 'default',
}) => {
  const getVariantStyles = () => {
    switch (variant) {
      case 'critical':
        return 'border-red-200 bg-red-50/40';
      case 'high':
        return 'border-orange-200 bg-orange-50/40';
      case 'accent':
        return 'border-blue-200 bg-blue-50/40';
      case 'secure':
        return 'border-emerald-200 bg-emerald-50/40';
      default:
        return 'border-hairline/80 bg-canvas';
    }
  };

  const getIconContainerStyles = () => {
    switch (variant) {
      case 'critical':
        return 'bg-red-100 text-red-700';
      case 'high':
        return 'bg-orange-100 text-orange-700';
      case 'accent':
        return 'bg-blue-100 text-accent';
      case 'secure':
        return 'bg-emerald-100 text-emerald-700';
      default:
        return 'bg-field text-ink';
    }
  };

  return (
    <div className={`border rounded-2xl p-5 sm:p-6 shadow-subtle flex flex-col justify-between transition-all duration-150 ${getVariantStyles()}`}>
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted">
          {label}
        </span>
        {Icon && (
          <div className={`w-8 h-8 rounded-[30%] flex items-center justify-center shrink-0 ${getIconContainerStyles()}`}>
            <Icon className="w-4 h-4" />
          </div>
        )}
      </div>

      <div className="mt-4">
        <div className="text-3xl font-bold tracking-tight text-ink font-sans">
          {value}
        </div>
        {subtitle && (
          <div className="text-xs text-text-muted mt-1 font-normal line-clamp-1">
            {subtitle}
          </div>
        )}
      </div>
    </div>
  );
};
