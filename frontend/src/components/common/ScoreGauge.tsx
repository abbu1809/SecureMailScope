import React from 'react';

interface ScoreGaugeProps {
  score: number;
  grade?: string;
  size?: number;
  strokeWidth?: number;
  showDetails?: boolean;
}

export const ScoreGauge: React.FC<ScoreGaugeProps> = ({
  score,
  grade,
  size = 140,
  strokeWidth = 10,
  showDetails = true,
}) => {
  const radius = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * radius;
  const progress = Math.min(100, Math.max(0, score));
  const strokeDashoffset = circumference - (progress / 100) * circumference;

  const getColorClass = (val: number) => {
    if (val <= 39) return { stroke: '#dc2626', text: 'text-risk-critical', bg: 'bg-red-50', border: 'border-red-200' };
    if (val <= 69) return { stroke: '#ea580c', text: 'text-risk-high', bg: 'bg-orange-50', border: 'border-orange-200' };
    if (val <= 89) return { stroke: '#d97706', text: 'text-risk-medium', bg: 'bg-amber-50', border: 'border-amber-200' };
    return { stroke: '#16a34a', text: 'text-risk-secure', bg: 'bg-emerald-50', border: 'border-emerald-200' };
  };

  const theme = getColorClass(score);

  return (
    <div className="flex flex-col items-center justify-center">
      <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="transform -rotate-90">
          {/* Background Track */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke="#f0f0f0"
            strokeWidth={strokeWidth}
            fill="transparent"
          />
          {/* Active Score Arc */}
          <circle
            cx={size / 2}
            cy={size / 2}
            r={radius}
            stroke={theme.stroke}
            strokeWidth={strokeWidth}
            strokeDasharray={circumference}
            strokeDashoffset={strokeDashoffset}
            strokeLinecap="round"
            fill="transparent"
            className="transition-all duration-1000 ease-out"
          />
        </svg>

        {/* Inner Content */}
        <div className="absolute inset-0 flex flex-col items-center justify-center text-center">
          <span className="text-3xl sm:text-4xl font-extrabold text-ink tracking-tight font-sans">
            {score}
          </span>
          <span className="text-[10px] uppercase font-bold text-text-muted tracking-wider">
            SCoRE
          </span>
        </div>
      </div>

      {showDetails && grade && (
        <div className={`mt-2 px-3 py-0.5 rounded-full text-xs font-bold ${theme.bg} ${theme.text} border ${theme.border}`}>
          Grade {grade}
        </div>
      )}
    </div>
  );
};
