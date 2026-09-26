import React, { useState } from 'react';
import { Search, BookOpen, Terminal, Check, Copy, Shield, Filter } from 'lucide-react';
import { useRules } from '../hooks/useAnalytics';
import { SeverityBadge } from '../components/common/SeverityBadge';

export const RulesPage: React.FC = () => {
  const { data: rules = [], isLoading } = useRules();
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [selectedSeverity, setSelectedSeverity] = useState('ALL');
  const [copiedRuleId, setCopiedRuleId] = useState<string | null>(null);

  const categories = ['ALL', ...Array.from(new Set(rules.map((r) => r.category)))];

  const filteredRules = rules.filter((r) => {
    if (selectedCategory !== 'ALL' && r.category !== selectedCategory) return false;
    if (selectedSeverity !== 'ALL' && r.severity !== selectedSeverity) return false;
    if (search) {
      const q = search.toLowerCase();
      return (
        r.rule_id.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) ||
        r.description.toLowerCase().includes(q) ||
        r.compliance_refs.some((ref) => ref.toLowerCase().includes(q))
      );
    }
    return true;
  });

  const handleCopy = (text: string, id: string) => {
    navigator.clipboard.writeText(text);
    setCopiedRuleId(id);
    setTimeout(() => setCopiedRuleId(null), 2000);
  };

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-8 py-8 space-y-8">
      {/* Header */}
      <div className="space-y-2">
        <div className="inline-flex items-center gap-2 bg-canvas-soft border border-hairline/80 px-3 py-1 rounded-full text-xs font-semibold text-ink">
          <BookOpen className="w-3.5 h-3.5 text-accent" />
          <span>Deterministic Vulnerability Rules Engine §3.4</span>
        </div>
        <h1 className="text-3xl font-bold tracking-tight text-ink font-sans">
          Cryptographic Security Rules Directory.
        </h1>
        <p className="text-sm text-text-muted font-light max-w-3xl leading-relaxed">
          Full catalog of 35 deterministic cryptographic weakness rules mapped to NIST SP 800-52r2,
          RFC 8996, RFC 8314, and PCI-DSS v4.0 with copy-paste server hardening snippets.
        </p>
      </div>

      {/* Controls Bar */}
      <div className="bg-canvas border border-hairline/80 rounded-2xl p-5 shadow-subtle space-y-4">
        <div className="flex flex-col md:flex-row items-center gap-4">
          <div className="relative flex-1 w-full">
            <Search className="w-4 h-4 text-text-muted absolute left-3.5 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Search rule ID, title, compliance standard, or keyword..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="input-field w-full pl-10 rounded-xl bg-field h-11 text-xs sm:text-sm"
            />
          </div>

          <div className="flex flex-wrap items-center gap-1.5 self-start md:self-auto bg-canvas-soft p-1 rounded-full border border-hairline-soft">
            {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
              <button
                key={sev}
                onClick={() => setSelectedSeverity(sev)}
                className={`px-3 py-1 rounded-full text-xs font-semibold transition-all ${
                  selectedSeverity === sev
                    ? 'bg-ink text-white shadow-xs'
                    : 'text-text-muted hover:text-ink'
                }`}
              >
                {sev}
              </button>
            ))}
          </div>
        </div>

        {/* Category Pills */}
        <div className="flex flex-wrap items-center gap-1.5 pt-3 border-t border-hairline-soft">
          <span className="text-[11px] font-bold uppercase tracking-wider text-text-muted mr-2">Category:</span>
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setSelectedCategory(cat)}
              className={`px-3 py-1 rounded-full text-xs font-semibold transition-all ${
                selectedCategory === cat
                  ? 'bg-canvas text-ink border border-hairline font-bold shadow-subtle'
                  : 'text-text-muted hover:text-ink bg-canvas-soft/60'
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Rules List */}
      <div className="space-y-4">
        {filteredRules.map((r) => (
          <div key={r.rule_id} className="p-6 rounded-2xl border border-hairline/80 bg-canvas space-y-3.5 shadow-subtle">
            <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
              <div className="flex items-center gap-3">
                <span className="font-mono font-bold text-xs bg-field text-ink px-2.5 py-1 rounded-lg">
                  {r.rule_id}
                </span>
                <h3 className="font-bold text-base text-ink font-sans">{r.title}</h3>
              </div>
              <div className="flex items-center gap-3 self-start sm:self-auto">
                <span className="text-xs text-text-muted font-mono font-semibold bg-canvas-soft px-2.5 py-0.5 rounded-full">Weight: {r.weight}</span>
                <SeverityBadge severity={r.severity} />
              </div>
            </div>

            <p className="text-xs sm:text-sm text-text-muted leading-relaxed font-light">
              {r.description}
            </p>

            {/* Compliance References */}
            {r.compliance_refs.length > 0 && (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {r.compliance_refs.map((ref, idx) => (
                  <span
                    key={idx}
                    className="text-[10px] px-2.5 py-0.5 rounded-full bg-canvas-soft border border-hairline text-text-muted font-semibold font-mono"
                  >
                    {ref}
                  </span>
                ))}
              </div>
            )}

            {/* Copyable Remediation snippet */}
            <div className="pt-2">
              <div className="flex items-center justify-between text-[11px] font-bold text-text-muted mb-1.5 uppercase tracking-wider">
                <span className="flex items-center gap-1.5">
                  <Terminal className="w-3.5 h-3.5 text-accent" />
                  Hardening Configuration Snippet
                </span>
                <button
                  onClick={() => handleCopy(r.remediation, r.rule_id)}
                  className="flex items-center gap-1 text-accent hover:underline lowercase font-sans font-semibold text-xs"
                >
                  {copiedRuleId === r.rule_id ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-600" />
                      <span className="text-emerald-600 font-bold">Copied!</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>Copy snippet</span>
                    </>
                  )}
                </button>
              </div>
              <pre className="bg-neutral-900 text-neutral-200 p-3.5 rounded-xl font-mono text-xs overflow-x-auto whitespace-pre-wrap leading-relaxed shadow-sm">
                {r.remediation}
              </pre>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
