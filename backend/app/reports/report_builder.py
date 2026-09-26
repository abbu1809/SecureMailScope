"""
Multi-Format Report Builder for SecureMailScope.
Supports Schema-Versioned JSON (v1.1), Standalone HTML, and Printable PDF formats.
"""
import json
from typing import Dict, Any, List
from jinja2 import Template
from app.core.schemas import PostureSummaryModel, SessionModel

HTML_REPORT_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SecureMailScope Security Posture Audit - {{ summary.filename }}</title>
    <style>
        :root {
            --ink: #141414;
            --ink-soft: #262626;
            --canvas: #ffffff;
            --canvas-soft: #f3f3f3;
            --hairline: #e0e0e0;
            --accent: #0066ff;
            --critical: #dc2626;
            --high: #ea580c;
            --medium: #d97706;
            --secure: #16a34a;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            color: var(--ink);
            background: var(--canvas);
            margin: 0;
            padding: 40px 20px;
            line-height: 1.5;
        }
        .container {
            max-width: 1000px;
            margin: 0 auto;
        }
        .header {
            border-bottom: 2px solid var(--ink);
            padding-bottom: 24px;
            margin-bottom: 32px;
            display: flex;
            justify-content: space-between;
            align-items: flex-end;
        }
        .brand {
            font-size: 28px;
            font-weight: 700;
            letter-spacing: -0.5px;
        }
        .meta {
            color: #707070;
            font-size: 14px;
        }
        .score-hero {
            background: var(--canvas-soft);
            border-radius: 24px;
            padding: 32px;
            display: grid;
            grid-template-columns: 200px 1fr;
            gap: 32px;
            align-items: center;
            margin-bottom: 32px;
        }
        .score-dial {
            width: 160px;
            height: 160px;
            border-radius: 50%;
            border: 12px solid var(--ink);
            display: flex;
            flex-direction: column;
            align-items: center;
            justify-content: center;
            margin: 0 auto;
        }
        .score-num {
            font-size: 44px;
            font-weight: 800;
            line-height: 1;
        }
        .score-grade {
            font-size: 16px;
            font-weight: 600;
            color: #707070;
            margin-top: 4px;
        }
        .grid-kpi {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 32px;
        }
        .card {
            background: var(--canvas);
            border: 1px solid var(--hairline);
            border-radius: 16px;
            padding: 20px;
        }
        .card-num {
            font-size: 28px;
            font-weight: 700;
            margin-top: 4px;
        }
        .card-label {
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #707070;
        }
        .badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 600;
        }
        .badge-critical { background: #fee2e2; color: #991b1b; }
        .badge-high { background: #ffedd5; color: #9a3412; }
        .badge-medium { background: #fef3c7; color: #92400e; }
        .badge-secure { background: #dcfce7; color: #166534; }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 16px;
            font-size: 14px;
        }
        th, td {
            text-align: left;
            padding: 12px 16px;
            border-bottom: 1px solid var(--hairline);
        }
        th {
            background: var(--canvas-soft);
            font-weight: 600;
            font-size: 12px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .code-box {
            background: #1e1e1e;
            color: #d4d4d4;
            padding: 16px;
            border-radius: 12px;
            font-family: monospace;
            font-size: 12px;
            white-space: pre-wrap;
            margin-top: 8px;
        }
        @media print {
            body { padding: 0; }
            .no-print { display: none; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <div class="brand">SecureMailScope</div>
                <div class="meta">AI-Assisted Cryptographic Security Posture Assessment · SIH PS 26159</div>
            </div>
            <div class="meta" style="text-align: right;">
                <div><strong>Capture:</strong> {{ summary.filename }}</div>
                <div><strong>Analyzed At:</strong> {{ summary.analyzed_at }}</div>
                <div><strong>Schema:</strong> v1.1.0</div>
            </div>
        </div>

        <div class="score-hero">
            <div class="score-dial">
                <div class="score-num">{{ summary.overall_score }}</div>
                <div class="score-grade">GRADE {{ summary.overall_grade }}</div>
            </div>
            <div>
                <h2 style="margin: 0 0 8px 0; font-size: 24px;">Executive Cryptographic Posture</h2>
                <p style="color: #707070; margin: 0 0 16px 0;">
                    Overall SCoRE assessment derived from deterministic cryptographic verification rules,
                    X.509 chain evaluation, and Isolation Forest ML anomaly scoring across {{ summary.total_sessions }} email conversations.
                </p>
                <div style="display: flex; gap: 8px;">
                    <span class="badge badge-critical">{{ summary.risk_distribution.Critical or 0 }} Critical</span>
                    <span class="badge badge-high">{{ summary.risk_distribution.High or 0 }} High</span>
                    <span class="badge badge-medium">{{ summary.risk_distribution.Medium or 0 }} Medium</span>
                    <span class="badge badge-secure">{{ summary.risk_distribution.Secure or 0 }} Secure</span>
                </div>
            </div>
        </div>

        <div class="grid-kpi">
            <div class="card">
                <div class="card-label">Total Sessions</div>
                <div class="card-num">{{ summary.total_sessions }}</div>
            </div>
            <div class="card">
                <div class="card-label">STARTTLS Stripped</div>
                <div class="card-num" style="color: var(--critical);">{{ summary.starttls_stripping_count }}</div>
            </div>
            <div class="card">
                <div class="card-label">Weak / Expired Certs</div>
                <div class="card-num" style="color: var(--high);">{{ summary.weak_cert_count }}</div>
            </div>
            <div class="card">
                <div class="card-label">AI Anomalies Flagged</div>
                <div class="card-num" style="color: var(--accent);">{{ summary.anomalies_count }}</div>
            </div>
        </div>

        <h3 style="margin-top: 40px;">Prioritized Action Queue</h3>
        <p style="color: #707070; font-size: 14px;">Ranked using SCoRE Priority: Priority = Severity × Exposure × (1 / Fix Effort)</p>
        {% for rem in summary.top_remediations %}
        <div class="card" style="margin-bottom: 16px;">
            <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
                <strong>{{ rem.rule_id }}: {{ rem.title }}</strong>
                <span class="badge badge-{{ rem.severity.lower() }}">{{ rem.severity }} (Score: {{ rem.priority_score }})</span>
            </div>
            <div style="font-size: 13px; color: #555; margin-bottom: 8px;">
                Affects {{ rem.affected_sessions_count }} sessions across hosts: {{ rem.affected_hosts | join(', ') }}
            </div>
            <div class="code-box">{{ rem.remediation_snippet }}</div>
        </div>
        {% endfor %}

        <h3 style="margin-top: 40px;">Reconstructed Sessions</h3>
        <table>
            <thead>
                <tr>
                    <th>Session ID</th>
                    <th>Flow (Src &rarr; Dst)</th>
                    <th>Protocol</th>
                    <th>STARTTLS</th>
                    <th>TLS Version</th>
                    <th>SCoRE</th>
                    <th>Risk Class</th>
                </tr>
            </thead>
            <tbody>
                {% for s in sessions %}
                <tr>
                    <td><code>{{ s.id }}</code></td>
                    <td>{{ s.src_ip }}:{{ s.src_port }} &rarr; {{ s.dst_ip }}:{{ s.dst_port }}</td>
                    <td>{{ s.protocol }}</td>
                    <td>{{ s.starttls_state }}</td>
                    <td>{{ s.tls_summary.negotiated_version if s.tls_summary else 'Cleartext' }}</td>
                    <td><strong>{{ s.score_trace.score }}</strong>/100</td>
                    <td><span class="badge badge-{{ s.score_trace.risk_class.lower() }}">{{ s.score_trace.risk_class }}</span></td>
                </tr>
                {% endfor %}
            </tbody>
        </table>

        <div style="margin-top: 60px; padding-top: 20px; border-top: 1px solid var(--hairline); font-size: 12px; color: #999; text-align: center;">
            Generated by SecureMailScope v1.1.0 · Single-node Passive Cryptographic Assessment · NIST SP 800-52r2 / RFC 8996 / RFC 8314 Compliant
        </div>
    </div>
</body>
</html>
"""

class ReportBuilder:
    """
    Builds JSON, HTML, and printable reports from posture results.
    """

    @classmethod
    def generate_json_report(cls, summary: PostureSummaryModel, sessions: List[SessionModel]) -> str:
        data = {
            "schema_version": "1.1.0",
            "system": "SecureMailScope",
            "problem_statement": "SIH PS 26159",
            "summary": summary.model_dump(),
            "sessions": [s.model_dump() for s in sessions]
        }
        return json.dumps(data, indent=2)

    @classmethod
    def generate_html_report(cls, summary: PostureSummaryModel, sessions: List[SessionModel]) -> str:
        tmpl = Template(HTML_REPORT_TEMPLATE)
        return tmpl.render(
            summary=summary.model_dump(),
            sessions=[s.model_dump() for s in sessions]
        )
