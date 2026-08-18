/**
 * SOCPilot AI Dashboard — Report Detail View
 * ===========================================
 * Tabbed detail view: Summary | IOCs | MITRE | Sigma | Threat Intel | Reasoning
 */

window.reportDetailModule = {
  _activeTab: 'summary',

  render(container, report) {
    this._activeTab = 'summary';
    const sev   = report.severity || 'UNKNOWN';
    const color = window.utils.sevColor(sev);
    const glow  = window.utils.sevGlow(sev);

    const iocs    = report.extracted_iocs || {};
    const mitre   = report.mitre_mappings || [];
    const sigma   = report.sigma_detections || [];
    const intel   = report.threat_intel_findings || [];
    const actions = report.recommended_actions || [];

    const totalIOCs = Object.values(iocs).reduce((s, v) => s + (Array.isArray(v) ? v.length : 0), 0);

    container.innerHTML = `
      <!-- Back + Header -->
      <div class="detail-header" style="--sev-color:${color};--sev-glow:${glow};">
        <div class="detail-header-top">
          <div class="detail-title-area">
            <button class="detail-back-btn" onclick="history.back()">
              <svg viewBox="0 0 16 16" fill="none" width="14" height="14">
                <path d="M10 3L5 8l5 5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
              </svg>
              Back to Reports
            </button>
            <div class="detail-report-id">${window.utils.escapeHtml(report.report_id || 'Unknown Report')}</div>
            <div class="detail-meta-row">
              ${window.utils.severityBadge(sev)}
              <span style="font-size:12px;color:var(--text-muted);">
                🕐 ${window.utils.formatDate(report.investigation_timestamp)}
              </span>
              <span style="font-size:12px;color:var(--text-muted);font-family:var(--font-mono);">
                🧵 ${window.utils.escapeHtml(report.thread_id || '—')}
              </span>
            </div>
          </div>
          <div class="detail-badges-col">
            ${report.escalation_required
              ? '<span class="escalation-chip yes" style="font-size:12px;padding:4px 12px;">🔺 ESCALATION REQUIRED</span>'
              : '<span class="escalation-chip no" style="font-size:12px;padding:4px 12px;">✓ No Escalation</span>'}
            <span class="fp-badge fp-${report.false_positive_likelihood || 'UNKNOWN'}" style="font-size:11px;">
              False Positive: ${report.false_positive_likelihood || 'UNKNOWN'}
            </span>
            <div class="download-row">
              <button class="btn btn-ghost" onclick="window.reportDetailModule.downloadJSON('${window.utils.escapeHtml(report._filename)}')">⬇ JSON</button>
              ${report._has_markdown ? `<button class="btn btn-ghost" onclick="window.reportDetailModule.viewMarkdown('${window.utils.escapeHtml(report._filename)}')">📄 Markdown</button>` : ''}
            </div>
          </div>
        </div>

        <!-- Alert Summary -->
        <div class="detail-summary-text">${window.utils.escapeHtml(report.alert_summary || 'No summary available.')}</div>

        <!-- Score Meters -->
        <div class="score-meters">
          ${this._scoreMeter('Risk Score', report.risk_score, 100, window.utils.riskColor(report.risk_score), window.utils.riskColor(report.risk_score) + '55')}
          ${this._scoreMeter('Confidence', Math.round((report.confidence_score || 0) * 100), 100, 'var(--cyan)', 'var(--cyan-glow)')}
          ${this._scoreMeter('Threat Intel IOCs', intel.filter(i => i.verdict === 'MALICIOUS').length, Math.max(intel.length, 1), 'var(--critical)', 'var(--critical-glow)', `${intel.filter(i=>i.verdict==='MALICIOUS').length}/${intel.length} malicious`)}
          ${this._scoreMeter('MITRE Techniques', mitre.length, 10, 'var(--high)', 'var(--high-glow)', `${mitre.length} mapped`)}
        </div>
      </div>

      <!-- Tabs -->
      <div class="tabs-bar" id="detail-tabs">
        ${this._tabBtn('summary',  '📋 Summary',       '')}
        ${this._tabBtn('iocs',     '🔍 IOCs',          totalIOCs)}
        ${this._tabBtn('mitre',    '⚔️ MITRE ATT&CK', mitre.length)}
        ${this._tabBtn('sigma',    '🚨 Sigma Rules',   sigma.length)}
        ${this._tabBtn('intel',    '🛡️ Threat Intel',  intel.length)}
        ${this._tabBtn('reasoning','🧠 Reasoning',     '')}
      </div>

      <!-- Tab Panels -->
      <div id="tab-panels">
        <!-- Summary -->
        <div class="tab-panel active" id="panel-summary">
          ${this._renderSummaryTab(report, actions, iocs, mitre, sigma, intel)}
        </div>
        <!-- IOCs -->
        <div class="tab-panel" id="panel-iocs">
          ${this._renderIOCsTab(iocs)}
        </div>
        <!-- MITRE -->
        <div class="tab-panel" id="panel-mitre">
          ${this._renderMITRETab(mitre)}
        </div>
        <!-- Sigma -->
        <div class="tab-panel" id="panel-sigma">
          ${this._renderSigmaTab(sigma)}
        </div>
        <!-- Threat Intel -->
        <div class="tab-panel" id="panel-intel">
          ${this._renderIntelTab(intel)}
        </div>
        <!-- Reasoning -->
        <div class="tab-panel" id="panel-reasoning">
          ${this._renderReasoningTab(report)}
        </div>
      </div>`;

    // Wire up tabs
    document.querySelectorAll('[data-tab]').forEach(btn => {
      btn.addEventListener('click', () => this._switchTab(btn.dataset.tab));
    });

    // Wire up sigma toggles
    document.querySelectorAll('.sigma-card-header').forEach(header => {
      header.addEventListener('click', () => {
        const card = header.closest('.sigma-card');
        card?.classList.toggle('open');
      });
    });
  },

  _tabBtn(id, label, count) {
    return `<button class="tab-btn ${id === 'summary' ? 'active' : ''}" data-tab="${id}">
      ${label}
      ${count !== '' ? `<span class="tab-count">${count}</span>` : ''}
    </button>`;
  },

  _switchTab(tabId) {
    this._activeTab = tabId;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tabId));
    document.querySelectorAll('.tab-panel').forEach(p => p.classList.toggle('active', p.id === `panel-${tabId}`));
  },

  _scoreMeter(label, value, max, barColor, barGlow, note) {
    const pct = Math.min(Math.round((value / max) * 100), 100);
    return `
      <div class="score-meter">
        <div class="score-meter-label">${label}</div>
        <div class="score-bar-wrap">
          <div class="score-bar" style="width:${pct}%;--bar-color:${barColor};--bar-glow:${barGlow};"></div>
        </div>
        <div class="score-val">${value}</div>
        ${note ? `<div style="font-size:10px;color:var(--text-muted);">${note}</div>` : ''}
      </div>`;
  },

  // ── Summary Tab ───────────────────────────────────────────────────────────────
  _renderSummaryTab(report, actions, iocs, mitre, sigma, intel) {
    const totalIOCs = Object.values(iocs).reduce((s, v) => s + (Array.isArray(v) ? v.length : 0), 0);
    return `
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:16px;">
        <!-- Quick Stats -->
        <div class="chart-card">
          <div class="section-title">Investigation At-a-Glance</div>
          <div style="margin-top:16px;display:flex;flex-direction:column;gap:12px;">
            ${this._infoRow('🔍 Total IOCs', `${totalIOCs} indicators extracted`)}
            ${this._infoRow('⚔️ MITRE Techniques', `${mitre.length} technique${mitre.length !== 1 ? 's' : ''} mapped`)}
            ${this._infoRow('🚨 Sigma Rules', `${sigma.length} rule${sigma.length !== 1 ? 's' : ''} matched`)}
            ${this._infoRow('🛡️ Threat Intel', `${intel.filter(i=>i.verdict==='MALICIOUS').length} malicious of ${intel.length} queried`)}
            ${this._infoRow('📌 Thread ID', `<span class="mono" style="font-size:12px;">${window.utils.escapeHtml(report.thread_id || '—')}</span>`)}
            ${this._infoRow('📅 Timestamp', window.utils.formatDate(report.investigation_timestamp))}
          </div>
        </div>
        <!-- RAG Context -->
        <div class="chart-card">
          <div class="section-title">RAG Context Summary</div>
          <div class="rag-block mt-4">${window.utils.escapeHtml(report.rag_context_summary || 'RAG context unavailable.')}</div>
        </div>
      </div>

      <!-- Recommended Actions -->
      <div class="chart-card mb-4">
        <div class="section-title">Recommended Actions</div>
        <div class="actions-list mt-4">
          ${actions.length
            ? actions.map((a, i) => `
              <div class="action-item">
                <div class="action-num">${i + 1}</div>
                <div class="action-text">${window.utils.escapeHtml(a)}</div>
              </div>`).join('')
            : '<div class="empty-state" style="padding:24px;"><p>No recommended actions.</p></div>'}
        </div>
      </div>

      <!-- Related Incidents -->
      ${report.related_incidents?.length ? `
        <div class="chart-card">
          <div class="section-title">Related Historical Incidents</div>
          <div class="mt-4">${report.related_incidents.map(inc => `
            <div class="notif-item" style="cursor:default;">${window.utils.escapeHtml(JSON.stringify(inc))}</div>
          `).join('')}</div>
        </div>` : ''}`;
  },

  _infoRow(label, value) {
    return `
      <div style="display:flex;align-items:center;justify-content:space-between;padding:8px 0;border-bottom:1px solid var(--border-subtle);">
        <span style="font-size:12px;color:var(--text-muted);">${label}</span>
        <span style="font-size:13px;color:var(--text-primary);">${value}</span>
      </div>`;
  },

  // ── IOCs Tab ──────────────────────────────────────────────────────────────────
  _renderIOCsTab(iocs) {
    const categories = [
      { key: 'ip_addresses',  label: 'IP Addresses',    icon: '🌐', cls: 'ip' },
      { key: 'domains',       label: 'Domains',         icon: '🔗', cls: 'domain' },
      { key: 'hostnames',     label: 'Hostnames',       icon: '🖥️', cls: 'hostname' },
      { key: 'file_hashes',   label: 'File Hashes',     icon: '#️⃣', cls: 'hash' },
      { key: 'process_names', label: 'Process Names',   icon: '⚙️', cls: 'process' },
      { key: 'urls',          label: 'URLs',            icon: '🔗', cls: 'url' },
      { key: 'cve_ids',       label: 'CVE IDs',         icon: '🔓', cls: 'hash' },
      { key: 'usernames',     label: 'Usernames',       icon: '👤', cls: 'hostname' },
      { key: 'command_lines', label: 'Command Lines',   icon: '💻', cls: 'process' },
      { key: 'registry_keys', label: 'Registry Keys',   icon: '🗝️', cls: 'hash' },
    ];

    const hasIOCs = categories.some(c => iocs[c.key]?.length > 0);
    if (!hasIOCs) {
      return `<div class="empty-state" style="padding:60px;">
        <svg viewBox="0 0 40 40" fill="none" width="40" height="40"><circle cx="20" cy="20" r="18" stroke="currentColor" stroke-width="1.5" opacity="0.3"/></svg>
        <h3>No IOCs Extracted</h3>
        <p>No structured indicators of compromise were found in this report.</p>
      </div>`;
    }

    return categories.filter(c => iocs[c.key]?.length > 0).map(c => `
      <div class="ioc-group">
        <div class="ioc-group-label">${c.icon} ${c.label} <span style="color:var(--cyan);font-size:10px;">${iocs[c.key].length}</span></div>
        <div class="ioc-chips">
          ${iocs[c.key].map(v => `
            <div class="ioc-chip ${c.cls}" onclick="window.utils.copyToClipboard('${window.utils.escapeHtml(v)}')" title="Click to copy">
              ${window.utils.escapeHtml(v)}
              <svg class="copy-icon" viewBox="0 0 16 16" fill="none" width="12" height="12">
                <rect x="5" y="5" width="9" height="9" rx="1.5" stroke="currentColor" stroke-width="1.5"/>
                <path d="M11 5V3a1 1 0 00-1-1H3a1 1 0 00-1 1v7a1 1 0 001 1h2" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
              </svg>
            </div>`).join('')}
        </div>
      </div>`).join('');
  },

  // ── MITRE Tab ─────────────────────────────────────────────────────────────────
  _renderMITRETab(mitre) {
    if (!mitre.length) {
      return `<div class="empty-state" style="padding:60px;"><h3>No MITRE Mappings</h3><p>No ATT&CK techniques were identified.</p></div>`;
    }

    return `<div class="mitre-grid">` + mitre.map(m => {
      const url = `https://attack.mitre.org/techniques/${(m.technique_id || '').replace('.', '/')}`;
      const tacticColors = {
        'Execution':        '#ff9500',
        'Defense Evasion':  '#ff2d55',
        'Persistence':      '#ff6b35',
        'Lateral Movement': '#af52de',
        'Exfiltration':     '#30d158',
        'Command and Control':'#00d4ff',
        'Discovery':        '#ffcc00',
        'Credential Access':'#ff2d55',
        'Collection':       '#ff9500',
      };
      const tacticColor = tacticColors[m.tactic] || '#636366';

      return `
        <div class="mitre-card">
          <div class="mitre-card-header">
            <a class="mitre-id-badge" href="${url}" target="_blank" rel="noopener" title="Open in MITRE ATT&CK">
              ${window.utils.escapeHtml(m.technique_id || '?')}
            </a>
            <div>
              <div class="mitre-tactic" style="color:${tacticColor};">${window.utils.escapeHtml(m.tactic || 'Unknown')}</div>
              <div class="mitre-name">${window.utils.escapeHtml(m.technique_name || 'Unknown Technique')}</div>
            </div>
          </div>
          ${m.sub_technique ? `<div style="margin-bottom:8px;"><span style="font-size:10px;background:var(--bg-glass);padding:2px 8px;border-radius:999px;color:var(--text-muted);">Sub: ${window.utils.escapeHtml(m.sub_technique)}</span></div>` : ''}
          <div class="mitre-desc">${window.utils.escapeHtml(m.description || '')}</div>
          ${m.triggered_by ? `<div class="mitre-trigger">🔧 Triggered by: <span style="color:var(--text-primary);">${window.utils.escapeHtml(m.triggered_by)}</span></div>` : ''}
        </div>`;
    }).join('') + `</div>`;
  },

  // ── Sigma Tab ─────────────────────────────────────────────────────────────────
  _renderSigmaTab(sigma) {
    if (!sigma.length) {
      return `<div class="empty-state" style="padding:60px;"><h3>No Sigma Rules Matched</h3><p>No detection rules fired for this alert.</p></div>`;
    }

    return sigma.map((rule, i) => `
      <div class="sigma-card ${i === 0 ? 'open' : ''}">
        <div class="sigma-card-header">
          ${window.utils.severityBadge(rule.severity)}
          <span class="sigma-title">${window.utils.escapeHtml(rule.title || 'Unnamed Rule')}</span>
          <svg class="sigma-chevron" viewBox="0 0 16 16" fill="none" width="14" height="14">
            <path d="M4 6l4 4 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"/>
          </svg>
        </div>
        <div class="sigma-body">
          <div class="sigma-meta">
            <span style="font-size:11px;color:var(--text-muted);">
              🔧 Triggered by: <span style="color:var(--text-primary);font-family:var(--font-mono);">${window.utils.escapeHtml(rule.triggered_by || '—')}</span>
            </span>
            <span style="font-size:11px;color:var(--text-muted);font-family:var(--font-mono);">${window.utils.escapeHtml(rule.rule_id || '')}</span>
          </div>
          <div class="sigma-desc">${window.utils.escapeHtml(rule.description || '')}</div>
          ${rule.tags?.length ? `
            <div class="sigma-tags">
              ${rule.tags.map(t => `<span class="sigma-tag">${window.utils.escapeHtml(t)}</span>`).join('')}
            </div>` : ''}
          ${rule.detection_logic ? `
            <div style="font-size:11px;color:var(--text-muted);margin-bottom:6px;font-weight:600;">DETECTION LOGIC</div>
            <div class="sigma-code-wrap">
              <code class="sigma-code">${window.utils.escapeHtml(rule.detection_logic)}</code>
            </div>` : ''}
        </div>
      </div>`).join('');
  },

  // ── Threat Intel Tab ──────────────────────────────────────────────────────────
  _renderIntelTab(intel) {
    if (!intel.length) {
      return `<div class="empty-state" style="padding:60px;"><h3>No Threat Intelligence</h3><p>No IOCs were queried against threat intelligence sources.</p></div>`;
    }

    return `
      <div class="intel-table-wrap">
        <table class="intel-table">
          <thead>
            <tr>
              <th>Source</th>
              <th>IOC</th>
              <th>Type</th>
              <th>Verdict</th>
              <th>Confidence</th>
              <th>Risk Score</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody>
            ${intel.map(item => `
              <tr>
                <td style="color:var(--cyan);font-weight:600;font-size:12px;">${window.utils.escapeHtml(item.source || '—')}</td>
                <td class="intel-ioc-cell" onclick="window.utils.copyToClipboard('${window.utils.escapeHtml(item.ioc || '')}');" style="cursor:pointer;" title="Click to copy">
                  ${window.utils.escapeHtml(item.ioc || '—')}
                </td>
                <td><span style="padding:2px 8px;background:var(--bg-glass);border-radius:4px;font-size:11px;text-transform:uppercase;">${window.utils.escapeHtml(item.ioc_type || '—')}</span></td>
                <td>${window.utils.verdictBadge(item.verdict)}</td>
                <td style="color:var(--text-primary);font-weight:600;">${Math.round((item.confidence || 0) * 100)}%</td>
                <td>
                  <span style="color:${window.utils.riskColor(item.raw_risk_score || 0)};font-family:var(--font-mono);font-weight:700;">
                    ${item.raw_risk_score || 0}
                  </span>
                </td>
                <td class="intel-details-cell">
                  ${this._formatDetails(item.details)}
                </td>
              </tr>`).join('')}
          </tbody>
        </table>
      </div>`;
  },

  _formatDetails(details) {
    if (!details) return '—';
    return Object.entries(details)
      .map(([k, v]) => `<div><span style="color:var(--text-muted);">${window.utils.escapeHtml(k)}:</span> ${window.utils.escapeHtml(String(v))}</div>`)
      .join('');
  },

  // ── Reasoning Tab ─────────────────────────────────────────────────────────────
  _renderReasoningTab(report) {
    return `
      <div class="chart-card mb-4">
        <div class="section-title">Analyst Reasoning Chain</div>
        <div class="reasoning-block mt-4">
          ${window.utils.escapeHtml(report.analyst_reasoning || 'Analyst reasoning not available.')}
        </div>
      </div>
      ${report.rag_context_summary ? `
        <div class="chart-card">
          <div class="section-title">RAG Context Used</div>
          <div class="rag-block mt-4">${window.utils.escapeHtml(report.rag_context_summary)}</div>
        </div>` : ''}`;
  },

  // ── Actions ───────────────────────────────────────────────────────────────────
  downloadJSON(filename) {
    window.open(`/api/reports/${encodeURIComponent(filename)}`, '_blank');
  },

  async viewMarkdown(filename) {
    try {
      const data = await window.api.fetchMarkdown(filename);
      const html = marked.parse(data.markdown || '');
      const win = window.open('', '_blank');
      win.document.write(`<!DOCTYPE html>
        <html>
        <head>
          <title>${filename} — Markdown</title>
          <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet"/>
          <style>
            body { font-family: Inter, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 24px;
                   background: #0a0e1a; color: #e8f4f8; line-height: 1.7; }
            h1,h2,h3 { color: #00d4ff; }
            table { border-collapse: collapse; width: 100%; }
            th, td { border: 1px solid #1a2a4a; padding: 8px 12px; font-size: 13px; }
            th { background: rgba(0,212,255,0.1); color: #00d4ff; }
            code { background: rgba(255,255,255,0.08); padding: 2px 6px; border-radius: 4px; font-size: 12px; }
            pre { background: rgba(0,0,0,0.4); padding: 16px; border-radius: 8px; overflow-x: auto; }
            hr { border-color: #1a2a4a; }
            blockquote { border-left: 3px solid #00d4ff; padding-left: 16px; color: #8aa8c0; }
          </style>
        </head>
        <body>${html}</body></html>`);
    } catch (e) {
      window.notify.toast('Markdown unavailable', e.message, '⚠️', 'var(--high)');
    }
  },
};
