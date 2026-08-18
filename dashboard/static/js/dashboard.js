/**
 * SOCPilot AI Dashboard — Overview & Stats Pages
 * ================================================
 * Renders: stat cards, charts (trend, severity donut, risk gauge), MITRE heatmap
 */

window.dashboardModule = {
  _charts: {},

  // ── Overview Page ─────────────────────────────────────────────────────────────
  render(container, reports, stats) {
    const critCount  = stats.severity_counts?.CRITICAL || 0;
    const highCount  = stats.severity_counts?.HIGH || 0;
    const medCount   = stats.severity_counts?.MEDIUM || 0;
    const lowCount   = stats.severity_counts?.LOW || 0;

    container.innerHTML = `
      <div class="page-title">Security Operations Center</div>
      <div class="page-subtitle">AI-generated investigation reports — Real-time monitoring dashboard</div>

      <!-- Stat Cards -->
      <div class="stats-grid stagger" id="stats-grid">
        ${this._statCard('📊', 'Total Reports', stats.total_reports, '', 'var(--cyan)', 'var(--cyan-dim)', 'var(--cyan-glow)')}
        ${this._statCard('🚨', 'Critical', critCount, `${Math.round(critCount/Math.max(stats.total_reports,1)*100)}% of total`, 'var(--critical)', 'var(--critical-dim)', 'var(--critical-glow)')}
        ${this._statCard('⚠️', 'High', highCount, `${Math.round(highCount/Math.max(stats.total_reports,1)*100)}% of total`, 'var(--high)', 'var(--high-dim)', 'var(--high-glow)')}
        ${this._statCard('🔶', 'Medium', medCount, `${Math.round(medCount/Math.max(stats.total_reports,1)*100)}% of total`, 'var(--medium)', 'var(--medium-dim)', 'var(--medium-glow)')}
        ${this._statCard('🔹', 'Low', lowCount, `${Math.round(lowCount/Math.max(stats.total_reports,1)*100)}% of total`, 'var(--low)', 'var(--low-dim)', 'var(--low-glow)')}
        ${this._statCard('🔺', 'Escalations', stats.escalation_count, 'Require immediate action', 'var(--critical)', 'var(--critical-dim)', 'var(--critical-glow)')}
        ${this._statCard('📈', 'Avg Risk Score', stats.avg_risk_score, 'out of 100', this._avgRiskColor(stats.avg_risk_score), this._avgRiskDim(stats.avg_risk_score), this._avgRiskGlow(stats.avg_risk_score))}
        ${this._statCard('🛡️', 'IOCs Flagged', this._totalMaliciousIOCs(stats), 'malicious verdicts', 'var(--critical)', 'var(--critical-dim)', 'var(--critical-glow)')}
      </div>

      <!-- Charts Row -->
      <div class="charts-grid">
        <div class="chart-card">
          <div class="section-title">Severity Trend Over Time</div>
          <div class="chart-canvas-wrap" style="height:220px;">
            <canvas id="trend-chart"></canvas>
          </div>
        </div>
        <div class="chart-card" style="display:flex;flex-direction:column;align-items:center;">
          <div class="section-title" style="align-self:flex-start;">Severity Distribution</div>
          <div class="chart-canvas-wrap" style="height:200px;width:200px;">
            <canvas id="sev-donut"></canvas>
          </div>
          <div id="donut-legend" style="margin-top:12px;display:flex;flex-direction:column;gap:6px;"></div>
        </div>
      </div>

      <!-- MITRE Heatmap + Threat Intel + Recent Reports -->
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:16px;margin-bottom:20px;">
        <div class="chart-card">
          <div class="section-title">MITRE ATT&CK Techniques</div>
          <div id="mitre-heatmap" class="heatmap-grid mt-4"></div>
        </div>
        <div class="chart-card">
          <div class="section-title">Threat Intelligence Verdicts</div>
          <div class="chart-canvas-wrap" style="height:180px;max-width:280px;margin:0 auto;">
            <canvas id="intel-chart"></canvas>
          </div>
        </div>
      </div>

      <!-- Recent Reports -->
      <div class="glass-card" style="padding:20px;">
        <div class="section-header">
          <div class="section-title">Recent Investigations</div>
          <button class="btn btn-ghost" onclick="window.navigate('/reports')">View All →</button>
        </div>
        <div id="recent-reports-list"></div>
      </div>`;

    // Animate counters
    container.querySelectorAll('.stat-value[data-target]').forEach(el => {
      window.utils.animateCounter(el, parseInt(el.dataset.target), 1200);
    });

    // Render charts after DOM is ready
    requestAnimationFrame(() => {
      this._renderTrendChart(stats);
      this._renderSeverityDonut(stats, container);
      this._renderIntelChart(stats);
      this._renderMitreHeatmap(stats, container);
      this._renderRecentReports(reports.slice(0, 6), container);
    });
  },

  _statCard(icon, label, value, sub, color, dim, glow) {
    return `
      <div class="stat-card" style="--stat-color:${color};--stat-dim:${dim};--stat-glow:${glow};">
        <div class="stat-card-icon">${icon}</div>
        <div class="stat-value" data-target="${value}">0</div>
        <div class="stat-label">${label}</div>
        ${sub ? `<div class="stat-sub">${sub}</div>` : ''}
      </div>`;
  },

  _totalMaliciousIOCs(stats) {
    return stats.verdict_counts?.MALICIOUS || 0;
  },

  _avgRiskColor(score) {
    if (score >= 70) return 'var(--critical)';
    if (score >= 50) return 'var(--high)';
    if (score >= 30) return 'var(--medium)';
    return 'var(--low)';
  },
  _avgRiskDim(score) {
    if (score >= 70) return 'var(--critical-dim)';
    if (score >= 50) return 'var(--high-dim)';
    if (score >= 30) return 'var(--medium-dim)';
    return 'var(--low-dim)';
  },
  _avgRiskGlow(score) {
    if (score >= 70) return 'var(--critical-glow)';
    if (score >= 50) return 'var(--high-glow)';
    if (score >= 30) return 'var(--medium-glow)';
    return 'var(--low-glow)';
  },

  // ── Trend Chart ───────────────────────────────────────────────────────────────
  _renderTrendChart(stats) {
    const canvas = document.getElementById('trend-chart');
    if (!canvas) return;
    if (this._charts.trend) { this._charts.trend.destroy(); }

    const daily = stats.daily_severity || {};
    const labels = Object.keys(daily).sort();
    const sevKeys = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW'];
    const colors  = ['#ff2d55', '#ff9500', '#ffcc00', '#30d158'];

    const datasets = sevKeys.map((sev, i) => ({
      label: sev,
      data: labels.map(d => daily[d]?.[sev] || 0),
      borderColor: colors[i],
      backgroundColor: colors[i] + '22',
      tension: 0.4,
      fill: true,
      pointBackgroundColor: colors[i],
      pointRadius: 4,
      pointHoverRadius: 6,
    }));

    this._charts.trend = new Chart(canvas, {
      type: 'line',
      data: { labels, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { labels: { color: '#8aa8c0', font: { size: 11 }, boxWidth: 12 } },
          tooltip: { backgroundColor: 'rgba(4,10,20,0.9)', borderColor: '#00d4ff33', borderWidth: 1 },
        },
        scales: {
          x: { ticks: { color: '#4a6a80', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
          y: { ticks: { color: '#4a6a80', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true },
        },
      },
    });
  },

  // ── Severity Donut ────────────────────────────────────────────────────────────
  _renderSeverityDonut(stats, container) {
    const canvas = document.getElementById('sev-donut');
    if (!canvas) return;
    if (this._charts.donut) { this._charts.donut.destroy(); }

    const sevMap = { CRITICAL: '#ff2d55', HIGH: '#ff9500', MEDIUM: '#ffcc00', LOW: '#30d158', UNKNOWN: '#636366' };
    const labels = Object.keys(stats.severity_counts || {});
    const data   = labels.map(k => stats.severity_counts[k]);
    const colors = labels.map(k => sevMap[k] || '#636366');

    this._charts.donut = new Chart(canvas, {
      type: 'doughnut',
      data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 2, borderColor: 'rgba(4,10,20,0.9)', hoverBorderWidth: 0 }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '70%',
        plugins: {
          legend: { display: false },
          tooltip: { backgroundColor: 'rgba(4,10,20,0.9)', borderColor: '#00d4ff33', borderWidth: 1 },
        },
      },
    });

    // Custom legend
    const legendEl = document.getElementById('donut-legend');
    if (legendEl) {
      legendEl.innerHTML = labels.map((lbl, i) => `
        <div style="display:flex;align-items:center;gap:8px;font-size:12px;">
          <span style="width:10px;height:10px;border-radius:2px;background:${colors[i]};flex-shrink:0;display:inline-block;"></span>
          <span style="color:var(--text-muted);">${lbl}</span>
          <span style="color:var(--text-primary);font-weight:700;margin-left:auto;">${data[i]}</span>
        </div>`).join('');
    }
  },

  // ── Intel Chart ───────────────────────────────────────────────────────────────
  _renderIntelChart(stats) {
    const canvas = document.getElementById('intel-chart');
    if (!canvas) return;
    if (this._charts.intel) { this._charts.intel.destroy(); }

    const verdicts = stats.verdict_counts || {};
    const labels = Object.keys(verdicts);
    const data   = labels.map(k => verdicts[k]);
    const colorMap = { MALICIOUS: '#ff2d55', CLEAN: '#30d158', SUSPICIOUS: '#ff9500', UNKNOWN: '#636366' };
    const colors = labels.map(k => colorMap[k] || '#636366');

    this._charts.intel = new Chart(canvas, {
      type: 'doughnut',
      data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 2, borderColor: 'rgba(4,10,20,0.9)', hoverBorderWidth: 0 }] },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '65%',
        plugins: {
          legend: { position: 'bottom', labels: { color: '#8aa8c0', font: { size: 11 }, padding: 10 } },
          tooltip: { backgroundColor: 'rgba(4,10,20,0.9)', borderColor: '#00d4ff33', borderWidth: 1 },
        },
      },
    });
  },

  // ── MITRE Heatmap ─────────────────────────────────────────────────────────────
  _renderMitreHeatmap(stats, container) {
    const el = document.getElementById('mitre-heatmap');
    if (!el) return;

    const techniques = stats.mitre_top_techniques || [];
    if (!techniques.length) {
      el.innerHTML = '<p style="color:var(--text-muted);font-size:12px;">No MITRE techniques detected across reports.</p>';
      return;
    }

    const maxCount = Math.max(...techniques.map(([, c]) => c), 1);

    el.innerHTML = techniques.map(([name, count]) => {
      const intensity = count / maxCount;
      const alpha = Math.round(0.2 + intensity * 0.7, 2);
      const parts = name.split(': ');
      const id = parts[0];
      const techName = parts.slice(1).join(': ') || name;
      const url = `https://attack.mitre.org/techniques/${id.replace('.', '/')}`;
      return `
        <a href="${url}" target="_blank" rel="noopener" class="heatmap-cell" 
           style="background:rgba(0,212,255,${alpha});color:${intensity > 0.6 ? '#fff' : 'var(--cyan)'};border:1px solid rgba(0,212,255,${alpha + 0.1});"
           title="${window.utils.escapeHtml(techName)} (${count} reports)">
          ${window.utils.escapeHtml(id)} <span style="opacity:0.7;font-size:9px;">${count}</span>
        </a>`;
    }).join('');
  },

  // ── Recent Reports ────────────────────────────────────────────────────────────
  _renderRecentReports(reports, container) {
    const el = document.getElementById('recent-reports-list');
    if (!el) return;

    if (!reports.length) {
      el.innerHTML = '<div class="empty-state"><h3>No reports yet</h3></div>';
      return;
    }

    el.innerHTML = `<div class="reports-list">` +
      reports.map(r => this._miniReportCard(r)).join('') +
      `</div>`;
  },

  _miniReportCard(r) {
    const sev = r.severity || 'UNKNOWN';
    const color = window.utils.sevColor(sev);
    return `
      <div class="report-card" style="--sev-color:${color};" onclick="window.navigate('/report/${encodeURIComponent(r.filename)}')">
        <div class="report-card-left">
          <div class="report-card-header">
            <span class="report-card-id">${window.utils.escapeHtml(r.report_id)}</span>
            ${window.utils.severityBadge(sev)}
            <span class="report-card-time">${window.utils.timeAgo(r.investigation_timestamp)}</span>
          </div>
          <div class="report-card-summary">${window.utils.escapeHtml(r.alert_summary)}</div>
          <div class="report-card-meta">
            <span class="meta-chip">
              <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/><path d="M5 8l2 2 4-4" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>
              ${r.ioc_count} IOCs
            </span>
            <span class="meta-chip">⚔️ ${r.mitre_count} MITRE</span>
            <span class="meta-chip">🚨 ${r.sigma_count} Sigma</span>
            ${r.escalation_required ? '<span class="escalation-chip yes">🔺 Escalate</span>' : ''}
          </div>
        </div>
        <div class="report-card-right">
          <div class="risk-pill" style="background:${window.utils.riskColor(r.risk_score)}22;color:${window.utils.riskColor(r.risk_score)};border:1px solid ${window.utils.riskColor(r.risk_score)}44;">
            ${r.risk_score}<span style="font-size:10px;opacity:0.7;">/100</span>
          </div>
        </div>
      </div>`;
  },

  // ── Statistics Page ───────────────────────────────────────────────────────────
  renderStats(container, reports, stats) {
    container.innerHTML = `
      <div class="page-title">Statistics & Analytics</div>
      <div class="page-subtitle">Historical analysis across all ${stats.total_reports} investigation reports</div>

      <div class="stats-charts-grid">
        <!-- Risk score timeline -->
        <div class="chart-card">
          <div class="section-title">Risk Score Over Time</div>
          <div class="chart-canvas-wrap" style="height:220px;">
            <canvas id="risk-timeline"></canvas>
          </div>
        </div>
        <!-- Severity Distribution -->
        <div class="chart-card">
          <div class="section-title">Severity Breakdown</div>
          <div class="chart-canvas-wrap" style="height:220px;">
            <canvas id="sev-bar"></canvas>
          </div>
        </div>
      </div>

      <div class="stats-charts-grid">
        <!-- Top MITRE Techniques -->
        <div class="chart-card">
          <div class="section-title">Top MITRE Tactics</div>
          <div class="chart-canvas-wrap" style="height:220px;">
            <canvas id="mitre-bar"></canvas>
          </div>
        </div>
        <!-- False Positive Likelihood -->
        <div class="chart-card">
          <div class="section-title">False Positive Likelihood</div>
          <div class="chart-canvas-wrap" style="height:220px;">
            <canvas id="fp-chart"></canvas>
          </div>
        </div>
      </div>

      <!-- Escalation Rate -->
      <div class="chart-card mb-4">
        <div class="section-title">Report Summary Table</div>
        <div style="overflow-x:auto;margin-top:16px;">
          <table class="intel-table">
            <thead><tr>
              <th>Report ID</th><th>Timestamp</th><th>Severity</th>
              <th>Risk Score</th><th>IOCs</th><th>MITRE</th><th>Escalate</th>
            </tr></thead>
            <tbody id="stats-table-body"></tbody>
          </table>
        </div>
      </div>`;

    requestAnimationFrame(() => {
      this._renderRiskTimeline(reports);
      this._renderSevBar(stats);
      this._renderMitreBar(stats);
      this._renderFPChart(stats);
      this._renderStatsTable(reports);
    });
  },

  _renderRiskTimeline(reports) {
    const canvas = document.getElementById('risk-timeline');
    if (!canvas) return;
    if (this._charts.riskLine) { this._charts.riskLine.destroy(); }

    const sorted = [...reports].sort((a, b) =>
      new Date(a.investigation_timestamp) - new Date(b.investigation_timestamp)
    );
    const labels = sorted.map(r => window.utils.timeAgo(r.investigation_timestamp));
    const data   = sorted.map(r => r.risk_score || 0);
    const ptColors = data.map(v => window.utils.riskColor(v));

    this._charts.riskLine = new Chart(canvas, {
      type: 'line',
      data: {
        labels,
        datasets: [{
          label: 'Risk Score',
          data,
          borderColor: '#00d4ff',
          backgroundColor: 'rgba(0,212,255,0.08)',
          tension: 0.4,
          fill: true,
          pointBackgroundColor: ptColors,
          pointRadius: 5,
          pointHoverRadius: 7,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { backgroundColor: 'rgba(4,10,20,0.9)', borderColor: '#00d4ff33', borderWidth: 1 } },
        scales: {
          x: { ticks: { color: '#4a6a80', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
          y: { ticks: { color: '#4a6a80', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' }, min: 0, max: 100 },
        },
      },
    });
  },

  _renderSevBar(stats) {
    const canvas = document.getElementById('sev-bar');
    if (!canvas) return;
    if (this._charts.sevBar) { this._charts.sevBar.destroy(); }

    const sevMap = { CRITICAL: '#ff2d55', HIGH: '#ff9500', MEDIUM: '#ffcc00', LOW: '#30d158', UNKNOWN: '#636366' };
    const labels = Object.keys(stats.severity_counts || {});
    const data   = labels.map(k => stats.severity_counts[k]);
    const colors = labels.map(k => sevMap[k] || '#636366');

    this._charts.sevBar = new Chart(canvas, {
      type: 'bar',
      data: { labels, datasets: [{ data, backgroundColor: colors, borderRadius: 6, hoverBorderWidth: 0 }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { backgroundColor: 'rgba(4,10,20,0.9)' } },
        scales: {
          x: { ticks: { color: '#8aa8c0' }, grid: { display: false } },
          y: { ticks: { color: '#4a6a80' }, grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true },
        },
      },
    });
  },

  _renderMitreBar(stats) {
    const canvas = document.getElementById('mitre-bar');
    if (!canvas) return;
    if (this._charts.mitreBar) { this._charts.mitreBar.destroy(); }

    const tactics = (stats.mitre_top_tactics || []).slice(0, 8);
    const labels = tactics.map(([t]) => t);
    const data   = tactics.map(([, c]) => c);

    this._charts.mitreBar = new Chart(canvas, {
      type: 'bar',
      data: { labels, datasets: [{ data, backgroundColor: 'rgba(0,212,255,0.6)', borderColor: '#00d4ff', borderWidth: 1, borderRadius: 6 }] },
      options: {
        indexAxis: 'y',
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false }, tooltip: { backgroundColor: 'rgba(4,10,20,0.9)' } },
        scales: {
          x: { ticks: { color: '#4a6a80' }, grid: { color: 'rgba(255,255,255,0.04)' }, beginAtZero: true },
          y: { ticks: { color: '#8aa8c0', font: { size: 10 } }, grid: { display: false } },
        },
      },
    });
  },

  _renderFPChart(stats) {
    const canvas = document.getElementById('fp-chart');
    if (!canvas) return;
    if (this._charts.fpChart) { this._charts.fpChart.destroy(); }

    const fp = stats.false_positive_likelihood || {};
    const labels = Object.keys(fp);
    const data   = labels.map(k => fp[k]);
    const colorMap = { LOW: '#ff2d55', MEDIUM: '#ffcc00', HIGH: '#30d158', UNKNOWN: '#636366' };
    const colors = labels.map(k => colorMap[k] || '#636366');

    this._charts.fpChart = new Chart(canvas, {
      type: 'pie',
      data: { labels, datasets: [{ data, backgroundColor: colors, borderWidth: 2, borderColor: 'rgba(4,10,20,0.9)' }] },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'right', labels: { color: '#8aa8c0', font: { size: 11 } } }, tooltip: { backgroundColor: 'rgba(4,10,20,0.9)' } },
      },
    });
  },

  _renderStatsTable(reports) {
    const tbody = document.getElementById('stats-table-body');
    if (!tbody) return;
    tbody.innerHTML = reports.map(r => {
      const sev = r.severity || 'UNKNOWN';
      return `<tr onclick="window.navigate('/report/${encodeURIComponent(r.filename)}')" style="cursor:pointer;">
        <td class="intel-ioc-cell">${window.utils.escapeHtml(r.report_id)}</td>
        <td>${window.utils.formatDate(r.investigation_timestamp)}</td>
        <td>${window.utils.severityBadge(sev)}</td>
        <td><span style="color:${window.utils.riskColor(r.risk_score)};font-weight:700;font-family:var(--font-mono);">${r.risk_score}/100</span></td>
        <td>${r.ioc_count}</td>
        <td>${r.mitre_count}</td>
        <td>${r.escalation_required ? '<span class="escalation-chip yes">🔺 YES</span>' : '<span class="escalation-chip no">NO</span>'}</td>
      </tr>`;
    }).join('');
  },
};
