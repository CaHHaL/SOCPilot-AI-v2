/**
 * SOCPilot AI Dashboard — Reports List Page
 * ==========================================
 * Handles: search, severity filter, sort, paginated report card list
 */

window.reportsModule = {
  _allReports: [],
  _filtered: [],
  _activeFilter: 'ALL',
  _sortBy: 'date-desc',
  _searchQuery: '',

  render(container, reports) {
    this._allReports = reports;
    this._filtered = [...reports];

    container.innerHTML = `
      <div class="page-title">Investigation Reports</div>
      <div class="page-subtitle">${reports.length} reports found — click any report to view full details</div>

      <!-- Controls -->
      <div class="reports-controls">
        <div class="search-wrap">
          <svg viewBox="0 0 16 16" fill="none" width="14" height="14">
            <circle cx="6.5" cy="6.5" r="5" stroke="currentColor" stroke-width="1.5"/>
            <line x1="10" y1="10" x2="14" y2="14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
          </svg>
          <input type="text" class="search-input" id="report-search" placeholder="Search by ID, summary, IOC, hostname..." />
        </div>
        <div class="filter-pills">
          <button class="filter-pill active" data-filter="ALL">All <span>${reports.length}</span></button>
          <button class="filter-pill CRITICAL" data-filter="CRITICAL">🚨 Critical <span>${reports.filter(r=>r.severity==='CRITICAL').length}</span></button>
          <button class="filter-pill HIGH" data-filter="HIGH">⚠️ High <span>${reports.filter(r=>r.severity==='HIGH').length}</span></button>
          <button class="filter-pill MEDIUM" data-filter="MEDIUM">🔶 Medium <span>${reports.filter(r=>r.severity==='MEDIUM').length}</span></button>
          <button class="filter-pill LOW" data-filter="LOW">🔹 Low <span>${reports.filter(r=>r.severity==='LOW').length}</span></button>
          <button class="filter-pill" data-filter="ESCALATE">🔺 Escalate</button>
        </div>
        <select class="sort-select" id="sort-select">
          <option value="date-desc">Newest First</option>
          <option value="date-asc">Oldest First</option>
          <option value="risk-desc">Highest Risk</option>
          <option value="risk-asc">Lowest Risk</option>
          <option value="severity">By Severity</option>
        </select>
      </div>

      <!-- Results Count -->
      <div style="font-size:12px;color:var(--text-muted);margin-bottom:12px;" id="results-count">
        Showing ${reports.length} reports
      </div>

      <!-- Report List -->
      <div class="reports-list" id="reports-list"></div>`;

    // Wire up events
    const searchInput = document.getElementById('report-search');
    searchInput?.addEventListener('input', (e) => {
      this._searchQuery = e.target.value.toLowerCase();
      this._applyFilters();
    });

    document.querySelectorAll('.filter-pill').forEach(pill => {
      pill.addEventListener('click', () => {
        document.querySelectorAll('.filter-pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        const f = pill.dataset.filter;
        pill.classList.toggle(f, true);
        this._activeFilter = f;
        this._applyFilters();
      });
    });

    document.getElementById('sort-select')?.addEventListener('change', (e) => {
      this._sortBy = e.target.value;
      this._applyFilters();
    });

    this._renderList();
  },

  _applyFilters() {
    let results = [...this._allReports];

    // Filter
    if (this._activeFilter === 'ESCALATE') {
      results = results.filter(r => r.escalation_required);
    } else if (this._activeFilter !== 'ALL') {
      results = results.filter(r => r.severity === this._activeFilter);
    }

    // Search
    if (this._searchQuery) {
      results = results.filter(r =>
        r.report_id?.toLowerCase().includes(this._searchQuery) ||
        r.alert_summary?.toLowerCase().includes(this._searchQuery) ||
        r.thread_id?.toLowerCase().includes(this._searchQuery) ||
        r.severity?.toLowerCase().includes(this._searchQuery) ||
        r.filename?.toLowerCase().includes(this._searchQuery)
      );
    }

    // Sort
    results = this._sort(results, this._sortBy);

    this._filtered = results;

    const countEl = document.getElementById('results-count');
    if (countEl) {
      countEl.textContent = `Showing ${results.length} of ${this._allReports.length} reports`;
    }

    this._renderList();
  },

  _sort(list, sortBy) {
    const clone = [...list];
    const sevOrder = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
    switch (sortBy) {
      case 'date-desc': return clone.sort((a, b) => new Date(b.investigation_timestamp) - new Date(a.investigation_timestamp));
      case 'date-asc':  return clone.sort((a, b) => new Date(a.investigation_timestamp) - new Date(b.investigation_timestamp));
      case 'risk-desc': return clone.sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0));
      case 'risk-asc':  return clone.sort((a, b) => (a.risk_score || 0) - (b.risk_score || 0));
      case 'severity':  return clone.sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));
      default: return clone;
    }
  },

  _renderList() {
    const listEl = document.getElementById('reports-list');
    if (!listEl) return;

    if (!this._filtered.length) {
      listEl.innerHTML = `
        <div class="empty-state">
          <svg viewBox="0 0 40 40" fill="none" width="48" height="48">
            <rect x="6" y="4" width="28" height="32" rx="3" stroke="currentColor" stroke-width="1.5" opacity="0.3"/>
            <line x1="12" y1="14" x2="28" y2="14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" opacity="0.4"/>
            <line x1="12" y1="20" x2="24" y2="20" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" opacity="0.4"/>
          </svg>
          <h3>No reports found</h3>
          <p>Try adjusting your search or filter criteria.</p>
        </div>`;
      return;
    }

    listEl.innerHTML = this._filtered.map((r, i) => this._reportCard(r, i)).join('');
  },

  _reportCard(r, index) {
    const sev = r.severity || 'UNKNOWN';
    const color = window.utils.sevColor(sev);
    const delay = Math.min(index * 0.04, 0.4);

    return `
      <div class="report-card" style="--sev-color:${color};animation-delay:${delay}s;"
           onclick="window.navigate('/report/${encodeURIComponent(r.filename)}')"
           id="rpt-${window.utils.escapeHtml(r.report_id)}">
        <div class="report-card-left">
          <div class="report-card-header">
            <span class="report-card-id">${window.utils.escapeHtml(r.report_id)}</span>
            ${window.utils.severityBadge(sev)}
            ${r.escalation_required ? '<span class="escalation-chip yes">🔺 Escalation Required</span>' : ''}
            <span class="report-card-time" title="${r.investigation_timestamp}">
              ${window.utils.timeAgo(r.investigation_timestamp)} · ${window.utils.formatDate(r.investigation_timestamp)}
            </span>
          </div>
          <div class="report-card-summary">${window.utils.escapeHtml(r.alert_summary)}</div>
          <div class="report-card-meta">
            <span class="meta-chip">
              <svg width="12" height="12" viewBox="0 0 16 16" fill="none"><circle cx="8" cy="8" r="6" stroke="currentColor" stroke-width="1.5"/></svg>
              ${r.ioc_count} IOCs extracted
            </span>
            <span class="meta-chip">⚔️ ${r.mitre_count} MITRE techniques</span>
            <span class="meta-chip">🛡️ ${r.sigma_count} Sigma rules</span>
            <span class="meta-chip">🔍 ${r.threat_intel_count} threat intel</span>
            <span class="meta-chip" style="color:var(--text-muted);">🧵 ${window.utils.escapeHtml(r.thread_id || '—')}</span>
            <span class="fp-badge fp-${r.false_positive_likelihood || 'UNKNOWN'}" style="margin-left:auto;">
              FP: ${r.false_positive_likelihood || 'UNKNOWN'}
            </span>
          </div>
        </div>
        <div class="report-card-right">
          <div class="risk-pill" style="background:${window.utils.riskColor(r.risk_score)}22;color:${window.utils.riskColor(r.risk_score)};border:1px solid ${window.utils.riskColor(r.risk_score)}55;">
            <span style="font-size:10px;opacity:0.7;">RISK</span>
            ${r.risk_score}<span style="font-size:10px;opacity:0.7;">/100</span>
          </div>
          <div class="confidence-label">Confidence: ${Math.round((r.confidence_score || 0) * 100)}%</div>
          ${r.has_markdown ? '<div style="margin-top:6px;font-size:10px;color:var(--low);">📝 MD available</div>' : ''}
        </div>
      </div>`;
  },
};
