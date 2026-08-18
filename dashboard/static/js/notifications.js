/**
 * SOCPilot AI Dashboard — Notifications & SSE
 * ============================================
 * Handles: SSE connection, toast system, notification drawer
 */

window.notify = {
  _charts: {},

  // ── Toast System ─────────────────────────────────────────────────────────────
  toast(title, subtitle, icon = '🔔', color = 'var(--cyan)', duration = 5000) {
    const container = document.getElementById('toast-container');
    if (!container) return;

    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.style.borderLeft = `3px solid ${color}`;
    toast.innerHTML = `
      <div class="toast-icon" style="background:${color}22;">${icon}</div>
      <div class="toast-body">
        <div class="toast-title">${window.utils.escapeHtml(title)}</div>
        <div class="toast-sub">${window.utils.escapeHtml(subtitle)}</div>
      </div>
      <div class="toast-progress" style="background:${color};"></div>`;

    toast.addEventListener('click', () => dismissToast(toast));
    container.appendChild(toast);

    setTimeout(() => dismissToast(toast), duration);
  },

  // ── SSE Connection ────────────────────────────────────────────────────────────
  initSSE() {
    const statusDot = document.getElementById('status-dot');
    const statusLabel = document.getElementById('status-label');
    const statusSub = document.getElementById('status-sub');

    const setStatus = (state, label, sub) => {
      if (statusDot)   { statusDot.className = `status-dot ${state}`; }
      if (statusLabel) { statusLabel.textContent = label; }
      if (statusSub)   { statusSub.textContent = sub; }
    };

    setStatus('', 'Connecting...', 'Live monitoring');

    let retryDelay = 3000;
    let es = null;

    const connect = () => {
      if (es) es.close();
      es = new EventSource('/api/stream');

      es.addEventListener('connected', () => {
        setStatus('connected', 'Live', 'Watching reports/');
        retryDelay = 3000;
      });

      es.addEventListener('new_report', (evt) => {
        try {
          const report = JSON.parse(evt.data);
          this._handleNewReport(report);
        } catch (e) {
          console.error('SSE parse error:', e);
        }
      });

      es.addEventListener('ping', () => {
        // Heartbeat — connection alive
      });

      es.onerror = () => {
        setStatus('error', 'Disconnected', 'Reconnecting...');
        es.close();
        setTimeout(connect, retryDelay);
        retryDelay = Math.min(retryDelay * 1.5, 30000);
      };
    };

    connect();
  },

  // ── Handle New Report Event ───────────────────────────────────────────────────
  _handleNewReport(report) {
    const sev = report.severity || 'UNKNOWN';
    const id = report.report_id || 'New Report';
    const summary = (report.alert_summary || '').slice(0, 100);
    const filename = report.filename;

    // Severity-based icon & color
    const sevMap = {
      CRITICAL: { icon: '🚨', color: 'var(--critical)' },
      HIGH:     { icon: '⚠️', color: 'var(--high)' },
      MEDIUM:   { icon: '🔶', color: 'var(--medium)' },
      LOW:      { icon: '🔹', color: 'var(--low)' },
    };
    const { icon, color } = sevMap[sev] || { icon: '📋', color: 'var(--cyan)' };

    // Toast notification
    this.toast(
      `New Report: ${id}`,
      `${sev} • Risk: ${report.risk_score || 0}/100 — ${summary}...`,
      icon,
      color,
    );

    // Add to notification drawer
    this._addNotifItem(report, icon);

    // Update badge
    window.SOC.notifCount++;
    const badge = document.getElementById('notif-badge');
    if (badge) {
      badge.textContent = window.SOC.notifCount;
      badge.classList.remove('hidden');
    }

    // If currently on reports or overview, refresh
    if (window.SOC.currentPage === 'overview') {
      setTimeout(() => showOverviewPage(), 500);
    } else if (window.SOC.currentPage === 'reports') {
      setTimeout(() => showReportsPage(), 500);
    }
  },

  _addNotifItem(report, icon) {
    const list = document.getElementById('notif-list');
    if (!list) return;

    // Remove empty state if present
    const empty = list.querySelector('.notif-empty');
    if (empty) empty.remove();

    const item = document.createElement('div');
    item.className = 'notif-item';
    item.innerHTML = `
      <div class="notif-item-header">
        <span style="font-size:16px;">${icon}</span>
        <span class="notif-item-id">${window.utils.escapeHtml(report.report_id || 'Unknown')}</span>
        ${window.utils.severityBadge(report.severity)}
        <span class="notif-item-time">${window.utils.timeAgo(report.investigation_timestamp)}</span>
      </div>
      <div class="notif-item-summary">${window.utils.escapeHtml((report.alert_summary || '').slice(0, 120))}...</div>`;

    item.addEventListener('click', () => {
      window.navigate(`/report/${encodeURIComponent(report.filename)}`);
      // close drawer
      document.getElementById('notif-drawer')?.classList.remove('open');
      document.querySelector('.overlay')?.classList.remove('visible');
    });

    list.prepend(item);
  },
};

function dismissToast(toast) {
  toast.classList.add('out');
  toast.addEventListener('animationend', () => toast.remove(), { once: true });
}
