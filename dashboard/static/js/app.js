/**
 * SOCPilot AI Dashboard — App Bootstrap & Router
 * ================================================
 * Handles: client-side routing, global state, API helpers, page lifecycle
 */

// ── Global State ───────────────────────────────────────────────────────────────
window.SOC = {
  reports: [],
  stats: null,
  currentPage: null,
  notifCount: 0,
};

// ── API Helper ─────────────────────────────────────────────────────────────────
window.api = {
  base: '',

  async get(path) {
    const res = await fetch(this.base + path);
    if (!res.ok) throw new Error(`API error ${res.status}: ${path}`);
    return res.json();
  },

  async fetchReports() {
    const data = await this.get('/api/reports');
    window.SOC.reports = data.reports || [];
    return window.SOC.reports;
  },

  async fetchReport(filename) {
    return this.get(`/api/reports/${encodeURIComponent(filename)}`);
  },

  async fetchStats() {
    const data = await this.get('/api/stats');
    window.SOC.stats = data;
    return data;
  },

  async fetchMarkdown(filename) {
    return this.get(`/api/reports/${encodeURIComponent(filename)}/markdown`);
  },
};

// ── Utilities ──────────────────────────────────────────────────────────────────
window.utils = {
  formatDate(ts) {
    if (!ts) return '—';
    try {
      const d = new Date(ts);
      return d.toLocaleString('en-US', {
        month: 'short', day: 'numeric', year: 'numeric',
        hour: '2-digit', minute: '2-digit', hour12: false,
      });
    } catch { return ts; }
  },

  timeAgo(ts) {
    if (!ts) return '';
    try {
      const d = new Date(ts);
      const now = Date.now();
      const diff = now - d.getTime();
      const mins = Math.floor(diff / 60000);
      if (mins < 1) return 'just now';
      if (mins < 60) return `${mins}m ago`;
      const hrs = Math.floor(mins / 60);
      if (hrs < 24) return `${hrs}h ago`;
      const days = Math.floor(hrs / 24);
      return `${days}d ago`;
    } catch { return ''; }
  },

  sevColor(sev) {
    const map = { CRITICAL: 'var(--critical)', HIGH: 'var(--high)', MEDIUM: 'var(--medium)', LOW: 'var(--low)' };
    return map[sev] || 'var(--unknown)';
  },

  sevGlow(sev) {
    const map = { CRITICAL: 'var(--critical-glow)', HIGH: 'var(--high-glow)', MEDIUM: 'var(--medium-glow)', LOW: 'var(--low-glow)' };
    return map[sev] || 'rgba(99,99,102,0.3)';
  },

  riskColor(score) {
    if (score >= 80) return 'var(--critical)';
    if (score >= 60) return 'var(--high)';
    if (score >= 40) return 'var(--medium)';
    return 'var(--low)';
  },

  animateCounter(el, target, duration = 1000) {
    const start = performance.now();
    const startVal = parseInt(el.textContent) || 0;
    const update = (time) => {
      const elapsed = time - start;
      const progress = Math.min(elapsed / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.round(startVal + (target - startVal) * eased);
      if (progress < 1) requestAnimationFrame(update);
    };
    requestAnimationFrame(update);
  },

  copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
      window.notify.toast('Copied!', text, '📋', 'var(--cyan)');
    }).catch(() => {
      // fallback
      const ta = document.createElement('textarea');
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
    });
  },

  escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  },

  severityBadge(sev) {
    return `<span class="severity-badge ${sev}">${sev || 'UNKNOWN'}</span>`;
  },

  verdictBadge(verdict) {
    return `<span class="verdict-badge verdict-${verdict || 'UNKNOWN'}">${verdict || 'UNKNOWN'}</span>`;
  },
};

// ── Router ─────────────────────────────────────────────────────────────────────
const routes = {
  '/':        showOverviewPage,
  '/reports': showReportsPage,
  '/stats':   showStatsPage,
};

function parseRoute() {
  const hash = location.hash.replace('#', '') || '/';
  // Handle /report/:filename
  if (hash.startsWith('/report/')) {
    const filename = decodeURIComponent(hash.replace('/report/', ''));
    showReportDetailPage(filename);
    return;
  }
  const handler = routes[hash] || showOverviewPage;
  handler();
}

function navigate(path) {
  location.hash = path;
}

window.navigate = navigate;

// ── Nav Highlighting ────────────────────────────────────────────────────────────
function updateNav(page) {
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
  const target = document.getElementById(`nav-${page}`);
  if (target) target.classList.add('active');

  const labels = { overview: 'Overview', reports: 'Reports', stats: 'Statistics' };
  const breadEl = document.getElementById('breadcrumb-current');
  if (breadEl) breadEl.textContent = labels[page] || 'Overview';
}

// ── Live Clock ─────────────────────────────────────────────────────────────────
function startClock() {
  const el = document.getElementById('current-time');
  if (!el) return;
  const tick = () => {
    const now = new Date();
    el.textContent = now.toLocaleTimeString('en-US', { hour12: false });
  };
  tick();
  setInterval(tick, 1000);
}

// ── Report Count Badge ─────────────────────────────────────────────────────────
function updateReportCountBadge(count) {
  const el = document.getElementById('reports-count-badge');
  if (el) el.textContent = count;
}

// ── Notification Drawer Toggle ─────────────────────────────────────────────────
function initNotifDrawer() {
  const btn = document.getElementById('notif-btn');
  const drawer = document.getElementById('notif-drawer');
  const clearBtn = document.getElementById('notif-clear-btn');
  const overlay = document.createElement('div');
  overlay.className = 'overlay';
  document.body.appendChild(overlay);

  const close = () => {
    drawer.classList.remove('open');
    overlay.classList.remove('visible');
    // Reset badge
    const badge = document.getElementById('notif-badge');
    if (badge) { badge.textContent = '0'; badge.classList.add('hidden'); }
    window.SOC.notifCount = 0;
  };

  btn?.addEventListener('click', () => {
    const isOpen = drawer.classList.contains('open');
    if (isOpen) { close(); }
    else {
      drawer.classList.add('open');
      overlay.classList.add('visible');
    }
  });

  overlay.addEventListener('click', close);

  clearBtn?.addEventListener('click', () => {
    const list = document.getElementById('notif-list');
    if (list) {
      list.innerHTML = `
        <div class="notif-empty">
          <svg viewBox="0 0 40 40" fill="none" width="40" height="40">
            <circle cx="20" cy="20" r="18" stroke="currentColor" stroke-width="1.5" opacity="0.3"/>
            <path d="M20 10a8 8 0 018 8v5l2 3H10l2-3v-5a8 8 0 018-8z" stroke="currentColor" stroke-width="1.5" opacity="0.5"/>
          </svg>
          <p>No new notifications</p>
          <span>Watching reports/ for changes...</span>
        </div>`;
    }
    close();
  });
}

// ── Sidebar Mobile Toggle ──────────────────────────────────────────────────────
function initSidebarToggle() {
  const btn = document.getElementById('sidebar-toggle');
  const sidebar = document.getElementById('sidebar');
  btn?.addEventListener('click', () => {
    sidebar.classList.toggle('mobile-open');
  });
}

// ── Refresh Button ─────────────────────────────────────────────────────────────
function initRefreshBtn() {
  const btn = document.getElementById('refresh-btn');
  btn?.addEventListener('click', () => {
    btn.style.animation = 'spin 0.5s linear';
    setTimeout(() => { btn.style.animation = ''; }, 500);
    parseRoute(); // reload current page
  });
}

// ── Init ───────────────────────────────────────────────────────────────────────
async function init() {
  startClock();
  initNotifDrawer();
  initSidebarToggle();
  initRefreshBtn();

  // Init SSE notifications
  window.notify.initSSE();

  // Listen for hash changes
  window.addEventListener('hashchange', parseRoute);

  // Initial load
  parseRoute();
}

document.addEventListener('DOMContentLoaded', init);

// ── Shared: show loading spinner ───────────────────────────────────────────────
function showLoading(container) {
  container.innerHTML = `
    <div class="page-loader">
      <div class="spinner"></div>
      <div class="loader-text">Loading data...</div>
    </div>`;
}

// ── Page: Overview ─────────────────────────────────────────────────────────────
async function showOverviewPage() {
  updateNav('overview');
  window.SOC.currentPage = 'overview';
  const container = document.getElementById('page-container');
  showLoading(container);

  try {
    const [reports, stats] = await Promise.all([
      api.fetchReports(),
      api.fetchStats(),
    ]);
    updateReportCountBadge(reports.length);
    renderOverviewPage(container, reports, stats);
  } catch (e) {
    container.innerHTML = `<div class="empty-state"><h3>Error loading data</h3><p>${e.message}</p></div>`;
  }
}

function renderOverviewPage(container, reports, stats) {
  window.dashboardModule.render(container, reports, stats);
}

// ── Page: Reports ──────────────────────────────────────────────────────────────
async function showReportsPage() {
  updateNav('reports');
  window.SOC.currentPage = 'reports';
  const container = document.getElementById('page-container');
  showLoading(container);

  try {
    const reports = await api.fetchReports();
    updateReportCountBadge(reports.length);
    renderReportsPage(container, reports);
  } catch (e) {
    container.innerHTML = `<div class="empty-state"><h3>Error loading reports</h3><p>${e.message}</p></div>`;
  }
}

function renderReportsPage(container, reports) {
  window.reportsModule.render(container, reports);
}

// ── Page: Stats ────────────────────────────────────────────────────────────────
async function showStatsPage() {
  updateNav('stats');
  window.SOC.currentPage = 'stats';
  const container = document.getElementById('page-container');
  showLoading(container);

  try {
    const [reports, stats] = await Promise.all([
      api.fetchReports(),
      api.fetchStats(),
    ]);
    updateReportCountBadge(reports.length);
    renderStatsPage(container, reports, stats);
  } catch (e) {
    container.innerHTML = `<div class="empty-state"><h3>Error loading stats</h3><p>${e.message}</p></div>`;
  }
}

function renderStatsPage(container, reports, stats) {
  window.dashboardModule.renderStats(container, reports, stats);
}

// ── Page: Report Detail ────────────────────────────────────────────────────────
async function showReportDetailPage(filename) {
  updateNav('reports');
  window.SOC.currentPage = 'detail';
  const breadEl = document.getElementById('breadcrumb-current');
  if (breadEl) breadEl.textContent = 'Report Detail';

  const container = document.getElementById('page-container');
  showLoading(container);

  try {
    const report = await api.fetchReport(filename);
    window.reportDetailModule.render(container, report);
  } catch (e) {
    container.innerHTML = `
      <div class="empty-state">
        <h3>Report Not Found</h3>
        <p>${e.message}</p>
        <button class="btn btn-ghost mt-4" onclick="navigate('/reports')">← Back to Reports</button>
      </div>`;
  }
}
