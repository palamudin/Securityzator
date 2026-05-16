/**
 * Audit Trail Viewer — hooks into the Reporter Proto sidebar.
 * Loads from /reporting/audit API (SQLite-backed).
 */

(function () {
  'use strict';

  const API = '/reporting/audit';

  // ── Bootstrap ──────────────────────────────────────────────────

  document.addEventListener('DOMContentLoaded', () => {
    // Hook into the existing nav system
    const auditBtn = document.querySelector('[data-view="audit"]');
    if (!auditBtn) return;

    auditBtn.addEventListener('click', () => loadAuditView());
    document.getElementById('auditRefreshBtn')?.addEventListener('click', () => loadAuditView());
    document.getElementById('auditFilterBtn')?.addEventListener('click', () => applyFilter());

    // Also trigger on scenario select change
    document.getElementById('auditScenarioSelect')?.addEventListener('change', () => applyFilter());
  });

  // ── Load ───────────────────────────────────────────────────────

  async function loadAuditView() {
    try {
      // Load stats
      const statsRes = await fetch(`${API}?action=stats`);
      const stats = await statsRes.json();
      document.getElementById('auditStats').textContent =
        `${stats.total_scenarios} scenarios · ${stats.total_events} events`;

      // Load scenarios for dropdown
      const scenRes = await fetch(`${API}?action=scenarios&limit=50`);
      const scenarios = await scenRes.json();
      const sel = document.getElementById('auditScenarioSelect');
      // Keep first option, replace rest
      sel.innerHTML = '<option value="">All scenarios</option>' +
        scenarios.map(s => `<option value="${s.id}">#${s.id}: ${s.name} (${s.event_count} events) — ${s.status}</option>`).join('');

      // Load all events by default
      const eventsRes = await fetch(`${API}?action=events&limit=100`);
      const events = await eventsRes.json();
      renderEvents(events);

    } catch (e) {
      document.getElementById('auditEventList').innerHTML =
        '<div style="color:#ff6b6b;padding:16px;">Failed to load audit data: ' + e.message + '</div>';
    }
  }

  // ── Filter ─────────────────────────────────────────────────────

  async function applyFilter() {
    const scenarioId = document.getElementById('auditScenarioSelect').value;
    const typeFilter = document.getElementById('auditTypeFilter').value.trim();

    try {
      let events;
      if (scenarioId) {
        const res = await fetch(`${API}?action=scenario&id=${scenarioId}`);
        const data = await res.json();
        events = data.events || [];
      } else if (typeFilter) {
        const res = await fetch(`${API}?action=events&type=${encodeURIComponent(typeFilter)}&limit=100`);
        events = await res.json();
      } else {
        const res = await fetch(`${API}?action=events&limit=100`);
        events = await res.json();
      }

      if (typeFilter && !scenarioId) {
        events = events.filter(e => e.event_type.toLowerCase().includes(typeFilter.toLowerCase()));
      }

      renderEvents(events);
    } catch (e) {
      document.getElementById('auditEventList').innerHTML =
        '<div style="color:#ff6b6b;padding:16px;">Filter error: ' + e.message + '</div>';
    }
  }

  // ── Render ─────────────────────────────────────────────────────

  function renderEvents(events) {
    const list = document.getElementById('auditEventList');
    if (!events || events.length === 0) {
      list.innerHTML = '<div style="color:rgba(236,246,255,.4);padding:24px;text-align:center;">No events recorded yet. Run a scenario to populate the audit trail.</div>';
      return;
    }

    const sourceColors = {
      agent: '#4fa7dc',
      graph: '#79d3a6',
      secz: '#f0a060',
      jira: '#2684ff',
      automated: '#a78bfa',
    };

    const statusIcons = {
      success: '✅',
      error: '❌',
      pending: '⏳',
    };

    list.innerHTML = events.map(e => {
      const color = sourceColors[e.source] || '#888';
      const icon = statusIcons[e.status] || '•';
      const ts = e.timestamp ? e.timestamp.replace('T', ' ').substring(0, 19) : '';
      const meta = e.metadata && e.metadata !== '{}'
        ? `<span style="font-size:10px;color:rgba(236,246,255,.3);">${e.metadata}</span>`
        : '';

      return `<div style="display:grid;grid-template-columns:140px 60px 1fr;gap:10px;align-items:center;
        background:rgba(255,255,255,0.03);border:1px solid rgba(255,255,255,0.06);border-radius:6px;padding:8px 12px;
        font-size:12px;color:rgba(236,246,255,.8);">
        <div style="color:rgba(236,246,255,.4);font-family:monospace;font-size:11px;">${ts}</div>
        <div><span style="background:${color};color:#000;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;">${e.source}</span></div>
        <div>
          <span style="margin-right:4px;">${icon}</span>
          <span style="font-weight:600;">${e.event_type}</span>
          <span style="color:rgba(236,246,255,.6);"> — ${e.detail}</span>
          ${e.target ? `<span style="color:rgba(236,246,255,.3);font-family:monospace;font-size:10px;"> [${e.target.substring(0,20)}]</span>` : ''}
          ${meta}
        </div>
      </div>`;
    }).join('');
  }

})();
