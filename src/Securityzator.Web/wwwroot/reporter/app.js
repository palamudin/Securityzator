(() => {
  const STORAGE_KEY = 'cw-gridstack-proto-split-v2';
  const LEGACY_KEYS = [
    STORAGE_KEY,
    'cw-gridstack-proto-split-v1',
    'cw-gridstack-proto-v13',
    'cw-gridstack-proto-v12',
    'cw-gridstack-proto-v11',
    'cw-gridstack-proto-v10',
    'cw-gridstack-proto-v9',
    'cw-gridstack-proto-v8',
    'cw-gridstack-proto-v7',
    'cw-gridstack-proto-v6'
  ];
  const TEMPLATES_KEY = STORAGE_KEY + '-templates';
  const BANNER_KEY = STORAGE_KEY + '-banner-dismissed';
  const GUIDE_KEY = STORAGE_KEY + '-guide-dismissed';
  const GRID_COLUMNS = 16;
  const GRID_CELL_HEIGHT = 108;

  const app = document.getElementById('app');
  const boardsHost = document.getElementById('boardsHost');
  const guideModal = document.getElementById('guideModal');
  const templateList = document.getElementById('templateList');
  const previewHolder = document.getElementById('previewHolder');
  const previewTitle = document.getElementById('previewTitle');
  const previewSub = document.getElementById('previewSub');
  const builderPreview = document.getElementById('builderPreview');
  const schemaList = document.getElementById('schemaList');
  const syncStatusText = document.getElementById('syncStatusText');
  const maxModal = document.getElementById('maxModal');
  const maxGrid = document.getElementById('maxGrid');
  const maxModalTitle = document.getElementById('maxModalTitle');
  const maxModalSub = document.getElementById('maxModalSub');

  const layoutPresets = {
    kpi: { w: 3, h: 3, minW: 2, minH: 2 },
    donut: { w: 5, h: 4, minW: 4, minH: 3 },
    bar: { w: 6, h: 4, minW: 5, minH: 3 },
    list: { w: 7, h: 5, minW: 6, minH: 4 },
    table: { w: 9, h: 5, minW: 8, minH: 4 }
  };

  const trimmedSchema = [
    { path: 'id', type: 'number', desc: 'Ticket identifier' },
    { path: 'summary', type: 'text', desc: 'Short subject / summary' },
    { path: 'company.name', type: 'dimension', desc: 'Client / company name' },
    { path: 'contact.name', type: 'dimension', desc: 'Primary contact' },
    { path: 'contact.email', type: 'dimension', desc: 'Contact email' },
    { path: 'board.name', type: 'dimension', desc: 'Board' },
    { path: 'status.name', type: 'status', desc: 'Ticket status' },
    { path: 'team.name', type: 'dimension', desc: 'Assigned team' },
    { path: 'owner.name', type: 'dimension', desc: 'Assigned engineer' },
    { path: 'priority.name', type: 'dimension', desc: 'Priority label' },
    { path: 'priority.level', type: 'dimension', desc: 'Priority tier / level' },
    { path: 'type.name', type: 'dimension', desc: 'Ticket type' },
    { path: 'subType.name', type: 'dimension', desc: 'Ticket subtype' },
    { path: 'item.name', type: 'dimension', desc: 'Ticket item' },
    { path: 'dateEntered', type: 'time', desc: 'Created date' },
    { path: 'lastUpdated', type: 'time', desc: 'Last touched / updated' },
    { path: 'closedDate', type: 'time', desc: 'Closed date' },
    { path: 'closedFlag', type: 'boolean', desc: 'Open / closed flag' },
    { path: 'slaStatus', type: 'status', desc: 'SLA posture' }
  ];

  const prereqs = [
    { key: 'countTickets', label: 'Count tickets', infer: { primary: 'id' } },
    { key: 'openClosed', label: 'Open / closed state', infer: { primary: 'closedFlag', endpoint: '/analytics/tickets/open-now', renderer: 'kpi' } },
    { key: 'createdDate', label: 'Created date', infer: { primary: 'dateEntered', endpoint: '/analytics/tickets/opened-today', renderer: 'kpi' } },
    { key: 'closedDate', label: 'Closed date', infer: { primary: 'closedDate', endpoint: '/analytics/tickets/closed-today', renderer: 'kpi' } },
    { key: 'lastTouch', label: 'Last touch', infer: { primary: 'lastUpdated', endpoint: '/analytics/tickets/stale-watchlist', renderer: 'list' } },
    { key: 'byEngineer', label: 'Group by engineer', infer: { group: 'owner.name', endpoint: '/analytics/tickets/by-engineer', renderer: 'bar' } },
    { key: 'byClient', label: 'Group by client', infer: { group: 'company.name', endpoint: '/analytics/tickets/by-client', renderer: 'bar' } },
    { key: 'byTeam', label: 'Group by team', infer: { group: 'team.name', endpoint: '/analytics/tickets/by-team', renderer: 'bar' } },
    { key: 'byBoard', label: 'Group by board', infer: { group: 'board.name', endpoint: '/analytics/tickets/by-board', renderer: 'donut' } },
    { key: 'byPriority', label: 'Group by priority', infer: { group: 'priority.level', endpoint: '/analytics/tickets/by-priority', renderer: 'donut' } },
    { key: 'detailRows', label: 'Detail rows', infer: { endpoint: '/service/tickets', renderer: 'table' } },
    { key: 'staleRisk', label: 'Stale risk', infer: { endpoint: '/analytics/tickets/stale-watchlist', renderer: 'list', primary: 'lastUpdated' } }
  ];

  const endpointCatalog = [
    { endpoint: '/service/tickets', label: 'Ticket list' },
    { endpoint: '/analytics/tickets/open-now', label: 'Open now KPI' },
    { endpoint: '/analytics/tickets/opened-today', label: 'Opened today KPI' },
    { endpoint: '/analytics/tickets/closed-today', label: 'Closed today KPI' },
    { endpoint: '/analytics/tickets/by-engineer', label: 'By engineer' },
    { endpoint: '/analytics/tickets/by-client', label: 'By client' },
    { endpoint: '/analytics/tickets/by-team', label: 'By team' },
    { endpoint: '/analytics/tickets/by-board', label: 'By board' },
    { endpoint: '/analytics/tickets/by-priority', label: 'By priority' },
    { endpoint: '/analytics/tickets/stale-watchlist', label: 'Stale watchlist' }
  ];

  const BASE_TEMPLATES = [
    { id: 'open-now', title: 'Current Open Tickets', type: 'kpi', description: 'Open workload right now.', endpoint: '/analytics/tickets/open-now', legend: ['Uses closedFlag', 'Counts open tickets only'], primaryField: 'closedFlag', groupField: '', prereqs: ['countTickets', 'openClosed'], roles: {}, custom: false },
    { id: 'opened-today', title: 'Tickets Opened Today', type: 'kpi', description: 'Created today from dateEntered.', endpoint: '/analytics/tickets/opened-today', legend: ['Uses dateEntered', 'Today = 2026-04-13 demo clock'], primaryField: 'dateEntered', groupField: '', prereqs: ['countTickets', 'createdDate'], roles: {}, custom: false },
    { id: 'closed-today', title: 'Tickets Closed Today', type: 'kpi', description: 'Closed today from closedDate.', endpoint: '/analytics/tickets/closed-today', legend: ['Uses closedDate', 'Today = 2026-04-13 demo clock'], primaryField: 'closedDate', groupField: '', prereqs: ['countTickets', 'closedDate'], roles: {}, custom: false },
    { id: 'by-engineer', title: 'Tickets per Engineer', type: 'bar', description: 'Grouped open ticket load by owner.', endpoint: '/analytics/tickets/by-engineer', legend: ['Group by owner.name', 'Open tickets only'], primaryField: 'id', groupField: 'owner.name', prereqs: ['countTickets', 'byEngineer'], roles: {}, custom: false },
    { id: 'by-client', title: 'Tickets per Client', type: 'bar', description: 'Grouped by company name.', endpoint: '/analytics/tickets/by-client', legend: ['Group by company.name', 'Open tickets only'], primaryField: 'id', groupField: 'company.name', prereqs: ['countTickets', 'byClient'], roles: {}, custom: false },
    { id: 'by-priority', title: 'Tickets by Tier', type: 'donut', description: 'Priority mix from the trimmed ticket payload.', endpoint: '/analytics/tickets/by-priority', legend: ['Group by priority.level', 'Open tickets only'], primaryField: 'id', groupField: 'priority.level', prereqs: ['countTickets', 'byPriority'], roles: {}, custom: false },
    { id: 'watchlist', title: 'Stale Ticket Watchlist', type: 'list', description: 'Oldest untouched tickets with client, owner and SLA posture.', endpoint: '/analytics/tickets/stale-watchlist', legend: ['Sort by lastUpdated oldest first', 'Open tickets only'], primaryField: 'lastUpdated', groupField: 'owner.name', prereqs: ['lastTouch', 'staleRisk'], roles: {'company.name':'label','priority.name':'status','slaStatus':'status'}, custom: false },
    { id: 'table', title: 'Engineer Workload Table', type: 'table', description: 'Compact row view driven from endpoint response.', endpoint: '/service/tickets', legend: ['Response slice shown below', 'Uses trimmed ticket fields only'], primaryField: 'id', groupField: '', prereqs: ['detailRows'], roles: {'company.name':'dimension','owner.name':'dimension'}, custom: false }
  ];

  function createTemplateId() {
    return 'tpl-' + Date.now().toString(36) + '-' + Math.random().toString(36).slice(2, 7);
  }

  function normalizeTemplate(raw, index) {
    const id = String(raw.id || createTemplateId());
    const type = ['kpi', 'bar', 'donut', 'list', 'table'].includes(raw.type) ? raw.type : 'kpi';
    const preset = layoutPresets[type] || { w: 4, h: 3, minW: 3, minH: 2 };
    return {
      id,
      title: String(raw.title || `Custom Template ${index + 1}`),
      description: String(raw.description || ''),
      type,
      endpoint: String(raw.endpoint || '/service/tickets'),
      legend: Array.isArray(raw.legend) ? raw.legend.map(String) : [],
      primaryField: String(raw.primaryField || ''),
      groupField: String(raw.groupField || ''),
      prereqs: Array.isArray(raw.prereqs) ? raw.prereqs.map(String) : [],
      roles: raw.roles && typeof raw.roles === 'object' ? { ...raw.roles } : {},
      custom: !!raw.custom,
      w: Number.isFinite(raw.w) ? raw.w : preset.w,
      h: Number.isFinite(raw.h) ? raw.h : preset.h,
      minW: Number.isFinite(raw.minW) ? raw.minW : preset.minW,
      minH: Number.isFinite(raw.minH) ? raw.minH : preset.minH
    };
  }

  function loadTemplates() {
    let custom = [];
    try {
      const raw = localStorage.getItem(TEMPLATES_KEY);
      if (raw) custom = JSON.parse(raw);
    } catch {}
    const base = BASE_TEMPLATES.map((tpl, index) => normalizeTemplate(tpl, index));
    const customNormalized = Array.isArray(custom) ? custom.map((tpl, index) => normalizeTemplate({ ...tpl, custom: true }, index)) : [];
    return [...customNormalized, ...base];
  }

  function saveTemplates() {
    try {
      const custom = templates.filter(template => template.custom);
      localStorage.setItem(TEMPLATES_KEY, JSON.stringify(custom));
    } catch {}
  }

  let templates = loadTemplates();
  let fakeTickets = [];
  let selectedTemplateId = templates[0]?.id || BASE_TEMPLATES[0].id;
  let builderState = { prereqs: new Set(['countTickets']), roles: {} };

  const runtime = {
    grids: new Map(),
    syncingDashboards: new Set(),
    selectedGroupId: '',
    groupMode: false,
    widgetSerial: 1,
    dashboardSerial: 3,
    builderEditingId: ''
  };

  function esc(value) {
    return String(value ?? '')
      .replaceAll('&', '&amp;')
      .replaceAll('<', '&lt;')
      .replaceAll('>', '&gt;')
      .replaceAll('"', '&quot;')
      .replaceAll("'", '&#39;');
  }

  function bindIf(id, eventName, handler) {
    const el = document.getElementById(id);
    if (!el) return;
    el.addEventListener(eventName, handler);
  }

  function defaultState() {
    return {
      activeDashboardId: 'dash-1',
      dashboards: [
        { id: 'dash-1', name: 'Dashboard 1', widgets: [] },
        { id: 'dash-2', name: 'Dashboard 2', widgets: [] }
      ],
      groups: []
    };
  }

  function shortName(title) {
    const clean = String(title || '').replace(/Tickets?/gi, '').trim();
    const parts = clean.split(/\s+/).filter(Boolean);
    return parts.slice(0, 2).join(' ');
  }

  function nextDashboardId() {
    while (true) {
      const id = 'dash-' + runtime.dashboardSerial++;
      if (!state.dashboards.some(d => d.id === id)) return id;
    }
  }

  function nextWidgetId() {
    return 'wid-' + Date.now().toString(36) + '-' + (runtime.widgetSerial++).toString(36);
  }

  function normalizeWidget(raw) {
    const out = { ...raw };
    const rawId = out.id || out.widgetId || '';
    const templateId = out.templateId || (templates.some(t => t.id === rawId) ? rawId : '');
    return {
      id: templates.some(t => t.id === rawId) ? nextWidgetId() : (rawId || nextWidgetId()),
      templateId,
      x: Number.isFinite(out.x) ? out.x : 0,
      y: Number.isFinite(out.y) ? out.y : 0,
      w: Number.isFinite(out.w) ? out.w : (presetForTemplate(templates.find(t => t.id === templateId) || {}).w || 4),
      h: Number.isFinite(out.h) ? out.h : (presetForTemplate(templates.find(t => t.id === templateId) || {}).h || 3)
    };
  }

  function normalizeDashboard(raw, index) {
    const dash = {
      id: String(raw.id || `dash-${index + 1}`),
      name: String(raw.name || `Dashboard ${index + 1}`),
      widgets: []
    };
    const widgets = Array.isArray(raw.widgets) ? raw.widgets : [];
    dash.widgets = widgets.map(normalizeWidget).filter(w => w.templateId && templates.some(t => t.id === w.templateId));
    return dash;
  }

  function deriveGroupMembers(rawGroup, dashboards) {
    if (Array.isArray(rawGroup.members)) {
      return rawGroup.members
        .map(m => ({ dashboardId: String(m.dashboardId || ''), widgetId: String(m.widgetId || '') }))
        .filter(m => m.dashboardId && m.widgetId);
    }

    const widgetIds = Array.isArray(rawGroup.widgetIds) ? rawGroup.widgetIds.map(String) : [];
    const templateIds = Array.isArray(rawGroup.templateIds) ? rawGroup.templateIds.map(String) : [];
    const members = [];

    dashboards.forEach(dash => {
      dash.widgets.forEach(widget => {
        if (widgetIds.includes(widget.id) || templateIds.includes(widget.templateId)) {
          members.push({ dashboardId: dash.id, widgetId: widget.id });
        }
      });
    });
    return members;
  }

  function normalizeGroup(rawGroup, dashboards, index) {
    const group = {
      id: String(rawGroup.id || `grp-${index + 1}`),
      baseName: String(rawGroup.baseName || rawGroup.name || 'Group').trim() || 'Group',
      members: deriveGroupMembers(rawGroup, dashboards)
    };
    return group;
  }

  function normalizeState(raw) {
    if (!raw || typeof raw !== 'object') return defaultState();
    const rawDashboards = Array.isArray(raw.dashboards) ? raw.dashboards : Array.isArray(raw.items) ? raw.items : [];
    const dashboards = rawDashboards.length ? rawDashboards.map(normalizeDashboard) : defaultState().dashboards;
    const rawGroups = Array.isArray(raw.groups) ? raw.groups : Array.isArray(raw.groupSets) ? raw.groupSets : [];
    const groups = rawGroups.map((group, index) => normalizeGroup(group, dashboards, index));
    const activeDashboardId = dashboards.some(d => d.id === raw.activeDashboardId) ? raw.activeDashboardId :
      dashboards.some(d => d.id === raw.activeId) ? raw.activeId : dashboards[0].id;
    return { activeDashboardId, dashboards, groups };
  }

  function loadState() {
    for (const key of LEGACY_KEYS) {
      try {
        const raw = localStorage.getItem(key);
        if (!raw) continue;
        return normalizeState(JSON.parse(raw));
      } catch {}
    }
    return defaultState();
  }

  let state = loadState();

  function recalcSerials() {
    const dashNums = state.dashboards.map(d => Number(String(d.id).split('-')[1])).filter(Number.isFinite);
    runtime.dashboardSerial = Math.max(3, ...dashNums.map(n => n + 1));
    runtime.widgetSerial = state.dashboards.reduce((count, dash) => count + dash.widgets.length, 1);
  }

  recalcSerials();

  function saveState() {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
  }

  function getDashboard(dashboardId = state.activeDashboardId) {
    return state.dashboards.find(d => d.id === dashboardId) || state.dashboards[0];
  }

  function getGrid(dashboardId = state.activeDashboardId) {
    return runtime.grids.get(dashboardId) || null;
  }

  function getSelectedGroup() {
    return state.groups.find(g => g.id === runtime.selectedGroupId) || null;
  }

  function presetForTemplate(template) {
    const base = layoutPresets[template?.type] || { w: 4, h: 3, minW: 3, minH: 2 };
    return {
      w: template?.w || base.w,
      h: template?.h || base.h,
      minW: template?.minW || base.minW,
      minH: template?.minH || base.minH
    };
  }

  function activeBoardCanvas() {
    return boardsHost.querySelector('.board-canvas.active');
  }

  function syncModalBodyLock() {
    const tpModal = document.getElementById('templatePreviewModal');
    const locked = (maxModal && maxModal.classList.contains('open')) || (guideModal && guideModal.classList.contains('open')) || (tpModal && tpModal.style.display === 'flex');
    document.body.classList.toggle('modal-open', !!locked);
  }

  function showView(view) {
    if (maxModal.classList.contains('open')) {
      maxModal.classList.remove('open');
      syncModalBodyLock();
    }
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const target = document.getElementById('view-' + view);
    if (target) target.classList.add('active');
    document.querySelectorAll('.nav-btn[data-view]').forEach(btn => btn.classList.toggle('active', btn.dataset.view === view));
    if (view === 'dashboard') activateDashboard(state.activeDashboardId);
  }

  async function loadMockTickets() {
    try {
      if (location.protocol === 'file:') throw new Error('file');
      const response = await fetch('/reporting/data?ts=' + Date.now(), { cache: 'no-store' });
      if (!response.ok) throw new Error('fetch');
      const data = await response.json();
      fakeTickets = Array.isArray(data) ? data : [];
      syncStatusText.textContent = 'JIRA MSP · ' + fakeTickets.length + ' tickets';
      return;
    } catch {
      fakeTickets = buildFallbackTickets(500);
      syncStatusText.textContent = 'Fallback dataset · ' + fakeTickets.length + ' tickets';
    }
  }

  function buildFallbackTickets(count = 120) {
    const out = [];
    for (let i = 0; i < count; i++) {
      out.push({
        id: 700000 + i,
        summary: 'Fallback ticket #' + (i + 1),
        company: { name: 'Fallback Co' },
        contact: { name: 'Fallback', email: 'fallback@example.com' },
        board: { name: 'Service Desk' },
        status: { name: 'In Progress' },
        team: { name: 'Pod A' },
        owner: { name: 'J. Carter' },
        priority: { name: 'P2', level: 'Medium' },
        type: { name: 'Incident' },
        subType: { name: 'General' },
        item: { name: 'Ticket' },
        dateEntered: '2026-04-13T08:00:00Z',
        lastUpdated: '2026-04-13T10:00:00Z',
        closedDate: null,
        closedFlag: false,
        slaStatus: 'Watching'
      });
    }
    return out;
  }

  function todayStr() {
    return new Date().toISOString().split('T')[0];
  }

  function endpointResponse(endpoint) {
    const openTickets = fakeTickets.filter(ticket => !ticket.closedFlag);
    const by = (path, src = openTickets) => {
      const map = new Map();
      src.forEach(ticket => {
        const value = path.split('.').reduce((acc, key) => (acc && acc[key] !== undefined ? acc[key] : undefined), ticket) || 'Unspecified';
        map.set(value, (map.get(value) || 0) + 1);
      });
      return [...map.entries()].map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value);
    };

    switch (endpoint) {
      case '/analytics/tickets/open-now':
        return { endpoint, metric: openTickets.length, label: 'Open tickets' };
      case '/analytics/tickets/opened-today':
        return { endpoint, metric: fakeTickets.filter(t => String(t.dateEntered).startsWith(todayStr())).length, label: 'Opened today' };
      case '/analytics/tickets/closed-today':
        return { endpoint, metric: fakeTickets.filter(t => String(t.closedDate || '').startsWith(todayStr())).length, label: 'Closed today' };
      case '/analytics/tickets/by-engineer':
        return { endpoint, rows: by('owner.name').slice(0, 6), meta: { group: 'owner.name', label: 'Open tickets by engineer' } };
      case '/analytics/tickets/by-client':
        return { endpoint, rows: by('company.name').slice(0, 6), meta: { group: 'company.name', label: 'Open tickets by client' } };
      case '/analytics/tickets/by-team':
        return { endpoint, rows: by('team.name').slice(0, 6), meta: { group: 'team.name', label: 'Open tickets by team' } };
      case '/analytics/tickets/by-board':
        return { endpoint, rows: by('board.name').slice(0, 6), meta: { group: 'board.name', label: 'Open tickets by board' } };
      case '/analytics/tickets/by-priority':
        return { endpoint, rows: by('priority.level'), meta: { group: 'priority.level', label: 'Open tickets by priority' } };
      case '/analytics/tickets/stale-watchlist':
        return {
          endpoint,
          rows: [...openTickets]
            .sort((a, b) => String(a.lastUpdated).localeCompare(String(b.lastUpdated)))
            .slice(0, 6)
            .map(ticket => ({
              id: ticket.id,
              summary: ticket.summary,
              client: ticket.company.name,
              owner: ticket.owner.name,
              priority: ticket.priority.name,
              sla: ticket.slaStatus
            }))
        };
      default:
        return {
          endpoint: '/service/tickets',
          rows: fakeTickets.slice(0, 10).map(ticket => ({
            id: ticket.id,
            summary: ticket.summary,
            client: ticket.company.name,
            owner: ticket.owner.name,
            board: ticket.board.name,
            status: ticket.status.name,
            priority: ticket.priority.name
          }))
        };
    }
  }

  function renderLegendRail(rows, title) {
    const swatches = ['sw-blue', 'sw-green', 'sw-amber', 'sw-red', 'sw-purple'];
    return `<div class="viz-legend"><div class="legend-head">${esc(title || 'legend')}</div>${(rows || []).slice(0, 5).map((row, index) => `<div class="legend-pill"><span class="legend-key"><span class="legend-swatch ${swatches[index % swatches.length]}"></span>${esc(row.label)}</span> <span class="legend-value">${row.value}</span></div>`).join('')}</div>`;
  }

  function renderDonutHoverLegend(rows) {
    const swatches = ['sw-blue', 'sw-green', 'sw-amber', 'sw-red', 'sw-purple'];
    return `<div class="donut-hover-legend">${(rows || []).slice(0, 5).map((row, index) => `<div class="legend-pill"><span class="legend-key"><span class="legend-swatch ${swatches[index % swatches.length]}"></span>${esc(row.label)}</span> <span class="legend-value">${row.value}</span></div>`).join('')}</div>`;
  }

  function renderContent(template) {
    const response = endpointResponse(template.endpoint);
    if (template.type === 'kpi') {
      return `<div class="kpi-wrap"><div class="kpi-big">${response.metric}</div><div class="kpi-small">${esc(response.label)}</div></div>`;
    }
    if (template.type === 'bar') {
      const rows = response.rows || [];
      const max = Math.max(...rows.map(row => row.value), 1);
      return `<div class="viz-split"><div class="viz-main"><div class="bar-wrap">${rows.map(row => `<div class="bar-row"><div class="bar-label">${esc(row.label)}</div><div class="track"><div class="fill" style="width:${Math.max(18, (row.value / max) * 100)}%">${row.value}</div></div><div class="bar-value">${row.value}</div></div>`).join('')}</div></div>${renderLegendRail(rows, 'series')}</div>`;
    }
    if (template.type === 'donut') {
      const rows = response.rows || [];
      const total = rows.reduce((sum, row) => sum + row.value, 0);
      return `<div class="donut-wrap"><div class="donut"></div><div class="donut-center"><div class="big">${total}</div><div class="small">${esc(response.meta?.group || template.groupField || 'mix')}</div></div>${renderDonutHoverLegend(rows)}</div>`;
    }
    if (template.type === 'list') {
      const rows = response.rows || [];
      return `<div class="list">${rows.map(row => `<div class="list-row"><div class="list-main">#${row.id} — ${esc(row.summary)}</div><div class="list-meta"><span>${esc(row.client)}</span><span>${esc(row.owner)}</span><span>${esc(row.priority)}</span><span>${esc(row.sla)}</span></div></div>`).join('')}</div>`;
    }
    const rows = response.rows || [];
    return `<div class="table-wrap"><div class="table-topnote">Wider by default so columns fit sideways before scrolling.</div><table><thead><tr><th>Ticket</th><th>Client</th><th>Owner</th><th>Board</th><th>Status</th><th>Priority</th></tr></thead><tbody>${rows.map(row => `<tr><td>#${row.id}</td><td>${esc(row.client)}</td><td>${esc(row.owner)}</td><td>${esc(row.board)}</td><td>${esc(row.status)}</td><td>${esc(row.priority)}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function tileHeaderExtras(template, widgetId, dashboardMode) {
    const badge = dashboardMode ? '' : `<div class="type-badge">${esc(template.type)}</div>`;
    return `
      <div>
        <div class="block-kicker">endpoint block</div>
        <div class="block-title">${esc(template.title)}</div>
        <div class="block-sub">${esc(template.description)}</div>
      </div>
      <div class="block-actions">
        ${dashboardMode ? `<button class="group-check" type="button" data-action="group-toggle" data-widget-id="${esc(widgetId)}"></button>` : ''}
        ${dashboardMode ? `<button class="refresh-btn" type="button" data-action="refresh" data-widget-id="${esc(widgetId)}" title="Refresh">↻</button>` : ''}
        ${dashboardMode ? `<button class="max-btn" type="button" data-action="maximize" data-widget-id="${esc(widgetId)}" title="Maximize">□</button>` : ''}
        ${dashboardMode ? `<button class="close-btn" type="button" data-action="close" data-widget-id="${esc(widgetId)}" title="Remove">✕</button>` : ''}
        ${badge}
      </div>`;
  }

  function blockHTML(template, widgetId, dashboardMode = true) {
    const response = endpointResponse(template.endpoint);
    return `<div class="grid-stack-item-content">
      <div class="block-head">
        ${tileHeaderExtras(template, widgetId, dashboardMode)}
      </div>
      <div class="block-body">
        <div class="block-inner">
          ${renderContent(template)}
          <button class="accordion-toggle legend-toggle" type="button" aria-expanded="false"><span>Legend</span><span class="arrow">▾</span></button>
          <div class="inline-drawer hidden"><div style="display:flex;gap:8px;flex-wrap:wrap">${(template.legend || []).map(item => `<div class="legend-pill">${esc(item)}</div>`).join('')}</div></div>
          <button class="accordion-toggle response-toggle" type="button" aria-expanded="false"><span>Response</span><span class="arrow">▾</span></button>
          <div class="inline-drawer response hidden"><pre>${esc(JSON.stringify(response, null, 2))}</pre></div>
        </div>
      </div>
    </div>`;
  }

  function createWidgetElement(widget) {
    const template = templates.find(t => t.id === widget.templateId);
    if (!template) return null;
    const element = document.createElement('div');
    element.className = 'grid-stack-item';
    element.dataset.widgetId = widget.id;
    element.dataset.templateId = template.id;
    element.dataset.type = template.type;
    element.innerHTML = blockHTML(template, widget.id, true);
    return element;
  }

  function ensureBoardRuntime(dashboardId) {
    if (runtime.grids.has(dashboardId)) return;
    const canvas = document.createElement('div');
    canvas.className = 'board-canvas';
    canvas.dataset.dashboardId = dashboardId;
    canvas.style.display = 'none';
    canvas.innerHTML = `<div class="grid-stack" data-dashboard-id="${esc(dashboardId)}"></div>`;
    boardsHost.appendChild(canvas);

    const gridEl = canvas.querySelector('.grid-stack');
    const grid = GridStack.init({
      column: GRID_COLUMNS,
      cellHeight: GRID_CELL_HEIGHT,
      margin: 14,
      float: false,
      acceptWidgets: false,
      removable: false
    }, gridEl);

    grid.on('added removed change', () => {
      if (runtime.syncingDashboards.has(dashboardId)) return;
      syncDashboardFromGrid(dashboardId);
    });

    runtime.grids.set(dashboardId, grid);
  }

  function withDashboardSync(dashboardId, fn) {
    runtime.syncingDashboards.add(dashboardId);
    try {
      fn();
    } finally {
      runtime.syncingDashboards.delete(dashboardId);
    }
  }

  function syncDashboardFromGrid(dashboardId) {
    const dashboard = getDashboard(dashboardId);
    const grid = getGrid(dashboardId);
    if (!dashboard || !grid) return;

    const snapshot = (grid.save(false) || []).map(node => ({
      id: node.el?.dataset?.widgetId || '',
      templateId: node.el?.dataset?.templateId || '',
      x: node.x,
      y: node.y,
      w: node.w,
      h: node.h
    })).filter(widget => widget.id && widget.templateId);

    dashboard.widgets = snapshot;
    saveState();
    renderDashboardTabs();
    updateEmptyState();
    refreshGroupSelectionUI();
  }

  function renderDashboardWidgets(dashboardId) {
    const dashboard = getDashboard(dashboardId);
    const grid = getGrid(dashboardId);
    const canvas = boardsHost.querySelector(`.board-canvas[data-dashboard-id="${dashboardId}"]`);
    if (!dashboard || !grid || !canvas) return;
    const gridEl = canvas.querySelector('.grid-stack');

    withDashboardSync(dashboardId, () => {
      grid.removeAll(true);
      dashboard.widgets.forEach(widget => {
        const element = createWidgetElement(widget);
        const template = templates.find(t => t.id === widget.templateId);
        const preset = presetForTemplate(template);
        if (!element) return;
        gridEl.appendChild(element);
        grid.makeWidget(element, {
          x: widget.x,
          y: widget.y,
          w: Math.max(widget.w, preset.minW),
          h: Math.max(widget.h, preset.minH),
          minW: preset.minW,
          minH: preset.minH
        });
      });
    });
  }

  function bootBoards() {
    boardsHost.innerHTML = '';
    runtime.grids.clear();
    state.dashboards.forEach(dashboard => {
      ensureBoardRuntime(dashboard.id);
      renderDashboardWidgets(dashboard.id);
    });
    activateDashboard(state.activeDashboardId);
    refreshGroupSelectionUI();
  }

  function activateDashboard(dashboardId) {
    state.activeDashboardId = dashboardId;
    state.dashboards.forEach(dashboard => {
      ensureBoardRuntime(dashboard.id);
      const canvas = boardsHost.querySelector(`.board-canvas[data-dashboard-id="${dashboard.id}"]`);
      if (!canvas) return;
      const active = dashboard.id === dashboardId;
      canvas.classList.toggle('active', active);
      canvas.style.display = active ? 'block' : 'none';
    });
    renderDashboardTabs();
    saveState();
    updateEmptyState();
    refreshGroupSelectionUI();
  }

  function updateEmptyState() {
    return;
  }

  function renderDashboardTabs() {
    const host = document.getElementById('dashboardTabs');
    host.innerHTML = state.dashboards.map(dashboard => `<button class="dashboard-tab ${dashboard.id === state.activeDashboardId ? 'active' : ''}" type="button" data-dash="${esc(dashboard.id)}">${esc(dashboard.name)}<span class="count">${dashboard.widgets.length}</span></button>`).join('');
  }

  function groupShortTitles(group) {
    return (group.members || []).map(member => {
      const dashboard = getDashboard(member.dashboardId);
      const widget = dashboard?.widgets?.find(item => item.id === member.widgetId);
      const template = widget ? templates.find(t => t.id === widget.templateId) : null;
      return template ? shortName(template.title) : '';
    }).filter(Boolean).slice(0, 3);
  }

  function groupLabel(group) {
    const base = String(group.baseName || 'Group').trim() || 'Group';
    const suffix = groupShortTitles(group).join(' + ');
    return suffix ? `${base} · ${suffix}` : base;
  }

  function renderGroupSelect() {
    const select = document.getElementById('groupSelect');
    const options = ['<option value="">No group selected</option>']
      .concat(state.groups.map(group => `<option value="${esc(group.id)}">${esc(groupLabel(group))}</option>`));
    select.innerHTML = options.join('');
    if (runtime.selectedGroupId && state.groups.some(group => group.id === runtime.selectedGroupId)) {
      select.value = runtime.selectedGroupId;
    } else {
      runtime.selectedGroupId = '';
      select.value = '';
    }
  }

  function toggleGroupMode(force) {
    runtime.groupMode = typeof force === 'boolean' ? force : !runtime.groupMode;
    document.body.classList.toggle('group-mode-on', runtime.groupMode);
    document.getElementById('toggleGroupModeBtn').textContent = 'Group mode: ' + (runtime.groupMode ? 'On' : 'Off');
    refreshGroupSelectionUI();
  }

  function refreshGroupSelectionUI() {
    const selectedGroup = getSelectedGroup();
    document.querySelectorAll('.group-check').forEach(button => {
      const item = button.closest('.grid-stack-item');
      const canvas = button.closest('.board-canvas');
      const widgetId = item?.dataset.widgetId || '';
      const dashboardId = canvas?.dataset.dashboardId || '';
      const checked = !!selectedGroup && (selectedGroup.members || []).some(member => member.dashboardId === dashboardId && member.widgetId === widgetId);
      button.classList.toggle('checked', checked);
      button.textContent = checked ? '✓' : '';
      button.title = runtime.groupMode ? (checked ? 'Remove from selected group' : 'Add to selected group') : 'Group mode is off';
    });
  }

  function pulseCard(cardOrItem) {
    const card = cardOrItem?.classList?.contains('grid-stack-item-content') ? cardOrItem : cardOrItem?.querySelector?.('.grid-stack-item-content');
    if (!card) return;

    const restart = () => {
      card.classList.remove('syncing');
      void card.offsetWidth;
      card.classList.add('syncing');
      setTimeout(() => card.classList.remove('syncing'), 900);
    };

    requestAnimationFrame(() => requestAnimationFrame(restart));
  }

  function findWidget(dashboardId, widgetId) {
    const dashboard = getDashboard(dashboardId);
    if (!dashboard) return null;
    const widget = dashboard.widgets.find(item => item.id === widgetId);
    if (!widget) return null;
    const template = templates.find(t => t.id === widget.templateId);
    if (!template) return null;
    return { dashboard, widget, template };
  }

  function addTemplateToDashboard(templateId, dashboardId = state.activeDashboardId, switchToDashboard = false) {
    const dashboard = getDashboard(dashboardId);
    const template = templates.find(t => t.id === templateId);
    const grid = getGrid(dashboardId);
    const canvas = boardsHost.querySelector(`.board-canvas[data-dashboard-id="${dashboardId}"]`);
    if (!dashboard || !template || !grid || !canvas) return;

    const preset = presetForTemplate(template);
    const widget = {
      id: nextWidgetId(),
      templateId: template.id,
      x: 0,
      y: 0,
      w: preset.w,
      h: preset.h
    };

    const element = createWidgetElement(widget);
    const gridEl = canvas.querySelector('.grid-stack');
    if (!element || !gridEl) return;

    withDashboardSync(dashboardId, () => {
      gridEl.appendChild(element);
      grid.makeWidget(element, {
        w: preset.w,
        h: preset.h,
        minW: preset.minW,
        minH: preset.minH
      });
    });

    dashboard.widgets.push({
      id: widget.id,
      templateId: template.id,
      x: element.gridstackNode?.x ?? 0,
      y: element.gridstackNode?.y ?? 0,
      w: element.gridstackNode?.w ?? preset.w,
      h: element.gridstackNode?.h ?? preset.h
    });

    saveState();
    renderDashboardTabs();
    if (switchToDashboard) showView('dashboard');
    if (dashboardId !== state.activeDashboardId) activateDashboard(dashboardId);
    updateEmptyState();
    refreshGroupSelectionUI();
    pulseCard(element);
  }

  function rerenderWidget(dashboardId, widgetId) {
    const resolved = findWidget(dashboardId, widgetId);
    if (!resolved) return;
    const canvas = boardsHost.querySelector(`.board-canvas[data-dashboard-id="${dashboardId}"]`);
    const item = canvas?.querySelector(`.grid-stack-item[data-widget-id="${widgetId}"]`);
    if (!item) return;
    item.innerHTML = blockHTML(resolved.template, widgetId, true);
    refreshGroupSelectionUI();
    requestAnimationFrame(() => {
      const freshItem = canvas?.querySelector(`.grid-stack-item[data-widget-id="${widgetId}"]`);
      if (freshItem) pulseCard(freshItem);
    });
  }

  function removeWidget(dashboardId, widgetId) {
    const dashboard = getDashboard(dashboardId);
    const grid = getGrid(dashboardId);
    const canvas = boardsHost.querySelector(`.board-canvas[data-dashboard-id="${dashboardId}"]`);
    const item = canvas?.querySelector(`.grid-stack-item[data-widget-id="${widgetId}"]`);
    if (!dashboard || !grid || !item) return;

    withDashboardSync(dashboardId, () => grid.removeWidget(item, true, true));
    dashboard.widgets = dashboard.widgets.filter(widget => widget.id !== widgetId);
    state.groups.forEach(group => {
      group.members = (group.members || []).filter(member => !(member.dashboardId === dashboardId && member.widgetId === widgetId));
    });
    saveState();
    renderDashboardTabs();
    renderGroupSelect();
    updateEmptyState();
    refreshGroupSelectionUI();
  }

  function maxCardClassForType(type) {
    if (type === 'kpi') return 'w4';
    if (type === 'donut') return 'w5';
    if (type === 'bar') return 'w6';
    if (type === 'list') return 'w6';
    return 'full';
  }

  function openMaximizedWidget(dashboardId, widgetId) {
    const resolved = findWidget(dashboardId, widgetId);
    if (!resolved) return;
    maxModalTitle.textContent = resolved.template.title;
    maxModalSub.textContent = resolved.dashboard.name;
    maxGrid.innerHTML = `<div class="max-card full">${blockHTML(resolved.template, widgetId, false)}</div>`;
    maxModal.classList.add('open');
    syncModalBodyLock();
  }

  function openGroup(group) {
    const cards = (group.members || []).map(member => findWidget(member.dashboardId, member.widgetId)).filter(Boolean);
    if (!cards.length) return;
    maxModalTitle.textContent = groupLabel(group);
    maxModalSub.textContent = 'Grouped maximized stats across dashboards';
    maxGrid.innerHTML = cards.map(card => `<div class="max-card ${cards.length === 1 ? 'full' : maxCardClassForType(card.template.type)}"><div style="padding:10px 14px;border-bottom:1px solid var(--line);font-size:11px;color:var(--muted);text-transform:uppercase;letter-spacing:.12em;">${esc(card.dashboard.name)}</div>${blockHTML(card.template, card.widget.id, false)}</div>`).join('');
    maxModal.classList.add('open');
    syncModalBodyLock();
  }

  function toggleWidgetInSelectedGroup(dashboardId, widgetId) {
    const group = getSelectedGroup();
    if (!runtime.groupMode || !group) return;
    const index = group.members.findIndex(member => member.dashboardId === dashboardId && member.widgetId === widgetId);
    if (index >= 0) group.members.splice(index, 1);
    else group.members.push({ dashboardId, widgetId });
    saveState();
    renderGroupSelect();
    refreshGroupSelectionUI();
  }

  function renderPreview() {
    const template = templates.find(t => t.id === selectedTemplateId) || templates[0];
    if (!template) return;
    const preset = presetForTemplate(template);
    previewTitle.textContent = template.title;
    previewSub.textContent = `${template.description || ''} · ${template.endpoint} · ${preset.w}×${preset.h}`;
    const widthPct = Math.min(100, (preset.w / GRID_COLUMNS) * 100 + 8);
    previewHolder.innerHTML = `<div class="preview-block" style="width:${widthPct}%; min-width:280px;">${blockHTML(template, 'preview', false)}</div>`;
    syncTemplateActionButtons(template);
  }

  function showTemplateModal(templateId) {
    var modal = document.getElementById('templatePreviewModal');
    var title = document.getElementById('tpModalTitle');
    var body = document.getElementById('tpModalBody');
    if (!modal || !title || !body) return;
    var template = templates.find(function(t) { return t.id === templateId; });
    if (!template) return;
    var preset = presetForTemplate(template);
    title.textContent = template.title;
    var widthPct = Math.min(100, (preset.w / GRID_COLUMNS) * 100 + 8);
    body.innerHTML = '<div class="preview-block" style="width:' + widthPct + '%; min-width:280px;">' + blockHTML(template, 'preview', false) + '</div>';
    modal.style.display = 'flex';
  }

  function templateLegendTags(template) {
    const tags = [];
    (template.prereqs || []).slice(0, 4).forEach(key => {
      const found = prereqs.find(item => item.key === key);
      tags.push(found ? found.label : key);
    });
    if (!tags.length) {
      tags.push(template.endpoint);
    }
    return tags;
  }

  function renderTemplateList() {
    templateList.innerHTML = templates.map(template => {
      const preset = presetForTemplate(template);
      const customBadge = template.custom ? '<div class="legend-pill">custom</div>' : '';
      return `<div class="template-card ${template.id === selectedTemplateId ? 'selected' : ''}">
        <div class="template-top">
          <div>
            <div class="template-kicker">${esc(template.endpoint)}</div>
            <div class="template-title">${esc(template.title)}</div>
          </div>
          <div class="type-badge">${esc(template.type)}</div>
        </div>
        <div class="template-copy">${esc(template.description || '')}</div>
        <div class="template-tags">${templateLegendTags(template).map(tag => `<span>${esc(tag)}</span>`).join('')}${customBadge}</div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <div class="legend-pill">${preset.w}×${preset.h}</div>
          <div class="legend-pill">min ${preset.minW}w</div>
          <div class="legend-pill">${esc(template.primaryField || 'no primary')}</div>
        </div>
        <div class="template-actions">
          <button class="btn" type="button" data-preview="${esc(template.id)}">Show Preview</button>
          <button class="btn" type="button" data-edit-template="${esc(template.id)}">Edit</button>
          <button class="btn" type="button" data-duplicate-template="${esc(template.id)}">Duplicate</button>
          ${template.custom ? `<button class="btn" type="button" data-delete-template="${esc(template.id)}">Delete</button>` : ''}
          <button class="btn" type="button" data-add="${esc(template.id)}">Add</button>
          <button class="btn primary" type="button" data-add-view="${esc(template.id)}">Add to dashboard</button>
        </div>
      </div>`;
    }).join('');
  }

  function syncTemplateActionButtons(template = templates.find(t => t.id === selectedTemplateId) || null) {
    const duplicateBtn = document.getElementById('duplicateTemplateBtn');
    const deleteBtn = document.getElementById('deleteTemplateBtn');
    if (duplicateBtn) duplicateBtn.disabled = !template;
    if (deleteBtn) {
      const canDelete = !!template?.custom;
      deleteBtn.disabled = !canDelete;
      deleteBtn.style.display = template ? '' : 'none';
      deleteBtn.textContent = canDelete ? 'Delete custom' : 'Built-in template';
    }
  }

  function syncBuilderActionButtons() {
    const deleteBtn = document.getElementById('builderDeleteBtn');
    const duplicateBtn = document.getElementById('builderDuplicateBtn');
    if (duplicateBtn) duplicateBtn.disabled = false;
    if (deleteBtn) {
      const editingCustom = !!(runtime.builderEditingId && templates.some(item => item.id === runtime.builderEditingId && item.custom));
      deleteBtn.disabled = !editingCustom;
      deleteBtn.textContent = editingCustom ? 'Delete custom' : 'Delete custom';
    }
  }

  function nextCopyTitle(title) {
    const original = String(title || 'Custom Template').trim() || 'Custom Template';
    const base = original.replace(/ Copy(?: \d+)?$/i, '').trim() || 'Custom Template';
    const existing = new Set(templates.map(item => String(item.title || '').trim()));
    let candidate = `${base} Copy`;
    let i = 2;
    while (existing.has(candidate)) {
      candidate = `${base} Copy ${i++}`;
    }
    return candidate;
  }

  function duplicateTemplate(templateId, openInBuilder = true) {
    const source = templates.find(item => item.id === templateId);
    if (!source) return null;
    const duplicate = normalizeTemplate({
      ...source,
      id: createTemplateId(),
      title: nextCopyTitle(source.title),
      custom: true,
      legend: [...(source.legend || [])],
      prereqs: [...(source.prereqs || [])],
      roles: { ...(source.roles || {}) }
    }, 0);
    templates = [duplicate, ...templates.filter(item => item.id !== duplicate.id)];
    selectedTemplateId = duplicate.id;
    runtime.builderEditingId = duplicate.id;
    saveTemplates();
    renderTemplateList();
    if (openInBuilder) {
      resetBuilder(duplicate);
      showView('builder');
    }
    return duplicate;
  }

  function deleteCustomTemplate(templateId, skipConfirm = false) {
    const template = templates.find(item => item.id === templateId);
    if (!template?.custom) return false;
    if (!skipConfirm && !confirm(`Delete custom template "${template.title}"? Any widgets using it will be removed from every dashboard.`)) {
      return false;
    }

    state.dashboards.forEach(dashboard => {
      const removedIds = (dashboard.widgets || []).filter(widget => widget.templateId === templateId).map(widget => widget.id);
      if (!removedIds.length) return;
      const grid = getGrid(dashboard.id);
      const canvas = boardsHost.querySelector(`.board-canvas[data-dashboard-id="${dashboard.id}"]`);
      if (grid && canvas) {
        withDashboardSync(dashboard.id, () => {
          removedIds.forEach(widgetId => {
            const item = canvas.querySelector(`.grid-stack-item[data-widget-id="${widgetId}"]`);
            if (item) grid.removeWidget(item, true, true);
          });
        });
      }
      dashboard.widgets = dashboard.widgets.filter(widget => widget.templateId !== templateId);
      state.groups.forEach(group => {
        group.members = (group.members || []).filter(member => !(member.dashboardId === dashboard.id && removedIds.includes(member.widgetId)));
      });
    });

    templates = templates.filter(item => item.id !== templateId);
    if (!templates.length) templates = loadTemplates();
    if (selectedTemplateId === templateId) {
      selectedTemplateId = templates[0]?.id || BASE_TEMPLATES[0].id;
    }
    if (runtime.builderEditingId === templateId) {
      runtime.builderEditingId = '';
      resetBuilder();
    }
    saveTemplates();
    saveState();
    renderDashboardTabs();
    renderGroupSelect();
    renderTemplateList();
    renderBuilderPreview();
    updateEmptyState();
    refreshGroupSelectionUI();
    return true;
  }

  function renderSchema() {
    if (!schemaList) return;
    schemaList.innerHTML = trimmedSchema.map(field => `
      <div class="schema-card">
        <div><span class="schema-path">${esc(field.path)}</span><span class="schema-type">${esc(field.type)}</span></div>
        <div class="schema-desc">${esc(field.desc)}</div>
      </div>
    `).join('');
  }

  function populateBuilderFields() {
    const opts = ['<option value="">None</option>']
      .concat(trimmedSchema.map(field => `<option value="${esc(field.path)}">${esc(field.path)}</option>`))
      .join('');
    const primary = document.getElementById('builderPrimary');
    const group = document.getElementById('builderGroup');
    const endpoint = document.getElementById('builderEndpoint');
    if (!primary || !group || !endpoint) return;
    primary.innerHTML = opts;
    group.innerHTML = opts;
    endpoint.innerHTML = endpointCatalog.map(item => `<option value="${esc(item.endpoint)}">${esc(item.label)} · ${esc(item.endpoint)}</option>`).join('');
  }

  function renderPrereqs() {
    const chips = document.getElementById('prereqChips');
    if (!chips) return;
    chips.innerHTML = prereqs.map(item => `<button class="chip-btn ${builderState.prereqs.has(item.key) ? 'active' : ''}" type="button" data-prereq="${esc(item.key)}">${esc(item.label)}</button>`).join('');
  }

  function renderRoleFields() {
    const primary = document.getElementById('builderPrimary')?.value || '';
    const group = document.getElementById('builderGroup')?.value || '';
    const wrap = document.getElementById('roleFields');
    if (!wrap) return;
    wrap.innerHTML = trimmedSchema
      .filter(field => field.path !== primary && field.path !== group)
      .slice(0, 12)
      .map(field => `
        <div class="field-line">
          <div>
            <div class="field-name">${esc(field.path)}</div>
            <div class="field-meta">${esc(field.desc)}</div>
          </div>
          <select class="select-mini" data-role-field="${esc(field.path)}">
            ${['ignore', 'label', 'dimension', 'filter', 'status', 'time', 'breakdown'].map(role => `<option value="${role}" ${(builderState.roles[field.path] || 'ignore') === role ? 'selected' : ''}>${role}</option>`).join('')}
          </select>
        </div>
      `).join('');
  }

  function autoLegend(template) {
    const legend = [];
    if (template.primaryField) legend.push(`Primary field · ${template.primaryField}`);
    if (template.groupField) legend.push(`Group by · ${template.groupField}`);
    (template.prereqs || []).slice(0, 3).forEach(key => {
      const found = prereqs.find(item => item.key === key);
      legend.push(found ? found.label : key);
    });
    if (!legend.length) legend.push('Custom template');
    return legend;
  }

  function currentBuilderTemplate() {
    const type = document.getElementById('builderRenderer')?.value || 'kpi';
    const preset = layoutPresets[type] || { w: 4, h: 3, minW: 3, minH: 2 };
    return normalizeTemplate({
      id: runtime.builderEditingId || createTemplateId(),
      title: document.getElementById('builderTitle')?.value || 'Custom Ticket Block',
      description: document.getElementById('builderDescription')?.value || '',
      endpoint: document.getElementById('builderEndpoint')?.value || '/service/tickets',
      type,
      primaryField: document.getElementById('builderPrimary')?.value || '',
      groupField: document.getElementById('builderGroup')?.value || '',
      prereqs: [...builderState.prereqs],
      roles: { ...builderState.roles },
      legend: [],
      custom: true,
      w: Number(document.getElementById('builderW')?.value || preset.w),
      h: Number(document.getElementById('builderH')?.value || preset.h),
      minW: preset.minW,
      minH: preset.minH
    }, 0);
  }

  function renderBuilderPreview() {
    if (!builderPreview) return;
    const template = currentBuilderTemplate();
    template.legend = autoLegend(template);
    builderPreview.innerHTML = `<div class="preview-block" style="width:100%; min-width:280px;">${blockHTML(template, 'builder-preview', false)}</div>`;
  }

  function resetBuilder(template = null) {
    runtime.builderEditingId = template?.custom ? template.id : '';
    document.getElementById('builderTitle').value = template?.title || 'Custom Ticket Block';
    document.getElementById('builderDescription').value = template?.description || 'Endpoint-driven custom block using the trimmed ticket payload.';
    document.getElementById('builderEndpoint').value = template?.endpoint || '/analytics/tickets/open-now';
    document.getElementById('builderRenderer').value = template?.type || 'kpi';
    document.getElementById('builderPrimary').value = template?.primaryField || 'id';
    document.getElementById('builderGroup').value = template?.groupField || '';
    document.getElementById('builderW').value = String(template?.w || 4);
    document.getElementById('builderH').value = String(template?.h || 3);
    builderState.prereqs = new Set(template?.prereqs || ['countTickets']);
    builderState.roles = { ...(template?.roles || {}) };
    renderPrereqs();
    renderRoleFields();
    renderBuilderPreview();
    syncBuilderActionButtons();
  }

  function openTemplateInBuilder(templateId) {
    const template = templates.find(item => item.id === templateId);
    if (!template) return;
    resetBuilder(template);
    showView('builder');
  }

  function inferBuilderFromPrereq(key) {
    const found = prereqs.find(item => item.key === key);
    if (!found?.infer) return;
    if (found.infer.primary) document.getElementById('builderPrimary').value = found.infer.primary;
    if (found.infer.group) document.getElementById('builderGroup').value = found.infer.group;
    if (found.infer.endpoint) document.getElementById('builderEndpoint').value = found.infer.endpoint;
    if (found.infer.renderer) document.getElementById('builderRenderer').value = found.infer.renderer;
  }

  function saveBuilderTemplate(saveAndAdd = false) {
    const template = currentBuilderTemplate();
    template.legend = autoLegend(template);

    if (runtime.builderEditingId && templates.some(item => item.id === runtime.builderEditingId && item.custom)) {
      const index = templates.findIndex(item => item.id === runtime.builderEditingId);
      if (index >= 0) templates[index] = template;
    } else {
      templates = [template, ...templates.filter(item => item.id !== template.id)];
      runtime.builderEditingId = template.id;
    }

    selectedTemplateId = template.id;
    saveTemplates();
    renderTemplateList();
    renderBuilderPreview();
    syncBuilderActionButtons();

    if (saveAndAdd) {
      hideGuideModal(true);
      addTemplateToDashboard(template.id, state.activeDashboardId, true);
      return;
    }

    showView('templates');
  }

  function hideGuideModal(persist = true) {
    if (!guideModal) return;
    guideModal.classList.remove('open');
    if (persist) {
      try { localStorage.setItem(GUIDE_KEY, '1'); } catch {}
    }
    syncModalBodyLock();
  }

  function showGuideModalIfNeeded(force = false) {
    if (!guideModal) return;
    let dismissed = false;
    try { dismissed = localStorage.getItem(GUIDE_KEY) === '1'; } catch {}
    guideModal.classList.toggle('open', !!(force || !dismissed));
    syncModalBodyLock();
  }

  function clearProtoStorage() {
    try {
      const keys = [];
      for (let i = 0; i < localStorage.length; i++) {
        const key = localStorage.key(i);
        if (key && (key.startsWith('cw-gridstack-proto-v') || key.startsWith('cw-gridstack-proto-split-v1'))) keys.push(key);
      }
      keys.forEach(key => localStorage.removeItem(key));
      localStorage.removeItem(TEMPLATES_KEY);
      localStorage.removeItem(BANNER_KEY);
      localStorage.removeItem(GUIDE_KEY);
    } catch {}
  }

  function hardReset() {
    clearProtoStorage();
    state = defaultState();
    templates = loadTemplates();
    runtime.selectedGroupId = '';
    runtime.builderEditingId = '';
    selectedTemplateId = templates[0]?.id || BASE_TEMPLATES[0].id;
    builderState = { prereqs: new Set(['countTickets']), roles: {} };
    recalcSerials();
    renderDashboardTabs();
    renderGroupSelect();
    renderTemplateList();
    renderSchema();
    populateBuilderFields();
    resetBuilder();
    bootBoards();
    toggleGroupMode(false);
    const banner = document.getElementById('persistenceBanner');
    if (banner) {
      banner.hidden = false;
      banner.style.display = '';
    }
    saveState();
    showGuideModalIfNeeded(true);
    syncStatusText.textContent = 'Storage cleared · defaults restored';
  }

  function renameSelectedGroup() {
    const group = getSelectedGroup();
    if (!group) return;
    const value = prompt('Group name', group.baseName || 'Group');
    if (value === null) return;
    group.baseName = value.trim() || 'Group';
    saveState();
    renderGroupSelect();
  }

  function handleGlobalClicks(event) {
    const drawerButton = event.target.closest('.legend-toggle, .response-toggle');
    if (drawerButton) {
      const drawer = drawerButton.nextElementSibling;
      if (!drawer) return;
      const willOpen = drawer.classList.contains('hidden');
      drawer.classList.toggle('hidden');
      drawerButton.classList.toggle('open', willOpen);
      drawerButton.setAttribute('aria-expanded', String(willOpen));
      return;
    }

    const boardAction = event.target.closest('[data-action]');
    if (boardAction) {
      const item = boardAction.closest('.grid-stack-item');
      const canvas = boardAction.closest('.board-canvas');
      const widgetId = boardAction.dataset.widgetId || item?.dataset.widgetId || '';
      const dashboardId = canvas?.dataset.dashboardId || state.activeDashboardId;
      switch (boardAction.dataset.action) {
        case 'maximize':
          openMaximizedWidget(dashboardId, widgetId);
          return;
        case 'refresh':
          rerenderWidget(dashboardId, widgetId);
          return;
        case 'close':
          removeWidget(dashboardId, widgetId);
          return;
        case 'group-toggle':
          toggleWidgetInSelectedGroup(dashboardId, widgetId);
          return;
        default:
          break;
      }
    }

    const gridItem = event.target.closest('.grid-stack-item');
    const boardCanvas = event.target.closest('.board-canvas');
    if (gridItem && boardCanvas && runtime.groupMode && getSelectedGroup()) {
      if (!event.target.closest('button,select,a,input,textarea')) {
        toggleWidgetInSelectedGroup(boardCanvas.dataset.dashboardId, gridItem.dataset.widgetId);
      }
    }
  }

  function initEvents() {
    bindIf('sidebarToggle', 'click', () => app.classList.toggle('collapsed'));
    document.querySelectorAll('.nav-btn[data-view]').forEach(button => button.addEventListener('click', () => showView(button.dataset.view)));

    bindIf('sidebarAddBtn', 'click', () => showView('templates'));
    bindIf('headerAddBlock', 'click', () => showView('templates'));
    bindIf('guideBrowseTemplatesBtn', 'click', () => {
      hideGuideModal(true);
      showView('templates');
    });
    bindIf('guideDismissBtn', 'click', () => hideGuideModal(true));

    bindIf('clearStorageBtn', 'click', hardReset);
    bindIf('bannerClearStorageBtn', 'click', hardReset);
    bindIf('bannerDismissBtn', 'click', () => {
      const banner = document.getElementById('persistenceBanner');
      if (banner) {
        banner.style.display = 'none';
        banner.hidden = true;
      }
      localStorage.setItem(BANNER_KEY, '1');
    });

    bindIf('newDashboardBtn', 'click', () => {
      const id = nextDashboardId();
      state.dashboards.push({ id, name: `Dashboard ${state.dashboards.length + 1}`, widgets: [] });
      ensureBoardRuntime(id);
      renderDashboardWidgets(id);
      activateDashboard(id);
      saveState();
    });

    bindIf('renameDashboardBtn', 'click', () => {
      const dashboard = getDashboard();
      const value = prompt('Dashboard name', dashboard.name);
      if (value === null) return;
      dashboard.name = value.trim() || dashboard.name;
      saveState();
      renderDashboardTabs();
    });

    bindIf('deleteDashboardBtn', 'click', () => {
      if (state.dashboards.length <= 1) return;
      const dashboard = getDashboard();
      state.groups.forEach(group => {
        group.members = (group.members || []).filter(member => member.dashboardId !== dashboard.id);
      });
      state.dashboards = state.dashboards.filter(item => item.id !== dashboard.id);
      const canvas = boardsHost.querySelector(`.board-canvas[data-dashboard-id="${dashboard.id}"]`);
      if (canvas) canvas.remove();
      runtime.grids.delete(dashboard.id);
      state.activeDashboardId = state.dashboards[0].id;
      saveState();
      renderDashboardTabs();
      renderGroupSelect();
      activateDashboard(state.activeDashboardId);
      updateEmptyState();
    });

    bindIf('newGroupBtn', 'click', () => {
      const name = prompt('Group name', 'Group');
      const group = {
        id: 'grp-' + Date.now().toString(36),
        baseName: (name || 'Group').trim() || 'Group',
        members: []
      };
      state.groups.push(group);
      runtime.selectedGroupId = group.id;
      renderGroupSelect();
      toggleGroupMode(true);
      saveState();
    });

    bindIf('renameGroupBtn', 'click', renameSelectedGroup);

    bindIf('groupSelect', 'change', event => {
      runtime.selectedGroupId = event.target.value || '';
      refreshGroupSelectionUI();
    });

    bindIf('toggleGroupModeBtn', 'click', () => toggleGroupMode());
    bindIf('openGroupBtn', 'click', () => {
      const group = getSelectedGroup();
      if (!group || !(group.members || []).length) return;
      openGroup(group);
    });

    bindIf('closeMaxModal', 'click', () => {
      maxModal.classList.remove('open');
      syncModalBodyLock();
    });

    maxModal.addEventListener('click', event => {
      if (event.target.id === 'maxModal') {
        maxModal.classList.remove('open');
        syncModalBodyLock();
      }
    });

    if (guideModal) {
      guideModal.addEventListener('click', event => {
        if (event.target.id === 'guideModal') hideGuideModal(true);
      });
    }

    var tpModal = document.getElementById('templatePreviewModal');
    if (tpModal) {
      tpModal.addEventListener('click', function(event) {
        if (event.target === tpModal) {
          tpModal.style.display = 'none';
          document.body.classList.remove('modal-open');
        }
      });
    }

    document.getElementById('dashboardTabs').addEventListener('click', event => {
      const button = event.target.closest('[data-dash]');
      if (!button) return;
      activateDashboard(button.dataset.dash);
    });

    templateList.addEventListener('click', event => {
      const previewId = event.target.dataset.preview;
      const editId = event.target.dataset.editTemplate;
      const duplicateId = event.target.dataset.duplicateTemplate;
      const deleteId = event.target.dataset.deleteTemplate;
      const addId = event.target.dataset.add;
      const addViewId = event.target.dataset.addView;
      if (previewId) {
        showTemplateModal(previewId);
        return;
      }
      if (editId) {
        openTemplateInBuilder(editId);
        return;
      }
      if (duplicateId) {
        duplicateTemplate(duplicateId, true);
        return;
      }
      if (deleteId) {
        deleteCustomTemplate(deleteId, false);
        return;
      }
      if (addId) {
        hideGuideModal(true);
        addTemplateToDashboard(addId, state.activeDashboardId, false);
        return;
      }
      if (addViewId) {
        hideGuideModal(true);
        addTemplateToDashboard(addViewId, state.activeDashboardId, true);
      }
    });

    bindIf('editTemplateBtn', 'click', () => openTemplateInBuilder(selectedTemplateId));
    bindIf('duplicateTemplateBtn', 'click', () => duplicateTemplate(selectedTemplateId, true));
    bindIf('deleteTemplateBtn', 'click', () => deleteCustomTemplate(selectedTemplateId, false));
    bindIf('addTemplateToBoardBtn', 'click', () => {
      hideGuideModal(true);
      addTemplateToDashboard(selectedTemplateId, state.activeDashboardId, true);
    });

    bindIf('builderResetBtn', 'click', () => resetBuilder());
    bindIf('builderDuplicateBtn', 'click', () => {
      const draft = currentBuilderTemplate();
      const duplicate = normalizeTemplate({
        ...draft,
        id: createTemplateId(),
        title: nextCopyTitle(draft.title),
        custom: true,
        legend: autoLegend(draft)
      }, 0);
      templates = [duplicate, ...templates.filter(item => item.id !== duplicate.id)];
      selectedTemplateId = duplicate.id;
      saveTemplates();
      resetBuilder(duplicate);
      renderTemplateList();
      showView('builder');
    });
    bindIf('builderDeleteBtn', 'click', () => {
      if (!runtime.builderEditingId) return;
      const deleted = deleteCustomTemplate(runtime.builderEditingId, false);
      if (deleted) {
        resetBuilder();
        showView('templates');
      }
    });
    bindIf('saveTemplateBtn', 'click', () => saveBuilderTemplate(false));
    bindIf('saveAndAddBtn', 'click', () => saveBuilderTemplate(true));

    bindIf('prereqChips', 'click', event => {
      const key = event.target?.dataset?.prereq;
      if (!key) return;
      if (builderState.prereqs.has(key)) builderState.prereqs.delete(key);
      else builderState.prereqs.add(key);
      inferBuilderFromPrereq(key);
      renderPrereqs();
      renderRoleFields();
      renderBuilderPreview();
    });

    ['builderTitle','builderDescription','builderEndpoint','builderRenderer','builderPrimary','builderGroup','builderW','builderH'].forEach(id => {
      bindIf(id, 'input', () => {
        renderRoleFields();
        renderBuilderPreview();
      });
      bindIf(id, 'change', () => {
        renderRoleFields();
        renderBuilderPreview();
      });
    });

    bindIf('roleFields', 'change', event => {
      const field = event.target?.dataset?.roleField;
      if (!field) return;
      builderState.roles[field] = event.target.value;
      renderBuilderPreview();
    });

    document.addEventListener('click', handleGlobalClicks);
  }

function applyDynamicDonuts(root = document) {
  const wraps = root.querySelectorAll('.donut-wrap');

  wraps.forEach(wrap => {
    const donut = wrap.querySelector('.donut');
    if (!donut) return;

    const pills = wrap.querySelectorAll('.donut-hover-legend .legend-pill');
    if (!pills.length) return;

    const slices = [];

    pills.forEach(pill => {
      const swatch = pill.querySelector('.legend-swatch');
      const valueEl = pill.querySelector('.legend-value');
      if (!swatch || !valueEl) return;

      const value = parseFloat(String(valueEl.textContent || '').replace(/[^\d.-]/g, ''));
      if (!Number.isFinite(value) || value <= 0) return;

      const color = getComputedStyle(swatch).backgroundColor;
      slices.push({ value, color });
    });

    const total = slices.reduce((sum, s) => sum + s.value, 0);
    if (!total) return;

    let acc = 0;
    const stops = slices.map(slice => {
      const start = (acc / total) * 100;
      acc += slice.value;
      const end = (acc / total) * 100;
      return `${slice.color} ${start}% ${end}%`;
    });

    donut.style.background = `conic-gradient(${stops.join(', ')})`;
  });
}

function installDynamicDonuts() {
  let queued = false;

  const refresh = () => {
    if (queued) return;
    queued = true;
    requestAnimationFrame(() => {
      queued = false;
      applyDynamicDonuts(document);
    });
  };

  refresh();

  const observer = new MutationObserver(() => refresh());
  observer.observe(document.body, {
    childList: true,
    subtree: true,
    characterData: true
  });

  window.addEventListener('resize', refresh);

  return { refresh, observer };
}

window.dynamicDonuts = installDynamicDonuts();



  async function bootstrap() {
    initEvents();
    populateBuilderFields();
    resetBuilder();
    renderSchema();
    await loadMockTickets();
    renderDashboardTabs();
    renderGroupSelect();
    renderTemplateList();
    renderBuilderPreview();
    syncTemplateActionButtons();
    syncBuilderActionButtons();
    bootBoards();
    updateEmptyState();
    showGuideModalIfNeeded(false);
    if (localStorage.getItem(BANNER_KEY) === '1') {
      const banner = document.getElementById('persistenceBanner');
      if (banner) {
        banner.style.display = 'none';
        banner.hidden = true;
      }
    }
  }

  // ── Export globals for app-jira.js integration layer ──
  window.loadMockTickets = loadMockTickets;
  window.renderPreview = renderPreview;
  window.renderTemplateList = renderTemplateList;
  window.syncStatusText = syncStatusText;
  Object.defineProperty(window, 'fakeTickets', {
    get() { return fakeTickets; },
    set(v) { fakeTickets = v; }
  });

  bootstrap();
})();
