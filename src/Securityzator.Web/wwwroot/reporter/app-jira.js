/**
 * Securityzator Reporter — JIRA Integration Layer
 * Loads AFTER app.js, overrides loadMockTickets with localStorage cache,
 * real-time header progress, and template grid improvements.
 */
(function() {

// ── localStorage caching with background refresh ────────────────

var DATA_CACHE_KEY = 'reporter-data-v3';
var DATA_META_KEY = 'reporter-meta-v3';

function getCacheKey(source) { return DATA_CACHE_KEY + '-' + source; }
function getMetaKey(source) { return DATA_META_KEY + '-' + source; }

var _originalLoadMockTickets = loadMockTickets;

loadMockTickets = async function(forceRefresh) {
  var source = '';
  try {
    var sel = document.getElementById('sourceSelect');
    if (sel) source = sel.value || '';
  } catch(e) {}
  
  if (!source) {
    fakeTickets = [];
    syncStatusText.textContent = 'Select a data source';
    return;
  }

  var cacheKey = getCacheKey(source);
  var metaKey = getMetaKey(source);

  // Try localStorage first (5 min TTL)
  if (!forceRefresh) {
    try {
      var meta = JSON.parse(localStorage.getItem(metaKey) || '{}');
      var age = Date.now() - (meta.ts || 0);
      if (meta.count > 0 && age < 300000) {
        var cached = localStorage.getItem(cacheKey);
        if (cached) {
          fakeTickets = JSON.parse(cached);
          syncStatusText.textContent = 'Cached · ' + fakeTickets.length + ' tickets · ' + Math.round(age/1000) + 's ago';
          _scheduleRefresh(source);
          return;
        }
      }
    } catch(e) {}
  }

  // Fetch with header progress bar
  var syncBar = document.getElementById('syncBar');
  var syncBarFill = document.getElementById('syncBarFill');
  var syncDot = document.getElementById('syncDot');
  var startTime = performance.now();
  
  if (syncBar && syncBarFill) {
    syncBar.style.display = 'block';
    syncBarFill.style.width = '0%';
    syncStatusText.textContent = 'Fetching ' + (source === 'jira' ? 'JIRA' : 'CWM') + '...';
    if (syncDot) syncDot.style.background = '#e8a838';
  }

  try {
    var response = await fetch('/reporting/data?source=' + source + '&ts=' + Date.now(), { cache: 'no-store' });
    if (!response.ok) throw new Error('fetch ' + response.status);
    
    var contentLength = parseInt(response.headers.get('content-length') || '0', 10);
    var received = 0;
    var reader = response.body.getReader();
    var chunks = [];
    
    while (true) {
      var result = await reader.read();
      if (result.done) break;
      chunks.push(result.value);
      received += result.value.length;
      if (syncBarFill) {
        var p = contentLength ? Math.min(95, Math.round((received / contentLength) * 100)) : Math.min(90, Math.round(((performance.now() - startTime)/1000)*5));
        syncBarFill.style.width = p + '%';
        syncStatusText.textContent = 'Fetching · ' + formatBytes(received);
      }
    }
    
    var blob = new Blob(chunks);
    var text = await blob.text();
    var data = JSON.parse(text);
    fakeTickets = Array.isArray(data) ? data : [];

    try {
      localStorage.setItem(cacheKey, text);
      localStorage.setItem(metaKey, JSON.stringify({ ts: Date.now(), count: fakeTickets.length, source: source }));
    } catch(e) {}

    var elapsed = ((performance.now() - startTime) / 1000).toFixed(1);
    syncStatusText.textContent = (source === 'jira' ? 'JIRA' : 'CWM') + ' · ' + fakeTickets.length + ' tickets · ' + elapsed + 's';
    if (syncDot) syncDot.style.background = '#79d3a6';
  } catch(e) {
    try {
      var stale = localStorage.getItem(cacheKey);
      if (stale) { fakeTickets = JSON.parse(stale); syncStatusText.textContent = 'Cached · ' + fakeTickets.length + ' tickets'; }
      else { fakeTickets = buildFallbackTickets(120); syncStatusText.textContent = 'Offline · 120 fallback'; }
    } catch(e2) { fakeTickets = buildFallbackTickets(120); }
    if (syncDot) syncDot.style.background = '#e05555';
  }

  if (syncBarFill) syncBarFill.style.width = '100%';
  setTimeout(function() { if (syncBar) syncBar.style.display = 'none'; }, 600);
  _scheduleRefresh(source);
};

var _refreshTimers = {};
function _scheduleRefresh(source) {
  if (_refreshTimers[source]) clearTimeout(_refreshTimers[source]);
  _refreshTimers[source] = setTimeout(function() { loadMockTickets(true); }, 300000);
}

// ── Source selector + refresh button ────────────────────────────

document.addEventListener('DOMContentLoaded', function() {
  var sel = document.getElementById('sourceSelect');
  var btn = document.getElementById('refreshBtn');
  if (sel) sel.addEventListener('change', async function() {
    await loadMockTickets(true);
    if (typeof bootBoards === 'function') bootBoards();
  });
  if (btn) btn.addEventListener('click', async function() {
    await loadMockTickets(true);
    if (typeof bootBoards === 'function') bootBoards();
  });
});

// ── Template grid + preview modal ───────────────────────────────

var _origRenderTemplateList = renderTemplateList;
var _origRenderPreview = renderPreview;

renderTemplateList = function() {
  templateList.innerHTML = templates.map(function(template) {
    var preset = presetForTemplate(template);
    var icon = template.type === 'kpi' ? '\ud83d\udcca' : template.type === 'bar' ? '\ud83d\udcc8' : template.type === 'donut' ? '\ud83c\udf69' : template.type === 'list' ? '\ud83d\udccb' : '\ud83d\udcc4';
    return '<div class="template-card-grid" data-preview="' + esc(template.id) + '">'
      + '<div class="tcg-icon">' + icon + '</div>'
      + '<div class="tcg-type">' + esc(template.type) + '</div>'
      + '<div class="tcg-title">' + esc(template.title) + '</div>'
      + '<div class="tcg-desc">' + esc(template.description || '') + '</div>'
      + '<div class="tcg-meta">' + esc(template.endpoint) + ' \u00b7 ' + preset.w + '\u00d7' + preset.h + '</div>'
      + '<div class="tcg-actions">'
      +   '<button class="btn btn-sm" type="button" data-preview="' + esc(template.id) + '">Preview</button>'
      +   '<button class="btn primary btn-sm" type="button" data-add-view="' + esc(template.id) + '">Add to dashboard</button>'
      + '</div></div>';
  }).join('');
  if (typeof syncTemplateActionButtons === 'function') syncTemplateActionButtons();
};

renderPreview = function() {
  var template = templates.find(function(t) { return t.id === selectedTemplateId; }) || templates[0];
  if (!template) return;
  var modal = document.getElementById('templatePreviewModal');
  var modalTitle = document.getElementById('tpModalTitle');
  var modalBody = document.getElementById('tpModalBody');
  if (!modal || !modalBody) return;
  if (modalTitle) modalTitle.textContent = template.title;
  modalBody.innerHTML = blockHTML(template, 'preview', false);
  modal.style.display = 'flex';
};

// Handle card clicks for preview
var origInitEvents = initEvents;
initEvents = function() {
  origInitEvents();
  templateList.addEventListener('click', function(event) {
    var card = event.target.closest('[data-preview]');
    if (card) {
      selectedTemplateId = card.getAttribute('data-preview');
      renderPreview();
      return;
    }
    // Also handle original button clicks
    var previewBtn = event.target.closest('[data-preview]');
    if (previewBtn && !card) {
      selectedTemplateId = previewBtn.getAttribute('data-preview');
      renderPreview();
    }
  });
};

})();
