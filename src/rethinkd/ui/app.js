'use strict';

/* ==========================================================================
   Rethink Root — UI application (vanilla JS, no build step, no modules).
   Talks to the rethinkd HTTP API documented in docs/api.md.
   ========================================================================== */

/* ------------------------------------------------------------- DOM utils */

function applyProps(node, props) {
  if (!props) return;
  for (const key in props) {
    const val = props[key];
    if (val == null || val === false) continue;
    if (key === 'class') node.setAttribute('class', val);
    else if (key === 'html') node.innerHTML = val;
    else if (key === 'text') node.textContent = String(val);
    else if (key.indexOf('on') === 0 && typeof val === 'function') node.addEventListener(key.slice(2), val);
    else if (val === true) node.setAttribute(key, '');
    else node.setAttribute(key, val);
  }
}

function appendKids(node, kids) {
  for (const kid of kids) {
    if (kid == null || kid === true || kid === false) continue;
    if (Array.isArray(kid)) appendKids(node, kid);
    else if (kid instanceof Node) node.appendChild(kid);
    else node.appendChild(document.createTextNode(String(kid)));
  }
}

function el(tag, props) {
  const node = document.createElement(tag);
  applyProps(node, props);
  appendKids(node, Array.prototype.slice.call(arguments, 2));
  return node;
}

function svgEl(tag, props) {
  const node = document.createElementNS('http://www.w3.org/2000/svg', tag);
  applyProps(node, props);
  appendKids(node, Array.prototype.slice.call(arguments, 2));
  return node;
}

function clear(node) {
  while (node.firstChild) node.removeChild(node.firstChild);
  return node;
}

/* Replaces a node's children with any mix of nodes, arrays and strings. */
function setKids(node) {
  clear(node);
  appendKids(node, Array.prototype.slice.call(arguments, 1));
  return node;
}

function icon(name, extraClass) {
  const svg = svgEl('svg', {
    class: 'ic' + (extraClass ? ' ' + extraClass : ''),
    'aria-hidden': 'true',
    focusable: 'false'
  });
  svg.appendChild(svgEl('use', { href: '#ic-' + name }));
  return svg;
}

/* ------------------------------------------------------------ formatting */

const NUM = new Intl.NumberFormat('en-US');
const fmtInt = (n) => NUM.format(Math.round(Number(n) || 0));

function trim1(x) {
  return String(Math.round(x * 10) / 10).replace(/\.0$/, '');
}

function fmtCompact(n) {
  n = Number(n) || 0;
  const a = Math.abs(n);
  if (a < 10000) return fmtInt(n);
  if (a < 1e6) return trim1(n / 1e3) + 'k';
  if (a < 1e9) return trim1(n / 1e6) + 'M';
  return trim1(n / 1e9) + 'B';
}

function fmtPct(n) {
  return (Math.round((Number(n) || 0) * 10) / 10).toFixed(1) + '%';
}

function pad2(n) {
  return n < 10 ? '0' + n : String(n);
}

function hms(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  return pad2(Math.floor(sec / 3600)) + ':' + pad2(Math.floor((sec % 3600) / 60)) + ':' + pad2(sec % 60);
}

function fmtUptime(sec) {
  sec = Math.max(0, Math.floor(Number(sec) || 0));
  const d = Math.floor(sec / 86400);
  if (d > 0) return d + 'd ' + Math.floor((sec % 86400) / 3600) + 'h ' + Math.floor((sec % 3600) / 60) + 'm';
  return hms(sec);
}

function hhmmss(epoch) {
  const d = new Date((Number(epoch) || 0) * 1000);
  return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
}

function hostOf(url) {
  if (!url) return '';
  try { return new URL(url).hostname; }
  catch (e) { return String(url).replace(/^https?:\/\//, '').split('/')[0]; }
}

/* ----------------------------------------------------------------- state */

const state = {
  page: null,
  session: null,
  status: null,
  stats: null,
  settings: null,
  apps: null,
  lists: null,
  dns: null,
  proxy: null,
  events: [],
  activityFilter: 'all',
  activityPaused: false,
  explicit: new Set(),
  bootAt: 0,
  connLost: false,
  timers: [],
  loopTimers: [],
  refs: {}
};

const TOKEN_KEY = 'rethink_token';

function getToken() {
  try { return localStorage.getItem(TOKEN_KEY) || ''; }
  catch (e) { return ''; }
}

/* ------------------------------------------------------- api / toast / ui */

class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.status = status || 0;
  }
}

async function api(path, opts) {
  opts = opts || {};
  const headers = { Accept: 'application/json' };
  const tk = getToken();
  if (tk) headers['X-Auth-Token'] = tk;

  let body = opts.body;
  if (body !== undefined && body !== null && typeof body !== 'string') {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }

  let res;
  try {
    res = await fetch(path, { method: opts.method || 'GET', headers: headers, body: body });
  } catch (e) {
    setConn('down');
    throw new ApiError('Cannot reach rethinkd — is the daemon running?', 0);
  }

  setConn(res.status === 401 ? 'down' : 'up');

  if (res.status === 401) {
    showConnect('That token was rejected by rethinkd. Run "rethinkctl ui" for a fresh one.');
    throw new ApiError('unauthorized', 401);
  }

  let data = {};
  try { data = await res.json(); }
  catch (e) { data = {}; }

  if (!res.ok) throw new ApiError(data.error || 'Request failed (' + res.status + ')', res.status);
  return data;
}

/* Mutating helper: toasts on success and on failure, never rejects. */
async function act(path, opts, okMsg) {
  try {
    const out = await api(path, opts);
    if (okMsg) toast(okMsg);
    return out;
  } catch (e) {
    if (e.status !== 401) toast(e.message || 'Request failed', 'err');
    return null;
  }
}

function toast(msg, kind) {
  const box = document.getElementById('toasts');
  if (!box) return;
  const node = el('div', { class: 'toast' + (kind === 'err' ? ' is-err' : '') },
    el('span', { class: 'toast-msg' }, msg),
    el('button', {
      class: 'toast-x', type: 'button', 'aria-label': 'Dismiss notification',
      onclick: () => node.remove()
    }, icon('x'))
  );
  box.appendChild(node);
  setTimeout(() => node.remove(), 4000);
}

function clearToasts() {
  document.querySelectorAll('.toast').forEach((n) => n.remove());
}

let modalResolve = null;

function confirmBox(title, message, okLabel) {
  return new Promise((resolve) => {
    const modal = document.getElementById('modal');
    document.getElementById('modal-title').textContent = title;
    document.getElementById('modal-msg').textContent = message;
    document.getElementById('modal-ok').textContent = okLabel || 'Confirm';
    modalResolve = (value) => {
      modal.hidden = true;
      modalResolve = null;
      resolve(value);
    };
    modal.hidden = false;
    document.getElementById('modal-ok').focus();
  });
}

function closeModal(value) {
  if (modalResolve) modalResolve(value);
}

function setConn(s) {
  const node = document.getElementById('conn');
  if (node) node.dataset.state = s;
}

function showConnect(msg) {
  stopLoops();
  clearTimers();
  document.getElementById('app').hidden = true;
  document.getElementById('connect').hidden = false;
  const err = document.getElementById('connect-err');
  err.hidden = !msg;
  err.textContent = msg || '';
  document.getElementById('connect-host').textContent = location.host || '127.0.0.1:8777';
}

function showApp() {
  document.getElementById('connect').hidden = true;
  document.getElementById('app').hidden = false;
}

/* ---------------------------------------------------------- shared widgets */

function seg(items, value, onChange, label) {
  let current = value;
  const node = el('div', { class: 'seg', role: 'group', 'aria-label': label || 'Options' });
  const buttons = items.map((item) => {
    const btn = el('button', {
      class: 'seg-btn', type: 'button', 'data-value': item.value,
      onclick: () => set(item.value, true)
    }, item.label);
    node.appendChild(btn);
    return btn;
  });

  function set(v, fire) {
    current = v;
    buttons.forEach((b) => {
      const on = b.dataset.value === v;
      b.classList.toggle('is-active', on);
      b.setAttribute('aria-pressed', String(on));
    });
    if (fire && onChange) onChange(v);
  }

  set(value, false);
  return { node: node, set: set, get: () => current };
}

function switchEl(opts) {
  const node = el('button', {
    class: 'switch', type: 'button', role: 'switch',
    'aria-checked': String(!!opts.checked),
    'aria-label': opts.label || 'Toggle',
    onclick: () => set(!get(), true)
  }, el('span', { class: 'switch-knob' }));

  function get() { return node.getAttribute('aria-checked') === 'true'; }
  function set(v, fire) {
    node.setAttribute('aria-checked', String(v));
    node.classList.toggle('is-on', v);
    if (fire && opts.onChange) opts.onChange(v);
  }

  set(!!opts.checked, false);
  return { node: node, set: set, get: get };
}

function statCard(label, hint) {
  const value = el('div', { class: 'stat-value' }, '—');
  const sub = el('div', { class: 'stat-sub' }, hint || '');
  const node = el('div', { class: 'card stat' },
    el('div', { class: 'stat-label' }, label), value, sub);
  return { node: node, value: value, sub: sub };
}

function mini(label, value) {
  return el('div', { class: 'mini' },
    el('div', { class: 'mini-label' }, label),
    el('div', { class: 'mini-value' }, value));
}

function chip(label, value, tone, sub) {
  return el('div', { class: 'chip' },
    el('span', { class: 'chip-label' }, label),
    el('span', { class: 'chip-value' + (tone ? ' ' + tone : '') }, value),
    sub ? el('span', { class: 'chip-sub', title: sub }, sub) : null);
}

function pill(kind, label, reason) {
  return el('span', { class: 'pill is-' + kind }, label,
    reason ? el('span', { class: 'pill-reason' }, ' · ' + reason) : null);
}

function emptyBox(title, hint) {
  return el('div', { class: 'empty' },
    el('div', { class: 'empty-title' }, title),
    el('div', { class: 'empty-hint' }, hint));
}

function skeleton(rows) {
  const wrap = el('div', { class: 'skeleton' });
  for (let i = 0; i < (rows || 5); i++) wrap.appendChild(el('div', { class: 'skel' }));
  return wrap;
}

function errorBox(msg, retry) {
  return el('div', { class: 'error-box' },
    el('span', null, msg),
    retry ? el('button', { class: 'btn btn-ghost btn-sm', type: 'button', onclick: retry },
      icon('refresh'), 'Retry') : null);
}

function setError(node, msg, retry) {
  if (!node) return;
  clear(node).appendChild(errorBox(msg, retry));
}

function fail(e, node, retry) {
  if (e.status === 401) return;
  if (node && node.isConnected) setError(node, e.message || 'Request failed', retry);
  toast(e.message || 'Request failed', 'err');
}

function busy(btn, on) {
  btn.disabled = on;
  btn.classList.toggle('is-busy', on);
}

/* ----------------------------------------------------------------- timers */

function every(ms, fn) {
  const id = setInterval(fn, ms);
  state.timers.push(id);
  return id;
}

function clearTimers() {
  state.timers.forEach((id) => clearInterval(id));
  state.timers = [];
}

function startLoops() {
  stopLoops();
  state.loopTimers.push(setInterval(pollStatus, 3000));
  state.loopTimers.push(setInterval(tickUptime, 1000));
  pollStatus();
  tickUptime();
}

function stopLoops() {
  state.loopTimers.forEach((id) => clearInterval(id));
  state.loopTimers = [];
}

/* --------------------------------------------------------------- auth/boot */

function ingestToken() {
  const url = new URL(location.href);
  const fromUrl = url.searchParams.get('token');
  if (fromUrl) {
    try { localStorage.setItem(TOKEN_KEY, fromUrl); } catch (e) { /* storage blocked */ }
  }
  if (url.searchParams.has('token')) {
    url.searchParams.delete('token');
    history.replaceState(null, '', url.pathname + url.search + url.hash);
  }
}

async function boot() {
  ingestToken();

  let session = null;
  try {
    session = await api('/api/session');
  } catch (e) {
    showConnect(e.status === 401
      ? 'No valid token is stored in this browser.'
      : e.message);
    return;
  }
  if (!session || !session.authed) {
    /* whatever is stored is not accepted by the daemon — start clean */
    try { localStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
    showConnect('No valid token is stored in this browser.');
    return;
  }

  state.session = session;
  document.getElementById('side-version').textContent = 'rethinkd v' + (session.version || '?');
  showApp();
  startLoops();
  go(pageFromHash());

  api('/api/status').then((s) => { state.status = s; paintTopbar(); }).catch(() => {});
  api('/api/settings').then((s) => {
    state.settings = s;
    applyTheme(s.theme);
  }).catch(() => {});
}

async function onConnectSubmit(e) {
  e.preventDefault();
  const input = document.getElementById('connect-token');
  const btn = e.target.querySelector('button[type="submit"]');
  const value = input.value.trim();
  if (!value) return;

  try { localStorage.setItem(TOKEN_KEY, value); } catch (err) { /* storage blocked */ }
  busy(btn, true);
  try {
    const s = await api('/api/session');
    if (s && s.authed) { location.reload(); return; }
    rejectToken(input);
  } catch (err) {
    if (err.status === 401) rejectToken(input);
    else showConnect(err.message);
  } finally {
    busy(btn, false);
  }
}

function rejectToken(input) {
  try { localStorage.removeItem(TOKEN_KEY); } catch (e) { /* ignore */ }
  showConnect('That token was rejected. Run "rethinkctl ui" to print a new one.');
  input.value = '';
  input.focus();
}

async function copyCmd() {
  try {
    await navigator.clipboard.writeText('rethinkctl ui');
    toast('Command copied');
  } catch (e) {
    const code = document.querySelector('.code-row code');
    const range = document.createRange();
    range.selectNodeContents(code);
    const sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    toast('Press Ctrl+C to copy');
  }
}

/* ------------------------------------------------------------- topbar/loop */

async function pollStatus() {
  if (document.hidden || !state.session) return;
  try {
    const s = await api('/api/status');
    state.status = s;
    const bootAt = Date.now() - (s.uptime_s || 0) * 1000;
    if (!state.bootAt || Math.abs(bootAt - state.bootAt) > 6000) state.bootAt = bootAt;
    if (state.connLost) { state.connLost = false; toast('Reconnected to rethinkd'); }
    paintTopbar();
  } catch (e) {
    if (e.status !== 401 && !state.connLost) {
      state.connLost = true;
      toast('Lost connection to rethinkd', 'err');
    }
  }
}

function tickUptime() {
  const node = document.getElementById('top-uptime');
  if (!node) return;
  node.textContent = state.bootAt ? 'up ' + fmtUptime((Date.now() - state.bootAt) / 1000) : 'up —';
}

function paintTopbar() {
  const s = state.status;
  if (!s) return;
  const on = !!s.protected;
  const btn = document.getElementById('protect-btn');
  btn.classList.toggle('is-on', on);
  btn.setAttribute('aria-checked', String(on));
  document.getElementById('protect-state').textContent = on ? 'On' : 'Off';
  document.getElementById('top-version').textContent = 'v' + (s.version || '—');
  document.getElementById('side-version').textContent =
    'rethinkd v' + (s.version || (state.session && state.session.version) || '?');
  if (state.page === 'dashboard') paintDashboard();
}

async function toggleProtection() {
  const s = state.status;
  if (!s) { toast('Status has not loaded yet', 'err'); return; }
  const next = !s.protected;
  s.protected = next;
  paintTopbar();
  try {
    await api('/api/protected', { method: 'POST', body: { on: next } });
    toast(next ? 'Protection enabled' : 'Protection disabled');
    const fresh = await api('/api/status');
    state.status = fresh;
    paintTopbar();
  } catch (e) {
    if (e.status !== 401) {
      s.protected = !next;
      paintTopbar();
      toast(e.message || 'Could not change protection', 'err');
    }
  }
}

/* ------------------------------------------------------------------ router */

const PAGES = {
  dashboard: { title: 'Dashboard', render: renderDashboard },
  apps: { title: 'Apps', render: renderApps },
  blocklists: { title: 'Blocklists', render: renderBlocklists },
  dns: { title: 'DNS', render: renderDns },
  proxy: { title: 'Proxy', render: renderProxy },
  activity: { title: 'Activity', render: renderActivity },
  settings: { title: 'Settings', render: renderSettings }
};

function pageFromHash() {
  const name = location.hash.replace('#', '');
  return PAGES[name] ? name : 'dashboard';
}

function go(name) {
  if (!PAGES[name]) name = 'dashboard';
  clearTimers();
  state.page = name;
  state.refs = {};

  document.querySelectorAll('.nav-item').forEach((btn) => {
    const active = btn.dataset.page === name;
    btn.classList.toggle('is-active', active);
    if (active) btn.setAttribute('aria-current', 'page');
    else btn.removeAttribute('aria-current');
  });
  document.querySelectorAll('.page').forEach((sec) => {
    sec.hidden = sec.id !== 'page-' + name;
  });
  document.getElementById('page-title').textContent = PAGES[name].title;
  closeDrawer();

  if (location.hash !== '#' + name) history.replaceState(null, '', '#' + name);
  try { PAGES[name].render(); }
  catch (e) { console.error(e); toast('Could not render ' + name, 'err'); }
}

function toggleDrawer() {
  const sb = document.getElementById('sidebar');
  const open = sb.classList.toggle('is-open');
  document.getElementById('side-scrim').hidden = !open;
  document.getElementById('menu-btn').setAttribute('aria-expanded', String(open));
}

function closeDrawer() {
  document.getElementById('sidebar').classList.remove('is-open');
  document.getElementById('side-scrim').hidden = true;
  document.getElementById('menu-btn').setAttribute('aria-expanded', 'false');
}

/* ============================================================== dashboard */

function renderDashboard() {
  const page = clear(document.getElementById('page-dashboard'));

  const cards = {
    queries: statCard('Queries', 'DNS queries handled'),
    blocked: statCard('Blocked', 'rejected by rules'),
    rate: statCard('Block rate', 'of all queries'),
    apps: statCard('Apps blocked', 'by firewall policy'),
    relayed: statCard('Proxy relayed', 'connections')
  };
  const spark = el('div', { class: 'spark' },
    el('div', { class: 'skeleton', style: 'padding:14px' },
      el('div', { class: 'skel' }), el('div', { class: 'skel', style: 'width:58%' })));
  const hour = el('div', { class: 'mini-row' });
  const top = el('div', { class: 'list' }, skeleton(4));
  const chips = el('div', { class: 'chips' });

  state.refs.dash = { cards: cards, spark: spark, hour: hour, top: top, chips: chips };

  page.appendChild(el('div', { class: 'stat-grid' },
    cards.queries.node, cards.blocked.node, cards.rate.node,
    cards.apps.node, cards.relayed.node));

  page.appendChild(el('div', { class: 'grid-2' },
    el('section', { class: 'card' },
      el('header', { class: 'card-head' },
        el('h2', null, 'DNS traffic · last 60 minutes'),
        el('div', { class: 'legend' },
          el('span', { class: 'lg' }, el('i', { class: 'lg-dot' }), 'Total'),
          el('span', { class: 'lg' }, el('i', { class: 'lg-dot lg-blocked' }), 'Blocked'))),
      spark, hour),
    el('section', { class: 'card' },
      el('header', { class: 'card-head' }, el('h2', null, 'Top blocked domains')),
      top)));

  page.appendChild(el('section', { class: 'card' },
    el('header', { class: 'card-head' },
      el('h2', null, 'System summary'),
      el('span', { class: 'card-sub' }, 'live from /api/status')),
    chips));

  paintDashboard();
  loadStats();
  every(15000, loadStats);
}

async function loadStats() {
  if (state.page !== 'dashboard') return;
  try {
    const stats = await api('/api/stats');
    if (state.page !== 'dashboard') return;
    state.stats = stats;
    paintDashboard();
  } catch (e) {
    fail(e, state.refs.dash && state.refs.dash.top, loadStats);
  }
}

function paintDashboard() {
  const d = state.refs.dash;
  if (!d) return;

  const s = state.status;
  if (s) {
    const dns = s.dns || {};
    const fw = s.firewall || {};
    const px = s.proxy || {};
    const lh = dns.last_hour || {};
    const c = d.cards;

    c.queries.value.textContent = fmtCompact(dns.queries);
    c.queries.sub.textContent = 'last hour ' + fmtInt(lh.total);
    c.blocked.value.textContent = fmtCompact(dns.blocked);
    c.blocked.sub.textContent = 'last hour ' + fmtInt(lh.blocked);
    c.rate.value.textContent = fmtPct(dns.block_rate);
    c.rate.sub.textContent = 'of all queries';
    c.apps.value.textContent = fmtInt(fw.apps_blocked);
    c.apps.sub.textContent = 'policy · ' + (fw.policy || '—');
    c.relayed.value.textContent = fmtCompact(px.relayed);
    c.relayed.sub.textContent = px.enabled ? 'active ' + fmtInt(px.active_conns) : 'proxy off';

    const lhRate = lh.total ? (lh.blocked / lh.total) * 100 : 0;
    setKids(d.hour, [
      mini('Last hour queries', fmtInt(lh.total)),
      mini('Last hour blocked', fmtInt(lh.blocked)),
      mini('Last hour rate', fmtPct(lhRate)),
      mini('Dropped packets', fmtInt(fw.dropped_packets))
    ]);

    const chips = [
      chip('Upstream', dns.upstream || '—', null, dns.upstream_url || ''),
      chip('DNS hijack', dns.hijack ? 'on' : 'off', dns.hijack ? 'on' : 'off'),
      chip('Listening', (dns.listening || []).join(', ') || '—'),
      chip('Firewall', fw.enabled ? 'enabled' : 'disabled', fw.enabled ? 'on' : 'warn',
        'policy · ' + (fw.policy || '—')),
      chip('Proxy', px.enabled ? (px.type || 'on') : 'off', px.enabled ? 'on' : 'off',
        px.enabled ? (px.endpoint || '') : 'relay disabled'),
      chip('Running as', s.running_as || '—')
    ];
    if (s.host) {
      chips.push(chip('Host', s.host.os || '—', null,
        'kernel ' + (s.host.kernel || '?') + ' · python ' + (s.host.python || '?')));
    }
    if (state.stats && state.stats.by_type) {
      const types = Object.keys(state.stats.by_type)
        .map((k) => k + ' ' + fmtInt(state.stats.by_type[k])).join(' · ');
      if (types) chips.push(chip('Query types', types));
    }
    setKids(d.chips, chips);
  }

  paintSpark();
  paintTopBlocked();
}

function paintSpark() {
  const d = state.refs.dash;
  if (!d) return;
  const series = (state.stats && state.stats.series) || [];
  const box = clear(d.spark);

  if (!series.length) {
    box.appendChild(emptyBox('No DNS traffic yet',
      'The 60 one-minute buckets fill in as soon as clients start resolving names.'));
    return;
  }

  const W = 600;
  const H = 158;
  const PAD = 10;
  const max = Math.max(1, ...series.map((p) => Number(p.total) || 0));
  const xAt = (i) => (i / Math.max(1, series.length - 1)) * W;
  const yAt = (v) => H - PAD - ((Number(v) || 0) / max) * (H - PAD * 2);
  const path = (key) => series.map((p, i) =>
    (i ? 'L' : 'M') + xAt(i).toFixed(1) + ' ' + yAt(p[key]).toFixed(1)).join(' ');

  box.appendChild(svgEl('svg', {
    class: 'spark-svg', viewBox: '0 0 ' + W + ' ' + H,
    preserveAspectRatio: 'none', role: 'img',
    'aria-label': 'Total and blocked DNS queries over the last 60 minutes'
  },
    svgEl('line', { class: 'spark-grid', x1: 0, y1: H - PAD, x2: W, y2: H - PAD }),
    svgEl('line', {
      class: 'spark-grid', x1: 0, y1: PAD + (H - PAD * 2) / 2, x2: W, y2: PAD + (H - PAD * 2) / 2
    }),
    svgEl('path', { class: 'spark-area', d: path('total') + ' L ' + W + ' ' + H + ' L 0 ' + H + ' Z' }),
    svgEl('path', { class: 'spark-line', d: path('total') }),
    svgEl('path', { class: 'spark-line spark-blocked', d: path('blocked') })
  ));
}

function paintTopBlocked() {
  const d = state.refs.dash;
  if (!d) return;
  const rows = ((state.stats && state.stats.top_blocked) || []).slice(0, 10);
  const box = clear(d.top);

  if (!rows.length) {
    box.appendChild(emptyBox('Nothing blocked yet',
      'Domains rejected by a rule or a blocklist show up here with their hit counts.'));
    return;
  }

  const max = Math.max(1, ...rows.map((r) => Number(r.count) || 0));
  rows.forEach((row) => {
    const pct = Math.max(4, Math.round(((Number(row.count) || 0) / max) * 100));
    box.appendChild(el('div', { class: 'list-row' },
      el('span', { class: 'row-main', title: row.domain }, row.domain),
      el('span', { class: 'row-count' }, fmtInt(row.count)),
      el('div', { class: 'row-sub' },
        el('div', { class: 'bar' },
          el('div', { class: 'bar-fill', style: 'width:' + pct + '%' })))));
  });
}

/* =================================================================== apps */

function renderApps() {
  const page = clear(document.getElementById('page-apps'));

  const policySeg = seg(
    [{ value: 'allow', label: 'Allow' }, { value: 'block', label: 'Block' }],
    'allow', setPolicy, 'Default policy');
  const policyExpl = el('p', { class: 'card-sub' }, 'Loading policy…');
  const rescanBtn = el('button', { class: 'btn btn-ghost btn-sm', type: 'button' },
    icon('refresh'), 'Rescan');
  rescanBtn.addEventListener('click', () => rescanApps(rescanBtn));

  const body = el('div', null, skeleton(6));
  const count = el('span', { class: 'toolbar-note' }, '');
  state.refs.apps = { policySeg: policySeg, policyExpl: policyExpl, body: body, count: count };

  page.appendChild(el('section', { class: 'card' },
    el('header', { class: 'card-head' },
      el('div', null, el('h2', null, 'Default policy'), policyExpl),
      policySeg.node)));

  page.appendChild(el('section', { class: 'card' },
    el('div', { class: 'toolbar' },
      el('span', { class: 'toolbar-title' }, 'Applications'),
      count,
      el('span', { class: 'spacer' }),
      rescanBtn),
    body));

  loadApps();
}

async function loadApps() {
  try {
    const data = await api('/api/apps');
    if (state.page !== 'apps') return data;
    state.apps = data;
    paintApps();
    return data;
  } catch (e) {
    if (state.page === 'apps') fail(e, state.refs.apps && state.refs.apps.body, loadApps);
    return null;
  }
}

/* The contract reports `action` but no explicit flag: an action that differs
   from the policy is explicit for sure, and rules the user just saved are
   remembered here until the next reload. */
function isExplicit(app) {
  if (typeof app.explicit === 'boolean') return app.explicit;
  if (state.explicit.has(app.uid)) return true;
  return !!state.apps && app.action !== state.apps.policy;
}

function paintApps() {
  const refs = state.refs.apps;
  const data = state.apps;
  if (!refs || !data) return;

  const policy = data.policy || 'allow';
  refs.policySeg.set(policy);
  refs.policyExpl.textContent = policy === 'block'
    ? 'Everything is blocked unless an app below explicitly allows traffic.'
    : 'Everything is allowed unless an app below is explicitly blocked.';

  const apps = data.apps || [];
  refs.count.textContent = apps.length ? fmtInt(apps.length) + ' seen' : '';

  const body = clear(refs.body);
  if (!apps.length) {
    body.appendChild(emptyBox('No applications discovered',
      'Press Rescan to read /proc for running processes and their open sockets.'));
    return;
  }

  const table = el('table', { class: 'table' });
  table.appendChild(el('thead', null, el('tr', null,
    th('App'), th('UID'), th('Executable'), th('Proc', true), th('Conns', true),
    th('Packets', true), th('Dropped', true), th('Rule'))));

  const tbody = el('tbody');
  apps.slice()
    .sort((a, b) => String(a.name).localeCompare(String(b.name)) || a.uid - b.uid)
    .forEach((app) => tbody.appendChild(appRow(app)));
  table.appendChild(tbody);
  body.appendChild(table);
}

function th(label, num) {
  return el('th', { scope: 'col', class: num ? 'num' : null }, label);
}

function appRow(app) {
  const segCtl = seg(
    [{ value: 'allow', label: 'Allow' }, { value: 'block', label: 'Block' }],
    app.action, (v) => setAppRule(app.uid, v), 'Rule for ' + app.name);

  let control;
  if (isExplicit(app)) {
    control = el('div', { class: 'rule-cell' }, segCtl.node,
      el('button', {
        class: 'icon-btn', type: 'button', title: 'Reset to default policy',
        'aria-label': 'Reset ' + app.name + ' to the default policy',
        onclick: () => resetAppRule(app.uid)
      }, icon('x')));
  } else {
    control = el('div', { class: 'rule-cell' }, segCtl.node,
      el('span', { class: 'chip-muted', title: 'No explicit rule — follows the default policy' },
        'default · ' + ((state.apps && state.apps.policy) || 'allow')));
  }

  return el('tr', null,
    el('td', { class: 'cell-main', 'data-label': 'App' },
      el('div', { class: 'cell-strong', title: app.name }, app.name)),
    el('td', { 'data-label': 'UID' }, String(app.uid)),
    el('td', { 'data-label': 'Executable' },
      el('span', { class: 'truncate', title: app.exe || '—' }, app.exe || '—')),
    el('td', { class: 'num', 'data-label': 'Proc' }, fmtInt(app.processes)),
    el('td', { class: 'num', 'data-label': 'Conns' }, fmtInt(app.conns)),
    el('td', { class: 'num', 'data-label': 'Packets' }, fmtInt(app.packets)),
    el('td', { class: 'num', 'data-label': 'Dropped' },
      el('span', { class: app.dropped > 0 ? 'num-bad' : 'num-ok' }, fmtInt(app.dropped))),
    el('td', { class: 'cell-action', 'data-label': 'Rule' }, control));
}

async function setPolicy(value) {
  if (!state.apps) return;
  state.apps.policy = value;
  paintApps();
  await act('/api/policy', { method: 'POST', body: { policy: value } },
    'Default policy: ' + value);
  await loadApps();
}

async function setAppRule(uid, action) {
  const app = state.apps && state.apps.apps.find((x) => x.uid === uid);
  if (app) app.action = action;
  state.explicit.add(uid);
  paintApps();
  await act('/api/apps', { method: 'POST', body: { uid: uid, action: action } }, 'Rule saved');
  await loadApps();
}

async function resetAppRule(uid) {
  const app = state.apps && state.apps.apps.find((x) => x.uid === uid);
  if (app && state.apps) app.action = state.apps.policy;
  state.explicit.delete(uid);
  paintApps();
  await act('/api/apps/' + uid, { method: 'DELETE' }, 'Rule removed');
  await loadApps();
}

async function rescanApps(btn) {
  if (btn.disabled) return;
  busy(btn, true);
  try {
    await act('/api/apps/refresh', { method: 'POST' }, 'Applications rescanned');
    await loadApps();
  } finally {
    busy(btn, false);
  }
}

/* ============================================================== blocklists */

function renderBlocklists() {
  const page = clear(document.getElementById('page-blocklists'));

  const totals = el('div', { class: 'totals' }, skeleton(1));
  const cats = el('div', { class: 'cat-grid' }, skeleton(4));
  const customList = el('div', { class: 'row-list' });
  const testOut = el('div', { class: 'test-result' });
  state.refs.lists = { totals: totals, cats: cats, customList: customList, testOut: testOut };

  const refreshBtn = el('button', { class: 'btn btn-ghost btn-sm', type: 'button' },
    icon('refresh'), 'Refresh all');
  refreshBtn.addEventListener('click', () => refreshAll(refreshBtn));

  const urlInput = el('input', {
    class: 'input', type: 'url', id: 'custom-url', autocomplete: 'off', spellcheck: 'false',
    placeholder: 'https://example.com/hosts.txt'
  });
  const addBtn = el('button', { class: 'btn btn-primary', type: 'submit' }, icon('plus'), 'Add list');
  const addForm = el('form', {
    class: 'inline-form',
    onsubmit: (e) => { e.preventDefault(); addCustomList(urlInput, addBtn); }
  },
    el('div', { class: 'grow' },
      el('label', { class: 'label', for: 'custom-url' }, 'List URL'), urlInput),
    addBtn);

  const testInput = el('input', {
    class: 'input', type: 'text', id: 'test-domain', autocomplete: 'off', spellcheck: 'false',
    placeholder: 'ads.example.com'
  });
  const testBtn = el('button', { class: 'btn btn-primary', type: 'submit' }, icon('flask'), 'Test');
  const testForm = el('form', {
    class: 'inline-form',
    onsubmit: (e) => { e.preventDefault(); testDomain(testInput, testBtn, testOut); }
  },
    el('div', { class: 'grow' },
      el('label', { class: 'label', for: 'test-domain' }, 'Domain'), testInput),
    testBtn);

  page.appendChild(totals);
  page.appendChild(el('section', { class: 'card' },
    el('header', { class: 'card-head' },
      el('div', null,
        el('h2', null, 'Categories'),
        el('p', { class: 'card-sub' }, 'Whole-category lists. Each switch saves immediately.')),
      refreshBtn),
    cats));
  page.appendChild(el('section', { class: 'card' },
    el('header', { class: 'card-head' }, el('h2', null, 'Custom lists')),
    addForm, customList));
  page.appendChild(el('section', { class: 'card' },
    el('header', { class: 'card-head' }, el('h2', null, 'Test a domain')),
    testForm, testOut));

  loadLists();
}

async function loadLists() {
  try {
    const data = await api('/api/blocklists');
    if (state.page !== 'blocklists') return;
    state.lists = data;
    paintLists();
  } catch (e) {
    if (state.page === 'blocklists') fail(e, state.refs.lists && state.refs.lists.cats, loadLists);
  }
}

function paintLists() {
  const refs = state.refs.lists;
  const data = state.lists;
  if (!refs || !data) return;

  const totals = data.totals || {};
  setKids(refs.totals, [
    el('div', { class: 'totals-item' },
      el('span', { class: 'totals-value' }, fmtCompact(totals.domains)),
      el('span', { class: 'totals-label' }, 'domains in play')),
    el('div', { class: 'totals-item' },
      el('span', { class: 'totals-value' }, fmtInt(totals.enabled)),
      el('span', { class: 'totals-label' }, 'lists enabled')),
    el('div', { class: 'totals-item' },
      el('span', { class: 'totals-value' }, fmtInt((data.categories || []).length)),
      el('span', { class: 'totals-label' }, 'categories')),
    el('div', { class: 'totals-item' },
      el('span', { class: 'totals-value' }, fmtInt((data.custom || []).length)),
      el('span', { class: 'totals-label' }, 'custom lists'))
  ]);

  const cats = clear(refs.cats);
  const categories = data.categories || [];
  if (!categories.length) {
    cats.appendChild(emptyBox('No categories shipped',
      'Add a custom list below, or check your rethinkd installation for bundled lists.'));
  } else {
    categories.forEach((cat) => cats.appendChild(catCard(cat)));
  }

  const list = clear(refs.customList);
  const custom = data.custom || [];
  if (!custom.length) {
    list.appendChild(emptyBox('No custom lists yet',
      'Paste any hosts or domain blocklist URL above to subscribe to it.'));
  } else {
    custom.forEach((item) => list.appendChild(customRow(item)));
  }
}

function catCard(cat) {
  const sw = switchEl({
    checked: !!cat.enabled,
    label: 'Enable ' + cat.name,
    onChange: (on) => toggleCategory(cat, on)
  });
  const card = el('div', { class: 'cat' + (cat.enabled ? '' : ' is-off') },
    el('div', { class: 'cat-head' },
      el('div', null,
        el('div', { class: 'cat-name' }, cat.name),
        el('div', { class: 'cat-domains' }, fmtInt(cat.domains) + ' domains')),
      sw.node),
    el('div', { class: 'cat-source', title: cat.source || 'bundled' },
      hostOf(cat.source) || 'bundled'));
  if (cat.last_error) {
    card.appendChild(el('div', { class: 'row-error' }, 'Last refresh failed: ' + cat.last_error));
  }
  return card;
}

async function toggleCategory(cat, on) {
  cat.enabled = on;
  paintLists();
  await act('/api/blocklists', { method: 'POST', body: { id: cat.id, enabled: on } },
    on ? cat.name + ' enabled' : cat.name + ' disabled');
  await loadLists();
}

function customRow(item) {
  const del = el('button', {
    class: 'icon-btn', type: 'button', title: 'Remove list',
    'aria-label': 'Remove list ' + item.url,
    onclick: async () => {
      const yes = await confirmBox('Remove this list?', item.url, 'Remove');
      if (!yes) return;
      const ok = await act('/api/blocklists/custom/' + item.id, { method: 'DELETE' }, 'List removed');
      if (ok) await loadLists();
    }
  }, icon('trash'));

  return el('div', { class: 'custom-row' },
    el('div', { class: 'grow' },
      el('div', { class: 'custom-url', title: item.url }, item.url),
      el('div', { class: 'custom-meta' },
        fmtInt(item.domains) + ' domains · ' + (item.enabled ? 'enabled' : 'disabled')),
      item.last_error ? el('div', { class: 'row-error' }, item.last_error) : null),
    del);
}

async function addCustomList(input, btn) {
  const url = input.value.trim();
  if (!url) { toast('Enter a list URL', 'err'); input.focus(); return; }
  busy(btn, true);
  try {
    const ok = await act('/api/blocklists/custom',
      { method: 'POST', body: { url: url, enabled: true } }, 'List added');
    if (ok) { input.value = ''; await loadLists(); }
  } finally {
    busy(btn, false);
  }
}

async function refreshAll(btn) {
  if (btn.disabled) return;
  busy(btn, true);
  try {
    const r = await act('/api/blocklists/refresh', { method: 'POST' }, null);
    if (r) {
      toast('Refreshed ' + fmtInt(r.categories) + ' categories · ' + fmtInt(r.domains) + ' domains');
    }
    await loadLists();
  } finally {
    busy(btn, false);
  }
}

async function testDomain(input, btn, out) {
  const domain = input.value.trim();
  if (!domain) { toast('Enter a domain to test', 'err'); input.focus(); return; }
  busy(btn, true);
  try {
    const r = await act('/api/blocklists/test', { method: 'POST', body: { domain: domain } }, null);
    if (!r) return;
    setKids(out, [
      el('span', { class: 'mono small' }, domain),
      r.blocked ? pill('blocked', 'blocked') : pill('allowed', 'allowed'),
      el('span', { class: 'test-reason' }, 'reason: ' + (r.reason || 'none'))
    ]);
  } finally {
    busy(btn, false);
  }
}

/* ==================================================================== dns */

function renderDns() {
  const page = clear(document.getElementById('page-dns'));

  const urlField = el('input', {
    class: 'input', type: 'url', id: 'dns-url', autocomplete: 'off', spellcheck: 'false',
    placeholder: 'https://dns.quad9.net/dns-query'
  });
  const urlWrap = el('div', { class: 'field', style: 'margin-top:14px' },
    el('label', { class: 'label', for: 'dns-url' }, 'Resolver URL'),
    urlField,
    el('p', { class: 'field-hint' }, 'Required for DoH and DoT; ignored for System and Plain.'));

  const upSeg = seg([
    { value: 'system', label: 'System' },
    { value: 'doh', label: 'DoH' },
    { value: 'dot', label: 'DoT' },
    { value: 'plain', label: 'Plain' }
  ], 'doh', (v) => { urlWrap.hidden = !(v === 'doh' || v === 'dot'); }, 'Upstream resolver mode');
  urlWrap.hidden = true;

  const upSave = el('button', { class: 'btn btn-primary', type: 'submit' }, 'Save upstream');
  const upForm = el('form', {
    onsubmit: (e) => { e.preventDefault(); saveUpstream(); }
  },
    el('div', { class: 'field' },
      el('span', { class: 'label' }, 'Resolver mode'), upSeg.node),
    urlWrap, upSave);

  const hijackSw = switchEl({
    checked: false, label: 'DNS hijack',
    onChange: (on) => setHijack(on)
  });
  const hijackState = el('span', { class: 'chip-value' }, '—');

  const domainInput = el('input', {
    class: 'input', type: 'text', id: 'dns-domain', autocomplete: 'off', spellcheck: 'false',
    placeholder: 'ads.example.com'
  });
  const domainSeg = seg(
    [{ value: 'block', label: 'Block' }, { value: 'allow', label: 'Allow' }],
    'block', null, 'Rule action');
  const addBtn = el('button', { class: 'btn btn-primary', type: 'submit' }, icon('plus'), 'Add rule');
  const domainForm = el('form', {
    class: 'inline-form',
    onsubmit: (e) => { e.preventDefault(); addDomainRule(); }
  },
    el('div', { class: 'grow' },
      el('label', { class: 'label', for: 'dns-domain' }, 'Domain'), domainInput),
    el('div', null, el('span', { class: 'label' }, 'Action'), domainSeg.node),
    addBtn);

  const blockCol = el('div', { class: 'rule-chips' });
  const allowCol = el('div', { class: 'rule-chips' });
  const counts = el('span', { class: 'toolbar-note' }, '');
  const log = el('div', { class: 'log' }, skeleton(6));
  const clearBtn = el('button', { class: 'btn btn-ghost btn-sm', type: 'button' },
    icon('trash'), 'Clear log');
  clearBtn.addEventListener('click', clearDnsLog);

  state.refs.dns = {
    upSeg: upSeg, urlField: urlField, urlWrap: urlWrap, hijackSw: hijackSw,
    hijackState: hijackState, domainInput: domainInput, domainSeg: domainSeg,
    blockCol: blockCol, allowCol: allowCol, counts: counts, log: log
  };

  page.appendChild(el('div', { class: 'grid-2' },
    el('section', { class: 'card' },
      el('header', { class: 'card-head' },
        el('div', null,
          el('h2', null, 'Upstream resolver'),
          el('p', { class: 'card-sub' }, 'Where queries are forwarded for an answer.'))),
      upForm),
    el('section', { class: 'card' },
      el('header', { class: 'card-head' },
        el('div', null,
          el('h2', null, 'DNS hijack'),
          el('p', { class: 'card-sub' },
            'Answer every port-53 query on this machine with rethinkd, even from apps that try to bypass it.')),
        hijackSw.node),
      hijackState)));

  page.appendChild(el('section', { class: 'card' },
    el('header', { class: 'card-head' }, el('h2', null, 'Per-domain rules')),
    domainForm,
    el('div', { class: 'rules-grid' },
      el('div', { class: 'rule-col' },
        el('div', { class: 'rule-col-title' },
          el('span', null, 'Blocked'), el('span', { class: 'rule-count' }, '0')),
        blockCol),
      el('div', { class: 'rule-col' },
        el('div', { class: 'rule-col-title' },
          el('span', null, 'Allowed'), el('span', { class: 'rule-count' }, '0')),
        allowCol))));

  page.appendChild(el('section', { class: 'card' },
    el('header', { class: 'card-head' },
      el('div', null, el('h2', null, 'Query log'), counts),
      clearBtn),
    log));

  loadDns();
  every(4000, loadDnsLog);
}

async function loadDns() {
  try {
    const data = await api('/api/dns');
    if (state.page !== 'dns') return;
    state.dns = data;
    paintDnsForms();
    paintDnsLog();
  } catch (e) {
    if (state.page === 'dns') fail(e, state.refs.dns && state.refs.dns.log, loadDns);
  }
}

/* Background refresh: repaints the log only, so in-progress form input
   (upstream URL, domain being typed) is never clobbered. */
async function loadDnsLog() {
  if (state.page !== 'dns') return;
  try {
    const data = await api('/api/dns');
    if (state.page !== 'dns') return;
    state.dns = data;
    paintDnsLog();
  } catch (e) { /* the connection dot already reflects the state */ }
}

function paintDnsForms() {
  const refs = state.refs.dns;
  const data = state.dns;
  if (!refs || !data) return;

  const up = data.upstream || {};
  refs.upSeg.set(up.type || 'system');
  refs.urlWrap.hidden = !(up.type === 'doh' || up.type === 'dot');
  if (document.activeElement !== refs.urlField) refs.urlField.value = up.url || '';

  refs.hijackSw.set(!!data.hijack);
  refs.hijackState.textContent = data.hijack
    ? 'On — every local port-53 query is answered by rethinkd.'
    : 'Off — clients keep using whatever resolver the system configures.';
  refs.hijackState.className = 'chip-value ' + (data.hijack ? 'on' : 'off');

  const block = data.block || [];
  const allow = data.allow || [];

  const counters = document.querySelectorAll('.rule-count');
  if (counters[0]) counters[0].textContent = fmtInt(block.length);
  if (counters[1]) counters[1].textContent = fmtInt(allow.length);

  fillRuleCol(refs.blockCol, block, 'block');
  fillRuleCol(refs.allowCol, allow, 'allow');
}

function fillRuleCol(node, domains, kind) {
  clear(node);
  if (!domains.length) {
    node.appendChild(el('span', { class: 'small muted' },
      kind === 'block' ? 'No blocked domains.' : 'No allowed domains.'));
    return;
  }
  domains.forEach((domain) => {
    node.appendChild(el('span', { class: 'rule-chip is-' + kind },
      el('span', { title: domain }, domain),
      el('button', {
        class: 'x', type: 'button',
        'aria-label': 'Remove ' + domain + ' from the ' + kind + ' list',
        onclick: () => removeDomainRule(domain)
      }, icon('x'))));
  });
}

function paintDnsLog() {
  const refs = state.refs.dns;
  const data = state.dns;
  if (!refs || !data) return;

  refs.counts.textContent = fmtInt(data.queries) + ' queries · ' + fmtInt(data.blocked) + ' blocked';

  const log = clear(refs.log);
  const entries = data.log || [];
  if (!entries.length) {
    log.appendChild(emptyBox('No queries yet',
      'Lookups handled by rethinkd stream in here every few seconds.'));
    return;
  }
  entries.forEach((entry) => log.appendChild(logRow(entry)));
}

function logRow(entry) {
  const blocked = !!entry.blocked;
  return el('div', { class: 'log-row' + (blocked ? ' is-blocked' : '') },
    el('span', { class: 'log-time' }, hhmmss(entry.t)),
    el('span', { class: 'log-name', title: entry.name }, entry.name),
    el('span', { class: 'log-type' }, entry.type || ''),
    pill(blocked ? 'blocked' : 'allowed', blocked ? 'blocked' : 'allowed', entry.reason),
    el('span', { class: 'log-client' }, entry.client || '—'));
}

async function saveUpstream() {
  const refs = state.refs.dns;
  if (!refs) return;
  const type = refs.upSeg.get();
  const needsUrl = type === 'doh' || type === 'dot';
  const url = refs.urlField.value.trim();
  if (needsUrl && !url) {
    toast('Enter the resolver URL', 'err');
    refs.urlField.focus();
    return;
  }
  const ok = await act('/api/dns/upstream',
    { method: 'POST', body: { type: type, url: needsUrl ? url : '' } }, 'Upstream saved');
  if (ok) await loadDns();
}

async function setHijack(on) {
  const refs = state.refs.dns;
  const ok = await act('/api/dns/hijack', { method: 'POST', body: { enabled: on } },
    on ? 'DNS hijack enabled' : 'DNS hijack disabled');
  if (ok) await loadDns();
  else if (refs) refs.hijackSw.set(!on);
}

async function addDomainRule() {
  const refs = state.refs.dns;
  if (!refs) return;
  const domain = refs.domainInput.value.trim().toLowerCase();
  if (!domain) { toast('Enter a domain', 'err'); refs.domainInput.focus(); return; }
  const action = refs.domainSeg.get();
  const ok = await act('/api/dns/domain',
    { method: 'POST', body: { domain: domain, action: action } }, 'Rule added');
  if (ok) { refs.domainInput.value = ''; await loadDns(); }
}

async function removeDomainRule(domain) {
  const data = state.dns;
  if (data) {
    data.block = (data.block || []).filter((d) => d !== domain);
    data.allow = (data.allow || []).filter((d) => d !== domain);
    paintDnsForms();
  }
  const ok = await act('/api/dns/domain/' + encodeURIComponent(domain),
    { method: 'DELETE' }, 'Rule removed');
  if (ok) await loadDns();
}

async function clearDnsLog() {
  const yes = await confirmBox('Clear the query log?',
    'The in-memory DNS query log will be emptied.', 'Clear log');
  if (!yes) return;
  const ok = await act('/api/dns/clearlog', { method: 'POST' }, 'Log cleared');
  if (ok) await loadDns();
}

/* ================================================================== proxy */

function renderProxy() {
  const page = clear(document.getElementById('page-proxy'));

  const enableSw = switchEl({
    checked: false, label: 'Enable proxy',
    onChange: (on) => setProxyEnabled(on)
  });
  const typeSeg = seg(
    [{ value: 'http', label: 'HTTP' }, { value: 'socks5', label: 'SOCKS5' }],
    'http', null, 'Proxy type');

  const hostInput = el('input', {
    class: 'input', type: 'text', id: 'px-host', autocomplete: 'off', placeholder: '127.0.0.1'
  });
  const portInput = el('input', {
    class: 'input', type: 'number', id: 'px-port', min: '1', max: '65535', placeholder: '8080'
  });
  const userInput = el('input', {
    class: 'input', type: 'text', id: 'px-user', autocomplete: 'off', placeholder: 'optional'
  });
  const passInput = el('input', {
    class: 'input', type: 'password', id: 'px-pass', autocomplete: 'new-password', placeholder: '••••••'
  });
  const passHint = el('p', { class: 'field-hint' }, 'Write-only — sent only when you type a value.');
  const lanInput = el('input', { type: 'checkbox', id: 'px-lan', checked: true });
  const bypassInput = el('input', {
    class: 'input', type: 'text', id: 'px-bypass', autocomplete: 'off',
    placeholder: '*.local, *.internal'
  });
  const preview = el('div', { class: 'chips-preview' });

  bypassInput.addEventListener('input', () => paintBypassPreview(bypassInput.value, preview));

  const saveBtn = el('button', { class: 'btn btn-primary', type: 'submit' }, 'Save proxy settings');
  const form = el('form', {
    onsubmit: (e) => { e.preventDefault(); saveProxy(); }
  },
    el('div', { class: 'form-grid' },
      el('div', { class: 'field' }, el('span', { class: 'label' }, 'Type'), typeSeg.node),
      el('div', { class: 'field' },
        el('label', { class: 'label', for: 'px-host' }, 'Host'), hostInput),
      el('div', { class: 'field' },
        el('label', { class: 'label', for: 'px-port' }, 'Port'), portInput),
      el('div', { class: 'field' },
        el('label', { class: 'label', for: 'px-user' }, 'Username'), userInput),
      el('div', { class: 'field' },
        el('label', { class: 'label', for: 'px-pass' }, 'Password'), passInput, passHint)),
    el('div', { class: 'field', style: 'margin-top:14px' },
      el('span', { class: 'label' }, 'Bypass'),
      el('label', { class: 'check' }, lanInput,
        el('span', null,
          el('strong', null, 'Bypass LAN'),
          el('span', { class: 'field-hint', style: 'display:block' },
            'Keep private ranges (127.0.0.0/8, 10/8, 172.16/12, 192.168/16, *.local) out of the relay so local services stay reachable.')))),
    el('div', { class: 'field' },
      el('label', { class: 'label', for: 'px-bypass' }, 'Bypass domains'),
      bypassInput,
      el('p', { class: 'field-hint' }, 'Comma-separated hosts or wildcards never sent through the proxy.'),
      preview),
    saveBtn);

  const stats = el('div', { class: 'kv-list' }, skeleton(4));
  state.refs.proxy = {
    enableSw: enableSw, typeSeg: typeSeg, host: hostInput, port: portInput,
    user: userInput, pass: passInput, passHint: passHint, lan: lanInput,
    bypass: bypassInput, preview: preview, stats: stats, passDirty: false
  };
  passInput.addEventListener('input', () => { state.refs.proxy.passDirty = true; });

  page.appendChild(el('div', { class: 'grid-2' },
    el('section', { class: 'card' },
      el('header', { class: 'card-head' },
        el('div', null,
          el('h2', null, 'Relay'),
          el('p', { class: 'card-sub' }, 'Forward app traffic through an upstream HTTP or SOCKS5 proxy.')),
        enableSw.node),
      form),
    el('section', { class: 'card' },
      el('header', { class: 'card-head' }, el('h2', null, 'Status')),
      stats)));

  loadProxy();
}

async function loadProxy() {
  try {
    const data = await api('/api/proxy');
    if (state.page !== 'proxy') return;
    state.proxy = data;
    paintProxy();
  } catch (e) {
    if (state.page === 'proxy') fail(e, state.refs.proxy && state.refs.proxy.stats, loadProxy);
  }
}

function paintProxy() {
  const refs = state.refs.proxy;
  const p = state.proxy;
  if (!refs || !p) return;

  refs.enableSw.set(!!p.enabled);
  refs.typeSeg.set(p.type || 'http');
  if (document.activeElement !== refs.host) refs.host.value = p.host || '';
  if (document.activeElement !== refs.port) refs.port.value = p.port || '';
  if (document.activeElement !== refs.user) refs.user.value = p.username || '';
  if (document.activeElement !== refs.bypass) refs.bypass.value = (p.bypass_domains || []).join(', ');
  if (document.activeElement !== refs.pass) refs.pass.value = '';
  refs.passDirty = false;
  refs.lan.checked = !!p.bypass_lan;
  refs.passHint.textContent = p.password_set
    ? 'A password is stored. Leave blank to keep it.'
    : 'Write-only — sent only when you type a value.';
  paintBypassPreview(refs.bypass.value, refs.preview);

  const stats = clear(refs.stats);
  setKids(stats, [
    kv('Enabled', p.enabled ? pill('allowed', 'on') : pill('muted', 'off')),
    kv('Type', (p.type || '—').toUpperCase()),
    kv('Endpoint', p.enabled
      ? (p.type || '?') + '://' + (p.host || '?') + ':' + (p.port || '?')
      : '—', true),
    kv('Active connections', fmtInt(p.active)),
    kv('Relayed', fmtInt(p.relayed)),
    kv('Password', p.password_set ? 'set' : 'not set'),
    p.last_error
      ? kv('Last error', pill('warn', p.last_error))
      : kv('Last error', el('span', { class: 'muted small' }, 'none'))
  ]);
}

function kv(label, value, mono) {
  return el('div', { class: 'kv' },
    el('span', { class: 'kv-label' }, label),
    el('span', { class: 'kv-value' + (mono ? ' mono' : '') }, value));
}

function paintBypassPreview(value, node) {
  const items = String(value).split(/[\s,]+/).filter(Boolean);
  clear(node);
  if (!items.length) {
    node.appendChild(el('span', { class: 'small muted' }, 'No bypass domains.'));
    return;
  }
  items.forEach((item) => node.appendChild(el('span', { class: 'chip-tag' }, item)));
}

async function setProxyEnabled(on) {
  const p = state.proxy;
  if (p) p.enabled = on;
  const ok = await act('/api/proxy/toggle', { method: 'POST', body: { enabled: on } },
    on ? 'Proxy enabled' : 'Proxy disabled');
  if (ok) await loadProxy();
  else if (p) { p.enabled = !on; paintProxy(); }
}

async function saveProxy() {
  const refs = state.refs.proxy;
  const p = state.proxy;
  if (!refs || !p) return;

  const host = refs.host.value.trim();
  const port = parseInt(refs.port.value, 10);
  if (!host) { toast('Host is required', 'err'); refs.host.focus(); return; }
  if (!(port >= 1 && port <= 65535)) {
    toast('Port must be between 1 and 65535', 'err');
    refs.port.focus();
    return;
  }

  const body = {
    enabled: !!p.enabled,
    type: refs.typeSeg.get(),
    host: host,
    port: port,
    username: refs.user.value.trim(),
    bypass_lan: refs.lan.checked,
    bypass_domains: refs.bypass.value.split(/[\s,]+/).filter(Boolean)
  };
  /* password is write-only: included only when the field was actually edited */
  if (refs.passDirty && refs.pass.value) body.password = refs.pass.value;

  const ok = await act('/api/proxy', { method: 'POST', body: body }, 'Proxy settings saved');
  if (ok) {
    refs.pass.value = '';
    refs.passDirty = false;
    await loadProxy();
  }
}

/* =============================================================== activity */

function renderActivity() {
  const page = clear(document.getElementById('page-activity'));

  const feed = el('div', { class: 'feed' }, skeleton(6));
  const note = el('span', { class: 'toolbar-note' }, '');
  const pauseBtn = el('button', { class: 'btn btn-ghost btn-sm', type: 'button' });
  const refreshBtn = el('button', { class: 'icon-btn', type: 'button', title: 'Refresh now' },
    icon('refresh'));
  refreshBtn.setAttribute('aria-label', 'Refresh activity now');
  refreshBtn.addEventListener('click', () => loadActivity());

  state.refs.act = { feed: feed, note: note, pauseBtn: pauseBtn };

  const filters = el('div', { class: 'filters' });
  const filterBtns = [
    ['all', 'All'], ['dns', 'DNS'], ['firewall', 'Firewall'], ['proxy', 'Proxy']
  ].map(([value, label]) => {
    const btn = el('button', {
      class: 'chip-btn' + (state.activityFilter === value ? ' is-active' : ''),
      type: 'button', 'aria-pressed': String(state.activityFilter === value),
      onclick: () => {
        state.activityFilter = value;
        filterBtns.forEach((b) => {
          const on = b.dataset.value === value;
          b.classList.toggle('is-active', on);
          b.setAttribute('aria-pressed', String(on));
        });
        paintActivity();
      },
      'data-value': value
    }, label);
    filters.appendChild(btn);
    return btn;
  });

  pauseBtn.addEventListener('click', () => {
    state.activityPaused = !state.activityPaused;
    paintPauseBtn();
    if (!state.activityPaused) loadActivity();
  });
  paintPauseBtn();

  page.appendChild(el('section', { class: 'card' },
    el('div', { class: 'toolbar' },
      el('span', { class: 'toolbar-title' }, 'Event feed'),
      note,
      el('span', { class: 'spacer' }),
      filters,
      refreshBtn,
      pauseBtn),
    feed));

  loadActivity();
  every(5000, () => { if (!state.activityPaused) loadActivity(); });
}

function paintPauseBtn() {
  const refs = state.refs.act;
  if (!refs) return;
  const paused = state.activityPaused;
  setKids(refs.pauseBtn, [
    icon(paused ? 'play' : 'pause'),
    paused ? 'Resume' : 'Pause'
  ]);
  refs.pauseBtn.setAttribute('aria-pressed', String(paused));
  refs.pauseBtn.title = paused ? 'Resume live updates' : 'Pause live updates';
}

async function loadActivity() {
  try {
    const data = await api('/api/activity?limit=200');
    if (state.page !== 'activity') return;
    state.events = data.events || [];
    paintActivity();
  } catch (e) {
    if (state.page === 'activity') fail(e, state.refs.act && state.refs.act.feed, loadActivity);
  }
}

function paintActivity() {
  const refs = state.refs.act;
  if (!refs) return;

  const all = state.events || [];
  const filter = state.activityFilter;
  const events = filter === 'all' ? all : all.filter((e) => e.kind === filter);

  refs.note.textContent = (state.activityPaused ? 'paused · ' : '') +
    fmtInt(events.length) + ' of ' + fmtInt(all.length) + ' events';

  const feed = clear(refs.feed);
  if (!all.length) {
    feed.appendChild(emptyBox('No activity yet',
      'DNS lookups, dropped connections and proxied flows appear here as they happen.'));
    return;
  }
  if (!events.length) {
    feed.appendChild(emptyBox('Nothing matches this filter',
      'Switch back to All to see every event rethinkd has handled.'));
    return;
  }
  events.forEach((event) => feed.appendChild(activityRow(event)));
}

function activityRow(event) {
  const kindIcon = { dns: 'dns', firewall: 'shield', proxy: 'proxy' }[event.kind] || 'activity';
  const action = event.action || 'allowed';
  const tone = action === 'blocked' ? 'blocked' : (action === 'relayed' ? 'relayed' : 'allowed');

  const detail = el('div', { class: 'feed-detail' },
    event.app ? el('span', { class: 'feed-app', title: event.app }, event.app) : null,
    event.reason ? el('span', null, (event.app ? ' · ' : '') + event.reason) : null);

  return el('div', { class: 'feed-row' + (tone === 'blocked' ? ' is-blocked' : '') },
    el('span', { class: 'feed-icon' }, icon(kindIcon)),
    el('span', { class: 'feed-time' }, hhmmss(event.t)),
    el('div', { class: 'feed-body' },
      el('div', { class: 'feed-name', title: event.name || '' }, event.name || '—'),
      (event.app || event.reason) ? detail : null),
    pill(tone, action));
}

/* =============================================================== settings */

function renderSettings() {
  const page = clear(document.getElementById('page-settings'));
  const body = el('div', { class: 'settings-grid' }, skeleton(3));
  state.refs.settings = { body: body };
  page.appendChild(body);
  loadSettings();
}

async function loadSettings() {
  try {
    const data = await api('/api/settings');
    if (state.page !== 'settings') return;
    state.settings = data;
    applyTheme(data.theme);
    paintSettings();
  } catch (e) {
    if (state.page === 'settings') fail(e, state.refs.settings && state.refs.settings.body, loadSettings);
  }
}

function paintSettings() {
  const refs = state.refs.settings;
  const s = state.settings;
  if (!refs || !s) return;
  const body = clear(refs.body);

  const themeSelect = el('select', { class: 'select', id: 'set-theme' },
    el('option', { value: 'dark' }, 'Dark'),
    el('option', { value: 'light' }, 'Light'),
    el('option', { value: 'system' }, 'System'));
  themeSelect.value = s.theme || 'dark';
  themeSelect.addEventListener('change', () => {
    applyTheme(themeSelect.value);
    saveSettings({ theme: themeSelect.value }, 'Theme saved');
  });

  const startInput = el('input', { type: 'checkbox', id: 'set-start', checked: !!s.start_protected });
  startInput.addEventListener('change', () =>
    saveSettings({ start_protected: startInput.checked }, 'Saved'));

  const levelSelect = el('select', { class: 'select', id: 'set-level' },
    ['debug', 'info', 'warn', 'error'].map((lv) => el('option', { value: lv }, lv)));
  levelSelect.value = s.log_level || 'info';
  levelSelect.addEventListener('change', () =>
    saveSettings({ log_level: levelSelect.value }, 'Log level saved'));

  const listenInput = el('input', {
    class: 'input', type: 'text', id: 'set-listen', value: s.listen || '', readonly: true
  });

  const tokenValue = el('code', { class: 'token-value' }, '••••••••');
  const revealBtn = el('button', { class: 'icon-btn', type: 'button', 'aria-label': 'Show token hint' });
  let revealed = false;
  revealBtn.addEventListener('click', () => {
    revealed = !revealed;
    tokenValue.textContent = revealed ? (s.token_hint || '—') : '••••••••';
    clear(revealBtn).appendChild(icon('eye'));
    revealBtn.setAttribute('aria-label', revealed ? 'Hide token hint' : 'Show token hint');
    revealBtn.title = revealed ? 'Hide token hint' : 'Show token hint';
  });
  clear(revealBtn).appendChild(icon('eye'));
  revealBtn.title = 'Show token hint';

  body.appendChild(el('section', { class: 'card' },
    el('header', { class: 'card-head' }, el('h2', null, 'Appearance & behaviour')),
    settingRow('Theme', 'Dark, light, or follow the desktop preference.',
      el('div', { class: 'setting-control' }, themeSelect), 'set-theme'),
    settingRow('Start protected', 'Turn protection on automatically when rethinkd starts.',
      el('label', { class: 'check' }, startInput, el('span', null, s.start_protected ? 'On' : 'Off')), null),
    settingRow('Log level', 'Verbosity of the daemon journal.',
      el('div', { class: 'setting-control' }, levelSelect), 'set-level')));

  body.appendChild(el('section', { class: 'card' },
    el('header', { class: 'card-head' }, el('h2', null, 'Daemon')),
    settingRow('Listen address', 'Where this UI and API are served (read-only).',
      el('div', { class: 'setting-control' }, listenInput), 'set-listen'),
    el('div', { class: 'setting-row' },
      el('div', { class: 'setting-info' },
        el('div', { class: 'setting-name' }, 'Token hint'),
        el('div', { class: 'setting-desc' },
          'Only a prefix is ever shown. Rotate the full token with rethinkctl token.')),
      el('div', { class: 'token-row setting-control' }, tokenValue, revealBtn))));

  const version = (state.session && state.session.version) ||
    (state.status && state.status.version) || '—';
  body.appendChild(el('section', { class: 'card' },
    el('header', { class: 'card-head' }, el('h2', null, 'About')),
    el('div', { class: 'about-list' },
      aboutItem('Version', 'rethinkd ' + version),
      aboutItem('License', 'Apache-2.0'),
      aboutItem('Repository',
        el('a', {
          href: 'https://github.com/kusal630/rethink-root-linux', target: '_blank',
          rel: 'noreferrer noopener'
        }, 'github.com/kusal630/rethink-root-linux')),
      aboutItem('API docs',
        el('a', {
          href: 'https://github.com/kusal630/rethink-root-linux/blob/main/docs/api.md',
          target: '_blank', rel: 'noreferrer noopener'
        }, 'docs/api.md')),
      aboutItem('Privacy', 'Everything is local: no telemetry, no external requests.'))));
}

function settingRow(name, desc, control, htmlFor) {
  return el('div', { class: 'setting-row' },
    el('div', { class: 'setting-info' },
      el('label', { class: 'setting-name', for: htmlFor }, name),
      el('div', { class: 'setting-desc' }, desc)),
    control);
}

function aboutItem(key, value) {
  return el('div', { class: 'about-item' },
    el('span', { class: 'about-key' }, key),
    el('span', null, value));
}

async function saveSettings(patch, msg) {
  const base = state.settings || {};
  const body = {
    theme: patch.theme !== undefined ? patch.theme : (base.theme || 'dark'),
    start_protected: patch.start_protected !== undefined
      ? patch.start_protected : !!base.start_protected,
    log_level: patch.log_level !== undefined ? patch.log_level : (base.log_level || 'info')
  };
  const ok = await act('/api/settings', { method: 'POST', body: body }, msg || 'Saved');
  if (ok) {
    try { state.settings = await api('/api/settings'); }
    catch (e) { /* keep the local copy */ }
  }
}

function applyTheme(theme) {
  const wanted = (theme === 'light' || theme === 'system') ? theme : 'dark';
  try { localStorage.setItem('rethink_theme', wanted); } catch (e) { /* storage blocked */ }
  const resolved = wanted === 'system'
    ? (window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark')
    : wanted;
  document.documentElement.setAttribute('data-theme', resolved);
}

/* ============================================================ global wiring */

document.getElementById('nav').addEventListener('click', (e) => {
  const btn = e.target.closest('.nav-item');
  if (btn) go(btn.dataset.page);
});

document.getElementById('menu-btn').addEventListener('click', toggleDrawer);
document.getElementById('side-scrim').addEventListener('click', closeDrawer);
document.getElementById('protect-btn').addEventListener('click', toggleProtection);
document.getElementById('connect-form').addEventListener('submit', onConnectSubmit);
document.getElementById('connect-retry').addEventListener('click', () => boot());
document.getElementById('copy-cmd').addEventListener('click', copyCmd);
document.getElementById('modal-ok').addEventListener('click', () => closeModal(true));
document.getElementById('modal-cancel').addEventListener('click', () => closeModal(false));
document.querySelector('#modal .modal-scrim').addEventListener('click', () => closeModal(false));

document.addEventListener('keydown', (e) => {
  if (e.key !== 'Escape') return;
  if (!document.getElementById('modal').hidden) { closeModal(false); return; }
  if (document.querySelector('.toast')) { clearToasts(); return; }
  closeDrawer();
});

window.addEventListener('hashchange', () => {
  const name = pageFromHash();
  if (name !== state.page) go(name);
});

document.addEventListener('visibilitychange', () => {
  if (!document.hidden && state.session) pollStatus();
});

window.matchMedia('(prefers-color-scheme: light)').addEventListener('change', () => {
  if ((state.settings || {}).theme === 'system') applyTheme('system');
});

boot();
