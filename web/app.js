/* CERBERUS web UI — dependency-free SPA. All dynamic text goes through esc():
   event and log content is attacker-influenced and must never reach innerHTML raw. */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const app = $('#app');
  const REFRESH_MS = 30000;
  const CHAT_KEY = 'cerberus-chat-id';
  const APP_VERSION = '0.2.0'; // must match VERSION in backend/app/main.py
  const state = { user: null, chat: [], chatId: null, convos: [], busy: false, live: null, abort: null, presets: [], hidden: {}, sorts: {}, apps: [], appsLoaded: false, navKey: '', emailReady: false, aiReady: false, aiTools: [], investigating: false };

  const esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const safeUrl = (u) => (/^https?:\/\//i.test(String(u || '')) ? String(u) : '');
  const fmtTime = (ts) => {
    if (!ts) return '—';
    const d = new Date(ts);
    return isNaN(d) ? esc(ts) : d.toLocaleString([], { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  };
  const ago = (ts) => {
    const s = Math.max(0, (Date.now() - new Date(ts).getTime()) / 1000);
    if (isNaN(s)) return '—';
    if (s < 90) return 'just now';
    if (s < 5400) return `${Math.round(s / 60)} min ago`;
    if (s < 129600) return `${Math.round(s / 3600)} h ago`;
    return `${Math.round(s / 86400)} d ago`;
  };
  const agoCell = (ts) => (ts ? `<span title="${esc(fmtTime(ts))}">${ago(ts)}</span>` : '—');
  const sevBadge = (label, sev) => `<span class="badge ${esc(label)}">${esc(label)}${sev ? ` · ${esc(sev)}` : ''}</span>`;
  const statusBadge = (s) => {
    const cls = { open: 'high', investigating: 'info', contained: 'medium', resolved: 'ok', false_positive: 'low',
      pending: 'high', approved: 'ok', denied: 'low', expired: 'low' }[s] || '';
    return `<span class="badge ${cls}">${esc(String(s).replace('_', ' '))}</span>`;
  };
  const demoBadge = (flag) => (flag ? ' <span class="badge">demo</span>' : '');
  const isAdmin = () => Boolean(state.user && state.user.role === 'admin');
  const roleName = (role) => (role === 'admin' ? 'Admin' : 'Analyst');

  const ICONS = {
    home: 'M3 11l9-8 9 8M5 10v10h5v-6h4v6h5V10',
    chat: 'M4 5h16v11H9l-5 4z',
    alert: 'M12 3l10 18H2zM12 10v5M12 18v.5',
    list: 'M4 6h16M4 12h16M4 18h16',
    server: 'M4 4h16v6H4zM4 14h16v6H4zM8 7h.5M8 17h.5',
    check: 'M9 12l2 2 4-4M12 3l8 3v6c0 5-3.500 8-8 9-4.500-1-8-4-8-9V6z',
    spark: 'M12 3l2 6 6 2-6 2-2 6-2-6-6-2 6-2z',
    plug: 'M9 3v5M15 3v5M6 8h12v4a6 6 0 01-12 0zM12 18v3',
    clock: 'M12 7v5l3 2M12 21a9 9 0 100-18 9 9 0 000 18z',
    search: 'M11 18a7 7 0 100-14 7 7 0 000 14zM20 20l-4-4',
    send: 'M5 12h14M13 6l6 6-6 6',
    stop: 'M7 7h10v10H7z',
    logout: 'M10 4H5v16h5M15 8l4 4-4 4M19 12H9',
    sun: 'M12 17a5 5 0 100-10 5 5 0 000 10zM12 2v2M12 20v2M4.900 4.900l1.400 1.400M17.700 17.700l1.400 1.400M2 12h2M20 12h2M4.900 19.100l1.400-1.400M17.700 6.300l1.400-1.400',
    moon: 'M20 14.500A8.500 8.500 0 019.500 4 8.500 8.500 0 1020 14.500z',
    menu: 'M4 7h16M4 12h16M4 17h16',
    copy: 'M9 9h11v11H9zM5 15H4V4h11v1',
    plus: 'M12 5v14M5 12h14',
    retry: 'M4 12a8 8 0 0113.700-5.700L20 8M20 4v4h-4M20 12a8 8 0 01-13.700 5.700L4 16M4 20v-4h4',
    tool: 'M14 6a4 4 0 005 5l-9 9-4-4 9-9z',
    inbox: 'M3 13l3-8h12l3 8v6H3zM3 13h5l1 3h6l1-3h5',
    edit: 'M4 20h4L19 9l-4-4L4 16zM13 7l4 4',
    close: 'M6 6l12 12M18 6L6 18',
    trash: 'M5 7h14M10 7V4h4v3M7 7l1 13h8l1-13',
    bell: 'M6 16v-5a6 6 0 0112 0v5l2 2H4zM10 20a2 2 0 004 0',
    users: 'M9 11a4 4 0 100-8 4 4 0 000 8zM2 21a7 7 0 0114 0M17 4a4 4 0 010 7M18 14a7 7 0 014 7',
    megaphone: 'M4 10v4h3l6 4V6l-6 4zM17 9a4 4 0 010 6',
    chevron: 'M6 15l6-6 6 6',
    user: 'M12 12a4 4 0 100-8 4 4 0 000 8zM4 21a8 8 0 0116 0',
    eye: 'M2 12s4-7 10-7 10 7 10 7-4 7-10 7S2 12 2 12zM12 15a3 3 0 100-6 3 3 0 000 6z',
    terminal: 'M4 5h16v14H4zM7 9l3 3-3 3M12 15h5',
    activity: 'M3 12h4l3-8 4 16 3-8h4',
    play: 'M8 5l11 7-11 7z',
    panel: 'M4 5h16v14H4zM10 5v14',
    download: 'M12 4v11M7 11l5 5 5-5M5 20h14',
    star: 'M12 4l2.400 5 5.600.800-4 3.900.900 5.500-4.900-2.600-4.900 2.600.900-5.500-4-3.900 5.600-.800z',
    mail: 'M3 6h18v12H3zM3 7l9 6 9-6',
    grid: 'M4 4h7v7H4zM13 4h7v7h-7zM4 13h7v7H4zM13 13h7v7h-7z',
    cloud: 'M7 18a4 4 0 010-8 5.5 5.5 0 0110.6-1.5A4.5 4.5 0 0117.5 18z',
    layers: 'M12 4l9 5-9 5-9-5zM3 14l9 5 9-5',
    shield: 'M12 3l8 3v6c0 5-3.5 8-8 9-4.5-1-8-4-8-9V6zM12 8v5M12 16v.5',
    external: 'M14 4h6v6M20 4l-9 9M18 14v6H4V6h6',
  };
  const icon = (name, size = 18) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.700" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${ICONS[name]}"/></svg>`;

  // The CERBERUS mark: a three-peak pulse crossing a dotted threshold line.
  const logo = () => `<svg class="logo-mark" viewBox="0 0 143 100" role="img" aria-label="CERBERUS"><g class="logo-dash"><rect x="4.0" y="34" width="7" height="4.500"/><rect x="17.6" y="34" width="7" height="4.500"/><rect x="31.2" y="34" width="7" height="4.500"/><rect x="44.8" y="34" width="7" height="4.500"/><rect x="58.4" y="34" width="7" height="4.500"/><rect x="72.0" y="34" width="7" height="4.500"/><rect x="85.6" y="34" width="7" height="4.500"/><rect x="99.2" y="34" width="7" height="4.500"/><rect x="112.8" y="34" width="7" height="4.500"/><rect x="126.4" y="34" width="7" height="4.500"/></g><path d="M0 77H27.300L44.500 32 56.700 62 67 0H76L86.300 62 98.500 32 115.700 77H143V86H108.800L98.500 59 82.800 99.500 71.500 29 60.200 99.500 44.500 59 34.200 86H0Z" fill="currentColor"/></svg>`;
  const ACCENTS = [['teal', 'Teal', '#0f766e'], ['indigo', 'Indigo', '#4f46e5'], ['blue', 'Blue', '#2563eb'], ['violet', 'Violet', '#7c3aed']];
  const pref = {
    get(key, fallback) { try { return localStorage.getItem(`cerberus-${key}`) || fallback; } catch { return fallback; } },
    set(key, value) { try { localStorage.setItem(`cerberus-${key}`, value); } catch { /* storage blocked */ } },
  };

  // ---------- plumbing ----------

  function errorDetail(data, status) {
    let detail = data && data.detail;
    if (Array.isArray(detail)) detail = detail.map((d) => `${(d.loc || []).slice(-1)[0]}: ${d.msg}`).join('; ');
    return detail || `Request failed (${status})`;
  }

  async function api(path, { method = 'GET', body } = {}) {
    const res = await fetch(`/api/v1${path}`, {
      method,
      headers: body === undefined ? {} : { 'Content-Type': 'application/json' },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
    });
    let data = null;
    try { data = await res.json(); } catch { /* empty body */ }
    if (res.status === 401 && state.user) { state.user = null; boot(); }
    if (!res.ok) throw new Error(errorDetail(data, res.status));
    return data;
  }

  let toastTimer;
  function toast(message, bad = false) {
    const el = $('#toast');
    el.textContent = message;
    el.className = `toast show${bad ? ' bad' : ''}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.className = 'toast'; }, bad ? 6000 : 3000);
  }
  const fail = (err) => toast(err.message || String(err), true);

  // Resolves to false when cancelled, otherwise { note, value }.
  function confirmDialog({ title, text, ok = 'Confirm', danger = false, note = false, input = null }) {
    return new Promise((resolve) => {
      const d = document.createElement('dialog');
      d.className = 'modal';
      d.innerHTML = `<form method="dialog"><h3>${esc(title)}</h3><p>${esc(text)}</p>
        ${input !== null ? `<input type="text" value="${esc(input)}" maxlength="120" aria-label="${esc(title)}">` : ''}
        ${note ? '<textarea placeholder="Optional note for the audit log" maxlength="1000"></textarea>' : ''}
        <div class="row end"><button type="button" class="btn" data-cancel>Cancel</button>
        <button class="btn ${danger ? 'danger-solid' : 'primary'}" value="yes">${esc(ok)}</button></div></form>`;
      document.body.appendChild(d);
      // Cancel is not a submit button, so pressing Enter in the text field always means "confirm".
      $('[data-cancel]', d).addEventListener('click', () => d.close('no'));
      $('form', d).addEventListener('submit', (e) => { e.preventDefault(); d.close('yes'); });
      d.addEventListener('close', () => {
        const area = $('textarea', d);
        const field = $('input', d);
        resolve(d.returnValue === 'yes' ? { note: area ? area.value.trim() : '', value: field ? field.value.trim() : '' } : false);
        d.remove();
      });
      d.showModal();
      if (input !== null) { $('input', d).focus(); $('input', d).select(); }
    });
  }

  // Ctrl+K: jump to a page, search events or hand a question to the AI.
  function openPalette() {
    if ($('dialog.palette') || !$('.shell')) return;
    const d = document.createElement('dialog');
    d.className = 'palette';
    d.innerHTML = `<div class="pal-input">${icon('search', 18)}<input type="text" placeholder="Go to a page, search events, or ask the AI…" aria-label="Search or jump to a page" autocomplete="off"></div>
      <div class="pal-list"></div><div class="pal-foot">↑ ↓ to move · Enter to open · Esc to close</div>`;
    const input = $('input', d);
    const list = $('.pal-list', d);
    const pages = NAV.flatMap(([, items]) => items).filter((item) => !item[3] || isAdmin())
      .map(([id, text, ic]) => ({ label: text, icon: ic, href: `#/${id}` }));
    pages.push({ label: 'My account', icon: 'user', href: '#/account' });
    state.apps.filter((a) => a.connected).forEach((a) => a.menu.forEach((g) => g.items.filter((it) => it.id).forEach((it) =>
      pages.push({ label: `${a.name}: ${it.label}`, icon: ICONS[it.icon] ? it.icon : 'list', href: `#/app/${a.id}/${it.id}` }))));
    let items = []; let sel = 0;
    const render = () => {
      const q = input.value.trim();
      items = pages.filter((p) => p.label.toLowerCase().includes(q.toLowerCase()));
      if (q) {
        items.push({ label: `Search events for “${q}”`, icon: 'list', href: `#/events?q=${encodeURIComponent(q)}` },
          { label: `Ask the AI: “${q}”`, icon: 'spark', href: `#/console?q=${encodeURIComponent(q)}` });
      }
      sel = Math.max(0, Math.min(sel, items.length - 1));
      list.innerHTML = items.map((it, i) => `<button type="button" class="pal-item ${i === sel ? 'on' : ''}" data-i="${i}">${icon(it.icon, 16)}<span>${esc(it.label)}</span></button>`).join('');
      const on = $('.pal-item.on', list);
      if (on) on.scrollIntoView({ block: 'nearest' });
    };
    const go = (item) => { if (!item) return; d.close(); if (location.hash === item.href) route(); else location.hash = item.href; };
    input.addEventListener('input', () => { sel = 0; render(); });
    input.addEventListener('keydown', (e) => {
      if (e.key === 'ArrowDown') { e.preventDefault(); sel = (sel + 1) % items.length; render(); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); sel = (sel - 1 + items.length) % items.length; render(); }
      else if (e.key === 'Enter') { e.preventDefault(); go(items[sel]); }
    });
    list.addEventListener('click', (e) => { const b = e.target.closest('.pal-item'); if (b) go(items[Number(b.dataset.i)]); });
    d.addEventListener('click', (e) => { if (e.target === d) d.close(); });
    d.addEventListener('close', () => d.remove());
    document.body.appendChild(d);
    d.showModal();
    render();
  }

  async function copyText(text) {
    try { await navigator.clipboard.writeText(text); toast('Copied'); return true; } catch { toast('Copy is blocked by the browser on this address', true); return false; }
  }

  const theme = {
    current() {
      let saved = null;
      try { saved = localStorage.getItem('cerberus-theme'); } catch { /* storage blocked */ }
      return saved || (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light');
    },
    apply() {
      const t = this.current();
      const accent = pref.get('accent', 'teal');
      document.documentElement.dataset.theme = t;
      document.documentElement.dataset.accent = ACCENTS.some(([id]) => id === accent) ? accent : 'teal';
      document.querySelectorAll('.swatch').forEach((s) => s.classList.toggle('on', s.dataset.value === document.documentElement.dataset.accent));
      const btn = $('#theme-btn');
      if (btn) { btn.innerHTML = icon(t === 'dark' ? 'sun' : 'moon'); btn.title = t === 'dark' ? 'Switch to light theme' : 'Switch to dark theme'; }
    },
    toggle() {
      try { localStorage.setItem('cerberus-theme', this.current() === 'dark' ? 'light' : 'dark'); } catch { /* storage blocked */ }
      this.apply();
    },
  };

  // ---------- markdown (escape-first) for model output ----------

  function inline(text) {
    const parts = String(text).split('`');
    if (parts.length % 2 === 0) parts.push(`\`${parts.pop()}`, ''); // unmatched backtick: keep it literal
    return parts.map((seg, i) => {
      if (i % 2) return `<code>${esc(seg)}</code>`;
      return esc(seg)
        .replace(/\[([^\]]+)\]\((https?:\/\/[^\s)]+)\)/g, '<a class="link" href="$2" target="_blank" rel="noopener noreferrer">$1</a>')
        .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
        .replace(/__([^_]+)__/g, '<strong>$1</strong>')
        .replace(/(^|[\s(])\*([^*\s][^*]*)\*(?=[\s).,;:!?]|$)/g, '$1<em>$2</em>')
        .replace(/\[?\b(INC-0*(\d+))\]?/g, '<a class="ref" href="#/incidents/$2">$1</a>')
        .replace(/\[?\b(EVT-\d+)\]?/g, '<span class="ref">$1</span>');
    }).join('');
  }

  function tableCells(line) {
    const cells = [];
    let cur = ''; let code = false;
    const src = line.trim();
    for (let i = 0; i < src.length; i += 1) {
      const ch = src[i];
      if (ch === '\\' && src[i + 1] === '|') { cur += '|'; i += 1; continue; }
      if (ch === '`') code = !code;
      if (ch === '|' && !code) { cells.push(cur); cur = ''; } else cur += ch;
    }
    cells.push(cur);
    if (cells[0].trim() === '') cells.shift();
    if (cells.length && cells[cells.length - 1].trim() === '') cells.pop();
    return cells.map((c) => c.trim());
  }

  const LIST_RE = /^(\s*)([-*•+]|\d+[.)])\s+(.*)/;
  const TABLE_SEP_RE = /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/;

  function md(text) {
    const lines = String(text || '').replace(/\r/g, '').split('\n');
    const out = [];
    const lists = [];
    let para = [];
    const flushPara = () => { if (para.length) { out.push(`<p>${para.map(inline).join('<br>')}</p>`); para = []; } };
    const closeLists = (toIndent = -1) => {
      while (lists.length && lists[lists.length - 1].indent > toIndent) out.push(`</li></${lists.pop().tag}>`);
    };
    const openList = (indent, tag, marker, body) => {
      lists.push({ indent, tag });
      const start = tag === 'ol' && parseInt(marker, 10) > 1 ? ` start="${parseInt(marker, 10)}"` : '';
      out.push(`<${tag}${start}><li>${inline(body)}`);
    };

    for (let i = 0; i < lines.length; i += 1) {
      const line = lines[i];
      if (/^\s*```/.test(line)) {
        flushPara(); closeLists();
        const buf = [];
        for (i += 1; i < lines.length && !/^\s*```/.test(lines[i]); i += 1) buf.push(lines[i]);
        out.push(`<pre><code>${esc(buf.join('\n'))}</code></pre>`);
        continue;
      }
      if (line.includes('|') && i + 1 < lines.length && lines[i + 1].includes('-') && TABLE_SEP_RE.test(lines[i + 1])) {
        flushPara(); closeLists();
        const head = tableCells(line);
        const rows = [];
        for (i += 2; i < lines.length && lines[i].trim() && lines[i].includes('|'); i += 1) rows.push(tableCells(lines[i]));
        i -= 1;
        out.push(`<div class="tbl"><table><thead><tr>${head.map((c) => `<th>${inline(c)}</th>`).join('')}</tr></thead><tbody>${
          rows.map((r) => `<tr>${head.map((_, k) => `<td>${inline(r[k] ?? '')}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`);
        continue;
      }
      if (!line.trim()) {
        flushPara();
        const next = lines.slice(i + 1).find((l) => l.trim());
        if (!next || !(LIST_RE.test(next) || /^\s{2,}/.test(next))) closeLists();
        continue;
      }
      const heading = line.match(/^\s*(#{1,6})\s+(.*?)\s*#*\s*$/);
      if (heading) {
        flushPara(); closeLists();
        const tag = heading[1].length <= 2 ? 'h3' : 'h4';
        out.push(`<${tag}>${inline(heading[2])}</${tag}>`);
        continue;
      }
      if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { flushPara(); closeLists(); out.push('<hr>'); continue; }
      if (/^\s*>/.test(line)) {
        flushPara(); closeLists();
        const buf = [];
        for (; i < lines.length && /^\s*>/.test(lines[i]); i += 1) buf.push(lines[i].replace(/^\s*>\s?/, ''));
        i -= 1;
        out.push(`<blockquote>${buf.map(inline).join('<br>')}</blockquote>`);
        continue;
      }
      const item = line.match(LIST_RE);
      if (item) {
        flushPara();
        const indent = item[1].replace(/\t/g, '    ').length;
        const tag = /\d/.test(item[2]) ? 'ol' : 'ul';
        closeLists(indent);
        const cur = lists[lists.length - 1];
        if (cur && cur.indent === indent && cur.tag === tag) out.push(`</li><li>${inline(item[3])}`);
        else {
          if (cur && cur.indent === indent) out.push(`</li></${lists.pop().tag}>`);
          openList(indent, tag, item[2], item[3]);
        }
        continue;
      }
      if (lists.length && /^\s{2,}/.test(line)) { out.push(`<br>${inline(line.trim())}`); continue; }
      closeLists();
      para.push(line);
    }
    flushPara(); closeLists();
    return `<div class="md">${out.join('')}</div>`;
  }

  // ---------- shell ----------

  // [section, [[route, label, icon, adminOnly]]]
  const NAV = [
    ['', [['overview', 'Overview', 'home']]],
    ['Investigate', [['console', 'Enforcer console', 'chat'], ['incidents', 'Incidents', 'alert'], ['events', 'Events', 'list'], ['approvals', 'Approvals', 'check']]],
    ['Monitor', [['watch', 'AI watch', 'eye'], ['logs', 'Logs', 'terminal'], ['infrastructure', 'Infrastructure', 'activity'], ['assets', 'Assets', 'server']]],
    ['Administer', [['users', 'Users', 'users', true], ['announcements', 'Announcements', 'megaphone', true],
      ['providers', 'AI providers', 'spark', true], ['integrations', 'Integrations', 'plug', true], ['audit', 'Audit log', 'clock', true]]],
  ];
  const closedGroups = () => pref.get('navclosed', '').split(',').filter(Boolean);
  const ADMIN_VIEWS = new Set(NAV.flatMap(([, items]) => items).filter((item) => item[3]).map((item) => item[0]));
  const TITLES = { account: 'My account', ...Object.fromEntries(NAV.flatMap(([, items]) => items).map(([id, text]) => [id, text])) };

  // The application chosen in the navbar: null means "All applications", the normal CERBERUS menu.
  const activeApp = () => state.apps.find((a) => a.id === pref.get('app', 'all')) || null;
  const NAV_BADGES = { incidents: 1, watch: 1, approvals: 1 };
  const navLink = (id, href, text, ic) => `<a href="${esc(href)}" data-nav="${esc(id)}" data-tip="${esc(text)}" aria-label="${esc(text)}">${icon(ICONS[ic] ? ic : 'list')}<span>${esc(text)}</span>${
    NAV_BADGES[id] ? `<span class="count" data-badge="${id}" hidden></span>` : ''}</a>`;
  const navGroup = (key, label, links) => {
    const closed = closedGroups().includes(key);
    return `<div class="nav-group ${closed ? 'closed' : ''}" data-group="${esc(key)}">
      <button type="button" class="nav-label" data-action="nav-group" aria-expanded="${!closed}"><span>${esc(label)}</span>${icon('chevron', 13)}</button>
      <div class="nav-items">${links}</div></div>`;
  };
  function navHtml() {
    const a = activeApp();
    if (!a) {
      return NAV.map(([label, items]) => [label, items.filter((item) => !item[3] || isAdmin())]).filter(([, items]) => items.length)
        .map(([label, items]) => { const links = items.map(([id, text, ic]) => navLink(id, `#/${id}`, text, ic)).join(''); return label ? navGroup(label, label, links) : links; }).join('');
    }
    const head = `<div class="nav-app"><span class="dot ${a.connected ? 'on' : 'off'}"></span><div><b>${esc(a.name)}</b><small>${esc(a.connected ? a.about : 'Not connected yet')}</small></div>
      <button type="button" class="btn sm ghost" data-action="app-pick" data-value="all" title="Back to everything in CERBERUS">All</button></div>`;
    return head + a.menu.map((g) => {
      const links = g.items.map((it) => (it.id ? navLink(`app/${a.id}/${it.id}`, `#/app/${a.id}/${it.id}`, it.label, it.icon)
        : navLink(it.route.replace(/^#\//, '').split(/[/?]/)[0], it.route, it.label, it.icon))).join('');
      return g.label ? navGroup(`${a.id}:${g.label}`, g.label, links) : links;
    }).join('');
  }
  function switcherHtml() {
    const cur = activeApp() ? activeApp().id : 'all';
    const item = (id, name, about, mark) => `<button class="menu-item app-item ${id === cur ? 'on' : ''}" data-action="app-pick" data-value="${esc(id)}">
      ${mark}<span class="app-text"><b>${esc(name)}</b><small>${esc(about)}</small></span></button>`;
    return `<div class="muted small pop-title">Show the menu of</div>${item('all', 'All applications', 'Everything in CERBERUS', icon('grid', 16))}
      ${state.apps.map((a) => item(a.id, a.name, a.connected ? a.about : 'Not connected yet', `<span class="dot ${a.connected ? 'on' : 'off'}"></span>`)).join('')}
      ${isAdmin() ? `<div class="menu-sep"></div><a class="menu-item" href="#/integrations">${icon('plus', 16)}<span>Connect an application</span></a>` : ''}`;
  }
  const markNav = () => document.querySelectorAll('[data-nav]').forEach((a) => a.classList.toggle('active', a.dataset.nav === state.navKey));
  function renderNav() {
    if (!$('.shell')) return;
    $('.nav').innerHTML = navHtml();
    $('#app-pop').innerHTML = switcherHtml();
    $('#app-name').textContent = activeApp() ? activeApp().name : 'All applications';
    markNav();
  }
  async function loadApps() {
    state.appsLoaded = true;
    try { state.apps = await api('/apps'); } catch { state.apps = []; }
    renderNav();
  }

  function ensureShell() {
    if ($('.shell')) return;
    app.innerHTML = `
      <div class="shell ${pref.get('sidebar', 'open') === 'rail' ? 'rail' : ''}">
        <aside class="sidebar">
          <div class="brand-row"><a class="brand" href="#/overview" aria-label="CERBERUS, go to Overview" data-tip="Overview">${logo()}<div><b>CERBERUS</b><small>Security operations</small></div></a>
            <button class="side-collapse" data-action="drawer" aria-label="Collapse or expand the sidebar" data-tip="Expand sidebar">${icon('panel', 17)}</button></div>
          <form class="quick" data-form="quick">${icon('search', 16)}
            <input type="text" name="q" id="quick" placeholder="Search or jump to…" autocomplete="off" aria-label="Search or jump to a page" readonly><kbd>Ctrl K</kbd></form>
          <nav class="nav" aria-label="Main">${navHtml()}</nav>
          <div class="side-status">
            <a href="#/console" id="ss-ai" data-tip="AI analyst"><span class="dot"></span><span class="ss-text"><b>AI analyst</b><small>Checking…</small></span></a>
            <a href="#/watch" id="ss-watch" data-tip="AI watch"><span class="dot"></span><span class="ss-text"><b>AI watch</b><small>Checking…</small></span></a>
          </div>
          <div class="side-foot pop-wrap">
            <button class="side-user" data-action="menu" aria-label="Account menu" data-tip="${esc(state.user.username)}">
              <span class="initial">${esc(state.user.username.slice(0, 1))}</span>
              <span class="me"><b>${esc(state.user.username)}</b><small>${roleName(state.user.role)}</small></span>${icon('chevron', 14)}</button>
            <div class="pop menu up" hidden>
              <a class="menu-item" href="#/account">${icon('user', 16)}<span>My account</span></a>
              <button class="menu-item" data-action="theme">${icon('moon', 16)}<span>Switch light or dark</span></button>
              <button class="menu-item" data-action="shortcuts">${icon('terminal', 16)}<span>Keyboard shortcuts</span></button>
              <div class="menu-sep"></div>
              <button class="menu-item danger" data-action="logout">${icon('logout', 16)}<span>Sign out</span></button>
            </div>
          </div>
        </aside>
        <div class="scrim" data-action="drawer"></div>
        <div class="main">
          <header class="topbar">
            <button class="btn ghost icon menu-btn" data-action="drawer" title="Show or hide the sidebar (Ctrl+B)" aria-label="Toggle sidebar">${icon('menu')}</button>
            <div class="pop-wrap"><button class="btn ghost app-btn" data-action="menu" title="Choose which application's menu to show" aria-label="Choose application">${icon('grid', 16)}<span id="app-name">${esc(activeApp() ? activeApp().name : 'All applications')}</span>${icon('chevron', 13)}</button>
              <div class="pop menu left" id="app-pop" hidden>${switcherHtml()}</div></div>
            <span class="top-title" id="top-title"></span>
            <span class="spacer"></span>
            <span class="live" title="Lists refresh every 30 seconds"><span class="dot on"></span>Live</span>
            <a class="btn ghost" href="#/console">${icon('spark')} Ask AI</a>
            <div class="pop-wrap"><button class="btn ghost icon bell" data-action="bell" title="Notifications" aria-label="Notifications">${icon('bell')}<span class="count" data-badge="notifications" hidden></span></button>
              <div class="pop wide" id="bell-pop" hidden></div></div>
            <div class="pop-wrap"><button class="btn ghost icon" data-action="palette" title="Colour palette" aria-label="Colour palette"><span class="swatch-dot"></span></button>
              <div class="pop" id="palette-pop" hidden><div class="muted small">Accent colour</div>
                <div class="swatches">${ACCENTS.map(([id, name, color]) => `<button class="swatch" data-action="accent" data-value="${id}" title="${name}" aria-label="${name}" style="background:${color}"></button>`).join('')}</div></div></div>
            <button class="btn ghost icon" id="theme-btn" data-action="theme" aria-label="Toggle theme"></button>
          </header>
          <div class="stale" id="stale" hidden>The CERBERUS server is running an older version than this page, so some features will not work.
            Restart it: press Ctrl+C in its window, then run <code>.\\run.ps1</code> again.</div>
          <main class="content" id="view"></main>
        </div>
      </div>`;
    theme.apply();
  }

  function setBadges(o) {
    const set = (name, n, tone = '') => { const el = $(`[data-badge="${name}"]`); if (el) { el.textContent = n > 99 ? '99+' : n; el.hidden = !n; if (name !== 'notifications') el.className = `count ${tone}`; } };
    set('incidents', o.open_incidents, o.critical ? 'crit' : 'quiet');
    // Small status rows at the bottom of the sidebar.
    const row = (id, tone, text) => { const el = $(id); if (el) { $('.dot', el).className = `dot ${tone}`; $('small', el).textContent = text; } };
    row('#ss-ai', o.ai_provider ? 'on' : 'off', o.ai_provider ? (o.ai_provider.model || o.ai_provider.name) : 'Not connected');
    const firing = (o.watch && o.watch.firing) || 0;
    row('#ss-watch', o.watch && o.watch.enabled ? (firing ? 'off' : 'on') : '', o.watch && o.watch.enabled ? (firing ? `${firing} need${firing === 1 ? 's' : ''} attention` : 'On · all clear') : 'Off');
    set('approvals', o.pending_approvals);
    set('notifications', o.unread_notifications || 0);
    set('watch', firing, 'warn');
    state.emailReady = Boolean(o.email_configured);
    state.stale = o.version !== APP_VERSION;
    const stale = $('#stale');
    if (stale) stale.hidden = !state.stale;
    state.aiReady = Boolean(o.ai_provider);
    state.aiModel = o.ai_provider ? (o.ai_provider.model || o.ai_provider.name) : '';
    state.aiTools = o.ai_tools || [];
  }
  async function loadOverview() { const o = await api('/overview'); setBadges(o); return o; }

  const page = (title, sub, actions, body, crumb = '') => `
    <div class="page">${crumb}
      <div class="page-head"><div><h1>${title}</h1>${sub ? `<p>${sub}</p>` : ''}</div><div class="row">${actions || ''}</div></div>
      ${body}
    </div>`;
  const empty = (title, text, extra = '', ic = 'inbox') => `<div class="card empty">${icon(ic, 34)}<h3>${title}</h3><div>${text}</div>${extra}</div>`;

  const incidentTable = (list, withStatus) => `<div class="card"><div class="table-scroll"><table>
    <tr><th data-sort="text">Incident</th>${withStatus ? '<th data-sort="text">Status</th>' : ''}<th data-sort="num">Severity</th><th data-sort="text">Asset</th><th data-sort="text">Source IP</th><th data-sort="num">Events</th><th data-sort="num">Last seen</th></tr>
    ${list.map((i) => `<tr class="clickable sev-${esc(i.severity_label)}" data-href="#/incidents/${i.id}">
      <td class="wrap"><strong>${esc(i.ref)}</strong> ${esc(i.title)}${demoBadge(i.demo)}</td>
      ${withStatus ? `<td>${statusBadge(i.status)}</td>` : ''}<td data-v="${i.severity}">${sevBadge(i.severity_label, i.severity)}</td><td>${esc(i.asset_name || '—')}</td>
      <td class="mono">${esc(i.source_ip || '—')}</td><td>${i.event_count}</td><td class="nowrap" data-v="${Date.parse(i.last_seen) || 0}">${agoCell(i.last_seen)}</td></tr>`).join('')}
  </table></div></div>`;

  // ---------- views: each returns an HTML string or { html, mount } ----------

  const views = {};

  // Severity is a status scale, so it uses the fixed status colours, always paired with a text label.
  const SEVERITIES = [['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']];
  const hourTotal = (h) => h.critical + h.high + h.medium + h.low;
  const niceMax = (n) => {
    if (n <= 4) return 4;
    if (n <= 10) return 10;
    const p = 10 ** Math.floor(Math.log10(n));
    const f = n / p;
    return (f <= 1 ? 1 : f <= 2 ? 2 : f <= 5 ? 5 : 10) * p;
  };
  const hourLabel = (iso) => `${String(new Date(iso).getHours()).padStart(2, '0')}:00`;

  const fmtNum = (n) => (n >= 1e6 ? `${(n / 1e6).toFixed(n >= 1e7 ? 0 : 1)}M` : n >= 1e4 ? `${Math.round(n / 1e3)}K` : n >= 1e3 ? `${(n / 1e3).toFixed(1)}K` : String(n));
  const clock = (ms) => { const d = new Date(ms); return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`; };
  const dayName = (ms) => new Date(ms).toLocaleDateString([], { weekday: 'short' });

  // Stacked columns over time, shared by every time chart in the app.
  // data: buckets with a start time `t` (ms) and one count per series key.
  // opts: series [[key, label, cssClass]] (first is drawn on top), group (legend toggle group), span (ms per bucket),
  //       unit [singular, plural], empty (text), axis(bucket, index, count) -> label or '', onPick(bucket) for click-through.
  const charts = new Map();
  function stackChart(id, data, opts) {
    charts.set(id, () => stackChart(id, data, opts));
    const el = document.getElementById(id);
    if (!el) return;
    const hidden = state.hidden[opts.group] || new Set();
    const series = opts.series.filter(([k]) => !hidden.has(k));
    const total = (b) => series.reduce((n, [k]) => n + (b[k] || 0), 0);
    if (!data.length || !data.some(total)) { el.innerHTML = `<div class="chart-empty">${esc(hidden.size ? 'Nothing to show for the selected series.' : opts.empty)}</div>`; return; }
    const W = Math.max(300, el.clientWidth);
    const H = 220;
    const m = { l: 44, r: 6, t: 10, b: 24 };
    const pw = W - m.l - m.r;
    const ph = H - m.t - m.b;
    const max = niceMax(Math.max(...data.map(total)));
    const y = (v) => m.t + ph - (v / max) * ph;
    const band = pw / data.length;
    const bw = Math.min(24, Math.max(2, band - (band > 9 ? 4 : 1)));
    const gap = band > 9 ? 2 : 0; // 2px surface gap between stacked segments when there is room for it
    let grid = ''; let hits = ''; let bars = ''; let labels = '';
    for (const t of [0, max / 2, max]) {
      grid += `<line class="${t ? 'grid' : 'axis'}" x1="${m.l}" x2="${W - m.r}" y1="${y(t)}" y2="${y(t)}"/><text class="tick" x="${m.l - 7}" y="${y(t) + 4}" text-anchor="end">${fmtNum(t)}</text>`;
    }
    const stack = [...series].reverse();
    data.forEach((b, i) => {
      const x = m.l + i * band + (band - bw) / 2;
      hits += `<rect class="hit" data-i="${i}" x="${m.l + i * band}" y="${m.t}" width="${band}" height="${ph}"/>`;
      const parts = stack.filter(([k]) => b[k] > 0);
      let acc = 0;
      parts.forEach(([k, , cls], j) => {
        const top = y(acc + b[k]);
        const height = Math.max(1, y(acc) - top - (j ? gap : 0));
        acc += b[k];
        if (j === parts.length - 1) {
          const r = Math.min(4, bw / 2, height);
          bars += `<path class="seg ${cls}" d="M${x},${top + height}V${top + r}Q${x},${top} ${x + r},${top}H${x + bw - r}Q${x + bw},${top} ${x + bw},${top + r}V${top + height}Z"/>`;
        } else bars += `<rect class="seg ${cls}" x="${x}" y="${top}" width="${bw}" height="${height}"/>`;
      });
      const label = opts.axis(b, i, data.length);
      if (label) labels += `<text class="tick" x="${m.l + i * band + band / 2}" y="${H - 6}" text-anchor="middle">${esc(label)}</text>`;
    });
    const sum = data.reduce((n, b) => n + total(b), 0);
    el.innerHTML = `<svg width="${W}" height="${H}" role="img" aria-label="${esc(`${fmtNum(sum)} ${opts.unit[1]} over time, stacked by ${opts.group === 'sev' ? 'severity' : 'level'}.`)}">${grid}${hits}${bars}${labels}</svg><div class="chart-tip" hidden></div>`;
    el.classList.toggle('pickable', Boolean(opts.onPick));
    const tip = $('.chart-tip', el);
    el.onmousemove = (e) => {
      const hit = e.target.closest('.hit');
      if (!hit) { tip.hidden = true; return; }
      const i = Number(hit.dataset.i);
      const b = data[i];
      tip.innerHTML = `<div class="tip-head">${opts.span >= 86400000 / 2 ? `${dayName(b.t)} ` : ''}${clock(b.t)} – ${clock(b.t + opts.span)}</div>
        <div class="tip-total">${total(b).toLocaleString()} ${total(b) === 1 ? opts.unit[0] : opts.unit[1]}</div>${
        series.filter(([k]) => b[k]).map(([k, name, cls]) => `<div class="tip-row"><span class="sw ${cls}"></span>${name}<b>${b[k].toLocaleString()}</b></div>`).join('')}${
        opts.onPick && total(b) ? `<div class="tip-hint">${opts.pickHint || 'Click to see these events'}</div>` : ''}`;
      tip.hidden = false;
      const center = m.l + i * band + band / 2;
      tip.style.left = `${Math.min(Math.max(center - tip.offsetWidth / 2, 0), W - tip.offsetWidth)}px`;
    };
    el.onmouseleave = () => { tip.hidden = true; };
    el.onclick = (e) => { const hit = e.target.closest('.hit'); if (hit && opts.onPick && total(data[Number(hit.dataset.i)])) opts.onPick(data[Number(hit.dataset.i)]); };
  }
  window.addEventListener('resize', () => charts.forEach((draw) => draw()));

  // Legend that doubles as a filter: click a series to hide or show it.
  const legend = (group, series, totals) => `<div class="legend">${series.map(([k, name, cls]) =>
    `<button type="button" class="lg ${(state.hidden[group] || new Set()).has(k) ? 'off' : ''}" data-action="legend" data-group="${group}" data-key="${k}" title="Click to hide or show"><i class="sw ${cls}"></i>${name} <b>${fmtNum(totals[k] || 0)}</b></button>`).join('')}</div>`;

  const SEV_SERIES = SEVERITIES.map(([k, name]) => [k, name, `sev-${k}`]);
  const sevTotals = (buckets) => Object.fromEntries(SEVERITIES.map(([k]) => [k, buckets.reduce((n, b) => n + b[k], 0)]));
  // Hourly buckets from the API -> chart buckets, optionally merged `per` hours at a time.
  function sevBuckets(hourly, per = 1) {
    const out = [];
    hourly.forEach((h, i) => {
      if (i % per === 0) out.push({ t: Date.parse(h.hour), critical: 0, high: 0, medium: 0, low: 0 });
      const b = out[out.length - 1];
      SEVERITIES.forEach(([k]) => { b[k] += h[k]; });
    });
    return out;
  }
  const sevChart = (id, buckets, per, extraQuery = '') => stackChart(id, buckets, {
    series: SEV_SERIES, group: 'sev', span: per * 3600000, unit: ['event', 'events'], empty: 'No events in this period.',
    axis: (b, i, n) => (per === 1 ? ((n - 1 - i) % 4 === 0 ? (i === n - 1 ? 'now' : clock(b.t)) : '') : (new Date(b.t).getHours() < per ? dayName(b.t) : '')),
    onPick: (b) => { location.hash = `#/events?start=${encodeURIComponent(new Date(b.t).toISOString())}&end=${encodeURIComponent(new Date(b.t + per * 3600000).toISOString())}${extraQuery}`; },
  });

  const barList = (rows) => {
    const max = Math.max(1, ...rows.map((r) => r.value));
    return rows.map((r) => `<${r.href ? `a href="${r.href}"` : 'div'} class="hbar" title="${esc(r.label)}: ${r.value}">
      <span class="hbar-label">${esc(r.label)}</span>
      <span class="hbar-track"><span class="hbar-fill ${r.cls}" style="width:${r.value ? Math.max(2, (r.value / max) * 100) : 0}%"></span></span>
      <span class="hbar-val">${r.value}</span></${r.href ? 'a' : 'div'}>`).join('');
  };

  views.overview = async ({ overview }) => {
    const o = await overview;
    const ai = o.ai_provider
      ? `<span class="dot on"></span> AI analyst ready · ${esc(o.ai_provider.model || o.ai_provider.name)}`
      : `<span class="dot off"></span> AI analyst not connected${isAdmin() ? ' — add a provider' : ''}`;
    const admin = isAdmin();
    const done = '<span class="badge ok">Connected</span>';
    const incidents = o.recent_incidents.length ? incidentTable(o.recent_incidents, false)
      : empty('No active incidents', 'Events arrive through the Grafana webhook or the ingest API.',
        o.has_demo_data || !admin ? '' : '<div style="margin-top:14px"><button class="btn" data-action="demo-load">Load demo data</button></div>', 'check');
    const buckets = sevBuckets(o.hourly || []);
    const html = `<div class="page">
      <div class="hero">
        <a class="pill" href="${admin ? '#/providers' : '#/console'}">${ai}</a>
        <a class="pill" href="#/watch">${o.watch && o.watch.enabled
          ? `<span class="dot ${o.watch.firing ? 'off' : 'on'}"></span> AI watch on · ${o.watch.firing ? `${o.watch.firing} need${o.watch.firing === 1 ? 's' : ''} attention` : 'all clear'}`
          : '<span class="dot"></span> AI watch is off'}</a>
        <h1>Let's get to work.</h1>
        <form class="ask" data-form="ask">${icon('search', 20)}
          <input type="text" name="q" placeholder="Ask CERBERUS — e.g. “Show all suspicious activity on sietlms in the last 24 hours”" autocomplete="off" aria-label="Ask CERBERUS"></form>
      </div>
      <div class="hero-actions"><button class="btn" data-action="ai-brief" data-kind="overview">${icon('spark', 16)} Brief me on the last 24 hours</button></div>
      <div id="ai-insight"></div>
      <div class="stats">
        <a class="card stat" href="#/assets"><div class="ico">${icon('server', 20)}</div><div><b>${o.assets}</b><span>Assets</span></div></a>
        <a class="card stat ${o.open_incidents ? 'attn' : ''}" href="#/incidents"><div class="ico">${icon('alert', 20)}</div><div><b>${o.open_incidents}</b><span>Open incidents</span></div></a>
        <a class="card stat ${o.critical ? 'alert' : ''}" href="#/incidents"><div class="ico">${icon('alert', 20)}</div><div><b>${o.critical}</b><span>Critical</span></div></a>
        <a class="card stat ${o.pending_approvals ? 'attn' : ''}" href="#/approvals"><div class="ico">${icon('check', 20)}</div><div><b>${o.pending_approvals}</b><span>Pending approval</span></div></a>
      </div>
      ${!admin ? '' : o.ai_provider && o.grafana_configured ? `<div class="card strip">
        <a href="#/providers">${icon('spark', 22)}<div class="grow"><b>AI analyst</b><small>${esc(o.ai_provider.model || o.ai_provider.name)}</small></div>${done}</a>
        <a href="#/integrations">${icon('plug', 22)}<div class="grow"><b>Grafana</b><small>Alerts in · metrics and logs out</small></div>${done}</a>
        <a href="#/approvals">${icon('check', 22)}<div class="grow"><b>Human approval</b><small>${o.pending_approvals ? `${o.pending_approvals} waiting for your decision` : 'Nothing waiting'}</small></div></a>
      </div>` : `<div class="tiles">
        <div class="card tile"><div class="tile-art">${icon('spark', 44)}${o.ai_provider ? done : ''}</div>
          <h3>Connect an AI model</h3><p>Use NVIDIA NIM, a local model through Ollama or LM Studio, or any OpenAI-compatible API.</p>
          <a class="btn" href="#/providers">${o.ai_provider ? 'Manage providers' : 'Add provider'}</a></div>
        <div class="card tile"><div class="tile-art">${icon('plug', 44)}${o.grafana_configured ? done : ''}</div>
          <h3>Connect Grafana</h3><p>Receive alerts by webhook and let the analyst query Prometheus and Loki through Grafana.</p>
          <a class="btn" href="#/integrations">${o.grafana_configured ? 'Manage Grafana' : 'Set up Grafana'}</a></div>
        <div class="card tile"><div class="tile-art">${icon('check', 44)}</div>
          <h3>Stay in control</h3><p>The AI investigates and proposes. Containment actions wait for your approval and are audited.</p>
          <a class="btn" href="#/approvals">Review approvals</a></div>
      </div>`}
      <div class="dash">
        <div class="card card-pad"><div class="section-head" style="margin-bottom:6px"><h2>Events in the last 24 hours</h2><a class="link small" href="#/events">View all events</a></div>
          ${legend('sev', SEV_SERIES, sevTotals(buckets))}
          <div class="chart" id="events-chart"></div></div>
        <div class="card card-pad">
          <h2>Active incidents by severity</h2>
          <div class="hbars">${barList(SEVERITIES.map(([k, name]) => ({ label: name, value: o[k] || 0, cls: `sev-${k}`, href: '#/incidents' })))}</div>
          <h2 style="margin-top:22px">Busiest assets, last 24 hours</h2>
          <div class="hbars">${o.top_assets && o.top_assets.length ? barList(o.top_assets.map((a) => ({ label: a.name, value: a.events, cls: 'series', href: `#/events?q=${encodeURIComponent(a.name)}` })))
            : '<div class="muted small" style="padding:8px 0">No events yet.</div>'}</div></div>
      </div>
      <div class="section-head"><h2>Active incidents</h2>
        <div class="row"><span class="muted small">Sources</span>
        ${o.sources.map((s) => `<a class="badge" href="#/events?source=${encodeURIComponent(s.source)}" title="Last event ${esc(fmtTime(s.last_seen))}">${esc(s.source)} · ${s.events}</a>`).join('')}
        ${o.has_demo_data && admin ? '<button class="btn sm ghost danger" data-action="demo-clear">Remove demo data</button>' : ''}</div></div>
      ${incidents}
    </div>`;
    return { html, mount: () => sevChart('events-chart', buckets, 1) };
  };

  // ---------- console ----------

  const SUGGESTIONS = [
    'Summarise the open incidents by priority and tell me what to look at first.',
    'Show all suspicious activity on sietlms during the last 24 hours.',
    'Which source IPs appear in more than one detection engine?',
    'Are all monitored endpoints up right now? Show a status table.',
  ];
  const TOOL_LABELS = {
    search_events: 'Search events', list_incidents: 'List incidents', get_incident: 'Open incident', list_assets: 'List assets',
    propose_response_action: 'Propose response action', get_server_health: 'Check server health', get_metric_history: 'Check metric history',
    wazuh_summary: 'Summarise Wazuh', search_wazuh_alerts: 'Search Wazuh alerts',
    wazuh_agents: 'List Wazuh agents', wazuh_configuration_assessment: 'Read Wazuh configuration assessment',
    send_report_to_admins: 'Email report to admins',
    query_prometheus: 'Query Prometheus', query_loki: 'Query Loki',
  };

  // Conversations are saved by the server as it answers; the browser only remembers which one is open.
  function rememberChat(id) {
    state.chatId = id;
    try { if (id) sessionStorage.setItem(CHAT_KEY, id); else sessionStorage.removeItem(CHAT_KEY); } catch { /* storage blocked */ }
  }
  function loadChat() {
    try { state.chatId = Number(sessionStorage.getItem(CHAT_KEY)) || null; } catch { state.chatId = null; }
  }
  function clearChat() { state.chat = []; rememberChat(null); }

  async function refreshHistory() {
    try { state.convos = await api('/ai/conversations'); } catch { state.convos = []; }
    renderHistory();
  }

  function renderHistory() {
    const list = $('#chat-history');
    if (!list) return;
    if (!state.convos.length) { list.innerHTML = '<div class="history-empty">Your conversations will appear here.</div>'; return; }
    const startOfToday = new Date().setHours(0, 0, 0, 0);
    const groupOf = (ts) => {
      const t = new Date(ts).getTime();
      if (t >= startOfToday) return 'Today';
      if (t >= startOfToday - 86400000) return 'Yesterday';
      if (t >= startOfToday - 7 * 86400000) return 'Previous 7 days';
      return 'Older';
    };
    let group = '';
    list.innerHTML = state.convos.map((c) => {
      const g = groupOf(c.updated_at);
      const head = g === group ? '' : `<div class="h-group">${g}</div>`;
      group = g;
      return `${head}<div class="h-item ${c.id === state.chatId ? 'on' : ''}" data-action="chat-open" data-id="${c.id}" tabindex="0" role="button">
        <div class="t"><b title="${esc(c.title)}">${esc(c.title)}</b><small>${ago(c.updated_at)} · ${c.message_count} messages</small></div>
        <button class="btn ghost" data-action="chat-rename" data-id="${c.id}" title="Rename" aria-label="Rename">${icon('edit', 14)}</button>
        <button class="btn ghost" data-action="chat-delete" data-id="${c.id}" title="Delete" aria-label="Delete">${icon('trash', 14)}</button></div>`;
    }).join('');
  }

  async function openChat(id) {
    const c = await api(`/ai/conversations/${id}`);
    state.chat = c.messages;
    rememberChat(c.id);
    renderChat(true);
    renderHistory();
  }

  const stepRow = (t, running = false) => `<div class="step ${t.error ? 'err' : ''}">${running ? '<span class="spinner"></span>' : ''}
    <span class="name">${esc(TOOL_LABELS[t.tool] || t.tool)}${t.error ? ' — failed' : ''}</span>
    ${Object.entries(t.arguments || {}).map(([k, v]) => `<span class="arg" title="${esc(typeof v === 'string' ? v : JSON.stringify(v))}">${esc(k)}: ${esc(String(typeof v === 'string' ? v : JSON.stringify(v)).slice(0, 80))}</span>`).join('')}</div>`;

  function messageHtml(m, index) {
    if (m.role === 'user') return `<div class="msg user"><div class="bubble">${esc(m.content)}</div></div>`;
    const avatar = `<div class="avatar">${icon('spark', 16)}</div>`;
    if (m.error) {
      return `<div class="msg error">${avatar}<div class="body"><div class="meta"><strong>CERBERUS</strong></div>
        <div class="errbox">${esc(m.content)}</div>
        <div class="actions"><button class="btn sm ghost" data-action="chat-retry">${icon('retry', 14)} Try again</button></div></div></div>`;
    }
    const trace = m.trace || [];
    const proposed = trace.some((t) => t.tool === 'propose_response_action' && !t.error);
    return `<div class="msg">${avatar}<div class="body">
      <div class="meta"><strong>CERBERUS</strong><span>${esc([m.model, m.seconds ? `${m.seconds}s` : ''].filter(Boolean).join(' · '))}</span></div>
      ${md(m.content)}
      ${m.tools_supported === false ? '<div class="muted small">This model did not accept tool calls, so it answered from a snapshot of recent data rather than running queries.</div>' : ''}
      ${proposed ? '<div class="callout" style="margin-top:10px">A response request is waiting for your decision. <a class="link" href="#/approvals">Open approvals</a></div>' : ''}
      ${trace.length ? `<details class="trace"><summary>${icon('tool', 13)} ${trace.length} evidence ${trace.length === 1 ? 'query' : 'queries'}</summary>${trace.map((t) => stepRow(t)).join('')}</details>` : ''}
      <div class="actions"><button class="btn sm ghost" data-action="chat-copy" data-index="${index}">${icon('copy', 14)} Copy</button>
        ${state.emailReady && state.chatId ? `<button class="btn sm ghost" data-action="chat-report" data-index="${state.chat.slice(0, index).filter((x) => !x.error).length}" title="Email this answer to the admins as a report">${icon('mail', 14)} Email to admins</button>` : ''}</div>
    </div></div>`;
  }

  function liveHtml() {
    const { steps, started } = state.live;
    const secs = Math.round((Date.now() - started) / 1000);
    return `<div class="msg"><div class="avatar">${icon('spark', 16)}</div><div class="body">
      <div class="meta"><strong>CERBERUS</strong></div>
      <div class="working"><span class="spinner"></span><span>${steps.length ? 'Reading the evidence' : 'Thinking'}… <span id="live-secs">${secs}</span>s</span></div>
      ${steps.length ? `<div class="steps-live">${steps.map((t) => stepRow(t)).join('')}</div>` : ''}
    </div></div>`;
  }

  function renderChat(forceBottom = false) {
    const log = $('#chat-log');
    if (!log) return;
    const stick = forceBottom || log.scrollHeight - log.scrollTop - log.clientHeight < 140;
    let html = '';
    if (!state.aiReady) {
      html += `<div class="callout" style="margin-bottom:18px">No AI provider is active yet. ${isAdmin()
        ? '<a class="link" href="#/providers">Add one</a> to use the console.' : 'Ask an admin to connect one.'}</div>`;
    }
    if (!state.chat.length && !state.busy) {
      html += `<div class="welcome"><div class="avatar-lg">${icon('spark', 26)}</div>
        <h1>What do you want to investigate?</h1>
        <p>Ask in plain language. The analyst answers from evidence it retrieves with bounded, audited queries, and it cannot execute response actions on its own.</p>
        <div class="suggest">${SUGGESTIONS.map((s) => `<button class="chip" data-action="suggest">${esc(s)}</button>`).join('')}</div>
        ${state.aiTools.length ? `<div class="toolchips"><span class="muted small">It can:</span>${state.aiTools.map((t) => `<span class="badge">${esc(TOOL_LABELS[t] || t)}</span>`).join('')}</div>` : ''}</div>`;
    }
    html += state.chat.map(messageHtml).join('');
    if (state.busy && state.live) html += liveHtml();
    $('.chat-inner', log).innerHTML = html;
    if (stick) log.scrollTop = log.scrollHeight;
    const send = $('#chat-send');
    if (send) {
      send.innerHTML = state.busy ? `${icon('stop')} Stop` : icon('send');
      send.dataset.action = state.busy ? 'chat-stop' : '';
      send.type = state.busy ? 'button' : 'submit';
      send.className = state.busy ? 'btn' : 'btn primary icon';
      send.title = state.busy ? 'Stop' : 'Send (Enter)';
    }
    const fresh = $('#chat-new');
    if (fresh) fresh.hidden = !state.chat.length;
  }

  views.console = async ({ overview, params }) => {
    await overview;
    return {
      html: `<div class="chat-wrap ${pref.get('history', 'open') === 'open' ? '' : 'no-history'}">
        <aside class="history"><div class="history-head"><span>History</span>
          <span class="row" style="gap:2px"><button class="btn sm ghost" data-action="chat-new" title="New chat">${icon('plus', 14)} New</button>
          <button class="btn sm ghost icon" data-action="history-toggle" title="Hide history" aria-label="Hide history">${icon('close', 14)}</button></span></div>
          <div class="history-list" id="chat-history"></div></aside>
        <div class="chat">
        <div class="chat-head">
          <button class="btn sm" id="history-btn" data-action="history-toggle" title="Show or hide past conversations">${icon('clock', 14)} History</button>
          ${state.aiReady ? `<span class="muted small">Model</span>${isAdmin() ? `<a class="badge" href="#/providers" title="Change the active model">${esc(state.aiModel)}</a>` : `<span class="badge">${esc(state.aiModel)}</span>`}` : '<span class="muted small">No model connected</span>'}
          <span class="spacer"></span>
          <button class="btn sm" id="chat-new" data-action="chat-new" hidden>${icon('plus', 14)} New chat</button></div>
        <div class="chat-log" id="chat-log"><div class="chat-inner"></div></div>
        <div class="chat-foot"><form class="chat-box" data-form="chat">
          <textarea name="q" id="chat-input" rows="1" placeholder="Ask about a host, IP, incident or time range…" aria-label="Message"></textarea>
          <button class="btn primary icon" id="chat-send"></button></form>
          <div class="chat-hint">Enter to send · Shift + Enter for a new line · Answers cite evidence as EVT and INC references</div></div>
        </div>
      </div>`,
      mount() {
        const q = params.get('q');
        // A question handed over from another page always starts its own conversation.
        if (q && !state.busy) clearChat();
        renderChat(true);
        refreshHistory();
        // After a reload, reopen the conversation that was on screen.
        if (state.chatId && !state.chat.length && !state.busy) openChat(state.chatId).catch(() => rememberChat(null));
        const input = $('#chat-input');
        const grow = () => { input.style.height = 'auto'; input.style.height = `${Math.min(input.scrollHeight, 200)}px`; };
        input.addEventListener('input', grow);
        input.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' && !e.shiftKey && !e.isComposing) { e.preventDefault(); input.form.requestSubmit(); }
        });
        input.focus();
        if (q) { history.replaceState(null, '', '#/console'); sendChat(q); }
      },
    };
  };

  async function sendChat(text) {
    text = String(text || '').trim();
    if (!text || state.busy) return;
    // The server replaces an unanswered question on the next send; mirror that so both sides stay in step.
    while (state.chat.length && state.chat[state.chat.length - 1].error) state.chat.pop();
    if (state.chat.length && state.chat[state.chat.length - 1].role === 'user') state.chat.pop();
    state.chat.push({ role: 'user', content: text });
    state.busy = true;
    state.live = { steps: [], started: Date.now() };
    state.abort = new AbortController();
    renderChat(true);
    const ticker = setInterval(() => {
      const el = $('#live-secs');
      if (el && state.live) el.textContent = Math.round((Date.now() - state.live.started) / 1000);
    }, 1000);
    try {
      const res = await fetch('/api/v1/ai/chat/stream', {
        method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin',
        body: JSON.stringify({ message: text, conversation_id: state.chatId, tz_offset: -new Date().getTimezoneOffset() }), signal: state.abort.signal,
      });
      if (res.status === 401) { state.user = null; boot(); return; }
      if (!res.ok) {
        let data = null;
        try { data = await res.json(); } catch { /* not JSON */ }
        if (res.status === 404 && state.chatId) { rememberChat(null); throw new Error('That conversation no longer exists. Send your question again to start a new one.'); }
        throw new Error(state.stale ? 'The CERBERUS server is running an older version. Restart it, then try again.' : errorDetail(data, res.status));
      }
      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buffer = ''; let final = null;
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let nl;
        while ((nl = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, nl).trim();
          buffer = buffer.slice(nl + 1);
          if (!line) continue;
          const step = JSON.parse(line);
          if (step.type === 'started') { rememberChat(step.conversation_id); refreshHistory(); }
          else if (step.type === 'tool') { state.live.steps.push(step); renderChat(); }
          else if (step.type === 'final') final = step;
          else if (step.type === 'error') throw new Error(step.detail);
        }
      }
      if (!final) throw new Error('The connection closed before the answer arrived. Try again.');
      state.chat.push(final.message);
    } catch (err) {
      state.chat.push({ role: 'assistant', error: true, content: err.name === 'AbortError' ? 'Stopped before the answer was ready.' : (err.message || String(err)) });
    } finally {
      clearInterval(ticker);
      state.busy = false; state.live = null; state.abort = null;
      renderChat(true);
      refreshHistory();
      loadOverview().catch(() => {});
      const input = $('#chat-input');
      if (input) input.focus();
    }
  }

  // ---------- incidents / events ----------

  views.incidents = async ({ id, params }) => {
    if (id) return incidentDetail(id);
    const status = params.get('status') || 'active';
    const list = await api(`/incidents?status=${encodeURIComponent(status === 'all' ? '' : status)}`);
    const tabs = [['active', 'Active'], ['resolved', 'Resolved'], ['false_positive', 'False positives'], ['all', 'All']];
    return page('Incidents', 'Correlated cases built from events on the same asset and source.',
      `<div class="tabs">${tabs.map(([v, t]) => `<a href="#/incidents?status=${v}" class="${v === status ? 'on' : ''}">${t}</a>`).join('')}</div>`,
      list.length ? incidentTable(list, true)
        : empty(status === 'active' ? 'No active incidents' : 'Nothing here', status === 'active'
          ? 'Incidents open automatically when events of medium severity or higher arrive.' : 'No incidents with this status.', '', 'check'));
  };

  const evidenceCell = (e) => {
    const ref = e.evidence_ref || {};
    const url = safeUrl(ref.panel_url) || safeUrl(ref.dashboard_url) || safeUrl(ref.generator_url);
    if (url) return `<a class="link" href="${esc(url)}" target="_blank" rel="noopener noreferrer">Open in ${esc(ref.backend || 'source')}</a>`;
    const parts = [ref.backend, ref.index, ref.document_id, ref.query].filter(Boolean);
    return parts.length ? `<span class="mono muted">${esc(parts.join(' · '))}</span>` : '<span class="muted">—</span>';
  };

  const eventTable = (events) => `<div class="table-scroll"><table>
    <tr><th>Time</th><th>Source</th><th>Severity</th><th>Event</th><th>Asset / source IP</th><th>Evidence</th></tr>
    ${events.map((e) => `<tr class="sev-${esc(e.severity_label)}">
      <td class="nowrap">${fmtTime(e.ts)}<div class="muted mono">${esc(e.ref)}</div></td>
      <td><span class="badge">${esc(e.source)}</span></td>
      <td>${sevBadge(e.severity_label, e.severity)}</td>
      <td class="wrap"><strong>${esc(e.title)}</strong>${demoBadge(e.demo)}
        ${e.message ? `<div class="logline" title="Click to expand">${esc(e.message)}</div>` : ''}</td>
      <td>${esc(e.asset_name || '—')}<div class="mono muted">${esc(e.source_ip)}</div></td>
      <td class="wrap narrow">${evidenceCell(e)}</td></tr>`).join('')}</table></div>`;

  const timeline = (events) => `<div class="timeline">${events.map((e) => `<div class="tl-item">
    <div class="tl-time">${fmtTime(e.ts)}<div class="muted mono">${esc(e.ref)}</div></div>
    <div class="tl-rail"><span class="tl-dot sev-${esc(e.severity_label)}"></span></div>
    <div class="tl-body"><div class="tl-head"><strong>${esc(e.title)}</strong>${sevBadge(e.severity_label, e.severity)}<span class="badge">${esc(e.source)}</span>${demoBadge(e.demo)}</div>
      ${e.message ? `<div class="logline" title="Click to expand">${esc(e.message)}</div>` : ''}
      <div class="tl-meta">${[e.asset_name && esc(e.asset_name), e.source_ip && `from <span class="mono">${esc(e.source_ip)}</span>`, e.username && `user <span class="mono">${esc(e.username)}</span>`].filter(Boolean).join(' · ')}
        <span class="tl-evidence">${evidenceCell(e)}</span></div></div></div>`).join('')}</div>`;

  async function incidentDetail(id) {
    const i = await api(`/incidents/${id}`);
    const statuses = ['open', 'investigating', 'contained', 'resolved', 'false_positive'];
    return page(`${esc(i.ref)} · ${esc(i.title)}`,
      `${sevBadge(i.severity_label, i.severity)} ${statusBadge(i.status)}${i.demo ? ' <span class="badge">demo data</span>' : ''}`,
      `<select data-change="incident-status" data-id="${i.id}" style="width:auto" aria-label="Status">
        ${statuses.map((s) => `<option value="${s}" ${s === i.status ? 'selected' : ''}>${s.replace('_', ' ')}</option>`).join('')}</select>
       <a class="btn" href="#/console?q=${encodeURIComponent(`Tell me about incident ${i.ref}`)}">${icon('chat')} Ask about it</a>
       <button class="btn primary" data-action="investigate" data-id="${i.id}">${icon('spark')} ${i.summary ? 'Re-investigate' : 'Investigate with AI'}</button>`,
      `<div class="split">
        <div class="card card-pad"><h2>AI assessment</h2>
          <div id="summary" style="margin-top:10px">${i.summary ? `${md(i.summary)}<div class="muted small" style="margin-top:10px">${esc(i.summary_meta)}</div>`
            : '<span class="muted">Not investigated yet. The analyst will pull this timeline and related activity, then report facts, assessment and unknowns.</span>'}</div></div>
        <div class="stack">
          <div class="card card-pad"><h2>Details</h2><dl class="kv" style="margin-top:12px">
            <dt>Asset</dt><dd>${esc(i.asset_name || '—')} <span class="mono muted">${esc(i.asset_ip || '')}</span></dd>
            <dt>Source IP</dt><dd class="mono">${i.source_ip ? `<a class="link" href="#/events?q=${encodeURIComponent(i.source_ip)}">${esc(i.source_ip)}</a>` : '—'}</dd>
            <dt>Rule</dt><dd class="mono">${esc(i.rule_id || '—')}</dd>
            <dt>First seen</dt><dd>${fmtTime(i.first_seen)}</dd><dt>Last seen</dt><dd>${fmtTime(i.last_seen)}</dd></dl></div>
          <div class="card card-pad"><h2>Response requests</h2>
            ${i.approvals.length ? `${i.approvals.map((p) => `<div style="margin-top:12px"><strong>${esc(p.action)}</strong> → <span class="mono">${esc(p.target)}</span> ${statusBadge(p.status)}
              <div class="muted small">${esc(p.rationale)}</div></div>`).join('')}<div style="margin-top:14px"><a class="link" href="#/approvals">Open approvals</a></div>`
              : '<p class="muted" style="margin:10px 0 0">None. The analyst can propose actions; they wait for your decision.</p>'}</div>
        </div>
      </div>
      <div class="card"><div class="card-pad" style="padding-bottom:8px"><h2>Timeline · ${i.events.length} events</h2></div>${timeline(i.events)}</div>`,
      '<div class="crumb"><a href="#/incidents">Incidents</a><span>/</span><span>' + esc(i.ref) + '</span></div>');
  }

  views.events = async ({ overview, params }) => {
    const f = { q: params.get('q') || '', min: params.get('min') || '1', source: params.get('source') || '',
      start: params.get('start') || '', end: params.get('end') || '', range: params.get('range') === '7d' ? '7d' : '24h' };
    const enc = encodeURIComponent;
    const filters = `q=${enc(f.q)}&min_severity=${enc(f.min)}&source=${enc(f.source)}`;
    const [events, stats, o] = await Promise.all([
      api(`/events?${filters}&start=${enc(f.start)}&end=${enc(f.end)}`), api(`/events/stats?hours=${f.range === '7d' ? 168 : 24}&${filters}`), overview]);
    // Link to this page with some filters changed; the time window is dropped unless asked for.
    const link = (change = {}) => {
      const p = new URLSearchParams();
      const next = { q: f.q, source: f.source, min: f.min === '1' ? '' : f.min, range: f.range === '7d' ? '7d' : '', ...change };
      Object.entries(next).forEach(([k, v]) => { if (v) p.set(k, v); });
      return `#/events${p.toString() ? `?${p}` : ''}`;
    };
    const per = f.range === '7d' ? 6 : 1;
    const buckets = sevBuckets(stats.hourly, per);
    const list = (title, rows, toChange) => `<div><h3>${title}</h3><div class="hbars">${rows.length
      ? barList(rows.map((r) => ({ label: r.name, value: r.count, cls: 'series', href: link(toChange(r.name)) }))) : '<div class="muted small" style="padding:6px 0">Nothing yet</div>'}</div></div>`;
    const html = page('Events', 'Normalised detections from every connected engine. Click a bar or a row in the charts to filter.',
      `<form class="row" data-form="events-filter"><input type="hidden" name="range" value="${f.range}">
        <input type="text" name="q" value="${esc(f.q)}" placeholder="Search title, message, type, IP, user, asset" style="width:280px" aria-label="Search">
        <select name="source" style="width:auto" aria-label="Source" data-change="submit-form"><option value="">All sources</option>
          ${o.sources.map((s) => `<option value="${esc(s.source)}" ${s.source === f.source ? 'selected' : ''}>${esc(s.source)}</option>`).join('')}</select>
        <select name="min" style="width:auto" aria-label="Minimum severity" data-change="submit-form">${[['1', 'All severities'], ['4', 'Medium +'], ['7', 'High +'], ['9', 'Critical']]
          .map(([v, t]) => `<option value="${v}" ${v === f.min ? 'selected' : ''}>${t}</option>`).join('')}</select>
        <button class="btn">Search</button>${f.q || f.source || f.min !== '1' || f.start ? '<a class="btn ghost" href="#/events">Clear</a>' : ''}</form>`,
      `<div class="card card-pad">
        <div class="section-head" style="margin-bottom:6px"><h2>Event volume <span class="muted small">· ${stats.total.toLocaleString()} in the last ${f.range === '7d' ? '7 days' : '24 hours'}</span></h2>
          <div class="tabs"><a href="${link({ range: '' })}" class="${f.range === '24h' ? 'on' : ''}">24 hours</a><a href="${link({ range: '7d' })}" class="${f.range === '7d' ? 'on' : ''}">7 days</a></div></div>
        ${legend('sev', SEV_SERIES, sevTotals(buckets))}
        <div class="chart" id="events-volume"></div>
        <div class="breakdowns">${list('By source', stats.sources, (name) => ({ source: name }))}${list('By type', stats.types, (name) => ({ q: name }))}
          ${list('Top source IPs', stats.ips, (name) => ({ q: name }))}${list('Top assets', stats.assets, (name) => ({ q: name }))}</div>
      </div>
      ${f.start ? `<div class="callout info row" style="justify-content:space-between"><span>Showing events from <strong>${fmtTime(f.start)}</strong> to <strong>${fmtTime(f.end)}</strong>.</span><a class="btn sm" href="${link()}">Show all times</a></div>` : ''}
      ${events.length ? `<div class="card">${eventTable(events)}</div>` : empty('No events match', 'Connect a source under Integrations, or widen the filter.', '', 'search')}`);
    const keep = `${f.q ? `&q=${enc(f.q)}` : ''}${f.source ? `&source=${enc(f.source)}` : ''}${f.min !== '1' ? `&min=${enc(f.min)}` : ''}${f.range === '7d' ? '&range=7d' : ''}`;
    return { html, mount: () => sevChart('events-volume', buckets, per, keep) };
  };

  // ---------- application workspaces: one screen draws every page the server describes ----------

  const TONE_BAR = { critical: 'sev-critical', high: 'sev-high', medium: 'sev-medium', low: 'sev-low' };
  const outLink = (url, inner, cls = 'link') => `<a class="${cls}" href="${esc(url)}" target="_blank" rel="noopener noreferrer">${inner}</a>`;
  const appTile = (t) => {
    const numeric = typeof t.value === 'number';
    const inner = `<div><b class="raw ${numeric ? '' : 'stat-text'}">${numeric ? t.value.toLocaleString() : esc(t.value)}</b><span>${esc(t.label)}${t.hint ? ` <small>· ${esc(t.hint)}</small>` : ''}</span></div>`;
    return t.href ? `<a class="card stat t-${esc(t.tone)}" href="${esc(t.href)}">${inner}</a>` : `<div class="card stat still t-${esc(t.tone)}">${inner}</div>`;
  };
  const appBars = (b) => {
    const max = Math.max(1, ...b.items.map((i) => i.value));
    return `<div class="card card-pad"><h2>${esc(b.title)}</h2><div class="hbars wide">${b.items.length ? b.items.map((i) => `
      <${i.href ? `a href="${esc(i.href)}"` : 'div'} class="hbar" title="${esc(i.label)}: ${i.value.toLocaleString()}"><span class="hbar-label">${esc(i.label)}</span>
        <span class="hbar-track"><span class="hbar-fill ${TONE_BAR[i.tone] || 'series'}" style="width:${i.value ? Math.max(2, (i.value / max) * 100) : 0}%"></span></span>
        <span class="hbar-val">${fmtNum(i.value)}</span></${i.href ? 'a' : 'div'}>`).join('') : `<div class="muted small" style="padding:6px 0">${esc(b.empty)}</div>`}</div></div>`;
  };
  const appTrend = (b) => {
    const pts = b.points;
    if (!pts.length) return '';
    const max = Math.max(1, ...pts.map((p) => p.v));
    const peak = pts.reduce((a, p) => (p.v > a.v ? p : a), pts[0]);
    return `<div class="card card-pad trend-card"><div class="section-head" style="margin-bottom:10px"><h2>${esc(b.title)}</h2>
        <span class="muted small">Busiest: ${peak.v.toLocaleString()} around ${fmtTime(peak.t)}</span></div>
      <div class="trend">${pts.map((p) => `<span class="trend-col" title="${fmtTime(p.t)} · ${p.v.toLocaleString()}"><i style="height:${p.v ? Math.max(3, (p.v / max) * 100) : 0}%"></i></span>`).join('')}</div>
      <div class="trend-axis"><span>${fmtTime(pts[0].t)}</span><span>${fmtTime(pts[pts.length - 1].t)}</span></div></div>`;
  };
  const appCell = (c, r, first) => {
    const v = r[c.key];
    if (c.kind === 'time') return v ? `<td class="nowrap" data-v="${Date.parse(v) || 0}">${agoCell(v)}</td>` : '<td data-v="0">—</td>';
    if (c.kind === 'badge') return `<td>${v && v.text ? `<span class="badge ${esc(v.tone)}">${esc(v.text)}</span>` : ''}</td>`;
    if (c.kind === 'num') return `<td data-v="${Number(v) || 0}">${typeof v === 'number' ? v.toLocaleString() : esc(v ?? '')}</td>`;
    const text = esc(v === 0 ? '0' : v || '—');
    const url = first && !r._detail && safeUrl(r._url);
    return `<td class="${c.kind === 'mono' ? 'mono brk' : c.kind === 'wrap' ? 'wrap' : 'nowrap'}">${url ? outLink(url, `${text} ${icon('external', 13)}`) : text}</td>`;
  };
  const appTable = (b) => {
    const row = (r) => `<tr ${r._href ? `class="clickable" data-href="${esc(r._href)}"`
      : r._detail ? `class="clickable" data-action="row-detail" data-detail="${esc(r._detail)}" data-url="${esc(safeUrl(r._url))}" data-cols="${b.columns.length}"` : ''}>${
      b.columns.map((c, i) => appCell(c, r, i === 0)).join('')}</tr>`;
    return `<div class="section-head app-section"><h2>${esc(b.title)}</h2>${b.note_time ? `<span class="muted small">${esc(b.note_label)} ${fmtTime(b.note_time)}</span>` : ''}</div>
      ${b.note ? `<p class="muted small app-note">${esc(b.note)}</p>` : ''}
      ${b.rows.length ? `<div class="card"><div class="table-scroll"><table><tr>${b.columns.map((c) => `<th data-sort="${c.kind === 'num' || c.kind === 'time' ? 'num' : 'text'}">${esc(c.label)}</th>`).join('')}</tr>
        ${b.rows.map(row).join('')}</table></div></div>${b.rows.some((r) => r._detail) ? '<p class="muted small" style="margin:8px 2px 0">Click a row for the details.</p>' : ''}`
    : `<div class="card card-pad muted">${esc(b.empty)}</div>`}`;
  };

  views.app = async ({ id, sub, params }) => {
    const pageId = sub || 'overview';
    const base = `#/app/${encodeURIComponent(id)}/${encodeURIComponent(pageId)}`;
    const d = await api(`/apps/${encodeURIComponent(id)}/${encodeURIComponent(pageId)}${params.toString() ? `?${params}` : ''}`);
    if (d.connected === false) {
      return page(esc(d.app_name), '', '', empty(`${esc(d.app_name)} is not connected`, isAdmin() ? 'Add its address and sign-in details under Integrations.' : 'Ask an admin to connect it under Integrations.',
        isAdmin() ? '<div style="margin-top:14px"><a class="btn primary" href="#/integrations">Open Integrations</a></div>' : '', 'plug'));
    }
    const filters = d.filters.length ? `<form class="row app-filters" data-form="app-filter" data-base="${esc(base)}">${d.filters.map((f) => (f.kind === 'select'
      ? `<select name="${esc(f.name)}" style="width:auto" aria-label="${esc(f.label)}" data-change="submit-form">${f.options.map(([v, t]) => `<option value="${esc(v)}" ${v === f.value ? 'selected' : ''}>${esc(t)}</option>`).join('')}</select>`
      : `<input type="text" name="${esc(f.name)}" value="${esc(f.value)}" placeholder="${esc(f.label)}" aria-label="${esc(f.label)}" style="width:${Number(f.width) || 220}px">`)).join('')}
      <button class="btn">Apply</button>${params.toString() ? `<a class="btn ghost" href="${esc(base)}">Clear</a>` : ''}</form>` : '';
    const tiles = d.tiles.length ? `<div class="stats app-stats" style="--n:${Math.min(4, d.tiles.length)}">${d.tiles.map(appTile).join('')}</div>` : '';
    let body = '';
    let run = [];
    const flush = () => { if (run.length) { body += `<div class="app-grid">${run.join('')}</div>`; run = []; } };
    d.blocks.forEach((b) => { if (b.type === 'bars') { run.push(appBars(b)); return; } flush(); body += b.type === 'trend' ? appTrend(b) : appTable(b); });
    flush();
    const open = d.external && safeUrl(d.external.url) ? outLink(d.external.url, `${icon('external', 16)} ${esc(d.external.label)}`, 'btn') : '';
    return { html: page(esc(d.title), esc(d.subtitle || ''), open, filters + tiles + body), mount: () => { $('#top-title').textContent = `${d.app_name} · ${d.label}`; } };
  };

  // ---------- AI briefings ----------

  // Ask the model for a short written briefing and show it in `target`. The server gathers the data.
  async function aiBrief(target, body, title) {
    const head = (extra = '') => `<div class="ai-head">${icon('spark', 16)}<b>${title}</b>${extra}</div>`;
    target.innerHTML = `<div class="card ai-card">${head()}<div class="working"><span class="spinner"></span><span>Reading the data…</span></div></div>`;
    try {
      const r = await api('/ai/brief', { method: 'POST', body: { ...body, tz_offset: -new Date().getTimezoneOffset() } });
      target.innerHTML = `<div class="card ai-card">${head(`<span class="muted small">${esc(r.model)}</span><span class="spacer"></span>
        <button class="btn ghost sm" data-action="ai-copy">${icon('copy', 14)} Copy</button><button class="btn ghost icon sm" data-action="ai-dismiss" title="Dismiss" aria-label="Dismiss">${icon('close', 14)}</button>`)}${md(r.text)}</div>`;
      target.dataset.text = r.text;
    } catch (err) {
      target.innerHTML = `<div class="callout">${esc(err.message)}</div>`;
    }
    // Remembered so a background refresh of the page does not wipe it.
    if (target.id === 'ai-insight') state.insight = { key: current, html: target.innerHTML, text: target.dataset.text || '' };
  }
  const BRIEF_TITLES = { overview: 'AI brief: the last 24 hours', infrastructure: 'AI health brief', logs: 'AI summary of these logs' };

  // ---------- AI watch (scheduled analyst) ----------

  const KIND_ICON = { disk: 'server', memory: 'activity', cpu: 'activity', load: 'activity', probe: 'plug', target: 'plug', logerr: 'terminal' };

  views.watch = async ({ params }) => {
    const w = await api('/watch');
    const s = w.settings;
    const admin = isAdmin();
    const wanted = params.get('tab');
    const tab = wanted === 'history' || (wanted === 'settings' && admin) ? wanted : 'now';
    const firing = w.findings.filter((x) => x.status === 'firing');
    const dismissed = w.findings.filter((x) => x.status === 'dismissed');
    const recovered = w.findings.filter((x) => x.status === 'recovered');
    const band = (x) => (x.severity >= 9 ? 'critical' : x.severity >= 7 ? 'high' : 'medium');
    const critical = firing.filter((x) => x.severity >= 9).length;
    // The analyst writes one note for all the findings of a check, so it is shown once, not on every finding.
    const notes = [...new Set(firing.map((x) => x.ai_note).filter(Boolean))];
    const ready = (ok, yes, no, href) => `<span class="${ok ? '' : 'warn'}">${ok ? icon('check', 13) : icon('alert', 13)} ${ok ? yes : (admin && href ? `<a href="${href}">${no}</a>` : no)}</span>`;
    const asked = (x) => encodeURIComponent(`${x.title}. Since when has this been the case, what is the likely cause, and what should I do?`);
    const untilNext = w.next_run ? Math.max(0, Math.round((Date.parse(w.next_run) - Date.now()) / 60000)) : null;
    const lastRun = w.runs[0];
    const row = (x) => `<div class="frow sev-${band(x)} ${x.status}">
      <span class="frow-ic">${icon(KIND_ICON[x.kind] || 'alert', 18)}</span>
      <div class="frow-main"><b>${esc(x.title)}</b><span>${esc(x.detail)}</span>
        <div class="fd-meta">${x.status === 'recovered' ? `From ${fmtTime(x.first_seen)} to ${fmtTime(x.last_seen)}` : `Since ${fmtTime(x.first_seen)} · ${ago(x.first_seen)}`}
          ${x.incident_id ? `<a class="ref" href="#/incidents/${x.incident_id}">INC-${String(x.incident_id).padStart(4, '0')}</a>` : ''}
          ${x.status !== 'recovered' ? `<a class="link" href="#/console?q=${asked(x)}">Ask the AI</a>` : ''}
          ${x.kind === 'logerr' ? `<a class="link" href="#/logs?host=${encodeURIComponent(x.asset)}&level=error">Error logs</a>` : ''}
          ${['disk', 'memory', 'cpu', 'load'].includes(x.kind) ? '<a class="link" href="#/infrastructure">Infrastructure</a>' : ''}</div></div>
      <div class="frow-side">${x.status === 'firing' ? sevBadge(band(x), x.severity) : x.status === 'recovered' ? '<span class="badge ok">recovered</span>' : '<span class="badge">dismissed</span>'}
        ${x.status === 'firing' ? `<button class="btn sm ghost" data-action="watch-dismiss" data-key="${esc(x.key)}" title="Hide this until it recovers and happens again">${icon('close', 13)} Dismiss</button>` : ''}
        ${x.status === 'dismissed' ? `<button class="btn sm ghost" data-action="watch-restore" data-key="${esc(x.key)}">Restore</button>` : ''}</div></div>`;
    const num = (name, label, value, hint, attrs) => `<div class="field"><label for="w-${name}">${label}</label><input id="w-${name}" type="number" name="${name}" value="${esc(value)}" ${attrs} required>
      ${hint ? `<div class="hint">${hint}</div>` : ''}</div>`;
    const tick = (name, label, on, group = '') => `<label class="check"><input type="checkbox" name="${name}" ${group} ${on ? 'checked' : ''}> ${label}</label>`;
    const option = (v, t, current) => `<option value="${v}" ${String(v) === String(current) ? 'selected' : ''}>${t}</option>`;

    const now = `
      <div class="stats watch-stats">
        <div class="card stat ${critical ? 'alert' : firing.length ? 'attn' : ''}"><div class="ico">${icon('alert', 20)}</div><div><b>${firing.length}</b><span>Need attention${critical ? ` · ${critical} critical` : ''}</span></div></div>
        <div class="card stat"><div class="ico">${icon('check', 20)}</div><div><b>${recovered.length}</b><span>Recovered in 24 hours</span></div></div>
        <div class="card stat"><div class="ico">${icon('close', 20)}</div><div><b>${dismissed.length}</b><span>Dismissed</span></div></div>
        <div class="card stat"><div class="ico">${icon('clock', 20)}</div><div><b class="stat-text">${!s.enabled ? 'Off' : untilNext === null ? '—' : untilNext === 0 ? 'Any moment' : `${untilNext} min`}</b><span>${s.enabled ? 'Until the next check' : 'No checks scheduled'}</span></div></div>
      </div>
      <div class="section-head" style="margin-top:6px"><h2>Needs attention <span class="muted small">· ${firing.length}</span></h2>
        ${firing.length > 1 ? `<button class="btn sm ghost" data-action="watch-dismiss" data-key="*">${icon('close', 13)} Dismiss all</button>` : ''}</div>
      ${firing.length ? `<div class="card frows">${firing.map(row).join('')}</div>`
        : empty(w.last_run ? 'All clear' : 'No checks yet', w.last_run ? (dismissed.length ? 'Nothing new. Dismissed items are listed below.' : 'Nothing crossed a limit in the latest check.') : 'Run a check to see what it finds.', '', 'check')}
      ${notes.length ? `<div class="card ai-card watch-note"><div class="ai-head">${icon('spark', 16)}<b>AI analyst on the latest findings</b>
        <span class="muted small">${lastRun ? ago(firing.find((x) => x.ai_note).first_seen) : ''}</span></div>${notes.map((n) => md(n)).join('<hr>')}</div>` : ''}
      ${dismissed.length ? `<details class="fold"><summary>${dismissed.length} dismissed <span class="muted small">hidden until they recover and happen again</span></summary><div class="card frows">${dismissed.map(row).join('')}</div></details>` : ''}
      ${recovered.length ? `<details class="fold" open><summary>${recovered.length} recovered in the last 24 hours</summary><div class="card frows">${recovered.map(row).join('')}</div></details>` : ''}`;

    const history = w.runs.length ? `<div class="card"><div class="table-scroll"><table>
        <tr><th>Time</th><th>Started by</th><th>Result</th><th>Took</th></tr>
        ${w.runs.map((r) => `<tr><td class="nowrap">${fmtTime(r.ts)}</td><td>${r.reason === 'manual' ? 'Someone, by hand' : 'Schedule'}</td>
          <td>${r.ok ? `${r.firing} need attention${r.fresh ? ` · <strong>${r.fresh} new</strong>` : ''}${r.recovered ? ` · ${r.recovered} recovered` : ''}` : `<span style="color:var(--bad)">Failed: ${esc(r.error)}</span>`}</td>
          <td>${r.seconds} s</td></tr>`).join('')}</table></div></div>` : empty('No checks yet', 'Each check is listed here with what it found.', '', 'clock');

    const settings = `<div class="card card-pad"><form data-form="watch">
          <div class="watch-grid">
            <div><h3>Checks</h3>${Object.entries(w.check_names).map(([k, name]) => tick(k, name, s.checks[k], 'data-check')).join('')}
              <div class="field" style="margin-top:14px"><label for="w-int">Check every</label><select id="w-int" name="interval_minutes">${[1, 2, 5, 10, 15, 30, 60].map((v) => option(v, `${v} minute${v === 1 ? '' : 's'}`, s.interval_minutes)).join('')}</select></div></div>
            <div><h3>Limits</h3>
              <div class="grid-2">${num('disk_pct', 'Disk full at (%)', s.disk_pct, '', 'min="50" max="100"')}${num('memory_pct', 'Memory at (%)', s.memory_pct, '', 'min="50" max="100"')}
                ${num('cpu_pct', 'CPU at (%)', s.cpu_pct, '', 'min="50" max="100"')}${num('load_factor', 'Load above cores ×', s.load_factor, '', 'min="0.1" max="10" step="0.1"')}</div>
              ${num('log_errors_5m', 'Error lines from one host in 5 minutes', s.log_errors_5m, 'Raise this if a noisy host keeps tripping it.', 'min="1" max="1000000"')}</div>
            <div><h3>Telling you</h3>${tick('notify_in_app', 'Notification in the app', s.notify_in_app)}${tick('notify_email', 'Email the admins', s.notify_email)}
              <div class="field" style="margin-top:10px"><label for="w-sev">Email only when at least</label><select id="w-sev" name="email_min_severity">${[[4, 'Medium'], [7, 'High'], [9, 'Critical']].map(([v, t]) => option(v, t, s.email_min_severity)).join('')}</select></div>
              <div class="field"><label for="w-quiet">Repeat the same problem at most every</label><select id="w-quiet" name="renotify_hours">${[1, 3, 6, 12, 24].map((v) => option(v, `${v} hour${v === 1 ? '' : 's'}`, s.renotify_hours)).join('')}</select></div>
              ${tick('ai_writeup', 'Have the AI explain each new finding', s.ai_writeup)}${tick('digest_enabled', 'Daily digest by email', s.digest_enabled)}
              <div class="field" style="margin-top:10px"><label for="w-hour">Digest time</label><select id="w-hour" name="digest_hour">${Array.from({ length: 24 }, (_, h) => option(h, `${String(h).padStart(2, '0')}:00`, s.digest_hour)).join('')}</select></div></div>
          </div>
          <div class="row"><button class="btn primary">Save</button><button type="button" class="btn" data-action="watch-digest">Send the digest now</button></div>
        </form></div>`;

    return `<div class="page">
      <div class="page-head"><div><h1>AI watch</h1><p>A scheduled analyst: it checks your servers and logs on its own, explains what it finds, and tells you.</p></div>
        <div class="row">${admin ? `<button class="btn" data-action="watch-run">${icon('retry', 16)} Run a check now</button>
          <button class="btn ${s.enabled ? '' : 'primary'}" data-action="watch-toggle" data-on="${s.enabled ? '' : '1'}">${s.enabled ? 'Turn off' : 'Turn on'}</button>` : ''}</div></div>
      <div class="card watch-status ${s.enabled ? 'on' : ''}">
        <div class="ws-icon">${icon('eye', 26)}</div>
        <div class="ws-text"><b>${s.enabled ? 'AI watch is on' : 'AI watch is off'}</b>
          <span>${s.enabled ? `Checks every ${s.interval_minutes} minute${s.interval_minutes === 1 ? '' : 's'}${w.last_run ? ` · last check ${ago(w.last_run)}` : ' · first check in under a minute'}`
            : (admin ? 'Turn it on to be told about problems without having to ask. You can also run a single check now.' : 'An admin can turn it on.')}
            ${lastRun && !lastRun.ok ? ` · <span style="color:var(--bad)">last check failed: ${esc(lastRun.error)}</span>` : ''}</span></div>
        <div class="stat-chips" style="margin:0">${ready(w.metrics_connected, 'Metrics', 'Connect metrics', '#/integrations')}${ready(w.logs_connected, 'Logs', 'Connect logs', '#/integrations')}
          ${ready(w.ai_ready, 'AI write-ups', 'No AI model', '#/providers')}${ready(w.email_ready, 'Email alerts', 'Email not ready', '#/integrations')}</div></div>
      <div class="tabs watch-tabs"><a href="#/watch" class="${tab === 'now' ? 'on' : ''}">Now${firing.length ? ` <span class="badge ${critical ? 'critical' : 'high'}">${firing.length}</span>` : ''}</a>
        <a href="#/watch?tab=history" class="${tab === 'history' ? 'on' : ''}">Check history</a>
        ${admin ? `<a href="#/watch?tab=settings" class="${tab === 'settings' ? 'on' : ''}">Settings</a>` : ''}</div>
      ${tab === 'history' ? history : tab === 'settings' ? settings : now}
    </div>`;
  };

  // ---------- logs (Loki through Grafana) ----------

  const LOG_SERIES = [['error', 'Error', 'lvl-error'], ['warn', 'Warning', 'lvl-warn'], ['info', 'Info', 'lvl-info'], ['debug', 'Debug', 'lvl-debug'], ['other', 'No level', 'lvl-other']];
  const LEVEL_MATCH = { error: 'error|err|critical|crit|fatal|emerg|alert|panic', warn: 'warn|warning', info: 'info|notice|informational', debug: 'debug|trace' };
  const LOG_RANGES = [['15', '15 minutes'], ['60', '1 hour'], ['360', '6 hours'], ['1440', '24 hours']];
  const logqlText = (v) => String(v).replace(/\\/g, '\\\\').replace(/"/g, '\\"');
  // Lines without a level label are classified from their text so problems still stand out.
  const lineLevel = (l) => (l.level !== 'other' ? l.level
    : /\b(error|fatal|panic|critical|failed|failure|denied|refused|segfault)\b/i.test(l.line) ? 'error' : /\bwarn(ing)?\b/i.test(l.line) ? 'warn' : 'other');
  const notConnected = (what, need) => empty(`${what} are not connected`, isAdmin() ? `Add your Grafana address, a service account token and the ${need} datasource under Integrations.`
    : `Ask an admin to connect Grafana with a ${need} datasource.`, isAdmin() ? '<div style="margin-top:14px"><a class="btn" href="#/integrations">Open Integrations</a></div>' : '', 'plug');

  // Saved searches are kept in this browser only.
  const savedSearches = {
    all() { try { return JSON.parse(localStorage.getItem('cerberus-log-saves') || '[]'); } catch { return []; } },
    set(list) { try { localStorage.setItem('cerberus-log-saves', JSON.stringify(list.slice(0, 12))); } catch { /* storage blocked */ } },
  };

  views.logs = async ({ overview, params }) => {
    const o = await overview;
    if (!o.loki_configured) return page('Logs', 'Search and chart the logs collected in Loki.', '', notConnected('Logs', 'Loki'));
    const enc = encodeURIComponent;
    const f = { job: params.get('job') || '', host: params.get('host') || '', program: params.get('program') || '', level: params.get('level') || '',
      text: params.get('text') || '', minutes: params.get('minutes') || '15', start: params.get('start') || '', end: params.get('end') || '',
      tab: params.get('tab') === 'patterns' ? 'patterns' : 'explore', live: params.get('live') === '1' };
    const matchers = [f.job && `job="${logqlText(f.job)}"`, f.host && `host="${logqlText(f.host)}"`, f.program && `program="${logqlText(f.program)}"`].filter(Boolean);
    const levelFilter = LEVEL_MATCH[f.level] ? ` | detected_level=~"${LEVEL_MATCH[f.level]}"` : '';
    // Text starting with "{" is taken as a full LogQL query; anything else means "lines containing".
    const raw = f.text.trim().startsWith('{');
    const query = raw ? f.text.trim() : `{${matchers.length ? matchers.join(', ') : 'job=~".+"'}}${levelFilter}${f.text ? ` |= "${logqlText(f.text)}"` : ''}`;
    const zoomed = Boolean(f.start && f.end);
    const [labels, data] = await Promise.all([
      state.logLabels ? state.logLabels : api('/logs/labels').then((l) => { state.logLabels = l; return l; }).catch(() => ({ job: [], host: [], program: [] })),
      api(`/logs?query=${enc(query)}&minutes=${enc(f.minutes)}&limit=200${zoomed ? `&start=${enc(f.start)}&end=${enc(f.end)}` : ''}`)
        .catch((err) => ({ error: err.message, lines: [], volume: [], patterns: [], total: 0 }))]);
    const link = (change = {}) => {
      const next = { job: f.job, host: f.host, program: f.program, level: f.level, text: f.text, minutes: f.minutes === '15' ? '' : f.minutes,
        start: f.start, end: f.end, tab: f.tab === 'patterns' ? 'patterns' : '', live: f.live ? '1' : '', ...change };
      const p = new URLSearchParams();
      Object.entries(next).forEach(([k, v]) => { if (v) p.set(k, v); });
      return `#/logs${p.toString() ? `?${p}` : ''}`;
    };
    state.logs = { data, query, f, link };
    const buckets = data.volume.map((v) => ({ ...v, t: Date.parse(v.ts) }));
    const totals = Object.fromEntries(LOG_SERIES.map(([k]) => [k, buckets.reduce((n, b) => n + (b[k] || 0), 0)]));
    const rangeName = zoomed ? `${clock(Date.parse(f.start))} – ${clock(Date.parse(f.end))}` : `Last ${(LOG_RANGES.find(([v]) => v === f.minutes) || LOG_RANGES[0])[1]}`;
    const facetsOpen = pref.get('logfacets', 'open') === 'open';
    const chartOpen = pref.get('logchart', 'open') === 'open';

    const chips = [['job', 'Job'], ['host', 'Host'], ['program', 'Program'], ['level', 'Level']].filter(([k]) => f[k])
      .map(([k, name]) => `<a class="fchip" href="${link({ [k]: '' })}" title="Remove this filter">${name}: <b>${esc(f[k])}</b>${icon('close', 12)}</a>`);
    if (zoomed) chips.push(`<a class="fchip" href="${link({ start: '', end: '' })}" title="Back to the full range">Time: <b>${rangeName}</b>${icon('close', 12)}</a>`);
    const saved = savedSearches.all().map((x) => `<span class="fchip saved"><a href="#/logs?${esc(x.q)}">${icon('star', 12)} ${esc(x.name)}</a>
      <button type="button" data-action="log-unsave" data-name="${esc(x.name)}" title="Remove this saved search" aria-label="Remove">${icon('close', 12)}</button></span>`);

    // Facets: what the newest lines are made of, each row a one-click filter.
    const tally = (pick) => { const m = new Map(); data.lines.forEach((l) => { const v = pick(l); if (v) m.set(v, (m.get(v) || 0) + 1); }); return [...m].sort((a, b) => b[1] - a[1]).slice(0, 8); };
    const facet = (title, name, rows) => (rows.length ? `<div class="facet"><h4>${title}</h4>${rows.map(([v, n]) => `<button type="button" class="facet-row ${f[name] === v ? 'on' : ''}" data-action="log-filter" data-name="${name}" data-value="${esc(v)}">
      <span class="fr-name">${esc(name === 'level' ? LOG_SERIES.find(([k]) => k === v)[1] : v)}</span><span class="fr-bar"><i style="width:${Math.max(4, (n / rows[0][1]) * 100)}%"></i></span><span class="fr-n">${n}</span></button>`).join('')}</div>` : '');
    const facets = `<aside class="facets card"><div class="facets-note">From the newest ${data.lines.length} lines</div>
      ${facet('Level', 'level', tally((l) => (LEVEL_MATCH[lineLevel(l)] ? lineLevel(l) : '')))}${facet('Host', 'host', tally((l) => l.labels.host))}${facet('Program', 'program', tally((l) => l.labels.program))}
      ${labels.job.length > 1 ? facet('Job', 'job', tally((l) => l.labels.job)) : ''}</aside>`;

    const rows = data.lines.map((l, i) => `<div class="logrow lvl-${lineLevel(l)}" data-action="log-open" data-i="${i}" tabindex="0" title="Open this line">
      <span class="lr-time">${esc(new Date(l.ts).toLocaleTimeString([], { hour12: false }))}</span>
      <span class="lr-src">${l.labels.host ? `<span class="lr-chip">${esc(l.labels.host)}</span>` : ''}${l.labels.program ? `<span class="lr-chip">${esc(l.labels.program)}</span>` : ''}</span>
      <span class="lr-text">${esc(l.line)}</span></div>`).join('');
    const nothing = `<div class="empty">${icon('search', 34)}<h3>No log lines found</h3><div>Try a longer time range or fewer filters.</div>
      <div style="margin-top:14px"><button class="btn" data-action="reload">${icon('retry', 16)} Refresh</button></div></div>`;
    const patterns = data.patterns.length ? `<div class="patterns">${data.patterns.map((p) => `<details class="pattern"><summary>
      <span class="pt-n">${p.count}</span><span class="fr-bar"><i style="width:${Math.max(4, (p.count / data.patterns[0].count) * 100)}%"></i></span>
      <span class="pt-text">${esc(p.pattern)}</span><span class="lr-src">${p.host ? `<span class="lr-chip">${esc(p.host)}</span>` : ''}${p.program ? `<span class="lr-chip">${esc(p.program)}</span>` : ''}</span></summary>
      <div class="pt-example"><span class="muted small">Example</span><pre>${esc(p.example)}</pre></div></details>`).join('')}</div>` : nothing;

    const html = `<div class="page wide">
      <div class="page-head"><div><h1>Logs</h1><p>Your Loki logs, read through Grafana.</p></div>
        <div class="tabs"><a href="${link({ tab: '' })}" class="${f.tab === 'explore' ? 'on' : ''}">Explore</a>
          <a href="${link({ tab: 'patterns' })}" class="${f.tab === 'patterns' ? 'on' : ''}">Patterns <span class="badge">${data.patterns.length}</span></a></div></div>
      <div class="toolbar">
        <button class="btn icon ${facetsOpen ? 'on' : ''}" data-action="log-facets" title="Show or hide the filter panel" aria-label="Filter panel">${icon('panel')}</button>
        <form class="tb-search" data-form="logs-filter">${icon('search', 17)}
          <input type="text" name="text" value="${esc(f.text)}" placeholder="Search lines, or write a LogQL query starting with {" autocomplete="off" spellcheck="false" aria-label="Search logs">
          <div class="pop-wrap"><button type="button" class="tb-help" data-action="menu" title="Search help" aria-label="Search help">?</button>
            <div class="pop menu help" hidden><b>Searching logs</b>
              <p>Type any text to find lines that contain it, for example <code>Failed password</code>.</p>
              <p>For full control write LogQL, starting with a brace:</p>
              <pre>{host="web01"} |= "error" != "timeout"</pre>
              <p>Use the panel on the left, or click a host or program in a line, to filter without typing.</p>
              <p class="muted small" style="margin:0">Query in use: <span class="mono">${esc(query)}</span></p></div></div></form>
        <a class="btn ${f.live ? 'on live-on' : ''}" href="${link({ live: f.live ? '' : '1', start: '', end: '' })}" title="Reload the newest lines every 5 seconds">${icon(f.live ? 'stop' : 'play', 16)} Live</a>
        <div class="pop-wrap"><button class="btn" data-action="menu">${icon('clock', 16)} ${rangeName}</button>
          <div class="pop menu" hidden>${LOG_RANGES.map(([v, t]) => `<a class="menu-item ${!zoomed && v === f.minutes ? 'on' : ''}" href="${link({ minutes: v === '15' ? '' : v, start: '', end: '' })}">Last ${t}</a>`).join('')}</div></div>
        <button class="btn" data-action="log-ai" title="Have the AI analyst summarise what these logs show">${icon('spark', 16)} Summarise</button>
        <div class="pop-wrap"><button class="btn icon" data-action="menu" title="More" aria-label="More">${DOTS}</button>
          <div class="pop menu" hidden><button class="menu-item" data-action="log-export">${icon('download', 16)}<span>Export these lines</span></button>
            <button class="menu-item" data-action="log-copy-query">${icon('copy', 16)}<span>Copy the query</span></button>
            <button class="menu-item" data-action="log-save">${icon('star', 16)}<span>Save this search</span></button></div></div>
      </div>
      ${chips.length || saved.length ? `<div class="fchips">${chips.join('')}${saved.length ? `<span class="muted small">Saved</span>${saved.join('')}` : ''}</div>` : ''}
      ${data.error ? `<div class="callout">${esc(data.error)}</div>` : ''}${data.warning ? `<div class="callout info">${esc(data.warning)}</div>` : ''}
      <div class="card chart-card ${chartOpen ? '' : 'closed'}"><div class="cc-head"><b>Log volume</b><span class="muted small">${fmtNum(data.total)} lines · ${rangeName}</span>
        <span class="spacer"></span>${legend('lvl', LOG_SERIES, totals)}
        <button class="btn icon sm" data-action="chart-collapse" title="Show or hide the chart" aria-label="Show or hide the chart">${icon('chevron', 16)}</button></div>
        <div class="cc-body"><div class="chart" id="logs-volume"></div></div></div>
      <div id="ai-insight"></div>
      <div class="logs-body ${facetsOpen ? '' : 'no-facets'}">${facets}
        <div class="card logs-list"><div class="ll-head"><b>${f.tab === 'patterns' ? `${data.patterns.length} patterns` : `Newest ${data.lines.length} lines`}</b>
          ${f.live ? '<span class="live"><span class="dot on"></span>Live</span>' : ''}<span class="spacer"></span>
          <span class="muted small">${f.tab === 'patterns' ? 'Similar lines grouped together, with the changing parts replaced' : 'Click a line for details, surrounding lines and an AI explanation'}</span></div>
          ${f.tab === 'patterns' ? patterns : (rows ? `<div class="logrows">${rows}</div>` : nothing)}</div></div>
    </div>`;
    const stepMs = (data.step || 60) * 1000;
    return { html, mount() {
      stackChart('logs-volume', buckets, { series: LOG_SERIES, group: 'lvl', span: stepMs, unit: ['line', 'lines'], empty: 'No log lines in this period.',
        axis: (b, i, n) => (i % Math.ceil(n / 6) === 0 ? clock(b.t) : ''), pickHint: 'Click to zoom into this moment',
        onPick: (b) => { location.hash = link({ start: new Date(b.t).toISOString(), end: new Date(b.t + stepMs).toISOString(), live: '' }); } });
      if (f.live) {
        state.logTimer = setInterval(() => {
          const typing = document.activeElement && /^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement.tagName);
          if (current === 'logs' && !document.hidden && !typing && !$('#log-drawer') && !$('dialog[open]') && !$('.pop:not([hidden])') && !String(getSelection())) route({ soft: true });
        }, 5000);
      }
    } };
  };

  function closeDrawer() { const d = $('#log-drawer'); if (d) d.remove(); }
  function openLogDrawer(index) {
    closeDrawer();
    const l = state.logs && state.logs.data.lines[index];
    if (!l) return;
    state.logLine = l;
    const level = lineLevel(l);
    const d = document.createElement('aside');
    d.id = 'log-drawer';
    d.className = 'drawer-panel';
    d.innerHTML = `<div class="dp-head"><div><b>Log line</b><small>${esc(new Date(l.ts).toLocaleString())}${LEVEL_MATCH[level] ? ` · ${LOG_SERIES.find(([k]) => k === level)[1]}` : ''}</small></div>
        <button class="btn ghost icon" data-action="drawer-close" title="Close (Esc)" aria-label="Close">${icon('close')}</button></div>
      <div class="dp-body"><pre class="dp-line lvl-${level}">${esc(l.line)}</pre>
        <div class="row"><button class="btn sm primary" data-action="log-explain">${icon('spark', 14)} Explain with AI</button>
          <button class="btn sm" data-action="log-context">Show surrounding lines</button><button class="btn sm" data-action="log-copy-line">${icon('copy', 14)} Copy</button></div>
        <div id="dp-ai"></div><div id="dp-context"></div>
        <h4>Labels</h4><dl class="kv dp-labels">${Object.entries(l.labels).map(([k, v]) => `<dt>${esc(k)}</dt><dd><span>${esc(v)}</span>
          ${['host', 'program', 'job'].includes(k) ? `<button class="linklike" data-action="log-filter" data-name="${k}" data-value="${esc(v)}">filter</button>` : ''}</dd>`).join('')}</dl></div>`;
    document.body.appendChild(d);
  }

  // ---------- infrastructure (Prometheus through Grafana) ----------

  const meter = (label, value) => {
    if (value === undefined || value === null) return '';
    const state = value >= 90 ? 'crit' : value >= 75 ? 'warn' : 'ok';
    return `<div class="meter ${state}" title="${label}: ${value.toFixed(1)}%"><div class="meter-top"><span>${label}</span><b>${Math.round(value)}%${state === 'crit' ? ' · high' : state === 'warn' ? ' · elevated' : ''}</b></div>
      <div class="meter-track"><span style="width:${Math.min(100, Math.max(1, value))}%"></span></div></div>`;
  };

  views.infrastructure = async ({ overview }) => {
    const o = await overview;
    if (!o.metrics_configured) return page('Infrastructure', 'Live health of your servers and services.', '', notConnected('Metrics', 'Prometheus'));
    const h = await api('/infrastructure');
    const bare = (instance) => String(instance).replace(/:\d+$/, '');
    const targetUp = Object.fromEntries(h.scrape_targets.map((t) => [t.instance, t.up]));
    const down = h.scrape_targets.filter((t) => !t.up).length + h.http_probes.filter((p) => !p.up).length;
    const slowest = Math.max(0.001, ...h.http_probes.map((p) => p.response_seconds || 0));
    const badge = (up) => (up ? '<span class="badge ok">up</span>' : '<span class="badge critical">down</span>');
    return page('Infrastructure', 'Live health from Prometheus, read through Grafana. Refreshes every 30 seconds.',
      `<button class="btn" data-action="ai-brief" data-kind="infrastructure">${icon('spark', 16)} AI health brief</button>`,
      `<div id="ai-insight"></div><div class="stat-chips" style="margin-top:0"><span class="${down ? 'warn' : ''}"><b>${down ? `${down} down` : 'All up'}</b></span>
        <span><b>${h.hosts.length}</b> hosts</span><span><b>${h.scrape_targets.length}</b> scrape targets</span><span><b>${h.http_probes.length}</b> web checks</span></div>
      ${h.hosts.length ? `<div class="host-grid">${h.hosts.map((x) => `<div class="card host">
        <div class="host-head"><div><b>${esc(bare(x.instance))}</b><small class="mono">${esc(x.instance)}</small></div>${badge(targetUp[x.instance] !== false)}</div>
        ${meter('CPU', x.cpu_pct)}${meter('Memory', x.mem_pct)}${meter('Disk', x.disk_pct)}
        <div class="host-foot"><span title="1-minute load compared with the number of CPU cores">Load <b>${x.load1 ?? '—'}</b>${x.cpu_cores ? ` / ${x.cpu_cores} cores` : ''}</span><span>Up <b>${x.uptime_days === undefined ? '—' : `${x.uptime_days} d`}</b></span>
          <a class="link" href="#/logs?host=${encodeURIComponent(bare(x.instance))}">Logs</a></div></div>`).join('')}</div>` : ''}
      ${h.http_probes.length ? `<div class="card card-pad"><h2>Web checks</h2><div class="probes">${h.http_probes.map((p) => `<div class="probe">
        <div class="probe-name"><b>${esc(p.job || p.target)}</b><small class="mono">${esc(p.target)}</small></div>
        <div class="probe-bar" title="Response time ${p.response_seconds ?? '—'} s"><span class="${p.up ? '' : 'bad'}" style="width:${Math.max(2, ((p.response_seconds || 0) / slowest) * 100)}%"></span></div>
        <div class="probe-ms">${p.response_seconds === undefined ? '—' : `${Math.round(p.response_seconds * 1000)} ms`}</div>${badge(p.up)}</div>`).join('')}</div></div>` : ''}
      <div class="card"><div class="card-pad" style="padding-bottom:8px"><h2>Scrape targets</h2></div><div class="table-scroll"><table>
        <tr><th data-sort="text">Job</th><th data-sort="text">Instance</th><th data-sort="num">Status</th></tr>
        ${h.scrape_targets.map((t) => `<tr><td>${esc(t.job)}</td><td class="mono">${esc(t.instance)}</td><td data-v="${t.up ? 1 : 0}">${badge(t.up)}</td></tr>`).join('')}</table></div></div>
      ${h.query_errors.length ? `<div class="callout info">Some measurements were unavailable: ${esc(h.query_errors.join('; '))}</div>` : ''}`);
  };

  views.assets = async () => {
    const assets = await api('/assets');
    return page('Assets', 'Hosts and services seen in events. New names are added automatically on first sight.', '',
      assets.length ? `<div class="card"><div class="table-scroll"><table>
        <tr><th data-sort="text">Name</th><th data-sort="text">IP</th><th data-sort="text">Kind</th><th data-sort="text">Criticality</th><th data-sort="num">Open incidents</th><th data-sort="num">Events</th><th>Last event</th></tr>
        ${assets.map((a) => `<tr class="clickable" data-href="#/events?q=${encodeURIComponent(a.name)}"><td><strong>${esc(a.name)}</strong>${demoBadge(a.demo)}</td>
          <td class="mono">${esc(a.ip || '—')}</td><td>${esc(a.kind)}</td><td>${esc(a.criticality)}</td>
          <td>${a.open_incidents ? `<span class="badge high">${a.open_incidents}</span>` : '<span class="muted">0</span>'}</td><td>${a.event_count}</td><td class="nowrap">${agoCell(a.last_event)}</td></tr>`).join('')}
      </table></div></div>` : empty('No assets yet', 'Assets appear once events reference them.', '', 'server'));
  };

  views.approvals = async () => {
    const list = await api('/approvals');
    return page('Approvals', 'Response actions proposed by the AI analyst. Nothing runs without a decision from an admin.', '',
      `<div class="callout info">No response executor is connected yet. Approving records your decision in the audit trail; it does not change any firewall, account or host.</div>
      ${list.length ? `<div class="card"><div class="table-scroll"><table>
        <tr><th>Request</th><th>Incident</th><th>Rationale</th><th>Status</th><th></th></tr>
        ${list.map((p) => `<tr><td><strong>${esc(p.action)}</strong><div class="mono">${esc(p.target)}</div><div class="muted small">${fmtTime(p.created_at)} · ${esc(p.requested_by)}</div></td>
          <td>${p.incident_id ? `<a class="ref" href="#/incidents/${p.incident_id}">INC-${String(p.incident_id).padStart(4, '0')}</a><div class="muted">${esc(p.incident_title || '')}</div>` : '—'}</td>
          <td class="wrap">${esc(p.rationale)}${p.decision_note ? `<div class="muted small">Note: ${esc(p.decision_note)}</div>` : ''}</td>
          <td>${statusBadge(p.status)}${p.decided_by ? `<div class="muted small">${esc(p.decided_by)} · ${fmtTime(p.decided_at)}</div>` : `<div class="muted small">expires ${fmtTime(p.expires_at)}</div>`}</td>
          <td class="nowrap">${p.status === 'pending' && !isAdmin() ? '<span class="muted small">Waiting for an admin</span>' : ''}${p.status === 'pending' && isAdmin() ? `<button class="btn sm primary" data-action="decide" data-id="${p.id}" data-decision="approved" data-label="${esc(p.action)} → ${esc(p.target)}">Approve</button>
            <button class="btn sm" data-action="decide" data-id="${p.id}" data-decision="denied" data-label="${esc(p.action)} → ${esc(p.target)}">Deny</button>` : ''}</td></tr>`).join('')}
      </table></div></div>` : empty('Nothing waiting', 'When the analyst recommends containment, the request appears here.', '', 'check')}`);
  };

  // ---------- configuration ----------

  views.providers = async ({ id }) => {
    const { providers, presets } = await api('/ai/providers');
    state.presets = presets;
    const editing = providers.find((p) => String(p.id) === String(id));
    const rows = providers.map((p) => `<tr>
      <td><strong>${esc(p.name)}</strong> ${p.is_active ? '<span class="badge ok">active</span>' : ''}<div class="muted mono">${esc(p.base_url)}</div></td>
      <td class="mono">${esc(p.model || '— not set —')}</td>
      <td>${p.has_key ? `<span class="mono">${esc(p.key_hint || 'set')}</span>` : '<span class="muted">none</span>'}</td>
      <td class="nowrap" style="text-align:right">
        <button class="btn sm" data-action="provider-test" data-id="${p.id}">Test</button>
        ${p.is_active ? '' : `<button class="btn sm" data-action="provider-activate" data-id="${p.id}">Set active</button>`}
        <a class="btn sm" href="#/providers/${p.id}">Edit</a>
        <button class="btn sm danger" data-action="provider-delete" data-id="${p.id}" data-label="${esc(p.name)}">Delete</button></td></tr>`).join('');
    const f = editing || { kind: 'nvidia', name: '', base_url: '', model: '' };
    return {
      html: page('AI providers', 'The analyst talks to any OpenAI-compatible endpoint. Keys stay on the server and are never sent back to the browser.', '',
        `${providers.length ? `<div class="card"><div class="table-scroll"><table><tr><th>Provider</th><th>Model</th><th>API key</th><th></th></tr>${rows}</table></div></div>`
          : empty('No AI provider yet', 'Add NVIDIA NIM, a local model, or another API below.', '', 'spark')}
        <div class="card card-pad"><h2>${editing ? `Edit ${esc(editing.name)}` : 'Add a provider'}</h2>
          <form data-form="provider" data-id="${editing ? editing.id : ''}" style="margin-top:14px">
            <div class="grid-2">
              <div class="field"><label for="p-kind">Type</label><select id="p-kind" name="kind" data-change="provider-preset">
                ${presets.map((p) => `<option value="${esc(p.kind)}" ${p.kind === f.kind ? 'selected' : ''}>${esc(p.label)}</option>`).join('')}</select></div>
              <div class="field"><label for="p-name">Display name</label><input id="p-name" type="text" name="name" value="${esc(f.name)}" required maxlength="80"></div>
            </div>
            <div class="field"><label for="p-url">Base URL</label><input id="p-url" type="url" name="base_url" value="${esc(f.base_url)}" required placeholder="https://…/v1">
              <div class="hint" id="p-url-hint"></div></div>
            <div class="grid-2">
              <div class="field"><label for="p-key">API key</label><input id="p-key" type="password" name="api_key" autocomplete="off" placeholder="${editing && editing.has_key ? 'Leave blank to keep the saved key' : 'Not needed for most local servers'}"></div>
              <div class="field"><label for="p-model">Model</label>
                <div class="row" style="flex-wrap:nowrap"><input id="p-model" type="text" name="model" value="${esc(f.model)}" list="p-models" placeholder="model id">
                  <button type="button" class="btn" data-action="provider-models">Load models</button></div>
                <datalist id="p-models"></datalist><div class="hint" id="p-model-hint"></div></div>
            </div>
            <div class="row"><button class="btn primary">${editing ? 'Save changes' : 'Add provider'}</button>
              ${editing ? '<a class="btn ghost" href="#/providers">Cancel</a>' : ''}</div>
          </form></div>`),
      mount() { if (!editing) applyPreset(); },
    };
  };

  function applyPreset() {
    const preset = state.presets.find((p) => p.kind === $('#p-kind').value);
    if (!preset) return;
    $('#p-url').value = preset.base_url;
    $('#p-name').value = preset.kind === 'custom' ? '' : preset.label;
    $('#p-model').placeholder = preset.model_hint || 'model id';
    $('#p-url-hint').textContent = preset.kind === 'ollama' || preset.kind === 'lmstudio'
      ? 'The address must be reachable from the machine running CERBERUS, not from your browser.'
      : (preset.kind === 'custom' ? 'Any server exposing /chat/completions (vLLM, llama.cpp, LiteLLM, Azure-compatible gateways…).' : '');
    $('#p-model-hint').textContent = preset.needs_key ? 'An API key is required for this provider.' : '';
  }

  views.integrations = async () => {
    const [data, mail, wz] = await Promise.all([api('/integrations'), api('/integrations/email'), api('/integrations/wazuh')]);
    const z = wz.settings;
    const g = data.grafana;
    const m = mail.settings;
    const hook = `${location.origin}/api/v1/webhooks/grafana`;
    const planned = ['Snort 3', 'Zeek', 'open-appsec', 'Velociraptor', 'VirusTotal / MISP', 'Slack', 'Jira', 'Gmail'];
    return page('Integrations', 'Push alerts in, and give the analyst bounded read access to your telemetry.', '',
      `<div class="card card-pad"><h2>Grafana → CERBERUS · alert webhook</h2>
        <p class="muted" style="margin:6px 0 14px">Grafana Alerting posts firing and resolved alerts here. Each becomes an event and is correlated into incidents.</p>
        <div class="field"><label for="hook-url">Webhook URL</label><div class="copy"><input type="text" readonly value="${esc(hook)}" id="hook-url"><button class="btn" data-action="copy" data-target="hook-url">Copy</button></div>
          ${/^(localhost|127\.)/.test(location.hostname) ? '<div class="hint">Grafana must be able to reach this address. From another machine, use a tunnel address or this PC’s LAN IP instead of localhost.</div>' : ''}</div>
        <div class="field"><label for="hook-token">Bearer token</label><form class="copy" data-form="noop"><input type="password" readonly value="${esc(data.ingest_token)}" id="hook-token" autocomplete="off">
          <button type="button" class="btn" data-action="reveal" data-target="hook-token">Show</button><button type="button" class="btn" data-action="copy" data-target="hook-token">Copy</button>
          <button type="button" class="btn danger" data-action="rotate-token">Rotate</button></form></div>
        <ol class="steps muted">
          <li>In Grafana open <strong>Alerting → Notification configuration → Contact points</strong>, create a contact point and choose <strong>Webhook</strong>.</li>
          <li>Paste the URL above. HTTP method: <strong>POST</strong>.</li>
          <li>Leave <strong>Authorization Header – Scheme</strong> as <code>Bearer</code> and paste the token into <strong>Authorization Header – Credentials</strong>.</li>
          <li>Press <strong>Test</strong>, save, then route alerts to it under <strong>Notification policies</strong>.</li>
        </ol></div>
      <div class="card card-pad"><h2>CERBERUS → Grafana · query access ${g.url ? '<span class="badge ok">configured</span>' : ''}</h2>
        <p class="muted" style="margin:6px 0 14px">With a read-only service account token the analyst can run PromQL and LogQL through Grafana’s datasource proxy.</p>
        <form data-form="grafana">
          <div class="grid-2">
            <div class="field"><label for="g-url">Grafana URL</label><input id="g-url" type="url" name="url" value="${esc(g.url || '')}" placeholder="http://grafana-host:3000"></div>
            <div class="field"><label for="g-token">Service account token</label><input id="g-token" type="password" name="token" autocomplete="off" placeholder="${g.has_token ? 'Leave blank to keep the saved token' : 'glsa_…'}"></div>
            <div class="field"><label for="g-prom">Prometheus datasource UID</label><input id="g-prom" type="text" name="prometheus_uid" value="${esc(g.prometheus_uid || '')}">
              <div class="hint">Leave empty and press “Save and test” to detect it.</div></div>
            <div class="field"><label for="g-loki">Loki datasource UID</label><input id="g-loki" type="text" name="loki_uid" value="${esc(g.loki_uid || '')}"></div>
          </div>
          <div class="field"><label class="check"><input type="checkbox" name="verify_tls" ${g.verify_tls === false ? '' : 'checked'}> Verify TLS certificate (turn off only for a self-signed internal Grafana)</label></div>
          <div class="row"><button class="btn primary">Save and test</button><span id="g-result" class="muted"></span></div>
        </form></div>
      <div class="card card-pad"><h2>Wazuh ${z.enabled && z.url ? `<span class="badge ${wz.last_ok ? 'ok' : 'critical'}">${wz.last_ok ? 'connected' : 'failing'}</span>` : ''}</h2>
        <p class="muted" style="margin:6px 0 14px">CERBERUS signs in to Wazuh and pulls its detections every few minutes. Nothing is installed on the Wazuh server.
          Alerts are grouped: one event per machine, rule and source IP per hour, with a running count.</p>
        <form data-form="wazuh">
          <div class="grid-2">
            <div class="field"><label for="z-url">Wazuh address</label><input id="z-url" type="url" name="url" value="${esc(z.url || '')}" placeholder="https://wazuh-host:8443">
              <div class="hint">The Wazuh dashboard address works, and so does the indexer (port 9200).</div></div>
            <div class="grid-2"><div class="field"><label for="z-user">Username</label><input id="z-user" type="text" name="username" value="${esc(z.username || '')}" autocomplete="off"></div>
              <div class="field"><label for="z-pass">Password</label><input id="z-pass" type="password" name="password" autocomplete="new-password" placeholder="${z.has_password ? 'Leave blank to keep it' : ''}"></div></div>
            <div class="grid-2"><div class="field"><label for="z-level">Bring in level</label><select id="z-level" name="min_level">${[[5, '5 and above (a lot)'], [7, '7 and above'], [10, '10 and above'], [12, '12 and above']]
                .map(([v, t]) => `<option value="${v}" ${Number(z.min_level) === v ? 'selected' : ''}>${t}</option>`).join('')}</select></div>
              <div class="field"><label for="z-poll">Check every</label><select id="z-poll" name="poll_minutes">${[1, 2, 5, 10].map((v) => `<option value="${v}" ${Number(z.poll_minutes) === v ? 'selected' : ''}>${v} minute${v === 1 ? '' : 's'}</option>`).join('')}</select></div></div>
            <div class="field"><label for="z-skip">Rule IDs to ignore</label><input id="z-skip" type="text" name="exclude_rules" value="${esc(z.exclude_rules || '')}" placeholder="e.g. 31533, 203">
              <div class="hint">Comma separated. Useful for a noisy rule you already know about.</div></div>
          </div>
          <div class="field row" style="gap:22px"><label class="check"><input type="checkbox" name="enabled" ${z.enabled ? 'checked' : ''}> Pull detections automatically</label>
            <label class="check"><input type="checkbox" name="verify_tls" ${z.verify_tls === false ? '' : 'checked'}> Verify the TLS certificate (turn off for a self-signed Wazuh)</label></div>
          <div class="row"><button class="btn primary">Save and test</button><button type="button" class="btn" data-action="wazuh-sync" ${z.url ? '' : 'disabled'}>Pull now</button>
            <span class="muted small" id="z-result">${wz.last_sync ? `Last pull ${ago(wz.last_sync)}: ${esc(wz.last_result)} · ${wz.events.toLocaleString()} Wazuh events stored` : 'Not pulled yet'}</span></div>
        </form></div>
      <div class="card card-pad"><h2>Email ${mail.configured ? '<span class="badge ok">configured</span>' : ''}</h2>
        <p class="muted" style="margin:6px 0 14px">Used for account verification, password resets, reports to admins and team announcements.</p>
        <form data-form="email">
          <div class="field"><label for="m-prov">Send with</label><select id="m-prov" name="provider" data-change="email-provider" style="max-width:320px">
            <option value="gmail" ${(m.provider || 'gmail') === 'gmail' ? 'selected' : ''}>Gmail (app password)</option>
            <option value="custom" ${m.provider === 'custom' ? 'selected' : ''}>Another mail server (SMTP)</option></select></div>
          <div id="m-gmail" ${(m.provider || 'gmail') === 'gmail' ? '' : 'hidden'}>
            <div class="grid-2">
              <div class="field"><label for="m-gaddr">Gmail address</label><input id="m-gaddr" type="text" name="gmail" value="${esc((m.provider || 'gmail') === 'gmail' ? (m.from_email || '') : '')}" placeholder="you@gmail.com" autocomplete="off"></div>
              <div class="field"><label for="m-gpass">App password</label><input id="m-gpass" type="password" name="app_password" autocomplete="new-password" placeholder="${m.has_password && (m.provider || 'gmail') === 'gmail' ? 'Leave blank to keep the saved one' : 'abcd efgh ijkl mnop'}"></div>
            </div>
            <ol class="steps muted" style="margin:0 0 16px">
              <li>Turn on <strong>2-Step Verification</strong> for that Google account (Google Account → Security).</li>
              <li>Open <span class="mono">myaccount.google.com/apppasswords</span>, create an app password named “CERBERUS”.</li>
              <li>Paste the 16 letters here. Spaces do not matter. Your normal Google password will not work.</li>
            </ol>
          </div>
          <div id="m-custom" ${m.provider === 'custom' ? '' : 'hidden'}>
            <div class="grid-2">
              <div class="field"><label for="m-host">SMTP server</label><input id="m-host" type="text" name="host" value="${esc(m.provider === 'custom' ? (m.host || '') : '')}" placeholder="smtp.example.com"></div>
              <div class="grid-2"><div class="field"><label for="m-port">Port</label><input id="m-port" type="text" name="port" value="${esc(m.provider === 'custom' ? (m.port || 587) : 587)}" inputmode="numeric"></div>
                <div class="field"><label for="m-sec">Encryption</label><select id="m-sec" name="security">${[['starttls', 'STARTTLS'], ['ssl', 'SSL/TLS'], ['none', 'None (not recommended)']]
                  .map(([v, t]) => `<option value="${v}" ${v === (m.security || 'starttls') ? 'selected' : ''}>${t}</option>`).join('')}</select></div></div>
              <div class="field"><label for="m-user">Username</label><input id="m-user" type="text" name="username" value="${esc(m.provider === 'custom' ? (m.username || '') : '')}" autocomplete="off"></div>
              <div class="field"><label for="m-pass">Password</label><input id="m-pass" type="password" name="password" autocomplete="new-password" placeholder="${m.has_password && m.provider === 'custom' ? 'Leave blank to keep the saved password' : ''}"></div>
              <div class="field"><label for="m-from">From address</label><input id="m-from" type="text" name="from_email" value="${esc(m.provider === 'custom' ? (m.from_email || '') : '')}" placeholder="cerberus@yourdomain.com"></div>
            </div>
          </div>
          <div class="grid-2">
            <div class="field"><label for="m-name">Sender name shown to recipients</label><input id="m-name" type="text" name="from_name" value="${esc(m.from_name || 'CERBERUS')}"></div>
            <div class="field"><label for="m-url">Address of this app, used for links in emails</label><input id="m-url" type="url" name="app_url" value="${esc(m.app_url || location.origin)}">
              <div class="hint">Verification and reset links point here. It must be an address your team can open.</div></div>
          </div>
          <div class="row"><button class="btn primary">Save</button>
            <button type="button" class="btn" data-action="email-test" ${mail.configured ? '' : 'disabled'}>Send test email</button>
            <span class="muted small">${mail.admin_email ? `The test goes to ${esc(mail.admin_email)}.` : 'Add your own email address under Users to receive the test.'}</span></div>
        </form>
        ${mail.log.length ? `<details class="trace" style="margin-top:16px"><summary>${icon('mail', 13)} Recent emails (${mail.log.length})</summary>
          <div class="table-scroll"><table><tr><th>Time</th><th>Type</th><th>To</th><th>Subject</th><th>Status</th></tr>
          ${mail.log.map((e) => `<tr><td class="nowrap">${fmtTime(e.created_at)}</td><td>${esc(e.kind)}</td><td>${esc(e.recipient)}</td><td class="wrap">${esc(e.subject)}</td>
            <td>${e.status === 'sent' ? '<span class="badge ok">sent</span>' : e.status === 'failed' ? `<span class="badge critical" title="${esc(e.error)}">failed</span><div class="muted small">${esc(e.error)}</div>` : '<span class="badge">queued</span>'}</td></tr>`).join('')}
          </table></div></details>` : ''}</div>
      <div class="card card-pad"><h2>Generic event intake</h2>
        <p class="muted" style="margin:6px 0 10px">Any other engine can push normalised events with the same bearer token.</p>
        <pre class="mono sample">POST ${esc(location.origin)}/api/v1/ingest/events
Authorization: Bearer &lt;token&gt;
{"events": [{"source": "wazuh", "source_event_id": "abc-123", "asset": "sietlms",
  "event_type": "authentication_failure", "severity": 6, "timestamp": "2026-10-13T09:00:00Z",
  "source_ip": "198.51.100.42", "username": "admin", "rule_id": "5710",
  "title": "sshd: authentication failed", "message": "raw log line"}]}</pre></div>
      <div class="card card-pad"><h2>Not built yet</h2>
        <p class="muted" style="margin:6px 0 12px">Dedicated adapters from the plan that are still to come. Until then, use the generic intake above.</p>
        <div class="row">${planned.map((p) => `<span class="badge">${p}</span>`).join('')}</div></div>`);
  };

  const userStatus = (u) => {
    if (u.disabled) return '<span class="badge">disabled</span>';
    if (!u.has_password) return '<span class="badge medium">invited</span>';
    if (!u.email_verified) return '<span class="badge medium">unverified</span>';
    return '<span class="badge ok">active</span>';
  };

  const DOTS = '<svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="5" cy="12" r="1.800"/><circle cx="12" cy="12" r="1.800"/><circle cx="19" cy="12" r="1.800"/></svg>';

  views.users = async () => {
    const { users, email_configured: mailOn } = await api('/users');
    state.mailOn = mailOn;
    const me = users.find((u) => u.id === state.user.id);
    const count = (test) => users.filter(test).length;
    const pending = count((u) => !u.disabled && (!u.has_password || !u.email_verified));
    const rows = users.map((u) => {
      const mine = u.id === state.user.id;
      const attrs = `data-id="${u.id}" data-name="${esc(u.username)}" data-email="${esc(u.email)}"`;
      const item = (action, label, ic, extra = '', cls = '') => `<button class="menu-item ${cls}" data-action="${action}" ${attrs} ${extra}>${icon(ic, 16)}<span>${label}</span></button>`;
      return `<div class="user-row ${u.disabled ? 'off' : ''}">
        <div class="user-id"><span class="avatar-md ${u.role === 'admin' ? 'admin' : ''}">${esc(u.username.slice(0, 1))}</span>
          <div class="user-name"><b>${esc(u.username)}</b>${mine ? '<span class="badge info">you</span>' : ''}
            <small>${u.email ? esc(u.email) : `<button class="linklike" data-action="user-email" ${attrs}>Add an email address</button>`}</small></div></div>
        <select class="sel-sm" data-change="user-role" ${attrs} aria-label="Role of ${esc(u.username)}">
          <option value="admin" ${u.role === 'admin' ? 'selected' : ''}>Admin</option><option value="analyst" ${u.role === 'analyst' ? 'selected' : ''}>Analyst</option></select>
        <div>${userStatus(u)}</div>
        <div class="user-seen"><small>Last sign-in</small>${u.last_login ? agoCell(u.last_login) : '<span class="muted">never</span>'}</div>
        <div class="pop-wrap"><button class="btn sm ghost icon" data-action="menu" title="Actions" aria-label="Actions for ${esc(u.username)}">${DOTS}</button>
          <div class="pop menu" hidden>
            ${item('user-email', u.email ? 'Change email address' : 'Add email address', 'mail')}
            ${item('user-password', mailOn && u.email ? 'Send password reset link' : 'Set a new password', 'retry', `data-mail="${mailOn && u.email ? '1' : ''}"`)}
            ${!u.email_verified && mailOn && u.email ? item('user-resend', 'Resend verification link', 'send') : ''}
            ${!u.email_verified ? item('user-verify', 'Mark as verified', 'check') : ''}
            ${mine ? '' : `<div class="menu-sep"></div>${item('user-toggle', u.disabled ? 'Enable account' : 'Disable account', u.disabled ? 'check' : 'stop', `data-disabled="${u.disabled ? '1' : ''}"`)}
            ${item('user-delete', 'Delete user', 'trash', '', 'danger')}`}
          </div></div>
      </div>`;
    }).join('');
    return page('Users', 'Admins manage users, integrations, AI providers and announcements. Analysts work incidents and use the console.',
      `<button class="btn primary" data-action="user-add">${icon('plus', 16)} Add user</button>`,
      `${me && !me.email ? `<div class="callout row" style="justify-content:space-between"><span><strong>Your account has no email address.</strong> Add one so you can receive reports and reset your own password.</span>
          <button class="btn sm" data-action="user-email" data-id="${me.id}" data-name="${esc(me.username)}" data-email="">Add my email</button></div>` : ''}
      ${mailOn ? '' : `<div class="callout info row" style="justify-content:space-between"><span><strong>Email is not set up yet.</strong> Until it is, you set each new user's password yourself. With email, they get an invitation and choose their own.</span>
          <a class="btn sm" href="#/integrations">Set up email</a></div>`}
      <div class="stat-chips">
        <span><b>${users.length}</b> ${users.length === 1 ? 'user' : 'users'}</span><span><b>${count((u) => u.role === 'admin')}</b> admin${count((u) => u.role === 'admin') === 1 ? '' : 's'}</span>
        <span><b>${count((u) => u.role === 'analyst')}</b> analyst${count((u) => u.role === 'analyst') === 1 ? '' : 's'}</span>
        ${pending ? `<span class="warn"><b>${pending}</b> waiting to verify</span>` : ''}${count((u) => u.disabled) ? `<span><b>${count((u) => u.disabled)}</b> disabled</span>` : ''}
        ${users.length > 6 ? '<input type="text" id="user-filter" placeholder="Filter by name or email" aria-label="Filter users" autocomplete="off">' : ''}
      </div>
      <div class="card user-list">${rows}
        ${users.length === 1 ? `<div class="user-empty">${icon('users', 30)}<div><b>It is just you so far.</b><br><span class="muted">Add your team so they can work incidents and use the AI console.</span></div>
          <button class="btn" data-action="user-add">${icon('plus', 16)} Add user</button></div>` : ''}</div>`);
  };

  function openUserDialog() {
    const mailOn = state.mailOn;
    const d = document.createElement('dialog');
    d.className = 'modal wide';
    d.innerHTML = `<form data-form="user-create"><h3>Add a user</h3>
      <p>${mailOn ? 'They receive an email invitation, confirm their address and choose their own password.' : 'Email is not set up, so you choose their first password and share it with them securely.'}</p>
      <div class="grid-2">
        <div class="field"><label for="u-name">Username</label><input id="u-name" type="text" name="username" required minlength="3" maxlength="64" autocomplete="off" placeholder="e.g. priya"></div>
        <div class="field"><label for="u-email">Email address</label><input id="u-email" type="text" name="email" required autocomplete="off" placeholder="name@company.com"></div>
      </div>
      <div class="field"><label>Role</label><div class="role-pick">
        <label class="role-card"><input type="radio" name="role" value="analyst" checked><span><b>Analyst</b><small>Works incidents and events, and uses the AI console.</small></span></label>
        <label class="role-card"><input type="radio" name="role" value="admin"><span><b>Admin</b><small>Everything an analyst can do, plus users, integrations, AI providers, approvals and announcements.</small></span></label></div></div>
      <div class="field"><label for="u-pass">${mailOn ? 'Initial password (optional)' : 'Initial password'}</label>
        <input id="u-pass" type="password" name="password" autocomplete="new-password" ${mailOn ? '' : 'required minlength="10"'} placeholder="${mailOn ? 'Leave blank to let them choose' : 'At least 10 characters'}"></div>
      <div class="form-error"></div>
      <div class="row end"><button type="button" class="btn" data-action="dialog-close">Cancel</button>
        <button class="btn primary">${mailOn ? 'Send invitation' : 'Add user'}</button></div></form>`;
    d.addEventListener('close', () => d.remove());
    document.body.appendChild(d);
    d.showModal();
    $('#u-name', d).focus();
  }

  views.announcements = async () => {
    const { items, email_configured: mailOn } = await api('/announcements');
    const audience = { all: 'Everyone', admins: 'Admins', analysts: 'Analysts' };
    return page('Announcements', 'Send a notice to the team: as a notification inside the app, by email, or both.', '',
      `<div class="card card-pad"><h2>New announcement</h2>
        <form data-form="announcement" style="margin-top:14px">
          <div class="field"><label for="n-title">Title</label><input id="n-title" type="text" name="title" required maxlength="120"></div>
          <div class="field"><label for="n-msg">Message</label><textarea id="n-msg" name="message" rows="5" required maxlength="5000"></textarea>
            <div class="hint">You can use **bold**, lists starting with "-" and blank lines between paragraphs.</div></div>
          <div class="grid-2">
            <div class="field"><label for="n-level">Importance</label><select id="n-level" name="level"><option value="info">Information</option><option value="warning">Important</option><option value="critical">Critical</option></select></div>
            <div class="field"><label for="n-aud">Send to</label><select id="n-aud" name="audience"><option value="all">Everyone</option><option value="admins">Admins only</option><option value="analysts">Analysts only</option></select></div>
          </div>
          <div class="field row" style="gap:22px"><label class="check"><input type="checkbox" name="in_app" checked> Show as a notification in the app</label>
            <label class="check"><input type="checkbox" name="email" ${mailOn ? '' : 'disabled'}> Also send as an announcement email</label>
            ${mailOn ? '' : '<span class="muted small">Set up email under Integrations to enable this.</span>'}</div>
          <button class="btn primary">Send announcement</button>
        </form></div>
      ${items.length ? `<div class="card"><div class="table-scroll"><table><tr><th>Announcement</th><th>Importance</th><th>Sent to</th><th>Delivery</th><th>When</th><th></th></tr>
        ${items.map((n) => `<tr><td class="wrap"><strong>${esc(n.title)}</strong><div class="logline" title="Click to expand">${esc(n.body)}</div></td>
          <td><span class="badge ${{ info: 'info', warning: 'medium', critical: 'critical' }[n.level]}">${esc(n.level)}</span></td><td>${audience[n.audience] || esc(n.audience)}</td>
          <td class="small">${n.in_app ? `In app · read by ${n.read_by}` : ''}${n.in_app && n.emailed ? '<br>' : ''}${n.emailed ? `Emailed to ${n.emailed}` : ''}</td>
          <td class="nowrap">${fmtTime(n.created_at)}<div class="muted small">${esc(n.created_by)}</div></td>
          <td><button class="btn sm danger" data-action="announcement-delete" data-id="${n.id}" data-name="${esc(n.title)}">Delete</button></td></tr>`).join('')}
      </table></div></div>` : empty('No announcements yet', 'Anything you send appears here with how many people have read it.', '', 'megaphone')}`);
  };

  views.account = async () => page('My account', '', '',
    `<div class="split">
      <div class="card card-pad"><h2>Change password</h2>
        <form data-form="password" style="margin-top:14px">
          <div class="field"><label for="a-cur">Current password</label><input id="a-cur" type="password" name="current" required autocomplete="current-password"></div>
          <div class="field"><label for="a-new">New password</label><input id="a-new" type="password" name="password" required minlength="10" autocomplete="new-password"><div class="hint">At least 10 characters. Other devices are signed out.</div></div>
          <div class="field"><label for="a-rep">Repeat new password</label><input id="a-rep" type="password" name="confirm" required autocomplete="new-password"></div>
          <div class="form-error"></div>
          <button class="btn primary">Change password</button>
        </form></div>
      <div class="card card-pad"><h2>Profile</h2><dl class="kv" style="margin-top:12px">
        <dt>Username</dt><dd>${esc(state.user.username)}</dd>
        <dt>Email</dt><dd>${esc(state.user.email || 'not set')}</dd>
        <dt>Role</dt><dd>${roleName(state.user.role)}</dd></dl>
        <p class="muted small" style="margin:14px 0 0">An admin can change your email address or role under Users.</p></div>
    </div>`);

  views.audit = async () => {
    const rows = await api('/audit');
    return page('Audit log', 'Sign-ins, configuration changes, AI queries, tool calls and approval decisions.', '',
      `<div class="card"><div class="table-scroll"><table><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th></tr>
        ${rows.map((r) => `<tr><td class="nowrap">${fmtTime(r.ts)}</td><td class="nowrap">${esc(r.actor)}</td><td class="mono nowrap">${esc(r.action)}</td>
          <td class="wrap"><div class="logline" title="Click to expand">${esc(JSON.stringify(r.detail))}</div></td></tr>`).join('')}</table></div></div>`);
  };

  // ---------- actions ----------

  const actions = {
    async logout() { await api('/auth/logout', { method: 'POST' }); state.user = null; clearChat(); boot(); },
    theme() { theme.toggle(); },
    drawer() {
      const shell = $('.shell');
      if (matchMedia('(max-width: 900px)').matches) { shell.classList.toggle('drawer'); return; }
      pref.set('sidebar', shell.classList.toggle('rail') ? 'rail' : 'open');
    },
    palette() { const pop = $('#palette-pop'); pop.hidden = !pop.hidden; },
    shortcuts() { shortcutsDialog(); },
    'app-pick'(el) {
      pref.set('app', el.dataset.value);
      renderNav();
      const target = el.dataset.value === 'all' ? '#/overview' : `#/app/${el.dataset.value}/overview`;
      if (location.hash === target) route(); else location.hash = target;
    },
    'row-detail'(el) {
      if (String(getSelection())) return;
      const next = el.nextElementSibling;
      if (next && next.classList.contains('detail-row')) { next.remove(); el.classList.remove('open'); return; }
      const tr = document.createElement('tr');
      tr.className = 'detail-row';
      const url = safeUrl(el.dataset.url);
      tr.innerHTML = `<td colspan="${Number(el.dataset.cols) || 1}"><pre>${esc(el.dataset.detail)}</pre>${url ? outLink(url, `Open reference ${icon('external', 13)}`, 'link small') : ''}</td>`;
      el.after(tr);
      el.classList.add('open');
    },
    'nav-group'(el) {
      const group = el.closest('.nav-group');
      const closed = group.classList.toggle('closed');
      el.setAttribute('aria-expanded', String(!closed));
      const name = group.dataset.group;
      pref.set('navclosed', [...closedGroups().filter((g) => g !== name), ...(closed ? [name] : [])].join(','));
    },
    accent(el) { pref.set('accent', el.dataset.value); theme.apply(); },
    async 'demo-load'() { const r = await api('/demo', { method: 'POST' }); toast(`Loaded ${r.created} demo events`); route(); },
    async 'demo-clear'() {
      if (!await confirmDialog({ title: 'Remove demo data?', text: 'Sample events, incidents and assets are deleted. Real data is not touched.', ok: 'Remove', danger: true })) return;
      await api('/demo', { method: 'DELETE' }); toast('Demo data removed'); route();
    },
    suggest(el) { sendChat(el.textContent); },
    'chat-stop'() { if (state.abort) state.abort.abort(); },
    'chat-new'() {
      if (state.busy) return toast('Wait for the current answer, or press Stop first');
      clearChat(); renderChat(true); renderHistory();
      $('.chat-wrap').classList.remove('show-history');
      const input = $('#chat-input'); if (input) input.focus();
    },
    async 'chat-open'(el) {
      if (state.busy) return toast('Wait for the current answer, or press Stop first');
      await openChat(Number(el.dataset.id));
      $('.chat-wrap').classList.remove('show-history');
    },
    async 'chat-rename'(el) {
      const convo = state.convos.find((c) => c.id === Number(el.dataset.id));
      const answer = await confirmDialog({ title: 'Rename conversation', text: 'Give it a name you will recognise later.', ok: 'Save', input: convo ? convo.title : '' });
      if (!answer || !answer.value) return;
      await api(`/ai/conversations/${el.dataset.id}`, { method: 'PUT', body: { title: answer.value } });
      refreshHistory();
    },
    async 'chat-delete'(el) {
      const id = Number(el.dataset.id);
      const convo = state.convos.find((c) => c.id === id);
      if (!await confirmDialog({ title: 'Delete this conversation?', text: convo ? convo.title : '', ok: 'Delete', danger: true })) return;
      if (id === state.chatId && state.busy) return toast('Wait for the current answer, or press Stop first');
      await api(`/ai/conversations/${id}`, { method: 'DELETE' });
      if (id === state.chatId) { clearChat(); renderChat(true); }
      refreshHistory();
    },
    'history-toggle'() {
      const wrap = $('.chat-wrap');
      if (matchMedia('(max-width: 900px)').matches) { wrap.classList.toggle('show-history'); return; }
      pref.set('history', wrap.classList.toggle('no-history') ? 'closed' : 'open');
    },
    'chat-copy'(el) { const m = state.chat[Number(el.dataset.index)]; if (m) copyText(m.content); },
    async 'chat-report'(el) {
      if (!await confirmDialog({ title: 'Email this answer to the admins?', text: 'The full answer is sent as a report to every admin with a verified email address.', ok: 'Send report' })) return;
      const r = await api('/ai/report', { method: 'POST', body: { conversation_id: state.chatId, index: Number(el.dataset.index) } });
      toast(`Report emailed to ${r.sent} admin${r.sent === 1 ? '' : 's'}`);
    },
    async bell() {
      const pop = $('#bell-pop');
      if (!pop.hidden) { pop.hidden = true; return; }
      pop.hidden = false;
      pop.innerHTML = '<div class="boot" style="padding:24px"><span class="spinner"></span></div>';
      const { items } = await api('/notifications');
      pop.innerHTML = `<div class="pop-head"><b>Notifications</b>${isAdmin() ? '<a class="link small" href="#/announcements">New announcement</a>' : ''}</div>${
        items.length ? items.map((n) => `<div class="note ${n.read ? '' : 'unread'} lvl-${esc(n.level)}"><div class="note-title">${esc(n.title)}</div>${md(n.body)}
          <div class="muted small">${esc(n.created_by)} · ${ago(n.created_at)}</div></div>`).join('') : '<div class="history-empty">Nothing yet. Announcements from your admins appear here.</div>'}`;
      await api('/notifications/read', { method: 'POST' });
      const badge = $('[data-badge="notifications"]');
      if (badge) badge.hidden = true;
    },
    async 'email-test'(el) {
      el.disabled = true; el.innerHTML = '<span class="spinner"></span> Sending';
      try { const r = await api('/integrations/email/test', { method: 'POST' }); toast(`Test email sent to ${r.to}`); }
      finally { el.disabled = false; el.textContent = 'Send test email'; route({ soft: true }); }
    },
    legend(el) {
      const set = state.hidden[el.dataset.group] || (state.hidden[el.dataset.group] = new Set());
      if (set.has(el.dataset.key)) set.delete(el.dataset.key); else set.add(el.dataset.key);
      document.querySelectorAll(`.lg[data-group="${el.dataset.group}"]`).forEach((b) => b.classList.toggle('off', set.has(b.dataset.key)));
      charts.forEach((draw) => draw());
    },
    'log-filter'(el) {
      const { f, link } = state.logs;
      closeDrawer();
      location.hash = link({ [el.dataset.name]: f[el.dataset.name] === el.dataset.value ? '' : el.dataset.value, text: f.text.trim().startsWith('{') ? '' : f.text });
    },
    'log-open'(el) { if (!String(getSelection())) openLogDrawer(Number(el.dataset.i)); },
    'drawer-close'() { closeDrawer(); },
    'log-facets'(el) { const open = $('.logs-body').classList.toggle('no-facets'); pref.set('logfacets', open ? 'closed' : 'open'); el.classList.toggle('on', !open); },
    'chart-collapse'(el) { const closed = el.closest('.chart-card').classList.toggle('closed'); pref.set('logchart', closed ? 'closed' : 'open'); if (!closed) charts.forEach((draw) => draw()); },
    'log-copy-line'() { copyText(state.logLine.line); },
    'log-copy-query'() { copyText(state.logs.query); },
    'log-export'() {
      const { data, query } = state.logs;
      if (!data.lines.length) return toast('There are no lines to export');
      const text = [`# CERBERUS log export · ${new Date().toISOString()} · ${query}`, ...data.lines.map((l) => `${l.ts}\t${l.labels.host || ''}\t${l.labels.program || ''}\t${l.line}`)].join('\n');
      const a = document.createElement('a');
      a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
      a.download = `cerberus-logs-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.log`;
      a.click();
      setTimeout(() => URL.revokeObjectURL(a.href), 2000);
      toast(`Exported ${data.lines.length} lines`);
    },
    async 'log-save'() {
      const answer = await confirmDialog({ title: 'Save this search', text: 'Give it a short name. Saved searches are kept in this browser.', ok: 'Save', input: state.logs.f.text || state.logs.f.host || state.logs.f.program || 'My search' });
      if (!answer || !answer.value) return;
      const q = (state.logs.link({ start: '', end: '', live: '' }).split('?')[1] || '');
      savedSearches.set([{ name: answer.value.slice(0, 40), q }, ...savedSearches.all().filter((x) => x.name !== answer.value)]);
      toast('Search saved'); route({ soft: true });
    },
    'log-unsave'(el) { savedSearches.set(savedSearches.all().filter((x) => x.name !== el.dataset.name)); route({ soft: true }); },
    'log-ai'() {
      const { query, f } = state.logs;
      $('#ai-insight').scrollIntoView({ block: 'nearest', behavior: 'smooth' });
      return aiBrief($('#ai-insight'), { kind: 'logs', query, minutes: Number(f.minutes) || 15, start: f.start, end: f.end }, BRIEF_TITLES.logs);
    },
    'log-explain'() { return aiBrief($('#dp-ai'), { kind: 'log_line', line: state.logLine.line, labels: state.logLine.labels }, 'What this line means'); },
    async 'log-context'(el) {
      const box = $('#dp-context');
      el.disabled = true;
      box.innerHTML = '<div class="working" style="margin:12px 0"><span class="spinner"></span><span>Loading surrounding lines…</span></div>';
      try {
        const keep = Object.fromEntries(Object.entries(state.logLine.labels).filter(([k]) => ['host', 'program', 'job', 'service_name', 'filename', 'unit'].includes(k)));
        const r = await api('/logs/context', { method: 'POST', body: { labels: keep, ns: state.logLine.ns } });
        box.innerHTML = `<h4>Surrounding lines <span class="muted small">same stream, oldest first</span></h4><div class="dp-context">${r.lines.map((x) => `<div class="${x.current ? 'cur' : ''}">
          <span>${esc(new Date(x.ts).toLocaleTimeString([], { hour12: false }))}</span>${esc(x.line)}</div>`).join('')}</div>`;
        const cur = $('.dp-context .cur', box);
        if (cur) cur.scrollIntoView({ block: 'center' });
      } catch (err) { box.innerHTML = `<div class="callout" style="margin:12px 0">${esc(err.message)}</div>`; } finally { el.disabled = false; }
    },
    async 'wazuh-sync'(el) {
      el.disabled = true; el.innerHTML = '<span class="spinner"></span> Pulling…';
      try {
        const r = await api('/integrations/wazuh/sync', { method: 'POST' });
        toast(r.ok ? `Pulled ${r.groups} grouped detections: ${r.new} new, ${r.updated} updated` : r.error, !r.ok);
      } finally { route({ soft: true }); }
    },
    async 'watch-toggle'(el) {
      const on = Boolean(el.dataset.on);
      await api('/watch', { method: 'PUT', body: { enabled: on, tz_offset: -new Date().getTimezoneOffset() } });
      toast(on ? 'AI watch is on. The first check runs within a minute.' : 'AI watch is off'); route({ soft: true });
    },
    async 'watch-run'(el) {
      el.disabled = true; el.innerHTML = '<span class="spinner"></span> Checking…';
      try {
        const r = await api('/watch/run', { method: 'POST', body: { tz_offset: -new Date().getTimezoneOffset() } });
        toast(r.ok ? `${r.firing} need attention${r.new ? `, ${r.new} new` : ''}${r.recovered ? `, ${r.recovered} recovered` : ''}` : (r.error || 'The check failed'), !r.ok);
      } finally { route({ soft: true }); }
    },
    async 'watch-dismiss'(el) {
      const all = el.dataset.key === '*';
      if (all && !await confirmDialog({ title: 'Dismiss everything listed?', text: 'Each item stays hidden until it recovers and then happens again. Its incident is left as it is.', ok: 'Dismiss all' })) return;
      await api('/watch/findings', { method: 'POST', body: { key: el.dataset.key, dismissed: true } });
      toast(all ? 'All dismissed' : 'Dismissed. It will come back only if it recovers and then happens again.'); route({ soft: true });
    },
    async 'watch-restore'(el) { await api('/watch/findings', { method: 'POST', body: { key: el.dataset.key, dismissed: false } }); route({ soft: true }); },
    async 'watch-digest'(el) {
      el.disabled = true;
      try { await api('/watch/digest', { method: 'POST' }); toast('Digest sent to the admins'); } finally { el.disabled = false; }
    },
    'ai-brief'(el) { return aiBrief($('#ai-insight'), { kind: el.dataset.kind }, BRIEF_TITLES[el.dataset.kind]); },
    'ai-dismiss'(el) { const box = el.closest('#ai-insight, #dp-ai'); box.innerHTML = ''; if (box.id === 'ai-insight') state.insight = null; },
    'ai-copy'(el) { copyText(el.closest('#ai-insight, #dp-ai').dataset.text || ''); },
    'pw-toggle'(el) {
      const input = $('input', el.parentElement);
      const show = input.type === 'password';
      input.type = show ? 'text' : 'password';
      el.setAttribute('aria-label', show ? 'Hide password' : 'Show password');
      el.classList.toggle('on', show);
      input.focus();
    },
    'user-add'() { openUserDialog(); },
    'dialog-close'(el) { el.closest('dialog').close(); },
    menu(el) {
      const pop = el.nextElementSibling;
      const open = pop.hidden;
      document.querySelectorAll('.pop.menu').forEach((p) => { p.hidden = true; });
      pop.hidden = !open;
    },
    async 'user-resend'(el) { await api(`/users/${el.dataset.id}/resend-verification`, { method: 'POST' }); toast(`Verification link sent to ${el.dataset.email}`); },
    async 'user-verify'(el) {
      if (!await confirmDialog({ title: 'Mark as verified?', text: `${el.dataset.name} will be able to sign in without confirming ${el.dataset.email || 'an email address'}.`, ok: 'Mark verified' })) return;
      await api(`/users/${el.dataset.id}`, { method: 'PUT', body: { email_verified: true } }); route({ soft: true });
    },
    async 'user-email'(el) {
      const own = Number(el.dataset.id) === state.user.id;
      const answer = await confirmDialog({ title: own ? 'Your email address' : `Email address for ${el.dataset.name}`,
        text: own ? 'Reports and your own password-reset links are sent here. If email is set up, you get a confirmation message.'
          : 'They must verify a new address before their next sign-in (unless email is not set up).', ok: 'Save', input: el.dataset.email });
      if (!answer || !answer.value || answer.value === el.dataset.email) return;
      const r = await api(`/users/${el.dataset.id}`, { method: 'PUT', body: { email: answer.value } });
      toast(r.mail === 'confirmation' ? `Saved. A confirmation was sent to ${answer.value} — check the inbox and spam folder.`
        : r.mail === 'verification' ? `Saved. A verification link was sent to ${answer.value}.`
          : (own && !state.mailOn ? 'Saved. No message was sent because email is not set up yet (Integrations → Email).' : 'Email address updated'));
      await refreshUser(); route({ soft: true });
    },
    async 'user-password'(el) {
      if (el.dataset.mail) {
        if (!await confirmDialog({ title: 'Send a password reset link?', text: `${el.dataset.name} gets an email at ${el.dataset.email} with a link that is valid for one hour.`, ok: 'Send link' })) return;
        await api(`/users/${el.dataset.id}/send-reset`, { method: 'POST' });
        return toast('Reset link sent');
      }
      const answer = await confirmDialog({ title: `New password for ${el.dataset.name}`, text: 'Email is not set up, so type a new password (10+ characters) and share it with them securely. They are signed out everywhere.', ok: 'Set password', input: '' });
      if (!answer || !answer.value) return;
      await api(`/users/${el.dataset.id}`, { method: 'PUT', body: { password: answer.value } });
      toast('Password changed');
    },
    async 'user-toggle'(el) {
      const disable = !el.dataset.disabled;
      if (disable && !await confirmDialog({ title: `Disable ${el.dataset.name}?`, text: 'They are signed out immediately and cannot sign in until you enable the account again.', ok: 'Disable', danger: true })) return;
      await api(`/users/${el.dataset.id}`, { method: 'PUT', body: { disabled: disable } }); route({ soft: true });
    },
    async 'user-delete'(el) {
      if (!await confirmDialog({ title: `Delete ${el.dataset.name}?`, text: 'The account and its chat history are removed permanently.', ok: 'Delete', danger: true })) return;
      await api(`/users/${el.dataset.id}`, { method: 'DELETE' }); toast('User deleted'); route({ soft: true });
    },
    async 'announcement-delete'(el) {
      if (!await confirmDialog({ title: 'Delete this announcement?', text: `"${el.dataset.name}" disappears from everyone's notifications. Emails already sent cannot be recalled.`, ok: 'Delete', danger: true })) return;
      await api(`/announcements/${el.dataset.id}`, { method: 'DELETE' }); route({ soft: true });
    },
    'chat-retry'() {
      if (state.busy) return;
      while (state.chat.length && state.chat[state.chat.length - 1].error) state.chat.pop();
      const last = state.chat[state.chat.length - 1];
      if (last && last.role === 'user') { state.chat.pop(); sendChat(last.content); } else renderChat();
    },
    async investigate(el) {
      el.disabled = true;
      state.investigating = true;
      const started = Date.now();
      $('#summary').innerHTML = '<div class="working"><span class="spinner"></span><span>Gathering evidence… <span id="inv-secs">0</span>s</span></div>';
      const ticker = setInterval(() => { const s = $('#inv-secs'); if (s) s.textContent = Math.round((Date.now() - started) / 1000); }, 1000);
      try { await api(`/incidents/${el.dataset.id}/investigate`, { method: 'POST' }); } catch (err) { fail(err); }
      clearInterval(ticker);
      state.investigating = false;
      route({ soft: true });
    },
    async decide(el) {
      const approve = el.dataset.decision === 'approved';
      const answer = await confirmDialog({ title: approve ? 'Approve this request?' : 'Deny this request?', text: el.dataset.label,
        ok: approve ? 'Approve' : 'Deny', danger: !approve, note: true });
      if (!answer) return;
      const r = await api(`/approvals/${el.dataset.id}/decision`, { method: 'POST', body: { decision: el.dataset.decision, note: answer.note } });
      toast(r.note); route({ soft: true });
    },
    async 'provider-test'(el) {
      el.disabled = true; el.innerHTML = '<span class="spinner"></span> Testing';
      try {
        const r = await api(`/ai/providers/${el.dataset.id}/test`, { method: 'POST' });
        toast(r.detail || (r.ok ? 'Connected' : 'Test failed'), !r.ok);
      } finally { el.disabled = false; el.textContent = 'Test'; }
    },
    async 'provider-activate'(el) { await api(`/ai/providers/${el.dataset.id}/activate`, { method: 'POST' }); toast('Active provider changed'); route({ soft: true }); },
    async 'provider-delete'(el) {
      if (!await confirmDialog({ title: 'Delete this provider?', text: `${el.dataset.label} and its saved key will be removed.`, ok: 'Delete', danger: true })) return;
      await api(`/ai/providers/${el.dataset.id}`, { method: 'DELETE' });
      if (location.hash === '#/providers') route(); else location.hash = '#/providers';
    },
    async 'provider-models'(el) {
      const form = el.closest('form');
      el.disabled = true;
      try {
        const r = await api('/ai/models', { method: 'POST', body: {
          base_url: form.base_url.value.trim(), api_key: form.api_key.value, provider_id: Number(form.dataset.id) || null } });
        $('#p-models').innerHTML = r.models.map((m) => `<option value="${esc(m)}">`).join('');
        $('#p-model-hint').textContent = r.models.length ? `${r.models.length} models found — start typing to pick one.` : 'The endpoint returned no models.';
        form.model.focus();
      } finally { el.disabled = false; }
    },
    async copy(el) {
      const input = $(`#${el.dataset.target}`);
      if (!await copyText(input.value)) { input.type = 'text'; input.select(); }
    },
    reveal(el) { const input = $(`#${el.dataset.target}`); const show = input.type === 'password'; input.type = show ? 'text' : 'password'; el.textContent = show ? 'Hide' : 'Show'; },
    async 'rotate-token'() {
      if (!await confirmDialog({ title: 'Rotate the token?', text: 'Grafana and any other sender will be rejected until you paste the new token into them.', ok: 'Rotate', danger: true })) return;
      await api('/integrations/ingest-token/rotate', { method: 'POST' }); toast('Token rotated — update Grafana'); route({ soft: true });
    },
  };

  const forms = {
    noop() {},
    quick() { openPalette(); },
    'app-filter'(f) {
      const p = new URLSearchParams();
      new FormData(f).forEach((v, k) => { if (String(v).trim()) p.set(k, String(v).trim()); });
      const target = `${f.dataset.base}${p.toString() ? `?${p}` : ''}`;
      if (location.hash === target) route(); else location.hash = target;
    },
    ask(f) { const q = f.q.value.trim(); if (q) location.hash = `#/console?q=${encodeURIComponent(q)}`; },
    chat(f) { if (state.busy) return; const q = f.q.value; f.q.value = ''; f.q.style.height = 'auto'; sendChat(q); },
    async wazuh(f) {
      const body = { enabled: f.enabled.checked, url: f.url.value.trim(), username: f.username.value.trim(), password: f.password.value, verify_tls: f.verify_tls.checked,
        min_level: Number(f.min_level.value), exclude_rules: f.exclude_rules.value.trim(), poll_minutes: Number(f.poll_minutes.value) };
      await api('/integrations/wazuh', { method: 'PUT', body });
      loadApps();
      if (!body.url) { toast('Wazuh settings cleared'); return route({ soft: true }); }
      $('#z-result').innerHTML = '<span class="spinner"></span> Testing…';
      const r = await api('/integrations/wazuh/test', { method: 'POST' }).catch((err) => { $('#z-result').textContent = ''; throw err; });
      toast(`Connected to Wazuh (${r.mode}). ${r.alerts_24h.toLocaleString()} alerts at this level in the last 24 hours from ${r.agents.length} agents.`);
      route({ soft: true });
    },
    async watch(f) {
      const checks = Object.fromEntries([...f.querySelectorAll('[data-check]')].map((c) => [c.name, c.checked]));
      const body = { checks, tz_offset: -new Date().getTimezoneOffset(), interval_minutes: Number(f.interval_minutes.value), disk_pct: Number(f.disk_pct.value),
        memory_pct: Number(f.memory_pct.value), cpu_pct: Number(f.cpu_pct.value), load_factor: Number(f.load_factor.value), log_errors_5m: Number(f.log_errors_5m.value),
        notify_in_app: f.notify_in_app.checked, notify_email: f.notify_email.checked, email_min_severity: Number(f.email_min_severity.value),
        renotify_hours: Number(f.renotify_hours.value), ai_writeup: f.ai_writeup.checked, digest_enabled: f.digest_enabled.checked, digest_hour: Number(f.digest_hour.value) };
      await api('/watch', { method: 'PUT', body });
      toast('Saved'); route({ soft: true });
    },
    'logs-filter'(f) {
      const next = state.logs.link({ text: f.text.value.trim() });
      if (location.hash === next) route(); else location.hash = next;
    },
    'events-filter'(f) {
      const p = new URLSearchParams();
      if (f.q.value.trim()) p.set('q', f.q.value.trim());
      if (f.source.value) p.set('source', f.source.value);
      if (f.min.value !== '1') p.set('min', f.min.value);
      if (f.range.value === '7d') p.set('range', '7d');
      const next = `#/events${p.toString() ? `?${p}` : ''}`;
      if (location.hash === next) route(); else location.hash = next;
    },
    async provider(f) {
      const body = { kind: f.kind.value, name: f.name.value.trim(), base_url: f.base_url.value.trim(), api_key: f.api_key.value, model: f.model.value.trim() };
      const id = f.dataset.id;
      await api(id ? `/ai/providers/${id}` : '/ai/providers', { method: id ? 'PUT' : 'POST', body });
      toast(id ? 'Provider saved' : 'Provider added — press Test to check it');
      if (location.hash === '#/providers') route(); else location.hash = '#/providers';
    },
    async grafana(f) {
      const body = { url: f.url.value.trim(), token: f.token.value.trim(), verify_tls: f.verify_tls.checked,
        prometheus_uid: f.prometheus_uid.value.trim(), loki_uid: f.loki_uid.value.trim() };
      await api('/integrations/grafana', { method: 'PUT', body });
      loadApps();
      if (!body.url) { toast('Grafana query access cleared'); return route({ soft: true }); }
      const out = $('#g-result');
      out.innerHTML = '<span class="spinner"></span> Testing…';
      const r = await api('/integrations/grafana/test', { method: 'POST' }).catch((err) => { out.textContent = ''; throw err; });
      // Fill in datasource UIDs the first time so the user doesn't have to hunt for them.
      const pick = (type) => (r.datasources.find((d) => d.type === type) || {}).uid || '';
      const found = { prometheus_uid: body.prometheus_uid || pick('prometheus'), loki_uid: body.loki_uid || pick('loki') };
      if (found.prometheus_uid !== body.prometheus_uid || found.loki_uid !== body.loki_uid) {
        await api('/integrations/grafana', { method: 'PUT', body: { ...body, ...found, token: '' } });
      }
      toast(r.warning || `Connected to Grafana ${r.version}`, Boolean(r.warning));
      route({ soft: true });
    },
    async email(f) {
      const shared = { from_name: f.from_name.value.trim(), app_url: f.app_url.value.trim() };
      const body = f.provider.value === 'gmail'
        ? { provider: 'gmail', from_email: f.gmail.value.trim(), password: f.app_password.value, ...shared }
        : { provider: 'custom', host: f.host.value.trim(), port: Number(f.port.value) || 587, security: f.security.value, username: f.username.value.trim(),
          password: f.password.value, from_email: f.from_email.value.trim(), ...shared };
      await api('/integrations/email', { method: 'PUT', body });
      toast(body.from_email ? 'Email settings saved — send a test to check them' : 'Email settings cleared'); route({ soft: true });
    },
    async 'user-create'(f) {
      const r = await api('/users', { method: 'POST', body: { username: f.username.value.trim(), email: f.email.value.trim(), role: f.role.value, password: f.password.value } });
      toast(r.invited ? `Invitation sent to ${f.email.value.trim()}` : 'User added');
      const dialog = f.closest('dialog');
      if (dialog) dialog.close();
      route({ soft: true });
    },
    async announcement(f) {
      const r = await api('/announcements', { method: 'POST', body: { title: f.title.value.trim(), message: f.message.value.trim(), level: f.level.value,
        audience: f.audience.value, in_app: f.in_app.checked, email: f.email.checked } });
      toast(r.emailed ? `Announcement sent, emailed to ${r.emailed}` : 'Announcement sent'); route({ soft: true });
    },
    async password(f) {
      if (f.password.value !== f.confirm.value) throw new Error('The two new passwords do not match');
      await api('/account/password', { method: 'PUT', body: { current: f.current.value, new: f.password.value } });
      toast('Password changed'); route();
    },
    async login(f) { await api('/auth/login', { method: 'POST', body: { username: f.username.value.trim(), password: f.password.value } }); boot(); },
    async setup(f) {
      if (f.password.value !== f.confirm.value) throw new Error('The two passwords do not match');
      await api('/auth/setup', { method: 'POST', body: { username: f.username.value.trim(), email: f.email.value.trim(), password: f.password.value } }); boot();
    },
    async forgot(f) {
      await api('/auth/forgot', { method: 'POST', body: { identifier: f.identifier.value.trim() } });
      authCard('Check your email', 'If an account matches what you entered, we have sent a link to reset the password. It is valid for one hour.',
        '<a class="btn" href="#/">Back to sign in</a>');
    },
    async token(f) {
      const body = { token: f.dataset.token };
      if (f.password) {
        if (f.password.value !== f.confirm.value) throw new Error('The two passwords do not match');
        body.password = f.password.value;
      }
      await api(`/auth/${f.dataset.kind}`, { method: 'POST', body });
      authCard(f.dataset.kind === 'verify' ? 'Account verified' : 'Password changed', 'You can sign in now.', '<a class="btn primary" href="#/">Go to sign in</a>');
    },
  };

  const changes = {
    'provider-preset': applyPreset,
    'email-provider'(el) { $('#m-gmail').hidden = el.value !== 'gmail'; $('#m-custom').hidden = el.value !== 'custom'; },
    async 'user-role'(el) {
      try { await api(`/users/${el.dataset.id}`, { method: 'PUT', body: { role: el.value } }); toast(`${el.dataset.name} is now ${el.value === 'admin' ? 'an admin' : 'an analyst'}`); }
      finally { await refreshUser(); route({ soft: true }); }
    },
    'submit-form'(el) { el.form.requestSubmit(); },
    async 'incident-status'(el) {
      await api(`/incidents/${el.dataset.id}`, { method: 'PATCH', body: { status: el.value } }); toast('Status updated'); route({ soft: true });
    },
  };

  document.addEventListener('click', (e) => {
    document.querySelectorAll('.pop:not([hidden])').forEach((pop) => { if (!pop.parentElement.contains(e.target)) pop.hidden = true; });
    const menuItem = e.target.closest('.menu-item');
    if (menuItem) menuItem.closest('.pop').hidden = true;
    const el = e.target.closest('[data-action]');
    if (el && actions[el.dataset.action]) { e.preventDefault(); Promise.resolve().then(() => actions[el.dataset.action](el)).catch(fail); return; }
    const th = e.target.closest('th[data-sort]');
    if (th) {
      const index = [...th.parentElement.children].indexOf(th);
      const dir = th.getAttribute('aria-sort') === 'ascending' ? -1 : 1;
      state.sorts[current] = { index, dir };
      sortTable(th, dir);
      return;
    }
    const log = e.target.closest('.logline');
    if (log && !String(getSelection())) { log.classList.toggle('open'); return; }
    const row = e.target.closest('[data-href]');
    if (row && !e.target.closest('a, button') && !String(getSelection())) location.hash = row.dataset.href;
  });
  document.addEventListener('submit', (e) => {
    const form = e.target.closest('[data-form]');
    if (!form) return;
    e.preventDefault();
    const button = $('button:not([type=button])', form);
    const lock = button && !form.matches('[data-form=chat]');
    if (lock) { button.disabled = true; button.classList.add('loading'); }
    Promise.resolve().then(() => forms[form.dataset.form](form)).catch((err) => {
      const slot = $('.form-error', form);
      if (slot) slot.textContent = err.message; else fail(err);
    }).finally(() => { if (lock) { button.disabled = false; button.classList.remove('loading'); } });
  });
  document.addEventListener('input', (e) => {
    if (e.target.id !== 'user-filter') return;
    const q = e.target.value.trim().toLowerCase();
    document.querySelectorAll('.user-row').forEach((row) => { row.hidden = Boolean(q) && !$('.user-name', row).textContent.toLowerCase().includes(q); });
  });
  document.addEventListener('change', (e) => {
    const el = e.target.closest('[data-change]');
    if (el && changes[el.dataset.change]) Promise.resolve().then(() => changes[el.dataset.change](el)).catch(fail);
  });
  // Click a column heading to sort by it; click again to reverse.
  function sortTable(th, dir) {
    const table = th.closest('table');
    table.querySelectorAll('tr.detail-row').forEach((r) => r.remove());
    table.querySelectorAll('tr.open').forEach((r) => r.classList.remove('open'));
    const index = [...th.parentElement.children].indexOf(th);
    const numeric = th.dataset.sort === 'num';
    const value = (row) => { const c = row.cells[index]; const v = c.dataset.v ?? c.textContent.trim(); return numeric ? Number(v) || 0 : v.toLowerCase(); };
    [...table.rows].slice(1).sort((a, b) => (value(a) > value(b) ? 1 : value(a) < value(b) ? -1 : 0) * dir).forEach((row) => row.parentElement.appendChild(row));
    [...th.parentElement.children].forEach((h) => h.removeAttribute('aria-sort'));
    th.setAttribute('aria-sort', dir === 1 ? 'ascending' : 'descending');
  }

  function shortcutsDialog() {
    if ($('dialog[open]')) return;
    const d = document.createElement('dialog');
    d.className = 'modal';
    const keys = [['Ctrl K', 'Search, jump to a page, or ask the AI'], ['Ctrl B', 'Show or hide the sidebar'], ['?', 'Show this list'],
      ['Enter', 'Send a message in the console'], ['Shift Enter', 'New line in the console'], ['Esc', 'Close a dialog or menu']];
    d.innerHTML = `<h3>Keyboard shortcuts</h3><div class="keys">${keys.map(([k, t]) => `<div><span>${k.split(' ').map((p) => `<kbd>${p}</kbd>`).join(' ')}</span><span>${t}</span></div>`).join('')}</div>
      <p style="margin:14px 0 0">Tables sort when you click a column heading. Chart legends hide and show series. Chart bars open the matching events.</p>
      <div class="row end" style="margin-top:16px"><button class="btn" data-action="dialog-close">Close</button></div>`;
    d.addEventListener('close', () => d.remove());
    document.body.appendChild(d);
    d.showModal();
  }

  document.addEventListener('keyup', (e) => {
    if (!e.target.matches || !e.target.matches('.pw-wrap input') || !e.getModifierState) return;
    const note = $('.caps', e.target.closest('.field'));
    if (note) note.hidden = !e.getModifierState('CapsLock');
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && $('#log-drawer') && !$('dialog[open]')) { closeDrawer(); return; }
    if (e.key === 'Enter' && e.target.matches && e.target.matches('.logrow')) { openLogDrawer(Number(e.target.dataset.i)); return; }
    if (e.key === '?' && $('.shell') && !/^(INPUT|TEXTAREA|SELECT)$/.test(e.target.tagName)) { e.preventDefault(); shortcutsDialog(); return; }
    if (!(e.ctrlKey || e.metaKey) || !$('.shell')) return;
    if (e.key.toLowerCase() === 'b') { e.preventDefault(); actions.drawer(); }
    if (e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); }
  });

  document.addEventListener('focusin', (e) => { if (e.target.id === 'quick') { e.target.blur(); openPalette(); } });
  document.addEventListener('mouseover', (e) => {
    const shell = $('.shell');
    const el = shell && shell.classList.contains('rail') && e.target.closest ? e.target.closest('.sidebar [data-tip]') : null;
    let tip = $('#rail-tip');
    if (!el) { if (tip) tip.hidden = true; return; }
    if (!tip) { tip = document.createElement('div'); tip.id = 'rail-tip'; document.body.appendChild(tip); }
    const box = el.getBoundingClientRect();
    tip.textContent = el.dataset.tip;
    tip.hidden = false;
    tip.style.left = `${box.right + 10}px`;
    tip.style.top = `${box.top + box.height / 2}px`;
  });

  // ---------- routing / boot ----------

  let renderSeq = 0;
  let current = '';
  async function route({ soft = false } = {}) {
    if (!state.user) return;
    const [path, query = ''] = location.hash.replace(/^#\/?/, '').split('?');
    const [name = '', id, sub] = path.split('/');
    const key = views[name] && (!ADMIN_VIEWS.has(name) || isAdmin()) ? name : 'overview';
    if (!state.appsLoaded) await loadApps();
    ensureShell();
    // Opening an application page directly switches the sidebar to that application.
    if (key === 'app' && pref.get('app', 'all') !== id && state.apps.some((a) => a.id === id)) { pref.set('app', id); renderNav(); }
    state.navKey = key === 'app' ? `app/${id}/${sub || 'overview'}` : key;
    markNav();
    $('#top-title').textContent = key === 'app' ? ((state.apps.find((a) => a.id === id) || {}).name || 'Application') : TITLES[key];
    $('.shell').classList.remove('drawer');
    const view = $('#view');
    const seq = ++renderSeq;
    clearInterval(state.logTimer);
    if (!soft) { closeDrawer(); state.insight = null; }
    current = key === 'app' ? state.navKey : key + (id ? '/detail' : '');
    if (!soft) {
      view.innerHTML = '<div class="page skeleton"><div class="sk w30"></div><div class="sk w50 thin"></div><div class="sk block"></div><div class="sk block short"></div></div>';
      view.scrollTop = 0;
    }
    const overview = loadOverview();
    overview.catch(() => {});
    try {
      const result = await views[key]({ id, sub, params: new URLSearchParams(query), overview });
      if (seq !== renderSeq || !state.user) return;
      const top = view.scrollTop;
      charts.clear();
      view.innerHTML = typeof result === 'string' ? result : result.html;
      if (!soft && view.firstElementChild) view.firstElementChild.classList.add('enter');
      if (soft) view.scrollTop = top;
      if (result.mount) result.mount();
      const insight = $('#ai-insight', view);
      if (insight && state.insight && state.insight.key === current) { insight.innerHTML = state.insight.html; insight.dataset.text = state.insight.text; }
      const sorted = state.sorts[current];
      const heading = sorted && $('th[data-sort]', view) && $('th[data-sort]', view).parentElement.children[sorted.index];
      if (heading && heading.dataset.sort) sortTable(heading, sorted.dir);
      if (!soft && !matchMedia('(prefers-reduced-motion: reduce)').matches) countUp(view);
    } catch (err) {
      if (seq === renderSeq && state.user && !soft) view.innerHTML = `<div class="page">${empty('Something went wrong', esc(err.message), '<div style="margin-top:14px"><button class="btn" data-action="reload">Try again</button></div>', 'alert')}</div>`;
    }
  }
  actions.reload = () => route();

  // Headline numbers count up when a page opens.
  function countUp(scope) {
    scope.querySelectorAll('.stat b:not(.raw)').forEach((el) => {
      const target = Number(el.textContent);
      if (!Number.isFinite(target) || target <= 0) return;
      const started = performance.now();
      const tick = (now) => {
        const p = Math.min(1, (now - started) / 550);
        el.textContent = Math.round(target * (1 - (1 - p) ** 3));
        if (p < 1 && el.isConnected) requestAnimationFrame(tick); else el.textContent = target;
      };
      requestAnimationFrame(tick);
    });
  }

  // Keep live views fresh without disturbing anyone who is typing, reading an expanded row or mid-dialog.
  const AUTO_REFRESH = new Set(['overview', 'watch', 'incidents', 'incidents/detail', 'events', 'infrastructure', 'assets', 'approvals', 'audit']);
  async function refreshUser() { const s = await api('/auth/state'); if (s.user) state.user = s.user; }
  setInterval(() => {
    if (!state.user || document.hidden || state.investigating) return;
    const active = document.activeElement;
    const typing = active && /^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName);
    if (AUTO_REFRESH.has(current) && !typing && !$('dialog[open]') && !$('.logline.open') && !String(getSelection())) route({ soft: true });
    else loadOverview().catch(() => {});
  }, REFRESH_MS);

  function authCard(title, text, inner, form = '') {
    // The same pulse as the logo, drifting across the background.
    const wave = `<path d="${Array.from({ length: 8 }, (_, i) => `M${i * 300} 80H${i * 300 + 100}l12-30 10 22 10-52 10 80 10-50 10 30H${i * 300 + 300}`).join('')}"/>`;
    app.innerHTML = `<div class="auth">
      <div class="auth-bg" aria-hidden="true"><span class="thresh t1"></span><span class="thresh t2"></span>
        <svg class="w1" viewBox="0 0 2400 120" preserveAspectRatio="none">${wave}</svg><svg class="w2" viewBox="0 0 2400 120" preserveAspectRatio="none">${wave}</svg></div>
      <div class="auth-wrap">
        <div class="auth-lockup">${logo()}<h2>CERBERUS</h2></div>
        <${form ? `form ${form}` : 'div'} class="card"><h1>${title}</h1><p>${text}</p>${inner}</${form ? 'form' : 'div'}>
        <ul class="auth-points"><li>${icon('alert', 15)}Correlated incidents</li><li>${icon('spark', 15)}Evidence-backed AI analyst</li><li>${icon('check', 15)}Human-approved response</li></ul>
      </div></div>`;
    const auth = $('.auth');
    auth.addEventListener('pointermove', (e) => { auth.style.setProperty('--mx', `${e.clientX}px`); auth.style.setProperty('--my', `${e.clientY}px`); });
    auth.querySelectorAll('input[type=password]').forEach((input) => {
      const wrap = document.createElement('div');
      wrap.className = 'pw-wrap';
      input.replaceWith(wrap);
      wrap.appendChild(input);
      wrap.insertAdjacentHTML('beforeend', `<button type="button" class="pw-toggle" data-action="pw-toggle" aria-label="Show password" title="Show or hide the password">${icon('eye', 18)}</button>`);
      wrap.insertAdjacentHTML('afterend', '<div class="caps" hidden>Caps Lock is on</div>');
    });
    const first = $('.auth input');
    if (first) first.focus();
  }
  const passwordFields = `<div class="field"><label for="a-pass">New password</label><input id="a-pass" type="password" name="password" required minlength="10" autocomplete="new-password"><div class="hint">At least 10 characters.</div></div>
    <div class="field"><label for="a-conf">Repeat password</label><input id="a-conf" type="password" name="confirm" required autocomplete="new-password"></div>`;

  function authScreen(setup) {
    authCard(setup ? 'Create the admin account' : 'Sign in to CERBERUS',
      setup ? 'First run. This account manages users, integrations and AI access.' : 'Security operations console',
      `<div class="field"><label for="a-user">${setup ? 'Username' : 'Username or email'}</label><input id="a-user" type="text" name="username" required ${setup ? 'minlength="3"' : ''} autocomplete="username"></div>
      ${setup ? '<div class="field"><label for="a-mail">Email address</label><input id="a-mail" type="text" name="email" autocomplete="email"><div class="hint">Optional now, but needed to receive reports and reset your own password.</div></div>' : ''}
      <div class="field"><label for="a-pass">Password</label><input id="a-pass" type="password" name="password" required ${setup ? 'minlength="10"' : ''} autocomplete="${setup ? 'new-password' : 'current-password'}">
        ${setup ? '<div class="hint">At least 10 characters.</div>' : ''}</div>
      ${setup ? '<div class="field"><label for="a-conf">Confirm password</label><input id="a-conf" type="password" name="confirm" required autocomplete="new-password"></div>' : ''}
      <div class="form-error"></div>
      <button class="btn primary">${setup ? 'Create account' : 'Sign in'}</button>
      ${setup ? '' : '<div class="auth-links"><a class="link" href="#/forgot">Forgot your password?</a></div>'}`,
      `data-form="${setup ? 'setup' : 'login'}"`);
  }

  function forgotScreen() {
    authCard('Reset your password', 'Enter your username or email address and we will email you a reset link.',
      `<div class="field"><label for="a-id">Username or email</label><input id="a-id" type="text" name="identifier" required autocomplete="username"></div>
      <div class="form-error"></div><button class="btn primary">Send reset link</button>
      <div class="auth-links"><a class="link" href="#/">Back to sign in</a></div>`, 'data-form="forgot"');
  }

  async function tokenScreen(kind, token) {
    let info;
    try { info = await api(`/auth/token?kind=${kind}&token=${encodeURIComponent(token)}`); } catch (err) {
      return authCard('This link cannot be used', esc(err.message), '<a class="btn" href="#/">Back to sign in</a>');
    }
    const verify = kind === 'verify';
    authCard(verify ? 'Verify your account' : 'Choose a new password',
      verify ? `Welcome, ${esc(info.username)}. ${info.needs_password ? 'Confirm your email address by choosing a password.' : 'Confirm that this email address is yours.'}`
        : `Set a new password for ${esc(info.username)}.`,
      `${info.needs_password ? passwordFields : ''}<div class="form-error"></div>
      <button class="btn primary">${verify ? (info.needs_password ? 'Verify and set password' : 'Verify my account') : 'Change password'}</button>`,
      `data-form="token" data-kind="${kind}" data-token="${esc(token)}"`);
  }

  const hashRoute = () => {
    const [path, query = ''] = location.hash.replace(/^#\/?/, '').split('?');
    return { path, params: new URLSearchParams(query) };
  };
  const PUBLIC_ROUTES = new Set(['verify', 'reset']);

  async function boot() {
    theme.apply();
    const { path, params } = hashRoute();
    try {
      // Links from emails work whether or not someone is signed in on this browser.
      if (PUBLIC_ROUTES.has(path)) return await tokenScreen(path, params.get('token') || '');
      const s = await api('/auth/state');
      state.user = s.user;
      if (!s.user) return path === 'forgot' && !s.setup_required ? forgotScreen() : authScreen(s.setup_required);
      loadChat();
      route();
    } catch (err) {
      app.innerHTML = `<div class="boot">Cannot reach the CERBERUS API: ${esc(err.message)}</div>`;
    }
  }

  window.addEventListener('hashchange', () => (state.user && $('.shell') && !PUBLIC_ROUTES.has(hashRoute().path) ? route() : boot()));
  boot();
})();
