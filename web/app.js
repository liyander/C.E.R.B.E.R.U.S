/* CERBERUS web UI — dependency-free SPA. All dynamic text goes through esc():
   event and log content is attacker-influenced and must never reach innerHTML raw. */
(() => {
  'use strict';

  const $ = (sel, root = document) => root.querySelector(sel);
  const app = $('#app');
  const REFRESH_MS = 30000;
  const CHAT_KEY = 'cerberus-chat-id';
  const APP_VERSION = '0.2.0'; // must match VERSION in backend/app/main.py
  const state = { user: null, chat: [], chatId: null, convos: [], busy: false, live: null, abort: null, presets: [], emailReady: false, aiReady: false, aiTools: [], investigating: false };

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
    user: 'M12 12a4 4 0 100-8 4 4 0 000 8zM4 21a8 8 0 0116 0',
    mail: 'M3 6h18v12H3zM3 7l9 6 9-6',
  };
  const icon = (name, size = 18) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.700" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="${ICONS[name]}"/></svg>`;

  // Three guardian heads on a tile that follows the chosen accent palette.
  const logo = () => `<svg viewBox="0 0 64 64" role="img" aria-label="CERBERUS"><defs><linearGradient id="logo-g" x1="0" y1="0" x2="1" y2="1"><stop offset="0" class="logo-a"/><stop offset="1" class="logo-b"/></linearGradient><radialGradient id="logo-h" cx=".3" cy=".1" r=".9"><stop offset="0" stop-color="#fff" stop-opacity=".28"/><stop offset=".6" stop-color="#fff" stop-opacity="0"/></radialGradient></defs><rect width="64" height="64" rx="15" fill="url(#logo-g)"/><rect width="64" height="64" rx="15" fill="url(#logo-h)"/><rect x=".75" y=".75" width="62.500" height="62.500" rx="14.250" fill="none" stroke="#fff" stroke-opacity=".2" stroke-width="1.500"/><g fill="#fff"><g opacity=".5"><path transform="translate(17.500 29.500) rotate(-20) scale(.66) translate(-32 -32)" d="M20.500 12 27 21.500 32 19.500 37 21.500 43.500 12 46.500 30 40.500 42.500 32 53 23.500 42.500 17.500 30Z"/><path transform="translate(46.500 29.500) rotate(20) scale(.66) translate(-32 -32)" d="M20.500 12 27 21.500 32 19.500 37 21.500 43.500 12 46.500 30 40.500 42.500 32 53 23.500 42.500 17.500 30Z"/></g><path d="M20.500 12 27 21.500 32 19.500 37 21.500 43.500 12 46.500 30 40.500 42.500 32 53 23.500 42.500 17.500 30Z" stroke="rgba(6,40,48,.28)" stroke-width="1.600" stroke-linejoin="round" paint-order="stroke"/></g><path d="M22.800 29.600 30 33.400 29.300 36.300 24.200 34.300ZM41.200 29.600 34 33.400 34.700 36.300 39.800 34.300ZM29.800 45.600h4.400L32 48.800Z" fill="#0a2f38"/></svg>`;
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
    ['Operate', [['console', 'Enforcer console', 'chat'], ['incidents', 'Incidents', 'alert'], ['events', 'Events', 'list'],
      ['assets', 'Assets', 'server'], ['approvals', 'Approvals', 'check']]],
    ['Administer', [['users', 'Users', 'users', true], ['announcements', 'Announcements', 'megaphone', true],
      ['providers', 'AI providers', 'spark', true], ['integrations', 'Integrations', 'plug', true], ['audit', 'Audit log', 'clock', true]]],
  ];
  const ADMIN_VIEWS = new Set(NAV.flatMap(([, items]) => items).filter((item) => item[3]).map((item) => item[0]));
  const TITLES = { account: 'My account', ...Object.fromEntries(NAV.flatMap(([, items]) => items).map(([id, text]) => [id, text])) };

  function ensureShell() {
    if ($('.shell')) return;
    const visible = NAV.map(([label, items]) => [label, items.filter((item) => !item[3] || isAdmin())]).filter(([, items]) => items.length);
    const nav = visible.map(([label, items]) => `${label ? `<div class="nav-label">${label}</div>` : ''}${items.map(([id, text, ic]) =>
      `<a href="#/${id}" data-nav="${id}" title="${text}">${icon(ic)}<span>${text}</span>${
        id === 'incidents' ? '<span class="count quiet" data-badge="incidents" hidden></span>' : ''}${
        id === 'approvals' ? '<span class="count" data-badge="approvals" hidden></span>' : ''}</a>`).join('')}`).join('');
    app.innerHTML = `
      <div class="shell ${pref.get('sidebar', 'open') === 'rail' ? 'rail' : ''}">
        <aside class="sidebar">
          <a class="brand" href="#/overview" title="CERBERUS">${logo()}<div><b>CERBERUS</b><small>Security operations</small></div></a>
          <form class="quick" data-form="quick">${icon('search', 16)}
            <input type="text" name="q" id="quick" placeholder="Search or jump to…" autocomplete="off" aria-label="Search or jump to a page" readonly><kbd>Ctrl K</kbd></form>
          <nav class="nav">${nav}</nav>
          <div class="side-foot"><a class="initial" href="#/account" title="My account">${esc(state.user.username.slice(0, 1))}</a>
            <a class="me" href="#/account" title="My account"><b>${esc(state.user.username)}</b><small>${roleName(state.user.role)}</small></a>
            <button class="btn ghost icon" data-action="logout" title="Sign out" aria-label="Sign out">${icon('logout')}</button></div>
        </aside>
        <div class="scrim" data-action="drawer"></div>
        <div class="main">
          <header class="topbar">
            <button class="btn ghost icon menu-btn" data-action="drawer" title="Show or hide the sidebar (Ctrl+B)" aria-label="Toggle sidebar">${icon('menu')}</button>
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
    const set = (name, n) => { const el = $(`[data-badge="${name}"]`); if (el) { el.textContent = n; el.hidden = !n; } };
    set('incidents', o.open_incidents);
    set('approvals', o.pending_approvals);
    set('notifications', o.unread_notifications || 0);
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
    <tr><th>Incident</th>${withStatus ? '<th>Status</th>' : ''}<th>Severity</th><th>Asset</th><th>Source IP</th><th>Events</th><th>Last seen</th></tr>
    ${list.map((i) => `<tr class="clickable sev-${esc(i.severity_label)}" data-href="#/incidents/${i.id}">
      <td class="wrap"><strong>${esc(i.ref)}</strong> ${esc(i.title)}${demoBadge(i.demo)}</td>
      ${withStatus ? `<td>${statusBadge(i.status)}</td>` : ''}<td>${sevBadge(i.severity_label, i.severity)}</td><td>${esc(i.asset_name || '—')}</td>
      <td class="mono">${esc(i.source_ip || '—')}</td><td>${i.event_count}</td><td class="nowrap">${agoCell(i.last_seen)}</td></tr>`).join('')}
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

  // Stacked columns: events per hour for the last 24 hours, split by severity.
  function drawEventsChart() {
    const el = $('#events-chart');
    const data = state.hourly;
    if (!el || !data) return;
    if (!data.some(hourTotal)) { el.innerHTML = '<div class="chart-empty">No events in the last 24 hours.</div>'; return; }
    const W = Math.max(300, el.clientWidth);
    const H = 220;
    const m = { l: 36, r: 6, t: 10, b: 24 };
    const pw = W - m.l - m.r;
    const ph = H - m.t - m.b;
    const max = niceMax(Math.max(...data.map(hourTotal)));
    const y = (v) => m.t + ph - (v / max) * ph;
    const band = pw / data.length;
    const bw = Math.min(24, Math.max(4, band - 4));
    let grid = ''; let hits = ''; let bars = ''; let labels = '';
    for (const t of [0, max / 2, max]) {
      grid += `<line class="${t ? 'grid' : 'axis'}" x1="${m.l}" x2="${W - m.r}" y1="${y(t)}" y2="${y(t)}"/><text class="tick" x="${m.l - 7}" y="${y(t) + 4}" text-anchor="end">${t}</text>`;
    }
    data.forEach((h, i) => {
      const x = m.l + i * band + (band - bw) / 2;
      hits += `<rect class="hit" data-i="${i}" x="${m.l + i * band}" y="${m.t}" width="${band}" height="${ph}"/>`;
      const parts = ['low', 'medium', 'high', 'critical'].filter((k) => h[k] > 0);
      let acc = 0;
      parts.forEach((k, j) => {
        const top = y(acc + h[k]);
        const height = Math.max(1, y(acc) - top - (j ? 2 : 0)); // 2px surface gap between stacked segments
        acc += h[k];
        if (j === parts.length - 1) {
          const r = Math.min(4, bw / 2, height);
          bars += `<path class="seg sev-${k}" d="M${x},${top + height}V${top + r}Q${x},${top} ${x + r},${top}H${x + bw - r}Q${x + bw},${top} ${x + bw},${top + r}V${top + height}Z"/>`;
        } else bars += `<rect class="seg sev-${k}" x="${x}" y="${top}" width="${bw}" height="${height}"/>`;
      });
      if ((data.length - 1 - i) % 4 === 0) labels += `<text class="tick" x="${m.l + i * band + band / 2}" y="${H - 6}" text-anchor="middle">${i === data.length - 1 ? 'now' : hourLabel(h.hour)}</text>`;
    });
    el.innerHTML = `<svg width="${W}" height="${H}" role="img" aria-label="Events per hour over the last 24 hours, stacked by severity. ${data.reduce((n, h) => n + hourTotal(h), 0)} events in total.">${grid}${hits}${bars}${labels}</svg><div class="chart-tip" hidden></div>`;
    const tip = $('.chart-tip', el);
    el.onmousemove = (e) => {
      const hit = e.target.closest('.hit');
      if (!hit) { tip.hidden = true; return; }
      const i = Number(hit.dataset.i);
      const h = data[i];
      const end = new Date(new Date(h.hour).getTime() + 3600000).toISOString();
      tip.innerHTML = `<div class="tip-head">${hourLabel(h.hour)} – ${hourLabel(end)}</div><div class="tip-total">${hourTotal(h)} ${hourTotal(h) === 1 ? 'event' : 'events'}</div>${
        SEVERITIES.filter(([k]) => h[k]).map(([k, name]) => `<div class="tip-row"><span class="sw sev-${k}"></span>${name}<b>${h[k]}</b></div>`).join('')}`;
      tip.hidden = false;
      const center = m.l + i * band + band / 2;
      tip.style.left = `${Math.min(Math.max(center - tip.offsetWidth / 2, 0), W - tip.offsetWidth)}px`;
    };
    el.onmouseleave = () => { tip.hidden = true; };
  }
  window.addEventListener('resize', () => drawEventsChart());

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
    state.hourly = o.hourly || [];
    const sevTotals = SEVERITIES.map(([k, name]) => [k, name, state.hourly.reduce((n, h) => n + h[k], 0)]);
    const html = `<div class="page">
      <div class="hero">
        <a class="pill" href="${admin ? '#/providers' : '#/console'}">${ai}</a>
        <h1>Let's get to work.</h1>
        <form class="ask" data-form="ask">${icon('search', 20)}
          <input type="text" name="q" placeholder="Ask CERBERUS — e.g. “Show all suspicious activity on sietlms in the last 24 hours”" autocomplete="off" aria-label="Ask CERBERUS"></form>
      </div>
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
          <div class="legend">${sevTotals.map(([k, name, n]) => `<span><i class="sw sev-${k}"></i>${name} <b>${n}</b></span>`).join('')}</div>
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
    return { html, mount: drawEventsChart };
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
    propose_response_action: 'Propose response action', get_server_health: 'Check server health',
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
        body: JSON.stringify({ message: text, conversation_id: state.chatId }), signal: state.abort.signal,
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
    const q = params.get('q') || '';
    const min = params.get('min') || '1';
    const source = params.get('source') || '';
    const [events, o] = await Promise.all([
      api(`/events?q=${encodeURIComponent(q)}&min_severity=${encodeURIComponent(min)}&source=${encodeURIComponent(source)}`), overview]);
    return page('Events', `Normalised detections from every connected engine, newest first. ${events.length ? `Showing ${events.length}.` : ''}`,
      `<form class="row" data-form="events-filter">
        <input type="text" name="q" value="${esc(q)}" placeholder="Search title, message, IP, user, asset" style="width:280px" aria-label="Search">
        <select name="source" style="width:auto" aria-label="Source" data-change="submit-form"><option value="">All sources</option>
          ${o.sources.map((s) => `<option value="${esc(s.source)}" ${s.source === source ? 'selected' : ''}>${esc(s.source)}</option>`).join('')}</select>
        <select name="min" style="width:auto" aria-label="Minimum severity" data-change="submit-form">${[['1', 'All severities'], ['4', 'Medium +'], ['7', 'High +'], ['9', 'Critical']]
          .map(([v, t]) => `<option value="${v}" ${v === min ? 'selected' : ''}>${t}</option>`).join('')}</select>
        <button class="btn">Search</button>${q || source || min !== '1' ? '<a class="btn ghost" href="#/events">Clear</a>' : ''}</form>`,
      events.length ? `<div class="card">${eventTable(events)}</div>` : empty('No events match', 'Connect a source under Integrations, or widen the filter.', '', 'search'));
  };

  views.assets = async () => {
    const assets = await api('/assets');
    return page('Assets', 'Hosts and services seen in events. New names are added automatically on first sight.', '',
      assets.length ? `<div class="card"><div class="table-scroll"><table>
        <tr><th>Name</th><th>IP</th><th>Kind</th><th>Criticality</th><th>Open incidents</th><th>Events</th><th>Last event</th></tr>
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
    const [data, mail] = await Promise.all([api('/integrations'), api('/integrations/email')]);
    const g = data.grafana;
    const m = mail.settings;
    const hook = `${location.origin}/api/v1/webhooks/grafana`;
    const planned = ['Wazuh', 'Snort 3', 'Zeek', 'open-appsec', 'Velociraptor', 'VirusTotal / MISP', 'Slack', 'Jira', 'Gmail'];
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
    ask(f) { const q = f.q.value.trim(); if (q) location.hash = `#/console?q=${encodeURIComponent(q)}`; },
    chat(f) { if (state.busy) return; const q = f.q.value; f.q.value = ''; f.q.style.height = 'auto'; sendChat(q); },
    'events-filter'(f) {
      const p = new URLSearchParams();
      if (f.q.value.trim()) p.set('q', f.q.value.trim());
      if (f.source.value) p.set('source', f.source.value);
      if (f.min.value !== '1') p.set('min', f.min.value);
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
    if (lock) button.disabled = true;
    Promise.resolve().then(() => forms[form.dataset.form](form)).catch((err) => {
      const slot = $('.form-error', form);
      if (slot) slot.textContent = err.message; else fail(err);
    }).finally(() => { if (lock) button.disabled = false; });
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
  document.addEventListener('keydown', (e) => {
    if (!(e.ctrlKey || e.metaKey) || !$('.shell')) return;
    if (e.key.toLowerCase() === 'b') { e.preventDefault(); actions.drawer(); }
    if (e.key.toLowerCase() === 'k') { e.preventDefault(); openPalette(); }
  });

  document.addEventListener('focusin', (e) => { if (e.target.id === 'quick') { e.target.blur(); openPalette(); } });

  // ---------- routing / boot ----------

  let renderSeq = 0;
  let current = '';
  async function route({ soft = false } = {}) {
    if (!state.user) return;
    const [path, query = ''] = location.hash.replace(/^#\/?/, '').split('?');
    const [name = '', id] = path.split('/');
    const key = views[name] && (!ADMIN_VIEWS.has(name) || isAdmin()) ? name : 'overview';
    ensureShell();
    document.querySelectorAll('[data-nav]').forEach((a) => a.classList.toggle('active', a.dataset.nav === key));
    $('#top-title').textContent = TITLES[key];
    $('.shell').classList.remove('drawer');
    const view = $('#view');
    const seq = ++renderSeq;
    current = key + (id ? '/detail' : '');
    if (!soft) {
      view.innerHTML = '<div class="page skeleton"><div class="sk w30"></div><div class="sk w50 thin"></div><div class="sk block"></div><div class="sk block short"></div></div>';
      view.scrollTop = 0;
    }
    const overview = loadOverview();
    overview.catch(() => {});
    try {
      const result = await views[key]({ id, params: new URLSearchParams(query), overview });
      if (seq !== renderSeq || !state.user) return;
      const top = view.scrollTop;
      view.innerHTML = typeof result === 'string' ? result : result.html;
      if (!soft && view.firstElementChild) view.firstElementChild.classList.add('enter');
      if (soft) view.scrollTop = top;
      if (result.mount) result.mount();
    } catch (err) {
      if (seq === renderSeq && state.user && !soft) view.innerHTML = `<div class="page">${empty('Something went wrong', esc(err.message), '<div style="margin-top:14px"><button class="btn" data-action="reload">Try again</button></div>', 'alert')}</div>`;
    }
  }
  actions.reload = () => route();

  // Keep live views fresh without disturbing anyone who is typing, reading an expanded row or mid-dialog.
  const AUTO_REFRESH = new Set(['overview', 'incidents', 'incidents/detail', 'events', 'assets', 'approvals', 'audit']);
  async function refreshUser() { const s = await api('/auth/state'); if (s.user) state.user = s.user; }
  setInterval(() => {
    if (!state.user || document.hidden || state.investigating) return;
    const active = document.activeElement;
    const typing = active && /^(INPUT|TEXTAREA|SELECT)$/.test(active.tagName);
    if (AUTO_REFRESH.has(current) && !typing && !$('dialog[open]') && !$('.logline.open') && !String(getSelection())) route({ soft: true });
    else loadOverview().catch(() => {});
  }, REFRESH_MS);

  function authCard(title, text, inner, form = '') {
    app.innerHTML = `<div class="auth">
      <div class="auth-brand"><div class="auth-brand-in">${logo()}
        <h2>CERBERUS</h2><p>AI-assisted security operations</p>
        <ul><li>${icon('alert', 18)}<span>Alerts from every engine, correlated into incidents</span></li>
          <li>${icon('spark', 18)}<span>An AI analyst that answers from evidence it retrieves</span></li>
          <li>${icon('check', 18)}<span>People approve every response action</span></li></ul></div></div>
      <div class="auth-main"><${form ? `form ${form}` : 'div'} class="card">
        <h1>${title}</h1><p>${text}</p>${inner}</${form ? 'form' : 'div'}></div></div>`;
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
