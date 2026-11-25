/* NetLine VPN — интерфейс (общий для компьютера и Android) */
(function () {
  'use strict';
  const L = window.NLLinks, C = window.NLConfig, N = window.native;
  const $ = function (id) { return document.getElementById(id); };
  const SUB_UA = 'v2rayN/7.13.8 NetLineVPN/1.0';
  const SITE = 'https://github.com/uproxe/NetLineVPN';

  const DEFAULT = { v: 1, settings: { mode: 'tun', ruDirect: true, autoConnect: false, autostart: false }, selected: null, subs: [], nodes: [] };
  const S = {
    state: null, platform: null, status: { state: 'off' }, view: 'home',
    delays: {}, testing: false, prev: null, autoNow: '', busy: false, lastError: '', names: {}
  };

  // ───────── помощники ─────────

  function esc(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function hash(s) {
    let h = 0x811c9dc5;
    for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 0x01000193); }
    return (h >>> 0).toString(36);
  }
  function uid() { return Date.now().toString(36) + Math.random().toString(36).slice(2, 6); }
  function bytes(n) {
    if (!n || n < 0) n = 0;
    const u = ['Б', 'КБ', 'МБ', 'ГБ', 'ТБ'];
    let i = 0;
    while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
    return (i && n < 10 ? n.toFixed(1) : Math.round(n)) + ' ' + u[i];
  }
  function duration(ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    const h = Math.floor(s / 3600), m = Math.floor(s / 60) % 60, x = s % 60;
    const p = function (v) { return (v < 10 ? '0' : '') + v; };
    return (h ? h + ':' : '') + p(m) + ':' + p(x);
  }
  function date(sec) { const d = new Date(sec * 1000); return d.toLocaleDateString('ru-RU', { day: 'numeric', month: 'short', year: 'numeric' }); }
  const BADGE = { vless: 'VLESS', vmess: 'VMESS', trojan: 'TROJAN', shadowsocks: 'SS', socks: 'SOCKS', http: 'HTTP', https: 'HTTPS',
    hysteria2: 'HY2', hysteria: 'HY', tuic: 'TUIC', anytls: 'ANYTLS', ssh: 'SSH', wireguard: 'WG', naive: 'NAIVE',
    openvpn: 'OVPN', openconnect: 'OC', shadowtls: 'STLS', shadowsocksr: 'SSR' };
  function badge(p) { return BADGE[p] || String(p || '?').toUpperCase().slice(0, 6); }

  // Флаги — картинками (Twemoji): в Windows эмодзи-флаги не рисуются, а так везде одинаково
  function flagImg(cc) {
    cc = String(cc || '').toLowerCase();
    return /^[a-z]{2}$/.test(cc) ? '<img class="flag" src="flags/' + cc + '.svg" alt="" onerror="this.remove()">' : '';
  }
  /** Название с флагами-эмодзи → безопасный HTML с картинками флагов */
  function nameHtml(name) {
    return esc(name).replace(/(\uD83C[\uDDE6-\uDDFF])(\uD83C[\uDDE6-\uDDFF])/g, function (m, a, b) {
      return flagImg(String.fromCharCode(a.charCodeAt(1) - 0xDDE6 + 97, b.charCodeAt(1) - 0xDDE6 + 97));
    });
  }
  let regionNames = null;
  function countryName(cc) {
    try {
      if (!regionNames) regionNames = new Intl.DisplayNames(['ru'], { type: 'region' });
      return regionNames.of(String(cc).toUpperCase()) || cc;
    } catch (e) { return cc; }
  }

  let toastTimer;
  function toast(msg, err) {
    const t = $('toast');
    t.textContent = msg;
    t.className = 'toast' + (err ? ' err' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { t.className = 'toast hidden'; }, err ? 6000 : 3000);
  }

  // ───────── хранение ─────────

  let saveTimer;
  function save() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(function () {
      N.call('save_state', { data: JSON.stringify(S.state) }).catch(function (e) { toast('Не удалось сохранить: ' + e.message, true); });
      pushReady();
    }, 250);
  }

  function allNodes() {
    const out = [];
    S.state.subs.forEach(function (s) { s.nodes.forEach(function (n) { out.push(n); }); });
    S.state.nodes.forEach(function (n) { out.push(n); });
    return out;
  }
  function findNode(id) { return allNodes().filter(function (n) { return n.id === id; })[0] || null; }
  function findSub(id) { return S.state.subs.filter(function (s) { return s.id === id; })[0] || null; }
  function withIds(nodes, prefix) {
    const seen = {};
    return nodes.map(function (n) {
      let id = prefix + hash(JSON.stringify(n.src));
      while (seen[id]) id += 'x';
      seen[id] = 1;
      return { id: id, name: n.name, proto: n.proto, host: n.host, port: n.port, src: n.src };
    });
  }

  /** Что подключать: { nodes, auto, label } */
  function selection() {
    const sel = S.state.selected || {};
    if (sel.auto) {
      const sub = findSub(sel.auto);
      if (sub && sub.nodes.length) return { nodes: sub.nodes, auto: true, label: 'Авто — ' + sub.name, sub: sub };
    }
    if (sel.id) { const n = findNode(sel.id); if (n) return { nodes: [n], auto: false, label: n.name, node: n }; }
    const first = allNodes()[0];
    return first ? { nodes: [first], auto: false, label: first.name, node: first } : null;
  }

  // ───────── конфигурация ─────────

  async function payload(nodes, auto, forceMode) {
    const compiled = [], used = [];
    nodes.forEach(function (n) {
      try { compiled.push(L.compile(n.src)); used.push(n); } catch (e) { /* неподдерживаемый сервер пропускаем */ }
    });
    if (!compiled.length) throw new Error('Этот сервер не поддерживается');
    const os = S.platform.os;
    const mode = forceMode || (os === 'android' ? 'android' : S.state.settings.mode);
    const xc = C.xrayCount(compiled);
    const ports = await N.call('free_ports', { count: 3 + xc });
    const secret = C.randomToken(16);
    const auth = { user: 'nl' + C.randomToken(4), pass: C.randomToken(16) };
    const b = C.build({ nodes: compiled, auto: auto, mode: mode, os: os, ruDirect: S.state.settings.ruDirect,
      rulesDir: S.platform.rulesDir, ports: { clash: ports[0], inbound: mode === 'proxy' ? C.PROXY_PORT : ports[1], check: ports[2], xray: ports.slice(3) },
      secret: secret, auth: auth });
    const names = {};
    Object.keys(b.tags).forEach(function (t) { names[t] = used[b.tags[t]].name; });
    return {
      mode: mode, singbox: JSON.stringify(b.singbox), xray: b.xray ? JSON.stringify(b.xray) : null,
      clashPort: ports[0], clashSecret: secret, proxyPort: C.PROXY_PORT,
      socksPort: ports[1], socksUser: auth.user, socksPass: auth.pass, checkPort: ports[2],
      label: auto ? 'Авто' : used[0].name, names: names, autoConnect: !!S.state.settings.autoConnect,
      tags: b.tags
    };
  }

  // для значка в трее и плитки Android: что включать без открытого окна
  let readyTimer;
  function pushReady() {
    clearTimeout(readyTimer);
    readyTimer = setTimeout(async function () {
      const sel = selection();
      try {
        if (!sel) { await N.call('set_ready', { ready: null }); return; }
        const p = await payload(sel.nodes, sel.auto);
        await N.call('set_ready', { ready: p });
      } catch (e) { /* не страшно: подключиться можно из окна */ }
    }, 400);
  }

  // ───────── подключение ─────────

  async function connect() {
    const sel = selection();
    if (!sel) { go('servers'); openAdd(); return; }
    S.busy = true;
    S.lastError = '';
    setStatus({ state: 'connecting' });
    try {
      const p = await payload(sel.nodes, sel.auto);
      S.names = p.names;
      await N.call('connect', p);
    } catch (e) {
      if (!/отмен/i.test(e.message)) toast(e.message, true);
      S.lastError = e.message;
    }
    S.busy = false;
    poll();
  }

  async function disconnect() {
    S.busy = true;
    try { await N.call('disconnect'); } catch (e) { toast(e.message, true); }
    setStatus({ state: 'off' });
    S.busy = false;
  }

  async function toggle() {
    if (S.busy) return;
    const st = S.status.state;
    if (st === 'on' || st === 'connecting') { await disconnect(); poll(); return; }
    await connect();
  }

  /** Переподключиться с новыми настройками (если было подключено) */
  async function reconnectIfOn(msg) {
    if (S.status.state !== 'on' || S.busy) { pushReady(); return; }
    if (msg) toast(msg);
    await disconnect();
    await connect();
  }

  // ───────── состояние ─────────

  let pollTimer, nowTimer = 0;
  async function poll() {
    clearTimeout(pollTimer);
    try { setStatus(await N.call('status')); } catch (e) { /* мост ещё не готов */ }
    if (!document.hidden) pollTimer = setTimeout(poll, 1000);
  }

  function setStatus(st) {
    const old = S.status.state;
    S.status = st;
    const s = st.state || 'off';
    document.body.className = document.body.className.replace(/\bst-\w+/g, '').trim() + ' st-' + s;
    const power = $('power');
    let title = 'Не подключено', sub = 'Нажмите, чтобы подключиться';
    if (s === 'connecting' && st.stage === 'check') { title = 'Подключение…'; sub = 'Проверяем, что сервер пропускает трафик'; }
    else if (s === 'connecting') { title = 'Подключение…'; sub = S.platform && S.platform.os === 'macos' && S.state.settings.mode === 'tun' ? 'Может понадобиться пароль администратора' : ''; }
    else if (s === 'on') { title = 'Подключено'; sub = st.since ? duration(Date.now() - st.since) : ''; }
    else if (s === 'error') { title = 'Ошибка'; sub = st.error || 'Не удалось подключиться'; }
    else if (S.lastError) { sub = S.lastError; }
    $('state').textContent = title;
    $('state-sub').textContent = sub;
    power.setAttribute('aria-label', s === 'on' || s === 'connecting' ? 'Отключить' : 'Подключить');

    // скорость
    const now = Date.now();
    if (s === 'on' && S.prev && st.rx >= S.prev.rx) {
      const dt = Math.max(0.2, (now - S.prev.t) / 1000);
      $('down').textContent = bytes((st.rx - S.prev.rx) / dt) + '/с';
      $('up').textContent = bytes((st.tx - S.prev.tx) / dt) + '/с';
    } else if (s !== 'on') {
      $('down').textContent = '0 Б/с'; $('up').textContent = '0 Б/с';
    }
    S.prev = { rx: st.rx || 0, tx: st.tx || 0, t: now };
    $('speed').classList.toggle('hidden', s !== 'on');
    const geoKey = s === 'on' ? (st.country || '') + '|' + (st.ip || '') : '';
    if (geoKey !== S.geoKey) {
      S.geoKey = geoKey;
      const g = $('geo');
      if (geoKey && (st.country || st.ip)) {
        g.innerHTML = flagImg(st.country) + (st.country ? '<span>' + esc(countryName(st.country)) + '</span>' : '') +
          (st.ip ? '<span class="ip">' + esc(st.ip) + '</span>' : '');
        g.classList.remove('hidden');
      } else { g.classList.add('hidden'); g.innerHTML = ''; }
    }

    if (s === 'error' && old !== 'error' && st.error) toast(st.error, true);
    if (s === 'on' && st.clashPort && now - nowTimer > 5000) { nowTimer = now; updateAutoNow(st); }
    if (s !== 'on') S.autoNow = '';
    if (old !== s) renderCurrent();
  }

  async function updateAutoNow(st) {
    try {
      const r = await N.call('fetch_url', { url: 'http://127.0.0.1:' + st.clashPort + '/proxies/proxy', headers: { Authorization: 'Bearer ' + st.clashSecret }, timeout: 2000 });
      const j = JSON.parse(r.body || '{}');
      const name = j.now ? (S.names[j.now] || (st.names && st.names[j.now]) || '') : '';
      if (name !== S.autoNow) { S.autoNow = name; renderCurrent(); }
    } catch (e) { /* не важно */ }
  }

  // ───────── отрисовка ─────────

  function go(view) {
    S.view = view;
    ['home', 'servers', 'settings'].forEach(function (v) { $('v-' + v).classList.toggle('hidden', v !== view); });
    if (view === 'servers') renderServers();
    if (view === 'settings') renderSettings();
    if (view === 'home') renderCurrent();
  }

  function delayHtml(id) {
    const d = S.delays[id];
    if (d === undefined) return '<span class="delay"></span>';
    if (d === 'wait') return '<span class="delay">…</span>';
    if (d === -2) return '<span class="delay badv">нет</span>';
    if (d < 0) return '<span class="delay badv">✕</span>';
    return '<span class="delay ' + (d < 300 ? 'good' : d < 800 ? 'mid' : 'badv') + '">' + d + ' мс</span>';
  }

  function renderCurrent() {
    $('mode-note').textContent = S.state.settings.mode === 'proxy' ? 'Режим: системный прокси (сменить — в настройках)' : '';
    const sel = selection();
    if (!sel) {
      $('cur-badge').textContent = '+';
      $('cur-name').textContent = 'Добавьте сервер';
      $('cur-info').textContent = 'Ссылка, подписка, WireGuard или OpenVPN';
      return;
    }
    if (sel.auto) {
      $('cur-badge').textContent = 'АВТО';
      $('cur-name').innerHTML = nameHtml(sel.sub.name);
      $('cur-info').innerHTML = S.autoNow ? 'Сейчас: ' + nameHtml(S.autoNow) : 'Самый быстрый из ' + sel.nodes.length;
    } else {
      const n = sel.node;
      $('cur-badge').textContent = badge(n.proto);
      $('cur-name').innerHTML = nameHtml(n.name);
      const d = S.delays[n.id];
      $('cur-info').textContent = (L.TITLES[n.proto] || n.proto) + (typeof d === 'number' && d >= 0 ? ' · ' + d + ' мс' : '');
    }
  }

  const DOTS = '<svg viewBox="0 0 24 24"><circle cx="12" cy="5" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="12" cy="19" r="2"/></svg>';

  function nodeRow(n, active) {
    return '<div class="row node' + (active ? ' active' : '') + '" data-node="' + esc(n.id) + '">' +
      '<span class="sel"></span><span class="badge">' + esc(badge(n.proto)) + '</span>' +
      '<span class="grow"><span class="title">' + nameHtml(n.name) + '</span><span class="muted small title">' + esc(n.host) + (n.port ? ':' + n.port : '') + '</span></span>' +
      delayHtml(n.id) + '<button class="more" data-menu-node="' + esc(n.id) + '" aria-label="Действия">' + DOTS + '</button></div>';
  }

  function renderServers() {
    const sel = S.state.selected || {};
    const cur = selection();
    const curId = cur && !cur.auto ? cur.node.id : null;
    let h = '';
    S.state.subs.forEach(function (s) {
      let info = [];
      if (s.info && s.info.total) info.push(bytes(s.info.upload + s.info.download) + ' из ' + bytes(s.info.total));
      else if (s.info && (s.info.upload || s.info.download)) info.push(bytes(s.info.upload + s.info.download));
      if (s.info && s.info.expire) info.push('до ' + date(s.info.expire));
      if (S.updating === s.id) info = ['обновление…'];
      h += '<div class="group"><div class="group-head"><span class="grow"><span class="title">' + nameHtml(s.name) + '</span>' +
        '<span class="muted small">' + esc(info.join(' · ') || (s.nodes.length + ' серв.')) + '</span></span>' +
        '<button class="more" data-menu-sub="' + esc(s.id) + '" aria-label="Подписка">' + DOTS + '</button></div>';
      if (s.nodes.length > 1) {
        h += '<div class="row node' + (sel.auto === s.id ? ' active' : '') + '" data-auto="' + esc(s.id) + '"><span class="sel"></span>' +
          '<span class="badge">АВТО</span><span class="grow"><span class="title">Самый быстрый</span><span class="muted small">Выбирается сам и меняется, если сервер перестал отвечать</span></span></div>';
      }
      s.nodes.forEach(function (n) { h += nodeRow(n, n.id === curId && !sel.auto); });
      if (!s.nodes.length) h += '<div class="row muted small">В подписке нет серверов</div>';
      h += '</div>';
    });
    if (S.state.nodes.length) {
      h += '<div class="group"><div class="group-title">Мои серверы</div>';
      S.state.nodes.forEach(function (n) { h += nodeRow(n, n.id === curId); });
      h += '</div>';
    }
    if (!h) {
      h = '<div class="empty"><div class="title">Серверов пока нет</div><div class="small">Добавьте ссылку, подписку или файл WireGuard/OpenVPN</div>' +
        '<button class="btn primary" id="empty-add">Добавить</button></div>';
    }
    $('servers').innerHTML = h;
    $('btn-test').classList.toggle('busy', S.testing);
  }

  function renderSettings() {
    const st = S.state.settings;
    Array.prototype.forEach.call(document.querySelectorAll('input[name=mode]'), function (r) { r.checked = r.value === st.mode; });
    $('opt-ru').checked = !!st.ruDirect;
    $('opt-autoconnect').checked = !!st.autoConnect;
    $('opt-autostart').checked = !!st.autostart;
    const p = S.platform || {};
    if (p.os === 'macos') $('tun-hint').textContent = 'Через сервер идёт трафик всех программ. При подключении macOS спросит пароль администратора';
    if (p.os === 'linux' && p.appimage) $('tun-hint').textContent = 'Через сервер идёт трафик всех программ. При подключении система спросит пароль';
    $('about').textContent = 'NetLine VPN ' + (p.version || '');
  }

  // ───────── окна ─────────

  function sheet(html, onOpen) {
    $('sheet').innerHTML = html;
    $('modal').classList.remove('hidden');
    if (onOpen) onOpen($('sheet'));
  }
  function closeSheet() { $('modal').classList.add('hidden'); $('sheet').innerHTML = ''; }

  function menu(items) {
    sheet('<div class="menu">' + items.map(function (it, i) {
      return '<button class="row link" data-i="' + i + '"><span class="grow title' + (it.danger ? ' bad' : '') + '">' + esc(it.label) + '</span></button>';
    }).join('') + '</div><div class="actions"><button class="btn grow1" data-close>Отмена</button></div>', function (el) {
      el.querySelectorAll('[data-i]').forEach(function (b) {
        b.onclick = function () { closeSheet(); items[+b.dataset.i].run(); };
      });
    });
  }

  function confirmBox(text, okLabel, run) {
    sheet('<h2>' + esc(text) + '</h2><div class="actions"><button class="btn grow1" data-close>Отмена</button>' +
      '<button class="btn primary grow1" id="cf-ok">' + esc(okLabel) + '</button></div>', function () {
      $('cf-ok').onclick = function () { closeSheet(); run(); };
    });
  }

  function prompt(title, value, run) {
    sheet('<h2>' + esc(title) + '</h2><label class="field"><input id="pr-v" value="' + esc(value) + '"></label>' +
      '<div class="actions"><button class="btn grow1" data-close>Отмена</button><button class="btn primary grow1" id="pr-ok">Сохранить</button></div>', function () {
      const i = $('pr-v'); i.focus(); i.select();
      const ok = function () { const v = i.value.trim(); if (!v) return; closeSheet(); run(v); };
      $('pr-ok').onclick = ok;
      i.onkeydown = function (e) { if (e.key === 'Enter') ok(); };
    });
  }

  async function copy(text) {
    try {
      if (S.platform.os === 'android') await N.call('clipboard_write', { text: text });
      else await navigator.clipboard.writeText(text);
      toast('Скопировано');
    } catch (e) {
      const ta = document.createElement('textarea');
      ta.value = text; document.body.appendChild(ta); ta.select();
      try { document.execCommand('copy'); toast('Скопировано'); } catch (x) { toast('Не удалось скопировать', true); }
      ta.remove();
    }
  }

  function srcText(n) { return typeof n.src === 'string' ? n.src : JSON.stringify(n.src.xray ? { remarks: n.name, outbounds: n.src.xray.outbounds } : (n.src.sb || n.src.sbEndpoint), null, 2); }

  // ───────── добавление ─────────

  function openAdd(prefill) {
    sheet('<h2>Добавить сервер</h2>' +
      '<p>Вставьте ссылку (vless://, hysteria2://, ss:// …), адрес подписки или содержимое файла WireGuard или OpenVPN.</p>' +
      '<textarea id="add-text" spellcheck="false" placeholder="vless://… или https://…"></textarea>' +
      '<div class="actions"><button class="btn" id="add-paste">Вставить</button><button class="btn" id="add-file">Из файла</button>' +
      '<button class="btn primary grow1" id="add-ok">Добавить</button></div>' +
      '<div class="links"><button id="add-proxy">Прокси или VPN вручную</button></div>', function () {
      const ta = $('add-text');
      if (prefill) ta.value = prefill;
      if (S.platform.os !== 'android') ta.focus();
      $('add-paste').onclick = async function () {
        try {
          const t = S.platform.os === 'android' ? await N.call('clipboard_read') : await navigator.clipboard.readText();
          if (t) ta.value = t; else toast('Буфер обмена пуст');
        } catch (e) { ta.focus(); toast('Нажмите Ctrl+V (⌘V) в поле'); }
      };
      $('add-file').onclick = function () { $('file').click(); };
      $('add-proxy').onclick = openProxyForm;
      $('add-ok').onclick = function () { addFromText(ta.value, this); };
    });
  }

  async function addFromText(text, btn, fileName) {
    let r;
    try { r = L.detect(text, { name: fileName }); } catch (e) { toast(e.message, true); return; }
    if (r.kind === 'url') {
      if (btn) { btn.disabled = true; btn.textContent = 'Загрузка…'; }
      try { await addSubscription(r.url); closeSheet(); } catch (e) { toast(e.message, true); }
      if (btn) { btn.disabled = false; btn.textContent = 'Добавить'; }
      return;
    }
    if (r.kind === 'ovpn') { openOvpnAuth(r, fileName); return; }
    addNodes(r.nodes, r.errors);
    closeSheet();
  }

  function addNodes(nodes, errors) {
    const existing = {};
    S.state.nodes.forEach(function (n) { existing[n.id] = 1; });
    const fresh = withIds(nodes, 'm').filter(function (n) { return !existing[n.id]; });
    S.state.nodes = S.state.nodes.concat(fresh);
    if (fresh.length) S.state.selected = { id: fresh[0].id };
    save();
    let msg = fresh.length === 1 ? 'Сервер добавлен' : (fresh.length ? 'Добавлено серверов: ' + fresh.length : 'Такой сервер уже есть');
    if (errors && errors.length) msg += ' · не подошло: ' + errors.length;
    toast(msg, !fresh.length && errors && errors.length);
    go(S.view === 'home' ? 'home' : 'servers');
  }

  function openOvpnAuth(r, fileName) {
    const name = (fileName || '').replace(/\.ovpn$/i, '');
    sheet('<h2>OpenVPN</h2>' + (r.needAuth ? '<p>Сервер просит логин и пароль.</p>' : '') +
      '<label class="field"><span>Название</span><input id="ov-name" value="' + esc(name) + '" placeholder="Например, Работа"></label>' +
      (r.needAuth ? '<label class="field"><span>Логин</span><input id="ov-user" autocomplete="username"></label>' +
        '<label class="field"><span>Пароль</span><input id="ov-pass" type="password" autocomplete="current-password"></label>' : '') +
      '<div class="actions"><button class="btn grow1" data-close>Отмена</button><button class="btn primary grow1" id="ov-ok">Добавить</button></div>', function () {
      $('ov-ok').onclick = function () {
        try {
          const n = L.ovpnNode(r.text, r.needAuth ? $('ov-user').value.trim() : '', r.needAuth ? $('ov-pass').value : '', $('ov-name').value.trim());
          closeSheet();
          addNodes([L.nodeFromCompiled(n)]);
        } catch (e) { toast(e.message, true); }
      };
    });
  }

  function openProxyForm() {
    sheet('<h2>Прокси или VPN вручную</h2>' +
      '<label class="field"><span>Тип</span><select id="px-type">' +
      '<option value="socks">SOCKS5</option><option value="http">HTTP</option><option value="https">HTTPS</option>' +
      '<option value="ssh">SSH</option><option value="openconnect">OpenConnect (Cisco AnyConnect и др.)</option></select></label>' +
      '<label class="field hidden" id="px-flavor-f"><span>Сервер VPN</span><select id="px-flavor">' +
      '<option value="anyconnect">Cisco AnyConnect / ocserv</option><option value="fortinet">Fortinet</option>' +
      '<option value="gp">Palo Alto GlobalProtect</option><option value="pulse">Pulse / Ivanti</option><option value="f5">F5</option><option value="nc">Juniper</option></select></label>' +
      '<div class="fields2"><label class="field"><span>Адрес</span><input id="px-host" placeholder="1.2.3.4 или proxy.example.com" spellcheck="false"></label>' +
      '<label class="field"><span>Порт</span><input id="px-port" inputmode="numeric" placeholder="1080"></label></div>' +
      '<label class="field"><span>Логин (если нужен)</span><input id="px-user" autocomplete="off" spellcheck="false"></label>' +
      '<label class="field"><span>Пароль</span><input id="px-pass" type="password" autocomplete="off"></label>' +
      '<label class="field"><span>Название</span><input id="px-name" placeholder="Необязательно"></label>' +
      '<div class="actions"><button class="btn grow1" data-close>Отмена</button><button class="btn primary grow1" id="px-ok">Добавить</button></div>', function () {
      const PH = { socks: '1080', http: '8080', https: '443', ssh: '22', openconnect: '443' };
      $('px-type').onchange = function () {
        $('px-port').placeholder = PH[this.value];
        $('px-flavor-f').classList.toggle('hidden', this.value !== 'openconnect');
      };
      $('px-ok').onclick = function () {
        try {
          const type = $('px-type').value;
          const link = L.proxyLink({ type: type, host: $('px-host').value, port: $('px-port').value || (type === 'openconnect' ? '443' : ''),
            user: $('px-user').value.trim(), pass: $('px-pass').value, name: $('px-name').value.trim(), flavor: $('px-flavor').value });
          const r = L.detect(link);
          closeSheet();
          addNodes(r.nodes);
        } catch (e) { toast(e.message, true); }
      };
    });
  }

  // ───────── подписки ─────────

  async function fetchSub(url) {
    const r = await N.call('fetch_url', { url: url, timeout: 20000, headers: { 'User-Agent': SUB_UA, Accept: '*/*' } });
    if (r.status < 200 || r.status >= 300) throw new Error('Сервер подписки ответил ошибкой ' + r.status);
    const h = {};
    Object.keys(r.headers || {}).forEach(function (k) { h[k.toLowerCase()] = r.headers[k]; });
    const parsed = L.parseSubscription(r.body);
    return { nodes: parsed.nodes, errors: parsed.errors, info: L.parseUserInfo(h['subscription-userinfo']),
      title: L.parseTitle(h['profile-title']), interval: parseInt(h['profile-update-interval'], 10) || 0 };
  }

  async function addSubscription(url) {
    if (S.state.subs.some(function (s) { return s.url === url; })) throw new Error('Эта подписка уже добавлена');
    const r = await fetchSub(url);
    let host = url;
    try { host = new URL(url).hostname; } catch (e) { /* оставляем как есть */ }
    const id = uid();
    const sub = { id: id, name: r.title || host, autoName: r.title || host, url: url, updated: Date.now(), info: r.info, interval: r.interval, nodes: withIds(r.nodes, id + '-') };
    S.state.subs.push(sub);
    S.state.selected = sub.nodes.length > 1 ? { auto: id } : (sub.nodes[0] ? { id: sub.nodes[0].id } : S.state.selected);
    save();
    toast('Подписка добавлена: ' + sub.nodes.length + ' серв.' + (r.errors.length ? ' · не подошло: ' + r.errors.length : ''));
    go(S.view === 'home' ? 'home' : 'servers');
  }

  async function updateSub(sub, quiet) {
    S.updating = sub.id;
    if (S.view === 'servers') renderServers();
    try {
      const r = await fetchSub(sub.url);
      sub.nodes = withIds(r.nodes, sub.id + '-');
      sub.info = r.info || sub.info;
      sub.interval = r.interval || sub.interval;
      if (r.title && sub.name === sub.autoName) { sub.name = r.title; sub.autoName = r.title; }
      sub.updated = Date.now();
      save();
      if (!quiet) toast('Подписка обновлена: ' + sub.nodes.length + ' серв.');
    } catch (e) {
      if (!quiet) toast(e.message, true);
    }
    S.updating = null;
    if (S.view === 'servers') renderServers();
    renderCurrent();
  }

  function autoUpdateSubs() {
    S.state.subs.forEach(function (s, i) {
      const hours = s.interval > 0 ? s.interval : 12;
      if (Date.now() - (s.updated || 0) > hours * 3600 * 1000) setTimeout(function () { updateSub(s, true); }, 1500 + i * 1500);
    });
  }

  // ───────── проверка задержки ─────────

  async function testAll() {
    if (S.testing) return;
    const list = allNodes();
    if (!list.length) return;
    S.testing = true;
    const items = [];
    list.forEach(function (n) {
      try { items.push({ n: n, c: L.compile(n.src) }); S.delays[n.id] = 'wait'; } catch (e) { S.delays[n.id] = -2; }
    });
    renderServers();
    try {
      for (let i = 0; i < items.length; i += 50) {
        const chunk = items.slice(i, i + 50);
        const compiled = chunk.map(function (x) { return x.c; });
        const ports = await N.call('free_ports', { count: 1 + C.xrayCount(compiled) });
        const secret = C.randomToken(16);
        const b = C.build({ nodes: compiled, auto: true, mode: 'test', os: S.platform.os, ruDirect: false, rulesDir: null,
          ports: { clash: ports[0], xray: ports.slice(1) }, secret: secret, auth: { user: 'nl' + C.randomToken(4), pass: C.randomToken(16) } });
        await N.call('test_start', { singbox: JSON.stringify(b.singbox), xray: b.xray ? JSON.stringify(b.xray) : null, clashPort: ports[0] });
        const tags = Object.keys(b.tags);
        let k = 0;
        const worker = async function () {
          while (k < tags.length) {
            const tag = tags[k++];
            const node = chunk[b.tags[tag]].n;
            try {
              const r = await N.call('fetch_url', { timeout: 9000, headers: { Authorization: 'Bearer ' + secret },
                url: 'http://127.0.0.1:' + ports[0] + '/proxies/' + encodeURIComponent(tag) + '/delay?timeout=6000&url=' + encodeURIComponent(C.TEST_URL) });
              const j = JSON.parse(r.body || '{}');
              S.delays[node.id] = r.status === 200 && j.delay ? j.delay : -1;
            } catch (e) { S.delays[node.id] = -1; }
            if (S.view === 'servers') renderServers();
          }
        };
        await Promise.all([worker(), worker(), worker(), worker(), worker(), worker(), worker(), worker()]);
        await N.call('test_stop');
      }
    } catch (e) {
      toast(e.message, true);
      items.forEach(function (x) { if (S.delays[x.n.id] === 'wait') delete S.delays[x.n.id]; });
      N.call('test_stop').catch(function () {});
    }
    S.testing = false;
    if (S.view === 'servers') renderServers();
    renderCurrent();
  }

  // ───────── действия в списке ─────────

  function selectNode(id) {
    S.state.selected = { id: id };
    save(); renderServers(); renderCurrent();
    if (S.status.state === 'on') reconnectIfOn('Переключаемся на выбранный сервер');
  }

  function nodeMenu(id) {
    const n = findNode(id);
    if (!n) return;
    const manual = S.state.nodes.indexOf(n) >= 0;
    const items = [{ label: 'Скопировать ' + (typeof n.src === 'string' ? 'ссылку' : 'настройки'), run: function () { copy(srcText(n)); } }];
    if (manual) {
      items.push({ label: 'Переименовать', run: function () { prompt('Название сервера', n.name, function (v) { n.name = v; save(); renderServers(); renderCurrent(); }); } });
      items.push({ label: 'Удалить', danger: true, run: function () {
        confirmBox('Удалить «' + n.name + '»?', 'Удалить', function () {
          S.state.nodes = S.state.nodes.filter(function (x) { return x !== n; });
          if (S.state.selected && S.state.selected.id === n.id) S.state.selected = null;
          save(); renderServers(); renderCurrent();
        });
      } });
    }
    menu(items);
  }

  function subMenu(id) {
    const s = findSub(id);
    if (!s) return;
    menu([
      { label: 'Обновить', run: function () { updateSub(s); } },
      { label: 'Переименовать', run: function () { prompt('Название подписки', s.name, function (v) { s.name = v; save(); renderServers(); renderCurrent(); }); } },
      { label: 'Скопировать адрес подписки', run: function () { copy(s.url); } },
      { label: 'Удалить подписку', danger: true, run: function () {
        confirmBox('Удалить подписку «' + s.name + '»?', 'Удалить', function () {
          S.state.subs = S.state.subs.filter(function (x) { return x !== s; });
          const sel = S.state.selected || {};
          if (sel.auto === s.id || (sel.id && sel.id.indexOf(s.id + '-') === 0)) S.state.selected = null;
          save(); renderServers(); renderCurrent();
        });
      } }
    ]);
  }

  // ───────── события ─────────

  function bind() {
    $('power').onclick = toggle;
    document.addEventListener('click', function (e) {
      const t = e.target.closest('[data-go],[data-node],[data-auto],[data-menu-node],[data-menu-sub],[data-close],#empty-add');
      if (!t) return;
      if (t.dataset.close !== undefined) { closeSheet(); return; }
      if (t.id === 'empty-add') { openAdd(); return; }
      if (t.dataset.menuNode) { e.stopPropagation(); nodeMenu(t.dataset.menuNode); return; }
      if (t.dataset.menuSub) { e.stopPropagation(); subMenu(t.dataset.menuSub); return; }
      if (t.dataset.go) { go(t.dataset.go); return; }
      if (t.dataset.node) { selectNode(t.dataset.node); return; }
      if (t.dataset.auto) {
        S.state.selected = { auto: t.dataset.auto };
        save(); renderServers(); renderCurrent();
        if (S.status.state === 'on') reconnectIfOn('Переключаемся на выбранный сервер');
      }
    });
    $('modal').addEventListener('click', function (e) { if (e.target === $('modal')) closeSheet(); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') { if (!$('modal').classList.contains('hidden')) closeSheet(); else if (S.view !== 'home') go('home'); }
    });
    $('btn-add').onclick = function () { openAdd(); };
    $('btn-test').onclick = testAll;
    $('file').onchange = function () {
      const f = this.files && this.files[0];
      this.value = '';
      if (!f) return;
      if (f.size > 2 * 1024 * 1024) { toast('Файл слишком большой', true); return; }
      const rd = new FileReader();
      rd.onload = function () { addFromText(String(rd.result), null, f.name.replace(/\.(conf|ovpn|json|txt)$/i, '')); };
      rd.readAsText(f);
    };
    document.querySelectorAll('input[name=mode]').forEach(function (r) {
      r.onchange = function () { if (r.checked) setMode(r.value); };
    });
    $('opt-ru').onchange = function () { S.state.settings.ruDirect = this.checked; save(); reconnectIfOn('Переподключаемся с новой настройкой'); };
    $('opt-autoconnect').onchange = function () { S.state.settings.autoConnect = this.checked; save(); };
    $('opt-autostart').onchange = async function () {
      const v = this.checked;
      try { await N.call('set_autostart', { enabled: v }); S.state.settings.autostart = v; save(); }
      catch (e) { this.checked = !v; toast(e.message, true); }
    };
    $('btn-log').onclick = async function () {
      let text = '';
      try { text = await N.call('log_tail'); } catch (e) { text = e.message; }
      sheet('<h2>Журнал подключения</h2><pre class="log">' + esc(text || 'Журнал пуст') + '</pre>' +
        '<div class="actions"><button class="btn" id="log-copy">Скопировать</button><button class="btn primary grow1" data-close>Закрыть</button></div>', function () {
        $('log-copy').onclick = function () { copy(text); };
      });
    };
    $('btn-site').onclick = function () { N.call('open_url', { url: SITE }).catch(function () { window.open(SITE, '_blank'); }); };
    $('btn-quit').onclick = function () { N.call('quit'); };
    document.addEventListener('visibilitychange', function () { if (!document.hidden) poll(); });
    // вставка ссылки прямо в окно (Ctrl+V на главном экране)
    document.addEventListener('paste', function (e) {
      if (!$('modal').classList.contains('hidden')) return;
      const t = (e.clipboardData || window.clipboardData).getData('text');
      if (t && t.trim()) { e.preventDefault(); openAdd(t.trim()); }
    });
  }

  function setMode(m) {
    if (S.state.settings.mode === m) return;
    S.state.settings.mode = m;
    save(); renderCurrent(); renderSettings();
    reconnectIfOn(m === 'proxy' ? 'Переподключаемся в режиме «Системный прокси»' : 'Переподключаемся в режиме VPN');
  }

  // ───────── запуск ─────────

  async function start() {
    bind();
    try { S.platform = await N.call('platform'); } catch (e) { S.platform = { os: 'linux' }; }
    document.body.classList.add(S.platform.os === 'android' ? 'android' : 'desktop', 'os-' + S.platform.os);
    let saved = null;
    try { const raw = await N.call('load_state'); saved = raw ? JSON.parse(raw) : null; } catch (e) { saved = null; }
    S.state = Object.assign({}, DEFAULT, saved || {});
    S.state.settings = Object.assign({}, DEFAULT.settings, (saved && saved.settings) || {});
    if (S.platform.os === 'android') S.state.settings.mode = 'tun';
    if (typeof S.platform.autostart === 'boolean') S.state.settings.autostart = S.platform.autostart;
    go('home');
    await poll();
    pushReady();
    autoUpdateSubs();
    // на Android «подключаться при запуске» делает интерфейс; на компьютере — сама программа
    if (S.platform.os === 'android' && S.state.settings.autoConnect && S.status.state === 'off' && selection()) toggle();
    // ссылка, переданная при запуске (netline://… или открытие файла)
    if (S.platform.pending) openAdd(S.platform.pending);
  }

  window.NetLineApp = { addFromText: function (t) { if (S.state) openAdd(t); } };
  // кнопка «Назад» на Android
  window.NetLineBack = function () {
    if (!$('modal').classList.contains('hidden')) { closeSheet(); return true; }
    if (S.view !== 'home') { go('home'); return true; }
    return false;
  };
  start();
})();
