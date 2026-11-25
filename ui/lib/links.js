/*
 * NetLine VPN — разбор того, что вставил пользователь.
 *
 * Понимает:
 *   ссылки  vless:// vmess:// trojan:// ss:// socks:// socks5:// http:// https://
 *           hysteria2:// hy2:// hysteria:// tuic:// anytls:// ssh:// wireguard:// wg://
 *           naive+https:// naive+quic:// openconnect://
 *   подписки (адрес http(s), список ссылок или base64 со списком ссылок, JSON Xray и sing-box)
 *   файлы   WireGuard (.conf) и OpenVPN (.ovpn)
 *
 * Сервер хранится как { id, name, proto, host, port, src }, где src — исходная ссылка
 * или готовый фрагмент конфигурации ({ xray } / { sb } / { sbEndpoint }).
 * compile(src) превращает его в описание, из которого config.js собирает конфигурацию ядер.
 */
(function (root) {
  'use strict';

  // ───────── мелкие помощники ─────────

  function fail(msg) { throw new Error(msg); }

  function b64decode(s) {
    s = String(s).trim().replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    const bin = atob(s);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return new TextDecoder('utf-8').decode(bytes);
  }

  function b64encode(s) {
    const bytes = new TextEncoder().encode(s);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin);
  }

  function safeDecode(s) {
    try { return decodeURIComponent(String(s).replace(/\+/g, '%2B')); } catch (e) { return s; }
  }

  // удалить пустые поля (undefined, null, '', пустые массивы)
  function clean(o) {
    Object.keys(o).forEach(function (k) {
      const v = o[k];
      if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length)) delete o[k];
    });
    return o;
  }

  function splitList(v) {
    if (!v) return undefined;
    const a = String(v).split(',').map(function (s) { return s.trim(); }).filter(Boolean);
    return a.length ? a : undefined;
  }

  function isTrue(v) { return v === '1' || v === 'true' || v === 'yes' || v === true; }

  function toInt(v) { const n = parseInt(v, 10); return isNaN(n) ? undefined : n; }

  /** scheme://userinfo@host:port/path?query#name */
  function parseURL(link) {
    const m = /^([a-z0-9+.\-]+):\/\/([^#]*)(?:#(.*))?$/i.exec(String(link).trim());
    if (!m) fail('Не похоже на ссылку');
    const scheme = m[1].toLowerCase();
    let rest = m[2];
    const name = m[3] ? safeDecode(m[3]).trim() : '';
    let query = '';
    const qi = rest.indexOf('?');
    if (qi >= 0) { query = rest.slice(qi + 1); rest = rest.slice(0, qi); }
    let path = '';
    const si = rest.indexOf('/');
    if (si >= 0) { path = rest.slice(si); rest = rest.slice(0, si); }
    let user = null;
    const at = rest.lastIndexOf('@');
    if (at >= 0) { user = rest.slice(0, at); rest = rest.slice(at + 1); }
    let host = rest, portStr = '';
    if (rest.charAt(0) === '[') {
      const e = rest.indexOf(']');
      host = rest.slice(1, e);
      portStr = rest.slice(e + 2);
    } else {
      const c = rest.lastIndexOf(':');
      if (c >= 0) { host = rest.slice(0, c); portStr = rest.slice(c + 1); }
    }
    const params = {};
    query.split('&').forEach(function (kv) {
      if (!kv) return;
      const e = kv.indexOf('=');
      const k = safeDecode(e >= 0 ? kv.slice(0, e) : kv);
      params[k] = e >= 0 ? safeDecode(kv.slice(e + 1)) : '';
    });
    // диапазон портов (hysteria2): 443,20000-30000
    let ports;
    if (/[,\-]/.test(portStr)) {
      ports = portStr.split(',').map(function (p) { return p.trim().replace('-', ':'); }).filter(Boolean);
      portStr = portStr.split(/[,\-]/)[0];
    }
    return {
      scheme: scheme, user: user, host: safeDecode(host), port: toInt(portStr) || 0, ports: ports,
      path: safeDecode(path), params: params, name: name
    };
  }

  function needHostPort(u) {
    if (!u.host) fail('В ссылке нет адреса сервера');
    if (!u.port || u.port < 1 || u.port > 65535) fail('В ссылке нет порта или он неверный');
  }

  function userPass(user) {
    if (user === null || user === undefined) return null;
    let ui = safeDecode(user);
    if (ui.indexOf(':') < 0) {
      try { const d = b64decode(ui); if (d.indexOf(':') > 0 && /^[\x20-\x7e]+$/.test(d)) ui = d; } catch (e) { /* не base64 */ }
    }
    const c = ui.indexOf(':');
    return c < 0 ? { user: ui, pass: '' } : { user: ui.slice(0, c), pass: ui.slice(c + 1) };
  }

  const TITLES = {
    vless: 'VLESS', vmess: 'VMess', trojan: 'Trojan', shadowsocks: 'Shadowsocks',
    socks: 'SOCKS5', http: 'HTTP', https: 'HTTPS', hysteria2: 'Hysteria2', hysteria: 'Hysteria',
    tuic: 'TUIC', anytls: 'AnyTLS', ssh: 'SSH', wireguard: 'WireGuard', naive: 'Naive',
    openvpn: 'OpenVPN', openconnect: 'OpenConnect', shadowtls: 'ShadowTLS', shadowsocksr: 'ShadowsocksR'
  };

  // ───────── VLESS / VMess / Trojan / Shadowsocks / SOCKS / HTTP → общее описание ─────────
  //
  // spec = { proto, server, port, uuid, flow, encryption, cipher, password, method, plugin, pluginOpts,
  //          username, net, headerType, path, host, serviceName, mode, authority, extra, seed,
  //          tls: null | { type: 'tls'|'reality', sni, fp, alpn, insecure, pbk, sid, spx, pqv, ech, pcs, vcn } }

  const NETWORKS = {
    tcp: 'tcp', raw: 'tcp', '': 'tcp', ws: 'ws', websocket: 'ws', grpc: 'grpc', gun: 'grpc',
    xhttp: 'xhttp', splithttp: 'xhttp', httpupgrade: 'httpupgrade', kcp: 'kcp', mkcp: 'kcp',
    h2: 'h2', http: 'h2', quic: 'quic'
  };

  function streamFrom(p, defaultSecurity) {
    const rawNet = String(p.type || p.net || 'tcp').toLowerCase();
    const net = NETWORKS[rawNet];
    if (!net) fail('Транспорт «' + rawNet + '» не поддерживается');
    const s = {
      net: net,
      headerType: (p.headerType || '').toLowerCase() || undefined,
      path: p.path || undefined,
      host: p.host || undefined,
      serviceName: p.serviceName || undefined,
      mode: p.mode || undefined,
      authority: p.authority || undefined,
      seed: p.seed || undefined,
      tls: null
    };
    if (p.extra) { try { s.extra = typeof p.extra === 'string' ? JSON.parse(p.extra) : p.extra; } catch (e) { /* битый extra пропускаем */ } }
    const security = String(p.security || defaultSecurity || 'none').toLowerCase();
    if (security === 'tls' || security === 'xtls') {
      s.tls = {
        type: 'tls', sni: p.sni || p.peer || undefined, fp: p.fp || undefined, alpn: splitList(p.alpn),
        insecure: isTrue(p.allowInsecure) || isTrue(p.insecure) || isTrue(p.allow_insecure),
        ech: p.ech || undefined, pcs: p.pcs || undefined, vcn: p.vcn || undefined
      };
    } else if (security === 'reality') {
      if (!p.pbk) fail('Для Reality в ссылке нужен параметр pbk (публичный ключ)');
      s.tls = { type: 'reality', sni: p.sni || undefined, fp: p.fp || undefined, pbk: p.pbk, sid: p.sid || '',
        spx: p.spx || undefined, pqv: p.pqv || undefined };
    } else if (security !== 'none' && security !== '') {
      fail('Шифрование «' + security + '» не поддерживается');
    }
    return s;
  }

  function specVless(u) {
    needHostPort(u);
    const id = safeDecode(u.user || '');
    if (!/^[0-9a-z-]{8,}$/i.test(id)) fail('В ссылке VLESS нет UUID пользователя');
    const s = streamFrom(u.params, 'none');
    return Object.assign(s, { proto: 'vless', server: u.host, port: u.port, uuid: id,
      flow: u.params.flow || undefined, encryption: u.params.encryption || 'none' });
  }

  function specTrojan(u) {
    needHostPort(u);
    const password = safeDecode(u.user || '');
    if (!password) fail('В ссылке Trojan нет пароля');
    const s = streamFrom(u.params, 'tls');
    return Object.assign(s, { proto: 'trojan', server: u.host, port: u.port, password: password });
  }

  function specVmess(link) {
    const body = link.slice(link.indexOf('://') + 3).split('#')[0];
    let j = null;
    try { j = JSON.parse(b64decode(body)); } catch (e) { j = null; }
    if (!j) {
      // редкий формат vmess://uuid@host:port?...
      const u = parseURL(link);
      needHostPort(u);
      const s = streamFrom(u.params, 'none');
      return { name: u.name, spec: Object.assign(s, { proto: 'vmess', server: u.host, port: u.port,
        uuid: safeDecode(u.user || ''), cipher: u.params.encryption || 'auto' }) };
    }
    const port = toInt(j.port);
    if (!j.add || !port) fail('В ссылке VMess нет адреса или порта');
    if (!j.id) fail('В ссылке VMess нет UUID');
    const net = String(j.net || 'tcp').toLowerCase();
    const p = {
      type: net, headerType: j.type, host: j.host, path: j.path,
      security: j.tls || 'none', sni: j.sni, alpn: j.alpn, fp: j.fp, allowInsecure: j.allowInsecure || j.insecure
    };
    if (net === 'grpc') { p.serviceName = j.path; p.path = undefined; p.mode = j.type === 'multi' ? 'multi' : undefined; p.headerType = undefined; }
    if (net === 'xhttp' || net === 'splithttp') { p.mode = j.type || j.mode; p.headerType = undefined; }
    const s = streamFrom(p, 'none');
    return { name: j.ps || '', spec: Object.assign(s, { proto: 'vmess', server: j.add, port: port, uuid: j.id,
      cipher: j.scy || 'auto' }) };
  }

  function specShadowsocks(link) {
    let rest = link.slice(link.indexOf('://') + 3);
    let name = '';
    const hi = rest.indexOf('#');
    if (hi >= 0) { name = safeDecode(rest.slice(hi + 1)).trim(); rest = rest.slice(0, hi); }
    let method, password, host, port, params = {};
    if (rest.indexOf('@') >= 0) {
      const u = parseURL('ss://' + rest);
      params = u.params;
      let ui = safeDecode(u.user || '');
      if (ui.indexOf(':') < 0) { try { ui = b64decode(ui); } catch (e) { fail('Не удалось разобрать логин Shadowsocks'); } }
      const c = ui.indexOf(':');
      method = ui.slice(0, c); password = ui.slice(c + 1);
      host = u.host; port = u.port;
    } else {
      // старый формат: ss://base64(method:password@host:port)
      let dec;
      const qi = rest.indexOf('?');
      try { dec = b64decode(qi >= 0 ? rest.slice(0, qi) : rest); } catch (e) { fail('Не удалось разобрать ссылку Shadowsocks'); }
      const at = dec.lastIndexOf('@');
      const cred = dec.slice(0, at), hp = dec.slice(at + 1);
      const c = cred.indexOf(':');
      method = cred.slice(0, c); password = cred.slice(c + 1);
      const pc = hp.lastIndexOf(':');
      host = hp.slice(0, pc).replace(/^\[|\]$/g, ''); port = toInt(hp.slice(pc + 1));
    }
    if (!method || !password) fail('В ссылке Shadowsocks нет метода или пароля');
    needHostPort({ host: host, port: port });
    const spec = { proto: 'shadowsocks', server: host, port: port, method: method.toLowerCase(), password: password, net: 'tcp', tls: null,
      uot: isTrue(params.uot) || isTrue(params['udp-over-tcp']) };
    if (params.plugin) {
      // SIP002: plugin=obfs-local;obfs=http;obfs-host=example.com
      const parts = params.plugin.split(';');
      let plugin = parts.shift();
      if (plugin === 'simple-obfs' || plugin === 'obfs') plugin = 'obfs-local';
      if (plugin !== 'obfs-local' && plugin !== 'v2ray-plugin') fail('Плагин Shadowsocks «' + plugin + '» не поддерживается');
      spec.plugin = plugin;
      spec.pluginOpts = parts.join(';');
    }
    return { name: name, spec: spec };
  }

  function specSocks(u) {
    needHostPort(u);
    const up = userPass(u.user);
    return { proto: 'socks', server: u.host, port: u.port, username: up ? up.user : undefined,
      password: up ? up.pass : undefined, net: 'tcp', tls: null };
  }

  function specHttp(u) {
    needHostPort(u);
    const up = userPass(u.user);
    return { proto: 'http', server: u.host, port: u.port, username: up ? up.user : undefined,
      password: up ? up.pass : undefined, net: 'tcp',
      tls: u.scheme === 'https' ? { type: 'tls', sni: u.params.sni || u.host, insecure: isTrue(u.params.insecure) } : null };
  }

  // ───────── протоколы, которые умеет только sing-box ─────────

  function sbTls(p, defaultAlpn, host) {
    return clean({
      enabled: true,
      server_name: p.sni || p.peer || host || undefined,
      insecure: (isTrue(p.insecure) || isTrue(p.allowInsecure) || isTrue(p.allow_insecure) || isTrue(p.skip_cert_verify)) ? true : undefined,
      alpn: splitList(p.alpn) || defaultAlpn
    });
  }

  function sbHysteria2(u) {
    needHostPort(u);
    const password = safeDecode(u.user || '') || u.params.auth || u.params.password;
    if (!password) fail('В ссылке Hysteria2 нет пароля');
    const p = u.params;
    const out = { type: 'hysteria2', server: u.host, server_port: u.port, password: password, tls: sbTls(p, ['h3'], u.host) };
    const ports = u.ports || (p.mport ? p.mport.split(',').map(function (x) { return x.trim().replace('-', ':'); }) : undefined);
    if (ports) {
      out.server_ports = ports.map(function (x) { return x.indexOf(':') > 0 ? x : x + ':' + x; });
      delete out.server_port;
    }
    if (p.obfs && p.obfs !== 'none') out.obfs = clean({ type: p.obfs, password: p['obfs-password'] || p.obfs_password || p.obfsParam });
    out.up_mbps = toInt(p.upmbps || p.up);
    out.down_mbps = toInt(p.downmbps || p.down);
    return clean(out);
  }

  function sbHysteria(u) {
    needHostPort(u);
    const p = u.params;
    return clean({
      type: 'hysteria', server: u.host, server_port: u.port,
      auth_str: p.auth || safeDecode(u.user || '') || undefined,
      obfs: p.obfsParam || p.obfs_param || (p.obfs && p.obfs !== 'xplus' ? p.obfs : undefined),
      up_mbps: toInt(p.upmbps || p.up) || 50,
      down_mbps: toInt(p.downmbps || p.down) || 100,
      tls: sbTls(p, ['hysteria'], u.host)
    });
  }

  function sbTuic(u) {
    needHostPort(u);
    const ui = safeDecode(u.user || '');
    const c = ui.indexOf(':');
    const uuid = c >= 0 ? ui.slice(0, c) : ui;
    const password = c >= 0 ? ui.slice(c + 1) : (u.params.password || '');
    if (!uuid) fail('В ссылке TUIC нет UUID');
    const p = u.params;
    const cc = p.congestion_control || p.congestion;
    return clean({
      type: 'tuic', server: u.host, server_port: u.port, uuid: uuid, password: password,
      congestion_control: ['cubic', 'new_reno', 'bbr'].indexOf(cc) >= 0 ? cc : 'bbr',
      udp_relay_mode: ['native', 'quic'].indexOf(p.udp_relay_mode) >= 0 ? p.udp_relay_mode : undefined,
      zero_rtt_handshake: isTrue(p.reduce_rtt) || isTrue(p.zero_rtt) ? true : undefined,
      tls: sbTls(p, ['h3'], u.host)
    });
  }

  function sbAnyTls(u) {
    needHostPort(u);
    const password = safeDecode(u.user || '');
    if (!password) fail('В ссылке AnyTLS нет пароля');
    return { type: 'anytls', server: u.host, server_port: u.port, password: password, tls: sbTls(u.params, undefined, u.host) };
  }

  function sbSsh(u) {
    needHostPort(u);
    const up = userPass(u.user);
    if (!up || !up.user) fail('В ссылке SSH нет пользователя');
    const p = u.params;
    return clean({ type: 'ssh', server: u.host, server_port: u.port, user: up.user, password: up.pass || undefined,
      private_key: p.pk || p.private_key || undefined, host_key: splitList(p.hk || p.host_key) });
  }

  function sbNaive(u) {
    needHostPort(u);
    const up = userPass(u.user);
    return clean({ type: 'naive', server: u.host, server_port: u.port,
      username: up ? up.user : undefined, password: up ? up.pass : undefined,
      quic: u.scheme === 'naive+quic' ? true : undefined,
      tls: sbTls(u.params, undefined, u.host) });
  }

  function sbOpenConnect(u) {
    if (!u.host) fail('В ссылке нет адреса сервера');
    const up = userPass(u.user);
    const flavor = u.params.flavor || 'anyconnect';
    if (['anyconnect', 'gp', 'fortinet', 'f5', 'pulse', 'nc'].indexOf(flavor) < 0) fail('Неизвестный вид OpenConnect: ' + flavor);
    return clean({ type: 'openconnect', server: u.host + (u.port && u.port !== 443 ? ':' + u.port : '') + (u.path && u.path !== '/' ? u.path : ''),
      flavor: flavor, username: up ? up.user : undefined, password: up ? up.pass : undefined,
      auth_group: u.params.group || undefined });
  }

  function wgAddress(list) {
    return list.map(function (a) { return a.indexOf('/') > 0 ? a : (a.indexOf(':') >= 0 ? a + '/128' : a + '/32'); });
  }

  function sbWireGuard(u) {
    needHostPort(u);
    const p = u.params;
    const privateKey = safeDecode(u.user || '') || p.privatekey || p.secretkey || p.private_key;
    const publicKey = p.publickey || p.public_key || p.peer_public_key || p.publicKey;
    if (!privateKey) fail('В ссылке WireGuard нет приватного ключа');
    if (!publicKey) fail('В ссылке WireGuard нет публичного ключа сервера (publickey)');
    if (p.jc || p.jmin || p.h1 || p.s1) fail('AmneziaWG пока не поддерживается — нужен обычный WireGuard');
    const peer = clean({
      address: u.host, port: u.port, public_key: publicKey,
      pre_shared_key: p.presharedkey || p.preshared_key || p.psk || undefined,
      allowed_ips: ['0.0.0.0/0', '::/0'],
      reserved: p.reserved ? p.reserved.split(',').map(function (x) { return toInt(x) || 0; }) : undefined,
      persistent_keepalive_interval: toInt(p.keepalive)
    });
    return clean({
      type: 'wireguard',
      address: wgAddress(splitList(p.address || p.ip || p.addresses) || ['10.0.0.2/32']),
      private_key: privateKey,
      mtu: toInt(p.mtu) || 1408,
      peers: [peer]
    });
  }

  // ───────── разбор одной ссылки ─────────

  /**
   * @returns {{proto, name, host, port, spec?, sb?, sbEndpoint?, xray?}}
   */
  function parseLink(link) {
    link = String(link || '').trim();
    const sm = /^([a-z0-9+.\-]+):\/\//i.exec(link);
    if (!sm) fail('Ссылка должна начинаться с vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, wireguard:// и т. п.');
    const scheme = sm[1].toLowerCase();
    let r;
    if (scheme === 'vless' || scheme === 'trojan') {
      const u = parseURL(link);
      r = { spec: scheme === 'vless' ? specVless(u) : specTrojan(u), name: u.name };
    } else if (scheme === 'vmess') {
      r = specVmess(link);
    } else if (scheme === 'ss') {
      r = specShadowsocks(link);
    } else if (scheme === 'socks' || scheme === 'socks5' || scheme === 'socks5h') {
      const u = parseURL(link); r = { spec: specSocks(u), name: u.name };
    } else if (scheme === 'http' || scheme === 'https') {
      const u = parseURL(link); r = { spec: specHttp(u), name: u.name };
    } else if (scheme === 'hysteria2' || scheme === 'hy2') {
      const u = parseURL(link); r = { sb: sbHysteria2(u), name: u.name };
    } else if (scheme === 'hysteria' || scheme === 'hy') {
      const u = parseURL(link); r = { sb: sbHysteria(u), name: u.name };
    } else if (scheme === 'tuic') {
      const u = parseURL(link); r = { sb: sbTuic(u), name: u.name };
    } else if (scheme === 'anytls') {
      const u = parseURL(link); r = { sb: sbAnyTls(u), name: u.name };
    } else if (scheme === 'ssh') {
      const u = parseURL(link); r = { sb: sbSsh(u), name: u.name };
    } else if (scheme === 'naive+https' || scheme === 'naive+quic' || scheme === 'naive') {
      const u = parseURL(link); r = { sb: sbNaive(u), name: u.name };
    } else if (scheme === 'openconnect' || scheme === 'anyconnect') {
      const u = parseURL(link); r = { sbEndpoint: sbOpenConnect(u), name: u.name };
    } else if (scheme === 'wireguard' || scheme === 'wg') {
      const u = parseURL(link); r = { sbEndpoint: sbWireGuard(u), name: u.name };
    } else if (scheme === 'ssr') {
      fail('ShadowsocksR устарел и не поддерживается');
    } else {
      fail('Неизвестный протокол: ' + scheme);
    }
    return finish(r);
  }

  function finish(r) {
    let proto, host, port;
    if (r.spec) { proto = r.spec.proto === 'http' && r.spec.tls ? 'https' : r.spec.proto; host = r.spec.server; port = r.spec.port; }
    else if (r.sb) { proto = r.sb.type; host = r.sb.server; port = r.sb.server_port || toInt(String((r.sb.server_ports || [''])[0]).split(':')[0]); }
    else if (r.sbEndpoint) {
      proto = r.sbEndpoint.type === 'openvpn-client' ? 'openvpn' : r.sbEndpoint.type;
      const peer = (r.sbEndpoint.peers || r.sbEndpoint.servers || [])[0] || {};
      host = peer.address || peer.server || r.sbEndpoint.server || '';
      port = peer.port || peer.server_port || 0;
      if (proto === 'openconnect') { const m = /^([^:/]+)(?::(\d+))?/.exec(host); host = m ? m[1] : host; port = m && m[2] ? +m[2] : 443; }
    }
    else if (r.xray) { proto = r.xray.proto; host = r.xray.host; port = r.xray.port; }
    const title = TITLES[proto] || proto;
    return Object.assign(r, {
      proto: proto, title: title, host: host || '', port: port || 0,
      name: (r.name || '').trim() || (title + ' ' + (host || '') + (port ? ':' + port : ''))
    });
  }

  // ───────── WireGuard .conf ─────────

  function iniSections(text) {
    const out = [];
    let cur = null;
    String(text).split(/\r?\n/).forEach(function (line) {
      line = line.replace(/[#;].*$/, '').trim();
      if (!line) return;
      const sm = /^\[(.+)\]$/.exec(line);
      if (sm) { cur = { name: sm[1].trim().toLowerCase(), kv: {} }; out.push(cur); return; }
      const e = line.indexOf('=');
      if (cur && e > 0) cur.kv[line.slice(0, e).trim().toLowerCase()] = line.slice(e + 1).trim();
    });
    return out;
  }

  function isWireGuardConf(text) { return /^\s*\[Interface\]/im.test(text) && /^\s*\[Peer\]/im.test(text); }

  function wireGuardConfToLink(text, name) {
    const secs = iniSections(text);
    const itf = (secs.filter(function (s) { return s.name === 'interface'; })[0] || {}).kv;
    const peer = (secs.filter(function (s) { return s.name === 'peer'; })[0] || {}).kv;
    if (!itf || !peer) fail('В файле WireGuard нет разделов [Interface] и [Peer]');
    if (itf.jc || itf.jmin || itf.s1 || itf.h1) fail('Это конфигурация AmneziaWG — она пока не поддерживается, нужен обычный WireGuard');
    if (!itf.privatekey) fail('В файле WireGuard нет PrivateKey');
    if (!peer.publickey) fail('В файле WireGuard нет PublicKey сервера');
    if (!peer.endpoint) fail('В файле WireGuard нет Endpoint сервера');
    const ep = peer.endpoint;
    const c = ep.lastIndexOf(':');
    const host = ep.slice(0, c).replace(/^\[|\]$/g, ''), port = ep.slice(c + 1);
    const q = ['publickey=' + encodeURIComponent(peer.publickey)];
    if (itf.address) q.push('address=' + encodeURIComponent(itf.address.replace(/\s+/g, '')));
    if (peer.presharedkey) q.push('presharedkey=' + encodeURIComponent(peer.presharedkey));
    if (itf.mtu) q.push('mtu=' + encodeURIComponent(itf.mtu));
    if (peer.persistentkeepalive) q.push('keepalive=' + encodeURIComponent(peer.persistentkeepalive));
    const h = host.indexOf(':') >= 0 ? '[' + host + ']' : host;
    return 'wireguard://' + encodeURIComponent(itf.privatekey) + '@' + h + ':' + port + '?' + q.join('&') +
      '#' + encodeURIComponent(name || ('WireGuard ' + host));
  }

  // ───────── OpenVPN .ovpn ─────────

  function isOvpn(text) {
    return /^\s*remote\s+\S+/m.test(text) && (/^\s*client\s*$/m.test(text) || /^\s*dev\s+tun/m.test(text) || /<ca>/.test(text));
  }

  function ovpnNeedsAuth(text) {
    return /^\s*auth-user-pass\b/m.test(text) && !/<auth-user-pass>/.test(text);
  }

  function ovpnToEndpoint(text, user, pass) {
    const blocks = {};
    text = String(text).replace(/<([a-z0-9-]+)>([\s\S]*?)<\/\1>/gi, function (_, tag, body) {
      blocks[tag.toLowerCase()] = body.trim();
      return '';
    });
    const servers = [];
    let proto = 'udp', port = 1194;
    const opt = {};
    text.split(/\r?\n/).forEach(function (line) {
      line = line.replace(/^\s*[#;].*$/, '').trim();
      if (!line) return;
      const parts = line.split(/\s+/);
      const k = parts[0].toLowerCase();
      if (k === 'remote') servers.push({ host: parts[1], port: toInt(parts[2]), proto: parts[3] });
      else if (k === 'proto') proto = parts[1];
      else if (k === 'port') port = toInt(parts[1]) || port;
      else opt[k] = parts.slice(1);
    });
    if (!servers.length) fail('В файле OpenVPN нет строки remote');
    const net = function (p) {
      p = String(p || proto).toLowerCase().replace('-client', '');
      return ['udp', 'udp4', 'udp6', 'tcp', 'tcp4', 'tcp6'].indexOf(p) >= 0 ? p : 'udp';
    };
    if (blocks['auth-user-pass']) {
      const l = blocks['auth-user-pass'].split(/\r?\n/);
      user = user || l[0]; pass = pass || l[1];
    }
    if (/^\s*auth-user-pass\b/m.test(text) && !user) fail('Для этого сервера OpenVPN нужны логин и пароль');
    const tls = clean({
      certificate: blocks.ca ? [blocks.ca] : undefined,
      client_certificate: blocks.cert ? [blocks.cert] : undefined,
      client_key: blocks.key ? [blocks.key] : undefined,
      remote_certificate_tls: opt['remote-cert-tls'] ? opt['remote-cert-tls'][0] : undefined,
      version_min: opt['tls-version-min'] ? opt['tls-version-min'][0] : undefined,
      server_name: opt['verify-x509-name'] ? opt['verify-x509-name'][0].replace(/^'|'$/g, '') : undefined,
      server_name_type: opt['verify-x509-name'] && opt['verify-x509-name'][1] ? opt['verify-x509-name'][1] : undefined
    });
    if (tls.server_name_type && ['subject', 'name', 'name-prefix'].indexOf(tls.server_name_type) < 0) delete tls.server_name_type;
    const kd = opt['key-direction'] ? opt['key-direction'][0] : undefined;
    if (blocks['tls-crypt-v2']) tls.control_wrap = { type: 'tls_crypt_v2', key: [blocks['tls-crypt-v2']] };
    else if (blocks['tls-crypt']) tls.control_wrap = { type: 'tls_crypt', key: [blocks['tls-crypt']] };
    else if (blocks['tls-auth']) tls.control_wrap = clean({ type: 'tls_auth', key: [blocks['tls-auth']], direction: kd === '1' ? 'client' : (kd === '0' ? 'server' : undefined) });
    if (!tls.certificate) fail('В файле OpenVPN нет сертификата <ca> — нужен файл со встроенными сертификатами');
    const ep = clean({
      type: 'openvpn-client',
      servers: servers.map(function (s) { return clean({ server: s.host, server_port: s.port || port, network: net(s.proto) }); }),
      username: user || undefined,
      password: pass || undefined,
      cipher: opt.cipher ? opt.cipher[0] : undefined,
      data_ciphers: opt['data-ciphers'] ? opt['data-ciphers'][0].split(':') : undefined,
      auth: opt.auth ? opt.auth[0] : undefined,
      tls: tls
    });
    if (opt['comp-lzo']) ep.compression_lzo = opt['comp-lzo'][0] === 'no' ? 'no' : 'adaptive';
    if (opt.compress) ep.compression = ['lz4', 'lz4-v2', 'stub', 'stub-v2'].indexOf(opt.compress[0]) >= 0 ? opt.compress[0] : 'stub';
    return ep;
  }

  function ovpnNode(text, user, pass, name) {
    const ep = ovpnToEndpoint(text, user, pass);
    const s = ep.servers[0];
    return finish({ sbEndpoint: ep, name: name || ('OpenVPN ' + s.server) });
  }

  // ───────── подписки ─────────

  /** Адрес подписки: http(s) с путём или параметрами (http://host:port без пути — это прокси) */
  function isSubscriptionURL(s) {
    s = String(s || '').trim();
    if (/\s/.test(s)) return false;
    const m = /^https?:\/\/([^\/?#]+)([\/?][^#]*)?/i.exec(s);
    if (!m) return false;
    if (m[1].indexOf('@') >= 0) return false;
    const tail = m[2] || '';
    return tail !== '' && tail !== '/';
  }

  const SB_TYPES = ['vless', 'vmess', 'trojan', 'shadowsocks', 'socks', 'http', 'hysteria', 'hysteria2', 'tuic',
    'anytls', 'ssh', 'naive', 'shadowtls', 'shadowsocksr', 'tor'];
  const SB_ENDPOINTS = ['wireguard', 'openvpn-client', 'openconnect'];
  const XRAY_SKIP = ['freedom', 'blackhole', 'dns', 'loopback'];

  function fromJSON(j) {
    const nodes = [];
    // sing-box: { outbounds: [...], endpoints: [...] } или массив исходящих
    const looksSingbox = function (o) { return o && typeof o === 'object' && typeof o.type === 'string'; };
    const looksXray = function (o) { return o && typeof o === 'object' && typeof o.protocol === 'string'; };
    const configs = Array.isArray(j) ? j : [j];
    configs.forEach(function (cfg) {
      if (looksSingbox(cfg) && SB_TYPES.indexOf(cfg.type) >= 0) cfg = { outbounds: [cfg] };
      if (looksSingbox(cfg) && SB_ENDPOINTS.indexOf(cfg.type) >= 0) cfg = { endpoints: [cfg] };
      if (!cfg || typeof cfg !== 'object') return;
      const outs = Array.isArray(cfg.outbounds) ? cfg.outbounds : [];
      if (outs.some(looksXray)) {
        // Xray: один сервер на конфигурацию, остальные исходящие (фрагментация и т. п.) берём с собой
        const main = outs.filter(function (o) { return looksXray(o) && XRAY_SKIP.indexOf(o.protocol) < 0; })[0];
        if (!main) return;
        const tag = main.tag || 'proxy';
        const list = outs.filter(function (o) { return looksXray(o) && o.tag !== 'direct' && o.tag !== 'block'; })
          .map(function (o) { return o === main ? Object.assign({}, o, { tag: tag }) : o; });
        const addr = xrayAddress(main);
        nodes.push(finish({ xray: { proto: main.protocol === 'shadowsocks' ? 'shadowsocks' : main.protocol,
          host: addr.host, port: addr.port, main: tag, outbounds: list }, name: cfg.remarks || cfg.remark || cfg.ps || '' }));
        return;
      }
      outs.forEach(function (o) {
        if (!looksSingbox(o) || SB_TYPES.indexOf(o.type) < 0) return;
        const c = Object.assign({}, o); const name = c.tag; delete c.tag;
        if (c.detour) return;  // цепочки sing-box не переносим
        nodes.push(finish({ sb: c, name: name }));
      });
      (Array.isArray(cfg.endpoints) ? cfg.endpoints : []).forEach(function (o) {
        if (!looksSingbox(o) || SB_ENDPOINTS.indexOf(o.type) < 0) return;
        const c = Object.assign({}, o); const name = c.tag; delete c.tag;
        nodes.push(finish({ sbEndpoint: c, name: name }));
      });
    });
    return nodes;
  }

  function xrayAddress(o) {
    const s = o.settings || {};
    const v = (s.vnext || s.servers || [])[0] || s;
    return { host: v.address || '', port: toInt(v.port) || 0 };
  }

  /**
   * Разобрать вставленный текст.
   * @returns {{kind:'url', url}|{kind:'ovpn', text, needAuth}|{kind:'nodes', nodes:[{name, proto, host, port, src}], errors:[]}}
   */
  function detect(text, opts) {
    opts = opts || {};
    let t = String(text || '').replace(/^﻿/, '').trim();
    if (!t) fail('Вставьте ссылку, адрес подписки или содержимое файла');
    if (isSubscriptionURL(t)) return { kind: 'url', url: t };
    if (isOvpn(t)) return { kind: 'ovpn', text: t, needAuth: ovpnNeedsAuth(t) };
    if (isWireGuardConf(t)) {
      const link = wireGuardConfToLink(t, opts.name);
      return { kind: 'nodes', nodes: [nodeFrom(link)], errors: [] };
    }
    if (/^[\[{]/.test(t)) {
      let j;
      try { j = JSON.parse(t); } catch (e) { fail('Не удалось прочитать JSON: ' + e.message); }
      const ns = fromJSON(j);
      if (!ns.length) fail('В JSON не найдено ни одного сервера');
      return { kind: 'nodes', nodes: ns.map(nodeFromCompiled), errors: [] };
    }
    if (/^(proxies|proxy-groups|mixed-port|port):/m.test(t)) fail('Формат Clash (YAML) не поддерживается — попросите у поставщика обычную подписку или ссылки');
    if (!/^[a-z0-9+.\-]+:\/\//im.test(t)) {
      try { t = b64decode(t).trim(); } catch (e) { fail('Не удалось распознать текст: это не ссылка, не подписка и не файл WireGuard или OpenVPN'); }
      if (/^[\[{]/.test(t)) return detect(t, opts);
    }
    const lines = t.split(/\r?\n/).map(function (l) { return l.trim(); }).filter(function (l) { return /^[a-z0-9+.\-]+:\/\/\S/i.test(l); });
    if (!lines.length) fail('Не найдено ни одной ссылки');
    if (lines.length === 1 && isSubscriptionURL(lines[0])) return { kind: 'url', url: lines[0] };
    const nodes = [], errors = [];
    lines.forEach(function (l) {
      try { nodes.push(nodeFrom(l)); } catch (e) { errors.push({ link: l, error: e.message }); }
    });
    if (!nodes.length) fail(errors.length === 1 ? errors[0].error : 'Ни одна ссылка не подошла: ' + errors[0].error);
    return { kind: 'nodes', nodes: nodes, errors: errors };
  }

  function nodeFrom(link) {
    const c = parseLink(link);
    return { name: c.name, proto: c.proto, host: c.host, port: c.port, src: link };
  }

  function nodeFromCompiled(c) {
    const src = c.xray ? { xray: c.xray } : (c.sb ? { sb: c.sb } : { sbEndpoint: c.sbEndpoint });
    return { name: c.name, proto: c.proto, host: c.host, port: c.port, src: src };
  }

  /** Содержимое подписки → серверы */
  function parseSubscription(body) {
    const r = detect(body);
    if (r.kind === 'nodes') return r;
    if (r.kind === 'url') fail('Вместо подписки пришёл адрес');
    fail('Подписка в этом формате не поддерживается');
  }

  /** Заголовок subscription-userinfo → объём и срок */
  function parseUserInfo(h) {
    if (!h) return null;
    const o = {};
    String(h).split(';').forEach(function (kv) {
      const p = kv.split('=');
      if (p.length === 2) o[p[0].trim().toLowerCase()] = Number(p[1].trim()) || 0;
    });
    if (!('total' in o) && !('expire' in o) && !('download' in o)) return null;
    return { upload: o.upload || 0, download: o.download || 0, total: o.total || 0, expire: o.expire || 0 };
  }

  /** Заголовок profile-title (может быть base64:...) */
  function parseTitle(h) {
    if (!h) return '';
    h = String(h).trim();
    if (/^base64:/i.test(h)) { try { return b64decode(h.slice(7)).trim(); } catch (e) { return ''; } }
    return h;
  }

  /** Описание сервера для сборки конфигурации */
  function compile(src) {
    if (typeof src === 'string') return parseLink(src);
    if (src && src.xray) return finish({ xray: src.xray, name: '' });
    if (src && src.sb) return finish({ sb: src.sb, name: '' });
    if (src && src.sbEndpoint) return finish({ sbEndpoint: src.sbEndpoint, name: '' });
    fail('Повреждённая запись сервера');
  }

  /** Ссылка для ручного прокси */
  function proxyLink(f) {
    const type = f.type || 'socks';
    const host = String(f.host || '').trim();
    const port = toInt(f.port);
    if (!host) fail('Укажите адрес');
    if (type !== 'openconnect' && (!port || port < 1 || port > 65535)) fail('Укажите порт от 1 до 65535');
    const auth = f.user ? encodeURIComponent(f.user) + (f.pass ? ':' + encodeURIComponent(f.pass) : '') + '@' : '';
    const h = host.indexOf(':') >= 0 && host.charAt(0) !== '[' ? '[' + host + ']' : host;
    const name = '#' + encodeURIComponent(f.name || '');
    if (type === 'socks') return 'socks5://' + auth + h + ':' + port + name;
    if (type === 'http') return 'http://' + auth + h + ':' + port + name;
    if (type === 'https') return 'https://' + auth + h + ':' + port + name;
    if (type === 'ssh') { if (!f.user) fail('Для SSH нужен пользователь'); return 'ssh://' + auth + h + ':' + port + name; }
    if (type === 'openconnect') {
      return 'openconnect://' + auth + h + (port && port !== 443 ? ':' + port : '') + '?flavor=' + encodeURIComponent(f.flavor || 'anyconnect') + name;
    }
    fail('Неизвестный тип прокси');
  }

  const api = {
    parseURL: parseURL, parseLink: parseLink, detect: detect, compile: compile,
    parseSubscription: parseSubscription, parseUserInfo: parseUserInfo, parseTitle: parseTitle,
    isSubscriptionURL: isSubscriptionURL, wireGuardConfToLink: wireGuardConfToLink,
    ovpnNode: ovpnNode, ovpnNeedsAuth: ovpnNeedsAuth, proxyLink: proxyLink, nodeFromCompiled: nodeFromCompiled,
    b64decode: b64decode, b64encode: b64encode, clean: clean, TITLES: TITLES
  };
  root.NLLinks = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : this);
