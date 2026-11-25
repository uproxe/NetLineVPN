/*
 * NetLine VPN — сборка конфигурации ядер.
 *
 * Главное ядро всегда sing-box: оно держит VPN (TUN) или локальный прокси, DNS и правила
 * («российские сайты напрямую»). Почти все протоколы sing-box умеет сам. То, что есть только
 * в Xray (XHTTP, mKCP, VLESS Encryption, постквантовая проверка Reality, конфигурации Xray
 * из подписок), идёт через второе ядро: sing-box → локальный SOCKS5 с паролем → Xray → сервер.
 */
(function (root) {
  'use strict';
  const L = root.NLLinks || (typeof require !== 'undefined' ? require('./links.js') : null);
  const clean = L.clean;

  const TEST_URL = 'https://www.gstatic.com/generate_204';
  const PROXY_PORT = 10808;
  const CORE_NAMES = ['netline-xray', 'netline-xray.exe', 'netline-singbox', 'netline-singbox.exe'];
  const RU_SUFFIX = ['.ru', '.su', '.xn--p1ai', '.xn--d1acj3b', '.xn--80asehdb', '.xn--80aswg', '.xn--c1avg', '.xn--80adxhks'];

  // uTLS sing-box понимает те же имена, что и Xray; неизвестное — как Chrome
  const FP = ['chrome', 'firefox', 'edge', 'safari', '360', 'qq', 'ios', 'android', 'random', 'randomized'];
  function fingerprint(fp) { fp = String(fp || '').toLowerCase(); return FP.indexOf(fp) >= 0 ? fp : 'chrome'; }

  function isIP(h) { return /^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.indexOf(':') >= 0; }

  // ───────── общее описание → sing-box (или null, если нужно Xray) ─────────

  function sbTransport(s) {
    if (s.net === 'tcp') {
      if (s.headerType && s.headerType !== 'none') return null;  // маскировка под HTTP — только Xray
      return undefined;
    }
    if (s.net === 'ws') {
      let path = s.path || '/';
      const t = { type: 'ws' };
      const m = /[?&]ed=(\d+)/.exec(path);
      if (m) {
        t.max_early_data = parseInt(m[1], 10);
        t.early_data_header_name = 'Sec-WebSocket-Protocol';
        path = path.replace(/([?&])ed=\d+&?/, '$1').replace(/[?&]$/, '');
      }
      t.path = path;
      if (s.host) t.headers = { Host: s.host };
      return t;
    }
    if (s.net === 'grpc') {
      if (s.mode === 'multi') return null;
      return clean({ type: 'grpc', service_name: s.serviceName || s.path || '' });
    }
    if (s.net === 'httpupgrade') return clean({ type: 'httpupgrade', path: s.path || '/', host: s.host });
    if (s.net === 'h2') return clean({ type: 'http', path: s.path || '/', host: s.host ? s.host.split(',') : undefined });
    if (s.net === 'quic') return { type: 'quic' };
    return null;  // xhttp, kcp
  }

  function sbTlsFrom(t) {
    if (!t) return undefined;
    if (t.type === 'reality') {
      if (t.pqv) return null;
      return { enabled: true, server_name: t.sni || undefined, utls: { enabled: true, fingerprint: fingerprint(t.fp) },
        reality: { enabled: true, public_key: t.pbk, short_id: t.sid || '' } };
    }
    if (t.ech || t.pcs || t.vcn) return null;
    return clean({ enabled: true, server_name: t.sni, insecure: t.insecure ? true : undefined, alpn: t.alpn,
      utls: { enabled: true, fingerprint: fingerprint(t.fp) } });
  }

  function specToSingbox(s) {
    if (s.proto === 'socks') return clean({ type: 'socks', server: s.server, server_port: s.port, version: '5', username: s.username, password: s.password });
    if (s.proto === 'http') {
      const o = clean({ type: 'http', server: s.server, server_port: s.port, username: s.username, password: s.password });
      if (s.tls) o.tls = clean({ enabled: true, server_name: s.tls.sni, insecure: s.tls.insecure ? true : undefined });
      return o;
    }
    if (s.proto === 'shadowsocks') {
      return clean({ type: 'shadowsocks', server: s.server, server_port: s.port, method: s.method, password: s.password,
        plugin: s.plugin, plugin_opts: s.pluginOpts, udp_over_tcp: s.uot ? true : undefined });
    }
    const transport = sbTransport(s);
    if (transport === null) return null;
    const tls = sbTlsFrom(s.tls);
    if (tls === null) return null;
    let o;
    if (s.proto === 'vless') {
      if (s.encryption && s.encryption !== 'none') return null;
      let flow = s.flow || '';
      if (flow === 'xtls-rprx-vision-udp443') flow = 'xtls-rprx-vision';
      if (flow && flow !== 'xtls-rprx-vision') return null;
      o = { type: 'vless', server: s.server, server_port: s.port, uuid: s.uuid, flow: flow || undefined, packet_encoding: 'xudp' };
    } else if (s.proto === 'vmess') {
      const sec = ['auto', 'none', 'zero', 'aes-128-cfb', 'aes-128-gcm', 'chacha20-poly1305'].indexOf(s.cipher) >= 0 ? s.cipher : 'auto';
      o = { type: 'vmess', server: s.server, server_port: s.port, uuid: s.uuid, security: sec, alter_id: 0, packet_encoding: 'xudp' };
    } else if (s.proto === 'trojan') {
      o = { type: 'trojan', server: s.server, server_port: s.port, password: s.password };
    } else {
      return null;
    }
    if (tls) o.tls = tls;
    if (transport) o.transport = transport;
    return clean(o);
  }

  // ───────── общее описание → Xray ─────────

  function xrayStream(s) {
    const net = s.net === 'tcp' ? 'raw' : s.net;
    if (net === 'h2' || net === 'quic') throw new Error('Транспорт ' + s.net + ' больше не поддерживается в Xray');
    const ss = { network: net };
    if (s.tls && s.tls.type === 'tls') {
      ss.security = 'tls';
      ss.tlsSettings = clean({ serverName: s.tls.sni, fingerprint: fingerprint(s.tls.fp), alpn: s.tls.alpn,
        echConfigList: s.tls.ech, pinnedPeerCertSha256: s.tls.pcs, verifyPeerCertByName: s.tls.vcn });
    } else if (s.tls && s.tls.type === 'reality') {
      ss.security = 'reality';
      ss.realitySettings = clean({ serverName: s.tls.sni, fingerprint: fingerprint(s.tls.fp), publicKey: s.tls.pbk,
        spiderX: s.tls.spx, mldsa65Verify: s.tls.pqv });
      ss.realitySettings.shortId = s.tls.sid || '';
    }
    if (net === 'raw' && s.headerType === 'http') {
      ss.rawSettings = { header: { type: 'http', request: clean({ path: [s.path || '/'], headers: s.host ? { Host: s.host.split(',') } : undefined }) } };
    } else if (net === 'ws') {
      ss.wsSettings = clean({ path: s.path || '/', host: s.host });
    } else if (net === 'grpc') {
      ss.grpcSettings = clean({ serviceName: s.serviceName || s.path || '', multiMode: s.mode === 'multi' ? true : undefined, authority: s.authority });
    } else if (net === 'xhttp') {
      ss.xhttpSettings = clean({ path: s.path || '/', host: s.host, mode: s.mode || 'auto', extra: s.extra });
    } else if (net === 'httpupgrade') {
      ss.httpupgradeSettings = clean({ path: s.path || '/', host: s.host });
    } else if (net === 'kcp') {
      ss.kcpSettings = {};
    }
    return ss;
  }

  function specToXray(s) {
    if (s.proto === 'vless') {
      return { protocol: 'vless', settings: { vnext: [{ address: s.server, port: s.port,
        users: [clean({ id: s.uuid, encryption: s.encryption || 'none', flow: s.flow })] }] }, streamSettings: xrayStream(s) };
    }
    if (s.proto === 'vmess') {
      return { protocol: 'vmess', settings: { vnext: [{ address: s.server, port: s.port,
        users: [{ id: s.uuid, security: s.cipher || 'auto' }] }] }, streamSettings: xrayStream(s) };
    }
    if (s.proto === 'trojan') {
      return { protocol: 'trojan', settings: { servers: [{ address: s.server, port: s.port, password: s.password }] }, streamSettings: xrayStream(s) };
    }
    if (s.proto === 'shadowsocks') {
      return { protocol: 'shadowsocks', settings: { servers: [clean({ address: s.server, port: s.port, method: s.method, password: s.password, uot: s.uot ? true : undefined })] } };
    }
    throw new Error('Этот сервер не поддерживается');
  }

  /**
   * Как запускать сервер: { kind: 'sb', outbound } | { kind: 'ep', endpoint } | { kind: 'xray', outbounds, main }
   */
  function plan(c) {
    if (c.spec) {
      const sb = specToSingbox(c.spec);
      if (sb) return { kind: 'sb', outbound: sb };
      const x = specToXray(c.spec);
      return { kind: 'xray', outbounds: [Object.assign({ tag: 'proxy' }, x)], main: 'proxy' };
    }
    if (c.sb) return { kind: 'sb', outbound: JSON.parse(JSON.stringify(c.sb)) };
    if (c.sbEndpoint) return { kind: 'ep', endpoint: JSON.parse(JSON.stringify(c.sbEndpoint)) };
    if (c.xray) return { kind: 'xray', outbounds: JSON.parse(JSON.stringify(c.xray.outbounds)), main: c.xray.main };
    throw new Error('Неизвестный сервер');
  }

  /** Сколько локальных портов нужно для Xray */
  function xrayCount(compiled) {
    return compiled.filter(function (c) { return plan(c).kind === 'xray'; }).length;
  }

  // ───────── Xray: по входу SOCKS5 на каждый сервер ─────────

  function buildXray(chains, auth) {
    const inbounds = [], outbounds = [], rules = [];
    chains.forEach(function (ch, k) {
      const prefix = 'c' + k + '-';
      const rename = {};
      ch.outbounds.forEach(function (o) { rename[o.tag || ''] = prefix + (o.tag || 'out'); });
      ch.outbounds.forEach(function (o) {
        const x = JSON.parse(JSON.stringify(o));
        x.tag = rename[o.tag || ''];
        const so = x.streamSettings && x.streamSettings.sockopt;
        if (so && so.dialerProxy && rename[so.dialerProxy]) so.dialerProxy = rename[so.dialerProxy];
        delete x.proxySettings;
        delete x.mux;  // мультиплексирование здесь не нужно
        outbounds.push(x);
      });
      inbounds.push({ tag: 'in' + k, listen: '127.0.0.1', port: ch.port, protocol: 'socks',
        settings: { auth: 'password', accounts: [{ user: auth.user, pass: auth.pass }], udp: true, ip: '127.0.0.1' } });
      rules.push({ type: 'field', inboundTag: ['in' + k], outboundTag: rename[ch.main] });
    });
    outbounds.push({ tag: 'direct', protocol: 'freedom' });
    return { log: { loglevel: 'warning' }, inbounds: inbounds, outbounds: outbounds,
      routing: { domainStrategy: 'AsIs', rules: rules } };
  }

  // ───────── главная сборка ─────────

  /**
   * @param o {
   *   nodes: [скомпилированные серверы], auto: bool,
   *   mode: 'tun' | 'proxy' | 'android' | 'test',
   *   os: 'windows' | 'macos' | 'linux' | 'android',
   *   ruDirect: bool, rulesDir: string|null,
   *   ports: { clash, inbound, xray: [] }, secret, auth: { user, pass }
   * }
   * @returns {{ singbox, xray, tags }}  tags: тег → номер сервера
   */
  function build(o) {
    const nodes = o.nodes;
    if (!nodes || !nodes.length) throw new Error('Не выбран сервер');
    const auth = o.auth;
    const outbounds = [], endpoints = [], chains = [], tags = {}, hosts = [];
    const single = nodes.length === 1 || !o.auto;
    let xi = 0;

    nodes.forEach(function (c, i) {
      const tag = single && o.mode !== 'test' ? 'proxy' : 'n' + i;
      tags[tag] = i;
      if (c.host && !isIP(c.host) && hosts.indexOf(c.host) < 0) hosts.push(c.host);
      const p = plan(c);
      if (p.kind === 'sb') outbounds.push(Object.assign({ tag: tag }, p.outbound));
      else if (p.kind === 'ep') endpoints.push(Object.assign({ tag: tag }, p.endpoint));
      else {
        const port = (o.ports.xray || [])[xi++];
        if (!port) throw new Error('Нет свободного порта для Xray');
        chains.push({ port: port, outbounds: p.outbounds, main: p.main });
        outbounds.push({ tag: tag, type: 'socks', server: '127.0.0.1', server_port: port, version: '5',
          username: auth.user, password: auth.pass });
      }
    });

    if (!single && o.mode !== 'test') {
      outbounds.push({ type: 'urltest', tag: 'proxy', outbounds: Object.keys(tags), url: TEST_URL,
        interval: '3m', tolerance: 80, idle_timeout: '30m' });
    }
    outbounds.push({ type: 'direct', tag: 'direct' });

    const desktop = o.os !== 'android';
    const ru = !!(o.ruDirect && o.rulesDir);
    const proxyTag = o.mode === 'test' ? Object.keys(tags)[0] : 'proxy';

    // DNS: сайты — через сервер (DoH), адреса самих серверов и российские сайты — напрямую
    const dnsRules = [];
    if (hosts.length) dnsRules.push({ domain: hosts, server: 'local' });
    if (ru) dnsRules.push({ rule_set: ['geosite-ru'], server: 'local' }, { domain_suffix: RU_SUFFIX, server: 'local' });
    const dns = {
      servers: [
        { type: 'https', tag: 'remote', server: '1.1.1.1', detour: proxyTag },
        { type: 'udp', tag: 'local', server: '77.88.8.8' }
      ],
      rules: dnsRules,
      final: o.mode === 'test' ? 'local' : 'remote',
      strategy: 'ipv4_only'
    };

    const inbounds = [];
    if (o.mode === 'tun') {
      const tun = { type: 'tun', tag: 'tun-in', address: ['172.19.0.1/30', 'fdfe:dcba:9876::1/126'], mtu: 9000,
        auto_route: true, strict_route: true, stack: 'mixed' };
      if (o.os === 'windows') tun.interface_name = 'NetLine VPN';
      if (o.os === 'linux') tun.interface_name = 'netline0';
      inbounds.push(tun);
    } else if (o.mode === 'proxy') {
      inbounds.push(clean({ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: o.ports.inbound || PROXY_PORT,
        set_system_proxy: (o.os === 'macos' || o.os === 'linux') ? true : undefined }));
    } else if (o.mode === 'android') {
      inbounds.push({ type: 'socks', tag: 'socks-in', listen: '127.0.0.1', listen_port: o.ports.inbound,
        users: [{ username: auth.user, password: auth.pass }] });
    }

    const rules = [];
    if (inbounds.length) {
      rules.push({ action: 'sniff' });
      rules.push({ protocol: 'dns', action: 'hijack-dns' });
      if (o.mode === 'android') rules.push({ ip_cidr: ['172.19.0.2/32'], action: 'hijack-dns' });
      rules.push({ ip_is_private: true, outbound: 'direct' });
      if (o.mode === 'tun') rules.push({ process_name: CORE_NAMES, outbound: 'direct' });
      if (ru) {
        rules.push({ rule_set: ['geoip-ru', 'geosite-ru'], outbound: 'direct' });
        rules.push({ domain_suffix: RU_SUFFIX, outbound: 'direct' });
      }
      // WireGuard и OpenVPN работают с IP-адресами: имя сайта узнаём через сервер, чтобы не было утечки DNS
      if (o.mode === 'proxy' && endpoints.length) rules.push({ action: 'resolve', server: 'remote' });
    }

    const route = { rules: rules, final: proxyTag, default_domain_resolver: 'local' };
    if (desktop) route.auto_detect_interface = true;
    if (ru) {
      const dir = String(o.rulesDir).replace(/[\\\/]+$/, '');
      route.rule_set = [
        { type: 'local', tag: 'geoip-ru', format: 'binary', path: dir + '/geoip-ru.srs' },
        { type: 'local', tag: 'geosite-ru', format: 'binary', path: dir + '/geosite-category-ru.srs' }
      ];
    }

    const singbox = {
      log: { level: 'warn', timestamp: true },
      dns: dns,
      inbounds: inbounds,
      outbounds: outbounds,
      route: route,
      experimental: { clash_api: { external_controller: '127.0.0.1:' + o.ports.clash, secret: o.secret } }
    };
    if (endpoints.length) singbox.endpoints = endpoints;

    return { singbox: singbox, xray: chains.length ? buildXray(chains, auth) : null, tags: tags };
  }

  function randomToken(n) {
    const a = new Uint8Array(n || 16);
    (root.crypto || require('crypto').webcrypto).getRandomValues(a);
    return Array.prototype.map.call(a, function (b) { return ('0' + b.toString(16)).slice(-2); }).join('');
  }

  const api = { build: build, plan: plan, xrayCount: xrayCount, specToSingbox: specToSingbox, specToXray: specToXray,
    randomToken: randomToken, TEST_URL: TEST_URL, PROXY_PORT: PROXY_PORT };
  root.NLConfig = api;
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
})(typeof self !== 'undefined' ? self : this);
