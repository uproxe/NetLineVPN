// Тесты общей логики: node tests/test.js
'use strict';
const assert = require('assert');
const L = require('../ui/lib/links.js');
const C = require('../ui/lib/config.js');

let passed = 0;
function t(name, fn) {
  try { fn(); passed++; } catch (e) { console.error('✗ ' + name + '\n  ' + (e.stack || e)); process.exitCode = 1; }
}
const one = (text) => { const r = L.detect(text); assert.strictEqual(r.kind, 'nodes'); return r.nodes[0]; };
const comp = (text) => L.compile(one(text).src);
const UUID = '0e9f3b3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b';
const PBK = 'Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw';

function sb(c) { return C.plan(c); }

// ───────── ссылки ─────────

t('VLESS Reality + Vision → sing-box', () => {
  const c = comp(`vless://${UUID}@example.com:443?type=tcp&security=reality&pbk=${PBK}&sid=6ba8&sni=www.microsoft.com&fp=firefox&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam`);
  assert.strictEqual(c.name, '🇳🇱 Amsterdam');
  const p = sb(c);
  assert.strictEqual(p.kind, 'sb');
  assert.strictEqual(p.outbound.type, 'vless');
  assert.strictEqual(p.outbound.flow, 'xtls-rprx-vision');
  assert.strictEqual(p.outbound.tls.reality.public_key, PBK);
  assert.strictEqual(p.outbound.tls.utls.fingerprint, 'firefox');
  assert.strictEqual(p.outbound.transport, undefined);
});

t('VLESS XHTTP → Xray', () => {
  const c = comp(`vless://${UUID}@1.2.3.4:443?type=xhttp&security=reality&pbk=${PBK}&sid=12&sni=a.com&path=%2Fapi&mode=packet-up&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%7D#x`);
  const p = sb(c);
  assert.strictEqual(p.kind, 'xray');
  const ss = p.outbounds[0].streamSettings;
  assert.strictEqual(ss.network, 'xhttp');
  assert.strictEqual(ss.xhttpSettings.mode, 'packet-up');
  assert.deepStrictEqual(ss.xhttpSettings.extra, { xPaddingBytes: '100-1000' });
  assert.strictEqual(ss.realitySettings.shortId, '12');
});

t('VLESS Encryption → Xray, allowInsecure не попадает в Xray', () => {
  const c = comp(`vless://${UUID}@h.com:443?type=tcp&security=tls&allowInsecure=1&encryption=mlkem768x25519plus.native.0rtt.abc&sni=h.com#e`);
  const p = sb(c);
  assert.strictEqual(p.kind, 'xray');
  assert.strictEqual(p.outbounds[0].settings.vnext[0].users[0].encryption, 'mlkem768x25519plus.native.0rtt.abc');
  assert.ok(!('allowInsecure' in p.outbounds[0].streamSettings.tlsSettings));
});

t('VLESS gRPC и WS с early data', () => {
  let p = sb(comp(`vless://${UUID}@g.com:443?type=grpc&serviceName=svc&security=tls&sni=g.com#g`));
  assert.deepStrictEqual(p.outbound.transport, { type: 'grpc', service_name: 'svc' });
  p = sb(comp(`vless://${UUID}@w.com:443?type=ws&path=%2Fws%3Fed%3D2560&host=cdn.w.com&security=tls#w`));
  assert.strictEqual(p.outbound.transport.max_early_data, 2560);
  assert.strictEqual(p.outbound.transport.path, '/ws');
  assert.strictEqual(p.outbound.transport.headers.Host, 'cdn.w.com');
  p = sb(comp(`vless://${UUID}@g.com:443?type=grpc&serviceName=svc&mode=multi&security=tls#m`));
  assert.strictEqual(p.kind, 'xray');
});

t('VMess base64', () => {
  const j = { v: '2', ps: 'Тест', add: 'vm.example.com', port: '8443', id: UUID, aid: '0', scy: 'auto', net: 'ws', type: 'none', host: 'vm.example.com', path: '/v', tls: 'tls', sni: 'vm.example.com' };
  const c = comp('vmess://' + Buffer.from(JSON.stringify(j)).toString('base64'));
  assert.strictEqual(c.name, 'Тест');
  assert.strictEqual(c.port, 8443);
  const p = sb(c);
  assert.strictEqual(p.outbound.type, 'vmess');
  assert.strictEqual(p.outbound.transport.type, 'ws');
  assert.strictEqual(p.outbound.tls.server_name, 'vm.example.com');
});

t('Trojan по умолчанию с TLS', () => {
  const p = sb(comp('trojan://p%40ss@t.org:443#t'));
  assert.strictEqual(p.outbound.password, 'p@ss');
  assert.strictEqual(p.outbound.tls.enabled, true);
});

t('Shadowsocks: SIP002, старый формат, плагин', () => {
  let c = comp('ss://' + Buffer.from('chacha20-ietf-poly1305:pw').toString('base64url') + '@1.1.1.1:8388#a');
  assert.strictEqual(sb(c).outbound.method, 'chacha20-ietf-poly1305');
  c = comp('ss://' + Buffer.from('aes-256-gcm:pw@2.2.2.2:443').toString('base64') + '#b');
  assert.strictEqual(c.host, '2.2.2.2');
  assert.strictEqual(sb(c).outbound.password, 'pw');
  c = comp('ss://' + Buffer.from('aes-128-gcm:pw').toString('base64url') + '@3.3.3.3:80/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dbing.com#c');
  assert.strictEqual(sb(c).outbound.plugin, 'obfs-local');
  assert.strictEqual(sb(c).outbound.plugin_opts, 'obfs=http;obfs-host=bing.com');
  c = comp('ss://2022-blake3-aes-128-gcm:a2V5a2V5a2V5a2V5a2V5aw%3D%3D@4.4.4.4:9000#d');
  assert.strictEqual(sb(c).outbound.password, 'a2V5a2V5a2V5a2V5a2V5aw==');
});

t('SOCKS5 и HTTP(S)-прокси', () => {
  let p = sb(comp('socks5://user:pw@9.9.9.9:1080#s'));
  assert.deepStrictEqual([p.outbound.type, p.outbound.username, p.outbound.password], ['socks', 'user', 'pw']);
  p = sb(comp('socks://' + Buffer.from('u:p').toString('base64') + '@9.9.9.9:1080'));
  assert.strictEqual(p.outbound.username, 'u');
  p = sb(comp('https://u:p@proxy.example.com:8443'));
  assert.strictEqual(p.outbound.type, 'http');
  assert.strictEqual(p.outbound.tls.server_name, 'proxy.example.com');
  assert.strictEqual(one('http://10.0.0.1:3128').proto, 'http');
});

t('Hysteria2 с прыжками портов, Hysteria, TUIC, AnyTLS, SSH, Naive', () => {
  let p = sb(comp('hy2://secret@hy.com:443?sni=hy.com&obfs=salamander&obfs-password=x&mport=20000-30000&insecure=1#h'));
  assert.strictEqual(p.outbound.type, 'hysteria2');
  assert.deepStrictEqual(p.outbound.server_ports, ['20000:30000']);
  assert.strictEqual(p.outbound.server_port, undefined);
  assert.strictEqual(p.outbound.tls.insecure, true);
  p = sb(comp('hysteria2://pw@h.com:443#n'));
  assert.strictEqual(p.outbound.server_port, 443);
  p = sb(comp('hysteria://h1.com:443?auth=a&peer=h1.com&upmbps=20&downmbps=80&obfsParam=k#h1'));
  assert.deepStrictEqual([p.outbound.type, p.outbound.auth_str, p.outbound.up_mbps, p.outbound.obfs], ['hysteria', 'a', 20, 'k']);
  p = sb(comp('tuic://' + UUID + ':pw@tu.com:443?congestion_control=cubic&udp_relay_mode=quic#t'));
  assert.deepStrictEqual([p.outbound.uuid, p.outbound.congestion_control, p.outbound.tls.server_name], [UUID, 'cubic', 'tu.com']);
  p = sb(comp('anytls://pw@a.com:443#a'));
  assert.strictEqual(p.outbound.type, 'anytls');
  p = sb(comp('ssh://root:pw@s.com:22#s'));
  assert.deepStrictEqual([p.outbound.type, p.outbound.user], ['ssh', 'root']);
  p = sb(comp('naive+quic://u:p@n.com:443#n'));
  assert.deepStrictEqual([p.outbound.type, p.outbound.quic, p.outbound.tls.server_name], ['naive', true, 'n.com']);
});

t('WireGuard: ссылка и файл .conf', () => {
  const conf = `[Interface]
PrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=
Address = 10.8.0.2/32, fd00::2/128
DNS = 1.1.1.1
MTU = 1420

[Peer]
PublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=
PresharedKey = /UwcSPg38hW/D9Y3tcS1FOV0K1wuURMbS0sesJEP5ak=
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = wg.example.com:51820
PersistentKeepalive = 25
`;
  const n = one(conf);
  assert.strictEqual(n.proto, 'wireguard');
  assert.strictEqual(n.host, 'wg.example.com');
  const p = sb(L.compile(n.src));
  assert.strictEqual(p.kind, 'ep');
  assert.strictEqual(p.endpoint.private_key, 'yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=');
  assert.deepStrictEqual(p.endpoint.address, ['10.8.0.2/32', 'fd00::2/128']);
  assert.strictEqual(p.endpoint.mtu, 1420);
  assert.strictEqual(p.endpoint.peers[0].public_key, 'xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=');
  assert.strictEqual(p.endpoint.peers[0].pre_shared_key, '/UwcSPg38hW/D9Y3tcS1FOV0K1wuURMbS0sesJEP5ak=');
  assert.strictEqual(p.endpoint.peers[0].persistent_keepalive_interval, 25);
  assert.throws(() => L.detect(conf.replace('MTU = 1420', 'Jc = 4\nJmin = 40')), /AmneziaWG/);
});

const OVPN = `client
dev tun
proto udp
remote vpn.example.com 1194
remote 5.5.5.5 443 tcp
cipher AES-256-GCM
data-ciphers AES-256-GCM:CHACHA20-POLY1305
auth SHA256
remote-cert-tls server
key-direction 1
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
MIIBszCCAVmgAwIBAgIUQ
-----END CERTIFICATE-----
</ca>
<tls-auth>
-----BEGIN OpenVPN Static key V1-----
abcdef
-----END OpenVPN Static key V1-----
</tls-auth>
`;

t('OpenVPN .ovpn', () => {
  const r = L.detect(OVPN);
  assert.strictEqual(r.kind, 'ovpn');
  assert.strictEqual(r.needAuth, true);
  assert.throws(() => L.ovpnNode(OVPN), /логин/);
  const n = L.ovpnNode(OVPN, 'ivan', 'secret');
  assert.strictEqual(n.proto, 'openvpn');
  assert.strictEqual(n.host, 'vpn.example.com');
  const ep = n.sbEndpoint;
  assert.strictEqual(ep.type, 'openvpn-client');
  assert.deepStrictEqual(ep.servers, [{ server: 'vpn.example.com', server_port: 1194, network: 'udp' }, { server: '5.5.5.5', server_port: 443, network: 'tcp' }]);
  assert.deepStrictEqual([ep.username, ep.password, ep.auth], ['ivan', 'secret', 'SHA256']);
  assert.strictEqual(ep.cipher, undefined);
  assert.strictEqual(ep.data_ciphers_fallback, 'AES-256-GCM');
  assert.deepStrictEqual(ep.data_ciphers, ['AES-256-GCM', 'CHACHA20-POLY1305']);
  assert.strictEqual(ep.tls.control_wrap.type, 'tls_auth');
  assert.strictEqual(ep.tls.control_wrap.direction, 'client');
  assert.strictEqual(ep.tls.remote_certificate_tls, 'server');
  assert.ok(ep.tls.certificate[0].startsWith('-----BEGIN CERTIFICATE-----'));
});

t('OpenConnect и ручной прокси', () => {
  const link = L.proxyLink({ type: 'openconnect', host: 'vpn.corp.ru', user: 'ivan', pass: 'p@ss', flavor: 'anyconnect', name: 'Работа' });
  const c = comp(link);
  assert.strictEqual(c.name, 'Работа');
  const p = sb(c);
  assert.deepStrictEqual([p.kind, p.endpoint.type, p.endpoint.server, p.endpoint.password], ['ep', 'openconnect', 'vpn.corp.ru', 'p@ss']);
  const s = comp(L.proxyLink({ type: 'socks', host: '10.0.0.5', port: '1080', user: 'u', pass: 'p:x' }));
  assert.strictEqual(sb(s).outbound.password, 'p:x');
  assert.throws(() => L.proxyLink({ type: 'http', host: 'h', port: '0' }), /порт/);
});

// ───────── подписки ─────────

t('Адрес подписки и HTTP-прокси различаются', () => {
  assert.strictEqual(L.detect('https://sub.example.com/s/abc').kind, 'url');
  assert.strictEqual(L.detect('https://sub.example.com/?token=1').kind, 'url');
  assert.strictEqual(L.detect('http://1.2.3.4:8080').kind, 'nodes');
  assert.strictEqual(L.detect('http://u:p@1.2.3.4:8080/').kind, 'nodes');
});

t('Подписка base64 со списком ссылок и ошибками', () => {
  const body = Buffer.from([
    `vless://${UUID}@a.com:443?security=tls#A`,
    'trojan://p@b.com:443#B',
    'bogus://x',
    ''
  ].join('\n')).toString('base64');
  const r = L.parseSubscription(body);
  assert.strictEqual(r.nodes.length, 2);
  assert.strictEqual(r.errors.length, 1);
  assert.deepStrictEqual(r.nodes.map((n) => n.name), ['A', 'B']);
});

t('Подписка JSON Xray (с фрагментацией через dialerProxy)', () => {
  const cfg = [{
    remarks: '🇩🇪 Германия',
    outbounds: [
      { tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'de.example.com', port: 443, users: [{ id: UUID, encryption: 'none' }] }] },
        streamSettings: { network: 'xhttp', security: 'tls', sockopt: { dialerProxy: 'fragment' } } },
      { tag: 'fragment', protocol: 'freedom', settings: { fragment: { packets: 'tlshello', length: '100-200', interval: '10-20' } } },
      { tag: 'direct', protocol: 'freedom' },
      { tag: 'block', protocol: 'blackhole' }
    ]
  }, {
    remarks: 'Второй',
    outbounds: [{ tag: 'proxy', protocol: 'trojan', settings: { servers: [{ address: 'tr.example.com', port: 443, password: 'x' }] } }]
  }];
  const r = L.detect(JSON.stringify(cfg));
  assert.strictEqual(r.nodes.length, 2);
  assert.strictEqual(r.nodes[0].name, '🇩🇪 Германия');
  assert.strictEqual(r.nodes[0].host, 'de.example.com');
  const nodes = r.nodes.map((n) => L.compile(n.src));
  const b = C.build({ nodes, auto: true, mode: 'proxy', os: 'linux', ports: { clash: 9090, inbound: 10808, xray: [20001, 20002] }, secret: 's', auth: { user: 'u', pass: 'p' } });
  const tags = b.xray.outbounds.map((o) => o.tag);
  assert.deepStrictEqual(tags, ['c0-proxy', 'c0-fragment', 'c1-proxy', 'direct']);
  assert.strictEqual(b.xray.outbounds[0].streamSettings.sockopt.dialerProxy, 'c0-fragment');
  assert.deepStrictEqual(b.xray.routing.rules.map((x) => x.outboundTag), ['c0-proxy', 'c1-proxy']);
});

t('Подписка JSON sing-box', () => {
  const r = L.detect(JSON.stringify({ outbounds: [
    { type: 'hysteria2', tag: 'HY', server: 'h.com', server_port: 443, password: 'x', tls: { enabled: true } },
    { type: 'selector', tag: 'select', outbounds: ['HY'] },
    { type: 'direct', tag: 'direct' }
  ], endpoints: [{ type: 'wireguard', tag: 'WG', address: ['10.0.0.2/32'], private_key: 'k', peers: [{ address: 'w.com', port: 51820, public_key: 'p', allowed_ips: ['0.0.0.0/0'] }] }] }));
  assert.deepStrictEqual(r.nodes.map((n) => [n.name, n.proto]), [['HY', 'hysteria2'], ['WG', 'wireguard']]);
});

t('Заголовки подписки', () => {
  assert.deepStrictEqual(L.parseUserInfo('upload=1; download=2; total=10737418240; expire=1767225600'),
    { upload: 1, download: 2, total: 10737418240, expire: 1767225600 });
  assert.strictEqual(L.parseUserInfo('nonsense'), null);
  assert.strictEqual(L.parseTitle('base64:' + Buffer.from('Мой VPN').toString('base64')), 'Мой VPN');
  assert.strictEqual(L.parseTitle('Simple'), 'Simple');
});

t('Понятные ошибки', () => {
  assert.throws(() => L.detect(''), /Вставьте/);
  assert.throws(() => L.detect('vless://nouuid@h:1'), /UUID/);
  assert.throws(() => L.detect('proxies:\n  - name: x'), /Clash/);
  assert.throws(() => L.detect('просто текст'), /распознать/);
  assert.throws(() => L.detect(`vless://${UUID}@h.com?security=tls`), /порт/);
});

// ───────── сборка конфигурации ─────────

const NODES = [
  `vless://${UUID}@nl.example.com:443?type=tcp&security=reality&pbk=${PBK}&sid=ab&sni=www.microsoft.com&flow=xtls-rprx-vision#NL`,
  `vless://${UUID}@5.5.5.5:443?type=xhttp&security=tls&sni=x.com#X`,
  'hy2://pw@hy.example.com:443#HY',
];

t('VPN (TUN) на Windows: автовыбор, российские сайты напрямую, Xray в обход туннеля', () => {
  const nodes = NODES.map((l) => comp(l));
  const b = C.build({ nodes, auto: true, mode: 'tun', os: 'windows', ruDirect: true, rulesDir: 'C:\\NetLine\\rules\\',
    ports: { clash: 9090, xray: [20000] }, secret: 's', auth: { user: 'u', pass: 'p' } });
  const s = b.singbox;
  assert.strictEqual(s.inbounds[0].type, 'tun');
  assert.strictEqual(s.inbounds[0].interface_name, 'NetLine VPN');
  const ut = s.outbounds.find((o) => o.type === 'urltest');
  assert.deepStrictEqual(ut.outbounds, ['n0', 'n1', 'n2']);
  assert.strictEqual(s.route.final, 'proxy');
  assert.ok(s.route.rules.some((r) => r.process_name && r.process_name.includes('netline-helper.exe')));
  assert.strictEqual(s.route.rule_set[0].path, 'C:\\NetLine\\rules/geoip-ru.srs');
  assert.deepStrictEqual(s.dns.rules[0].domain, ['nl.example.com', 'hy.example.com']);
  assert.strictEqual(s.route.auto_detect_interface, true);
  assert.strictEqual(b.xray.inbounds[0].port, 20000);
  assert.deepStrictEqual(b.tags, { n0: 0, n1: 1, n2: 2 });
});

t('Прокси и одиночный сервер: системный прокси ставит ядро только на Linux', () => {
  const b = C.build({ nodes: [comp(NODES[0])], auto: true, mode: 'proxy', os: 'linux', ruDirect: false, rulesDir: '/x',
    ports: { clash: 9090, inbound: 10808, xray: [] }, secret: 's', auth: { user: 'u', pass: 'p' } });
  assert.deepStrictEqual(b.singbox.inbounds, [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 10808, set_system_proxy: true }]);
  const m = C.build({ nodes: [comp(NODES[0])], mode: 'proxy', os: 'macos', ports: { clash: 1, inbound: 2 }, secret: 's', auth: {} });
  assert.strictEqual(m.singbox.inbounds[0].set_system_proxy, undefined);
  assert.strictEqual(b.singbox.outbounds[0].tag, 'proxy');
  assert.strictEqual(b.singbox.route.rule_set, undefined);
  assert.strictEqual(b.xray, null);
  const w = C.build({ nodes: [comp(NODES[0])], mode: 'proxy', os: 'windows', ports: { clash: 1, inbound: 2 }, secret: 's', auth: {} });
  assert.strictEqual(w.singbox.inbounds[0].set_system_proxy, undefined);
});

t('Проверочный вход: с паролем и всегда через сервер, мимо правил', () => {
  const b = C.build({ nodes: [comp(NODES[0])], mode: 'tun', os: 'macos', ruDirect: true, rulesDir: '/r',
    ports: { clash: 1, check: 7777 }, secret: 's', auth: { user: 'u', pass: 'p' } });
  const ci = b.singbox.inbounds.find((i) => i.tag === 'check-in');
  assert.deepStrictEqual(ci, { type: 'socks', tag: 'check-in', listen: '127.0.0.1', listen_port: 7777, users: [{ username: 'u', password: 'p' }] });
  assert.deepStrictEqual(b.singbox.route.rules[0], { inbound: ['check-in'], outbound: 'proxy' });
  assert.strictEqual(b.singbox.inbounds[0].stack, 'gvisor');
  const w = C.build({ nodes: [comp(NODES[0])], mode: 'tun', os: 'windows', ports: { clash: 1 }, secret: 's', auth: {} });
  assert.strictEqual(w.singbox.inbounds[0].stack, 'mixed');
  assert.ok(!w.singbox.inbounds.some((i) => i.tag === 'check-in'));
});

t('Android: SOCKS5 с паролем, без привязки к интерфейсу', () => {
  const b = C.build({ nodes: [comp(NODES[2])], mode: 'android', os: 'android', ruDirect: true, rulesDir: '/data/rules',
    ports: { clash: 9090, inbound: 10900 }, secret: 's', auth: { user: 'u', pass: 'p' } });
  assert.deepStrictEqual(b.singbox.inbounds[0].users, [{ username: 'u', password: 'p' }]);
  assert.strictEqual(b.singbox.route.auto_detect_interface, undefined);
  assert.ok(b.singbox.route.rules.some((r) => r.ip_cidr && r.action === 'hijack-dns'));
});

t('Проверка задержки: без входов, каждый сервер под своим тегом', () => {
  const nodes = NODES.map((l) => comp(l));
  const b = C.build({ nodes, auto: true, mode: 'test', os: 'linux', ports: { clash: 9090, xray: [20000] }, secret: 's', auth: { user: 'u', pass: 'p' } });
  assert.deepStrictEqual(b.singbox.inbounds, []);
  assert.ok(!b.singbox.outbounds.some((o) => o.type === 'urltest'));
  assert.strictEqual(b.singbox.route.final, 'n0');
});

t('WireGuard в режиме прокси: имена сайтов через сервер', () => {
  const wg = 'wireguard://' + encodeURIComponent('yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=') + '@1.2.3.4:51820?publickey=' + encodeURIComponent('xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=') + '#wg';
  const b = C.build({ nodes: [comp(wg)], mode: 'proxy', os: 'linux', ports: { clash: 1, inbound: 2 }, secret: 's', auth: {} });
  assert.strictEqual(b.singbox.endpoints[0].tag, 'proxy');
  assert.deepStrictEqual(b.singbox.route.rules[b.singbox.route.rules.length - 1], { action: 'resolve', server: 'remote' });
});

console.log(process.exitCode ? 'есть ошибки' : 'все тесты пройдены: ' + passed);
