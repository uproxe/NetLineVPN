// Собирает конфигурации ядер для разных серверов и режимов, чтобы проверить их настоящими
// sing-box и Xray (sing-box check / xray run -test). Используется в CI:
//   node tests/gen-configs.js <папка> <папка с .srs> [ca.pem]
'use strict';
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const L = require('../ui/lib/links.js');
const C = require('../ui/lib/config.js');

const out = process.argv[2] || 'configs';
const rulesDir = path.resolve(process.argv[3] || 'rules');
const caFile = process.argv[4];
fs.mkdirSync(out, { recursive: true });

const UUID = crypto.randomUUID();
const key32 = () => crypto.randomBytes(32).toString('base64');
const PBK = crypto.randomBytes(32).toString('base64url');
const enc = encodeURIComponent;

const LINKS = {
  'vless-reality-vision': `vless://${UUID}@nl.example.com:443?type=tcp&security=reality&pbk=${PBK}&sid=6ba85179&sni=www.microsoft.com&fp=chrome&flow=xtls-rprx-vision#NL`,
  'vless-ws-tls': `vless://${UUID}@w.example.com:443?type=ws&path=%2Fws%3Fed%3D2048&host=cdn.example.com&security=tls&sni=cdn.example.com&alpn=h2%2Chttp%2F1.1#WS`,
  'vless-grpc': `vless://${UUID}@g.example.com:443?type=grpc&serviceName=grpc&security=tls&sni=g.example.com#GRPC`,
  'vless-httpupgrade': `vless://${UUID}@u.example.com:80?type=httpupgrade&path=%2Fup&host=u.example.com#HU`,
  'vless-xhttp-reality': `vless://${UUID}@1.2.3.4:443?type=xhttp&security=reality&pbk=${PBK}&sid=ab&sni=www.apple.com&path=%2Fx&mode=auto#XH`,
  'vless-xhttp-tls-extra': `vless://${UUID}@x.example.com:443?type=xhttp&security=tls&sni=x.example.com&path=%2Fapi&mode=packet-up&extra=${enc('{"xPaddingBytes":"100-1000","noGRPCHeader":true}')}#XE`,
  'vless-grpc-multi': `vless://${UUID}@m.example.com:443?type=grpc&serviceName=svc&mode=multi&security=tls&sni=m.example.com#GM`,
  'vless-kcp': `vless://${UUID}@k.example.com:9000?type=kcp#KCP`,
  'vmess-ws': 'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'VM', add: 'vm.example.com', port: '443', id: UUID, aid: '0', scy: 'auto', net: 'ws', host: 'vm.example.com', path: '/v', tls: 'tls', sni: 'vm.example.com' })).toString('base64'),
  'vmess-tcp-http': 'vmess://' + Buffer.from(JSON.stringify({ v: '2', ps: 'VH', add: 'vh.example.com', port: '80', id: UUID, aid: '0', net: 'tcp', type: 'http', host: 'bing.com', path: '/' })).toString('base64'),
  'trojan-tls': 'trojan://secret@t.example.com:443?sni=t.example.com#TR',
  'ss-2022': 'ss://' + Buffer.from('2022-blake3-aes-128-gcm:' + crypto.randomBytes(16).toString('base64')).toString('base64url') + '@5.6.7.8:8388#SS',
  'ss-obfs': 'ss://' + Buffer.from('aes-128-gcm:pw').toString('base64url') + '@3.3.3.3:80/?plugin=' + enc('obfs-local;obfs=http;obfs-host=bing.com') + '#SO',
  'socks5': 'socks5://user:pw@9.9.9.9:1080#S5',
  'https-proxy': 'https://u:p@proxy.example.com:8443',
  'hysteria2-hop': 'hy2://secret@hy.example.com:443?sni=hy.example.com&obfs=salamander&obfs-password=x&mport=20000-30000#HY2',
  'hysteria': 'hysteria://h1.example.com:443?auth=a&peer=h1.example.com&upmbps=20&downmbps=80#HY1',
  'tuic': `tuic://${UUID}:pw@tu.example.com:443?congestion_control=bbr&udp_relay_mode=native#TUIC`,
  'anytls': 'anytls://pw@a.example.com:443?sni=a.example.com#AT',
  'ssh': 'ssh://root:pw@s.example.com:22#SSH',
  'naive': 'naive+https://u:p@n.example.com:443#NV',
  'wireguard': `wireguard://${enc(key32())}@wg.example.com:51820?publickey=${enc(key32())}&address=${enc('10.8.0.2/32,fd00::2/128')}&mtu=1420#WG`,
  'openconnect': L.proxyLink({ type: 'openconnect', host: 'vpn.corp.example', user: 'ivan', pass: 'pw', flavor: 'anyconnect', name: 'OC' }),
};

function nodeOf(text) {
  const r = L.detect(text);
  if (r.kind !== 'nodes') throw new Error('не сервер: ' + text);
  return L.compile(r.nodes[0].src);
}

const nodes = {};
Object.keys(LINKS).forEach((k) => { nodes[k] = nodeOf(LINKS[k]); });

// Xray из подписки JSON
nodes['xray-json-fragment'] = L.compile(L.detect(JSON.stringify({
  remarks: 'DE',
  outbounds: [
    { tag: 'proxy', protocol: 'vless', settings: { vnext: [{ address: 'de.example.com', port: 443, users: [{ id: UUID, encryption: 'none', flow: 'xtls-rprx-vision' }] }] },
      streamSettings: { network: 'raw', security: 'reality', realitySettings: { serverName: 'www.microsoft.com', fingerprint: 'chrome', publicKey: PBK, shortId: '' }, sockopt: { dialerProxy: 'fragment' } } },
    { tag: 'fragment', protocol: 'freedom', settings: { domainStrategy: 'AsIs' }, streamSettings: { sockopt: { tcpNoDelay: true } } },
    { tag: 'direct', protocol: 'freedom' }
  ]
})).nodes[0].src);

if (caFile) {
  const ca = fs.readFileSync(caFile, 'utf8').trim();
  const hex = crypto.randomBytes(256).toString('hex').match(/.{32}/g).join('\n');
  const ovpn = `client\ndev tun\nproto udp\nremote vpn.example.com 1194\nremote-cert-tls server\ncipher AES-256-GCM\nauth SHA256\nkey-direction 1\nauth-user-pass\n<ca>\n${ca}\n</ca>\n<tls-auth>\n-----BEGIN OpenVPN Static key V1-----\n${hex}\n-----END OpenVPN Static key V1-----\n</tls-auth>\n`;
  nodes.openvpn = L.compile({ sbEndpoint: L.ovpnNode(ovpn, 'ivan', 'pw').sbEndpoint });
}

const auth = { user: 'u' + C.randomToken(4), pass: C.randomToken(12) };
let port = 21000;
const ports = (n) => Array.from({ length: n }, () => port++);
let count = 0;

function write(name, b) {
  fs.writeFileSync(path.join(out, 'singbox-' + name + '.json'), JSON.stringify(b.singbox, null, 2));
  if (b.xray) fs.writeFileSync(path.join(out, 'xray-' + name + '.json'), JSON.stringify(b.xray, null, 2));
  count++;
}

const OS = { tun: 'windows', proxy: 'macos', android: 'android', test: 'linux' };
Object.keys(nodes).forEach((k) => {
  ['tun', 'proxy', 'android'].forEach((mode) => {
    const list = [nodes[k]];
    write(k + '-' + mode, C.build({ nodes: list, mode, os: mode === 'tun' ? 'linux' : OS[mode], ruDirect: true, rulesDir,
      ports: { clash: port++, inbound: port++, xray: ports(C.xrayCount(list)) }, secret: 's', auth }));
  });
});
// все сразу: автовыбор и проверка задержки
const all = Object.keys(nodes).map((k) => nodes[k]);
['tun', 'proxy', 'android', 'test'].forEach((mode) => {
  write('all-auto-' + mode + '-' + OS[mode], C.build({ nodes: all, auto: true, mode, os: OS[mode], ruDirect: true, rulesDir,
    ports: { clash: port++, inbound: port++, xray: ports(C.xrayCount(all)) }, secret: 's', auth }));
});
console.log('конфигураций: ' + count + ' → ' + out);
