/*
 * Мост к «родной» части: Tauri на компьютере, Java на Android.
 * Интерфейс одинаковый: native.call('команда', {аргументы}) → Promise.
 * В обычном браузере работает заглушка — для разработки и снимков интерфейса.
 */
(function () {
  'use strict';
  const tauri = window.__TAURI__ && window.__TAURI__.core;
  const android = window.NetLineAndroid;
  let seq = 0;
  const pending = {};

  // Android отвечает вызовом __nlResolve(id, ok, значение)
  window.__nlResolve = function (id, ok, value) {
    const p = pending[id];
    if (!p) return;
    delete pending[id];
    if (ok) p.resolve(value); else p.reject(new Error(String(value)));
  };

  function errorOf(e) {
    if (e instanceof Error) return e;
    return new Error(typeof e === 'string' ? e : (e && e.message) || JSON.stringify(e));
  }

  function call(cmd, args) {
    args = args || {};
    if (tauri) return tauri.invoke(cmd, { args: args }).catch(function (e) { throw errorOf(e); });
    if (android) {
      return new Promise(function (resolve, reject) {
        const id = ++seq;
        pending[id] = { resolve: resolve, reject: reject };
        android.call(id, cmd, JSON.stringify(args));
      });
    }
    return mock(cmd, args);
  }

  // ───────── заглушка для браузера ─────────
  const M = { state: null, status: { state: 'off', since: 0, error: '', rx: 0, tx: 0 } };
  function mock(cmd, a) {
    const ok = function (v) { return new Promise(function (r) { setTimeout(function () { r(v); }, 60); }); };
    switch (cmd) {
      case 'platform': return ok({ os: /android/i.test(navigator.userAgent) ? 'android' : 'linux', version: '1.0.0', cores: { singbox: '1.14.4', xray: '26.11.9' }, rulesDir: '/rules', autostart: false });
      case 'load_state': return ok(M.state);
      case 'save_state': M.state = a.data; return ok(null);
      case 'free_ports': return ok(Array.from({ length: a.count }, function (_, i) { return 30000 + i; }));
      case 'connect':
        M.status = { state: 'connecting', since: 0, error: '', rx: 0, tx: 0 };
        setTimeout(function () { M.status = { state: 'on', since: Date.now(), error: '', rx: 0, tx: 0 }; }, 900);
        return ok(null);
      case 'disconnect': M.status = { state: 'off', since: 0, error: '', rx: 0, tx: 0 }; return ok(null);
      case 'status':
        if (M.status.state === 'on') { M.status.rx += 180000 + Math.random() * 90000; M.status.tx += 9000 + Math.random() * 4000; }
        return ok(Object.assign({}, M.status));
      case 'fetch_url':
        if (/\/delay\?/.test(a.url)) return ok({ status: 200, headers: {}, body: JSON.stringify({ delay: 40 + Math.round(Math.random() * 300) }) });
        return ok({ status: 200, headers: { 'subscription-userinfo': 'upload=1073741824; download=5368709120; total=107374182400; expire=1798675200', 'profile-title': 'Мой VPN' },
          body: window.NLLinks.b64encode(['vless://0e9f3b3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b@nl.example.com:443?security=reality&pbk=Z84J2IelR9ch3k8VtlVhhs5ycBUlXA7wHBWcBrjqnAw&sid=ab&sni=www.microsoft.com&flow=xtls-rprx-vision#%F0%9F%87%B3%F0%9F%87%B1%20Нидерланды',
            'vless://0e9f3b3a-1c2d-4e5f-8a9b-0c1d2e3f4a5b@de.example.com:443?type=xhttp&security=tls&sni=de.example.com#%F0%9F%87%A9%F0%9F%87%AA%20Германия',
            'hy2://pw@fi.example.com:443#%F0%9F%87%AB%F0%9F%87%AE%20Финляндия'].join('\n')) });
      case 'test_start': case 'test_stop': case 'set_ready': case 'set_autostart': case 'open_url': case 'quit': return ok(null);
      case 'log_tail': return ok('Журнал пуст');
      case 'clipboard_read': return navigator.clipboard ? navigator.clipboard.readText() : ok('');
      case 'clipboard_write': return navigator.clipboard ? navigator.clipboard.writeText(a.text) : ok(null);
      default: return Promise.reject(new Error('Неизвестная команда ' + cmd));
    }
  }

  window.native = { call: call, kind: tauri ? 'tauri' : (android ? 'android' : 'browser') };
})();
