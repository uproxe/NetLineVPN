package io.github.uproxe.netline;

import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.webkit.JavascriptInterface;
import android.webkit.WebView;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicReference;
import org.json.JSONArray;
import org.json.JSONObject;

/**
 * Мост между страницей интерфейса и Android: те же команды, что у программы для компьютера.
 * Страница вызывает NetLineAndroid.call(id, команда, аргументы), ответ приходит в __nlResolve(id, ok, значение).
 */
final class Bridge {
  private final MainActivity activity;
  private final WebView web;
  private final ExecutorService pool = Executors.newCachedThreadPool();
  private final List<Core> testCores = new ArrayList<>();
  volatile String pendingText;

  Bridge(MainActivity activity, WebView web) {
    this.activity = activity;
    this.web = web;
  }

  @JavascriptInterface
  public void call(int id, String cmd, String argsJson) {
    pool.execute(
        () -> {
          try {
            final JSONObject a = argsJson == null || argsJson.isEmpty() ? new JSONObject() : new JSONObject(argsJson);
            handle(id, cmd, a);
          } catch (Exception e) {
            reject(id, e.getMessage() == null ? e.toString() : e.getMessage());
          }
        });
  }

  private void handle(int id, String cmd, JSONObject a) throws Exception {
    final Context c = activity.getApplicationContext();
    switch (cmd) {
      case "platform": {
        final JSONObject o = new JSONObject();
        o.put("os", "android");
        o.put("version", c.getPackageManager().getPackageInfo(c.getPackageName(), 0).versionName);
        o.put("cores", new JSONObject().put("singbox", BuildConfig.SING_BOX_VERSION).put("xray", BuildConfig.XRAY_VERSION));
        o.put("rulesDir", Store.rulesDir(c).getAbsolutePath());
        final String p = pendingText;
        pendingText = null;
        if (p != null) o.put("pending", p);
        resolve(id, o);
        return;
      }
      case "load_state":
        resolve(id, Store.read(c, "state.json"));
        return;
      case "save_state":
        Store.write(c, "state.json", a.optString("data"));
        resolve(id, null);
        return;
      case "free_ports": {
        final JSONArray arr = new JSONArray();
        final int n = Math.min(200, Math.max(1, a.optInt("count", 1)));
        final List<java.net.ServerSocket> keep = new ArrayList<>();
        try {
          for (int i = 0; i < n; i++) {
            final java.net.ServerSocket s = new java.net.ServerSocket(0, 1, java.net.InetAddress.getByName("127.0.0.1"));
            keep.add(s);
            arr.put(s.getLocalPort());
          }
        } finally {
          for (java.net.ServerSocket s : keep) s.close();
        }
        resolve(id, arr);
        return;
      }
      case "connect":
        activity.requestVpn(
            a,
            err -> {
              if (err == null) resolve(id, null);
              else reject(id, err);
            });
        return;
      case "disconnect":
        NetLineVpn.stop(c);
        for (int i = 0; i < 50 && !"off".equals(NetLineVpn.state) && !"error".equals(NetLineVpn.state); i++) Thread.sleep(100);
        resolve(id, null);
        return;
      case "status":
        resolve(id, NetLineVpn.status());
        return;
      case "fetch_url":
        resolve(id, fetch(a));
        return;
      case "test_start":
        testStart(a);
        resolve(id, null);
        return;
      case "test_stop":
        testStop();
        resolve(id, null);
        return;
      case "set_ready": {
        final Object r = a.opt("ready");
        if (r instanceof JSONObject) Store.write(c, "ready.json", r.toString());
        else Store.delete(c, "ready.json");
        resolve(id, null);
        return;
      }
      case "set_autostart":
        resolve(id, null);
        return;
      case "log_tail":
        resolve(id, NetLineVpn.logTail());
        return;
      case "open_url": {
        final String url = a.optString("url");
        if (!url.startsWith("https://")) throw new Exception("Можно открыть только адрес https");
        activity.runOnUiThread(() -> activity.startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url))));
        resolve(id, null);
        return;
      }
      case "clipboard_read":
        resolve(id, onUi(() -> {
          final ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
          final ClipData d = cm.getPrimaryClip();
          if (d == null || d.getItemCount() == 0) return "";
          final CharSequence t = d.getItemAt(0).coerceToText(activity);
          return t == null ? "" : t.toString();
        }));
        return;
      case "clipboard_write": {
        final String text = a.optString("text");
        onUi(() -> {
          final ClipboardManager cm = (ClipboardManager) activity.getSystemService(Context.CLIPBOARD_SERVICE);
          cm.setPrimaryClip(ClipData.newPlainText("NetLine VPN", text));
          return "";
        });
        resolve(id, null);
        return;
      }
      case "quit":
        activity.runOnUiThread(activity::finish);
        resolve(id, null);
        return;
      default:
        reject(id, "Неизвестная команда " + cmd);
    }
  }

  // ───────── сеть ─────────

  private JSONObject fetch(JSONObject a) throws Exception {
    String url = a.optString("url");
    if (!url.startsWith("https://") && !url.startsWith("http://")) throw new Exception("Поддерживаются только адреса http и https");
    final int timeout = Math.max(1000, Math.min(120000, a.optInt("timeout", 20000)));
    final JSONObject headers = a.optJSONObject("headers");
    for (int hop = 0; hop < 8; hop++) {
      final HttpURLConnection con = (HttpURLConnection) new URL(url).openConnection();
      try {
        con.setConnectTimeout(timeout);
        con.setReadTimeout(timeout);
        con.setInstanceFollowRedirects(false);
        if (headers != null) {
          final Iterator<String> it = headers.keys();
          while (it.hasNext()) {
            final String k = it.next();
            con.setRequestProperty(k, headers.optString(k));
          }
        }
        final int code;
        try {
          code = con.getResponseCode();
        } catch (java.net.UnknownHostException e) {
          throw new Exception("Не удалось найти сервер по адресу — проверьте ссылку и интернет");
        } catch (java.net.SocketTimeoutException e) {
          throw new Exception("Сервер не ответил вовремя");
        }
        if (code >= 300 && code < 400 && con.getHeaderField("Location") != null) {
          url = new URL(new URL(url), con.getHeaderField("Location")).toString();
          continue;
        }
        final JSONObject hs = new JSONObject();
        for (Map.Entry<String, List<String>> e : con.getHeaderFields().entrySet()) {
          if (e.getKey() != null && !e.getValue().isEmpty()) hs.put(e.getKey().toLowerCase(), e.getValue().get(0));
        }
        final InputStream in = code >= 400 ? con.getErrorStream() : con.getInputStream();
        final String body = in == null ? "" : new String(Store.readAll(in, 32 << 20), StandardCharsets.UTF_8);
        return new JSONObject().put("status", code).put("headers", hs).put("body", body);
      } finally {
        con.disconnect();
      }
    }
    throw new Exception("Слишком много перенаправлений");
  }

  // ───────── проверка задержки: отдельные ядра без VPN ─────────

  private void testStart(JSONObject a) throws Exception {
    testStop();
    final Context c = activity.getApplicationContext();
    final java.io.File work = new java.io.File(c.getFilesDir(), "test");
    final String xray = a.optString("xray", "");
    try {
      if (!xray.isEmpty() && !"null".equals(xray)) {
        final Core x = new Core(c, "xray");
        synchronized (testCores) {
          testCores.add(x);
        }
        x.start(xray, work);
      }
      final Core s = new Core(c, "sing-box");
      synchronized (testCores) {
        testCores.add(s);
      }
      s.start(a.getString("singbox"), work);
      s.waitPort(a.getInt("clashPort"), 20000);
    } catch (Exception e) {
      testStop();
      throw e;
    }
  }

  private void testStop() {
    synchronized (testCores) {
      for (Core x : testCores) x.stop();
      testCores.clear();
    }
  }

  void destroy() {
    testStop();
    pool.shutdown();
  }

  // ───────── ответы странице ─────────

  interface UiCall {
    String run() throws Exception;
  }

  private String onUi(UiCall f) throws Exception {
    final CountDownLatch done = new CountDownLatch(1);
    final AtomicReference<String> out = new AtomicReference<>("");
    final AtomicReference<Exception> err = new AtomicReference<>();
    activity.runOnUiThread(
        () -> {
          try {
            out.set(f.run());
          } catch (Exception e) {
            err.set(e);
          }
          done.countDown();
        });
    done.await();
    if (err.get() != null) throw err.get();
    return out.get();
  }

  private static String literal(Object v) {
    if (v == null || v == JSONObject.NULL) return "null";
    if (v instanceof String) return JSONObject.quote((String) v);
    if (v instanceof JSONObject || v instanceof JSONArray || v instanceof Number || v instanceof Boolean) return v.toString();
    return JSONObject.quote(v.toString());
  }

  void resolve(int id, Object value) {
    send("__nlResolve(" + id + ",true," + literal(value) + ")");
  }

  void reject(int id, String message) {
    send("__nlResolve(" + id + ",false," + JSONObject.quote(message == null ? "Ошибка" : message) + ")");
  }

  void send(String js) {
    web.post(() -> web.evaluateJavascript(js, null));
  }
}
