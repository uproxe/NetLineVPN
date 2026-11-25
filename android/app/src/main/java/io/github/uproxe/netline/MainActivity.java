package io.github.uproxe.netline;

import android.Manifest;
import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.net.VpnService;
import android.os.Build;
import android.os.Bundle;
import android.webkit.ValueCallback;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/** Окно приложения: та же страница интерфейса, что и на компьютере */
public final class MainActivity extends Activity {
  private static final int REQ_VPN = 1;
  private static final int REQ_FILE = 2;

  private WebView web;
  private Bridge bridge;
  private boolean loaded;
  private ValueCallback<Uri[]> fileCallback;
  private JSONObject pendingPayload;
  private NetLineVpn.Done pendingDone;

  @Override
  protected void onCreate(Bundle state) {
    super.onCreate(state);
    web = new WebView(this);
    web.setBackgroundColor(0xFF0B1220);
    setContentView(web);
    final WebSettings s = web.getSettings();
    s.setJavaScriptEnabled(true);
    s.setDomStorageEnabled(true);
    s.setAllowFileAccess(true);
    s.setAllowContentAccess(true);
    s.setSupportZoom(false);
    s.setMediaPlaybackRequiresUserGesture(true);
    bridge = new Bridge(this, web);
    web.addJavascriptInterface(bridge, "NetLineAndroid");
    web.setWebViewClient(
        new WebViewClient() {
          @Override
          public boolean shouldOverrideUrlLoading(WebView view, WebResourceRequest req) {
            final Uri u = req.getUrl();
            if ("file".equals(u.getScheme())) return false;
            try {
              startActivity(new Intent(Intent.ACTION_VIEW, u));
            } catch (Exception ignored) {
              // некуда открыть
            }
            return true;
          }

          @Override
          public void onPageFinished(WebView view, String url) {
            loaded = true;
          }
        });
    web.setWebChromeClient(
        new WebChromeClient() {
          @Override
          public boolean onShowFileChooser(WebView v, ValueCallback<Uri[]> cb, FileChooserParams params) {
            if (fileCallback != null) fileCallback.onReceiveValue(null);
            fileCallback = cb;
            final Intent i = new Intent(Intent.ACTION_GET_CONTENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*");
            try {
              startActivityForResult(Intent.createChooser(i, "Файл WireGuard или OpenVPN"), REQ_FILE);
            } catch (Exception e) {
              fileCallback = null;
              return false;
            }
            return true;
          }
        });
    handleIntent(getIntent());
    web.loadUrl("file:///android_asset/ui/index.html");
    if (Build.VERSION.SDK_INT >= 33 && checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
      requestPermissions(new String[] {Manifest.permission.POST_NOTIFICATIONS}, 3);
    }
  }

  @Override
  protected void onNewIntent(Intent intent) {
    super.onNewIntent(intent);
    setIntent(intent);
    handleIntent(intent);
  }

  /** Ссылка или файл, которыми поделились с приложением */
  private void handleIntent(Intent intent) {
    if (intent == null) return;
    String text = null;
    try {
      if (Intent.ACTION_SEND.equals(intent.getAction())) {
        text = intent.getStringExtra(Intent.EXTRA_TEXT);
        final Uri stream = intent.getParcelableExtra(Intent.EXTRA_STREAM);
        if (text == null && stream != null) text = readText(stream);
      } else if (Intent.ACTION_VIEW.equals(intent.getAction()) && intent.getData() != null) {
        final Uri d = intent.getData();
        text = "content".equals(d.getScheme()) || "file".equals(d.getScheme()) ? readText(d) : d.toString();
      }
    } catch (Exception ignored) {
      // не удалось прочитать
    }
    if (text == null || text.trim().isEmpty()) return;
    if (loaded) {
      final String js = "window.NetLineApp && NetLineApp.addFromText(" + JSONObject.quote(text.trim()) + ")";
      web.evaluateJavascript(js, null);
    } else {
      bridge.pendingText = text.trim();
    }
  }

  private String readText(Uri uri) throws Exception {
    try (InputStream in = getContentResolver().openInputStream(uri)) {
      if (in == null) return null;
      return new String(Store.readAll(in, 2 << 20), StandardCharsets.UTF_8);
    }
  }

  /** Подключение: при первом разе Android спросит разрешение на VPN */
  void requestVpn(JSONObject payload, NetLineVpn.Done done) {
    runOnUiThread(
        () -> {
          final Intent prep = VpnService.prepare(this);
          if (prep == null) {
            NetLineVpn.start(this, payload, done);
            return;
          }
          if (pendingDone != null) pendingDone.done("Подключение отменено");
          pendingPayload = payload;
          pendingDone = done;
          try {
            startActivityForResult(prep, REQ_VPN);
          } catch (Exception e) {
            pendingDone = null;
            done.done("Не удалось запросить разрешение на VPN: " + e.getMessage());
          }
        });
  }

  @Override
  protected void onActivityResult(int req, int result, Intent data) {
    super.onActivityResult(req, result, data);
    if (req == REQ_VPN) {
      final NetLineVpn.Done done = pendingDone;
      final JSONObject p = pendingPayload;
      pendingDone = null;
      pendingPayload = null;
      if (done == null) return;
      if (result == RESULT_OK) NetLineVpn.start(this, p, done);
      else done.done("Подключение отменено: нет разрешения на VPN");
    } else if (req == REQ_FILE) {
      final ValueCallback<Uri[]> cb = fileCallback;
      fileCallback = null;
      if (cb != null) {
        final Uri u = result == RESULT_OK && data != null ? data.getData() : null;
        cb.onReceiveValue(u == null ? null : new Uri[] {u});
      }
    }
  }

  @Override
  @SuppressWarnings("deprecation")
  public void onBackPressed() {
    // назад: закрыть окно или вернуться на главный экран; на главном — свернуть (VPN продолжит работать)
    web.evaluateJavascript(
        "window.NetLineBack ? NetLineBack() : false",
        v -> {
          if (!"true".equals(v)) moveTaskToBack(true);
        });
  }

  @Override
  protected void onResume() {
    super.onResume();
    if (loaded) web.evaluateJavascript("document.dispatchEvent(new Event('visibilitychange'))", null);
  }

  @Override
  protected void onDestroy() {
    bridge.destroy();
    web.removeJavascriptInterface("NetLineAndroid");
    web.destroy();
    super.onDestroy();
  }
}
