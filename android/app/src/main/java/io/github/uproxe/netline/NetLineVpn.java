package io.github.uproxe.netline;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ServiceInfo;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.service.quicksettings.TileService;
import java.io.File;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import org.json.JSONObject;

/**
 * VPN для всего телефона.
 * Пакеты VPN-интерфейса → hev-socks5-tunnel → SOCKS5 (с паролем) ядра sing-box → сервер.
 * Само приложение (и его ядра) исключено из VPN, поэтому их соединения идут напрямую и не зацикливаются.
 */
public final class NetLineVpn extends VpnService {
  static final String ACTION_START = "io.github.uproxe.netline.START";
  static final String ACTION_STOP = "io.github.uproxe.netline.STOP";
  private static final int NOTIFICATION = 1;
  private static final String CHANNEL = "vpn";

  interface Done {
    void done(String error);
  }

  // состояние общее для окна, плитки и службы (один процесс)
  static volatile String state = "off";
  static volatile long since;
  static volatile String error = "";
  static volatile JSONObject current;
  private static volatile JSONObject pending;
  private static volatile Done pendingDone;
  static final StringBuilder lastLog = new StringBuilder();

  private final ExecutorService worker = Executors.newSingleThreadExecutor();
  private Core singbox, xray;
  private ParcelFileDescriptor tun;
  private volatile boolean running;

  // ───────── вызовы из окна и плитки ─────────

  static void start(Context c, JSONObject payload, Done done) {
    pending = payload;
    pendingDone = done;
    state = "connecting";
    error = "";
    notifyTile(c);
    final Intent i = new Intent(c, NetLineVpn.class).setAction(ACTION_START);
    if (Build.VERSION.SDK_INT >= 26) c.startForegroundService(i);
    else c.startService(i);
  }

  static void stop(Context c) {
    if ("off".equals(state) || "error".equals(state)) {
      state = "off";
      return;
    }
    c.startService(new Intent(c, NetLineVpn.class).setAction(ACTION_STOP));
  }

  static JSONObject status() {
    final JSONObject o = new JSONObject();
    try {
      o.put("state", state);
      o.put("since", since);
      o.put("error", error);
      long rx = 0, tx = 0;
      if ("on".equals(state)) {
        try {
          final long[] s = TunNative.TProxyGetStats();
          if (s != null && s.length >= 4) {
            tx = s[1];
            rx = s[3];
          }
        } catch (Throwable ignored) {
          // библиотека ещё не загружена
        }
      }
      o.put("rx", rx);
      o.put("tx", tx);
      final JSONObject p = current;
      if (p != null && "on".equals(state)) {
        o.put("clashPort", p.optInt("clashPort"));
        o.put("clashSecret", p.optString("clashSecret"));
        o.put("names", p.optJSONObject("names"));
      }
    } catch (Exception ignored) {
      // JSON без ошибок
    }
    return o;
  }

  static void notifyTile(Context c) {
    try {
      TileService.requestListeningState(c, new ComponentName(c, QuickTile.class));
    } catch (Exception ignored) {
      // плитка не добавлена
    }
  }

  // ───────── служба ─────────

  @Override
  public int onStartCommand(Intent intent, int flags, int startId) {
    final String action = intent == null ? null : intent.getAction();
    if (ACTION_STOP.equals(action)) {
      worker.execute(() -> shutdown(null));
      return START_NOT_STICKY;
    }
    foreground("Подключение…");
    JSONObject p = pending;
    final Done done = pendingDone;
    pending = null;
    pendingDone = null;
    // постоянный VPN из настроек Android или перезапуск системой — берём последние параметры
    if (p == null) p = Store.readJson(this, "ready.json");
    final JSONObject payload = p;
    worker.execute(() -> run(payload, done));
    return START_NOT_STICKY;
  }

  private void run(JSONObject p, Done done) {
    if (p == null) {
      fail("Сервер не выбран — откройте NetLine VPN", done);
      return;
    }
    stopCores();
    state = "connecting";
    notifyTile(this);
    try {
      final File work = new File(getFilesDir(), "core");
      // 1. Xray, если сервер требует его возможностей
      final String xcfg = p.optString("xray", "");
      if (!xcfg.isEmpty() && !"null".equals(xcfg)) {
        xray = new Core(this, "xray");
        xray.onExit = this::coreDied;
        xray.start(xcfg, work);
        final JSONObject xj = new JSONObject(xcfg);
        final org.json.JSONArray in = xj.optJSONArray("inbounds");
        if (in != null && in.length() > 0) xray.waitPort(in.getJSONObject(0).optInt("port"), 8000);
      }
      // 2. sing-box
      singbox = new Core(this, "sing-box");
      singbox.onExit = this::coreDied;
      singbox.start(p.getString("singbox"), work);
      singbox.waitPort(p.getInt("socksPort"), 20000);
      // 3. VPN-интерфейс
      final Builder b = new Builder();
      b.setSession(p.optString("label", "NetLine VPN"));
      b.setMtu(8500);
      b.addAddress("172.19.0.1", 30);
      b.addRoute("0.0.0.0", 0);
      b.addAddress("fdfe:dcba:9876::1", 126);
      b.addRoute("::", 0);
      b.addDnsServer("172.19.0.2");
      b.addDisallowedApplication(getPackageName());
      if (Build.VERSION.SDK_INT >= 29) b.setMetered(false);
      b.setConfigureIntent(openApp());
      tun = b.establish();
      if (tun == null) throw new Exception("Android не разрешил VPN — откройте NetLine VPN и подключитесь ещё раз");
      // 4. hev-socks5-tunnel
      final File conf = new File(getCacheDir(), "tunnel.yml");
      final String yml =
          "tunnel:\n  mtu: 8500\n  ipv4: 172.19.0.1\n  ipv6: 'fdfe:dcba:9876::1'\n"
              + "socks5:\n  port: " + p.getInt("socksPort") + "\n  address: 127.0.0.1\n  udp: 'udp'\n"
              + "  username: '" + p.getString("socksUser") + "'\n  password: '" + p.getString("socksPass") + "'\n"
              + "misc:\n  task-stack-size: 81920\n  log-level: warn\n";
      try (java.io.FileOutputStream out = new java.io.FileOutputStream(conf)) {
        out.write(yml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
      }
      if (!TunNative.TProxyStartService(conf.getAbsolutePath(), tun.getFd())) throw new Exception("Не удалось запустить туннель");
      // туннель читает настройки в своём потоке: если что-то не так, он сразу завершится
      Thread.sleep(300);
      if (!TunNative.TProxyIsRunning()) throw new Exception("Туннель VPN остановился сразу после запуска");
      current = p;
      running = true;
      since = System.currentTimeMillis();
      state = "on";
      error = "";
      foreground("Подключено · " + p.optString("label", ""));
      notifyTile(this);
      if (done != null) done.done(null);
    } catch (Exception e) {
      final String msg = e.getMessage() == null ? e.toString() : e.getMessage();
      fail(msg, done);
    }
  }

  private void coreDied(Core c) {
    worker.execute(() -> {
      if (!running && !"connecting".equals(state)) return;
      final String log = c.log();
      remember(log);
      shutdown(Core.explain(c.name, log));
    });
  }

  private void fail(String msg, Done done) {
    remember((xray != null ? xray.log() + "\n" : "") + (singbox != null ? singbox.log() : ""));
    shutdown(msg);
    if (done != null) done.done(msg);
  }

  private static void remember(String log) {
    synchronized (lastLog) {
      lastLog.setLength(0);
      lastLog.append(log);
    }
  }

  static String logTail() {
    synchronized (lastLog) {
      return lastLog.toString();
    }
  }

  private void stopCores() {
    running = false;
    try {
      if (TunNative.TProxyIsRunning()) TunNative.TProxyStopService();
    } catch (Throwable ignored) {
      // не запускался
    }
    if (tun != null) {
      try {
        tun.close();
      } catch (Exception ignored) {
        // уже закрыт
      }
      tun = null;
    }
    if (singbox != null) {
      remember((xray != null ? xray.log() + "\n" : "") + singbox.log());
      singbox.stop();
      singbox = null;
    }
    if (xray != null) {
      xray.stop();
      xray = null;
    }
  }

  /** Остановить всё. error == null — обычное отключение */
  private void shutdown(String err) {
    stopCores();
    current = null;
    since = 0;
    state = err == null ? "off" : "error";
    error = err == null ? "" : err;
    notifyTile(this);
    if (Build.VERSION.SDK_INT >= 24) stopForeground(STOP_FOREGROUND_REMOVE);
    else stopForeground(true);
    stopSelf();
  }

  @Override
  public void onRevoke() {
    // VPN забрала другая программа или пользователь отключил его в настройках
    worker.execute(() -> shutdown(null));
  }

  @Override
  public void onDestroy() {
    if (running) stopCores();
    if ("on".equals(state) || "connecting".equals(state)) state = "off";
    worker.shutdown();
    super.onDestroy();
  }

  // ───────── уведомление ─────────

  private PendingIntent openApp() {
    final Intent i = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_SINGLE_TOP);
    return PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE | PendingIntent.FLAG_UPDATE_CURRENT);
  }

  private void foreground(String text) {
    final NotificationManager nm = getSystemService(NotificationManager.class);
    if (Build.VERSION.SDK_INT >= 26 && nm.getNotificationChannel(CHANNEL) == null) {
      final NotificationChannel ch = new NotificationChannel(CHANNEL, getString(R.string.channel), NotificationManager.IMPORTANCE_LOW);
      ch.setShowBadge(false);
      nm.createNotificationChannel(ch);
    }
    final PendingIntent stop =
        PendingIntent.getService(this, 1, new Intent(this, NetLineVpn.class).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE);
    final Notification.Builder nb = Build.VERSION.SDK_INT >= 26 ? new Notification.Builder(this, CHANNEL) : new Notification.Builder(this);
    final Notification n =
        nb.setSmallIcon(R.drawable.ic_stat)
            .setContentTitle("NetLine VPN")
            .setContentText(text)
            .setContentIntent(openApp())
            .setOngoing(true)
            .setShowWhen(false)
            .setColor(0xFF38BDF8)
            .addAction(new Notification.Action.Builder(null, "Отключить", stop).build())
            .build();
    if (Build.VERSION.SDK_INT >= 34) startForeground(NOTIFICATION, n, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE);
    else startForeground(NOTIFICATION, n);
  }
}
