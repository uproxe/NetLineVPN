package io.github.uproxe.netline;

import android.app.PendingIntent;
import android.content.Intent;
import android.net.VpnService;
import android.os.Build;
import android.service.quicksettings.Tile;
import android.service.quicksettings.TileService;
import org.json.JSONObject;

/** Плитка в быстрых настройках: включить или выключить VPN, не открывая приложение */
public final class QuickTile extends TileService {
  @Override
  public void onStartListening() {
    refresh();
  }

  private void refresh() {
    final Tile t = getQsTile();
    if (t == null) return;
    final String s = NetLineVpn.state;
    t.setState("on".equals(s) || "connecting".equals(s) ? Tile.STATE_ACTIVE : Tile.STATE_INACTIVE);
    t.setLabel("NetLine VPN");
    if (Build.VERSION.SDK_INT >= 29) {
      t.setSubtitle("on".equals(s) ? "Подключено" : "connecting".equals(s) ? "Подключение…" : "Отключено");
    }
    t.updateTile();
  }

  @Override
  public void onClick() {
    final String s = NetLineVpn.state;
    if ("on".equals(s) || "connecting".equals(s)) {
      NetLineVpn.stop(this);
      refresh();
      return;
    }
    final JSONObject ready = Store.readJson(this, "ready.json");
    if (ready == null || VpnService.prepare(this) != null) {
      // нужен выбор сервера или разрешение на VPN — откроем приложение
      openApp();
      return;
    }
    NetLineVpn.start(this, ready, null);
    refresh();
  }

  @SuppressWarnings("deprecation")
  private void openApp() {
    final Intent i = new Intent(this, MainActivity.class).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK);
    if (Build.VERSION.SDK_INT >= 34) {
      startActivityAndCollapse(PendingIntent.getActivity(this, 0, i, PendingIntent.FLAG_IMMUTABLE));
    } else {
      startActivityAndCollapse(i);
    }
  }
}
