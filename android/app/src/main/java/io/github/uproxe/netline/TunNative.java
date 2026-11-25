package io.github.uproxe.netline;

/**
 * hev-socks5-tunnel (С, через JNI): переносит пакеты из VPN-интерфейса Android
 * в локальный SOCKS5 ядра sing-box. Имя класса задаётся при сборке библиотеки (PKGNAME/CLSNAME).
 */
final class TunNative {
  static {
    System.loadLibrary("hev-socks5-tunnel");
  }

  private TunNative() {}

  static native boolean TProxyStartService(String configPath, int fd);

  static native boolean TProxyStopService();

  static native boolean TProxyIsRunning();

  /** [отправлено пакетов, отправлено байт, получено пакетов, получено байт] (со стороны VPN-интерфейса) */
  static native long[] TProxyGetStats();
}
