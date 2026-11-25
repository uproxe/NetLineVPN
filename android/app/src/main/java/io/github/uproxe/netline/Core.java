package io.github.uproxe.netline;

import android.content.Context;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayDeque;

/**
 * Одно ядро VPN: основное («core», sing-box) или вспомогательное («helper», Xray). Это обычные программы, они лежат в приложении как lib*.so
 * (так Android разрешает их запускать). Настройки передаются через stdin — ключи серверов
 * не попадают на диск. Последние строки вывода хранятся для журнала и сообщений об ошибках.
 */
final class Core {
  interface ExitListener {
    void onExit(Core core);
  }

  /** "core" или "helper" */
  final String name;
  private final Context context;
  private Process process;
  private final ArrayDeque<String> tail = new ArrayDeque<>();
  private volatile boolean stopping;
  ExitListener onExit;

  Core(Context context, String name) {
    this.context = context.getApplicationContext();
    this.name = name;
  }

  private File binary() {
    final String dir = context.getApplicationInfo().nativeLibraryDir;
    return new File(dir, "core".equals(name) ? "libnlcore.so" : "libnlhelper.so");
  }

  synchronized void start(String config, File workDir) throws Exception {
    stop();
    stopping = false;
    final File exe = binary();
    if (!exe.exists()) throw new Exception("В этой сборке нет файла " + exe.getName());
    workDir.mkdirs();
    final ProcessBuilder pb =
        "core".equals(name)
            ? new ProcessBuilder(exe.getAbsolutePath(), "run", "-c", "stdin", "-D", workDir.getAbsolutePath())
            : new ProcessBuilder(exe.getAbsolutePath(), "run", "-config", "stdin:");
    pb.directory(workDir);
    pb.redirectErrorStream(true);
    pb.environment().put("XRAY_LOCATION_ASSET", workDir.getAbsolutePath());
    final Process p = pb.start();
    process = p;
    synchronized (tail) {
      tail.clear();
    }
    try (OutputStream in = p.getOutputStream()) {
      in.write(config.getBytes(StandardCharsets.UTF_8));
    }
    final Thread reader =
        new Thread(
            () -> {
              try (BufferedReader r =
                  new BufferedReader(new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                  synchronized (tail) {
                    tail.add(line);
                    while (tail.size() > 60) tail.poll();
                  }
                }
              } catch (Exception ignored) {
                // поток закрылся вместе с ядром
              }
              try {
                p.waitFor();
              } catch (InterruptedException ignored) {
                // выходим
              }
              final boolean current;
              synchronized (Core.this) {
                current = process == p;
                if (current) process = null;
              }
              if (current && !stopping && onExit != null) onExit.onExit(Core.this);
            },
            "netline-" + name);
    reader.setDaemon(true);
    reader.start();
  }

  boolean alive() {
    final Process p = process;
    if (p == null) return false;
    try {
      p.exitValue();
      return false;
    } catch (IllegalThreadStateException e) {
      return true;
    }
  }

  /** Ждать, пока ядро начнёт принимать подключения на порту */
  void waitPort(int port, long timeoutMs) throws Exception {
    final long deadline = System.currentTimeMillis() + timeoutMs;
    while (System.currentTimeMillis() < deadline) {
      if (!alive()) throw new Exception(Core.explain(name, log()));
      if (tcpPing("127.0.0.1", port, 300) >= 0) return;
      Thread.sleep(100);
    }
    throw new Exception(title(name) + " не ответило вовремя");
  }

  synchronized void stop() {
    stopping = true;
    final Process p = process;
    process = null;
    if (p != null) {
      p.destroy();
      try {
        // мягкая остановка, затем принудительная
        if (android.os.Build.VERSION.SDK_INT >= 26 && !p.waitFor(3, java.util.concurrent.TimeUnit.SECONDS)) {
          p.destroyForcibly();
        }
      } catch (InterruptedException ignored) {
        p.destroyForcibly();
      }
    }
  }

  String log() {
    synchronized (tail) {
      return String.join("\n", tail);
    }
  }

  static String title(String name) {
    return "core".equals(name) ? "Ядро VPN" : "Вспомогательное ядро VPN";
  }

  /** Понятная причина ошибки по выводу ядра */
  static String explain(String name, String log) {
    final String low = log.toLowerCase();
    if (low.contains("address already in use")) return "Порт занят: возможно, запущен другой VPN-клиент";
    String last = "";
    for (String l : log.split("\n")) {
      final String x = l.toLowerCase();
      if (x.contains("fatal") || x.contains("error") || x.contains("failed")) last = l.trim();
    }
    if (last.isEmpty()) {
      final String[] lines = log.trim().split("\n");
      last = lines.length > 0 ? lines[lines.length - 1].trim() : "";
    }
    if (last.isEmpty()) return title(name) + " неожиданно завершилось";
    final int i = last.indexOf("] ");
    if (i >= 0 && i < 60) last = last.substring(i + 2);
    if (last.length() > 300) last = last.substring(0, 300);
    return "Ошибка ядра VPN: " + last;
  }

  static int freePort() throws Exception {
    try (ServerSocket s = new ServerSocket(0)) {
      s.setReuseAddress(true);
      return s.getLocalPort();
    }
  }

  /** Время установки TCP-соединения в миллисекундах или -1 */
  static int tcpPing(String host, int port, int timeoutMs) {
    final long t = System.nanoTime();
    try (Socket s = new Socket()) {
      s.connect(new InetSocketAddress(host, port), timeoutMs);
      return (int) ((System.nanoTime() - t) / 1_000_000);
    } catch (Exception e) {
      return -1;
    }
  }
}
