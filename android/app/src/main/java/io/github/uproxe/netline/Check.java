package io.github.uproxe.netline;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;

/**
 * Проверка, что через сервер действительно работает интернет: запрос идёт через проверочный вход
 * ядра (SOCKS5 с паролем) и возвращает внешний IP и страну. Так же устроено в программе для компьютера.
 */
final class Check {
  interface Alive {
    boolean ok();
  }

  private Check() {}

  /** Повторять до успеха или до истечения времени. Результат: {IP, код страны} (могут быть пустыми) */
  static String[] until(int port, String user, String pass, long timeoutMs, Alive alive) throws Exception {
    final long deadline = System.currentTimeMillis() + timeoutMs;
    String last = "";
    while (System.currentTimeMillis() < deadline) {
      if (!alive.ok()) throw new Exception("Ядро VPN неожиданно завершилось");
      try {
        return once(port, user, pass);
      } catch (Exception e) {
        last = e.getMessage() == null ? e.toString() : e.getMessage();
      }
      Thread.sleep(700);
    }
    throw new Exception("Сервер не пропускает трафик — интернет через него не работает. Проверьте ссылку или выберите другой сервер (" + last + ")");
  }

  static String[] once(int port, String user, String pass) throws Exception {
    final StringBuilder errors = new StringBuilder();
    try {
      final String[] r = get(port, user, pass, "1.1.1.1", 80, "/cdn-cgi/trace");
      if ("200".equals(r[0])) {
        String ip = "", cc = "";
        for (String l : r[1].split("\n")) {
          l = l.trim();
          if (l.startsWith("ip=")) ip = l.substring(3);
          if (l.startsWith("loc=")) cc = l.substring(4);
        }
        if ("XX".equals(cc) || "T1".equals(cc)) cc = "";
        if (!ip.isEmpty()) return new String[] {ip, cc};
      }
      errors.append("1.1.1.1: ответ ").append(r[0]).append("; ");
    } catch (Exception e) {
      errors.append(e.getMessage()).append("; ");
    }
    try {
      final String[] r = get(port, user, pass, "ip-api.com", 80, "/line/?fields=status,countryCode,query");
      if (!"0".equals(r[0])) {
        final String[] l = r[1].trim().split("\\s*\\n\\s*");
        if (r[0].equals("200") && l.length >= 3 && "success".equals(l[0])) return new String[] {l[2], l[1]};
        return new String[] {"", ""};
      }
    } catch (Exception e) {
      errors.append(e.getMessage()).append("; ");
    }
    final String[] r = get(port, user, pass, "cp.cloudflare.com", 80, "/generate_204");
    if (!"0".equals(r[0])) return new String[] {"", ""};
    throw new Exception(errors.toString());
  }

  /** GET через SOCKS5 с паролем. Результат: {код ответа, тело} */
  private static String[] get(int port, String user, String pass, String host, int hport, String path) throws Exception {
    try (Socket s = new Socket()) {
      s.connect(new InetSocketAddress("127.0.0.1", port), 3000);
      s.setSoTimeout(8000);
      final OutputStream out = s.getOutputStream();
      final DataInputStream in = new DataInputStream(s.getInputStream());
      out.write(new byte[] {5, 1, 2});
      final byte[] b = new byte[2];
      in.readFully(b);
      if (b[0] != 5 || b[1] != 2) throw new Exception("локальный вход ядра не принял вход по паролю");
      final byte[] u = user.getBytes(StandardCharsets.UTF_8), p = pass.getBytes(StandardCharsets.UTF_8);
      final ByteArrayOutputStream a = new ByteArrayOutputStream();
      a.write(1);
      a.write(u.length);
      a.write(u);
      a.write(p.length);
      a.write(p);
      out.write(a.toByteArray());
      in.readFully(b);
      if (b[1] != 0) throw new Exception("локальный вход ядра отклонил пароль");
      final ByteArrayOutputStream c = new ByteArrayOutputStream();
      c.write(new byte[] {5, 1, 0});
      if (host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
        c.write(1);
        for (String part : host.split("\\.")) c.write(Integer.parseInt(part));
      } else {
        final byte[] h = host.getBytes(StandardCharsets.UTF_8);
        c.write(3);
        c.write(h.length);
        c.write(h);
      }
      c.write((hport >> 8) & 0xff);
      c.write(hport & 0xff);
      out.write(c.toByteArray());
      final byte[] h = new byte[4];
      in.readFully(h);
      if (h[1] != 0) throw new Exception("сервер не открыл соединение (код SOCKS " + h[1] + ")");
      int rest = h[3] == 1 ? 4 : h[3] == 4 ? 16 : h[3] == 3 ? in.readUnsignedByte() : 0;
      in.readFully(new byte[rest + 2]);
      final String req = "GET " + path + " HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: curl/8.7.1\r\nAccept: */*\r\nConnection: close\r\n\r\n";
      out.write(req.getBytes(StandardCharsets.UTF_8));
      out.flush();
      final ByteArrayOutputStream body = new ByteArrayOutputStream();
      final InputStream is = s.getInputStream();
      final byte[] buf = new byte[8192];
      int n;
      try {
        while (body.size() < 256 * 1024 && (n = is.read(buf)) > 0) body.write(buf, 0, n);
      } catch (java.net.SocketTimeoutException e) {
        // часть ответа уже есть
      }
      if (body.size() == 0) throw new Exception(host + ": нет ответа через сервер");
      final String text = new String(body.toByteArray(), StandardCharsets.UTF_8);
      final String[] first = text.split("\r\n", 2)[0].split(" ");
      final String code = first.length > 1 ? first[1] : "0";
      final int i = text.indexOf("\r\n\r\n");
      return new String[] {code, i >= 0 ? text.substring(i + 4) : ""};
    }
  }
}
