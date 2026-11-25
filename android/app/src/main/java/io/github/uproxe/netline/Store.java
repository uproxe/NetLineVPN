package io.github.uproxe.netline;

import android.content.Context;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import org.json.JSONObject;

/** Файлы приложения: настройки интерфейса, последние параметры подключения, списки сайтов */
final class Store {
  private Store() {}

  static String read(Context c, String name) {
    final File f = new File(c.getFilesDir(), name);
    if (!f.exists()) return null;
    try (InputStream in = new FileInputStream(f)) {
      return new String(readAll(in, 64 << 20), StandardCharsets.UTF_8);
    } catch (Exception e) {
      return null;
    }
  }

  static JSONObject readJson(Context c, String name) {
    final String s = read(c, name);
    if (s == null || s.isEmpty()) return null;
    try {
      return new JSONObject(s);
    } catch (Exception e) {
      return null;
    }
  }

  static void write(Context c, String name, String data) throws Exception {
    final File dir = c.getFilesDir();
    final File tmp = new File(dir, name + ".tmp");
    try (OutputStream out = new FileOutputStream(tmp)) {
      out.write(data.getBytes(StandardCharsets.UTF_8));
      out.flush();
    }
    if (!tmp.renameTo(new File(dir, name))) throw new Exception("Не удалось сохранить " + name);
  }

  static void delete(Context c, String name) {
    new File(c.getFilesDir(), name).delete();
  }

  static byte[] readAll(InputStream in, int limit) throws Exception {
    final ByteArrayOutputStream out = new ByteArrayOutputStream();
    final byte[] buf = new byte[16384];
    int n;
    while ((n = in.read(buf)) > 0) {
      out.write(buf, 0, n);
      if (out.size() > limit) throw new Exception("Слишком большой ответ");
    }
    return out.toByteArray();
  }

  /** Списки российских сайтов лежат в приложении; ядру нужен обычный файл */
  static File rulesDir(Context c) {
    final File dir = new File(c.getFilesDir(), "rules");
    dir.mkdirs();
    try {
      final String[] names = c.getAssets().list("rules");
      if (names != null) {
        for (String n : names) {
          final File dst = new File(dir, n);
          try (InputStream in = c.getAssets().open("rules/" + n)) {
            final byte[] data = readAll(in, 32 << 20);
            if (dst.exists() && dst.length() == data.length) continue;
            try (OutputStream out = new FileOutputStream(dst)) {
              out.write(data);
            }
          }
        }
      }
    } catch (Exception ignored) {
      // без списков просто не будет правила «российские сайты напрямую»
    }
    return dir;
  }
}
