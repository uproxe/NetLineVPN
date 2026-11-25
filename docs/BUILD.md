# Сборка

Все установщики собирает GitHub Actions (`.github/workflows/build.yml`). Локально:

## Компьютер (Tauri 2)

Нужны Rust (stable), Node.js 22 и для Linux — `libwebkit2gtk-4.1-dev libayatana-appindicator3-dev librsvg2-dev`.

```bash
bash tools/fetch-cores.sh linux-x64        # или windows-x64, macos-universal
cd desktop
npx @tauri-apps/cli@2 dev                  # запуск для разработки
npx @tauri-apps/cli@2 build                # установщики в desktop/target/release/bundle
```

Ядра (`desktop/binaries/netline-core-<платформа>`, `netline-helper-<платформа>`) и списки сайтов
(`desktop/resources/rules/*.srs`) скачивает `tools/fetch-cores.sh`, версии — в `cores.env`.

Права на VPN:

| Система | Как |
|---|---|
| Windows | программа запускается от администратора (манифест), автозапуск — задание планировщика с наивысшими правами |
| Linux (.deb/.rpm/.pacman) | при установке ядру выдаётся `cap_net_admin` (setcap), пароль не нужен |
| Linux (AppImage) | `pkexec` при каждом подключении |
| macOS | окно пароля администратора при подключении в режиме VPN |

## Android

Нужны JDK 21, Android SDK с NDK и Gradle 9:

```bash
bash tools/android-build.sh
```

Скрипт копирует `ui/` в приложение, скачивает ядра, собирает `hev-socks5-tunnel` (NDK) и APK.

## Значки

Исходники — SVG в `branding/`. После изменения: `python3 tools/make_icons.py` (нужны `rsvg-convert` и Pillow).
