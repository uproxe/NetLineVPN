#!/usr/bin/env bash
# Описание релиза: раздел версии из CHANGELOG.md и таблица установки.
#   bash tools/release-notes.sh <версия>
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VER="$1"
. "$ROOT/cores.env"
awk -v v="$VER" '
  /^## \[/ { if (on) exit; if (index($0, "## [" v "]") == 1) { on = 1; next } }
  on { print }
' "$ROOT/CHANGELOG.md"
cat <<NOTES

### Какой файл скачать

| Система | Файл |
|---|---|
| Windows 10 и 11 | \`NetLineVPN-$VER-windows-x64-setup.exe\` |
| macOS 10.15 и новее (Apple Silicon и Intel) | \`NetLineVPN-$VER-macos-universal.dmg\` |
| Ubuntu, Debian, Mint, Astra Linux | \`netline-vpn_${VER}_amd64.deb\` |
| Fedora, РЕД ОС, РОСА, openSUSE | \`netline-vpn-$VER-1.x86_64.rpm\` |
| Arch, Manjaro | \`netline-vpn-$VER-1-x86_64.pkg.tar.zst\` |
| Любой Linux без установки | \`NetLineVPN-$VER-x86_64.AppImage\` |
| Android 8 и новее | \`NetLineVPN-$VER-android-arm64.apk\` |

Ядра: sing-box $SING_BOX_VERSION, Xray $XRAY_VERSION. Рядом с каждым файлом — контрольная сумма \`.sha256\`.
Сборки не подписаны платными сертификатами Microsoft и Apple — при первом запуске система покажет предупреждение (как обойти — в README).
NOTES
