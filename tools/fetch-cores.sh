#!/usr/bin/env bash
# Скачивает ядра VPN (sing-box, Xray) и списки российских сайтов для сборки.
#   bash tools/fetch-cores.sh windows-x64 | linux-x64 | macos-universal | android-arm64 | rules <папка>
# Версии — в cores.env. Ядра кладутся туда, где их ждёт сборка (desktop/binaries, android/app/src/main/jniLibs).
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=/dev/null
. "$ROOT/cores.env"
TARGET="${1:?укажите систему}"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
SB="https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION"
XR="https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION"
BIN="$ROOT/desktop/binaries"

dl() { echo "    $1"; curl -fsSL --retry 5 --retry-delay 3 -o "$2" "$1"; }

# Xray публикует контрольные суммы в файлах .dgst
xray() {   # <архив> <папка>
  dl "$XR/$1" "$TMP/$1"
  if curl -fsSL --retry 3 -o "$TMP/$1.dgst" "$XR/$1.dgst"; then
    want="$(grep -i '^SHA2-256=' "$TMP/$1.dgst" | head -1 | awk '{print $2}')"
    have="$( (sha256sum "$TMP/$1" 2>/dev/null || shasum -a 256 "$TMP/$1") | awk '{print $1}')"
    [ -z "$want" ] || [ "$want" = "$have" ] || { echo "Контрольная сумма Xray не совпала: $1"; exit 1; }
  fi
  mkdir -p "$2"; unzip -qo "$TMP/$1" -d "$2"
}
singbox() {   # <архив> <папка>
  dl "$SB/$1" "$TMP/$1"
  mkdir -p "$2"
  case "$1" in *.zip) unzip -qo "$TMP/$1" -d "$2" ;; *) tar -xzf "$TMP/$1" -C "$2" ;; esac
}

rules() {   # <папка>
  mkdir -p "$1"
  dl https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs "$1/geoip-ru.srs"
  dl https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ru.srs "$1/geosite-category-ru.srs"
}

echo "==> Ядра для $TARGET: sing-box $SING_BOX_VERSION, Xray $XRAY_VERSION"
case "$TARGET" in
  windows-x64)
    singbox "sing-box-$SING_BOX_VERSION-windows-amd64.zip" "$TMP/sb"
    xray Xray-windows-64.zip "$TMP/x"
    mkdir -p "$BIN" "$ROOT/desktop/resources"
    cp "$TMP"/sb/*/sing-box.exe "$BIN/netline-singbox-x86_64-pc-windows-msvc.exe"
    cp "$TMP"/sb/*/libcronet.dll "$ROOT/desktop/resources/libcronet.dll"
    cp "$TMP/x/xray.exe" "$BIN/netline-xray-x86_64-pc-windows-msvc.exe"
    rules "$ROOT/desktop/resources/rules"
    ;;
  linux-x64)
    # musl: собрано статически, работает на любом дистрибутиве и умеет NaiveProxy без libcronet
    singbox "sing-box-$SING_BOX_VERSION-linux-amd64-musl.tar.gz" "$TMP/sb"
    xray Xray-linux-64.zip "$TMP/x"
    mkdir -p "$BIN"
    install -m 755 "$TMP"/sb/*/sing-box "$BIN/netline-singbox-x86_64-unknown-linux-gnu"
    install -m 755 "$TMP/x/xray" "$BIN/netline-xray-x86_64-unknown-linux-gnu"
    rules "$ROOT/desktop/resources/rules"
    ;;
  macos-universal)
    singbox "sing-box-$SING_BOX_VERSION-darwin-arm64.tar.gz" "$TMP/sa"
    singbox "sing-box-$SING_BOX_VERSION-darwin-amd64.tar.gz" "$TMP/si"
    xray Xray-macos-arm64-v8a.zip "$TMP/xa"
    xray Xray-macos-64.zip "$TMP/xi"
    mkdir -p "$BIN"
    for n in singbox xray; do
      if [ $n = singbox ]; then A="$(echo "$TMP"/sa/*/sing-box)"; I="$(echo "$TMP"/si/*/sing-box)"; else A="$TMP/xa/xray"; I="$TMP/xi/xray"; fi
      install -m 755 "$A" "$BIN/netline-$n-aarch64-apple-darwin"
      install -m 755 "$I" "$BIN/netline-$n-x86_64-apple-darwin"
      lipo -create "$A" "$I" -output "$BIN/netline-$n-universal-apple-darwin"
      chmod 755 "$BIN/netline-$n-universal-apple-darwin"
      lipo -info "$BIN/netline-$n-universal-apple-darwin"
    done
    rules "$ROOT/desktop/resources/rules"
    ;;
  android-arm64)
    LIBS="$ROOT/android/app/src/main/jniLibs/arm64-v8a"
    singbox "sing-box-$SING_BOX_VERSION-android-arm64.tar.gz" "$TMP/sb"
    xray Xray-android-arm64-v8a.zip "$TMP/x"
    mkdir -p "$LIBS"
    # Android разрешает запускать программы только из папки библиотек, поэтому имена lib*.so
    install -m 755 "$TMP"/sb/*/sing-box "$LIBS/libsingbox.so"
    install -m 755 "$TMP/x/xray" "$LIBS/libxray.so"
    rules "$ROOT/android/app/src/main/assets/rules"
    ;;
  rules)
    rules "${2:?папка}"
    ;;
  *) echo "Неизвестная система: $TARGET"; exit 2 ;;
esac
echo "    готово"
