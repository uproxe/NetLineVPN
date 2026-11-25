#!/usr/bin/env bash
# Сборка APK для Android:  bash tools/android-build.sh [версия AGP]
# Нужны: ANDROID_HOME (с NDK), gradle, git, curl. Результат: android/app/build/outputs/apk/release/app-release.apk
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT/cores.env"
AGP="${1:-}"
APP="$ROOT/android/app/src/main"
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
step() { echo; echo "==> $*"; }

step "Интерфейс (тот же, что на компьютере)"
rm -rf "$APP/assets/ui"; mkdir -p "$APP/assets"
cp -r "$ROOT/ui" "$APP/assets/ui"

step "Ядра VPN и списки сайтов"
rm -rf "$APP/jniLibs"
bash "$ROOT/tools/fetch-cores.sh" android-arm64

step "hev-socks5-tunnel $HEV_VERSION"
NDK="${ANDROID_NDK_HOME:-${ANDROID_NDK_LATEST_HOME:-}}"
if [ -z "$NDK" ] || [ ! -x "$NDK/ndk-build" ]; then
  NDK="$(ls -d "$ANDROID_HOME"/ndk/* 2>/dev/null | sort -V | tail -1)"
fi
[ -x "$NDK/ndk-build" ] || { echo "Не найден Android NDK"; exit 1; }
echo "    NDK: $NDK"
git clone -q --depth 1 --branch "$HEV_VERSION" --recursive --shallow-submodules https://github.com/heiher/hev-socks5-tunnel "$TMP/hev"
"$NDK/ndk-build" -C "$TMP/hev" -j"$(nproc)" \
  NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk NDK_APPLICATION_MK=Application.mk \
  APP_ABI=arm64-v8a APP_PLATFORM=android-26 \
  APP_CFLAGS="-O3 -DPKGNAME=io/github/uproxe/netline -DCLSNAME=TunNative" >/dev/null
install -m 755 "$TMP/hev/libs/arm64-v8a/libhev-socks5-tunnel.so" "$APP/jniLibs/arm64-v8a/"
ls -la "$APP/jniLibs/arm64-v8a"

step "APK"
yes | "$ANDROID_HOME/cmdline-tools/latest/bin/sdkmanager" --licenses >/dev/null 2>&1 || true
gradle -p "$ROOT/android" --no-daemon assembleRelease ${AGP:+-PagpVersion="$AGP"}
