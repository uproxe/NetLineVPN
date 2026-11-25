#!/usr/bin/env bash
# Проверка собранных конфигураций настоящими ядрами (Linux):
#   bash tests/check-configs.sh   — скачает ядра и списки сайтов во временную папку
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$ROOT/cores.env"
W="$(mktemp -d)"
trap 'rm -rf "$W"' EXIT
cd "$W"
curl -fsSL --retry 5 -o sb.tgz "https://github.com/SagerNet/sing-box/releases/download/v$SING_BOX_VERSION/sing-box-$SING_BOX_VERSION-linux-amd64-musl.tar.gz"
curl -fsSL --retry 5 -o x.zip "https://github.com/XTLS/Xray-core/releases/download/v$XRAY_VERSION/Xray-linux-64.zip"
mkdir sb x && tar -xzf sb.tgz -C sb && unzip -q x.zip -d x
SB="$(echo "$W"/sb/*/sing-box)"; XR="$W/x/xray"
"$SB" version | head -1; "$XR" version | head -1
bash "$ROOT/tools/fetch-cores.sh" rules "$W/rules"
openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem -out ca.pem -days 2 -subj /CN=netline-test 2>/dev/null
node "$ROOT/tests/gen-configs.js" "$W/cfg" "$W/rules" "$W/ca.pem"
fail=0
for f in "$W"/cfg/singbox-*.json; do
  if ! out="$("$SB" check -c "$f" 2>&1)"; then echo "✗ sing-box: $(basename "$f")"; echo "$out" | tail -5; fail=1; fi
done
for f in "$W"/cfg/xray-*.json; do
  if ! out="$("$XR" run -test -c "$f" 2>&1)"; then echo "✗ xray: $(basename "$f")"; echo "$out" | tail -5; fail=1; fi
done
[ $fail = 0 ] && echo "все конфигурации приняты ядрами: $(ls "$W"/cfg | wc -l)"
exit $fail
