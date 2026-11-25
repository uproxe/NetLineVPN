#!/bin/sh
# NetLine VPN: ядру sing-box нужно право настраивать сеть, чтобы включать VPN без пароля.
# Право выдаётся только самому ядру, а не всей программе.
if command -v setcap >/dev/null 2>&1; then
  setcap cap_net_admin,cap_net_raw,cap_net_bind_service+ep /usr/bin/netline-core 2>/dev/null || true
fi
command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database -q /usr/share/applications 2>/dev/null || true
exit 0
