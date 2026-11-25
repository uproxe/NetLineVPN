# История изменений

Формат — [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/), версии — [SemVer](https://semver.org/lang/ru/).

## [1.0.0] — 2026-11-25

Первая версия.

- Одна кнопка «Подключить»: VPN для всего устройства или системный прокси (Windows, macOS, Linux), VPN на Android.
- Протоколы: VLESS (Reality, Vision, XHTTP, WebSocket, gRPC, HTTPUpgrade, VLESS Encryption), VMess, Trojan,
  Shadowsocks (в том числе 2022 и obfs), Hysteria2 (со сменой портов), Hysteria, TUIC, AnyTLS, NaiveProxy, SSH,
  WireGuard, OpenVPN, OpenConnect (Cisco AnyConnect, Fortinet, GlobalProtect и др.), SOCKS5, HTTP и HTTPS-прокси.
- Подписки: список ссылок, base64, JSON Xray и sing-box; объём трафика и срок действия; обновление раз в 12 часов.
- Импорт файлов WireGuard (.conf) и OpenVPN (.ovpn), прокси вручную.
- «Самый быстрый» сервер подписки выбирается сам и меняется, если перестал отвечать.
- Проверка задержки всех серверов настоящим подключением.
- «Российские сайты напрямую» — банки и Госуслуги открываются без VPN.
- Значок в области уведомлений, автозапуск, подключение при запуске; плитка в быстрых настройках Android.
- Ядра: sing-box 1.14.4, Xray 26.11.9.
