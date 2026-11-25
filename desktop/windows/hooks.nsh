; NetLine VPN — дополнения к установщику Tauri (NSIS)

!macro NSIS_HOOK_PREINSTALL
  ; обновление поверх запущенной программы: ядра VPN держат файлы
  nsExec::Exec 'taskkill /F /IM netline-singbox.exe'
  nsExec::Exec 'taskkill /F /IM netline-xray.exe'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::Exec 'taskkill /F /IM netline-singbox.exe'
  nsExec::Exec 'taskkill /F /IM netline-xray.exe'
  ; автозапуск убираем только при настоящем удалении, не при обновлении
  ${If} $UpdateMode <> 1
    nsExec::Exec 'schtasks /Delete /TN "NetLine VPN" /F'
  ${EndIf}
!macroend
