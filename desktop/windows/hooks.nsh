; NetLine VPN — дополнения к установщику Tauri (NSIS)

!macro NSIS_HOOK_PREINSTALL
  ; обновление поверх запущенной программы: ядра VPN держат файлы
  nsExec::Exec 'taskkill /F /IM netline-core.exe'
  nsExec::Exec 'taskkill /F /IM netline-helper.exe'
!macroend

!macro NSIS_HOOK_POSTINSTALL
  ; разрешение в брандмауэре Windows — чтобы при первом подключении не появлялся вопрос о сетевом доступе
  nsExec::Exec 'netsh advfirewall firewall delete rule name="NetLine VPN"'
  nsExec::Exec 'netsh advfirewall firewall add rule name="NetLine VPN" dir=in action=allow program="$INSTDIR\netline-core.exe" enable=yes profile=any'
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  nsExec::Exec 'taskkill /F /IM netline-core.exe'
  nsExec::Exec 'taskkill /F /IM netline-helper.exe'
  ; автозапуск и правило брандмауэра убираем только при настоящем удалении, не при обновлении
  ${If} $UpdateMode <> 1
    nsExec::Exec 'schtasks /Delete /TN "NetLine VPN" /F'
    nsExec::Exec 'netsh advfirewall firewall delete rule name="NetLine VPN"'
  ${EndIf}
!macroend
