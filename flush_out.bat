@echo off
@setlocal enabledelayedexpansion

:: Принимаем переменную из GUI интерфейса
SET IP_S=%1
set DNS_PRI=%2
set DNS_SEC=%3

:: Сокращаем параметр пути в реестре к сетевым профилям 
set root=HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles

:: Удаляем маршрут к прокси-серверу
route delete %IP_S%

:: Находим сетевой профиль в реестре, созданный интерфейсом tun2socks
FOR /F "usebackq delims=\ tokens=8 " %%a IN (`reg query "%root%" /s /f "gateway" ^|findstr "HKEY" `) do (
 set tun_profile=%%a
)

:: Удаляем сетевой профиль из реестра, если параметр истинный удаляется без подтверждения, если ложный на любые запросы подтверждения отвечаем "нет"
echo N|reg delete "%root%\%tun_profile%" /f

:: Возвращаем сохраненные настройки DNS из файла dns-saved.txt

:: Если настройки не применялись идем на метку exit
IF "%2" EQU "" goto :exit

:: Находим индекс основного шлюза
FOR /F "usebackq tokens=1" %%a IN (`find "0.0.0.0/0" def-gw-info.txt`) do (
 set IF_INDX=%%a
)

:: Идем в файл dns-saved.txt за предыдущими настройками DNS
FOR /F "usebackq tokens=3" %%a IN (`find "NameServer" dns-saved.txt`) do (
 set DNS_PR=%%a
)

:: Если настройки DNS Автоматически DHCP переходим на метку next
IF "%DNS_PR%" == "DHCP" goto :next

:: Возвращаем прежний DNS
powershell -command Set-DnsClientServerAddress -InterfaceIndex !IF_INDX! -ServerAddresses ('!DNS_PR!')
ipconfig /flushdns

exit

:next
:: Возвращаем настройки DNS в Автоматический DHCP режим
powershell -command Set-DnsClientServerAddress -InterfaceIndex !IF_INDX! -ResetServerAddresses

:exit
exit