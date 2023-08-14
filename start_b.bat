@echo off
@setlocal enabledelayedexpansion

:: Принимаем переменные из GUI интерфейса
set IP_S=%1
set DNS_PRI=%2
set DNS_SEC=%3

:: Назначаем имя и IP адрес сетевому интерфейсу tun2socks
netsh interface ip set address name="gateway" static 192.168.105.1 255.255.255.0 gateway=none

:: Находим индекс и адрес основного шлюза и записываем в файл def-gw-info.txt
powershell -command "(Get-NetRoute -ErrorAction SilentlyContinue -DestinationPrefix '0.0.0.0/0', '::/0' | Sort-Object -Property { $_.InterfaceMetric + $_.RouteMetric } | Select-Object -First 1) | Out-File def-gw-info.txt"

:: Назначаем переменную для индекса основного шлюза
FOR /F "usebackq tokens=1" %%a IN (`find "0.0.0.0/0" def-gw-info.txt`) do (
 set IF_INDX=%%a
)


:: Назначаем переменную для адреса основного шлюза
FOR /F "usebackq tokens=3" %%a IN (`find "0.0.0.0/0" def-gw-info.txt`) do (
 set DEF_GW=%%a
)


:: Находим индекс интерфейса tun2socks
powershell -command "Get-NetIPAddress -AddressFamily ipv4|ft | Out-File tun_if.txt"
FOR /F "usebackq tokens=1" %%a IN (`find "192.168.105.1" tun_if.txt`) do (
 set TUN_IF=%%a
)


:: Назначаем маршруты для tun2socks и прокси сервера
route add %IP_S% mask 255.255.255.255 !DEF_GW!
route add 0.0.0.0 mask 0.0.0.0 192.168.105.0 if "!TUN_IF!" metric 30
route add 0.0.0.0 mask 128.0.0.0 192.168.105.0 if "!TUN_IF!" metric 30
route add 128.0.0.0 mask 128.0.0.0 192.168.105.0 if "!TUN_IF!" metric 30

:: Если поле DNS1 пустое переходим на следующую метку :next
IF "%2" EQU "" goto :next

:: Сохраняем существующие настройки днс в файл dns-saved.txt
set root=HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces
FOR /F "usebackq delims=\ tokens=8 " %%a IN (`reg query "%root%" /s /f "!DEF_GW!" ^|findstr "HKEY" `) do (
 set def_gw_prof_profile=%%a
)

FOR /F "usebackq delims=" %%a IN (`reg query %root%\%def_gw_prof_profile% /s /f NameServer ^| findstr /V "DhcpNameServer :" `) do (
 set NameServer=%%a
)

echo %NameServer% DHCP > dns-saved.txt

:: Назначаем DNS с помошью PowerShell по индексу интерфейса
powershell -command Set-DnsClientServerAddress -InterfaceIndex !IF_INDX! -ServerAddresses ('!DNS_PRI!', '!DNS_SEC!')
ipconfig /flushdns

:next
exit

