@echo off
:: Frame settings
mode con: cols=100 lines=40
Title "CCDC Windows Script"

::Generic Firewall rules
netsh advfirewall firewall set rule name="Web State" new dir=out action=allow enable=no profile=any remoteip=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall set rule name="DNS State" new dir=out action=allow enable=no profile=any remoteport=53 protocol=udp
