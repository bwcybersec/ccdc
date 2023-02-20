@echo off
Title "CCDC Windows Script"

::Generic Firewall rules
netsh advfirewall firewall set rule name="CCDC-Web State" new dir=out action=allow enable=yes profile=any remoteip=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall set rule name="CCDC-DNS State" new dir=out action=allow enable=yes profile=any remoteport=53 protocol=udp
