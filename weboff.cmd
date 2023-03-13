@echo off
::Generic Firewall rules
netsh advfirewall firewall set rule name="CCDC-Web Regional" new dir=out action=allow enable=no profile=any remoteip=any remoteport=80,443 protocol=tcp
netsh advfirewall firewall set rule name="CCDC-DNS Regional" new dir=out action=allow enable=no profile=any remoteport=53 protocol=udp
