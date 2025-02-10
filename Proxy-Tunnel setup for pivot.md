## [Ligolo](https://github.com/nicocha30/ligolo-ng)
- Server 
```bash
proxy -selfcert
ifcreate --name ligolo
ifconfig
route_add --name ligolo --route 172.16.20.0/24
session
start
```
- Client
```bash
./agent -connect 10.10.16.67:11601 -ignore-cert
```

## [Sshuttle](https://github.com/sshuttle/sshuttle.git)
```bash
sshuttle -r ebelford@ip -N 172.16.20.0/24
password: ThePlague61780
c : Connected to server.
```

