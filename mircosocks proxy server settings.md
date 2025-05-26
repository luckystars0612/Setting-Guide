## Installation
- Download and build
```bash
git clone https://github.com/rofl0r/microsocks.git
cd microsocks
make
sudo make install
```
- Move it to path
```bash
mv microsocks /usr/local/bin
```
## Setup service
- Create service config
```bash
nano /etc/systemd/system/microsocks.service
```
```bash
# /etc/systemd/system/microsocks.service
[Unit]
Description=Microsocks SOCKS5 Proxy
After=network.target

[Service]
ExecStart=/usr/local/bin/microsocks -u username -P password
Restart=always
User=nobody
Group=nogroup

[Install]
WantedBy=multi-user.target
```
- Reload deamon and run service
```bash
sudo systemctl daemon-reload
sudo systemctl enable --now microsocks
sudo systemctl start microsocks.service
```
- Check microsocks service
```bash
sudo systemctl status microsocks.service
```
