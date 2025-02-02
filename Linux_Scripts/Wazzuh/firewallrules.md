# Wazuh Server/Indexer: firewall rules

- [ ] ports 9200, 1515, 55000, 1514 must be open on wazuh server for single node indexer,server,dashboard. Also open https port for dashboard if we are going to access from another host

## firewalld

```bash
sudo firewall-cmd --permanent --add-port=9200/tcp
sudo firewall-cmd --permanent --add-port=1514/tcp
sudo systemctl restart firewalld
```

Wazuh server
| Port | protocol | Service|
|------|:--------:|-------:|
| 1514 | TCP | Agent Connection (default)
| 1514 | UDP | Agent Connection (optional)
| 1515 | TCP | Agent Enrollment Service
| 1516 | TCP | Wazuh cluster daemon
| 514 | UDP | Wazuh Syslog collector (optional)
| 55000 | TCP | Wazuh RESTful API

Wazuh indexer
| Port | protocol | Service|
|------|:--------:|-------:|
| 9200 | TCP | indexer RESTful API
| 9300-9400 | TCP | index cluster communication

Wazuh dashboard
| Port | protocol | Service|
|------|:--------:|-------:|
| 443 | TCP | Wazuh web interface

- [ ] in my script I set the wazuh interface to 9000
