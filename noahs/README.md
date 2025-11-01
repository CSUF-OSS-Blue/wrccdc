## Wazuh-Docker Walkthrough

This project provides scripts to deploy **Wazuh with Docker** quickly and reliably.

---

### Scripts

| File | Description |
|------|------------|
| `wazuh.py` | For **Windows** or environments where Bash may not work |
| `wazuh.sh` | For **Linux** machines (preferred if Python is not installed) |

---

### Commands

#### Run with Python
```bash
python3 wazuh.py
```

#### Run with Bash
```bash
bash wazuh.sh
# or
./wazuh.sh
```

> ⚠️ You may need to use `sudo`.  
> If you run the scripts with `sudo`, all Docker commands will also require `sudo` unless you add your user to the Docker group.

---

### Requirements

- ~20GB free disk space
- Docker & Docker Compose installed  
  Example (APT systems):
  ```bash
  sudo apt install docker-compose
  ```
- Git installed (required to download Wazuh Docker files)
- Add your user to Docker group if needed:
  ```bash
  sudo usermod -aG docker $USER
  ```
  *(Log out & back in after running this)*

- Running as root may work, but **not preferred** unless required

---

### Accessing the Wazuh Dashboard

Once deployment is complete, open:

```
https://<host-ip>:443
```

Example:
```
https://192.168.1.100:443
```

---

### Performance Note

> ⚠️ Wazuh uses a lot of RAM.  
Your system may slow down on low-memory hardware.

---

### Useful Docker Commands

| Command | Description |
|--------|-------------|
| `docker ps` | Show running containers |
| `docker-compose up -d` | Start all Wazuh containers *(script already does this)* |
| `docker-compose down` | Stop all Wazuh containers |

