# Wazuh Central Components Restoration Script

This repository provides a **Bash script** to restore Wazuh **Manager**, **Indexer**, and **Dashboard** components from backup archives.  
It is based on the [official Wazuh restoration guide](https://documentation.wazuh.com/current/migration-guide/restoring/wazuh-central-components.html#single-node-data-restoration).

---

## Features
- ✅ Automated restoration of:
  - Wazuh **Indexer** (config, security, data)
  - Wazuh **Dashboard** (config, data)
  - Wazuh **Manager** (config, var files, rules & decoders)
- ✅ Backup integrity verification with `sha256sum`
- ✅ Service stop/start handling
- ✅ Permission fixes after restoration
- ✅ Logging of all actions with timestamps

---

## Requirements
- Linux system with Wazuh installed  
- Root privileges (`sudo` or run as `root`)  
- Backup files placed in the defined backup directory  

Default paths:
- Backup directory: `/var/backups/wazuh-restore`
- Log file: `/var/log/wazuh_restore_<date>.log`

---

## Usage

1. Clone this repository:
   ```bash
   git clone https://github.com/enes-ismaili/wazuh-backup.git
   cd wazuh-backup
   chmod +x wazuh_restore.sh
   sudo ./wazuh_restore.sh

