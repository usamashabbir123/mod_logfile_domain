# **mod_logfile_domain**
### *Per-Domain Logging Module for FreeSWITCH*

`mod_logfile_domain` is a custom FreeSWITCH module designed to generate **separate log files for each SIP domain**, making **multi-tenant debugging, tracing, and auditing significantly easier**.

It extends the default `mod_logfile` behavior by intelligently creating and managing **domain-specific logging profiles** with minimal performance overhead.

---

## 🚀 **Features**

- 📁 **Automatic Per-Domain Log File Creation**  
  Each domain gets its own log file stored at:
  
/usr/local/freeswitch/log/<domain>.log

- 🔎 **Accurate Domain Detection** using:
- SIP UUID metadata  
- SIP message headers  
- Profile → Domain mapping  

- ⚡ **Built-in Domain Lookup Cache**  
Ensures high performance and reduced lookup overhead.

- 🔄 **Supports Log Rotation**  
Integrates smoothly with existing FreeSWITCH rotation systems.

- 🧩 **Fully Compatible with Default `mod_logfile` Module**  
Works alongside the standard module without conflicts.

---


---

## 🛠️ **Installation Instructions**

### **1️⃣ Clone the Repository**
```bash
git clone https://github.com/usamashabbir123/mod_logfile_domain.git
Note: Adjust the FreeSWITCH source directory in install_mod_logfile_domain.sh according to your FreeSWITCH version.
Example:
FS_SRC="/usr/src/freeswitch-1.10.11"
Change this if your FreeSWITCH source directory is different.

Run the Installer Script

chmod +x install_mod_logfile_domain.sh
sudo bash ./install_mod_logfile_domain.sh
Verify Module Installation
fs_cli -x "module_exists mod_logfile_domain"


