# **mod_logfile_domain**  
### *Per-Domain Logging Module for FreeSWITCH*

`mod_logfile_domain` is an enhanced logging module for FreeSWITCH that creates **separate log files per SIP domain**, making multi-tenant debugging significantly easier.  
It extends the default `mod_logfile` module by automatically generating and managing domain-specific log profiles.

---

## 🚀 **Features**

- 📁 **Automatic log creation per domain**  
  Logs stored under:
/usr/local/freeswitch/log/<domain>.log


- 🔎 **Accurate domain detection** using:
- UUID metadata  
- SIP message headers  
- Profile/domain mapping

- ⚡ **Domain lookup cache** for high performance

- 🔄 **Log rotation support**

- 🧩 **Works alongside the default `mod_logfile` module**

---

## 📂 **Directory Structure**

mod_logfile_domain/
│
├── conf/
│ └── autoload_configs/
│ └── logfile_domain.conf.xml
│
├── mod_logfile_domain.c
├── Makefile.am
└── README.md

---

## 🛠️ **Installation Instructions**

### 1️⃣ Clone the repository
```bash

git clone https://github.com/usamashabbir123/mod_logfile_domain.git
chmod +X install_mod_logfile_domain.sh
sudo bash ./install_mod_logfile_domain.sh
fs_cli -x "module_exists mod_logfile_domain


In case of a non-tenant solution:
The file name will be the IP address.

The following domain names are not allowed.

The module will skip creating log files for these domain names:
invalid
freeswitch
example.com
example.org
test.
.test
default