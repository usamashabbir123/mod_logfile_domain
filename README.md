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

cp -r mod_logfile_domain /usr/src/freeswitch-1.10.11/src/mod/loggers/


sudo cp mod_logfile_domain/conf/autoload_configs/logfile_domain.conf.xml \
    /etc/freeswitch/autoload_configs/


cd /usr/src/freeswitch-1.10.11
make mod_logfile_domain-clean
make mod_logfile_domain
make mod_logfile_domain-install

sudo cp /usr/src/freeswitch-1.10.11/src/mod/loggers/mod_logfile_domain/.libs/mod_logfile_domain.so \
    /usr/lib/freeswitch/mod/

systemctl restart freeswitch
fs_cli -x "reload mod_logfile_domain"
