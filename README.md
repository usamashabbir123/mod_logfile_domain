# mod_logfile_domain

A FreeSWITCH logging module that creates **separate log files per domain**.
It extends the behavior of the stock `mod_logfile` module by dynamically
creating log profiles based on SIP domain names.

## Features
- Automatic domain log generation: `/usr/local/freeswitch/log/<domain>.log`
- UUID-based domain detection
- SIP header domain extraction
- Cache for faster domain lookups
- Rotating logs per domain
- Mirrors the behavior of the original mod_logfile

## Directory Structure
