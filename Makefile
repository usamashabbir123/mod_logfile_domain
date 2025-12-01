MODNAME = mod_logfile_domain
FS_SRC ?= /usr/src/freeswitch-1.10.11

LOCAL_CFLAGS =
LOCAL_LDFLAGS =

include $(FS_SRC)/build/modmake.rules

$(MODNAME).so: $(MODNAME).c
