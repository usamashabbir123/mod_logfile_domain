#!/bin/bash
# ------------------------------------------------------------
#  Production Installer for mod_logfile_domain
# ------------------------------------------------------------

set -e

# Configuration
FS_SRC="/usr/src/freeswitch-1.10.11"
MODULE_DIR="$FS_SRC/src/mod/loggers"
FS_MOD_DIR="/usr/lib/freeswitch/mod"
AUTOLOAD="/etc/freeswitch/autoload_configs"
MODULES_CONF="$AUTOLOAD/modules.conf.xml"
REPO_URL="https://github.com/usamashabbir123/mod_logfile_domain.git"
MODULE_NAME="mod_logfile_domain"

echo "============================================================"
echo " Installing mod_logfile_domain for FreeSWITCH "
echo "============================================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "ERROR: Please run as root (sudo)"
    exit 1
fi

# Check if FreeSWITCH source exists
if [ ! -d "$FS_SRC" ]; then
    echo "ERROR: FreeSWITCH source not found at $FS_SRC"
    exit 1
fi

# 1. Clone Repository
echo "[1/9] Cloning repository..."
cd /tmp
rm -rf mod_logfile_domain
git clone "$REPO_URL"

# 2. Copy module source
echo "[2/9] Copying module source to FreeSWITCH directory..."
rm -rf "$MODULE_DIR/mod_logfile_domain"
cp -r mod_logfile_domain "$MODULE_DIR/"

# 3. Register module in modules.conf (build-time)
echo "[3/9] Registering module in build configuration..."
MODULES_CONF_BUILD="$FS_SRC/modules.conf"

if [ -f "$MODULES_CONF_BUILD" ]; then
    if ! grep -q "loggers/mod_logfile_domain" "$MODULES_CONF_BUILD"; then
        echo "loggers/mod_logfile_domain" >> "$MODULES_CONF_BUILD"
        echo "   - Added to modules.conf"
    else
        echo "   - Already registered in modules.conf"
    fi
else
    echo "ERROR: $MODULES_CONF_BUILD not found"
    exit 1
fi

# 4. Add module to Makefile.am in loggers directory
echo "[4/9] Updating Makefile.am..."
MAKEFILE_AM="$MODULE_DIR/Makefile.am"

if [ -f "$MAKEFILE_AM" ]; then
    # Backup original
    cp "$MAKEFILE_AM" "$MAKEFILE_AM.backup"
    
    # Check if module already exists
    if ! grep -q "mod_logfile_domain" "$MAKEFILE_AM"; then
        # Add module to the list (after mod_logfile if it exists)
        sed -i '/mod_logfile.la/a mod_logfile_domain.la \\' "$MAKEFILE_AM"
        echo "   - Added to Makefile.am"
    else
        echo "   - Already in Makefile.am"
    fi
else
    echo "WARNING: $MAKEFILE_AM not found, will try direct compilation"
fi

# 5. Re-run bootstrap and configure if needed
echo "[5/9] Reconfiguring build system..."
cd "$FS_SRC"

# Run bootstrap to regenerate build files
if [ -f "bootstrap.sh" ]; then
    ./bootstrap.sh -j 2>&1 | tail -20
elif [ -f "rebootstrap.sh" ]; then
    ./rebootstrap.sh -j 2>&1 | tail -20
fi

# 6. Build Module
echo "[6/9] Building module..."
cd "$FS_SRC"

# Clean any previous builds
make mod_logfile_domain-clean 2>/dev/null || true

# Build the module
if ! make mod_logfile_domain; then
    echo "ERROR: Module compilation failed"
    exit 1
fi

# Install the module
make mod_logfile_domain-install

# 7. Verify .so file was created
echo "[7/9] Verifying compiled module..."
SO_FILE="$MODULE_DIR/mod_logfile_domain/.libs/mod_logfile_domain.so"

if [ -f "$SO_FILE" ]; then
    echo "   - Module compiled successfully"
    # Copy to FreeSWITCH module directory as backup
    cp "$SO_FILE" "$FS_MOD_DIR/"
    chmod 755 "$FS_MOD_DIR/mod_logfile_domain.so"
else
    echo "ERROR: .so file not found at $SO_FILE"
    exit 1
fi

# 8. Install XML configuration
echo "[8/9] Installing XML configuration..."
if [ -f "/tmp/mod_logfile_domain/conf/autoload_configs/logfile_domain.conf.xml" ]; then
    cp /tmp/mod_logfile_domain/conf/autoload_configs/logfile_domain.conf.xml "$AUTOLOAD/"
    chmod 644 "$AUTOLOAD/logfile_domain.conf.xml"
    echo "   - Configuration installed"
else
    echo "WARNING: Configuration file not found, you may need to create it manually"
fi

# 9. Register module in modules.conf.xml (runtime)
echo "[9/9] Registering module in runtime configuration..."
if grep -q 'mod_logfile_domain' "$MODULES_CONF"; then
    echo "   - Already registered in modules.conf.xml"
else
    # Add after mod_logfile or in loggers section
    if grep -q 'mod_logfile' "$MODULES_CONF"; then
        sed -i '/<load module="mod_logfile"\/>/a \    <load module="mod_logfile_domain"\/>' "$MODULES_CONF"
    else
        # Find loggers section and add there
        sed -i '/<!\-\- Loggers \-\->/a \    <load module="mod_logfile_domain"\/>' "$MODULES_CONF"
    fi
    echo "   - Module registered in modules.conf.xml"
fi

# 10. Restart FreeSWITCH
echo ""
echo "============================================================"
echo " Build Complete - Restarting FreeSWITCH..."
echo "============================================================"
systemctl restart freeswitch
sleep 5

# 11. Verification
echo ""
echo "Verifying module load..."
if fs_cli -x "module_exists mod_logfile_domain" 2>/dev/null | grep -q "true"; then
    echo "============================================================"
    echo " ✓ SUCCESS: mod_logfile_domain installed and loaded!"
    echo "============================================================"
    exit 0
else
    echo "============================================================"
    echo " ⚠ WARNING: Module compiled but may not have loaded"
    echo " Check logs: tail -f /var/log/freeswitch/freeswitch.log"
    echo "============================================================"
    echo ""
    echo "Manual load command: fs_cli -x 'load mod_logfile_domain'"
    exit 1
fi