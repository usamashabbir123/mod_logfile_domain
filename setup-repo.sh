#!/bin/bash

# Setup script for mod_logfile_domain GitHub repository
# This script creates the complete repository structure

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}mod_logfile_domain Repository Setup${NC}"
echo -e "${BLUE}========================================${NC}"
echo ""

# Create directory structure
echo -e "${YELLOW}Creating directory structure...${NC}"
mkdir -p conf/autoload_configs

# Create .gitignore
echo -e "${YELLOW}Creating .gitignore...${NC}"
cat > .gitignore << 'EOF'
# Compiled Object files
*.o
*.ko
*.obj
*.elf

# Precompiled Headers
*.gch
*.pch

# Libraries
*.lib
*.a
*.la
*.lo

# Shared objects (inc. Windows DLLs)
*.dll
*.so
*.so.*
*.dylib

# Executables
*.exe
*.out
*.app
*.i*86
*.x86_64
*.hex

# Debug files
*.dSYM/
*.su
*.idb
*.pdb

# Libtool
.libs/
.deps/

# Build directories
build/
.build/
*.build/

# Module build artifacts
*.slo
*.la
*.lo
.libs
Makefile.in
aclocal.m4
autom4te.cache
config.guess
config.h
config.h.in
config.log
config.status
config.sub
configure
depcomp
install-sh
libtool
ltmain.sh
missing
stamp-h1

# FreeSWITCH specific
*.core
core.*
.mod_*

# Editor files
*~
*.swp
*.swo
*.swn
.*.sw?
*.bak
*.orig
.vscode/
.idea/
*.sublime-*
.project
.cproject
.settings/

# OS files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db
Desktop.ini

# Logs (for testing)
*.log
*.log.*

# Temporary files
*.tmp
tmp/
temp/

# Package files
*.tar.gz
*.tgz
*.zip
*.rar
*.rpm
*.deb

# Documentation build
docs/_build/
*.pdf

# Test files
test_output/
test_*.log
EOF

# Create LICENSE
echo -e "${YELLOW}Creating LICENSE (MPL 1.1)...${NC}"
cat > LICENSE << 'EOF'
Mozilla Public License Version 1.1

1. Definitions.

    1.0.1. "Commercial Use" means distribution or otherwise making the
    Covered Code available to a third party.

    1.1. "Contributor" means each entity that creates or contributes to
    the creation of Modifications.

    1.2. "Contributor Version" means the combination of the Original
    Code, prior Modifications used by a Contributor, and the Modifications
    made by that particular Contributor.

    1.3. "Covered Code" means the Original Code or Modifications or the
    combination of the Original Code and Modifications, in each case
    including portions thereof.

    1.4. "Electronic Distribution Mechanism" means a mechanism generally
    accepted in the software development community for the electronic
    transfer of data.

    1.5. "Executable" means Covered Code in any form other than Source
    Code.

    1.6. "Initial Developer" means the individual or entity identified
    as the Initial Developer in the Source Code notice required by Exhibit
    A.

    1.7. "Larger Work" means a work which combines Covered Code or
    portions thereof with code not governed by the terms of this License.

    1.8. "License" means this document.

    1.8.1. "Licensable" means having the right to grant, to the maximum
    extent possible, whether at the time of the initial grant or
    subsequently acquired, any and all of the rights conveyed herein.

    1.9. "Modifications" means any addition to or deletion from the
    substance or structure of either the Original Code or any previous
    Modifications. When Covered Code is released as a series of files, a
    Modification is:
        A. Any addition to or deletion from the contents of a file
        containing Original Code or previous Modifications.

        B. Any new file that contains any part of the Original Code or
        previous Modifications.

    1.10. "Original Code" means Source Code of computer software code
    which is described in the Source Code notice required by Exhibit A as
    Original Code, and which, at the time of its release under this
    License is not already Covered Code governed by this License.

[... Full MPL 1.1 text ...]

For the complete license text, see:
https://www.mozilla.org/en-US/MPL/1.1/
EOF

# Create CONTRIBUTING.md
echo -e "${YELLOW}Creating CONTRIBUTING.md...${NC}"
cat > CONTRIBUTING.md << 'EOF'
# Contributing to mod_logfile_domain

Thank you for your interest in contributing! We welcome contributions from the community.

## How to Contribute

1. **Fork the Repository**
   ```bash
   git fork https://github.com/yourusername/mod_logfile_domain.git
   ```

2. **Create a Feature Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Your Changes**
   - Follow the coding style (ISO C90 compatible)
   - Add comments for complex logic
   - Test your changes thoroughly

4. **Commit Your Changes**
   ```bash
   git add .
   git commit -m "Description of your changes"
   ```

5. **Push to Your Fork**
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Submit a Pull Request**
   - Provide a clear description of your changes
   - Reference any related issues

## Coding Standards

- Use ISO C90 compatible code
- Follow FreeSWITCH coding conventions
- Use tabs for indentation (4 spaces)
- Maximum line length: 120 characters
- Add header comments for new functions
- Use meaningful variable names

## Testing

Before submitting:

1. Build the module without errors
   ```bash
   make clean
   make
   ```

2. Test with FreeSWITCH
   ```bash
   make install
   fs_cli -x "reload mod_logfile_domain"
   ```

3. Verify domain-specific logs are created
4. Test with multiple domains
5. Test log rotation functionality

## Reporting Issues

When reporting bugs, please include:

- FreeSWITCH version
- Operating system and version
- Steps to reproduce
- Expected vs actual behavior
- Relevant log excerpts

## Code of Conduct

- Be respectful and constructive
- Focus on the code, not the person
- Welcome newcomers
- Help others learn

Thank you for contributing!
EOF

echo -e "${GREEN}✓ Repository structure created successfully!${NC}"
echo ""
echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}Repository Structure:${NC}"
echo -e "${BLUE}========================================${NC}"
tree -L 2 -a 2>/dev/null || find . -type f -o -type d | grep -v '\.git' | sort

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Next Steps:${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo -e "1. ${YELLOW}Initialize Git repository:${NC}"
echo -e "   git init"
echo -e "   git add ."
echo -e "   git commit -m 'Initial commit'"
echo ""
echo -e "2. ${YELLOW}Create GitHub repository and push:${NC}"
echo -e "   git remote add origin https://github.com/yourusername/mod_logfile_domain.git"
echo -e "   git branch -M main"
echo -e "   git push -u origin main"
echo ""
echo -e "3. ${YELLOW}Build and test:${NC}"
echo -e "   make"
echo -e "   sudo make install"
echo ""
echo -e "${BLUE}Repository setup complete!${NC}"
EOF

chmod +x setup-repo.sh