#!/bin/bash
# ═══════════════════════════════════════════════════════════════
#   WebVulnScan Suite - Linux Installer
# ═══════════════════════════════════════════════════════════════
#   Installs: webvulnscan, headerscanner, techdetector, portsubscan
# ═══════════════════════════════════════════════════════════════

set -e
BOLD="\033[1m"; G="\033[92m"; Y="\033[93m"; R="\033[91m"; CY="\033[96m"; X="\033[0m"

INSTALL_DIR="/opt/webvulnscan-suite"
BIN_DIR="/usr/local/bin"

echo -e "${CY}${BOLD}"
echo " ╔══════════════════════════════════════════════════════════════╗"
echo " ║        WebVulnScan Suite - Linux Installer                   ║"
echo " ║     webvulnscan + headerscanner + techdetector + portsubscan ║"
echo " ╚══════════════════════════════════════════════════════════════╝"
echo -e "${X}"

[[ $EUID -ne 0 ]] && { echo -e "${R}[!] Please run as root:  sudo bash install.sh${X}"; exit 1; }

# Package manager detect
if   command -v apt     >/dev/null 2>&1; then PM="apt"
elif command -v pacman  >/dev/null 2>&1; then PM="pacman"
elif command -v dnf     >/dev/null 2>&1; then PM="dnf"
elif command -v yum     >/dev/null 2>&1; then PM="yum"
elif command -v apk     >/dev/null 2>&1; then PM="apk"
else echo -e "${R}[!] No supported package manager found.${X}"; exit 1
fi
echo -e "${CY}[*] Package manager: ${PM}${X}"

# Python install
echo -e "${CY}[*] Installing Python3 and pip...${X}"
case $PM in
    apt)    apt update -qq && apt install -y python3 python3-pip >/dev/null 2>&1 ;;
    pacman) pacman -Sy --noconfirm python python-pip >/dev/null 2>&1 ;;
    dnf)    dnf install -y python3 python3-pip >/dev/null 2>&1 ;;
    yum)    yum install -y python3 python3-pip >/dev/null 2>&1 ;;
    apk)    apk add python3 py3-pip >/dev/null 2>&1 ;;
esac

# Python deps
echo -e "${CY}[*] Installing Python dependencies (requests, urllib3)...${X}"
pip3 install --quiet --break-system-packages requests urllib3 2>/dev/null || \
pip3 install --quiet requests urllib3 2>/dev/null || \
python3 -m pip install --quiet --user requests urllib3

# Copy files
echo -e "${CY}[*] Installing tools to ${INSTALL_DIR}...${X}"
mkdir -p "$INSTALL_DIR/extra_tools"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
for f in webvulnscan.py portsubscan.py; do
    [[ -f "$SCRIPT_DIR/$f" ]] && install -m 0755 "$SCRIPT_DIR/$f" "$INSTALL_DIR/$f"
done
for f in headerscanner.py techdetector.py; do
    [[ -f "$SCRIPT_DIR/extra_tools/$f" ]] && install -m 0755 "$SCRIPT_DIR/extra_tools/$f" "$INSTALL_DIR/extra_tools/$f"
done
[[ -f "$SCRIPT_DIR/README.md" ]] && install -m 0644 "$SCRIPT_DIR/README.md" "$INSTALL_DIR/README.md"

# Launchers
echo -e "${CY}[*] Creating command launchers...${X}"
cat > "$BIN_DIR/webvulnscan"  <<EOF
#!/bin/bash
exec python3 $INSTALL_DIR/webvulnscan.py "\$@"
EOF
cat > "$BIN_DIR/headerscanner" <<EOF
#!/bin/bash
exec python3 $INSTALL_DIR/extra_tools/headerscanner.py "\$@"
EOF
cat > "$BIN_DIR/techdetector"  <<EOF
#!/bin/bash
exec python3 $INSTALL_DIR/extra_tools/techdetector.py "\$@"
EOF
cat > "$BIN_DIR/portsubscan"   <<EOF
#!/bin/bash
exec python3 $INSTALL_DIR/portsubscan.py "\$@"
EOF
chmod +x "$BIN_DIR/webvulnscan" "$BIN_DIR/headerscanner" "$BIN_DIR/techdetector" "$BIN_DIR/portsubscan"

echo
echo -e "${G}${BOLD} ╔══════════════════════════════════════════════════════════════╗"
echo -e " ║   ✅  Suite Installed Successfully!                          ║"
echo -e " ╚══════════════════════════════════════════════════════════════╝${X}"
echo
echo -e "${BOLD}Available commands:${X}"
echo -e "  ${CY}webvulnscan${X}   - Full vulnerability scan (XSS, SQLi, LFI, ...)"
echo -e "  ${CY}headerscanner${X} - HTTP security headers audit + grade"
echo -e "  ${CY}techdetector${X}  - CMS/framework/JS library fingerprinting"
echo -e "  ${CY}portsubscan${X}   - Port + subdomain + DNS discovery"
echo
echo -e "${BOLD}Examples:${X}"
echo -e "  ${CY}webvulnscan -u https://target.com --full -o report.html${X}"
echo -e "  ${CY}headerscanner -u https://target.com -o header.json${X}"
echo -e "  ${CY}techdetector -u https://target.com -o tech.json${X}"
echo -e "  ${CY}portsubscan -t target.com --full -o recon.json${X}"
echo
echo -e "${BOLD}Uninstall:${X}  ${CY}sudo bash uninstall.sh${X}"

