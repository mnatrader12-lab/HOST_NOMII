#!/bin/bash
BOLD="\033[1m"; G="\033[92m"; R="\033[91m"; CY="\033[96m"; X="\033[0m"
[[ $EUID -ne 0 ]] && { echo -e "${R}[!] Please run as root:  sudo bash uninstall.sh${X}"; exit 1; }
echo -e "${CY}${BOLD}[*] Removing WebVulnScan Suite...${X}"
rm -rf /opt/webvulnscan-suite
rm -f  /usr/local/bin/webvulnscan /usr/local/bin/headerscanner /usr/local/bin/techdetector /usr/local/bin/portsubscan
echo -e "${G}${BOLD}[✓] All tools removed successfully.${X}"

