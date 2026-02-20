#!/bin/bash
#
# Kestrel Tool Check Script
# Verifies Kali Linux environment and required tools
#
# Usage: ./toolcheck.sh [--install]
#   --install    Attempt to install missing tools via apt
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Track status
MISSING_TOOLS=()
FOUND_TOOLS=()

echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║              Kestrel Tool Check v0.0.0.1                ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# ----------------------------------------------------------------------------
# Check if running on Kali Linux
# ----------------------------------------------------------------------------
check_kali() {
    echo -e "${BLUE}[*] Checking operating system...${NC}"
    
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" == "kali" ]]; then
            echo -e "${GREEN}[✓] Running on Kali Linux ($VERSION)${NC}"
            return 0
        fi
    fi
    
    echo -e "${RED}[✗] Not running on Kali Linux${NC}"
    echo -e "${YELLOW}    Kestrel requires Kali Linux for native tool execution.${NC}"
    echo -e "${YELLOW}    Please install Kali or run in a Kali VM.${NC}"
    return 1
}

# ----------------------------------------------------------------------------
# Check Python version
# ----------------------------------------------------------------------------
check_python() {
    echo -e "\n${BLUE}[*] Checking Python version...${NC}"
    
    if command -v python3 &> /dev/null; then
        PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
        PY_MAJOR=$(echo $PY_VERSION | cut -d. -f1)
        PY_MINOR=$(echo $PY_VERSION | cut -d. -f2)
        
        if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
            echo -e "${GREEN}[✓] Python $PY_VERSION found${NC}"
            return 0
        else
            echo -e "${RED}[✗] Python $PY_VERSION found, but 3.11+ required${NC}"
            return 1
        fi
    else
        echo -e "${RED}[✗] Python 3 not found${NC}"
        return 1
    fi
}

# ----------------------------------------------------------------------------
# Check for a single tool
# ----------------------------------------------------------------------------
check_tool() {
    local tool=$1
    local package=${2:-$1}  # Package name if different from tool name
    
    if command -v "$tool" &> /dev/null; then
        local version=$($tool --version 2>&1 | head -n1 || echo "version unknown")
        echo -e "${GREEN}[✓] $tool${NC} - $version"
        FOUND_TOOLS+=("$tool")
        return 0
    else
        echo -e "${RED}[✗] $tool${NC} - not found (package: $package)"
        MISSING_TOOLS+=("$package")
        return 1
    fi
}

# ----------------------------------------------------------------------------
# Check all required tools
# ----------------------------------------------------------------------------
check_tools() {
    echo -e "\n${BLUE}[*] Checking security tools...${NC}"
    echo ""
    
    echo -e "${YELLOW}--- Reconnaissance ---${NC}"
    check_tool "nmap" "nmap"
    check_tool "masscan" "masscan"
    check_tool "subfinder" "subfinder"
    check_tool "amass" "amass"
    
    echo ""
    echo -e "${YELLOW}--- Web Enumeration ---${NC}"
    check_tool "gobuster" "gobuster"
    check_tool "feroxbuster" "feroxbuster"
    check_tool "nikto" "nikto"
    check_tool "dirb" "dirb"
    
    echo ""
    echo -e "${YELLOW}--- Vulnerability Scanning ---${NC}"
    check_tool "nuclei" "nuclei"
    check_tool "searchsploit" "exploitdb"
    
    echo ""
    echo -e "${YELLOW}--- Exploitation ---${NC}"
    check_tool "sqlmap" "sqlmap"
    check_tool "curl" "curl"
    check_tool "wget" "wget"
    
    echo ""
    echo -e "${YELLOW}--- Fingerprinting ---${NC}"
    check_tool "whatweb" "whatweb"
    check_tool "httpx" "httpx-toolkit"
    
    echo ""
    echo -e "${YELLOW}--- Utilities ---${NC}"
    check_tool "jq" "jq"
    check_tool "netcat" "netcat-openbsd"
}

# ----------------------------------------------------------------------------
# Install missing tools
# ----------------------------------------------------------------------------
install_missing() {
    if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
        echo -e "\n${GREEN}[✓] All tools are installed!${NC}"
        return 0
    fi
    
    echo -e "\n${YELLOW}[!] Missing tools: ${MISSING_TOOLS[*]}${NC}"
    
    if [ "$1" == "--install" ]; then
        echo -e "\n${BLUE}[*] Attempting to install missing tools...${NC}"
        
        # Update package list
        sudo apt update
        
        # Install each missing package
        for package in "${MISSING_TOOLS[@]}"; do
            echo -e "${BLUE}[*] Installing $package...${NC}"
            if sudo apt install -y "$package"; then
                echo -e "${GREEN}[✓] Installed $package${NC}"
            else
                echo -e "${RED}[✗] Failed to install $package${NC}"
            fi
        done
        
        echo -e "\n${BLUE}[*] Re-checking tools after installation...${NC}"
        MISSING_TOOLS=()
        FOUND_TOOLS=()
        check_tools
    else
        echo -e "\n${YELLOW}Run with --install to attempt automatic installation:${NC}"
        echo -e "${YELLOW}  ./toolcheck.sh --install${NC}"
        return 1
    fi
}

# ----------------------------------------------------------------------------
# Print summary
# ----------------------------------------------------------------------------
print_summary() {
    echo ""
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}                           SUMMARY                              ${NC}"
    echo -e "${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "Found:   ${GREEN}${#FOUND_TOOLS[@]}${NC} tools"
    echo -e "Missing: ${RED}${#MISSING_TOOLS[@]}${NC} tools"
    echo ""
    
    if [ ${#MISSING_TOOLS[@]} -eq 0 ]; then
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║          Environment ready for Kestrel!                 ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
        return 0
    else
        echo -e "${YELLOW}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${YELLOW}║     Some tools missing - Kestrel may have limited      ║${NC}"
        echo -e "${YELLOW}║     functionality. Install missing tools for full support.  ║${NC}"
        echo -e "${YELLOW}╚══════════════════════════════════════════════════════════════╝${NC}"
        return 1
    fi
}

# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
main() {
    # Check Kali
    if ! check_kali; then
        exit 1
    fi
    
    # Check Python
    if ! check_python; then
        exit 1
    fi
    
    # Check tools
    check_tools
    
    # Handle missing tools
    install_missing "$1"
    
    # Print summary
    print_summary
}

main "$@"
