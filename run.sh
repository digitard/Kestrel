#!/bin/bash
#
# Kestrel Startup Script
#
# Usage: ./run.sh [--dev]
#   --dev    Run in development mode with auto-reload
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Read version
VERSION=$(cat VERSION 2>/dev/null || echo "0.0.0.1")

# Print banner
echo -e "${CYAN}"
cat << 'EOF'
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║    ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗                    ║
║    ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝                    ║
║    ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝                     ║
║    ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝                      ║
║    ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║                       ║
║    ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝                       ║
║                                                                              ║
║    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗                       ║
║    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗                      ║
║    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝                      ║
║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗                      ║
║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║                      ║
║    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝                      ║
║                                                                              ║
║                   LLM-Assisted Bug Bounty Hunting                            ║
EOF
printf "║                          Version %-10s                               ║\n" "$VERSION"
cat << 'EOF'
║                                                                              ║
║   ⚠️  For authorized bug bounty programs only                                ║
║   🔒 Human authorization required for all exploits                           ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check for required environment variables
check_env() {
    echo -e "${BLUE}[*] Checking environment...${NC}"
    
    if [ -z "$ANTHROPIC_API_KEY" ]; then
        echo -e "${YELLOW}    ⚠ ANTHROPIC_API_KEY not set (LLM features disabled)${NC}"
    else
        echo -e "${GREEN}    ✓ ANTHROPIC_API_KEY configured${NC}"
    fi
    
    if [ -z "$HACKERONE_API_KEY" ]; then
        echo -e "${YELLOW}    ⚠ HACKERONE_API_KEY not set (HackerOne disabled)${NC}"
    else
        echo -e "${GREEN}    ✓ HACKERONE_API_KEY configured${NC}"
    fi
    
    if [ -z "$BUGCROWD_API_KEY" ]; then
        echo -e "${YELLOW}    ⚠ BUGCROWD_API_KEY not set (Bugcrowd disabled)${NC}"
    else
        echo -e "${GREEN}    ✓ BUGCROWD_API_KEY configured${NC}"
    fi
    
    echo ""
}

# Run the application
run_app() {
    local reload_flag=""
    
    if [ "$1" == "--dev" ]; then
        echo -e "${GREEN}[*] Development mode enabled (auto-reload)${NC}"
        reload_flag="--reload"
    fi
    
    echo -e "${GREEN}[*] Starting Kestrel on http://127.0.0.1:8080${NC}"
    echo -e "${BLUE}[*] Press Ctrl+C to stop${NC}"
    echo ""
    
    # Run with uvicorn
    python -m uvicorn kestrel.api.main:app \
        --host 127.0.0.1 \
        --port 8080 \
        $reload_flag
}

# Main
check_env
run_app "$1"
