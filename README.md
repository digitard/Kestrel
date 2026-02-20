# Kestrel

```
██   ██ ███████  ██████   █████ ██████  ███████ ██
██  ██  ██      ██         ██    ██   ██ ██      ██
█████   █████    █████     ██    ██████  █████   ██
██  ██  ██           ██    ██    ██   ██ ██      ██
██   ██ ███████ ██████     ██    ██   ██ ███████ ███████
                                    OTS - Own the System
```

**LLM-Assisted Bug Bounty Hunting Platform for Kali Linux**

> ⚠️ **This tool is for authorized bug bounty hunting only.** Only use on programs where you have explicit permission.

## Overview

Kestrel automates the discovery, validation, and exploitation of vulnerabilities in authorized bug bounty programs. It integrates with platforms like HackerOne and Bugcrowd, enforces strict scope validation, and **requires human authorization for all exploitation attempts**.

Built following the "Intent is the New Skill" methodology - where human operators provide high-level intent and AI handles the technical execution.

## Features

- 🎯 **Platform Integration** - Connect to HackerOne, Bugcrowd, and more
- 🔍 **Automated Recon** - Native Kali tool execution (nmap, gobuster, nikto, etc.)
- 🔗 **CVE Correlation** - Match findings to known vulnerabilities
- 🤖 **LLM-Assisted Analysis** - Intelligent exploit planning with Claude
- 🛡️ **Authorization Gate** - Human approval required for all exploits
- 📊 **Web Dashboard** - Visual program browsing and hunt management
- 📝 **Report Generation** - Platform-ready submission reports

## Requirements

- **Kali Linux** (tested on 2024.x)
- **Python 3.11+**
- **Anthropic API Key** (for LLM features)
- **Platform API Keys** (HackerOne, Bugcrowd)

## Quick Start

```bash
# Clone the repository
git clone https://github.com/example/kestrel.git
cd kestrel

# Check tool availability
./toolcheck.sh --install

# Install Python dependencies
pip install -e ".[dev]"

# Configure credentials
export ANTHROPIC_API_KEY="your-key-here"
export HACKERONE_API_KEY="your-key-here"
export HACKERONE_USERNAME="your-username"

# Run the application
kestrel
```

## Safety

Kestrel enforces multiple safety measures:

1. **Scope Validation** - Every action validates against program scope
2. **Authorization Gate** - Human approval required before any exploit
3. **Audit Logging** - All actions logged with timestamps
4. **Rate Limiting** - Respects program-specific rate limits
5. **Fail Closed** - Any validation error = deny

## Documentation

- [Project Documentation](PROJECT_DOCUMENTATION.md) - Full architecture and phase plan
- [Project Journal](PROJECT_JOURNAL.md) - Development history and decisions

## Development Status

**Current Version:** 0.3.0.2 (Phase 1 Complete — Execution Layer + LLM Infrastructure)

See [PROJECT_DOCUMENTATION.md](PROJECT_DOCUMENTATION.md) for the full phase plan.

## License

GNU General Public License v3 — See [LICENSE](LICENSE) for details.

Copyright (C) 2026 David Kuznicki and Kestrel Contributors

## Disclaimer

This tool is designed for **authorized security testing only**. Users are responsible for ensuring they have proper authorization before testing any target. The developers assume no liability for misuse.

---

*Built with the "Intent is the New Skill" methodology*
