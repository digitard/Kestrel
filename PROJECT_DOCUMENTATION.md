# BountyHunter - Project Documentation

**Project Name:** BountyHunter  
**Purpose:** Automated Bug Bounty Hunting with LLM Integration  
**Status:** In Development  
**Version:** 0.0.0.1  
**Started:** 2026-02-02  
**Last Updated:** 2026-02-02  

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Project Purpose](#project-purpose)
3. [Architecture Overview](#architecture-overview)
4. [Design Principles](#design-principles)
5. [Technology Stack](#technology-stack)
6. [Version Numbering](#version-numbering)
7. [Phase Plan](#phase-plan)
8. [Current Progress](#current-progress)
9. [File Structure](#file-structure)
10. [Testing Methodology](#testing-methodology)
11. [Security Considerations](#security-considerations)

---

## Executive Summary

BountyHunter is an LLM-assisted bug bounty hunting platform that automates the discovery, validation, and exploitation of vulnerabilities in **authorized bug bounty programs only**. Built for native Kali Linux execution, it integrates with platforms like HackerOne and Bugcrowd, enforces strict scope validation, and maintains human-in-the-loop authorization for all exploitation attempts.

**Core Principle:**
> **Authorized targets only, human-approved exploitation always.**

**This project is:**
- A parallel project to IntentSec (not a replacement)
- Built entirely through AI-assisted development (no manual coding by human operator)
- Native Kali Linux only (no Docker complexity)
- Includes a Web UI for bounty program management
- Potential conference talk material

---

## Project Purpose

### Primary Thesis
> "Intent is the New Skill" - Extended to bug bounty hunting. A human operator can effectively hunt for bounties by expressing intent to an AI agent, without needing to manually correlate CVEs, craft exploits, or navigate platform APIs.

### Goals
1. Aggregate and display bounty programs from major platforms (HackerOne, Bugcrowd)
2. Automate reconnaissance within authorized scope
3. Correlate discovered services with known CVEs
4. Generate exploit plans with LLM assistance
5. Require explicit human authorization before any exploit attempt
6. Generate submission-ready reports
7. Track earnings and submission history

### What This Is NOT
- Not a tool for unauthorized testing
- Not fully autonomous (human authorization required)
- Not a replacement for skilled researchers
- Not for script kiddies (requires understanding of what you're approving)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              BOUNTYHUNTER                                    │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                      WEB UI (localhost:8080)                         │   │
│   │  - Dashboard (stats, recent activity)                                │   │
│   │  - Program browser (filter, search, details)                         │   │
│   │  - Hunt management (start, monitor, authorize)                       │   │
│   │  - Report viewer (generated submissions)                             │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    │ REST API + WebSocket                    │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                      FASTAPI BACKEND                                 │   │
│   │  - /api/programs, /api/hunts, /api/findings, /api/reports           │   │
│   │  - /ws/hunt/{id} (real-time progress)                               │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                         CORE ENGINE                                  │   │
│   │                                                                      │   │
│   │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────────┐  │   │
│   │  │  Platform   │ │   Scope     │ │    CVE      │ │   Exploit     │  │   │
│   │  │  Clients    │ │  Validator  │ │ Correlator  │ │   Planner     │  │   │
│   │  │ (H1, BC)    │ │  (CRITICAL) │ │ (NVD, EDB)  │ │  (LLM-based)  │  │   │
│   │  └─────────────┘ └─────────────┘ └─────────────┘ └───────────────┘  │   │
│   │                                                                      │   │
│   │  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌───────────────┐  │   │
│   │  │   Native    │ │    LLM      │ │   Report    │ │    Session    │  │   │
│   │  │  Executor   │ │ (Anthropic) │ │  Generator  │ │    Manager    │  │   │
│   │  │ (subprocess)│ │             │ │             │ │               │  │   │
│   │  └─────────────┘ └─────────────┘ └─────────────┘ └───────────────┘  │   │
│   │                                                                      │   │
│   │  ┌──────────────────────────────────────────────────────────────┐   │   │
│   │  │              AUTHORIZATION GATE (Human Required)              │   │   │
│   │  │  - Displays exploit plan                                      │   │   │
│   │  │  - Shows exact commands                                       │   │   │
│   │  │  - Requires explicit approval                                 │   │   │
│   │  │  - Logs all decisions                                         │   │   │
│   │  └──────────────────────────────────────────────────────────────┘   │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                    │                                         │
│                                    ▼                                         │
│   ┌─────────────────────────────────────────────────────────────────────┐   │
│   │                    NATIVE KALI EXECUTION                             │   │
│   │  - Direct subprocess calls to installed tools                        │   │
│   │  - nmap, gobuster, nikto, sqlmap, nuclei, etc.                      │   │
│   │  - No Docker, no containers, no abstraction layer                    │   │
│   └─────────────────────────────────────────────────────────────────────┘   │
│                                                                              │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## Design Principles

### "Intent is the New Skill" Tenants

| # | Tenant | Implementation |
|---|--------|----------------|
| 1 | No Hands-On Coding | Human provides intent only; AI writes all code |
| 2 | Testing Is Primary Control | Every phase validated by automated tests |
| 3 | Error-Driven Iteration | Errors are feedback; paste error → AI fixes |
| 4 | Explicit Intent | All components documented with purpose |
| 5 | Native Kali Only | No Docker/container abstraction - direct tool execution |
| 6 | Visible Guardrails | Scope enforcement, authorization gates, audit logs |
| 7 | Dual-Use Acknowledged | Tool hunts bounties on authorized targets only |
| 8 | Artifacts > Claims | Working code and tests prove capability |
| 9 | Methodology Over Models | Process matters as much as product |
| 10 | Friction = Security | Authorization required, no auto-exploit |
| 11 | Journal Every Build | Every version bump documented in PROJECT_JOURNAL.md |
| 12 | No Skips in Integration | Tests must pass or fail definitively |

### Development Methodology

```
Design → Build Backend → Test → Build Frontend → Test → Validate → Next Phase
```

Each phase:
1. Define scope and success criteria
2. Build minimal implementation
3. Create tests
4. Run tests, fix errors
5. Document wins/problems in PROJECT_JOURNAL.md
6. Get explicit approval before next phase

---

## Technology Stack

### Core Technologies

| Component | Technology | Rationale |
|-----------|------------|-----------|
| Language | Python 3.11+ | Ubiquitous, good async support, Kali default |
| Execution | Native subprocess | Direct tool access, no Docker overhead |
| Platform | Kali Linux | Industry standard, all tools pre-installed |
| LLM | Anthropic Claude | Strong reasoning, tool use capabilities |
| Backend | FastAPI | Async, fast, auto-docs, WebSocket support |
| Database | SQLite | Local, no setup, sufficient for single-user |
| Frontend | HTMX + Alpine.js | Minimal JS, server-driven, no build step |
| Styling | Tailwind CSS | Utility classes, CDN-deliverable |

### Security Tools (Native Kali)

| Category | Tools |
|----------|-------|
| Reconnaissance | nmap, masscan, subfinder, amass |
| Web Enumeration | gobuster, feroxbuster, nikto, dirb |
| Vulnerability Scanning | nuclei, nikto, searchsploit |
| Exploitation | sqlmap, curl, custom payloads |
| Fingerprinting | whatweb, wappalyzer-cli, httpx |

---

## Version Numbering

### Format: AA.BB.CC.DD

| Segment | Meaning | Increments When |
|---------|---------|-----------------|
| AA | Major | Breaking changes, major milestones |
| BB | Phase | New phase completed |
| CC | Feature | New feature within phase |
| DD | Build | Bug fixes, iterations, journal entries |

### Examples
- `0.0.0.1` - Initial project scaffold
- `0.1.0.0` - Phase 1 complete (Core Foundation)
- `0.2.0.0` - Phase 2 complete (Platform Integration)
- `0.2.1.0` - New feature added in Phase 2
- `0.2.1.5` - Fifth iteration/fix of that feature
- `1.0.0.0` - First major release (all phases complete)

### Current Version: 0.0.0.1

---

## Phase Plan

### Phase 0: Project Scaffold ← CURRENT
**Goal:** Establish project structure, documentation, and tooling

**Deliverables:**
- [ ] PROJECT_DOCUMENTATION.md (this file)
- [ ] PROJECT_JOURNAL.md
- [ ] Directory structure
- [ ] pyproject.toml with dependencies
- [ ] toolcheck.sh script
- [ ] Basic configuration system
- [ ] VERSION file

**Success Criteria:**
- Project structure matches design
- `toolcheck.sh` verifies Kali environment
- Documentation complete
- Ready for Phase 1

**Version:** 0.0.x.x

---

### Phase 1: Core Foundation
**Goal:** Native execution engine and basic tool integration

**Deliverables:**
- [ ] Native executor (subprocess wrapper)
- [ ] Tool wrappers (nmap, gobuster, nikto, sqlmap)
- [ ] Output parsers for each tool
- [ ] Session management
- [ ] Basic LLM integration (Anthropic client)
- [ ] Configuration management
- [ ] Logging system

**Success Criteria:**
- Can execute tools natively on Kali
- Output is parsed into structured data
- LLM can translate intent → tool command
- All unit tests pass

**Version:** 0.1.x.x

---

### Phase 2: Platform Integration
**Goal:** Connect to bug bounty platforms and manage programs

**Deliverables:**
- [ ] HackerOne API client
- [ ] Bugcrowd API client
- [ ] Program data models
- [ ] Local program cache (SQLite)
- [ ] Scope parsing and validation
- [ ] Rate limit management

**Success Criteria:**
- Can authenticate with platforms
- Can list and filter programs
- Can parse scope rules
- Scope validator blocks out-of-scope targets
- All unit tests pass

**Version:** 0.2.x.x

---

### Phase 3: CVE Correlation
**Goal:** Match discovered services to known vulnerabilities

**Deliverables:**
- [ ] NVD API client
- [ ] Exploit-DB search integration
- [ ] Fingerprint extraction from scan results
- [ ] LLM-assisted CVE matching
- [ ] Exploitability scoring

**Success Criteria:**
- Can query CVEs by product/version
- Can find public exploits
- LLM correlates findings to CVEs intelligently
- All unit tests pass

**Version:** 0.3.x.x

---

### Phase 4: Exploit Planning
**Goal:** Generate actionable exploit plans with LLM assistance

**Deliverables:**
- [ ] Exploit plan data model
- [ ] LLM prompt engineering for exploit generation
- [ ] Step-by-step command generation
- [ ] Risk assessment scoring
- [ ] Plan validation (scope check before execution)

**Success Criteria:**
- LLM generates valid exploit chains
- Plans include exact commands
- Risk levels are reasonable
- Plans respect scope boundaries
- All unit tests pass

**Version:** 0.4.x.x

---

### Phase 5: Authorization Gate
**Goal:** Human-in-the-loop authorization for all exploits

**Deliverables:**
- [ ] Authorization request model
- [ ] CLI authorization prompt (for testing)
- [ ] Audit logging (all decisions recorded)
- [ ] Modify/skip/approve workflow
- [ ] Per-step vs all-steps approval

**Success Criteria:**
- No exploit runs without explicit approval
- All authorizations logged with timestamp
- User can modify commands before approval
- User can approve individual steps
- All unit tests pass

**Version:** 0.5.x.x

---

### Phase 6: Hunt Orchestration
**Goal:** End-to-end hunt workflow

**Deliverables:**
- [ ] Hunt state machine
- [ ] Recon → Correlate → Plan → Auth → Execute pipeline
- [ ] Finding aggregation
- [ ] Evidence capture
- [ ] Hunt history

**Success Criteria:**
- Can run complete hunt on authorized target
- Findings flow through entire pipeline
- Authorization gate enforced
- Evidence collected
- All integration tests pass

**Version:** 0.6.x.x

---

### Phase 7: Web API
**Goal:** FastAPI backend for UI

**Deliverables:**
- [ ] FastAPI application structure
- [ ] REST endpoints for programs, hunts, findings
- [ ] WebSocket for real-time hunt updates
- [ ] Authentication (local, single-user)
- [ ] API documentation (auto-generated)

**Success Criteria:**
- All core operations available via API
- WebSocket streams hunt progress
- API docs accessible at /docs
- All API tests pass

**Version:** 0.7.x.x

---

### Phase 8: Web UI
**Goal:** Browser-based interface for bounty hunting

**Deliverables:**
- [ ] Dashboard view
- [ ] Program browser with filters
- [ ] Program detail view with scope
- [ ] Hunt management interface
- [ ] Authorization modal
- [ ] Real-time hunt progress
- [ ] Report viewer

**Success Criteria:**
- Can browse and select programs
- Can start and monitor hunts
- Authorization works via UI
- Real-time updates display
- Responsive design

**Version:** 0.8.x.x

---

### Phase 9: Report Generation
**Goal:** Generate submission-ready reports

**Deliverables:**
- [ ] HackerOne report format
- [ ] Bugcrowd report format
- [ ] PDF export
- [ ] Evidence attachment
- [ ] Reproduction steps (from execution log)

**Success Criteria:**
- Reports match platform requirements
- Include all required sections
- Evidence properly attached
- Copy-paste ready for submission

**Version:** 0.9.x.x

---

### Phase 10: Polish & Integration
**Goal:** Production readiness

**Deliverables:**
- [ ] Error handling review
- [ ] Edge case testing
- [ ] Performance optimization
- [ ] Documentation review
- [ ] Demo preparation

**Success Criteria:**
- No unhandled errors in normal use
- Reasonable performance
- Documentation complete
- Demo-ready

**Version:** 1.0.x.x

---

## Current Progress

| Phase | Description | Status | Version |
|-------|-------------|--------|---------|
| Phase 0 | Project Scaffold | ✅ COMPLETE | 0.0.0.2 |
| Phase 1 | Core Foundation | ✅ COMPLETE | 0.1.1.0 |
| Phase 1.1 | Tool Registry | ✅ COMPLETE | 0.1.1.0 |
| Phase 2 | Platform Integration | 🟡 IN PROGRESS | 0.2.x.x |
| Phase 3 | CVE Correlation | ⬜ NOT STARTED | - |
| Phase 4 | Exploit Planning | ⬜ NOT STARTED | - |
| Phase 5 | Authorization Gate | ⬜ NOT STARTED | - |
| Phase 6 | Hunt Orchestration | ⬜ NOT STARTED | - |
| Phase 7 | Web API | ⬜ NOT STARTED | - |
| Phase 8 | Web UI | ⬜ NOT STARTED | - |
| Phase 9 | Report Generation | ⬜ NOT STARTED | - |
| Phase 10 | Polish & Integration | ⬜ NOT STARTED | - |

---

## File Structure

### Target Structure (End State)

```
bountyhunter/
├── pyproject.toml              # Project config, dependencies
├── README.md                   # User-facing documentation
├── PROJECT_DOCUMENTATION.md    # This file
├── PROJECT_JOURNAL.md          # Build history and decisions
├── VERSION                     # Current version
├── toolcheck.sh                # Verify Kali tools
├── run.sh                      # Start application
│
├── config/
│   ├── default.yaml            # Default configuration
│   └── logging.yaml            # Logging configuration
│
├── bountyhunter/
│   ├── __init__.py
│   │
│   ├── core/                   # Core execution engine
│   │   ├── __init__.py
│   │   ├── executor.py         # Native subprocess execution
│   │   ├── session.py          # Session state management
│   │   └── config.py           # Configuration management
│   │
│   ├── tools/                  # Tool wrappers
│   │   ├── __init__.py
│   │   ├── base.py             # Base tool wrapper
│   │   ├── nmap.py
│   │   ├── gobuster.py
│   │   ├── nikto.py
│   │   ├── sqlmap.py
│   │   └── nuclei.py
│   │
│   ├── parsers/                # Output parsers
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── nmap.py
│   │   ├── gobuster.py
│   │   ├── nikto.py
│   │   └── sqlmap.py
│   │
│   ├── platforms/              # Bounty platform clients
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── hackerone.py
│   │   ├── bugcrowd.py
│   │   └── models.py
│   │
│   ├── hunting/                # Hunt logic
│   │   ├── __init__.py
│   │   ├── scope.py            # Scope validation
│   │   ├── cve.py              # CVE correlation
│   │   ├── planner.py          # Exploit planning
│   │   ├── authorization.py    # Auth gate
│   │   └── orchestrator.py     # Hunt orchestration
│   │
│   ├── llm/                    # LLM integration
│   │   ├── __init__.py
│   │   ├── anthropic.py
│   │   └── prompts.py
│   │
│   ├── reports/                # Report generation
│   │   ├── __init__.py
│   │   ├── base.py
│   │   ├── hackerone.py
│   │   ├── bugcrowd.py
│   │   └── pdf.py
│   │
│   ├── api/                    # FastAPI backend
│   │   ├── __init__.py
│   │   ├── main.py
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   ├── programs.py
│   │   │   ├── hunts.py
│   │   │   ├── findings.py
│   │   │   └── reports.py
│   │   ├── websocket.py
│   │   └── deps.py
│   │
│   ├── web/                    # Frontend assets
│   │   ├── static/
│   │   │   ├── css/
│   │   │   └── js/
│   │   └── templates/
│   │
│   └── db/                     # Database
│       ├── __init__.py
│       ├── models.py
│       └── database.py
│
└── tests/
    ├── __init__.py
    ├── conftest.py             # Pytest fixtures
    ├── test_core/
    ├── test_tools/
    ├── test_parsers/
    ├── test_platforms/
    ├── test_hunting/
    ├── test_llm/
    ├── test_api/
    └── fixtures/               # Test data
```

---

## Testing Methodology

### Approach

1. **Unit Tests**: Each module tested in isolation
2. **Integration Tests**: Multi-component workflows
3. **API Tests**: Endpoint validation
4. **End-to-End Tests**: Full hunt simulation (on test targets)

### Test Execution

```bash
# Run all tests
cd /path/to/bountyhunter
pytest

# Run specific phase tests
pytest tests/test_core/
pytest tests/test_platforms/

# Run with coverage
pytest --cov=bountyhunter --cov-report=html
```

### Success Criteria

- All tests must pass before phase completion
- Errors documented in PROJECT_JOURNAL.md
- No skipped tests without documented reason

---

## Security Considerations

### Safety Invariants (MUST Always Hold)

1. **No action without scope validation** - Every network request validates scope first
2. **No exploitation without authorization** - Human must explicitly approve each exploit
3. **Complete audit trail** - Every action logged with timestamp
4. **Fail closed** - Any validation error = deny by default
5. **Re-validation before execution** - Scope checked again immediately before exploit
6. **No credentials in logs** - API keys and passwords never logged
7. **Rate limit respect** - Per-program rate limits enforced

### What This Tool Will NOT Do

1. No automated target discovery outside scope
2. No exploitation without human approval
3. No data exfiltration
4. No persistence mechanisms on targets
5. No bypassing platform rules

---

## Appendix

### A. Glossary

| Term | Definition |
|------|------------|
| Hunt | A complete bounty hunting session on one program |
| Program | A bug bounty program on a platform |
| Scope | Assets authorized for testing |
| Finding | A discovered vulnerability or security issue |
| Authorization | Human approval for an exploit attempt |
| CVE | Common Vulnerabilities and Exposures identifier |

### B. Related Projects

- **IntentSec** - Parent project, general pentesting framework
- Runs in parallel, no code sharing (clean room)

### C. Version History

| Version | Date | Changes |
|---------|------|---------|
| 0.0.0.1 | 2026-02-02 | Initial project documentation |

---

*Document generated as part of BountyHunter development*  
*"Intent is the New Skill" - Bounty Hunting Edition*
