# Kestrel — Project Documentation

**Project Name:** Kestrel
**GitHub:** https://github.com/digitard/Kestrel
**Current Version:** 0.2.1.0
**Last Updated:** 2026-02-20
**Part of:** "Intent is the New Skill" project series

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Design Philosophy](#2-design-philosophy)
3. [Platform Architecture](#3-platform-architecture)
4. [Technology Stack](#4-technology-stack)
5. [CTFRunner Integration](#5-ctfrunner-integration)
6. [API Integrations](#6-api-integrations)
7. [Security Model](#7-security-model)
8. [Phase Plan](#8-phase-plan)
9. [File Structure](#9-file-structure)
10. [Testing Methodology](#10-testing-methodology)
11. [Version Numbering](#11-version-numbering)

---

## 1. Executive Summary

Kestrel is an LLM-assisted bug bounty automation platform. Humans provide high-level intent — "hunt this program", "follow this finding" — and Kestrel handles all technical execution: reconnaissance, CVE correlation, exploit planning, and report generation. It integrates with major bug bounty platforms (HackerOne, Bugcrowd), enforces strict scope validation at every step, and requires explicit human authorization before any exploitation attempt.

**Core principle:**
> Authorized targets only. Human-approved exploitation always. Hardware determines pace, not capability.

**What Kestrel does:**
- Connects to HackerOne, Bugcrowd (and future platforms) to browse and select programs
- Imports program scope and enforces it fail-closed throughout the entire hunt
- Runs automated reconnaissance within scope using Kali security tools
- Correlates discovered services against CVE databases and exploit repositories
- Generates ranked, actionable exploit plans with LLM assistance
- Presents plans to the human operator for explicit approval
- Executes approved exploits autonomously, following each chain as deep as it goes
- Tracks findings: shells gained, credentials found, privilege escalation achieved
- Generates submission-ready reports formatted for each platform
- Optionally submits reports directly via platform API

**What Kestrel is not:**
- Not a tool for unauthorized testing — scope validation is fail-closed, not advisory
- Not fully autonomous — human authorization is a hard gate before any exploitation
- Not a replacement for skilled researchers — it amplifies skill, not substitutes for judgment
- Not Kali-only — it runs on any platform, hardware determines pace

---

## 2. Design Philosophy

### "Intent is the New Skill"

Kestrel is part of a series of projects exploring the thesis that human operators can accomplish sophisticated technical tasks by expressing high-level intent to an AI agent, without hands-on technical execution. The human's skill is in knowing *what* to do and *whether to approve* — the AI handles the *how*.

Previous projects in the series:
- **IntentSec** — General penetration testing framework (the parent project)
- **CTFRunner** — AI-powered Capture The Flag assistant (see Section 5)
- **Kestrel** — Bug bounty automation (this project)

### Tenets (Non-Negotiable)

| # | Tenet | Meaning |
|---|-------|---------|
| 1 | No Hands-On Coding | Human provides intent only; AI writes all code |
| 2 | Testing Is Primary Control | Every phase validated by automated tests before advancing |
| 3 | Error-Driven Iteration | Errors are feedback — fix and retest, never explain away |
| 4 | Explicit Intent | All components documented with purpose |
| 5 | Platform Agnostic | Auto-detects environment, optimizes accordingly |
| 6 | Visible Guardrails | Scope enforcement, authorization gates, audit logs |
| 7 | Dual-Use Acknowledged | Authorized targets only, always |
| 8 | Artifacts > Claims | Working code and passing tests prove capability |
| 9 | Methodology Over Models | Process matters as much as product |
| 10 | Friction = Security | Authorization required, no auto-exploit |
| 11 | Journal Every Build | Every version bump documented in PROJECT_JOURNAL.md |
| 12 | No Skips in Integration | Tests must pass or fail definitively — no skipping |
| 13 | Commit Every Build | Every version bump committed and pushed to GitHub |

### Development Methodology

```
Define Scope → Build → Test → Fix → Journal → Commit/Push → Approval → Next Phase
```

No phase advances until:
1. All tests for that phase pass
2. A journal entry is written documenting what was built, why, and what was learned
3. The version is bumped and committed to GitHub
4. The operator has explicitly approved proceeding

---

## 3. Platform Architecture

Kestrel is platform-agnostic. It auto-detects the runtime environment and selects the optimal execution and LLM strategy. Same features everywhere — hardware determines pace.

### LLM Engine Detection (in order)

```
1. Apple Silicon (arm64 + Darwin)?    → MLX backend
                                        Full Neural Engine + unified memory bandwidth
                                        Fastest local inference available

2. CUDA GPU detected?                 → Ollama + CUDA backend
                                        NVIDIA GPU acceleration

3. Vulkan GPU detected?               → Ollama + Vulkan backend
                                        Intel Xe, AMD, other Vulkan-capable GPUs

4. Everything else                    → Ollama CPU
                                        Fully functional, slower pace

5. Complex task (any platform)?       → Anthropic API
                                        HybridRouter decides based on task complexity
```

### Tool Execution Detection (in order)

```
1. Running on native Kali Linux?      → Native subprocess
                                        Direct tool access, zero overhead
                                        Bypasses Docker entirely

2. Docker available?                  → Kali container (kestrel-tools image)
                                        ARM64 + AMD64 multi-arch support
                                        Pinned tool versions, consistent environment

3. Neither available?                 → Clear error with install instructions
```

### Recommended Model Sizes (auto-suggested from detected RAM)

| RAM | Apple Silicon (MLX) | Other Platforms (Ollama) |
|-----|---------------------|--------------------------|
| 8 GB | Mistral-7B Q4 | llama3.2:3b |
| 16 GB | Llama-3.1-8B | llama3.1:8b |
| 32 GB | Qwen2.5-Coder-14B | qwen2.5-coder:14b |
| 64 GB | Llama-3.1-34B | llama3.1:70b Q4 |
| 128 GB+ | Llama-3.1-70B | llama3.1:70b |

### Hybrid LLM Routing

The HybridRouter (ported from CTFRunner) classifies every task by complexity before routing:

**Routes to local LLM (fast, free):**
- Banner identification and service classification
- Output summarization and formatting
- Simple lookups and pattern matching
- Scope validation queries

**Routes to cloud API (powerful, paid):**
- Multi-step CVE correlation and exploit chain analysis
- Exploit plan generation from recon results
- Post-exploitation reasoning and pivot planning
- Report generation and submission writeups

Fallback: if the primary backend fails, the router falls back to the secondary (configurable). This means a cloud API outage falls back to local, and a local model failure falls back to cloud.

### The Capability Parity Principle

Every user — regardless of hardware — gets the full Kestrel feature set. A user on an 8 GB MacBook Air and a user on a 128 GB Mac Studio with dedicated GPU run identical code paths. The only difference is how long each step takes. This is intentional. Kestrel does not gate features behind hardware requirements.

---

## 4. Technology Stack

| Layer | Technology | Rationale |
|-------|------------|-----------|
| Language | Python 3.11+ | Async support, broad library ecosystem, universal |
| Local LLM (Apple Silicon) | MLX | Neural Engine + unified memory, purpose-built for Apple Silicon |
| Local LLM (other) | Ollama | Universal local LLM runner, CUDA/Vulkan/CPU backends |
| Cloud LLM | Anthropic Claude | Strong multi-step reasoning for complex analysis |
| LLM routing | HybridRouter (CTFRunner) | Complexity-based routing, cost control |
| Tool execution (non-Kali) | Docker (Kali container) | Consistent toolset, ARM64 + AMD64 |
| Tool execution (Kali native) | subprocess | Direct access, zero overhead |
| Platform clients | aiohttp / httpx | Async HTTP for H1, Bugcrowd, NVD APIs |
| CVE data | NVD API + Exploit-DB | Authoritative CVE source + public exploit search |
| Passive recon | Shodan / Censys | Pre-scan surface mapping (optional, API key required) |
| Knowledge store | SQLite + FAISS | Technique and CVE recall via vector similarity |
| Web backend | FastAPI | Async, WebSocket support, auto-docs |
| Web frontend | HTMX + Alpine.js | Minimal JS, server-driven, no build step |
| Local data | SQLite | Program cache, hunt history, findings |
| Styling | Tailwind CSS | CDN-deliverable, no build step |

### Security Tools (via Docker or native Kali)

| Category | Tools |
|----------|-------|
| Port scanning | nmap, masscan |
| Subdomain enumeration | subfinder, amass, dnsx |
| Web enumeration | gobuster, feroxbuster, ffuf |
| Vulnerability scanning | nuclei, nikto |
| Web fingerprinting | whatweb, httpx, wafw00f |
| Exploitation | sqlmap, metasploit (msfconsole/msfvenom) |
| CVE/Exploit search | searchsploit (offline Exploit-DB) |
| Post-exploitation | linpeas, winpeas, pwncat |

Missing tools are automatically logged to `docker/tool_manifest.yaml` for inclusion in the next Docker image build.

---

## 5. CTFRunner Integration

CTFRunner is a sister project in the "Intent is the New Skill" series — an AI-powered Capture The Flag assistant built with the same methodology: human intent drives everything, AI executes, every phase is tested before advancing.

CTFRunner and Kestrel share significant architectural overlap:
- Both require a hybrid LLM layer (local for routine tasks, cloud for complex reasoning)
- Both run an agent loop (Plan → Execute → Observe → Reason)
- Both need a persistent knowledge store for technique recall
- Both execute security tools and process structured output

Rather than duplicate this work, proven CTFRunner components are **ported** (adapted for bug bounty context, renamed, extended) into Kestrel's codebase. CTFRunner is read-only reference material — it is never modified.

### Components Ported from CTFRunner

| CTFRunner Source | Kestrel Destination | Adaptations |
|---|---|---|
| `llm/backend.py` | `kestrel/llm/backend.py` | None — direct port |
| `llm/hybrid_router.py` | `kestrel/llm/hybrid_router.py` | Keywords tuned for bug bounty tasks |
| `llm/backend_factory.py` | `kestrel/llm/backend_factory.py` | Same platform detection logic |
| `llm/mlx_backend.py` | `kestrel/llm/mlx_backend.py` | None — direct port |
| `llm/ollama_backend.py` | `kestrel/llm/ollama_backend.py` | None — direct port |
| `core/orchestrator.py` | `kestrel/hunting/orchestrator.py` | Extended for multi-target persistent hunts |
| `knowledge/store.py` | `kestrel/knowledge/store.py` | Extended for CVE + technique data |
| `knowledge/technique_library.py` | `kestrel/knowledge/technique_library.py` | Extended with bug bounty techniques |

---

## 6. API Integrations

All credentials stored in `~/.kestrel/credentials.yaml` (chmod 600). Never in the project directory. Resolution order: environment variable → credentials file → interactive prompt.

### Credential Registry

| Key | Environment Variable | Service | Required | Phase |
|-----|---------------------|---------|----------|-------|
| `anthropic_api_key` | `ANTHROPIC_API_KEY` | Anthropic Claude (cloud LLM) | Yes | Phase 2 |
| `h1_username` | `KESTREL_H1_USERNAME` | HackerOne API username | No | Phase 4 |
| `h1_token` | `KESTREL_H1_TOKEN` | HackerOne API token | No | Phase 4 |
| `bc_username` | `KESTREL_BC_USERNAME` | Bugcrowd token username | No | Phase 4 |
| `bc_password` | `KESTREL_BC_PASSWORD` | Bugcrowd token password | No | Phase 4 |
| `nvd_api_key` | `NVD_API_KEY` | NVD CVE API (improves rate limits) | No | Phase 5 |
| `shodan_api_key` | `SHODAN_API_KEY` | Shodan passive recon | No | Phase 5 |
| `censys_api_id` | `CENSYS_API_ID` | Censys passive recon | No | Phase 5 |
| `censys_api_secret` | `CENSYS_API_SECRET` | Censys passive recon | No | Phase 5 |
| `vulners_api_key` | `VULNERS_API_KEY` | Vulners CVE/exploit aggregator | No | Phase 5 |
| `intigriti_token` | `KESTREL_INTIGRITI_TOKEN` | IntiGriti platform | No | Phase 4+ |
| `yeswehack_token` | `KESTREL_YWH_TOKEN` | YesWeHack platform | No | Phase 4+ |

### Data Sources

| Source | Type | Use Case |
|--------|------|----------|
| HackerOne API v1 | REST | Program list, scope, report submission |
| Bugcrowd REST API | REST | Program list, scope, report submission |
| IntiGriti API | REST | Program list, scope (future) |
| YesWeHack API | REST | Program list, scope (future) |
| NVD (NIST) | REST | CVE lookup by CPE/product/version |
| Exploit-DB (searchsploit) | Local CLI | Offline exploit search on Kali/Docker |
| Exploit-DB API | REST | Online exploit search (Docker mode fallback) |
| Vulners | REST | CVE + exploit aggregation, richer than NVD alone |
| Shodan | REST | Passive surface mapping before active recon |
| Censys | REST | Certificate and IP passive enumeration |
| GitHub Security Advisories | REST | CVE data with PoC links |

---

## 7. Security Model

### Safety Invariants (Must Always Hold)

1. **Scope validation is fail-closed** — Out-of-scope overrides in-scope. Empty scope = blocked. No match = blocked. This runs before every action.
2. **No exploitation without authorization** — The authorization gate is a hard stop. No code path bypasses it.
3. **Re-validation at execution time** — Scope is checked again immediately before each exploit command runs, even after prior approval.
4. **Complete audit trail** — Every action logged with timestamp, session ID, operator decision, and tool output. No credentials in logs.
5. **Rate limit respect** — Platform-specific rate limits enforced by the API clients.
6. **Unknown tools require auth** — Tools not in the ToolRegistry default to `requires_auth=True`.
7. **No persistence on targets** — Kestrel does not install backdoors, persistent shells, or any mechanism that survives a reboot on the target.
8. **No data exfiltration** — Tool output is captured for the report only. No data is sent anywhere except the operator's machine and the platform report submission.

### What Kestrel Will Not Do (Enforced by Design)

- Run tools against targets not in program scope
- Execute any exploit without explicit operator approval for that specific action
- Store credentials in logs, git, or any unencrypted location
- Submit reports without operator review and approval
- Operate autonomously past the authorization gate

---

## 8. Phase Plan

### Status Overview

| Phase | Description | Status | Version |
|-------|-------------|--------|---------|
| 0 | Scaffold + Platform Detection | ✅ Complete | 0.0.x.x – 0.2.1.x |
| **1** | **Execution Layer** | **⬜ Next** | **0.3.x.x** |
| 2 | LLM Abstraction Layer | ⬜ | 0.4.x.x |
| 3 | Tool Layer | ⬜ | 0.5.x.x |
| 4 | Platform Integration | ⬜ | 0.6.x.x |
| 5 | CVE + Knowledge Layer | ⬜ | 0.7.x.x |
| 6 | Hunt Orchestrator | ⬜ | 0.8.x.x |
| 7 | Authorization Gate | ⬜ | 0.9.x.x |
| 8 | Exploit Execution Loop | ⬜ | 0.10.x.x |
| 9 | Web API | ⬜ | 0.11.x.x |
| 10 | Web UI | ⬜ | 0.12.x.x |
| 11 | Report Generation + Submission | ⬜ | 0.13.x.x |
| 12 | Polish + Integration | ⬜ | 1.0.0.0 |

> **Note on version numbering:** Versions continue forward from 0.2.1.0. After the architectural reset, the BB segment no longer maps 1:1 to phase numbers. The PROJECT_JOURNAL.md is the authoritative record of what each version represents.

---

### Phase 0: Scaffold + Platform Detection ✅ Complete

**What was built:**
- Project structure, config system, branding
- NativeExecutor (subprocess), SessionManager
- Tool wrappers: nmap, gobuster, nikto, sqlmap
- Two-tier ToolRegistry (25+ Kali tool definitions)
- Output parsers for all four wrapped tools
- HackerOne + Bugcrowd API clients
- ScopeValidator (fail-closed), SQLite program cache
- CredentialManager (~/.kestrel/credentials.yaml)
- Platform detection discussion and architectural pivot decision
- Project renamed BountyHunter → Kestrel, GitHub repo created

**Note:** The executor and LLM layer built in this phase are replaced in Phases 1 and 2. The platform clients, parsers, config, and session manager migrate cleanly.

---

### Phase 1: Execution Layer ⬜ Next (v0.3.x.x)

**Goal:** Build the unified execution abstraction that everything else depends on. This is the true foundation.

**Deliverables:**
- **Platform detector** — `kestrel/core/platform.py`
  - Detects: Apple Silicon, CUDA GPU, Vulkan GPU, native Kali Linux, Docker availability
  - Returns structured `PlatformInfo` dataclass consumed by executor and LLM factory
- **Kali Docker image** — `docker/Dockerfile`
  - Base: `kalilinux/kali-rolling`
  - Multi-arch: ARM64 (Mac, Raspberry Pi) + AMD64 (Intel/AMD x86)
  - Pinned tool versions for reproducibility
  - Initial tools: nmap, gobuster, nikto, sqlmap, nuclei, subfinder, ffuf, whatweb, httpx, searchsploit
- **Tool manifest** — `docker/tool_manifest.yaml`
  - Tracks installed tool versions
  - Logs tools requested-but-missing during hunts for next build inclusion
- **Unified executor** — `kestrel/core/executor.py` (rebuild)
  - `ExecutionMode` enum: `NATIVE` | `DOCKER`
  - Auto-selects mode from `PlatformInfo` at startup
  - Native mode: direct subprocess (zero overhead on Kali)
  - Docker mode: `docker exec` into running kestrel-tools container
  - Identical interface regardless of mode — tool wrappers don't know which path they're on
  - Streaming output, timeout support, exit code capture
- **Docker lifecycle manager** — `kestrel/core/docker_manager.py`
  - Start/stop/check kestrel-tools container
  - Volume mounts for workspace and output
  - Health check before first tool run

**Success Criteria:**
- `PlatformInfo` correctly identifies: Apple Silicon Mac, Intel Mac, native Kali (AMD64), native Kali (ARM64)
- Docker image builds successfully for both ARM64 and AMD64
- `nmap --version` runs successfully through Docker executor on Mac
- `nmap --version` runs successfully through native executor on Kali
- Same tool wrapper code path works for both execution modes
- Missing tool logging writes to `tool_manifest.yaml`
- All new tests pass, 188 existing tests still pass

---

### Phase 2: LLM Abstraction Layer ⬜ (v0.4.x.x)

**Goal:** Replace the thin Anthropic placeholder with the full CTFRunner-pattern LLM abstraction. This enables hybrid local/cloud routing for all subsequent phases.

**Deliverables (port from CTFRunner, adapt for Kestrel):**
- `kestrel/llm/backend.py` — `LLMBackend` Protocol, `Message`, `LLMResponse`
- `kestrel/llm/backend_factory.py` — Creates correct backend from `PlatformInfo`
- `kestrel/llm/hybrid_router.py` — Complexity classification + routing + fallback
- `kestrel/llm/mlx_backend.py` — Apple Silicon inference via MLX
- `kestrel/llm/ollama_backend.py` — All other platforms via Ollama
- `kestrel/llm/anthropic_backend.py` — Cloud API backend (replaces current `anthropic.py`)
- `kestrel/llm/prompts.py` — Bug-bounty-specific prompt builders (extends existing)
- `kestrel/llm/context_trimmer.py` — Long-session context management (port from CTFRunner)

**Success Criteria:**
- On Mac: factory creates `MLXBackend` (or `OllamaBackend` if MLX not installed)
- On Linux non-Kali: factory creates `OllamaBackend`
- On Kali: factory creates `OllamaBackend`
- HybridRouter correctly classifies simple/complex bug bounty tasks
- Simple tasks route to local, complex tasks route to Anthropic API
- Fallback works: API failure → local, local failure → API (configurable)
- `estimated_cost()` tracks spend per session
- All tests pass, 188 baseline maintained

---

### Phase 3: Tool Layer ⬜ (v0.5.x.x)

**Goal:** Migrate existing tool wrappers and parsers onto the new executor foundation. Validate that everything works identically in both Docker and native modes.

**Deliverables:**
- Migrate tool wrappers (nmap, gobuster, nikto, sqlmap) onto new unified executor
- Migrate all parsers — these are already correct, minimal changes
- Rebuild `ToolRegistry` with Docker-aware auto-discovery
  - Discovery runs through the executor (not direct subprocess)
  - Works on Mac (via Docker) and native Kali (direct)
- Add new tool wrappers: nuclei, subfinder, ffuf, httpx, whatweb
- Docker-mode tool test suite (Claude Code on Mac can run these directly)

**Success Criteria:**
- All four existing tool wrappers execute successfully via Docker on Mac
- All four existing tool wrappers execute successfully natively on Kali
- ToolRegistry auto-discovery works in both modes
- New tool wrappers (nuclei, subfinder, ffuf, httpx) tested in Docker
- All parsers produce identical output regardless of execution mode
- Zero regressions on existing 188 tests + all new tests pass

---

### Phase 4: Platform Integration ⬜ (v0.6.x.x)

**Goal:** Migrate the existing platform clients into the clean new structure. Add credential entries for new platforms and data sources. Validate everything still works against live APIs.

**Deliverables:**
- Migrate HackerOne client, Bugcrowd client, models, ScopeValidator, cache, CredentialManager
- Add credential entries to CredentialManager: Shodan, Censys, Vulners, IntiGriti, YesWeHack
- Add platform stubs for IntiGriti and YesWeHack (interface only, full implementation deferred)
- Update config with new platform settings
- Kali-native integration test script for live API validation

**Success Criteria:**
- All existing Phase 2 tests pass unchanged
- CredentialManager handles all new credential types
- Live H1 API test passes (scope fetch, validation)
- ScopeValidator still fail-closed after migration
- Zero regressions

---

### Phase 5: CVE + Knowledge Layer ⬜ (v0.7.x.x)

**Goal:** Build the intelligence layer. Given a discovered service and version, Kestrel can find relevant CVEs, locate public exploits, assess exploitability, and store technique knowledge for recall.

**Deliverables:**
- `kestrel/knowledge/store.py` — SQLite + FAISS knowledge store (port from CTFRunner, extend)
- `kestrel/knowledge/technique_library.py` — Bug bounty technique patterns (port + extend)
- `kestrel/cve/nvd_client.py` — NVD API client (CPE-based CVE search)
- `kestrel/cve/exploitdb_client.py` — Exploit-DB / searchsploit integration
- `kestrel/cve/vulners_client.py` — Vulners API client (richer CVE + exploit aggregation)
- `kestrel/cve/shodan_client.py` — Shodan passive recon (optional, degrades gracefully without key)
- `kestrel/cve/censys_client.py` — Censys passive recon (optional)
- `kestrel/cve/correlator.py` — LLM-assisted CVE matching via HybridRouter
- `kestrel/cve/scorer.py` — Exploitability scoring (CVSS + public exploit availability + version match confidence)
- Fingerprint extractor — pulls product/version from parsed scan output
- Knowledge store populated from CVE feeds on first run, updated periodically

**Success Criteria:**
- Given "Apache 2.4.49", returns relevant CVEs with CVSS scores
- Given CVE ID, returns public exploits from Exploit-DB and Vulners
- LLM correctly correlates ambiguous version strings to CVE products
- Knowledge store persists between sessions
- Shodan/Censys queries return structured results (skipped gracefully without keys)
- Exploitability score is deterministic and explainable
- All tests pass

---

### Phase 6: Hunt Orchestrator ⬜ (v0.8.x.x)

**Goal:** Build the autonomous hunt loop. The orchestrator drives the full recon → correlate → plan cycle, managing state across iterations and sessions.

**Deliverables (adapt from CTFRunner orchestrator):**
- `kestrel/hunting/orchestrator.py` — Plan/Execute/Observe/Reason loop
  - LLM emits `<cmd>` tags for tool execution
  - Executor runs commands, returns structured output
  - Results feed back to LLM for next reasoning step
  - Iteration limit + depth limit to prevent runaway hunts
  - Scope re-validated before every command execution
- `kestrel/hunting/session.py` — Persistent multi-target hunt sessions
  - Resume interrupted hunts
  - Track findings across multiple targets
  - Evidence capture (command output, timestamps, session IDs)
- `kestrel/hunting/planner.py` — Exploit plan generation
  - LLM generates ranked attack chains from CVE + recon data
  - Each plan includes: rationale, exact commands, risk level, scope confirmation
- Finding aggregation — deduplication, severity classification, evidence linking

**Success Criteria:**
- Orchestrator runs a complete recon loop on a test target (scope-limited)
- LLM correctly interprets scan output and requests follow-up commands
- Iteration limit is respected and logged
- Scope check fires before every command — out-of-scope command is blocked, logged, loop continues
- Hunt session persists to disk and resumes correctly after interruption
- Exploit plans are structured and parseable by the authorization gate
- All tests pass

---

### Phase 7: Authorization Gate ⬜ (v0.9.x.x)

**Goal:** The human-in-the-loop safety gate. No exploit runs without explicit operator approval. This phase makes that guarantee enforced by code, not convention.

**Deliverables:**
- `kestrel/authorization/gate.py` — Authorization gate core
  - Receives exploit plan from orchestrator
  - Presents plan to operator: target, rationale, exact commands, risk level, CVE references
  - Accepts: approve all / approve step-by-step / modify command / reject
  - Issues signed authorization token for each approved action
  - Executor checks token before running any exploit-class command
- `kestrel/authorization/audit.py` — Audit log
  - Every authorization decision logged: timestamp, session, operator, action, decision
  - Immutable append-only log (never modified after write)
  - No credentials in log entries
- CLI authorization interface (terminal-based, no UI required for this phase)

**Success Criteria:**
- No exploit-class tool runs without a valid authorization token
- Token is scoped to the specific command and session — cannot be reused
- Approve/reject/modify workflow all work correctly from CLI
- All decisions appear in audit log with correct metadata
- Attempting to bypass the gate programmatically fails
- All tests pass

---

### Phase 8: Exploit Execution Loop ⬜ (v0.10.x.x)

**Goal:** Post-authorization autonomous execution. Kestrel follows each chain as deep as it goes, pivoting based on what it finds, tracking every milestone.

**Deliverables:**
- `kestrel/hunting/executor_loop.py` — Authorized exploit execution loop
  - Receives authorized exploit plan
  - Executes step by step, observing output
  - LLM reasons about results: pivot to next technique, deepen, or conclude
  - Scope re-validated at every step (not just at plan approval)
  - Max depth limit enforced
- Post-exploitation tracking:
  - Shell access gained (type: bind/reverse/web, privilege level)
  - Credentials found (masked in logs, stored securely)
  - Privilege escalation achieved
  - Lateral movement opportunities identified
- Evidence capture at every step (command, output, timestamp, finding classification)
- Automatic conclusion detection: LLM signals done / stuck / needs more information

**Success Criteria:**
- Loop follows a multi-step exploit chain correctly (tested against intentionally vulnerable target)
- Scope re-check fires at every command — out-of-scope pivot is blocked
- Post-exploitation state tracked correctly across loop iterations
- Max depth respected and cleanly concluded
- Evidence chain is complete and readable for report generation
- All tests pass

---

### Phase 9: Web API ⬜ (v0.11.x.x)

**Goal:** FastAPI backend exposing all Kestrel capabilities via REST and WebSocket. Foundation for the Web UI.

**Deliverables:**
- `kestrel/api/main.py` — FastAPI application
- REST endpoints:
  - `GET /api/programs` — list/search bug bounty programs
  - `GET /api/programs/{id}` — program detail + scope
  - `POST /api/hunts` — start a new hunt
  - `GET /api/hunts/{id}` — hunt status and findings
  - `POST /api/hunts/{id}/authorize` — submit authorization decision
  - `GET /api/findings` — all findings across hunts
  - `GET /api/reports/{hunt_id}` — generated report preview
  - `POST /api/reports/{hunt_id}/submit` — submit report to platform
- WebSocket: `ws://localhost:8080/ws/hunt/{id}` — real-time hunt progress stream
- Local single-user authentication (token-based, no external auth service)
- Auto-generated API docs at `/docs`

**Success Criteria:**
- All endpoints return correct responses and status codes
- WebSocket streams hunt progress events in real time
- Authorization endpoint correctly feeds the authorization gate
- API tests cover all endpoints
- All tests pass

---

### Phase 10: Web UI ⬜ (v0.12.x.x)

**Goal:** Browser-based interface for the full Kestrel workflow.

**Deliverables:**
- Program browser: search, filter by bounty range, scope type, platform
- Program detail view: full scope display, bounty table, past hunts
- Hunt management: start hunt, select target from scope, monitor progress
- Real-time hunt display: live tool output, LLM reasoning, findings as they land
- Authorization modal: presents exploit plan, shows commands, approve/modify/reject
- Findings pane: categorized findings with evidence links
- Report viewer: formatted report preview before submission

**Success Criteria:**
- Full end-to-end workflow completable from browser
- Real-time updates display without page refresh
- Authorization modal correctly handles all three decisions
- Responsive layout works at common desktop resolutions
- UI tests cover critical paths

---

### Phase 11: Report Generation + Submission ⬜ (v0.13.x.x)

**Goal:** Generate submission-ready reports and optionally submit directly via platform API.

**Deliverables:**
- `kestrel/reports/generator.py` — Report generator
  - Pulls evidence chain from hunt session
  - LLM drafts narrative sections (summary, impact, reproduction steps)
  - Operator reviews and edits before submission
- Platform-formatted report templates:
  - HackerOne: title, severity, weakness, steps to reproduce, impact, supporting material
  - Bugcrowd: target, classification, description, PoC steps, impact
- CVSS score calculator based on finding characteristics
- Evidence packaging: command outputs, screenshots (future), tool logs
- PDF export
- Direct API submission (with operator confirmation)

**Success Criteria:**
- Generated report contains all required sections for each platform
- LLM-drafted sections are accurate and based on actual evidence
- CVSS score is reasonable for the finding type
- Direct submission via H1 API succeeds on test program
- Operator can edit any section before submission
- All tests pass

---

### Phase 12: Polish + Integration ⬜ (v1.0.0.0)

**Goal:** Production readiness. Full end-to-end test, documentation, demo preparation.

**Deliverables:**
- Full end-to-end hunt simulation on an intentionally vulnerable target
- Edge case hardening: malformed scope, API rate limits, tool timeouts, LLM failures
- Error message review: every user-facing error is actionable
- Documentation review: README, CLAUDE.md, inline docs
- Performance review: startup time, first-tool latency, LLM routing overhead
- Demo preparation

**Success Criteria:**
- End-to-end hunt completes successfully on test target
- No unhandled exceptions in normal operation
- All error states produce clear, actionable messages
- Documentation is accurate and complete
- Demo-ready

---

## 9. File Structure

### Target End-State Structure

```
kestrel/                                    # Project root
├── CLAUDE.md                               # Project rules (living document)
├── PROJECT_DOCUMENTATION.md               # This file
├── PROJECT_JOURNAL.md                      # Chronological build log
├── VERSION                                 # Current version string
├── pyproject.toml                          # Python project config
├── run.sh                                  # Start application
├── toolcheck.sh                            # Verify tool environment
│
├── config/
│   └── default.yaml                        # Default configuration
│
├── docker/
│   ├── Dockerfile                          # Kali-based tool image (ARM64 + AMD64)
│   ├── docker-compose.yml                  # Container lifecycle
│   └── tool_manifest.yaml                  # Pinned versions + missing tool log
│
├── kestrel/                                # Main Python package
│   ├── __init__.py
│   │
│   ├── core/
│   │   ├── platform.py                     # Platform detection (PlatformInfo)
│   │   ├── executor.py                     # Unified executor (native OR Docker)
│   │   ├── docker_manager.py               # Container lifecycle management
│   │   ├── config.py                       # Configuration system
│   │   └── session.py                      # Hunt session state machine
│   │
│   ├── llm/
│   │   ├── backend.py                      # LLMBackend Protocol + types
│   │   ├── backend_factory.py              # Platform-aware backend creation
│   │   ├── hybrid_router.py                # Complexity routing
│   │   ├── anthropic_backend.py            # Cloud API backend
│   │   ├── mlx_backend.py                  # Apple Silicon backend
│   │   ├── ollama_backend.py               # All other platforms
│   │   ├── context_trimmer.py              # Long-session context management
│   │   └── prompts.py                      # Bug bounty prompt builders
│   │
│   ├── tools/
│   │   ├── registry.py                     # Two-tier tool discovery
│   │   ├── base.py                         # Base tool wrapper
│   │   ├── nmap.py
│   │   ├── gobuster.py
│   │   ├── nikto.py
│   │   ├── sqlmap.py
│   │   ├── nuclei.py
│   │   ├── subfinder.py
│   │   ├── ffuf.py
│   │   └── httpx.py
│   │
│   ├── parsers/
│   │   ├── base.py
│   │   ├── nmap.py
│   │   ├── gobuster.py
│   │   ├── nikto.py
│   │   └── sqlmap.py
│   │
│   ├── platforms/
│   │   ├── models.py                       # Program, ScopeEntry, ScopeValidator
│   │   ├── base.py                         # BasePlatformClient, RateLimiter
│   │   ├── credentials.py                  # CredentialManager
│   │   ├── cache.py                        # SQLite program cache
│   │   ├── hackerone.py
│   │   ├── bugcrowd.py
│   │   ├── intigriti.py                    # Stub (Phase 4)
│   │   └── yeswehack.py                    # Stub (Phase 4)
│   │
│   ├── cve/
│   │   ├── nvd_client.py                   # NVD API
│   │   ├── exploitdb_client.py             # Exploit-DB / searchsploit
│   │   ├── vulners_client.py               # Vulners aggregator
│   │   ├── shodan_client.py                # Shodan passive recon
│   │   ├── censys_client.py                # Censys passive recon
│   │   ├── correlator.py                   # LLM-assisted CVE matching
│   │   └── scorer.py                       # Exploitability scoring
│   │
│   ├── knowledge/
│   │   ├── store.py                        # SQLite + FAISS vector store
│   │   └── technique_library.py            # Bug bounty technique patterns
│   │
│   ├── hunting/
│   │   ├── orchestrator.py                 # Plan/Execute/Observe/Reason loop
│   │   ├── planner.py                      # Exploit plan generation
│   │   ├── executor_loop.py                # Authorized execution loop
│   │   └── session.py                      # Persistent hunt sessions
│   │
│   ├── authorization/
│   │   ├── gate.py                         # Authorization gate
│   │   └── audit.py                        # Immutable audit log
│   │
│   ├── reports/
│   │   ├── generator.py                    # Report generation
│   │   ├── hackerone.py                    # H1-formatted output
│   │   ├── bugcrowd.py                     # Bugcrowd-formatted output
│   │   └── pdf.py                          # PDF export
│   │
│   ├── api/
│   │   ├── main.py                         # FastAPI application
│   │   ├── websocket.py                    # WebSocket handler
│   │   └── routes/
│   │       ├── programs.py
│   │       ├── hunts.py
│   │       ├── findings.py
│   │       └── reports.py
│   │
│   ├── web/                                # Frontend assets
│   │   ├── static/
│   │   └── templates/
│   │
│   ├── db/                                 # Database models
│   ├── assets/                             # Branding
│   └── reports/
│
└── tests/
    ├── conftest.py
    ├── test_phase0_scaffold.py             # Migrated
    ├── test_phase1_executor.py             # New — Phase 1
    ├── test_phase1_docker.py               # New — Phase 1
    ├── test_phase2_llm.py                  # New — Phase 2
    ├── test_phase3_tools.py                # New — Phase 3
    ├── test_phase4_platforms.py            # Migrated from test_phase2_platforms.py
    ├── test_phase5_cve.py                  # New — Phase 5
    ├── test_phase6_orchestrator.py         # New — Phase 6
    ├── test_phase7_authgate.py             # New — Phase 7
    ├── test_phase8_exploit_loop.py         # New — Phase 8
    ├── test_phase9_api.py                  # New — Phase 9
    ├── test_kali_integration.py            # Standalone Kali-native tests
    └── fixtures/
```

---

## 10. Testing Methodology

### Principles

- Every phase has a dedicated test file
- Tests are written before or alongside the implementation, never after
- The full test suite runs before and after every change
- Any regression = fix before proceeding, no exceptions
- Kali-native and Docker tests that require live credentials have standalone scripts in `tests/` with `pytest.skip()` guards so they don't run in the standard suite

### Running Tests

```bash
# Full suite — run before and after every change
python3 -m pytest tests/ -v --tb=short

# Specific phase
python3 -m pytest tests/test_phase1_executor.py -v

# Kali/Docker live tests (requires credentials or Docker)
python3 tests/test_kali_integration.py
```

### Baseline

Current: **188 passed, 36 skipped, 0 failed**
All 188 passing tests are against platform-agnostic components and migrate cleanly through the rebuild.

---

## 11. Version Numbering

### Format: `AA.BB.CC.DD`

| Segment | Name | Meaning |
|---------|------|---------|
| AA | Release | 0 until public release (v1.0.0.0) |
| BB | Major | Increments with each significant phase or milestone |
| CC | Feature | New features or sub-phases within a major |
| DD | Patch | Bug fixes, doc updates, minor corrections |

### Current Version Sequence

| Version | Description |
|---------|-------------|
| 0.0.0.1 – 0.0.0.2 | Phase 0: Initial scaffold |
| 0.1.0.0 – 0.1.1.0 | Phase 1 (old): Core foundation + tool registry |
| 0.2.0.0 – 0.2.0.1 | Phase 2 (old): Platform integration |
| 0.2.1.0 | Architectural pivot + rename to Kestrel |
| **0.3.x.x** | **Phase 1 (new): Execution layer — starts here** |
| 0.4.x.x | Phase 2 (new): LLM abstraction layer |
| 0.5.x.x | Phase 3 (new): Tool layer migration |
| 0.6.x.x | Phase 4 (new): Platform integration migration |
| 0.7.x.x | Phase 5 (new): CVE + knowledge layer |
| 0.8.x.x | Phase 6 (new): Hunt orchestrator |
| 0.9.x.x | Phase 7 (new): Authorization gate |
| 0.10.x.x | Phase 8 (new): Exploit execution loop |
| 0.11.x.x | Phase 9 (new): Web API |
| 0.12.x.x | Phase 10 (new): Web UI |
| 0.13.x.x | Phase 11 (new): Report generation + submission |
| 1.0.0.0 | Phase 12: Polish + public release |

---

*"Intent is the New Skill" — Kestrel Edition*
*Authorized targets only. Human-approved exploitation always.*
