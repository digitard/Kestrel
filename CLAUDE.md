# CLAUDE.md - Kestrel Project Instructions

## Project Overview

**Kestrel** is an LLM-assisted bug bounty automation platform built on the "Intent is the New Skill" methodology. Humans provide high-level intent; AI handles all technical execution. The platform integrates with bug bounty platforms (HackerOne, Bugcrowd), automates reconnaissance, correlates CVEs, generates exploit plans, and produces submission-ready reports — all with mandatory human authorization before any exploitation.

**Project Name:** Kestrel
**GitHub:** https://github.com/digitard/Kestrel
**Current Version:** 0.2.1.0
**Current Phase:** Phase 2 Complete — Architecture pivot to platform-agnostic design
**Python:** 3.11+ (tested on 3.13/3.14)
**Part of:** "Intent is the New Skill" project series (IntentSec → CTFRunner → Kestrel)

---

## Critical Rules — READ FIRST

### 1. "Intent is the New Skill" Tenets

These are NON-NEGOTIABLE. Every action must comply:

| # | Tenet | What It Means |
|---|-------|---------------|
| 1 | **No Hands-On Coding** | The human provides intent only; AI writes ALL code |
| 2 | **Testing Is Primary Control** | Every phase validated by automated tests before advancing |
| 3 | **Error-Driven Iteration** | Errors are feedback — fix them, don't explain them away |
| 4 | **Explicit Intent** | All components documented with purpose |
| 5 | **Platform Agnostic** | Auto-detects environment; optimizes accordingly |
| 6 | **Visible Guardrails** | Scope enforcement, authorization gates, audit logs |
| 7 | **Dual-Use Acknowledged** | Tool hunts bounties on AUTHORIZED TARGETS ONLY |
| 8 | **Artifacts > Claims** | Working code and tests prove capability |
| 9 | **Methodology Over Models** | Process matters as much as product |
| 10 | **Friction = Security** | Authorization required, no auto-exploit |
| 11 | **Journal Every Build** | Every version bump documented in PROJECT_JOURNAL.md |
| 12 | **No Skips in Integration** | Tests must pass or fail definitively |
| 13 | **Commit Every Build** | Every version bump committed and pushed to GitHub |

### 2. Safety-First Design

- **Scope Validator is fail-closed**: Out-of-scope checked FIRST (overrides in-scope), empty scope = blocked, no match = blocked
- **Authorization gate required** before ANY exploitation attempt — human must explicitly approve
- **Audit logging** for all actions — no credential storage in logs
- Unknown tools default to `requires_auth=True`
- All API credentials stored in `~/.kestrel/credentials.yaml` (chmod 600), NEVER in the project directory

### 3. Build Naming Convention

**All zip builds MUST use UTC timestamps:**
```
kestrel_vX.X.X.X_YYYYMMDD_HHMM_UTC.zip
```
Example: `kestrel_v0.2.1.0_20260220_1200_UTC.zip`

### 4. Version Numbering

Format: `AA.BB.CC.DD` — `Major.Phase.Feature.Build`
- Bump BB when starting a new phase
- Bump CC for features within a phase
- Bump DD for patches/bugfixes
- Update BOTH `VERSION` file and `kestrel/__init__.py`

### 5. GitHub — Commit Every Build

Every version bump MUST be committed and pushed:
```bash
git add -A
git commit -m "vX.X.X.X - Description"
git push origin main
```
No exceptions. The journal entry and the commit happen together.

### 6. Kali-Native Tests

Any code that requires real API credentials or native Kali/Docker tools MUST have a separate test script in `tests/` that the user can run and paste results back. These scripts:
- Use the `CredentialManager` for credential resolution
- Print clear pass/fail output
- Include `pytest.skip(allow_module_level=True)` guard so pytest ignores them

---

## Platform Architecture — CRITICAL

Kestrel is **platform-agnostic**. It auto-detects the runtime environment and optimizes accordingly. The same codebase runs on all platforms with no user configuration required.

### LLM Engine Selection (auto-detected)

```
1. Apple Silicon (arm64 + Darwin)?     → MLX backend (Neural Engine + unified memory)
2. CUDA GPU available?                 → Ollama + CUDA backend
3. Vulkan GPU available?               → Ollama + Vulkan backend (Intel Xe, AMD)
4. Everything else                     → Ollama CPU
5. Complex task on any of the above?  → Anthropic API (HybridRouter decides)
```

### Tool Execution Selection (auto-detected)

```
1. Running on native Kali Linux?       → Native subprocess (bypass Docker entirely)
2. Docker available?                   → Kali container (kestrel-tools image)
3. Neither?                            → Clear error + install instructions
```

### Recommended Model Sizes (auto-suggested based on detected RAM)

| RAM | Apple Silicon (MLX) | Other (Ollama) |
|-----|--------------------|--------------------|
| 8GB | Mistral-7B Q4 | llama3.2:3b |
| 16GB | Llama-3.1-8B | llama3.1:8b |
| 32GB | Qwen2.5-Coder-14B | qwen2.5-coder:14b |
| 64GB | Llama-3.1-34B | llama3.1:70b Q4 |
| 128GB+ | Llama-3.1-70B | llama3.1:70b |

### Hybrid LLM Routing

The HybridRouter (ported from CTFRunner) classifies task complexity and routes accordingly:

- **Local (fast, free):** Banner identification, output summarization, simple lookups
- **Cloud API (powerful, paid):** Multi-step exploit planning, CVE correlation analysis, report generation

Fallback: if primary backend fails, falls back to secondary (configurable).

### Capability Parity Principle

Every user gets the same features regardless of hardware. Hardware determines **pace**, not **capability**. An 8GB machine works — it's slower. A 128GB machine with GPU is faster. Same code path, same results.

---

## Development Methodology

```
Design → Build Backend → Test → Fix → Journal → Commit/Push → Approval → Next Phase
```

For each task:
1. Define scope and success criteria
2. Build minimal implementation
3. Create comprehensive tests (every code path)
4. Run ALL tests (`python3 -m pytest tests/`) — zero regressions allowed
5. Document in PROJECT_JOURNAL.md
6. Commit and push to GitHub
7. Get explicit user approval before next phase

### When Running Tests

Always run the FULL suite after any change:
```bash
python3 -m pytest tests/ -v --tb=short
```
Current baseline: **188 passed, 36 skipped, 0 failed**. Any regression = fix before proceeding.

---

## Architecture

### Project Structure

```
kestrel/                           # Project root (GitHub: digitard/Kestrel)
├── CLAUDE.md                      # THIS FILE - project rules
├── PROJECT_DOCUMENTATION.md       # Full architecture & phase plan
├── PROJECT_JOURNAL.md             # Build log (append-only)
├── VERSION                        # Current version string
├── pyproject.toml                 # Python project config
├── config/
│   └── default.yaml               # Default configuration
├── docker/                        # Docker tool execution layer
│   ├── Dockerfile                 # Kali-based tool image
│   └── tool_manifest.yaml         # Pinned tool versions + missing tool log
├── kestrel/                       # Main Python package
│   ├── __init__.py                # Version export
│   ├── core/                      # Config, Executor, SessionManager
│   │   ├── config.py
│   │   ├── executor.py            # Platform-aware: native Kali OR Docker
│   │   └── session.py
│   ├── tools/                     # Tool wrappers + ToolRegistry
│   │   ├── registry.py            # Two-tier tool discovery system
│   │   ├── nmap.py
│   │   ├── gobuster.py
│   │   ├── nikto.py
│   │   └── sqlmap.py
│   ├── parsers/                   # Output parsers
│   ├── platforms/                 # Bug bounty platform integration
│   │   ├── models.py              # Program, ScopeEntry, ScopeValidator
│   │   ├── base.py                # BasePlatformClient, RateLimiter
│   │   ├── hackerone.py           # HackerOne API v1
│   │   ├── bugcrowd.py            # Bugcrowd REST API
│   │   ├── cache.py               # SQLite program cache
│   │   └── credentials.py         # Credential manager (~/.kestrel/)
│   ├── llm/                       # LLM abstraction layer (CTFRunner pattern)
│   │   ├── backend.py             # LLMBackend Protocol + Message/LLMResponse
│   │   ├── backend_factory.py     # Factory: api/local/hybrid + platform detection
│   │   ├── hybrid_router.py       # HybridRouter: complexity routing
│   │   ├── anthropic_backend.py   # Anthropic API backend
│   │   ├── mlx_backend.py         # Apple Silicon MLX backend
│   │   ├── ollama_backend.py      # Ollama backend (all other platforms)
│   │   └── prompts.py             # Prompt builders
│   ├── knowledge/                 # Technique library + CVE knowledge base
│   │   ├── store.py               # SQLite + FAISS vector store
│   │   └── technique_library.py   # Reusable technique patterns
│   ├── hunting/                   # Hunt orchestration
│   │   └── orchestrator.py        # Plan/Execute/Observe/Reason loop
│   ├── api/                       # FastAPI backend (Phase 7)
│   ├── web/                       # Web UI (Phase 8)
│   ├── db/                        # Database models
│   ├── assets/                    # Branding/static assets
│   └── reports/                   # Report generation (Phase 9)
└── tests/
    ├── test_phase0_scaffold.py
    ├── test_phase1_core.py
    ├── test_phase1_1_registry.py
    ├── test_phase2_platforms.py
    ├── test_phase2_kali_native.py  # Standalone Kali/Docker native tests
    └── test_kali_integration.py    # Standalone Kali-native tests
```

### Key Architecture Decisions

1. **Platform-Agnostic Execution** — NativeExecutor detects runtime: native Kali uses subprocess directly; all other platforms route through Docker (Kali container). Same tool wrappers, different execution target.

2. **CTFRunner LLM Pattern** — Full LLM abstraction layer ported from CTFRunner: `LLMBackend` Protocol, `HybridRouter`, `BackendFactory` with platform detection (MLX on Apple Silicon, Ollama everywhere else), with Anthropic API as cloud fallback.

3. **Two-Tier Tool System** (ToolRegistry):
   - **Tier 1 (Wrapped)**: nmap, gobuster, nikto, sqlmap — structured I/O for recon pipeline
   - **Tier 2 (Discovered)**: All other tools — auto-discovered, direct execution. Missing tools logged to `docker/tool_manifest.yaml` for Dockerfile inclusion.

4. **ScopeValidator is the Safety Gate** — Fail-closed. Out-of-scope overrides in-scope. Unknown = blocked.

5. **Knowledge Store** — SQLite + FAISS for CVE data, technique patterns, and past hunt memory. LLM uses RAG for "I've seen this before" recall during hunts.

6. **Orchestrator Loop** — Plan/Execute/Observe/Reason loop (adapted from CTFRunner). LLM emits `<cmd>` tags; executor runs them; results feed back. Iterates until done or max depth hit.

### Credential Storage

```
~/.kestrel/
├── credentials.yaml    # API keys (chmod 600)
└── programs.db         # SQLite program cache
```

Credential resolution order: env var → `~/.kestrel/credentials.yaml` → interactive prompt

Key credentials:
- `anthropic_api_key` — env: `ANTHROPIC_API_KEY`
- `h1_username` / `h1_token` — env: `BH_H1_USERNAME` / `BH_H1_TOKEN`
- `bc_username` / `bc_password` — env: `BH_BC_USERNAME` / `BH_BC_PASSWORD`
- `nvd_api_key` — env: `NVD_API_KEY`

---

## Phase Roadmap

| Phase | Description | Status | Version |
|-------|-------------|--------|---------|
| Phase 0 | Scaffold + Platform Detection (all prior work) | ✅ Complete | 0.0.x.x – 0.2.1.0 |
| **Phase 1** | **Execution Layer** | **⬜ NEXT** | **0.3.x.x** |
| Phase 2 | LLM Abstraction Layer | ⬜ | 0.4.x.x |
| Phase 3 | Tool Layer | ⬜ | 0.5.x.x |
| Phase 4 | Platform Integration | ⬜ | 0.6.x.x |
| Phase 5 | CVE + Knowledge Layer | ⬜ | 0.7.x.x |
| Phase 6 | Hunt Orchestrator | ⬜ | 0.8.x.x |
| Phase 7 | Authorization Gate | ⬜ | 0.9.x.x |
| Phase 8 | Exploit Execution Loop | ⬜ | 0.10.x.x |
| Phase 9 | Web API | ⬜ | 0.11.x.x |
| Phase 10 | Web UI | ⬜ | 0.12.x.x |
| Phase 11 | Report Generation + Submission | ⬜ | 0.13.x.x |
| Phase 12 | Polish + Integration | ⬜ | 1.0.0.0 |

> **Note on version numbering:** After the architectural reset at v0.2.1.0, the BB segment no longer maps 1:1 to phase numbers. PROJECT_JOURNAL.md is the authoritative record. PROJECT_DOCUMENTATION.md has full phase specs.

### Phase 1: Execution Layer (NEXT — v0.3.x.x)

**Goal:** Build the unified execution abstraction that everything else depends on. Docker image (ARM64 + AMD64) + native Kali detection + bypass logic + unified executor interface.

**Deliverables:**
- `kestrel/core/platform.py` — PlatformInfo detection (Apple Silicon, CUDA, Vulkan, Kali, Docker)
- `docker/Dockerfile` — Kali-based multi-arch image with pinned tools
- `docker/tool_manifest.yaml` — Pinned versions + missing tool log
- `kestrel/core/executor.py` — Rebuilt: native subprocess OR Docker exec, identical interface
- `kestrel/core/docker_manager.py` — Container lifecycle management

**Success Criteria:**
- Platform detection correctly identifies all target environments
- Docker image builds for ARM64 and AMD64
- nmap runs correctly via Docker on Mac
- nmap runs correctly natively on Kali
- Same wrapper code works for both — executors are transparent
- 188 existing tests still pass + all new tests pass

---

## Known Issues & Lessons Learned

1. **HackerOne returns None for boolean fields** — Always use `bool()` wrapping when normalizing H1 API data. Fixed in v0.2.0.1.

2. **Flag parsing regex** — Initial regex missed flags with argument placeholders. Fixed in v0.1.1.0.

3. **Circular imports** — `_initialize_registry()` imports wrappers inside function body to avoid circular dependency.

4. **sed on macOS** — `sed -i ''` (BSD sed) requires empty string arg for in-place edit. GNU sed uses `sed -i`.

---

## How to Run

### Tests (environment-agnostic, any platform)
```bash
python3 -m pytest tests/ -v --tb=short
```

### Kali/Docker Native Tests (requires credentials or Docker)
```bash
python3 tests/test_phase2_kali_native.py --setup   # first-time setup
python3 tests/test_phase2_kali_native.py            # run tests
python3 tests/test_phase2_kali_native.py --status   # check credentials
```

### Tool Check
```bash
bash toolcheck.sh
```

---

## For Claude Code: Working With This Project

When making changes:
1. **Read PROJECT_JOURNAL.md** to understand what's been built and why
2. **Read the relevant phase section** in PROJECT_DOCUMENTATION.md for specs
3. **Run full test suite** before AND after changes (`python3 -m pytest tests/ -v --tb=short`)
4. **Append to PROJECT_JOURNAL.md** for any version bump
5. **Commit and push to GitHub** after every version bump
6. **Never modify credential files** or store secrets in the project
7. **Always create Kali-native/Docker test scripts** for code requiring real APIs or tools
8. **Use the CredentialManager** for all credential access — never hardcode
9. **Use `python3`** not `python` — this environment uses python3
