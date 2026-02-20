# BountyHunter - Project Journal

**Project:** BountyHunter  
**Started:** 2026-02-02  
**Methodology:** Intent-Driven Development  

---

## Journal Purpose

This document records every significant build, decision, error, and resolution throughout the BountyHunter development process. Per Tenant #11: "Journal Every Build" - every version bump requires an entry documenting changes, failures, and resolutions.

---

## Version 0.0.0.1 - Initial Project Scaffold

**Date:** 2026-02-02  
**Phase:** 0 (Project Scaffold)  
**Status:** In Progress  

### What Was Done
- Created PROJECT_DOCUMENTATION.md with full phase plan
- Created PROJECT_JOURNAL.md (this file)
- Defined 10 phases with clear success criteria
- Established version numbering scheme (AA.BB.CC.DD)
- Documented architecture decisions

### Key Decisions Made

#### Decision 1: Native Kali Only (No Docker)
**Context:** IntentSec uses Docker for portability. Should BountyHunter do the same?

**Decision:** Native Kali execution only, no Docker support.

**Rationale:**
- Bug bounty hunting is a specific use case where portability is less important
- Docker adds complexity without benefit for this use case
- Native execution is faster and more reliable
- Tool updates via `apt` are simpler than rebuilding containers
- Anyone can install Kali + BountyHunter and be ready to go
- Reduces attack surface (no Docker daemon required)

**Tradeoff:** Cannot run on Windows/Mac without Kali VM. Acceptable for target audience.

#### Decision 2: Web UI Required
**Context:** IntentSec is CLI-only. Is that sufficient for bounty hunting?

**Decision:** Include a local Web UI (FastAPI + HTMX).

**Rationale:**
- Bounty programs have complex nested data (scope, rewards, rules)
- Need to browse/filter hundreds of programs
- Visual progress tracking improves UX
- Authorization gate benefits from visual display
- Report previews need rich rendering

**Tradeoff:** More development effort. Worth it for usability.

#### Decision 3: Parallel Project (Not Fork)
**Context:** Should BountyHunter share code with IntentSec?

**Decision:** Clean room implementation - no code sharing.

**Rationale:**
- IntentSec is stable and preparing for presentation
- Don't want to risk breaking IntentSec
- Allows different architectural decisions (no Docker)
- Can incorporate lessons learned without legacy constraints
- Both projects can evolve independently

**Tradeoff:** Some duplication of effort. Acceptable for isolation benefits.

### Technical Notes
- Project structure designed for Python 3.11+
- Will use FastAPI for async support and WebSocket
- SQLite for local data (programs, hunts, findings)
- HTMX + Alpine.js for minimal-JS frontend

### Open Questions
1. HackerOne API rate limits - need to research
2. Bugcrowd API availability - verify access requirements
3. NVD API key requirements - check if needed

### Next Steps
1. ~~Create directory structure~~ ✓
2. ~~Create pyproject.toml~~ ✓
3. ~~Create toolcheck.sh~~ ✓
4. ~~Create VERSION file~~ ✓
5. ~~Create basic config system~~ ✓
6. ~~Create Phase 0 tests~~ ✓
7. ~~Run tests and fix issues~~ ✓

### Tests
- **17 tests written** for Phase 0 scaffold validation
- **17 passed, 0 failed** (after fix)
- Test categories:
  - TestProjectStructure (5 tests)
  - TestVersionFile (3 tests)
  - TestPackageImports (3 tests)
  - TestConfigFile (3 tests)
  - TestDocumentation (3 tests)

### Wins
- Clean architecture documented before coding
- Clear phase boundaries defined
- Version scheme established
- All scaffold tests passing
- Safety defaults verified by tests (authorization required, fail closed, etc.)

### Problems
- **FIXED:** Missing `__init__.py` in `bountyhunter/web/` - added file, tests pass

---

## Version 0.0.0.2 - Phase 0 Complete

**Date:** 2026-02-02  
**Phase:** 0 (Project Scaffold)  
**Status:** ✅ Complete  

### What Was Done
- Added Phase 0 scaffold tests (17 tests)
- Fixed missing `__init__.py` in web module
- Created ASCII logo/branding assets
- Updated run.sh with proper BountyHunter banner
- All tests passing

### Tests
- 17 passed, 0 failed
- All scaffold validation tests green

### Wins
- Phase 0 complete with full test coverage
- Clear visual branding distinct from IntentSec
- Safety defaults verified by automated tests

### Problems
- None

### Next Steps
- Phase 1: Core Foundation
  - Native executor (subprocess)
  - Tool wrappers
  - Output parsers
  - Session management
  - LLM integration
  - Configuration system

---

## Version 0.1.0.0 - Phase 1 Complete: Core Foundation

**Date:** 2026-02-02  
**Phase:** 1 (Core Foundation)  
**Status:** ✅ Complete  

### What Was Done

**Configuration System (`core/config.py`):**
- Dataclass-based configuration with typed fields
- YAML loading with merge support (default + user + explicit)
- Safety validation for critical settings
- Singleton pattern for global access

**Native Executor (`core/executor.py`):**
- Direct subprocess execution (no Docker)
- Tool availability checking
- Timeout support
- Streaming output callback support
- Kali environment detection

**Session Management (`core/session.py`):**
- HuntSession with state machine (created → running → paused → completed)
- Finding tracking with severity levels
- Execution records for audit trail
- JSON serialization/deserialization
- LLM context generation

**Tool Wrappers (`tools/`):**
- Base wrapper class with validation framework
- NmapWrapper with scan type presets
- GobusterWrapper with dir/dns/vhost modes
- NiktoWrapper with tuning options
- SqlmapWrapper with safety warnings
- Tool registry for lookup

**Output Parsers (`parsers/`):**
- Base parser class with common data structures
- NmapParser for port/service extraction
- GobusterParser for path extraction
- NiktoParser with severity assessment
- SqlmapParser for injection detection
- Auto-detection for parser selection

**LLM Integration (`llm/`):**
- AnthropicClient with API key management
- Prompt builders for:
  - Intent translation
  - Vulnerability analysis
  - Exploit planning
  - Report generation
  - CVE correlation

### Tests
- **31 new tests** for Phase 1
- **48 total tests** (17 Phase 0 + 31 Phase 1)
- All passing

Test categories:
- TestConfiguration (4 tests)
- TestNativeExecutor (6 tests)
- TestSession (6 tests)
- TestToolWrappers (5 tests)
- TestParsers (4 tests)
- TestLLMIntegration (4 tests)
- TestIntegration (2 tests)

### Wins
- Clean separation of concerns
- All tools follow consistent wrapper pattern
- Parsers extract structured data reliably
- Session provides good LLM context
- Safety validation built into config

### Problems
- **FIXED:** SqlmapParser DBMS regex didn't match "is MySQL" format - updated regex

### Key Files Created
```
bountyhunter/
├── core/
│   ├── __init__.py
│   ├── config.py      (293 lines)
│   ├── executor.py    (267 lines)
│   └── session.py     (350 lines)
├── tools/
│   ├── __init__.py
│   ├── base.py        (175 lines)
│   ├── nmap.py        (205 lines)
│   ├── gobuster.py    (195 lines)
│   ├── nikto.py       (185 lines)
│   └── sqlmap.py      (225 lines)
├── parsers/
│   ├── __init__.py
│   ├── base.py        (145 lines)
│   ├── nmap.py        (185 lines)
│   ├── gobuster.py    (145 lines)
│   ├── nikto.py       (195 lines)
│   └── sqlmap.py      (195 lines)
├── llm/
│   ├── __init__.py
│   ├── anthropic.py   (165 lines)
│   └── prompts.py     (230 lines)
└── assets/
    └── __init__.py    (ASCII branding)
```

### Next Steps
- Phase 2: Platform Integration
  - HackerOne API client
  - Bugcrowd API client
  - Program data models
  - Scope validation engine

---

## Version 0.1.0.2 - Kali Integration Tests Validated

**Date:** 2026-02-02  
**Phase:** 1 (Core Foundation)  
**Status:** ✅ Complete + Validated on Kali  

### What Was Done
- Created Kali integration test suite (35 tests)
- Fixed test compatibility issues discovered on real Kali:
  - `jq` made optional (skips if not installed)
  - `gobuster version` → `gobuster -h` (gobuster doesn't have version subcommand)
  - `sqlmap` timeout increased to 30s (slow Python startup)
  - `sqlmap --version` assertion relaxed (just outputs version number)
  - Phase 0 tests updated for current version (0.1.x.x not 0.0.x.x)
  - Added proper `pytest.mark.slow` marker

### Test Results on Kali
```
Platform: Kali Linux (Python 3.13.9)
Total Tests: 83
Passed: 82
Skipped: 1 (jq optional)
Failed: 0
Time: ~3 seconds
```

### Environment Validated
- ✅ Kali Linux detected
- ✅ nmap installed and functional
- ✅ gobuster installed and functional  
- ✅ nikto installed and functional
- ✅ sqlmap installed and functional
- ✅ Wordlists present at expected paths
- ✅ toolcheck.sh runs successfully
- ✅ NativeExecutor works with real tools
- ✅ Parsers correctly parse real nmap output

### Wins
- Full end-to-end validation on target platform
- Real tool execution tested (not just mocks)
- Test suite properly handles tool quirks

### Problems
- None remaining

---

## Version 0.1.0.2 - Kali Integration Tests Verified

**Date:** 2026-02-02  
**Phase:** 1 (Core Foundation)  
**Status:** ✅ Complete - Verified on Kali  

### What Was Done
- Created Kali-specific integration tests (35 tests)
- Fixed tool-specific quirks:
  - gobuster doesn't have `version` subcommand
  - sqlmap outputs just version number, not "sqlmap"
  - sqlmap is slow to start (increased timeout to 30s)
  - jq made optional (not installed by default)
- Updated Phase 0 tests to work with current version (0.1.x)
- Added proper pytest marker for slow tests

### Test Results on Kali Linux
```
Platform: Kali Linux (Python 3.13.9)
Total tests: 83
Passed: 82
Skipped: 1 (jq optional)
Failed: 0
Time: ~3 seconds
```

### Kali Environment Verified
- ✓ nmap installed and working
- ✓ gobuster installed and working
- ✓ nikto installed and working
- ✓ sqlmap installed and working
- ✓ All wordlists present
- ✓ NativeExecutor works with real tools
- ✓ toolcheck.sh runs successfully

### Ready for Phase 2
Core foundation complete and verified on target platform.

---

## Template for Future Entries

```markdown
## Version X.X.X.X - [Title]

**Date:** YYYY-MM-DD  
**Phase:** N ([Phase Name])  
**Status:** Complete | In Progress | Blocked  

### What Was Done
- [List of changes]

### Key Decisions Made
- [Any significant decisions with rationale]

### Technical Notes
- [Implementation details worth remembering]

### Tests
- [Test results: X passed, Y failed]
- [Any test-related notes]

### Wins
- [What went well]

### Problems
- [What went wrong and how it was resolved]

### Next Steps
- [What comes next]
```

---

*Journal entries are append-only. Never edit past entries except to add resolution notes.*

## Version 0.1.1.0 - Tool Registry

**Date:** 2026-02-05  
**Phase:** 1.1 (Core Foundation - Tool Registry Enhancement)  
**Status:** Complete  

### What Was Done
- Created `bountyhunter/tools/registry.py` - Central ToolRegistry system
- Two-tier architecture: Wrapped (Tier 1) and Discovered (Tier 2) tools
- Auto-discovery of all installed Kali security tools
- 25+ pre-defined tool metadata entries in KNOWN_TOOLS
- ToolCapability enum for LLM-driven task planning
- Safety classification: `requires_authorization`, `can_modify_target`, `is_passive`
- LLM context generation: `build_llm_context()`, `build_tool_selection_prompt()`
- Help text extraction and flag parsing from `--help` output
- Global singleton with lazy initialization
- Updated `tools/__init__.py` with registry exports, backward-compatible
- Created `tests/test_phase1_1_registry.py` with 58 tests across 11 test classes

### Key Decisions Made
- **Moved to Claude Opus 4.6**: From this build forward, development is assisted by Claude Opus 4.6 (upgraded from Sonnet 4.5 used in Phase 0 and Phase 1). This aligns with the project's need for deeper architectural reasoning as we move into more complex phases.
- **Direct translation over wrappers for exploit pipeline**: The ToolRegistry enables the LLM to generate arbitrary commands for any Kali tool through NativeExecutor, while wrapped tools provide structured I/O for the recon pipeline. This avoids needing a wrapper per tool for exploit-phase work.
- **Fail-closed safety**: Unknown tools (not in registry) default to `requires_auth=True`. The authorization gate decides, not the registry.
- **Two-tier design**: Wrapped tools (★) get structured schemas/parsers. Discovered tools (○) get basic metadata from --help. Both are visible to the LLM.
- **Pre-defined KNOWN_TOOLS**: 25+ Kali tools with hand-curated metadata (category, capabilities, safety flags, usage hints) so the LLM gets rich context even without probing --help.

### Technical Notes
- `_parse_common_flags()` uses regex to extract flags from help text including argument placeholders (e.g., `-p, --port PORT`)
- Help text is capped at 2000 chars per tool to manage LLM context window
- Discovery probes `--help`, `-h`, `help` with 5s timeout per tool
- Version extraction tries `--version`, `-V`, `-v`, `version` in order
- `build_llm_context()` groups by category and marks tier with ★/○ visual indicators
- Registry init imports wrappers inside function to avoid circular imports

### Tests
- 58 new tests: ALL PASSED
- 48 existing tests (Phase 0 + Phase 1): ALL PASSED
- Total: 106 tests, 0 failures, 0 regressions
- Test coverage: registry creation, both tiers, discovery, all lookup methods, safety classification, LLM context generation, serialization, singleton lifecycle, helper functions, KNOWN_TOOLS integrity, edge cases

### Wins
- Clean two-tier design that unlocks direct execution for exploit pipeline without rearchitecture
- Fail-closed safety default (unknown tools require auth) is the right call
- LLM context generation produces clean, filterable tool descriptions
- Zero regressions on existing tests
- 25+ tool definitions give the LLM immediate awareness of the Kali ecosystem

### Problems
- Initial flag parsing regex missed flags with argument placeholders (`-p, --port PORT`)
- Fixed by updating regex to include optional `[A-Z_]+` argument capture
- Fixed in same session, no rework needed

### Next Steps
- Phase 2: Platform Integration (HackerOne/Bugcrowd API clients)
- The ToolRegistry is now the backbone for LLM tool selection in Phases 4-6

---

## Version 0.2.0.0 - Platform Integration

**Date:** 2026-02-05  
**Phase:** 2 (Platform Integration)  
**Status:** Complete  
**Model:** Claude Opus 4.6  

### What Was Done
- Created `bountyhunter/platforms/models.py` - Platform-agnostic data models
  - Program, ScopeEntry, ScopeValidator, ScopeValidationResult
  - AssetType enum (domain, wildcard, CIDR, IP, URL, mobile, API, source_code, etc.)
  - Platform enum (hackerone, bugcrowd, manual)
  - ScopeEntry.matches() with domain/wildcard/CIDR/IP/URL matching logic
- Created `bountyhunter/platforms/base.py` - Shared HTTP client infrastructure
  - BasePlatformClient ABC with auth, retry, rate limiting
  - RateLimiter (token bucket)
  - Error hierarchy: PlatformAPIError → AuthenticationError, RateLimitError, NotFoundError
  - ClientConfig dataclass
- Created `bountyhunter/platforms/hackerone.py` - HackerOne Hacker API v1 client
  - HTTP Basic Auth, program listing, scope fetching
  - Full normalization from H1 JSON:API format to our models
  - Asset type mapping (WILDCARD, URL, CIDR, mobile, etc.)
- Created `bountyhunter/platforms/bugcrowd.py` - Bugcrowd REST API client
  - Token auth, JSON:API include/fields support
  - target_groups → targets scope extraction
  - Smart asset type inference from identifier strings
- Created `bountyhunter/platforms/cache.py` - SQLite program cache
  - WAL mode, foreign keys, proper indexing
  - Full CRUD: upsert, get, list, search, delete, clear
  - Staleness checking for cache invalidation
  - Cross-platform scope search
- Created `tests/test_phase2_platforms.py` - 67 environment-agnostic tests
- Created `tests/test_phase2_kali_native.py` - Live API integration tests for Kali

### Key Decisions Made
- **Thin clients, no wrapper abstraction** per architecture decision from Phase 1 review
- **ScopeValidator is fail-closed**: out-of-scope checked FIRST (overrides in-scope), empty scope = blocked, no match = blocked
- **SQLite over JSON files**: WAL mode gives concurrent reads, proper indexing enables fast scope search across all programs
- **Smart asset inference for Bugcrowd**: Their API is less typed than H1, so we infer CIDR/wildcard/IP from the identifier string itself

### Architecture: ScopeValidator Safety Design
```
Target → Check out-of-scope FIRST → Check in-scope → No match = FAIL_CLOSED
         ↓ match = BLOCKED          ↓ match = PASS   ↓ = BLOCKED
```
This is non-negotiable. Out-of-scope always wins. Unknown always loses.

### Tests
- 67 new tests: ALL PASSED (environment-agnostic)
- 173 total tests across all phases: ALL PASSED, 0 regressions
- Kali-native test script provided for live API verification

### Deliverable Checklist
- [x] HackerOne API client
- [x] Bugcrowd API client
- [x] Program data models
- [x] Local program cache (SQLite)
- [x] Scope parsing and validation
- [x] Rate limit management

### Next Steps
- Run `test_phase2_kali_native.py` on Kali with real API credentials
- Phase 3: CVE Correlation

---

## Version 0.2.0.1 - Kali Validation + Bugfix

**Date:** 2026-02-06  
**Phase:** 2 (Platform Integration - Patch)  
**Status:** Validated on Kali  
**Model:** Claude Opus 4.6  

### Kali Native Test Results
- Python 3.13.9, Kali Linux
- Credential Manager: ✅ All tests passed (setup, persistence, permissions 600)
- HackerOne Auth: ✅ Authenticated successfully
- HackerOne Programs: ✅ Fetched 5 programs (first: "security" / HackerOne)
- HackerOne Scope: ✅ 35 scope entries parsed from HackerOne's own program
- HackerOne Program Detail: ✅ Full detail fetch with state/bounties/scope
- HackerOne Scope Validation: ✅ Real-data validation confirmed
  - `app.pullrequest.com` → IN_SCOPE ✓
  - `definitely-not-in-scope-12345.evil.test` → FAIL_CLOSED ✓
- H1 Cache Flow: ❌ Fixed (see below)
- Cross-Platform: ✅ Passed

### Bug Fixed
- **H1 Cache Flow TypeError**: HackerOne API returns `None` for boolean fields
  (`offers_bounties`, `triage_active`) on some programs. `int(None)` crashes.
  - Fix: `int(bool(program.offers_bounties))` in cache upsert
  - Also hardened: `bool()` wrapping in HackerOne normalizer
  - Also hardened: `float(x or 0.0)` for numeric fields (response_efficiency, bounties)

### Bugcrowd Status
- **DEFERRED**: Bugcrowd API requires Organization Owner role to provision API tokens.
  Client code is complete and tested (normalization, JSON:API parsing, asset inference).
  Will validate when API access is available.

### Tests
- 188 passed, 0 failed, 36 skipped (Kali native)
- Zero regressions after bugfix

---

## Version 0.2.1.0 — Architecture Pivot: Platform-Agnostic + Rename to Kestrel

**Date:** 2026-02-20
**Phase:** 2.1 (Architecture Pivot)
**Status:** ✅ Complete
**Model:** Claude Sonnet 4.6 (Claude Code)

### What Was Done

**Project renamed from BountyHunter → Kestrel:**
- Parent folder renamed: `Claude Projects/BountyHunter/` → `Claude Projects/Kestrel/`
- Python package renamed: `bountyhunter/` → `kestrel/`
- All imports, references, credential paths, config values updated across entire codebase
- GitHub repo created: `digitard/Kestrel`
- README.md, CLAUDE.md, PROJECT_DOCUMENTATION.md fully rewritten for new name and architecture

**Architecture pivot — "Kali native only" → Platform-Agnostic:**

The original "Kali native only, no Docker" mandate was revised after architectural review. Key drivers:
- Development on Mac M-series with VMWare Fusion Kali VM is limiting: Claude Code can't directly test native tools, local LLM inference inside a VM has no GPU passthrough (CPU-only = unusably slow)
- Mac M-series with MLX (Neural Engine + unified memory) is the fastest local LLM platform available — better than most dedicated hardware
- Docker for tool execution solves the Mac development problem while keeping the Kali toolset intact
- A dedicated Intel i7-1365U / 32GB / Intel Xe Kali machine exists but is weaker for local LLM (Ollama Vulkan mode) than the Mac (MLX)

**New architecture: Capability Parity, Hardware-Determined Pace:**

Every user gets full feature set. Hardware determines speed, not capability.

LLM engine auto-detection:
1. Apple Silicon → MLX (fastest local inference)
2. CUDA GPU → Ollama + CUDA
3. Vulkan GPU → Ollama + Vulkan (Intel Xe, AMD)
4. Everything else → Ollama CPU
5. Complex tasks on any platform → Anthropic API (HybridRouter)

Tool execution auto-detection:
1. Native Kali Linux → subprocess directly (bypass Docker)
2. Docker available → Kali container (kestrel-tools image)
3. Neither → clear error + install instructions

**CTFRunner components identified for port:**
- `LLMBackend` Protocol + `Message`/`LLMResponse` dataclasses
- `HybridRouter` — complexity-based routing (simple→local, complex→API)
- `BackendFactory` — platform-aware factory (MLX/Ollama/Anthropic)
- `MLXBackend` — Apple Silicon local inference
- `OllamaBackend` — all other platforms
- Orchestrator loop pattern (Plan/Execute/Observe/Reason with `<cmd>` tags)
- Knowledge store pattern (SQLite + FAISS)

### Key Decisions Made

**Decision: Rename to Kestrel**
- "BountyHunter" too generic, poor as a brand/GitHub name
- "Kestrel" — a hunting falcon, precise and fast, hunts alone, flows well phonetically
- No major security tool conflicts (kestrel-lang by OpenCybersecurityAlliance is a query language, different niche)
- GitHub: `digitard/Kestrel`

**Decision: Docker + Native Detection instead of Kali-only**
- Unblocks development on Mac with full Claude Code testing capability
- Ollama/MLX on Mac host (not in VM) gets full Metal GPU — dramatically faster than VM CPU inference
- Native Kali auto-bypass preserves zero-overhead path for dedicated Kali hardware
- Same codebase works on 8GB MacBook Air through dedicated GPU rigs — hardware determines pace

**Decision: Phase 3 combines LLM layer port + CVE correlation**
- CTFRunner LLM abstraction is prerequisite for cost-efficient CVE correlation
- Building both together avoids retrofitting later
- HybridRouter routes CVE lookups to local LLM, exploit planning to cloud API

### Tests
- 188 passed, 36 skipped, 0 failed
- Zero regressions after full rename and reference update
- Baseline maintained through architectural pivot

### Wins
- Clean rename with zero test regressions
- Architecture now supports the full user spectrum (8GB MacBook through dedicated server)
- CTFRunner reuse dramatically reduces Phase 3 development effort
- Claude Code on Mac can now directly test tool integration via Docker

### Problems
- `sed -i ''` (BSD sed on macOS) missed README.md in bulk replace — caught immediately by test suite, fixed with targeted sed
- Historical journal entries intentionally retain original "bountyhunter" path references for accuracy

### Next Steps
- Phase 3: Port CTFRunner LLM layer + build CVE correlation on top of it
- Build Kali Docker image (kestrel-tools) with pinned tool versions
- Add Docker executor mode to NativeExecutor with Kali detection bypass

---

## Architectural Reset Decision — Foundation Rebuild

**Date:** 2026-02-20
**Type:** Strategic Decision (no version bump — pre-build planning entry)
**Status:** Decision Made — Rebuild begins at v0.3.0.0
**Model:** Claude Sonnet 4.6 (Claude Code)

### The Decision

After reviewing the full phase plan against the new platform-agnostic architecture, the decision was made to **perform a foundational rebuild of Kestrel rather than continue building on the existing phase structure.**

This is not a rewrite from scratch. It is a surgical restructuring: the existing codebase is reviewed, platform-agnostic components are migrated into a clean new foundation, and components built on the wrong assumptions (Kali-native-only) are rebuilt correctly from the start.

### Why This Decision Was Made

**Intent from operator:**
> "Foundation is everything. It's better to take the regression in phases now due to our shifted focus and the important ingestion of supporting code from CTFRunner where we can cleanly build out and test, versus the problems likely if we start to build into it without a proper foundation."

This is the correct call. The original phase structure was designed around "Kali native only, no Docker" — a mandate that has since been fully reversed. Several foundational components were built under that wrong assumption:

1. **`core/executor.py` (NativeExecutor)** — Built assuming always-native subprocess on Kali. The new architecture requires a unified execution abstraction that detects native Kali vs Docker at runtime and routes accordingly. Retrofitting this after other phases are built on top of it is guaranteed to be messier than rebuilding it as the true foundation it is.

2. **`kestrel/llm/`** — The existing LLM layer is a thin placeholder (single Anthropic client, basic prompts). The new design calls for the full CTFRunner abstraction pattern: `LLMBackend` Protocol, `HybridRouter`, `BackendFactory` with platform detection, `MLXBackend`, `OllamaBackend`. This is not an extension of the existing code — it replaces it entirely, and it should be Phase 2 of the new structure, not Phase 3.

3. **Docker infrastructure** — Entirely absent from the current codebase. Under the new architecture, this is foundational. The Kali Docker image (ARM64 + AMD64 multi-arch), tool manifest, and container execution layer need to exist before tool wrappers and the ToolRegistry can be properly validated on non-Kali platforms. This belongs in Phase 1.

4. **Phase ordering** — The original phase plan treated the execution layer and LLM layer as subordinate components. They are actually the foundation everything else depends on. Getting the ordering wrong and building on top of it compounds technical debt with every subsequent phase.

### What Is Being Preserved

The rebuild does not discard all existing work. The following components were built correctly and are platform-agnostic by design — they migrate cleanly into the new structure:

| Component | Status | Notes |
|---|---|---|
| `platforms/hackerone.py` | ✅ Migrate | Pure API client, no execution assumptions |
| `platforms/bugcrowd.py` | ✅ Migrate | Pure API client, no execution assumptions |
| `platforms/models.py` | ✅ Migrate | Data models (Program, ScopeEntry, ScopeValidator) |
| `platforms/cache.py` | ✅ Migrate | SQLite cache, fully platform-agnostic |
| `platforms/credentials.py` | ✅ Migrate | CredentialManager, already updated for new credential set |
| `platforms/base.py` | ✅ Migrate | BasePlatformClient, RateLimiter, error hierarchy |
| `parsers/` (all) | ✅ Migrate | Pure Python parsing, zero execution assumptions |
| `core/config.py` | ✅ Migrate | Config system, needs new keys for Docker/LLM |
| `core/session.py` | ✅ Migrate | Session state machine, platform-agnostic |
| `tools/base.py` | ✅ Migrate | Tool wrapper base class, needs new executor underneath |
| Tool wrappers (nmap, gobuster, nikto, sqlmap) | ✅ Migrate | Wrapper logic is sound, needs working executor |
| Test suite (188 passing, 36 skipped) | ✅ Migrate | Tests against platform-agnostic components survive |

| Component | Status | Notes |
|---|---|---|
| `core/executor.py` | ❌ Rebuild | Assumes Kali-native subprocess only |
| `kestrel/llm/` (all) | ❌ Rebuild | Replace with CTFRunner pattern entirely |
| `tools/registry.py` | ⚠️ Rebuild | Discovery logic needs Docker-aware executor underneath |
| Docker layer | ❌ Build new | Does not exist — foundational Phase 1 deliverable |
| `kestrel/knowledge/` | ❌ Build new | Does not exist — Phase 5 deliverable |

### CTFRunner: Sister Project in the Same Methodology

CTFRunner is a separate project in the "Intent is the New Skill" series — an AI-powered Capture The Flag assistant built using the same methodology as Kestrel: human provides intent, AI writes all code, every phase tested before advancing, no hands-on coding by the operator.

CTFRunner and Kestrel share significant overlapping architectural needs:
- Both require a hybrid LLM layer (local for cheap tasks, cloud API for complex reasoning)
- Both run an agent loop (Plan/Execute/Observe/Reason)
- Both need a knowledge store for technique recall (SQLite + FAISS)
- Both run security tools and need to handle output parsing

Rather than rebuild these components from scratch in Kestrel, the decision was made to port the proven, tested implementations directly from CTFRunner. This is not code sharing in a dependency sense — CTFRunner is read-only reference material. The components are ported (adapted, renamed, extended for bug bounty context) into Kestrel's own codebase.

CTFRunner components being ported:
- `llm/backend.py` → `LLMBackend` Protocol + `Message`/`LLMResponse` dataclasses
- `llm/hybrid_router.py` → `HybridRouter` (classify simple/complex, route to local/API)
- `llm/backend_factory.py` → `BackendFactory` (auto-detect MLX/Ollama/Anthropic)
- `llm/mlx_backend.py` → `MLXBackend` (Apple Silicon inference)
- `llm/ollama_backend.py` → `OllamaBackend` (all other platforms)
- `core/orchestrator.py` → Hunt orchestrator loop pattern (adapted for bug bounty context)
- `knowledge/store.py` + `knowledge/technique_library.py` → CVE/technique knowledge base

### New Phase Structure

The phase plan is restructured to reflect correct foundational ordering. Version numbers continue forward from 0.2.1.0 — the BB segment no longer maps 1:1 to phase numbers after the reset, and that is intentional. The journal is the source of truth for what each version represents.

```
Phase 0  — Scaffold + Platform Detection      (complete: v0.0.x.x–v0.2.1.0)
Phase 1  — Execution Layer                    (v0.3.x.x) ← START HERE
           Docker image (ARM64 + AMD64 Kali)
           Native Kali detection + bypass
           Unified executor abstraction
           Tool manifest + missing tool logging

Phase 2  — LLM Abstraction Layer              (v0.4.x.x)
           Port from CTFRunner: Backend Protocol, HybridRouter,
           BackendFactory, MLXBackend, OllamaBackend

Phase 3  — Tool Layer                         (v0.5.x.x)
           Migrate tool wrappers + parsers onto new executor
           ToolRegistry with Docker-aware discovery

Phase 4  — Platform Integration               (v0.6.x.x)
           Migrate H1, Bugcrowd, ScopeValidator, cache, credentials
           Add IntiGriti, YesWeHack stubs for future expansion

Phase 5  — CVE + Knowledge Layer              (v0.7.x.x)
           NVD API client
           Exploit-DB / searchsploit integration
           Shodan/Censys passive recon
           SQLite + FAISS knowledge store (port from CTFRunner)
           LLM-assisted CVE matching + exploitability scoring

Phase 6  — Hunt Orchestrator                  (v0.8.x.x)
           Plan/Execute/Observe/Reason loop (port from CTFRunner)
           Multi-target persistent sessions
           Finding aggregation + evidence capture

Phase 7  — Authorization Gate                 (v0.9.x.x)
           Exploit plan display
           Human approval workflow (CLI first, UI later)
           Audit logging of all decisions

Phase 8  — Exploit Execution Loop             (v0.10.x.x)
           Autonomous rabbit-hole following
           Post-exploit tracking (shell/creds/root/lateral)
           Scope re-validation at every step

Phase 9  — Web API                            (v0.11.x.x)
           FastAPI + WebSocket
           Real-time hunt progress streaming

Phase 10 — Web UI                             (v0.12.x.x)
           Program browser + hunt management
           Authorization modal
           Real-time hunt display

Phase 11 — Report Generation + Submission     (v0.13.x.x)
           H1/Bugcrowd formatted reports
           Evidence packaging
           API submission

Phase 12 — Polish + Integration               (v1.0.0.0)
           Edge case hardening, demo prep, docs complete
```

### Tests at Decision Point
- 188 passed, 36 skipped, 0 failed
- All passing tests are against platform-agnostic components — they migrate with the rebuild

### What Happens Next
- `PROJECT_DOCUMENTATION.md` rewritten with new architecture and phase structure
- `CLAUDE.md` updated to reflect new phase numbering and foundation-first ordering
- Phase 1 (Execution Layer) begins at v0.3.0.0
- All work proceeds under the "Intent is the New Skill" methodology: tests pass before any phase advances, every version bump journaled, every build committed and pushed to GitHub

---

## Version 0.3.0.0 - Phase 1: Execution Layer

**Date:** 2026-02-20
**Phase:** 1 (Execution Layer)
**Status:** Complete
**Intent:** "Build the platform-detection and tool-execution foundation that every later phase depends on"

### What Was Built

#### `kestrel/core/platform.py` — PlatformInfo Detection
Auto-detects the runtime environment at startup. Returns a `PlatformInfo` dataclass consumed by the executor and LLM factory. No user configuration required — detection is fully automatic.

Key types:
- `ExecutionMode` enum: `NATIVE` (Kali subprocess), `DOCKER` (container), `UNAVAILABLE`
- `LLMBackendType` enum: `MLX` (Apple Silicon), `OLLAMA_CUDA`, `OLLAMA_VULKAN`, `OLLAMA_CPU`, `ANTHROPIC_ONLY`
- `PlatformInfo` dataclass: os_name, arch, ram_gb, execution_mode, llm_backend, recommended_model, summary
- `get_platform()` singleton — detected once, cached for the session
- `reset_platform()` — test support

Detection hierarchy:
```
LLM:   Apple Silicon → MLX | CUDA GPU → Ollama+CUDA | Vulkan → Ollama+Vulkan | else → Ollama CPU
Tools: Native Kali → subprocess | Docker available → Kali container | else → UNAVAILABLE
```

Model sizing: RAM-tiered recommendations (8 GB → Mistral 7B, 128 GB+ → Llama 3.1 70B).

#### `docker/Dockerfile` — Kali Linux Tool Image
Multi-arch (ARM64 + AMD64) Docker image from `kalilinux/kali-rolling`.

Tools installed:
- **Tier 1 (wrapped, structured parsers):** nmap, gobuster, nikto, sqlmap
- **Tier 2 (apt):** whatweb, dirb, dnsenum, dnsrecon
- **Tier 2 (Go binaries, pinned):** ffuf 2.1.0, subfinder 2.6.6, httpx 1.6.8, nuclei 3.3.7
- **Exploit research:** exploitdb (searchsploit)
- **Wordlists:** wordlists, seclists (rockyou auto-decompressed)

Workspace: `/workspace`, `/workspace/output`, `/workspace/scans`, `/workspace/loot`
Container kept alive with `CMD tail -f /dev/null` for `docker exec` access.

#### `docker/tool_manifest.yaml` — Tool Version Manifest
YAML manifest tracking installed tools (tier, install method, pinned version, binary name, description).
Includes a `missing_tools_log: {}` section populated at runtime by DockerManager when a tool request fails — developer feedback loop for next Dockerfile build.

#### `kestrel/core/docker_manager.py` — Docker Container Manager
Manages the kestrel-tools container lifecycle using subprocess (no Python docker SDK required).

Key capabilities:
- `is_available()` — checks docker CLI and daemon connectivity
- `is_running()` — checks container state via `docker inspect`
- `ensure_running()` — start stopped container, create new container, auto-build image
- `exec_command(command, workdir, timeout)` — `docker exec` with timeout wrapping, returns `ExecutionResult`
- `check_tool(tool)` — `which <tool>` inside container
- `get_tool_version(tool)` — `<tool> --version` inside container
- `build_image()` — `docker build -t kestrel-tools:latest docker/`
- `_detect_missing_tool()` — exit code 127 / "command not found" detection
- `_log_missing_tool()` — updates `docker/tool_manifest.yaml` missing_tools_log
- `status()` — health-check dict for CLI / debugging

Workspace: `~/.kestrel/workspace` mounted to `/workspace` in container.
Container runs with `--network host` for full target reachability.

#### `kestrel/core/executor.py` — Added UnifiedExecutor
`NativeExecutor`, `ExecutionResult`, `ExecutionStatus`, `check_kali_environment` retained unchanged (backward compat — 188 passing tests rely on these).

New `UnifiedExecutor` added:
- `__init__(platform_info=None)` — auto-detects if None
- `execute(command, timeout, env, cwd, on_output)` — same signature as NativeExecutor
- Routes to `NativeExecutor` (NATIVE mode) or `DockerManager.exec_command` (DOCKER mode)
- Returns `ExecutionResult(FAILED)` with install instructions on UNAVAILABLE
- `execute_tool(tool, args, ...)` — tool availability check + execute
- `check_tool(tool)`, `get_tool_version(tool)`, `cancel_all()` — delegated to active backend
- `execution_mode` property, `platform` property, `status()` dict

`kestrel/core/__init__.py` updated to export: `UnifiedExecutor`, `PlatformInfo`, `ExecutionMode`, `LLMBackendType`, `detect_platform`, `get_platform`, `reset_platform`, `DockerManager`.

### Tests Added

#### `tests/test_phase1_executor.py` (80 tests)
- Backward-compat imports: all legacy Phase 1 exports still importable
- PlatformInfo dataclass contracts (can_run_tools, uses_local_llm, to_dict, summary)
- Platform detection helpers (all detection functions, model sizing, singleton)
- UnifiedExecutor NATIVE mode routing
- UnifiedExecutor DOCKER mode delegation
- UnifiedExecutor UNAVAILABLE mode (returns FAILED, clear error message)
- ExecutionResult contracts (success property, to_dict)

#### `tests/test_phase1_docker.py` (49 tests)
- DockerManager availability (CLI present, daemon responds)
- Container state detection (is_running, _image_exists, _container_exists)
- ensure_running state machine (already running, start stopped, create new, build image)
- exec_command (success, failure, timeout detection, container-not-started)
- Missing tool detection (exit 127, "command not found" string, chained commands, no false positives)
- status() structure
- check_tool / get_tool_version

### Error Encountered and Fixed

**Test failure:** `TestDockerManagerToolCheck::test_check_tool_found` — `check_tool()` calls `is_running()` before `exec_command()`. Test patched `exec_command` but forgot to patch `is_running`. Since Docker is not running on the dev machine (macOS + Claude Code), `is_running()` returned False, short-circuiting the mock. Fixed by adding `patch.object(mgr, "is_running", return_value=True)`.

### Test Results
- **Before:** 188 passed, 36 skipped, 0 failed
- **After:** 268 passed, 36 skipped, 0 failed (+80 new tests, 0 regressions)

### Files Changed
- `kestrel/core/platform.py` — NEW
- `docker/Dockerfile` — NEW
- `docker/tool_manifest.yaml` — NEW
- `kestrel/core/docker_manager.py` — NEW
- `kestrel/core/executor.py` — MODIFIED (added UnifiedExecutor, updated docstring)
- `kestrel/core/__init__.py` — MODIFIED (added new exports)
- `tests/test_phase1_executor.py` — NEW
- `tests/test_phase1_docker.py` — NEW
- `VERSION` — 0.2.1.0 → 0.3.0.0
- `kestrel/__init__.py` — version bump
- `pyproject.toml` — version bump

### Architecture Note
The Capability Parity Principle is now implemented at the execution layer: every user gets the same features regardless of hardware. Hardware determines pace, not capability. An 8 GB Mac runs the same recon pipeline as a 32 GB Kali workstation — Docker containers handle the tool execution transparently on the Mac, native subprocess on the Kali box.

---

## Version 0.3.0.1 - ASCII Banner + GNU GPL v3 License

**Date:** 2026-02-20
**Phase:** 1 (Core Foundation — polish)
**Status:** Complete

### What Was Done
- Created `kestrel/banner.py` — KESTREL block-art ASCII logo with OTS tag right-aligned to logo edge, bordered info box (version/author/license). Mirrors CTFRunner banner.py API: `get_banner()`, `print_banner()`, `get_banner_plain()`.
- Migrated project license from MIT to GNU General Public License v3.
  - Added `LICENSE` file (full GPL v3 text, copied from CTFRunner).
  - Added GPL v3 file header to all 38 `kestrel/` Python source files.
  - Updated `pyproject.toml` license field and classifier.
  - Updated `README.md` license section with copyright notice.

### Test Results
- **After:** 268 passed, 36 skipped, 0 failed (no change — no new tests this build)

### Files Changed
- `kestrel/banner.py` — NEW
- `LICENSE` — NEW
- All 38 `kestrel/**/*.py` — GPL v3 headers added
- `pyproject.toml` — license field + classifier updated
- `README.md` — license section updated

### Note on Version Strings
Version strings in `VERSION`, `kestrel/__init__.py`, and `pyproject.toml` were inadvertently not bumped in this commit. Corrected in v0.3.0.2.

---

## Version 0.3.0.2 - Banner Alignment + README Logo

**Date:** 2026-02-20
**Phase:** 1 (Core Foundation — polish)
**Status:** Complete

### What Was Done
- Fixed KESTREL ASCII art T-bar alignment: top bar `███████ ` was visually left-shifted relative to the T stem in rows 2-5. Changed to `  █████ ` (2sp+5█+sp), centering the 5-wide bar over the 2-wide stem (bar center at relative col 4 vs stem center at ~4.5 — essentially aligned).
- Added ASCII logo block to `README.md` directly below the `# Kestrel` heading.
- Updated `README.md` development status version (was stale at 0.0.0.1).
- Fixed `__license__` string in `kestrel/__init__.py` (was still `"MIT"`, now `"GPL-3.0-or-later"`).
- Properly bumped all version strings: `VERSION`, `kestrel/__init__.py`, `pyproject.toml` → 0.3.0.2.

### Test Results
- **After:** 268 passed, 36 skipped, 0 failed (no regressions)

### Files Changed
- `kestrel/banner.py` — MODIFIED (T bar row 1 + get_banner_plain row 1)
- `README.md` — MODIFIED (logo block added, version updated)
- `kestrel/__init__.py` — version 0.3.0.0 → 0.3.0.2, license MIT → GPL-3.0-or-later
- `VERSION` — 0.3.0.0 → 0.3.0.2
- `pyproject.toml` — version 0.3.0.0 → 0.3.0.2

---

## Version 0.3.0.3 - Deprecated Content Cleanup

**Date:** 2026-02-20
**Phase:** 1 (Core Foundation — housekeeping)
**Status:** Complete

### What Was Done
Removed stale BountyHunter-era content before it became harder to trace:

- **Deleted `run.sh`** — Old bash startup script with BountyHunter box-drawing logo, wrong env var names, references to `kestrel.api.main:app` (not built yet), and `python` instead of `python3`. Superseded by `kestrel/banner.py` for branding; proper entrypoint will be created in Phase 7.
- **Deleted `screenshot.png` and `screenshot2.png`** — Debug screenshots, not project files.
- **Replaced `kestrel/assets/__init__.py`** — Entire file was old BountyHunter Figlet logo (`LOGO`, `LOGO_COMPACT`, `Colors`, `print_logo()` etc.). Replaced with a minimal GPL placeholder. Branding now lives in `kestrel/banner.py`.
- **Updated `toolcheck.sh`** — Version header `v0.0.0.1` → `v0.3.0.2`. Kali check now warns instead of hard-exiting; non-Kali systems use Docker and can skip this script.
- **Updated `tests/test_phase0_scaffold.py`** — Removed `run.sh` from `test_root_files_exist` and `test_scripts_are_executable`.
- **Kept `kestrel/llm/anthropic.py`** — Still referenced by tests; will be properly replaced by `anthropic_backend.py` during Phase 2.

### Test Results
- **After:** 268 passed, 36 skipped, 0 failed (no regressions)

### Files Changed
- `run.sh` — DELETED
- `screenshot.png` / `screenshot2.png` — DELETED
- `kestrel/assets/__init__.py` — REPLACED (stub placeholder)
- `toolcheck.sh` — MODIFIED (version + Kali check message)
- `tests/test_phase0_scaffold.py` — MODIFIED (removed run.sh references)
- `VERSION` / `kestrel/__init__.py` / `pyproject.toml` — 0.3.0.2 → 0.3.0.3

---

## Version 0.4.0.0 - Phase 2: LLM Abstraction Layer

**Date:** 2026-02-20
**Phase:** 2 (LLM Abstraction Layer)
**Status:** Complete

### What Was Done

Ported and adapted CTFRunner's full LLM stack into Kestrel. The abstraction
layer enables platform-aware backend selection, complexity-based routing, and
context window management — all without touching the orchestrator or tools.

**New files in `kestrel/llm/`:**
- **`backend.py`** — `LLMBackend` Protocol, `Message` and `LLMResponse` dataclasses.
  The orchestrator will depend only on this interface, never on a specific backend.
- **`context_trimmer.py`** — Token budget trimmer. Char-based heuristic (1 token ≈ 4 chars).
  Keeps first message (hunt context) + most recent tail; drops middle messages when over budget.
- **`anthropic_backend.py`** — Cloud API backend for complex tasks (CVE correlation,
  exploit planning, report generation). Resolves key from env var → `~/.kestrel/credentials.yaml`.
  Includes per-model pricing table for cost estimation.
- **`mlx_backend.py`** — Apple Silicon local inference via MLX. Lazy-loads model on first use.
  Uses `PlatformInfo.recommended_model` for hardware-appropriate model selection.
- **`ollama_backend.py`** — Ollama backend for all non-Apple-Silicon platforms (CUDA/Vulkan/CPU).
  Speaks the Ollama `/api/chat` REST API; no external SDK dependency.
- **`hybrid_router.py`** — Complexity classifier + router. Routes simple recon tasks (banner
  parsing, port summary) to local; complex tasks (CVE correlation, exploit planning,
  report generation) to Anthropic API. Three-stage classification: keyword scan →
  LLM fallback → cache. Safe default: ambiguous = complex.
- **`backend_factory.py`** — Platform-aware factory. Uses `PlatformInfo.llm_backend`
  (detected at startup by `kestrel.core.platform`) to select MLX vs Ollama vs Anthropic.
  Supports modes: `"api"`, `"local"`, `"hybrid"` (default), `"auto"`.

**Updated files in `kestrel/llm/`:**
- **`prompts.py`** — Added `BUG_BOUNTY_SYSTEM_PROMPT` — bug-bounty-specific system prompt
  used by all backends. Covers: authorization gate, CVE correlation, exploit planning,
  report format, scope awareness, and command execution via `<cmd>` tags.
- **`__init__.py`** — Re-exported all new types. Legacy exports (`AnthropicClient`,
  builder functions) kept for Phase 1 test backward compatibility.

**Updated `config/default.yaml`:**
- Added `llm.mode` (`"hybrid"` default)
- Added `llm.api` (model, max_tokens, temperature for cloud backend)
- Added `llm.local` (backend auto-select, context_length, ollama_host)
- Added `llm.hybrid` (fallback flags, keyword overrides)

**New test file:**
- **`tests/test_llm/test_phase2_llm.py`** — 72 tests covering all new modules:
  Message/LLMResponse dataclasses, context trimmer (all edge cases), HybridRouter
  (keyword routing, LLM fallback, fallback-on-error, no-fallback-raises),
  BackendFactory (all modes + platform routing), AnthropicBackend pricing,
  OllamaBackend message building, and module import smoke tests.

### Key Design Decisions

1. **PlatformInfo drives local backend selection** — `backend_factory.py` reads
   `PlatformInfo.llm_backend` (LLMBackendType enum) rather than re-detecting
   Apple Silicon inline. Single source of truth.

2. **Complex keywords take priority over simple** — In HybridRouter, if a prompt
   matches both keyword sets, complex wins. Safety-first: use the more capable
   backend when in doubt.

3. **Module-level import for patchability** — `get_platform` is imported at the
   top of `mlx_backend.py` and `ollama_backend.py` (not inside `__init__`) so
   tests can patch it with `unittest.mock.patch`.

4. **No external tokenizer** — Context trimmer uses char-based heuristic
   (1 token ≈ 4 chars) to avoid mlx-lm/tiktoken as a hard dependency for trimming.

5. **Old `anthropic.py` retained** — Phase 1 tests still import `AnthropicClient`.
   Will be removed cleanly when Phase 6 (Hunt Orchestrator) replaces all call sites.

### Errors Encountered and Fixed

1. **`get_platform` not patchable** — Initially imported inside `__init__` method.
   Fixed by moving to module-level import.
2. **`asyncio.get_event_loop()` deprecated in Python 3.14** — Replaced all
   `asyncio.get_event_loop().run_until_complete(...)` with `asyncio.run(...)`.

### Test Results
- **Before:** 268 passed, 36 skipped, 0 failed
- **After:** 340 passed, 36 skipped, 0 failed (+72 new tests, 0 regressions)

### Files Changed
- `kestrel/llm/backend.py` — NEW
- `kestrel/llm/context_trimmer.py` — NEW
- `kestrel/llm/anthropic_backend.py` — NEW
- `kestrel/llm/mlx_backend.py` — NEW
- `kestrel/llm/ollama_backend.py` — NEW
- `kestrel/llm/hybrid_router.py` — NEW
- `kestrel/llm/backend_factory.py` — NEW
- `kestrel/llm/prompts.py` — MODIFIED (added BUG_BOUNTY_SYSTEM_PROMPT)
- `kestrel/llm/__init__.py` — MODIFIED (new exports + legacy compat)
- `config/default.yaml` — MODIFIED (llm.mode/api/local/hybrid sections)
- `tests/test_llm/__init__.py` — NEW (empty, makes directory a package)
- `tests/test_llm/test_phase2_llm.py` — NEW (72 tests)
- `VERSION` / `kestrel/__init__.py` / `pyproject.toml` — 0.3.0.3 → 0.4.0.0

---
