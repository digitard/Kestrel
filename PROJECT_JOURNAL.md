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
