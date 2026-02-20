# Kestrel — LLM-assisted bug bounty hunting platform
# Copyright (C) 2026 David Kuznicki and Kestrel Contributors
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

"""
Kestrel Configuration Management

Loads and manages application configuration from YAML files
and environment variables.
"""

import os
from pathlib import Path
from typing import Any, Optional
from dataclasses import dataclass, field

import yaml


# Default paths
DEFAULT_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "default.yaml"
USER_CONFIG_PATH = Path.home() / ".config" / "kestrel" / "config.yaml"


@dataclass
class ServerConfig:
    """Web server configuration."""
    host: str = "127.0.0.1"
    port: int = 8080
    reload: bool = False


@dataclass
class DatabaseConfig:
    """Database configuration."""
    path: str = "~/.local/share/kestrel/kestrel.db"
    program_cache_ttl: int = 86400  # 24 hours
    
    def get_path(self) -> Path:
        """Get expanded database path."""
        return Path(self.path).expanduser()


@dataclass
class LLMConfig:
    """LLM provider configuration."""
    provider: str = "anthropic"
    model: str = "claude-sonnet-4-20250514"
    max_tokens: int = 4096
    temperature: float = 0.0
    
    # Token budgets
    budget_translation: int = 500
    budget_analysis: int = 2000
    budget_exploit_planning: int = 3000
    budget_report_generation: int = 4000
    
    @property
    def api_key(self) -> Optional[str]:
        """Get API key from environment."""
        return os.environ.get("ANTHROPIC_API_KEY")


@dataclass
class ScopeConfig:
    """Scope validation configuration - CRITICAL SAFETY SETTINGS."""
    revalidate_before_exec: bool = True  # MUST be True
    fail_closed: bool = True  # MUST be True
    rate_limit_buffer: float = 1.5
    global_blocklist: list = field(default_factory=lambda: [
        "*.gov", "*.mil", "*.edu",
        "localhost", "127.0.0.1",
        "10.*", "172.16.*", "192.168.*"
    ])


@dataclass
class AuthorizationConfig:
    """Authorization gate configuration - CRITICAL SAFETY SETTINGS."""
    require_authorization: bool = True  # MUST be True - NEVER set to False
    show_commands: bool = True
    allow_step_authorization: bool = True
    prompt_timeout: int = 0  # 0 = no timeout


@dataclass
class AuditConfig:
    """Audit logging configuration."""
    enabled: bool = True  # SHOULD be True
    path: str = "~/.local/share/kestrel/audit/"
    retention_days: int = 90
    
    def get_path(self) -> Path:
        """Get expanded audit path."""
        return Path(self.path).expanduser()


@dataclass
class HuntingConfig:
    """Hunting behavior configuration."""
    max_concurrent_hunts: int = 1
    max_exploits_per_hunt: int = 5
    auto_suggest: bool = True
    
    # Tool timeouts (seconds)
    timeout_nmap_quick: int = 120
    timeout_nmap_full: int = 600
    timeout_gobuster: int = 300
    timeout_nikto: int = 300
    timeout_sqlmap: int = 600
    timeout_nuclei: int = 300
    timeout_default: int = 300
    
    def get_timeout(self, tool: str, scan_type: str = "default") -> int:
        """Get timeout for a specific tool."""
        if tool == "nmap":
            if scan_type == "quick":
                return self.timeout_nmap_quick
            return self.timeout_nmap_full
        
        timeout_attr = f"timeout_{tool}"
        return getattr(self, timeout_attr, self.timeout_default)


@dataclass
class Config:
    """Main configuration container."""
    server: ServerConfig = field(default_factory=ServerConfig)
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    llm: LLMConfig = field(default_factory=LLMConfig)
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    authorization: AuthorizationConfig = field(default_factory=AuthorizationConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    hunting: HuntingConfig = field(default_factory=HuntingConfig)
    
    # App metadata
    app_name: str = "Kestrel"
    app_version: str = "0.0.0.2"
    debug: bool = False
    log_level: str = "INFO"
    
    def validate_safety(self) -> list[str]:
        """
        Validate that critical safety settings are properly configured.
        Returns list of violations (empty if all good).
        """
        violations = []
        
        if not self.authorization.require_authorization:
            violations.append(
                "CRITICAL: authorization.require_authorization MUST be True"
            )
        
        if not self.scope.fail_closed:
            violations.append(
                "CRITICAL: scope.fail_closed MUST be True"
            )
        
        if not self.scope.revalidate_before_exec:
            violations.append(
                "WARNING: scope.revalidate_before_exec SHOULD be True"
            )
        
        if not self.audit.enabled:
            violations.append(
                "WARNING: audit.enabled SHOULD be True"
            )
        
        return violations


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dictionaries."""
    result = base.copy()
    
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = _deep_merge(result[key], value)
        else:
            result[key] = value
    
    return result


def _dict_to_config(data: dict) -> Config:
    """Convert dictionary to Config object."""
    config = Config()
    
    # App-level settings
    if "app" in data:
        app = data["app"]
        config.app_name = app.get("name", config.app_name)
        config.app_version = app.get("version", config.app_version)
        config.debug = app.get("debug", config.debug)
        config.log_level = app.get("log_level", config.log_level)
    
    # Server
    if "server" in data:
        s = data["server"]
        config.server = ServerConfig(
            host=s.get("host", "127.0.0.1"),
            port=s.get("port", 8080),
            reload=s.get("reload", False),
        )
    
    # Database
    if "database" in data:
        d = data["database"]
        config.database = DatabaseConfig(
            path=d.get("path", config.database.path),
            program_cache_ttl=d.get("program_cache_ttl", config.database.program_cache_ttl),
        )
    
    # LLM
    if "llm" in data:
        llm = data["llm"]
        budgets = llm.get("budgets", {})
        config.llm = LLMConfig(
            provider=llm.get("provider", "anthropic"),
            model=llm.get("model", config.llm.model),
            max_tokens=llm.get("max_tokens", config.llm.max_tokens),
            temperature=llm.get("temperature", config.llm.temperature),
            budget_translation=budgets.get("translation", config.llm.budget_translation),
            budget_analysis=budgets.get("analysis", config.llm.budget_analysis),
            budget_exploit_planning=budgets.get("exploit_planning", config.llm.budget_exploit_planning),
            budget_report_generation=budgets.get("report_generation", config.llm.budget_report_generation),
        )
    
    # Scope (CRITICAL)
    if "scope" in data:
        sc = data["scope"]
        config.scope = ScopeConfig(
            revalidate_before_exec=sc.get("revalidate_before_exec", True),
            fail_closed=sc.get("fail_closed", True),
            rate_limit_buffer=sc.get("rate_limit_buffer", 1.5),
            global_blocklist=sc.get("global_blocklist", config.scope.global_blocklist),
        )
    
    # Authorization (CRITICAL)
    if "authorization" in data:
        auth = data["authorization"]
        config.authorization = AuthorizationConfig(
            require_authorization=auth.get("require_authorization", True),
            show_commands=auth.get("show_commands", True),
            allow_step_authorization=auth.get("allow_step_authorization", True),
            prompt_timeout=auth.get("prompt_timeout", 0),
        )
    
    # Audit
    if "audit" in data:
        aud = data["audit"]
        config.audit = AuditConfig(
            enabled=aud.get("enabled", True),
            path=aud.get("path", config.audit.path),
            retention_days=aud.get("retention_days", 90),
        )
    
    # Hunting
    if "hunting" in data:
        h = data["hunting"]
        timeouts = h.get("timeouts", {})
        config.hunting = HuntingConfig(
            max_concurrent_hunts=h.get("max_concurrent_hunts", 1),
            max_exploits_per_hunt=h.get("max_exploits_per_hunt", 5),
            auto_suggest=h.get("auto_suggest", True),
            timeout_nmap_quick=timeouts.get("nmap_quick", 120),
            timeout_nmap_full=timeouts.get("nmap_full", 600),
            timeout_gobuster=timeouts.get("gobuster", 300),
            timeout_nikto=timeouts.get("nikto", 300),
            timeout_sqlmap=timeouts.get("sqlmap", 600),
            timeout_nuclei=timeouts.get("nuclei", 300),
            timeout_default=timeouts.get("default", 300),
        )
    
    return config


def load_config(
    config_path: Optional[Path] = None,
    validate_safety: bool = True
) -> Config:
    """
    Load configuration from files.
    
    Priority (highest to lowest):
    1. Specified config_path
    2. User config (~/.config/kestrel/config.yaml)
    3. Default config (config/default.yaml)
    
    Args:
        config_path: Optional explicit config file path
        validate_safety: If True, raise error on safety violations
        
    Returns:
        Config object
        
    Raises:
        ValueError: If safety validation fails and validate_safety=True
    """
    # Start with defaults
    config_data = {}
    
    # Load default config
    if DEFAULT_CONFIG_PATH.exists():
        with open(DEFAULT_CONFIG_PATH) as f:
            config_data = yaml.safe_load(f) or {}
    
    # Merge user config
    if USER_CONFIG_PATH.exists():
        with open(USER_CONFIG_PATH) as f:
            user_data = yaml.safe_load(f) or {}
            config_data = _deep_merge(config_data, user_data)
    
    # Merge explicit config
    if config_path and config_path.exists():
        with open(config_path) as f:
            explicit_data = yaml.safe_load(f) or {}
            config_data = _deep_merge(config_data, explicit_data)
    
    # Convert to Config object
    config = _dict_to_config(config_data)
    
    # Validate safety settings
    if validate_safety:
        violations = config.validate_safety()
        critical = [v for v in violations if v.startswith("CRITICAL")]
        
        if critical:
            raise ValueError(
                "Safety configuration violations detected:\n" +
                "\n".join(critical)
            )
    
    return config


# Global config instance (lazy loaded)
_config: Optional[Config] = None


def get_config() -> Config:
    """Get the global configuration instance."""
    global _config
    
    if _config is None:
        _config = load_config()
    
    return _config


def reset_config() -> None:
    """Reset the global configuration (for testing)."""
    global _config
    _config = None
