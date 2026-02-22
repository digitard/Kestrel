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
Kestrel - Credential Manager

Handles secure storage and retrieval of API credentials.
Stores credentials in ~/.kestrel/credentials.yaml alongside
the program cache database.

On first run (or when credentials are missing), prompts the user
interactively. Supports:
  - Anthropic API key
  - HackerOne API credentials (username + token)
  - Bugcrowd API credentials (token username + password)
  - IntiGriti API token
  - YesWeHack credentials (email + password)
  - Shodan API key (for passive recon)
  - Censys API credentials (id + secret)
  - Vulners API key (for CVE correlation)
  - NVD API key (for CVE correlation)

Design:
  - Credentials stored in a single YAML file outside the project
  - File permissions set to 600 (owner-only read/write)
  - Never logged, never in audit trail, never in git
  - Interactive prompts with masked password input
  - Environment variable overrides always take precedence
"""

import os
import sys
import stat
import getpass
import logging
from pathlib import Path
from typing import Optional, Any
from dataclasses import dataclass, field

import yaml


logger = logging.getLogger(__name__)


# ─────────────────────────────────────────────────────────────────────
#  Paths
# ─────────────────────────────────────────────────────────────────────

KESTREL_DIR = Path.home() / ".kestrel"
CREDENTIALS_FILE = KESTREL_DIR / "credentials.yaml"

# Environment variable names (override file-stored creds)
ENV_VARS = {
    "anthropic_api_key": "ANTHROPIC_API_KEY",
    "h1_username": "BH_H1_USERNAME",
    "h1_token": "BH_H1_TOKEN",
    "bc_username": "BH_BC_USERNAME",
    "bc_password": "BH_BC_PASSWORD",
    "intigriti_token": "INTIGRITI_TOKEN",
    "ywh_email": "YWH_EMAIL",
    "ywh_password": "YWH_PASSWORD",
    "shodan_api_key": "SHODAN_API_KEY",
    "censys_api_id": "CENSYS_API_ID",
    "censys_api_secret": "CENSYS_API_SECRET",
    "vulners_api_key": "VULNERS_API_KEY",
    "nvd_api_key": "NVD_API_KEY",
}


# ─────────────────────────────────────────────────────────────────────
#  Credential Definitions
# ─────────────────────────────────────────────────────────────────────

@dataclass
class CredentialSpec:
    """Defines a single credential field."""
    key: str                    # Key in the YAML file
    env_var: str               # Environment variable name
    prompt: str                # Human-readable prompt
    required: bool = False     # Whether it's required to run
    secret: bool = True        # Whether to mask input
    group: str = ""            # Grouping label for display


# All credentials Kestrel uses
CREDENTIAL_SPECS = [
    CredentialSpec(
        key="anthropic_api_key",
        env_var="ANTHROPIC_API_KEY",
        prompt="Anthropic API Key",
        required=True,
        secret=True,
        group="LLM",
    ),
    CredentialSpec(
        key="h1_username",
        env_var="BH_H1_USERNAME",
        prompt="HackerOne API Username",
        required=False,
        secret=False,
        group="HackerOne",
    ),
    CredentialSpec(
        key="h1_token",
        env_var="BH_H1_TOKEN",
        prompt="HackerOne API Token",
        required=False,
        secret=True,
        group="HackerOne",
    ),
    CredentialSpec(
        key="bc_username",
        env_var="BH_BC_USERNAME",
        prompt="Bugcrowd Token Username",
        required=False,
        secret=False,
        group="Bugcrowd",
    ),
    CredentialSpec(
        key="bc_password",
        env_var="BH_BC_PASSWORD",
        prompt="Bugcrowd Token Password",
        required=False,
        secret=True,
        group="Bugcrowd",
    ),
    CredentialSpec(
        key="intigriti_token",
        env_var="INTIGRITI_TOKEN",
        prompt="IntiGriti API Token",
        required=False,
        secret=True,
        group="IntiGriti",
    ),
    CredentialSpec(
        key="ywh_email",
        env_var="YWH_EMAIL",
        prompt="YesWeHack Email",
        required=False,
        secret=False,
        group="YesWeHack",
    ),
    CredentialSpec(
        key="ywh_password",
        env_var="YWH_PASSWORD",
        prompt="YesWeHack Password",
        required=False,
        secret=True,
        group="YesWeHack",
    ),
    CredentialSpec(
        key="shodan_api_key",
        env_var="SHODAN_API_KEY",
        prompt="Shodan API Key (optional, for passive recon)",
        required=False,
        secret=True,
        group="Recon APIs",
    ),
    CredentialSpec(
        key="censys_api_id",
        env_var="CENSYS_API_ID",
        prompt="Censys API ID (optional, for passive recon)",
        required=False,
        secret=False,
        group="Recon APIs",
    ),
    CredentialSpec(
        key="censys_api_secret",
        env_var="CENSYS_API_SECRET",
        prompt="Censys API Secret (optional, for passive recon)",
        required=False,
        secret=True,
        group="Recon APIs",
    ),
    CredentialSpec(
        key="vulners_api_key",
        env_var="VULNERS_API_KEY",
        prompt="Vulners API Key (optional, improves CVE lookups)",
        required=False,
        secret=True,
        group="CVE/NVD",
    ),
    CredentialSpec(
        key="nvd_api_key",
        env_var="NVD_API_KEY",
        prompt="NVD API Key (optional, improves rate limits)",
        required=False,
        secret=True,
        group="CVE/NVD",
    ),
]


# ─────────────────────────────────────────────────────────────────────
#  Credential Manager
# ─────────────────────────────────────────────────────────────────────

class CredentialManager:
    """
    Manages API credentials for Kestrel.

    Resolution order for each credential:
      1. Environment variable (always wins)
      2. ~/.kestrel/credentials.yaml
      3. Interactive prompt (if needed and terminal is available)

    Usage:
        creds = CredentialManager()

        # Get a specific credential
        api_key = creds.get("anthropic_api_key")

        # Get configured platform clients
        h1_config = creds.get_hackerone_config()
        bc_config = creds.get_bugcrowd_config()

        # Interactive setup
        creds.setup()  # Prompts for all missing credentials
    """

    def __init__(self, credentials_dir: Optional[Path] = None):
        self._dir = credentials_dir or KESTREL_DIR
        self._file = self._dir / "credentials.yaml"
        self._cache: dict[str, str] = {}
        self._loaded = False

    @property
    def credentials_file(self) -> Path:
        return self._file

    @property
    def credentials_dir(self) -> Path:
        return self._dir

    def _ensure_dir(self) -> None:
        """Create credentials directory with proper permissions."""
        self._dir.mkdir(parents=True, exist_ok=True)
        # Set directory to owner-only access
        try:
            os.chmod(self._dir, stat.S_IRWXU)  # 700
        except OSError:
            pass  # May fail on some filesystems

    def _load(self) -> None:
        """Load credentials from YAML file."""
        if self._loaded:
            return

        if self._file.exists():
            try:
                with open(self._file, "r") as f:
                    data = yaml.safe_load(f) or {}
                self._cache = {k: str(v) for k, v in data.items() if v}
            except Exception as e:
                logger.warning(f"Failed to load credentials: {e}")
                self._cache = {}

        self._loaded = True

    def _save(self) -> None:
        """Save credentials to YAML file with restricted permissions."""
        self._ensure_dir()

        # Only save non-empty values
        data = {k: v for k, v in self._cache.items() if v}

        with open(self._file, "w") as f:
            yaml.dump(data, f, default_flow_style=False)

        # Set file to owner-only read/write
        try:
            os.chmod(self._file, stat.S_IRUSR | stat.S_IWUSR)  # 600
        except OSError:
            pass

    # ── Get / Set ───────────────────────────────────────────────────

    def get(self, key: str) -> Optional[str]:
        """
        Get a credential value.

        Resolution: env var → file → None

        Args:
            key: Credential key (e.g., "anthropic_api_key")

        Returns:
            Credential value or None
        """
        # 1. Environment variable always wins
        env_var = ENV_VARS.get(key, "")
        if env_var:
            env_val = os.environ.get(env_var, "")
            if env_val:
                return env_val

        # 2. File-stored credential
        self._load()
        return self._cache.get(key)

    def set(self, key: str, value: str) -> None:
        """
        Set a credential value (persists to file).

        Args:
            key: Credential key
            value: Credential value
        """
        self._load()
        self._cache[key] = value
        self._save()

    def delete(self, key: str) -> bool:
        """
        Delete a credential.

        Args:
            key: Credential key

        Returns:
            True if credential existed and was deleted
        """
        self._load()
        if key in self._cache:
            del self._cache[key]
            self._save()
            return True
        return False

    def has(self, key: str) -> bool:
        """Check if a credential is available (from any source)."""
        return self.get(key) is not None

    # ── Status ──────────────────────────────────────────────────────

    def status(self) -> dict:
        """
        Get the status of all credentials.

        Returns:
            Dict with credential status info
        """
        result = {}
        for spec in CREDENTIAL_SPECS:
            env_val = os.environ.get(spec.env_var, "")
            self._load()
            file_val = self._cache.get(spec.key, "")

            source = "not set"
            if env_val:
                source = f"env ({spec.env_var})"
            elif file_val:
                source = f"file ({self._file.name})"

            result[spec.key] = {
                "set": bool(env_val or file_val),
                "source": source,
                "required": spec.required,
                "group": spec.group,
            }
        return result

    def is_ready(self) -> bool:
        """Check if all required credentials are available."""
        for spec in CREDENTIAL_SPECS:
            if spec.required and not self.has(spec.key):
                return False
        return True

    def missing_required(self) -> list[str]:
        """Get list of missing required credential keys."""
        return [
            spec.key for spec in CREDENTIAL_SPECS
            if spec.required and not self.has(spec.key)
        ]

    # ── Interactive Setup ───────────────────────────────────────────

    def setup(self, force: bool = False) -> None:
        """
        Interactive credential setup.

        Prompts for any missing credentials. If force=True,
        prompts for all credentials even if already set.

        Args:
            force: Re-prompt for all credentials
        """
        if not sys.stdin.isatty():
            logger.warning("Not a terminal — cannot prompt for credentials")
            return

        print("\n╔══════════════════════════════════════════╗")
        print("║  Kestrel - Credential Setup          ║")
        print("╚══════════════════════════════════════════╝")
        print(f"\nCredentials stored in: {self._file}")
        print("Environment variables always take precedence.\n")

        current_group = ""
        any_changed = False

        for spec in CREDENTIAL_SPECS:
            # Show group header
            if spec.group != current_group:
                current_group = spec.group
                print(f"\n── {current_group} ──")

            # Check current state
            current = self.get(spec.key)
            has_env = bool(os.environ.get(spec.env_var, ""))

            if has_env:
                print(f"  {spec.prompt}: ✅ (from env ${spec.env_var})")
                continue

            if current and not force:
                masked = current[:4] + "..." + current[-4:] if len(current) > 8 else "****"
                print(f"  {spec.prompt}: ✅ ({masked})")
                continue

            # Prompt for value
            required_tag = " [REQUIRED]" if spec.required else " [optional, Enter to skip]"
            prompt_text = f"  {spec.prompt}{required_tag}: "

            if spec.secret:
                value = getpass.getpass(prompt_text)
            else:
                value = input(prompt_text)

            value = value.strip()

            if value:
                self.set(spec.key, value)
                any_changed = True
                print(f"    → Saved ✓")
            elif spec.required:
                print(f"    ⚠️  Required but not set. You can set ${spec.env_var} later.")
            else:
                print(f"    → Skipped")

        if any_changed:
            print(f"\n✅ Credentials saved to {self._file}")
            print(f"   File permissions: 600 (owner-only)")
        else:
            print("\n✅ No changes needed.")

        # Show summary
        self._print_status()

    def _print_status(self) -> None:
        """Print credential status table."""
        print("\n── Status ──")
        status = self.status()
        for key, info in status.items():
            icon = "✅" if info["set"] else ("❌" if info["required"] else "⬜")
            req = " [REQUIRED]" if info["required"] else ""
            print(f"  {icon} {key}: {info['source']}{req}")

    # ── Platform Config Helpers ─────────────────────────────────────

    def get_hackerone_config(self):
        """
        Get a ClientConfig for HackerOne.

        Returns:
            ClientConfig or None if credentials not available
        """
        from .base import ClientConfig

        username = self.get("h1_username")
        token = self.get("h1_token")

        if not username or not token:
            return None

        return ClientConfig(
            api_key=username,
            api_secret=token,
        )

    def get_bugcrowd_config(self):
        """
        Get a ClientConfig for Bugcrowd.

        Returns:
            ClientConfig or None if credentials not available
        """
        from .base import ClientConfig

        username = self.get("bc_username")
        password = self.get("bc_password")

        if not username or not password:
            return None

        return ClientConfig(
            api_key=username,
            api_secret=password,
        )

    def get_intigriti_config(self):
        """
        Get a ClientConfig for IntiGriti.

        Returns:
            ClientConfig or None if credentials not available
        """
        from .base import ClientConfig

        token = self.get("intigriti_token")
        if not token:
            return None
        return ClientConfig(api_key=token)

    def get_yeswehack_config(self):
        """
        Get a ClientConfig for YesWeHack.

        Returns:
            ClientConfig or None if credentials not available
        """
        from .base import ClientConfig

        email = self.get("ywh_email")
        password = self.get("ywh_password")
        if not email or not password:
            return None
        return ClientConfig(api_key=email, api_secret=password)

    def get_shodan_key(self) -> Optional[str]:
        """Get the Shodan API key."""
        return self.get("shodan_api_key")

    def get_censys_config(self) -> Optional[tuple[str, str]]:
        """
        Get Censys credentials as (api_id, api_secret) tuple.

        Returns:
            (api_id, api_secret) tuple or None if not configured
        """
        api_id = self.get("censys_api_id")
        api_secret = self.get("censys_api_secret")
        if not api_id or not api_secret:
            return None
        return (api_id, api_secret)

    def get_vulners_key(self) -> Optional[str]:
        """Get the Vulners API key."""
        return self.get("vulners_api_key")

    def get_anthropic_key(self) -> Optional[str]:
        """Get the Anthropic API key."""
        return self.get("anthropic_api_key")

    def get_nvd_key(self) -> Optional[str]:
        """Get the NVD API key."""
        return self.get("nvd_api_key")


# ─────────────────────────────────────────────────────────────────────
#  Global Instance
# ─────────────────────────────────────────────────────────────────────

_manager: Optional[CredentialManager] = None


def get_credentials(credentials_dir: Optional[Path] = None) -> CredentialManager:
    """Get the global credential manager instance."""
    global _manager
    if _manager is None:
        _manager = CredentialManager(credentials_dir)
    return _manager


def reset_credentials() -> None:
    """Reset the global credential manager (for testing)."""
    global _manager
    _manager = None
