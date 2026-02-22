"""
Phase 4: Platform Integration — Unit Tests

Tests cover:
  - New credential specs (IntiGriti, YesWeHack, Shodan, Censys, Vulners)
  - New ENV_VARS entries
  - New Platform enum members
  - CredentialManager helper methods (new)
  - IntiGritiClient stub behaviour
  - YesWeHackClient stub behaviour
  - __init__.py exports completeness
  - config/default.yaml new sections present
"""

import os
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock
from tempfile import TemporaryDirectory

from kestrel.platforms.credentials import (
    CREDENTIAL_SPECS,
    ENV_VARS,
    CredentialManager,
)
from kestrel.platforms.models import Platform
from kestrel.platforms.base import ClientConfig, NotFoundError
from kestrel.platforms.intigriti import IntiGritiClient, INTIGRITI_API_URL
from kestrel.platforms.yeswehack import YesWeHackClient, YESWEHACK_API_URL
from kestrel.platforms import (
    IntiGritiClient as ExportedIntiGriti,
    YesWeHackClient as ExportedYesWeHack,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _spec_keys() -> set[str]:
    return {s.key for s in CREDENTIAL_SPECS}


def _spec_by_key(key: str):
    for s in CREDENTIAL_SPECS:
        if s.key == key:
            return s
    return None


# ─────────────────────────────────────────────────────────────────────────────
# New Credential Specs
# ─────────────────────────────────────────────────────────────────────────────

class TestNewCredentialSpecs:
    """New credential specs added in Phase 4 are present and correct."""

    def test_intigriti_token_spec_exists(self):
        assert "intigriti_token" in _spec_keys()

    def test_ywh_email_spec_exists(self):
        assert "ywh_email" in _spec_keys()

    def test_ywh_password_spec_exists(self):
        assert "ywh_password" in _spec_keys()

    def test_shodan_api_key_spec_exists(self):
        assert "shodan_api_key" in _spec_keys()

    def test_censys_api_id_spec_exists(self):
        assert "censys_api_id" in _spec_keys()

    def test_censys_api_secret_spec_exists(self):
        assert "censys_api_secret" in _spec_keys()

    def test_vulners_api_key_spec_exists(self):
        assert "vulners_api_key" in _spec_keys()

    def test_intigriti_token_is_secret(self):
        spec = _spec_by_key("intigriti_token")
        assert spec is not None
        assert spec.secret is True

    def test_ywh_email_is_not_secret(self):
        spec = _spec_by_key("ywh_email")
        assert spec is not None
        assert spec.secret is False

    def test_ywh_password_is_secret(self):
        spec = _spec_by_key("ywh_password")
        assert spec is not None
        assert spec.secret is True

    def test_shodan_key_is_optional(self):
        spec = _spec_by_key("shodan_api_key")
        assert spec is not None
        assert spec.required is False

    def test_censys_id_is_optional(self):
        spec = _spec_by_key("censys_api_id")
        assert spec is not None
        assert spec.required is False

    def test_intigriti_group(self):
        spec = _spec_by_key("intigriti_token")
        assert spec.group == "IntiGriti"

    def test_yeswehack_group(self):
        spec = _spec_by_key("ywh_email")
        assert spec.group == "YesWeHack"

    def test_shodan_recon_group(self):
        spec = _spec_by_key("shodan_api_key")
        assert spec.group == "Recon APIs"

    def test_censys_recon_group(self):
        spec = _spec_by_key("censys_api_id")
        assert spec.group == "Recon APIs"

    def test_vulners_cve_group(self):
        spec = _spec_by_key("vulners_api_key")
        assert spec.group == "CVE/NVD"


# ─────────────────────────────────────────────────────────────────────────────
# ENV_VARS mapping
# ─────────────────────────────────────────────────────────────────────────────

class TestNewEnvVars:
    """ENV_VARS dict has correct entries for all new credentials."""

    def test_intigriti_env_var(self):
        assert ENV_VARS.get("intigriti_token") == "INTIGRITI_TOKEN"

    def test_ywh_email_env_var(self):
        assert ENV_VARS.get("ywh_email") == "YWH_EMAIL"

    def test_ywh_password_env_var(self):
        assert ENV_VARS.get("ywh_password") == "YWH_PASSWORD"

    def test_shodan_env_var(self):
        assert ENV_VARS.get("shodan_api_key") == "SHODAN_API_KEY"

    def test_censys_id_env_var(self):
        assert ENV_VARS.get("censys_api_id") == "CENSYS_API_ID"

    def test_censys_secret_env_var(self):
        assert ENV_VARS.get("censys_api_secret") == "CENSYS_API_SECRET"

    def test_vulners_env_var(self):
        assert ENV_VARS.get("vulners_api_key") == "VULNERS_API_KEY"


# ─────────────────────────────────────────────────────────────────────────────
# Platform Enum
# ─────────────────────────────────────────────────────────────────────────────

class TestPlatformEnum:
    """Platform enum has new members."""

    def test_intigriti_member(self):
        assert Platform.INTIGRITI.value == "intigriti"

    def test_yeswehack_member(self):
        assert Platform.YESWEHACK.value == "yeswehack"

    def test_original_members_unchanged(self):
        assert Platform.HACKERONE.value == "hackerone"
        assert Platform.BUGCROWD.value == "bugcrowd"
        assert Platform.MANUAL.value == "manual"

    def test_platform_from_value(self):
        assert Platform("intigriti") == Platform.INTIGRITI
        assert Platform("yeswehack") == Platform.YESWEHACK


# ─────────────────────────────────────────────────────────────────────────────
# CredentialManager — new helper methods
# ─────────────────────────────────────────────────────────────────────────────

class TestCredentialManagerNewHelpers:
    """New helper methods return correct values or None."""

    def setup_method(self):
        self._tmpdir = TemporaryDirectory()
        self._creds = CredentialManager(Path(self._tmpdir.name))

    def teardown_method(self):
        self._tmpdir.cleanup()

    # ── get_intigriti_config ──────────────────────────────────────────────

    def test_get_intigriti_config_returns_none_when_not_set(self):
        result = self._creds.get_intigriti_config()
        assert result is None

    def test_get_intigriti_config_returns_client_config(self):
        self._creds.set("intigriti_token", "inti_test_token_abc123")
        cfg = self._creds.get_intigriti_config()
        assert cfg is not None
        assert cfg.api_key == "inti_test_token_abc123"

    def test_get_intigriti_config_from_env(self):
        with patch.dict(os.environ, {"INTIGRITI_TOKEN": "env_inti_token"}):
            cfg = self._creds.get_intigriti_config()
        assert cfg is not None
        assert cfg.api_key == "env_inti_token"

    # ── get_yeswehack_config ──────────────────────────────────────────────

    def test_get_yeswehack_config_returns_none_when_not_set(self):
        result = self._creds.get_yeswehack_config()
        assert result is None

    def test_get_yeswehack_config_returns_none_when_only_email_set(self):
        self._creds.set("ywh_email", "hunter@example.com")
        result = self._creds.get_yeswehack_config()
        assert result is None

    def test_get_yeswehack_config_returns_client_config(self):
        self._creds.set("ywh_email", "hunter@example.com")
        self._creds.set("ywh_password", "s3cr3t")
        cfg = self._creds.get_yeswehack_config()
        assert cfg is not None
        assert cfg.api_key == "hunter@example.com"
        assert cfg.api_secret == "s3cr3t"

    def test_get_yeswehack_config_from_env(self):
        env = {"YWH_EMAIL": "env@example.com", "YWH_PASSWORD": "envpass"}
        with patch.dict(os.environ, env):
            cfg = self._creds.get_yeswehack_config()
        assert cfg is not None
        assert cfg.api_key == "env@example.com"

    # ── get_shodan_key ────────────────────────────────────────────────────

    def test_get_shodan_key_returns_none_when_not_set(self):
        assert self._creds.get_shodan_key() is None

    def test_get_shodan_key_returns_value(self):
        self._creds.set("shodan_api_key", "shodan_test_key")
        assert self._creds.get_shodan_key() == "shodan_test_key"

    def test_get_shodan_key_from_env(self):
        with patch.dict(os.environ, {"SHODAN_API_KEY": "env_shodan"}):
            assert self._creds.get_shodan_key() == "env_shodan"

    # ── get_censys_config ─────────────────────────────────────────────────

    def test_get_censys_config_returns_none_when_not_set(self):
        assert self._creds.get_censys_config() is None

    def test_get_censys_config_returns_none_when_only_id_set(self):
        self._creds.set("censys_api_id", "test_id")
        assert self._creds.get_censys_config() is None

    def test_get_censys_config_returns_tuple(self):
        self._creds.set("censys_api_id", "test_id_123")
        self._creds.set("censys_api_secret", "test_secret_xyz")
        result = self._creds.get_censys_config()
        assert result == ("test_id_123", "test_secret_xyz")

    def test_get_censys_config_from_env(self):
        env = {"CENSYS_API_ID": "env_id", "CENSYS_API_SECRET": "env_secret"}
        with patch.dict(os.environ, env):
            result = self._creds.get_censys_config()
        assert result == ("env_id", "env_secret")

    # ── get_vulners_key ───────────────────────────────────────────────────

    def test_get_vulners_key_returns_none_when_not_set(self):
        assert self._creds.get_vulners_key() is None

    def test_get_vulners_key_returns_value(self):
        self._creds.set("vulners_api_key", "vulners_abc")
        assert self._creds.get_vulners_key() == "vulners_abc"

    def test_get_vulners_key_from_env(self):
        with patch.dict(os.environ, {"VULNERS_API_KEY": "env_vulners"}):
            assert self._creds.get_vulners_key() == "env_vulners"


# ─────────────────────────────────────────────────────────────────────────────
# IntiGriti stub client
# ─────────────────────────────────────────────────────────────────────────────

class TestIntiGritiClient:
    """IntiGritiClient stub behaves correctly."""

    def setup_method(self):
        self._config = ClientConfig(api_key="test_inti_token")
        self._client = IntiGritiClient(self._config)

    def test_platform_is_intigriti(self):
        assert self._client.platform == Platform.INTIGRITI

    def test_is_stub_returns_true(self):
        assert self._client.is_stub is True

    def test_default_api_url(self):
        assert self._client._api_url == INTIGRITI_API_URL

    def test_custom_api_url(self):
        cfg = ClientConfig(api_key="tok", base_url="https://custom.intigriti.com")
        client = IntiGritiClient(cfg)
        assert client._api_url == "https://custom.intigriti.com"

    def test_get_headers_contains_bearer(self):
        headers = self._client._get_headers()
        assert "Authorization" in headers
        assert headers["Authorization"] == "Bearer test_inti_token"

    def test_list_programs_returns_empty_list(self):
        result = self._client.list_programs()
        assert result == []

    def test_list_programs_returns_list_type(self):
        result = self._client.list_programs()
        assert isinstance(result, list)

    def test_get_program_raises_not_found(self):
        with pytest.raises(NotFoundError):
            self._client.get_program("some-handle")

    def test_test_auth_returns_false(self):
        assert self._client.test_auth() is False


# ─────────────────────────────────────────────────────────────────────────────
# YesWeHack stub client
# ─────────────────────────────────────────────────────────────────────────────

class TestYesWeHackClient:
    """YesWeHackClient stub behaves correctly."""

    def setup_method(self):
        self._config = ClientConfig(
            api_key="hunter@example.com",
            api_secret="s3cr3tp4ss",
        )
        self._client = YesWeHackClient(self._config)

    def test_platform_is_yeswehack(self):
        assert self._client.platform == Platform.YESWEHACK

    def test_is_stub_returns_true(self):
        assert self._client.is_stub is True

    def test_default_api_url(self):
        assert self._client._api_url == YESWEHACK_API_URL

    def test_custom_api_url(self):
        cfg = ClientConfig(api_key="e@e.com", api_secret="p", base_url="https://custom.ywh.com")
        client = YesWeHackClient(cfg)
        assert client._api_url == "https://custom.ywh.com"

    def test_email_stored(self):
        assert self._client._email == "hunter@example.com"

    def test_password_stored(self):
        assert self._client._password == "s3cr3tp4ss"

    def test_jwt_initially_none(self):
        assert self._client._jwt is None

    def test_get_headers_no_bearer_without_jwt(self):
        headers = self._client._get_headers()
        assert "Authorization" not in headers

    def test_get_headers_with_jwt(self):
        self._client._jwt = "fake_jwt_token"
        headers = self._client._get_headers()
        assert headers["Authorization"] == "Bearer fake_jwt_token"

    def test_login_returns_false(self):
        assert self._client.login() is False

    def test_list_programs_returns_empty_list(self):
        result = self._client.list_programs()
        assert result == []

    def test_get_program_raises_not_found(self):
        with pytest.raises(NotFoundError):
            self._client.get_program("some-program")

    def test_test_auth_returns_false(self):
        assert self._client.test_auth() is False


# ─────────────────────────────────────────────────────────────────────────────
# __init__.py exports
# ─────────────────────────────────────────────────────────────────────────────

class TestPlatformsExports:
    """kestrel.platforms exports new clients."""

    def test_intigriti_client_exported(self):
        assert ExportedIntiGriti is IntiGritiClient

    def test_yeswehack_client_exported(self):
        assert ExportedYesWeHack is YesWeHackClient

    def test_platform_enum_exported_with_new_members(self):
        from kestrel.platforms import Platform as ExportedPlatform
        assert Platform.INTIGRITI in list(ExportedPlatform)
        assert Platform.YESWEHACK in list(ExportedPlatform)


# ─────────────────────────────────────────────────────────────────────────────
# config/default.yaml new sections
# ─────────────────────────────────────────────────────────────────────────────

class TestDefaultConfigNewSections:
    """config/default.yaml has the new platform and recon_apis sections."""

    def setup_method(self):
        import yaml
        config_path = Path(__file__).parent.parent / "config" / "default.yaml"
        with open(config_path) as f:
            self._config = yaml.safe_load(f)

    def test_intigriti_platform_section_exists(self):
        assert "intigriti" in self._config["platforms"]

    def test_yeswehack_platform_section_exists(self):
        assert "yeswehack" in self._config["platforms"]

    def test_intigriti_is_disabled_by_default(self):
        assert self._config["platforms"]["intigriti"]["enabled"] is False

    def test_yeswehack_is_disabled_by_default(self):
        assert self._config["platforms"]["yeswehack"]["enabled"] is False

    def test_recon_apis_section_exists(self):
        assert "recon_apis" in self._config

    def test_shodan_in_recon_apis(self):
        assert "shodan" in self._config["recon_apis"]

    def test_censys_in_recon_apis(self):
        assert "censys" in self._config["recon_apis"]

    def test_shodan_disabled_by_default(self):
        assert self._config["recon_apis"]["shodan"]["enabled"] is False

    def test_censys_disabled_by_default(self):
        assert self._config["recon_apis"]["censys"]["enabled"] is False

    def test_vulners_in_cve_section(self):
        assert "vulners" in self._config["cve"]

    def test_vulners_disabled_by_default(self):
        assert self._config["cve"]["vulners"]["enabled"] is False

    def test_original_platforms_still_present(self):
        assert "hackerone" in self._config["platforms"]
        assert "bugcrowd" in self._config["platforms"]

    def test_hackerone_still_enabled(self):
        assert self._config["platforms"]["hackerone"]["enabled"] is True

    def test_bugcrowd_still_enabled(self):
        assert self._config["platforms"]["bugcrowd"]["enabled"] is True
