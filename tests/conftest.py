"""
Kestrel Test Configuration

Shared fixtures and configuration for pytest.
"""

import pytest
from pathlib import Path


@pytest.fixture
def project_root() -> Path:
    """Return the project root directory."""
    return Path(__file__).parent.parent


@pytest.fixture
def fixtures_dir() -> Path:
    """Return the test fixtures directory."""
    return Path(__file__).parent / "fixtures"


@pytest.fixture
def sample_program() -> dict:
    """Return a sample bounty program for testing."""
    return {
        "platform": "hackerone",
        "program_id": "test_program",
        "name": "Test Program",
        "url": "https://hackerone.com/test_program",
        "scope": [
            {
                "asset_type": "domain",
                "asset": "*.test.com",
                "eligible": True,
                "max_severity": "critical",
            },
            {
                "asset_type": "domain",
                "asset": "api.test.com",
                "eligible": True,
                "max_severity": "critical",
            },
        ],
        "out_of_scope": [
            {
                "asset_type": "domain",
                "asset": "blog.test.com",
                "eligible": False,
            },
        ],
        "rewards": {
            "low": {"min": 100, "max": 250},
            "medium": {"min": 250, "max": 1000},
            "high": {"min": 1000, "max": 5000},
            "critical": {"min": 5000, "max": 10000},
        },
        "active": True,
    }


@pytest.fixture
def sample_finding() -> dict:
    """Return a sample finding for testing."""
    return {
        "title": "Open port 443/tcp",
        "description": "Service: https (nginx 1.18.0)",
        "severity": "info",
        "tool": "nmap",
        "target": "test.com",
        "evidence": "nginx/1.18.0",
    }


@pytest.fixture
def sample_cve() -> dict:
    """Return a sample CVE for testing."""
    return {
        "id": "CVE-2021-41773",
        "description": "Apache HTTP Server 2.4.49 path traversal",
        "cvss": 9.8,
        "severity": "critical",
        "affected_products": [
            {"vendor": "apache", "product": "http_server", "version": "2.4.49"}
        ],
    }
