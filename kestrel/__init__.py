"""
Kestrel - LLM-Assisted Bug Bounty Hunting Platform

A native Kali Linux tool for automated bug bounty hunting with
human-in-the-loop authorization for all exploitation attempts.

Built following the "Intent is the New Skill" methodology.
"""

__version__ = "0.3.0.0"
__author__ = "Kestrel Team"
__license__ = "MIT"

from pathlib import Path

# Package root directory
PACKAGE_DIR = Path(__file__).parent
PROJECT_DIR = PACKAGE_DIR.parent

# Version info
VERSION_TUPLE = tuple(int(x) for x in __version__.split("."))
VERSION_MAJOR = VERSION_TUPLE[0]  # AA - Major release
VERSION_PHASE = VERSION_TUPLE[1]  # BB - Phase
VERSION_FEATURE = VERSION_TUPLE[2]  # CC - Feature
VERSION_BUILD = VERSION_TUPLE[3]  # DD - Build/iteration


def get_version() -> str:
    """Return the current version string."""
    return __version__


def get_version_info() -> dict:
    """Return detailed version information."""
    return {
        "version": __version__,
        "major": VERSION_MAJOR,
        "phase": VERSION_PHASE,
        "feature": VERSION_FEATURE,
        "build": VERSION_BUILD,
    }
