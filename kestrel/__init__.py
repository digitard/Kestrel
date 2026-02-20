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
Kestrel - LLM-Assisted Bug Bounty Hunting Platform

A native Kali Linux tool for automated bug bounty hunting with
human-in-the-loop authorization for all exploitation attempts.

Built following the "Intent is the New Skill" methodology.
"""

__version__ = "0.4.0.0"
__author__ = "Kestrel Team"
__license__ = "GPL-3.0-or-later"

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
