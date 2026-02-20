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

"""Kestrel ASCII art banner."""

from kestrel import __version__

# ANSI escape codes
_BOLD_CYAN  = "\033[1;96m"
_CYAN       = "\033[36m"
_DIM        = "\033[2m"
_RESET      = "\033[0m"

# ─────────────────────────────────────────────────────────────────────
#  ASCII logo
#
#  Each letter occupies exactly 8 character columns, giving a total art
#  width of 56 (7 letters × 8 cols).  The OTS tag is right-aligned to
#  this width so its final character sits flush with the rightmost point
#  of the logo.
#
#  Letter shapes (8-col, 5-row block style):
#
#    K  ██   ██   ██  ██   █████   ██  ██   ██   ██
#    E  ███████   ██      █████    ██      ███████
#    S   ██████   ██       █████       ██  ██████
#    T  ███████     ██      ██       ██       ██
#    R  ██████    ██   ██  ██████   ██  ██   ██   ██
#    L  ██        ██       ██       ██      ███████
# ─────────────────────────────────────────────────────────────────────

_ART = r"""
██   ██ ███████  ██████   █████ ██████  ███████ ██
██  ██  ██      ██         ██    ██   ██ ██      ██
█████   █████    █████     ██    ██████  █████   ██
██  ██  ██           ██    ██    ██   ██ ██      ██
██   ██ ███████ ██████     ██    ██   ██ ███████ ███████
"""

_BOX_WIDTH = 56  # inner width between ║ and ║

# Right-align OTS tag to the widest art line so the final character of
# the tag sits flush with the rightmost point of the logo.
_ART_WIDTH = max(len(line) for line in _ART.strip("\n").split("\n"))

_OTS_TAG = "OTS - Own the System"


def _box_line(content: str) -> str:
    """Return a single box row padded to exactly _BOX_WIDTH inner chars."""
    return f" ║{content.ljust(_BOX_WIDTH)}║"


_LICENSE_LINE = "  License: GNU GPL v3      github.com/digitard/Kestrel"


def _build_info_box(version: str) -> str:
    """Build the info box with every line exactly the same total width."""
    top    = " ╔" + "═" * _BOX_WIDTH + "╗"
    bottom = " ╚" + "═" * _BOX_WIDTH + "╝"

    version_prefix = f"  Version: {version:<12s}"
    author_text    = "Author: David Kuznicki"
    gap = " " * max(1, len(_LICENSE_LINE) - len(version_prefix) - len(author_text))

    lines = [
        top,
        _box_line("  LLM-Assisted Bug Bounty Hunting Platform"),
        _box_line(f"{version_prefix}{gap}{author_text}"),
        _box_line(_LICENSE_LINE),
        bottom,
    ]
    return "\n".join(lines) + "\n"


def get_banner() -> str:
    """Return the Kestrel banner with ANSI colors and current version."""
    ots_line = f"{_DIM}{_OTS_TAG.rjust(_ART_WIDTH)}{_RESET}\n"
    return (
        f"{_BOLD_CYAN}{_ART}{_RESET}"
        f"{ots_line}"
        f"{_CYAN}{_build_info_box(__version__)}{_RESET}"
    )


def print_banner() -> None:
    """Print the Kestrel banner to stdout."""
    print(get_banner())


def get_banner_plain() -> str:
    """Return a plain-text banner (no ANSI) for log files and markdown."""
    ots_line = _OTS_TAG.rjust(_ART_WIDTH)
    return f"""\
██   ██ ███████  ██████   █████ ██████  ███████ ██
██  ██  ██      ██         ██    ██   ██ ██      ██
█████   █████    █████     ██    ██████  █████   ██
██  ██  ██           ██    ██    ██   ██ ██      ██
██   ██ ███████ ██████     ██    ██   ██ ███████ ███████
{ots_line}
  Kestrel v{__version__}
  LLM-Assisted Bug Bounty Hunting Platform
  Copyright (C) 2026 David Kuznicki and Kestrel Contributors
  License: GNU GPL v3 | github.com/digitard/Kestrel
"""
