#!/usr/bin/env python3
"""Backward-compatible entry point: ``python main.py`` runs the IPTI CLI.

Prefer the installed console script ``ipti`` (see pyproject.toml).
"""

from __future__ import annotations

import sys

from ipti.cli import main

if __name__ == "__main__":
    sys.exit(main())
