"""Standalone entry point for the PyInstaller ``--onefile`` build.

PyInstaller runs this file as the top-level ``__main__`` script, so it must use
an absolute import (the package's own ``__main__.py`` uses a relative import and
is meant for ``python -m msgscope``).
"""

from __future__ import annotations

from msgscope.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
