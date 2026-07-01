"""Enable ``python -m msgscope`` and the PyInstaller entry point."""

from __future__ import annotations

from .cli import main

if __name__ == "__main__":
    raise SystemExit(main())
