"""Module entrypoint for `python -m src.qa`."""

from __future__ import annotations

from src.qa.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
