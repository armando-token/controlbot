"""CLI entrypoint for `python -m deploy.validate` (M8 / F17)."""

from __future__ import annotations

from deploy.config import main

if __name__ == "__main__":
    raise SystemExit(main())
