#!/usr/bin/env python3
"""Run host and port Web first-pass reconnaissance."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from webrecon.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
