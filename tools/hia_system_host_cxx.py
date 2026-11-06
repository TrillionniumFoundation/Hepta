#!/usr/bin/env python3
"""Explicit recorded Kbuild host compiler boundary."""
from pathlib import Path
import sys
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hepta.hia_system import host_main
raise SystemExit(host_main("clangxx"))
