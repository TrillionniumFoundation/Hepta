#!/usr/bin/env python3
"""Focused context for the existing public HIA patch tool.

This read-only tool never publishes an artifact or skips whole-program checks.
Use `python -m hepta hia patch ...` for existing snapshot-bound patch admission.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from hepta.hia_agent_context import focused_context, measure_payloads
from hepta.hia_program_tools import MAX_INPUT_BYTES, bounded_json_wire, read_bounded


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", help="complete primitive HIA v6/v7/v8 JSON file")
    parser.add_argument("--function", action="append", required=True, dest="functions")
    parser.add_argument("--extra-opcode", action="append", default=[], dest="extra_opcodes")
    parser.add_argument("--measure", action="store_true", help="count UTF-8 payload bytes, without invoking a model")
    args = parser.parse_args(argv)
    try:
        document = read_bounded(args.source)
        operation = measure_payloads if args.measure else focused_context
        result = operation(document, args.functions, extra_opcodes=args.extra_opcodes)
    except ValueError as exc:
        print(bounded_json_wire({"ok": False, "error": str(exc)}, MAX_INPUT_BYTES,
                                ensure_ascii=False).decode())
        return 1
    print(bounded_json_wire(result, MAX_INPUT_BYTES, ensure_ascii=False).decode())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
