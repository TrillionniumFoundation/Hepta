"""Reproduce the two fixed HIA heap kernels for the Core source gate."""
from __future__ import annotations

import argparse
from pathlib import Path

from hepta.hia_agent_assembly import render_assembly
from tools.hia_heap_live_engine import document as live_document
from tools.hia_heap_payload import document as payload_document


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    folder = Path(__file__).resolve().parents[1] / 'examples/hia_bootstrap'
    for name, factory in (('heap_live_engine', live_document),
                          ('heap_payload', payload_document)):
        target = folder / (name + '.hepta')
        generated = render_assembly(factory()).encode('utf-8')
        if args.check:
            if target.read_bytes() != generated:
                raise SystemExit('native heap kernel source differs: ' + name)
        else:
            target.write_bytes(generated)


if __name__ == '__main__':
    main()
