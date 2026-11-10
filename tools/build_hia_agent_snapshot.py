"""Build the optional HIA Agent snapshot kernel from a completed cold compiler."""
from __future__ import annotations
import argparse
from pathlib import Path
from tools.build_hia_json_preflight import build as _build


def build(output, compiler, cold_report):
    return _build(output, compiler, cold_report, candidate='agent-snapshot')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
