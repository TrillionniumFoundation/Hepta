"""Build an explicitly selected HIA JSON value-arena candidate, without activation."""
from __future__ import annotations
import argparse
from pathlib import Path
from tools.build_hia_json_preflight import build as build_candidate


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    return build_candidate(output, compiler, cold_report, candidate='decode')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
