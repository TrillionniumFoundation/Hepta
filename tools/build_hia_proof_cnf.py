"""Build the standalone HIA Boolean solver and circuit filter."""
from __future__ import annotations

import argparse
from pathlib import Path

from tools.build_hia_native_filter import build_filter


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    return build_filter(output, compiler, cold_report, application='cnf',
                        filename='hia-proof-cnf', schema='hepta.hia.proof-cnf-build.v1')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))
