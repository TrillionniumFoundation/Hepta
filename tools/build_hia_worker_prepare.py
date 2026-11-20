"""Package the cold-built HIA Worker request encoder as a static Linux executable."""
from __future__ import annotations

import argparse
from pathlib import Path

from tools.build_hia_native_filter import build_filter


def build(output: Path, compiler: Path, cold_report: Path) -> Path:
    return build_filter(output, compiler, cold_report, application='worker-prepare',
                        filename='hia-worker-prepare', schema='hepta.hia.worker-prepare-build.v1')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('output', 'compiler', 'cold-report'):
        parser.add_argument('--' + name, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))
