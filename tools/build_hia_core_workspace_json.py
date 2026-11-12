"""Build the explicit HIA workspace JSON linker from a completed cold compiler."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
if __package__ in {None, ''}:
    sys.path.insert(0, str(ROOT))

from tools.build_hia_json_preflight import build as build_candidate


def build(output, compiler, cold_report):
    return build_candidate(output, compiler, cold_report, candidate='core-workspace-json')


if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    for name in ('output','compiler','cold-report'):p.add_argument('--'+name,type=Path,required=True)
    a=p.parse_args()
    print(build(a.output.resolve(),a.compiler.resolve(),a.cold_report.resolve()))
