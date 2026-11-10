"""Build an explicit Core module graph policy from a completed cold compiler."""
import argparse
from pathlib import Path
from tools.build_hia_json_preflight import build as build_candidate

def build(output, compiler, cold_report):
    return build_candidate(output, compiler, cold_report, candidate='core-module-graph')

if __name__ == '__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--output', type=Path, required=True)
    p.add_argument('--compiler', type=Path, required=True)
    p.add_argument('--cold-report', type=Path, required=True)
    a = p.parse_args()
    print(build(a.output.resolve(), a.compiler.resolve(), a.cold_report.resolve()))
