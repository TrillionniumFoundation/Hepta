"""Build an explicit native Core capability edge policy from a cold compiler."""
import argparse
from pathlib import Path
from tools.build_hia_json_preflight import build as build_candidate

def build(output, compiler, cold_report):
    return build_candidate(output, compiler, cold_report, candidate='capability-renaming')

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--compiler', type=Path, required=True)
    parser.add_argument('--cold-report', type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))
