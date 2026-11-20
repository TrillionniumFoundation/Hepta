"""Build the source-bound native Agent artifact capture executable."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from tools.build_hia_sqlite_components import CAPTURE_ADAPTERS, build_executables
from tools.build_hia_agent_store import write_new


DRIVER = 'tools/build_hia_agent_artifact_capture.py'
UNIT = 'agent-artifact-capture'


def build(output, compiler, cold_report):
    report, sources = build_executables(output, compiler, cold_report, (UNIT,), CAPTURE_ADAPTERS, (DRIVER,))
    report.update(schema='hepta.hia.agent-artifact-capture-build.v1',
                  status='NATIVE_AGENT_ARTIFACT_CAPTURE_BUILT', source_manifest=sources)
    # This record is later admitted as runtime authority, not just a log.
    write_new(output / 'build.json', (json.dumps(report, indent=2, sort_keys=True) + '\n').encode())
    return output / ('hia-' + UNIT)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for arg in ('compiler', 'cold-report', 'output'):
        parser.add_argument('--' + arg, type=Path, required=True)
    args = parser.parse_args()
    print(build(args.output.resolve(), args.compiler.resolve(), args.cold_report.resolve()))


if __name__ == '__main__':
    main()
