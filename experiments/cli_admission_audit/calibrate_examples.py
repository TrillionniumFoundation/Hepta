"""Observe current example headroom; never selects a production policy.

Each independent owner loads then explicitly revalidates on the same ledger.
Counts may depend on checkout path and Python version. This is not a benchmark,
all-dimension coverage, deadline measurement or hard memory qualification.
"""
from dataclasses import asdict
import json
from pathlib import Path
import platform
import sys

from hepta.ast import HeptaError
from experiments.package_copy.owner import Limits, Owner


def observe():
    limits = asdict(Limits()); peaks = {}; graph_count = 0; diagnostics = []
    for path in sorted(Path('examples').rglob('*.hepta')):
        owner = Owner()
        try:
            handle = owner.load(path)
        except HeptaError as error:
            diagnostics.append({'case': path.as_posix(), 'code': error.diagnostic.code})
            continue
        initial = dict(owner.context.counts)
        initial.update(reads=owner.context.reader.reads, total_bytes=owner.context.reader.bytes_read)
        if not handle.unchanged():
            raise AssertionError('fixture changed during calibration: ' + str(path))
        final = dict(owner.context.counts)
        final.update(reads=owner.context.reader.reads, total_bytes=owner.context.reader.bytes_read)
        graph_count += 1
        for name, count in final.items():
            if name not in peaks or count > peaks[name]['max_observed']:
                peaks[name] = {'max_observed': count, 'case': path.as_posix(),
                               'after_load': initial[name], 'current_limit': limits[name]}
    return {'schema': 'hepta.experimental.loader-headroom.v1',
            'reference_commit': 'e9f65e2c0c53ccb38b6257ad7821314a200fa6c4',
            'python': platform.python_version(), 'implementation': sys.implementation.name,
            'checkout_path_dependent': True, 'policy_selected': False,
            'runtime_checkout_attested': False, 'diagnostic_case_counters_measured': False,
            'scope': 'peaks cover only successful loads plus one same-owner revalidation; diagnostic cases, analysis and native work are not measured',
            'graphs': graph_count, 'diagnostics': diagnostics, 'peaks': peaks,
            'unmeasured_limit_dimensions': sorted(set(limits) - set(peaks))}


if __name__ == '__main__':
    print(json.dumps(observe(), indent=2, sort_keys=True))
