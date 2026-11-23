"""Compare the installed VM's HIA-owned bulk operations to complete portable reports."""
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from tests.test_hia_bulk_memory import bulk_program
from tests.test_hia_offset_copy_v5 import copy_program
from tests.test_hia_overlap_move import move_program
from tests.test_hia_range_fill_v6 import fill_program
from tests.test_hia_swap_v4 import swap_program


INSTALLED = os.environ.get('HEPTA_HIA_TEST_INSTALLED_BULK_SITE')


def inventory():
    maximum = (1 << 64) - 1
    spans = [(d, s, n) for d, s, n in ((0, 0, 5), (1, 0, 4), (0, 1, 4), (5, 5, 0),
                                         (5, 4, 1), (0, 5, 1), (1, maximum, 0))]
    range_inputs = [[5, d, s, n, p] for d, s, n in spans for p in range(5)]
    return {
        'bulk': (bulk_program(), [[n, count, 0xa5] for n, count in
                                  ((0, 0), (2, 0), (2, 1), (2, 2), (3, 4), (1, maximum))]),
        'move_bytes': (move_program(), range_inputs),
        'copy_offset': (copy_program(), range_inputs),
        'swap_bytes': (swap_program(), [[5, a, b, i] for a, b in ((0, 4), (4, 0), (2, 2), (maximum, 0))
                                         for i in range(5)]),
        'fill_range': (fill_program(), [[5, o, n, 234, i] for o, n in
                                       ((0, 5), (1, 3), (5, 0), (5, 1), (maximum, 0)) for i in range(5)]),
    }


PROBE = '''
from collections import Counter
from contextlib import nullcontext
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch

site = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(site))
from hepta import hia_program_runtime as vm
from hepta.hia_bounded_memory_native import SELECTOR
from hepta.hia_scalar_reference_native import NativeScalarReference

assert Path(vm.__file__).resolve().is_relative_to(site)
domains = json.loads(Path(sys.argv[2]).read_bytes())
counts = Counter()
rows = {}
mode = sys.argv[3]
def observed(image, name, destination, **options):
    assert image._default_package_binding
    counts[name] += 1
    return actual(image, name, destination, **options)

if mode == 'native':
    actual = NativeScalarReference.package_byte_operation
    scope = patch.object(NativeScalarReference, 'package_byte_operation', observed)
else:
    scope = nullcontext()
with scope:
    for name, (document, cases) in domains.items():
        verified = vm.verify_program(document)
        reports = []
        for args in cases:
            try:
                report = vm.execute_program(verified, name, args)
            except vm.HIAProgramTrap as error:
                report = error.report
            reports.append(report)
        rows[name] = reports

if mode == 'native':
    assert all(counts[label] for label in ('fill', 'copy', 'move', 'copy_range', 'swap')), counts
    # The explicit bounded-memory selector historically takes effect only
    # after the range checks and only when a nonempty move/fill is requested.
    with patch.dict(os.environ, {SELECTOR: ''}):
        fn = vm.verify_program(domains['fill_range'][0])
        assert vm.execute_program(fn, 'fill_range', [5, 5, 0, 77, 1])['result'] == 0
        for name, args in [('fill_range', [5, 0, 1, 77, 1]), ('move_bytes', [5, 1, 0, 4, 0]),
                           ('bulk', [0, 0, 2])]:
            try:
                vm.execute_program(domains[name][0], name, args)
            except ValueError as exc:
                assert str(exc) == 'bounded-memory selector must not be empty'
            else:
                raise AssertionError('explicit bounded owner was bypassed')
Path(sys.argv[4]).write_text(json.dumps({'reports': rows, 'counts': dict(counts)}))
'''


@unittest.skipUnless(INSTALLED, 'requires a pip-installed matching-source native wheel')
class InstalledBulkMemoryTests(unittest.TestCase):
    def test_overlap_ranges_and_explicit_selector_order(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            plan = root / 'inputs.json'
            plan.write_text(json.dumps(inventory()))
            results = []
            for mode, site in (('portable', Path(__file__).resolve().parents[1]), ('native', INSTALLED)):
                output = root / (mode + '.json')
                result = subprocess.run([sys.executable, '-I', '-B', '-c', PROBE,
                                         str(site), str(plan), mode, str(output)],
                                        cwd=root, env={'PATH': ''}, capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stderr)
                results.append(json.loads(output.read_bytes()))
            self.assertEqual(results[0]['reports'], results[1]['reports'])
