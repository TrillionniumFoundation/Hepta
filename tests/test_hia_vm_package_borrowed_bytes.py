"""Exercise source-bound fixed-width borrowed operations through the installed VM."""
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from tests.hia_distribution_fixture import VM_EXECUTION_ROUTES

from tools.hia_word_memory_cases import owned_program


INSTALLED = os.environ.get('HEPTA_HIA_TEST_INSTALLED_BORROWED_SITE')
PROBE = VM_EXECUTION_ROUTES + '''
from collections import Counter
import ctypes
import json
from pathlib import Path
import sys
from unittest.mock import patch

site = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(site))
from hepta import hia_program_runtime as vm
from hepta.hia_default_native import default_integer_image
from hepta.hia_scalar_reference_native import NativeScalarReference

assert Path(vm.__file__).resolve().is_relative_to(site)
program = Path(sys.argv[2]).read_bytes()
mode = sys.argv[3]
seen = Counter()
actual = getattr(NativeScalarReference, 'package_byte_operation', None)

def observed(image, name, owner, **arguments):
    assert image._default_package_binding and image._borrowed_entry._flags_ & ctypes._FUNCFLAG_PYTHONAPI
    seen[name] += 1
    return actual(image, name, owner, **arguments)

def run(check_primitive):
    rows = []
    verified = vm.verify_program(program)
    for name in ('load_le', 'load_be', 'store_le', 'store_be'):
        for n, at, value, probe in (
                (8, 0, 0, 0), (9, 1, 0x0123456789abcdef, 1),
                (17, 8, 0xffffffffffffffff, 16), (9, 0, 42, 8),
                (0, 0, 7, 0), (7, 0, 255, 0), (8, (1 << 64) - 1, 127, 0),
                (9, 1, 0x1020304050607080, 9)):
            try:
                report = vm.execute_program(verified, name, [n, at, value, probe])
            except vm.HIAProgramTrap as error:
                report = error.report
            rows.append(report)
    return rows

if mode == 'native':
    with patch.object(NativeScalarReference, 'package_byte_operation', observed):
        rows = compare_vm_routes(run)
    assert set(seen) == {'load', 'store', 'load.u64.le', 'load.u64.be', 'store.u64.le', 'store.u64.be'}, seen
    assert seen['store'] == 4 * 67
    image = default_integer_image()
    for name in seen:
        owner = bytearray(range(7))
        try:
            image.package_byte_operation(name, owner, offset=(1 << 64) - 1)
        except vm.HIAProgramTrap as error:
            assert error.code == 'bounds' and owner == bytearray(range(7))
            owner.extend(b'!')  # A retained trap traceback must not keep the array exported.
        else:
            raise AssertionError(name)
else:
    rows = run(False)
Path(sys.argv[4]).write_text(json.dumps({'reports': rows, 'calls': dict(seen)}))
'''


@unittest.skipUnless(INSTALLED, 'requires a pip-installed matching-source native wheel')
class InstalledBorrowedByteTests(unittest.TestCase):
    def test_byte_and_word_results_bounds_and_full_vm_reports(self):
        with TemporaryDirectory() as directory:
            temp = Path(directory)
            program = temp / 'borrowed.hepta'
            program.write_text(json.dumps(owned_program()))
            results = []
            for site, mode in ((Path(__file__).resolve().parents[1], 'portable'), (INSTALLED, 'native')):
                output = temp / (mode + '.json')
                result = subprocess.run([sys.executable, '-I', '-B', '-c', PROBE,
                                         str(site), str(program), mode, str(output)],
                                        cwd=temp, env={'PATH': ''}, capture_output=True, text=True, timeout=180)
                self.assertEqual(result.returncode, 0, result.stderr)
                results.append(json.loads(output.read_text()))
            self.assertEqual(results[0]['reports'], results[1]['reports'])
