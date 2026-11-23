"""Exercise the ordinary installed VM allocation policy with sealed package inputs."""
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from tests.hia_distribution_fixture import VM_EXECUTION_ROUTES

from tests.test_hia_program import b, c, f, i, m, ret


INSTALLED = os.environ.get('HEPTA_HIA_TEST_INSTALLED_ALLOCATION_SITE')
CHECK = VM_EXECUTION_ROUTES + '''
import json
from pathlib import Path
import sys
from unittest.mock import patch

site = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(site))
from hepta import hia_program_runtime as vm
from hepta.hia_scalar_reference_native import NativeScalarReference

assert Path(vm.__file__).resolve().is_relative_to(site)
program = Path(sys.argv[2]).read_bytes()
decisions = []
actual = NativeScalarReference.allocation

def observed(image, *arguments):
    assert image._default_package_binding
    result = actual(image, *arguments)
    decisions.append(result)
    return result

def forbidden(*args):
    raise AssertionError('ordinary installed VM used its host allocation policy')

with patch.object(NativeScalarReference, 'allocation', observed), patch.object(vm._Machine, '_reference_allocation_decision', forbidden):
    def run(name, n, budget, fail_at=None):
        try:
            return vm.execute_program(program, name, [n], max_heap_bytes=budget, allocation_fail_at=fail_at)
        except (vm.HIAProgramTrap, vm.HIAProgramBudgetExceeded) as error:
            return error.report

    def collect(check_primitive):
        reports = []
        def capture(*args):
            result = run(*args)
            reports.append(result)
            return result
        for name in ('new', 'try_new'):
            assert capture(name, 0, 0, 1)['values'] == [0, True]
            assert capture(name, 2, 2, 1 << 70)['values'] == [2, True]
            assert capture(name, 2, 1, 1)['status'] == 'budget_exceeded'
        for n, budget, fail_at in ((2, 2, 1), (1 << 63, 0, 1)):
            assert capture('new', n, budget, fail_at)['status'] == 'trapped'
            refused = capture('try_new', n, budget, fail_at)
            assert refused['values'] == [0, False] and refused['resources']['live_owners'] == 0
        return reports
    compare_vm_routes(collect)
assert decisions == [('empty', 0), ('allocate', 1), ('heap-budget', 0)] * 2 + [('injected', 1)] * 2 + [('object-model', 0)] * 2, decisions
'''


@unittest.skipUnless(INSTALLED, 'requires a pip-installed matching-source native wheel')
class InstalledAllocationTests(unittest.TestCase):
    def test_allocation_status_and_attempts_come_from_hia(self):
        functions = []
        for name in ('new', 'try_new'):
            outputs = [('owner', 'buffer')]
            if name == 'try_new':
                outputs.append(('ok', 'bool'))
            operations = [i('buffer.' + name, ['n'], outputs)]
            if name == 'new':
                operations.append(c('ok', 'bool', True))
            operations.extend([i('buffer.len', ['owner'], [('size', 'usize')]), i('owner.drop', ['owner'])])
            parameters = [('n', 'usize')]
            functions.append(f(name, parameters, ['usize', 'bool'], ['alloc', 'trap'],
                               [b('entry', parameters, operations, ret('size', 'ok'))]))
        with TemporaryDirectory() as temp:
            root = Path(temp)
            program = root / 'allocation.hepta'
            program.write_text(json.dumps(m(*functions)))
            result = subprocess.run([sys.executable, '-I', '-B', '-c', CHECK, INSTALLED, str(program)],
                                    cwd=root, env={'PATH': ''}, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
