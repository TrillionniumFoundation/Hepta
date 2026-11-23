"""Compare the installed HIA ledger with the VM's published report contract."""
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_opcodes import (
    EXECUTION_CHAIN_FIELDS, EXECUTION_RESOURCE_FIELDS, ExecutionObservationRejected,
    _reference_validate_execution_observation,
)
from tests.test_hia_execution_observation_native import cases
from tests.test_hia_program_tools import scalar_program


INSTALLED = os.environ.get('HEPTA_HIA_TEST_INSTALLED_LEDGER_SITE')
CHECK = '''
import json
from pathlib import Path
import sys
from unittest.mock import patch

site = Path(sys.argv[1]).resolve()
sys.path.insert(0, str(site))
from hepta import hia_opcodes, hia_program_runtime as vm
from hepta.hia_execution_ledger_native import NativeExecutionLedger, vm_execution_ledger_validator

assert Path(vm.__file__).resolve().is_relative_to(site)
cases, program = json.loads(Path(sys.argv[2]).read_bytes())
validate = vm_execution_ledger_validator()
assert isinstance(validate.__self__, NativeExecutionLedger)
for status, counters, options, expected in cases:
    try:
        validate(status, counters, **options)
        message = None
    except hia_opcodes.ExecutionObservationRejected as error:
        message = str(error)
    assert message == expected, (status, counters, options, expected, message)

seen = []
original = NativeExecutionLedger.validate
def observed(image, status, counters, **options):
    assert image._default_package_binding
    seen.append(status)
    return original(image, status, counters, **options)

with patch.object(NativeExecutionLedger, 'validate', observed), patch.object(
        hia_opcodes, '_reference_validate_execution_observation', side_effect=AssertionError('host ledger used')):
    for value, max_steps, status in ((1, 20, 'returned'), (2**32 - 1, 20, 'trapped'), (1, 1, 'budget_exceeded')):
        try:
            report = vm.execute_program(program, 'increment', [value], max_steps=max_steps)
        except (vm.HIAProgramTrap, vm.HIAProgramBudgetExceeded) as error:
            report = error.report
        assert report['status'] == status
assert seen == ['returned', 'trapped', 'budget_exceeded']
'''


@unittest.skipUnless(INSTALLED, 'requires a pip-installed matching-source native wheel')
class InstalledExecutionLedgerTests(unittest.TestCase):
    def test_native_ledger_checks_reports_and_preserves_error_order(self):
        rows = []
        empty = dict.fromkeys(EXECUTION_RESOURCE_FIELDS, 0)
        chains = dict.fromkeys(EXECUTION_CHAIN_FIELDS, 0)
        limits = dict(steps=1, max_steps=10, max_heap_bytes=64)
        edge_cases = [
            ('returned', {**empty, 'peak_bytes': 65}, limits),
            ('returned', {**empty, **chains, 'chain_nodes_created': 1, 'live_chain_nodes': 1},
             {**limits, 'with_chains': True}),
            ('returned', {**empty, 'owners_created': 1, 'live_owners': 1}, limits),
            ('invalid', None, {**limits, 'with_chains': 'wrong', 'max_steps': False}),
            ('trapped', {**empty, 'peak_bytes': 65}, {**limits, 'error_code': 'steps', 'steps': 0}),
        ]
        for status, counters, options in [*cases(), *edge_cases]:
            try:
                _reference_validate_execution_observation(status, counters, **options)
                message = None
            except ExecutionObservationRejected as error:
                message = str(error)
            rows.append([status, counters, options, message])
        with TemporaryDirectory() as temp:
            root = Path(temp)
            records = root / 'reports.json'
            records.write_text(json.dumps([rows, scalar_program()]))
            result = subprocess.run([sys.executable, '-I', '-B', '-c', CHECK, INSTALLED, str(records)],
                                    cwd=root, env={'PATH': ''}, capture_output=True, text=True, timeout=90)
        self.assertEqual(result.returncode, 0, result.stderr)
