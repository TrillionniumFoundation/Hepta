"""Check the VM's flat HIA ledger against the existing public report contract."""

from hashlib import sha256
import json
from pathlib import Path
import sys
from unittest.mock import patch

from hepta import hia_opcodes
from hepta.hia_execution_ledger_native import SELECTOR, installed_execution_ledger
from hepta.hia_native_helpers import ABI, SCHEMA, TARGET, native_helpers_scope
from hepta.hia_program_runtime import HIAProgramBudgetExceeded, HIAProgramTrap, execute_program
from tests.test_hia_execution_observation_native import cases, outcome
from tests.test_hia_program_tools import scalar_program


def check(manifest):
    ledger = installed_execution_ledger(str(manifest))
    count = 0
    for status, counters, options in cases():
        expected = outcome(lambda: hia_opcodes._reference_validate_execution_observation(
            status, counters, **options))
        actual = outcome(lambda: ledger.validate(status, counters, **options))
        assert actual == expected, (status, counters, options, actual, expected)
        count += 1

    program = scalar_program()

    def reports():
        returned = execute_program(program, 'increment', [4])
        results = [returned]
        for value, options in ((2**32 - 1, {}), (0, {'max_steps': 1})):
            try:
                execute_program(program, 'increment', [value], **options)
            except (HIAProgramTrap, HIAProgramBudgetExceeded) as error:
                results.append(error.report)
            else:
                raise AssertionError('missing trap or budget stop')
        return results

    expected = reports()
    bundle = manifest.parent / 'ledger-qualification-bundle.json'
    bundle.write_text(json.dumps({'schema': SCHEMA, 'target': TARGET, 'abi': ABI, 'helpers': [{
        'selector': SELECTOR, 'manifest_path': manifest.name,
        'manifest_sha256': sha256(manifest.read_bytes()).hexdigest()}]}))
    with native_helpers_scope(str(bundle), sha256(bundle.read_bytes()).hexdigest()) as selection:
        with patch.object(hia_opcodes, '_reference_validate_execution_observation',
                          side_effect=AssertionError('hosted observation used')):
            assert reports() == expected
        selection.check()
    return count + len(expected)


if __name__ == '__main__':
    path = Path(sys.argv[1]).resolve(strict=True)
    print(f'{check(path)} native execution ledger comparisons passed')
