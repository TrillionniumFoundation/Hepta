"""Recover the former diagnostic test fixture as data for its historical controls."""
from hashlib import sha256
import json
from pathlib import Path

from tests import hia_caller_diagnostics_admission as diagnostics
from tests import hia_native_transport_worker_successor as delivery


def diagnostic_predecessor(root, raw):
    """Check the actual inherited source, then restore its reviewed predecessor."""
    if diagnostics.pin(raw) == diagnostics.CURRENT:
        return raw
    return delivery._reverse_sqlite_boundary(diagnostics.PATH, raw,
        (root / delivery.SQLITE_BOUNDARY_FIXTURE).read_bytes(),
        delivery.DIAGNOSTIC_FIXTURE, (root / delivery.DIAGNOSTIC_FIXTURE).read_bytes(), diagnostics.CURRENT)


def historical_caller_dependencies(root, sources, expected):
    """Recover only the reviewed Machine and Proof fixture versions as data."""
    from tests.hia_store_delivery_successor import reverse_exact

    from tests.hia_installed_distribution_history import predecessor
    from tools.hia_frozen_component_sources import cold_caller_source
    for name, raw in sources.items():
        prior, _ = cold_caller_source(root, name, raw, take=Path.read_bytes)
        sources[name] = predecessor(name, prior, root=root)
    machine = delivery.MACHINE_RECEIPT_CALLER
    if machine in expected and diagnostics.pin(sources[machine])['sha256'] != expected[machine]:
        authority = (root / delivery.MACHINE_RECEIPT_FIXTURE).read_bytes()
        if diagnostics.pin(authority) != delivery.MACHINE_RECEIPT_FIXTURE_PIN:
            raise ValueError('the retained machine source authority changed')
        record = json.loads(authority)['record']
        sources[machine] = delivery.restore_machine_receipt_caller(root, sources[machine],
            {'bytes': record['old_bytes'], 'sha256': expected[machine]})
    proof = 'tests/test_hia_agent_native_proof_contract.py'
    if proof in expected and diagnostics.pin(sources[proof])['sha256'] != expected[proof]:
        authority = (root / delivery.COMPONENT_FIXTURE).read_bytes()
        if sha256(authority).hexdigest() != delivery.COMPONENT_FIXTURE_SHA256:
            raise ValueError('the retained proof source authority changed')
        record = json.loads(authority)['files'][proof][expected[proof]]
        sources[proof] = reverse_exact(sources[proof], record,
            {'bytes': record['old_bytes'], 'sha256': expected[proof]})


def historical_bootstrap_dependencies(root, sources, scopes):
    historical_caller_dependencies(root, sources, {
        name: record['sha256'] for name, record in scopes['ordinary']['files'].items()})


def historical_terminal_pair(root, sources, current, physical):
    from tests.hia_installed_distribution_history import predecessor

    def capture(name):
        if name not in physical:
            physical[name] = (root / name).read_bytes()
        return physical[name]

    for name, expected in current.items():
        raw = delivery._installed_predecessor(name, sources[name], root=root,
            take=lambda path: capture(path.relative_to(root).as_posix()))
        if diagnostics.pin(raw) != expected:
            if name == delivery.TRANSPORT:
                raw = delivery._reverse_sqlite_boundary(
                    name, raw, capture(delivery.SQLITE_BOUNDARY_FIXTURE), delivery.FIXTURE,
                    capture(delivery.FIXTURE), expected)
            elif name == delivery.DELIVERY:
                raw = delivery.restore_sql_source(name, raw, capture, expected, root=root)
            elif name == delivery.EVALUATION:
                physical_raw = capture(name)
                from tools.hia_frozen_component_sources import cold_caller_source
                prior, _ = cold_caller_source(root, name, physical_raw,
                    take=lambda path: capture(path.relative_to(root).as_posix()))
                prior = delivery._installed_predecessor(name, prior, root=root,
                    take=lambda path: capture(path.relative_to(root).as_posix()))
                if prior != raw:
                    raise ValueError('terminal evaluation view differs from its actual source')
                raw = delivery.restore_evaluation_store(physical_raw,
                    capture(delivery.EVALUATION_STORE_FIXTURE), root=root,
                    take=lambda path: capture(path.relative_to(root).as_posix()))
        if diagnostics.pin(raw) != expected:
            raise ValueError('terminal test predecessor differs: ' + name)
        sources[name] = raw
    if any((root / name).read_bytes() != raw for name, raw in physical.items()):
        raise ValueError('terminal source inputs changed during capture')



def historical_terminal_callers(root, sources, expected):
    from hepta.hia_native_helpers import HELPERS
    from tests.hia_store_delivery_successor import reverse_exact

    historical_caller_dependencies(root, sources, expected)
    name = diagnostics.PATH
    sources[name] = diagnostic_predecessor(root, sources[name])
    name = 'tests/test_hia_cost_ledger_native.py'
    fixed = (root / delivery.COMPONENT_FIXTURE).read_bytes()
    if sha256(fixed).hexdigest() != delivery.COMPONENT_FIXTURE_SHA256:
        raise ValueError('terminal component test authority differs')
    record = json.loads(fixed)['files'][name][expected[name]]
    sources[name] = reverse_exact(sources[name], record, {'bytes': record['old_bytes'], 'sha256': expected[name]})
    name = 'tests/test_hia_worker_native_helpers.py'
    fixed = (root / 'tests/fixtures/store_caller_worker_helpers_successor.json').read_bytes()
    if sha256(fixed).hexdigest() != '168ef69fadf672e41f3dd717d3d79e54fcd1af70105d2e3552687b72af824904':
        raise ValueError('terminal worker test authority differs')
    record = json.loads(fixed)['record']
    prior = reverse_exact(sources[name], record, {'bytes': record['old_bytes'], 'sha256': expected[name]})
    old = b'        self.assertEqual(len(HELPERS), 37)\n'
    if prior.count(old) != 1:
        raise ValueError('original terminal worker helper-count assertion differs')
    sources[name] = prior.replace(old, old.replace(b'37', str(len(HELPERS)).encode('ascii')), 1)


def cold_control_source(root, name, raw, physical, adjustments):
    """Recover a fixed caller view while retaining every actual physical input."""
    from pathlib import Path
    from tools import hia_cold_caller_sources as cold
    from tools import hia_frozen_component_sources as frozen

    if type(raw) is not bytes:
        raise ValueError('cold control source must be complete immutable bytes')
    if name not in cold.PATHS:
        return raw
    root = Path(root)
    captured = {}

    def take(path):
        relative = path.relative_to(root).as_posix()
        current = path.read_bytes()
        if relative in physical and physical[relative] != current:
            raise ValueError('cold control physical capture differs: ' + relative)
        if relative in captured and captured[relative] != current:
            raise ValueError('cold control physical input changed: ' + relative)
        physical[relative] = current
        captured[relative] = current
        return current

    if take(root / name) != raw:
        raise ValueError('cold control argument differs from actual physical source')
    helper = take(root / cold.SOURCE)
    if (diagnostics.pin(helper) != frozen.COLD_CALLER_HELPER_PIN
            or Path(cold.__file__).read_bytes() != helper):
        raise ValueError('cold control source helper differs')
    prior, proof = frozen.cold_caller_source(root, name, raw, take=take)
    if proof is None:
        # The generic compatibility reader leaves historical inputs to their
        # callers. This source-control boundary admits only the fixed complete
        # predecessor and never treats an unknown source as a historical one.
        strict = cold.original_caller_source(root, name, raw, take=take)
        if strict != raw:
            raise ValueError('cold control current source lacks physical proof')
        prior = strict
    else:
        if name in adjustments and adjustments[name] != proof:
            raise ValueError('cold control source proof changed')
        adjustments[name] = proof
    for relative, current in tuple(captured.items()):
        if take(root / relative) != current:
            raise ValueError('cold control terminal physical reread differs')
    return prior
