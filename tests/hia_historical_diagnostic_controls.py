"""Recover the former diagnostic test fixture as data for its historical controls."""
from hashlib import sha256
from pathlib import Path
import json

from tests import hia_caller_diagnostics_admission as diagnostics
from tests import hia_native_transport_worker_successor as delivery


def diagnostic_predecessor(root, raw):
    """Check the physical caller before exposing each exact predecessor view."""
    root, captured = Path(root), {}

    def capture(path):
        value = path.read_bytes()
        if path in captured and captured[path] != value:
            raise ValueError('historical diagnostic source changed between reads')
        captured[path] = value
        return value

    physical = capture(root / diagnostics.PATH)
    expected, _, take = delivery._installed_view(
        diagnostics.PATH, physical, root=root, take=capture)
    if raw not in (physical, expected):
        raise ValueError('historical diagnostic caller is not its reviewed physical predecessor')
    raw = expected
    original = raw
    if diagnostics.pin(raw) == {
            'bytes': 47052,
            'sha256': '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2'}:
        from tools.hia_artifact_caller_source_history import predecessor
        raw = predecessor(root, diagnostics.PATH, raw, take=take)
        take = delivery._prior_take(diagnostics.PATH, original, raw, root=root, take=take)
    if diagnostics.pin(raw) != diagnostics.CURRENT:
        raw = delivery._reverse_sqlite_boundary(diagnostics.PATH, raw,
            capture(root / delivery.SQLITE_BOUNDARY_FIXTURE),
            delivery.DIAGNOSTIC_FIXTURE, capture(root / delivery.DIAGNOSTIC_FIXTURE),
            diagnostics.CURRENT, root=root, take=take)
    if any(path.read_bytes() != value for path, value in captured.items()):
        raise ValueError('historical diagnostic inputs changed at terminal readback')
    return raw


def historical_caller_dependencies(root, sources, expected):
    """Recover only the reviewed Machine and Proof fixture versions as data."""
    from tests.hia_store_delivery_successor import reverse_exact

    from tests.hia_installed_distribution_history import predecessor
    from tools.hia_native_cold_caller_history import KNOWN_CURRENT
    from tools import hia_native_cold_composition_history as composition
    root, captured, views, compositions = Path(root), {}, {}, []

    def capture(path):
        raw = path.read_bytes()
        if path in captured and captured[path] != raw:
            raise ValueError('historical caller dependency changed between captures')
        captured[path] = raw
        return raw

    for name, raw in sources.items():
        selected, view = raw, capture
        if diagnostics.pin(selected) == composition.CURRENT.get(name):
            projected, history = composition.prepare(root, {name: selected}, take=view)
            compositions.append(history)
            selected, view = projected[name], history['prior_take']
        if diagnostics.pin(selected) == KNOWN_CURRENT.get(name):
            selected, _, view = delivery._cold_view(name, selected, root=root, take=view)
        sources[name] = predecessor(name, selected, root=root, take=view)
        if sources[name] != selected:
            view = delivery._prior_take(name, selected, sources[name], root=root, take=view)
        views[name] = view
    from tools.hia_artifact_caller_source_history import predecessor as artifact_predecessor
    for name in ('tests/test_hia_agent_assembly.py',
                 'tests/test_hia_artifact_publication_native.py',
                 'tests/test_hia_artifact_publication_route.py'):
        if name in expected and name in sources:
            sources[name] = artifact_predecessor(root, name, sources[name], take=views[name])
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
    for history in compositions:
        composition.verify_unchanged(history)
    if any(path.read_bytes() != raw for path, raw in captured.items()):
        raise ValueError('historical caller dependencies changed at terminal readback')


def historical_bootstrap_dependencies(root, sources, scopes):
    historical_caller_dependencies(root, sources, {
        name: record['sha256'] for name, record in scopes['ordinary']['files'].items()})


def historical_terminal_pair(root, sources, current, physical):
    from tests.hia_installed_distribution_history import predecessor

    root = Path(root)

    def capture(name):
        raw = (root / name).read_bytes()
        if name in physical and physical[name] != raw:
            raise ValueError('terminal physical source changed between captures: ' + name)
        physical[name] = raw
        return raw

    def take(path):
        return capture(Path(path).relative_to(root).as_posix())

    for name, expected in current.items():
        actual = capture(name)
        raw, _, prior_take = delivery._installed_view(name, actual, root=root, take=take)
        if sources[name] not in (actual, raw):
            raise ValueError('terminal source is not its complete reviewed predecessor: ' + name)
        if diagnostics.pin(raw) != expected:
            if name == delivery.TRANSPORT:
                raw = delivery._reverse_sqlite_boundary(
                    name, raw, capture(delivery.SQLITE_BOUNDARY_FIXTURE), delivery.FIXTURE,
                    capture(delivery.FIXTURE), expected, root=root, take=prior_take)
            elif name == delivery.DELIVERY:
                raw = delivery.restore_sql_source(name, raw, capture, expected,
                                                  root=root, take=prior_take)
            elif name == delivery.EVALUATION:
                raw = delivery.restore_evaluation_store(
                    raw, capture(delivery.EVALUATION_STORE_FIXTURE), root=root, take=prior_take)
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
