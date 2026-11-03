"""Bounded single-process ordinary-VM pre/post observations, never a proof.

Keep production zero initialization. Ghost W tracks explicit successful stores,
not the bytes supplied by allocation. No native/emitter/Lean entry point exists.
The temporary class patch is only for an isolated, nonconcurrent research run.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
from hepta.hia_program import verify_program
from hepta import hia_program_runtime as vm
from tools.check_initialization_frontiers import DENY
from tools.extract_initialization_obligations import OBLIGATIONS, source_identity as ledger_identity


MAX_SNAPSHOT_OWNER_ROWS = 16384

def source_identity():
    result = ledger_identity()
    root = Path(__file__).resolve().parents[1]
    for path in (Path(__file__), root / 'tools/extract_initialization_obligations.py',
                 root / 'experiments/hia_initialization_frontiers_20261103/SINGLE_STORE_CONNECTION.md'):
        result[str(path.relative_to(root))] = sha256(path.read_bytes()).hexdigest()
    return result


def audit_store_event(event):
    """Finite concrete frame check; not a Lean theorem or a trusted receipt."""
    try:
        before, after = event['before'], event['after']
        if before.keys() != after.keys() or event['resources_before'] != event['resources_after']:
            return False
        for snapshot in (before, after):
            for key, row in snapshot.items():
                if (type(key) is not int or key <= 0 or type(row['runtime_ident']) is not int
                        or row['active'] is not True or type(row['bytes']) is not list
                        or any(type(v) is not int or not 0 <= v < 256 for v in row['bytes'])
                        or type(row['written']) is not list
                        or any(type(i) is not int or not 0 <= i < len(row['bytes']) for i in row['written'])
                        or row['written'] != sorted(set(row['written']))):
                    return False
        epoch = event['owner_epoch']
        if epoch is not None and (type(epoch) is not int or epoch <= 0):
            return False
        if event['outcome'] != 'success':
            return event['outcome'] == 'failure' and before == after
        index, value = event['index'], event['value']
        if type(index) is not int or type(value) is not int or not (0 <= value < 256):
            return False
        original, final = before[epoch], after[epoch]
        if not 0 <= index < len(original['bytes']):
            return False
        expected = deepcopy(before)
        expected[epoch]['bytes'][index] = value
        expected[epoch]['written'] = sorted(set(original['written']) | {index})
        if expected != after:
            return False
        # Project into the existing Memory shape: none for bytes without a
        # successful explicit-store event, even though actual bytes are zeroed.
        old_w, new_w = set(original['written']), set(final['written'])
        if any(type(i) is not int or not 0 <= i < len(original['bytes']) for i in old_w | new_w):
            return False
        for address in range(len(original['bytes'])):
            old = original['bytes'][address] if address in old_w else None
            new = final['bytes'][address] if address in new_w else None
            if new != (value if address == index else old):
                return False
        return True
    except (KeyError, TypeError, ValueError, IndexError, AttributeError):
        return False


def observe_single_stores(program, arguments, *, function='calculate',
                          max_observed_bytes=4096, max_events=4096, **limits):
    if (type(max_observed_bytes) is not int or not 0 <= max_observed_bytes <= 65536
            or type(max_events) is not int or not 0 <= max_events <= 4096):
        raise ValueError('invalid observation bound')
    identity = source_identity()
    checked = verify_program(program)
    owners, written, events, complete = {}, {}, [], True
    snapshot_cells = 0
    snapshot_rows = 0
    operation = vm._Machine.operation
    # Binding by actual operation identity inside this execute invocation avoids
    # conflating structurally equal instructions or repeated static sites.
    def synchronize(machine):
        nonlocal complete
        if not complete:
            return
        for owner in machine.owners.values():
            if owner not in owners:
                if len(owners) >= 4096:
                    complete = False
                    return
                owners[owner] = len(owners) + 1
                written[owner] = set()

    def snapshot(machine):
        synchronize(machine)
        if sum(len(o.data) for o in machine.owners.values()) > max_observed_bytes:
            raise OverflowError('observation byte bound')
        return {owners[o]: {'runtime_ident': o.ident, 'active': o.active,
                           'bytes': list(o.data), 'written': sorted(written[o])}
                for o in machine.owners.values()}

    def watched(machine, ins, env, depth):
        nonlocal complete, snapshot_cells, snapshot_rows
        synchronize(machine)
        if ins['op'] != 'buffer.store' or not complete:
            result = operation(machine, ins, env, depth)
            synchronize(machine)
            return result
        size = sum(len(o.data) for o in machine.owners.values())
        rows = 2 * len(machine.owners)
        if (len(events) >= max_events or snapshot_cells + 2 * size > 262144
                or snapshot_rows + rows > MAX_SNAPSHOT_OWNER_ROWS):
            complete = False
            return operation(machine, ins, env, depth)
        try:
            before = snapshot(machine)
        except OverflowError:
            complete = False
            return operation(machine, ins, env, depth)
        snapshot_cells += 2 * size
        snapshot_rows += rows
        resources = machine.resources()
        locators = [{'function': f['name'], 'block': b['id'], 'ordinal': n}
                    for f in machine.functions.values() for b in f['blocks']
                    for n, op in enumerate(b['ops']) if op is ins]
        if len(locators) != 1:
            complete = False
            return operation(machine, ins, env, depth)
        owner = None
        try:
            owner = vm._underlying(env[ins['args'][0]])
        except vm.HIAProgramRejected:
            pass  # The real operation must produce its own rejection.
        event = {'operation': deepcopy(ins), 'locator': locators[0], 'step': machine.steps,
                 'owner_epoch': owners.get(owner),
                 'index': env[ins['args'][1]], 'value': env[ins['args'][2]],
                 'before': before, 'resources_before': resources}
        try:
            result = operation(machine, ins, env, depth)
        except Exception:
            event.update(outcome='failure', after=snapshot(machine), resources_after=machine.resources())
            event['finite_frame_matches'] = audit_store_event(event)
            events.append(event)
            raise
        if owner not in written:
            complete = False
        else:
            written[owner].add(event['index'])
        event.update(outcome='success', after=snapshot(machine), resources_after=machine.resources())
        event['finite_frame_matches'] = audit_store_event(event)
        events.append(event)
        return result

    with patch.object(vm._Machine, 'operation', watched):
        try:
            outcome = vm.execute_program(checked, function, arguments, **limits)
        except (vm.HIAProgramTrap, vm.HIAProgramBudgetExceeded) as error:
            outcome = error.report
    unchanged = source_identity() == identity
    complete = complete and unchanged
    return {'schema': 'hepta.hia.single-store-projection-observation.v1',
            'source_sha256': identity, 'sources_unchanged': unchanged,
            'core_sha256': checked.sha256, 'function': function,
            'arguments': deepcopy(arguments), 'limits': deepcopy(limits),
            'events': events, 'vm_outcome': outcome,
            'observation_complete': complete,
            'finite_frame_matches': complete and all(e['finite_frame_matches'] for e in events),
            'observed_store_count': len(events),
            'observed_successful_store_count': sum(e['outcome'] == 'success' for e in events),
            'all_program_loads_covered_claim': False,
            'owner_epochs_seen': len(owners),
            'observation_bounds': {'bytes': max_observed_bytes, 'events': max_events, 'total_snapshot_byte_cells': 262144, 'total_snapshot_owner_rows': MAX_SNAPSHOT_OWNER_ROWS, 'owner_epochs': 4096},
            'obligations': [{'id': name, 'status': 'unproved'} for name, _ in OBLIGATIONS],
            'actual_core_bridge_proved': False, 'finite_observation_only': True,
            'ordinary_zero_initialization_retained': True, **DENY}
