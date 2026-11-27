"""Verify the five frozen SQL journal effects survived migration to typed HIA Store.

This is a static source guard plus explicit negative controls, not a claim of
end-to-end equivalence or permission to discard the original source tests.
"""
from __future__ import annotations
import ast
from hashlib import sha256
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FROZEN = 'tests/fixtures/native_delivery_original_9c46166.json'
FROZEN_SHA256 = 'a1f82e1c955ece21319cc49a0e3834658a2eeb0be7636d6f13690e1d6b83dea7'

# The original journal issued five literal SQL calls. The HIA Store migration
# moves them behind typed methods; checking only execute() ASTs would reject a
# working migration, while blindly accepting an empty list would lose the
# original method/argument-order protection. Keep both sides pinned.
_JOURNAL_SQL_SUCCESSOR = (
    "service.store.journal_lookup(session.key)",
    "observe_store(service.store.journal_reserve, session.key, session.request_digest, tool, str(hosted.time.time_ns()))",
    "observe_store(service.store.journal_complete, session.key, instruction.response.decode('utf-8'))",
    "service.store.journal_cost_observed(*_delivery_guard((context_id, str(tool), request_id, hosted.time.monotonic_ns() - started, instruction.status, instruction.cost_details)))",
    "service.store.journal_complete(*_delivery_guard((session.key, instruction.response.decode('utf-8'))))",
)
_JOURNAL_SQL_ORIGINAL = {
    'journal_lookup': 'SELECT * FROM requests WHERE key=?',
    'journal_reserve': 'INSERT INTO requests VALUES (?,?,?,?,?,?)',
    'journal_complete': "UPDATE requests SET state='completed',response=? WHERE key=?",
    'journal_cost': 'INSERT INTO costs (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)',
}
_JOURNAL_NATIVE_DISPATCH = {
    'journal_lookup': '_JOURNAL_LOOKUP',
    'journal_reserve': '_JOURNAL_RESERVE',
    'journal_complete': '_JOURNAL_COMPLETE',
    'journal_cost': '_JOURNAL_COST',
}


def admit_journal_sql_successor(root, journal_tree):
    """Require exact typed effects and the original SQL fallback/ABI, fail closed."""
    calls = []
    for node in ast.walk(journal_tree):
        if not isinstance(node, ast.Call):
            continue
        func = ast.unparse(node.func)
        if (func.startswith('service.store.journal_') or
                func == 'observe_store' and node.args and
                ast.unparse(node.args[0]).startswith('service.store.journal_')):
            calls.append((node.lineno, ast.dump(node, include_attributes=False)))
    actual = [value for _, value in sorted(calls)]
    expected = [ast.dump(ast.parse(source, mode='eval').body, include_attributes=False)
                for source in _JOURNAL_SQL_SUCCESSOR]
    if actual != expected:
        raise AssertionError('journal typed SQL successor method, order, or arguments changed')
    if any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
           and node.func.attr in ('execute', '_execute') for node in ast.walk(journal_tree)):
        raise AssertionError('HIA journal bypasses typed Store with a raw SQL call')

    hosted = ast.parse((root / 'hepta/hia_agent_store.py').read_bytes())
    native = ast.parse((root / 'hepta/hia_agent_store_native.py').read_bytes())
    declarations = {
        node.targets[0].id: node.value
        for node in native.body
        if isinstance(node, ast.Assign) and len(node.targets) == 1
        and isinstance(node.targets[0], ast.Name)
    }
    # The typed operation indices are an executable ABI: verify not merely the
    # Python method names but the exact indexed SQL and physical row layout.
    schemas = {
        '_SELECTS': ((9, _JOURNAL_SQL_ORIGINAL['journal_lookup']),),
        '_INSERTS': ((6, _JOURNAL_SQL_ORIGINAL['journal_reserve']),
                     (2, _JOURNAL_SQL_ORIGINAL['journal_cost'])),
        '_UPDATES': ((1, _JOURNAL_SQL_ORIGINAL['journal_complete']),),
    }
    for table, entries in schemas.items():
        nodes = declarations[table].elts
        for index, query in entries:
            if (not isinstance(nodes[index - 1], ast.Tuple)
                    or not isinstance(nodes[index - 1].elts[0], ast.Constant)
                    or nodes[index - 1].elts[0].value != query):
                raise AssertionError('native journal indexed SQL query differs: ' + table)
    for name, body in {
        '_JOURNAL_LOOKUP': '_query_plan(9)',
        '_JOURNAL_RESERVE': "_write_plan(6, _INSERTS, b'HIAINS01')",
        '_JOURNAL_COMPLETE': "_write_plan(1, _UPDATES, b'HIAUPB01')",
        '_JOURNAL_COST': "_write_plan(2, _INSERTS, b'HIAINS01')",
    }.items():
        if ast.dump(declarations[name]) != ast.dump(ast.parse(body, mode='eval').body):
            raise AssertionError('native journal typed operation index differs: ' + name)
    rows = declarations['_COLUMNS']
    if ast.literal_eval(next(value for key, value in zip(rows.keys, rows.values)
                             if isinstance(key, ast.Constant) and key.value == 'requests')) != (
            'key', 'digest', 'tool', 'state', 'response', 'started_ns'):
        raise AssertionError('native journal request physical columns changed')
    for method, statement in _JOURNAL_SQL_ORIGINAL.items():
        owner = next(node for node in hosted.body if isinstance(node, ast.ClassDef)
                     and node.name == 'AgentStore')
        function = next(node for node in owner.body if isinstance(node, ast.FunctionDef)
                        and node.name == method)
        literals = [node.value for node in ast.walk(function)
                    if isinstance(node, ast.Constant) and isinstance(node.value, str)]
        if literals.count(statement) != 1:
            raise AssertionError('original journal SQL literal/binding was not preserved: ' + method)
        native_calls = [ast.unparse(node) for node in ast.walk(function)
                        if isinstance(node, ast.Call)]
        if not any('.db.' + method + '(' in call for call in native_calls):
            raise AssertionError('journal typed Store forwarding changed: ' + method)
        backend = next(node for node in native.body if isinstance(node, ast.ClassDef)
                       and node.name == 'NativeStoreConnection')
        selected = next(node for node in backend.body
                        if isinstance(node, ast.FunctionDef) and node.name == method)
        selected_src = ast.unparse(selected)
        if ('_typed_operation(' + _JOURNAL_NATIVE_DISPATCH[method] not in selected_src):
            raise AssertionError('native journal SQL opcode was not preserved: ' + method)
    hosted_observed = next(node for node in owner.body
                           if isinstance(node, ast.FunctionDef)
                           and node.name == 'journal_cost_observed')
    observed = ast.unparse(hosted_observed)
    if ('self.db.journal_cost_observed(context, tool, request_id, elapsed_ns, status, details)' not in observed
            or "self.journal_cost(context, tool, request_id, str(elapsed_ns), status, details.decode('utf-8'))" not in observed):
        raise AssertionError('journal cost observation lost a typed or original fallback')
    native_observed = next(node for node in backend.body if isinstance(node, ast.FunctionDef)
                           and node.name == 'journal_cost_observed')
    observed = ast.unparse(native_observed)
    if ('self._descriptor_unique_transaction(18, result.stdout[8:], len(_CURSOR_COMMIT_INTENT))' not in observed
            or 'self._check_live()' not in observed or 'with self.lock:' not in observed):
        raise AssertionError('native journal cost atomic bounded commit changed')


def qualify(root=ROOT):
    raw = (root / FROZEN).read_bytes()
    if sha256(raw).hexdigest() != FROZEN_SHA256:
        raise AssertionError('frozen native-delivery evidence differs')
    expected = json.loads(raw)['sql_call_asts']['hepta/hia_agent_journal_native.py']
    if len(expected) != 5:
        raise AssertionError('frozen journal did not contain five SQL writes/reads')
    journal_tree = ast.parse((root / 'hepta/hia_agent_journal_native.py').read_bytes())
    admit_journal_sql_successor(root, journal_tree)
    return {'frozen_sql_calls': len(expected), 'typed_journal_calls': len(_JOURNAL_SQL_SUCCESSOR),
            'original_sha256': FROZEN_SHA256, 'typed_source_sha256':
            sha256((root / 'hepta/hia_agent_journal_native.py').read_bytes()).hexdigest()}


if __name__ == '__main__':
    import sys
    try:
        print(json.dumps(qualify(), indent=2, sort_keys=True))
    except Exception as exc:
        print(f'{type(exc).__name__}: {exc}', file=sys.stderr)
        sys.exit(1)
