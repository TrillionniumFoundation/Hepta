"""Resolve the actual Store adapters at the original native-delivery SQL sites."""
import ast
import copy


def _name(node):
    return ast.unparse(node)


def _require(match, reason):
    if not match:
        raise AssertionError(reason)


class _Bind(ast.NodeTransformer):
    def __init__(self, arguments):
        self.arguments = arguments

    def visit_Name(self, node):
        return copy.deepcopy(self.arguments.get(node.id, node))


def _store_sql(store, operation, args, receiver):
    owner = next(node for node in store.body if isinstance(node, ast.ClassDef) and node.name == 'AgentStore')
    method = next(node for node in owner.body if isinstance(node, ast.FunctionDef) and node.name == operation)
    bound = dict(zip((arg.arg for arg in method.args.args[1:]), args, strict=True))
    candidates = [n for n in ast.walk(method) if isinstance(n, ast.Call)]
    if operation in ('journal_cost_observed', 'context_created_ns'):
        next_op = {'journal_cost_observed': 'journal_cost', 'context_created_ns': 'context_created'}[operation]
        calls = [n for n in candidates if _name(n.func) == 'self.' + next_op]
        _require(len(calls) == 1 and not calls[0].keywords, operation + ' adapter changed')
        forwarded = [_Bind(bound).visit(copy.deepcopy(value)) for value in calls[0].args]
        return _store_sql(store, next_op, forwarded, receiver)
    if operation == 'context_created':
        records = [n for n in candidates if _name(n.func) == 'self._record']
        _require(len(records) == 1 and ast.literal_eval(records[0].args[0]) == operation
                 and len(records[0].args) == 3 and not records[0].keywords, 'context record adapter changed')
        call = ast.Call(func=ast.parse('self.db.execute', mode='eval').body,
                        args=[_Bind(bound).visit(copy.deepcopy(v)) for v in records[0].args[1:]], keywords=[])
        call.func.value.value = receiver
        return call
    sql = [n for n in candidates if _name(n.func) == 'self.db.execute']
    _require(len(sql) == 1, operation + ' must have exactly one SQL implementation')
    call = _Bind(bound).visit(copy.deepcopy(sql[0]))
    call.func.value.value = receiver
    return call


def _guarded_args(args):
    if len(args) == 1 and isinstance(args[0], ast.Starred):
        value = args[0].value
        _require(isinstance(value, ast.Call) and _name(value.func) == '_delivery_guard'
                 and not value.keywords and len(value.args) == 1 and isinstance(value.args[0], ast.Tuple),
                 'Store call lost its checked argument preparation')
        return value.args[0].elts
    return args


_BUDGET_PORTS = {
    'begin_immediate': ('BEGIN IMMEDIATE', False),
    'attempt_lookup': ('SELECT id,attempts FROM main.contexts WHERE id=?', True),
    'attempt_set': ('UPDATE main.contexts SET attempts=? WHERE id=? AND attempts=?', False),
    'wall_budget_lookup': ('SELECT context_id,used_native_ns,owner FROM main.execution_budgets WHERE context_id=?', True),
    'wall_budget_create': ('INSERT INTO main.execution_budgets(context_id,used_native_ns,owner) VALUES (?,?,NULL)', False),
    'wall_budget_claim': ('UPDATE main.execution_budgets SET owner=? WHERE context_id=? AND used_native_ns=? AND owner IS NULL', False),
    'wall_budget_finish': ('UPDATE main.execution_budgets SET owner=NULL,used_native_ns=? WHERE context_id=? AND used_native_ns=? AND owner=?', False),
    'commit': ('COMMIT', False),
    'rollback': ('ROLLBACK', False),
}


def _budget_effect(call):
    observed = _name(call.func) == 'self._observed_effect'
    values = call.args
    if observed:
        _require(_name(values[0]) == 'delivery', 'budget effect changed delivery owner')
        values = values[1:]
    port = ast.literal_eval(values[0])
    if port == 'context_create':
        _require(not observed and not call.keywords and [_name(v) for v in values[1:]]
                 == ['INSERT_CONTEXT', '(context, *context_record)'], 'additional context creation changed')
        return None
    sql, read = _BUDGET_PORTS[port]
    _require(ast.literal_eval(values[1]) == sql and observed == (port != 'rollback'), 'budget effect changed')
    _require([(kw.arg, ast.literal_eval(kw.value)) for kw in call.keywords] == ([('read', True)] if read else []),
             'budget read or acknowledgement changed')
    return ast.Call(func=ast.parse('self._execute', mode='eval').body, args=values[1:], keywords=[])


def delivery_sql_calls(tree, name, root):
    """Project only real SQL/Store effects, keeping their original source ordering."""
    store = ast.parse((root / 'hepta/hia_agent_store.py').read_bytes())
    parent = {child: node for node in ast.walk(tree) for child in ast.iter_child_nodes(node)}
    def owner(node):
        while node in parent and not isinstance(node, ast.FunctionDef):
            node = parent[node]
        return getattr(node, 'name', None)
    is_service = name.endswith('/hia_agent_service.py')
    is_journal = name.endswith('/hia_agent_journal_native.py')
    calls = []
    journal_ports = []
    evaluate_direct = None
    evaluate_port = None
    for call in (node for node in ast.walk(tree) if isinstance(node, ast.Call)):
        fn = _name(call.func)
        if isinstance(call.func, ast.Attribute) and call.func.attr in ('execute', '_execute'):
            if owner(call) == '_effect' and fn == 'self._execute':
                _require(_name(call) == 'self._execute(sql, parameters)', 'budget SQL forwarding changed')
                continue
            if is_service and owner(call) == '_hia_evaluate_reference':
                _require(evaluate_direct is None, 'Evaluate introduced an extra SQL effect')
                evaluate_direct = call
            else:
                calls.append(call)
            continue
        projected = None
        if (is_service and owner(call) == '_reference_call') or (is_journal and owner(call) == '_run_native_journal'):
            target, args = call.func, call.args
            if fn == 'observe_store':
                target, *args = args
            receiver = 'self.store' if is_service else 'service.store'
            if not isinstance(target, ast.Attribute) or _name(target.value) != receiver or not target.attr.startswith('journal_'):
                continue
            journal_ports.append((call.lineno, (target.attr, fn == 'observe_store',
                                  bool(args and isinstance(args[0], ast.Starred)))))
            _require(not call.keywords, 'unexpected Store keyword binding')
            projected = _store_sql(store, target.attr, _guarded_args(args), target.value)
        elif is_service and fn == 'self.store.context_created_ns' and owner(call) in (
                '_hia_evaluate_reference', '_hia_evaluate_with_components'):
            _require(evaluate_port is None and not call.keywords, 'Evaluate changed its typed Store call')
            evaluate_port = ast.copy_location(_store_sql(store, 'context_created_ns', call.args, call.func.value), call)
            continue
        elif name.endswith('_budget_native.py') and fn in ('self._effect', 'self._observed_effect') and owner(call) in (
                '_drive_observed', '_consume_observed'):
            projected = _budget_effect(call)
        if projected is not None:
            calls.append(ast.copy_location(projected, call))
    if journal_ports:
        expected = ([('journal_lookup', False, False), ('journal_reserve', True, False),
                     ('journal_complete', True, False), ('journal_cost_observed', False, True),
                     ('journal_complete', False, True)] if is_journal else
                    [('journal_lookup', False, False), ('journal_reserve', False, False),
                     ('journal_complete', False, True), ('journal_cost', False, True),
                     ('journal_complete', False, True)])
        _require([item for _, item in sorted(journal_ports)] == expected, 'Journal changed observed, guarded, or transaction effect ordering')
    if is_service:
        # The frozen and typed Evaluate routes perform the same original read.
        if evaluate_direct is not None and evaluate_port is not None:
            _require(ast.dump(evaluate_direct) == ast.dump(evaluate_port), 'Evaluate SQL and typed Store arguments differ')
        _require(evaluate_direct is not None or evaluate_port is not None, 'Evaluate lost its Store read')
        calls.append(evaluate_direct if evaluate_direct is not None else evaluate_port)
    return calls


def check_store_delegation(test):
    from threading import RLock
    from types import SimpleNamespace
    from hepta.hia_agent_store import AgentStore
    from hepta import hia_agent_store_native as native
    from hepta.hia_execution_budget_native import NativeExecutionBudgetStore

    class Connection(native.NativeStoreConnection):
        def __init__(self):
            self.lock = RLock()
            self.journal_cost_code = None
            self.in_transaction = False
            self.events = []
            self.failure = None

        def _check_live(self):
            pass

        def _perform(self, specification, values, *, raw_row_limit=None):
            self.events.append((specification, tuple(values), raw_row_limit))
            if self.failure is not None:
                raise self.failure
            return SimpleNamespace(fetchone=lambda: {'created_ns': '23'}, rowcount=1)

        def _transaction_command(self, *, begin=False, commit=False):
            self.events.append(('tx', begin, commit))
            self.in_transaction = begin

    db = Connection()
    store = object.__new__(AgentStore)
    store._native_backend = True
    store.db, store.lock = db, db.lock
    budget = object.__new__(NativeExecutionBudgetStore)
    budget._db = db
    budget.borrowed = True

    def compare(effect, statement, bindings):
        db.events.clear()
        effect()
        typed = list(db.events)
        db.events.clear()
        db.execute(statement, bindings)
        test.assertEqual(typed, db.events)
        test.assertEqual(len(typed), 1)

    lookup = 'SELECT * FROM requests WHERE key=?'
    reserve = 'INSERT INTO requests VALUES (?,?,?,?,?,?)'
    complete = "UPDATE requests SET state='completed',response=? WHERE key=?"
    cost = 'INSERT INTO costs (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)'
    compare(lambda: store.journal_lookup('key'), lookup, ('key',))
    compare(lambda: store.journal_reserve('key', 'digest', 'tool', '13'), reserve,
            ('key', 'digest', 'tool', 'running', None, '13'))
    compare(lambda: store.journal_complete('key', 'body'), complete, ('body', 'key'))
    compare(lambda: store.journal_cost_observed(None, 'tool', 'id', 19, 'rejected', b'detail'), cost,
            (None, 'tool', 'id', '19', 'rejected', 'detail'))
    compare(lambda: test.assertEqual(store.context_created_ns('ctx'), 23),
            'SELECT created_ns FROM contexts WHERE id=?', ('ctx',))
    budget_values = {'attempt_lookup': ('ctx',), 'attempt_set': (3, 'ctx', 2),
                     'wall_budget_lookup': ('ctx',), 'wall_budget_create': ('ctx', '23'),
                     'wall_budget_claim': ('owner', 'ctx', '23'),
                     'wall_budget_finish': ('35', 'ctx', '23', 'owner')}
    for operation, (sql, read) in _BUDGET_PORTS.items():
        values = budget_values.get(operation, ())
        compare(lambda: budget._effect(operation, sql, values, read=read), sql, values)

    for commit in (False, True):
        db.events.clear()
        error = KeyboardInterrupt()
        try:
            with store._native_transaction():
                store.journal_reserve('key', 'digest', 'tool', '13')
                if not commit:
                    raise error
                store.journal_complete('key', 'body')
        except KeyboardInterrupt as caught:
            test.assertIs(caught, error)
        test.assertEqual(db.events[0], ('tx', True, False))
        test.assertEqual(db.events[-1], ('tx', False, commit))
        test.assertEqual(len(db.events), 4 if commit else 3)
        test.assertFalse(db.in_transaction)

    budget.lock = db.lock
    budget.official = db
    budget.check = lambda: None
    db.in_transaction = True
    db.events.clear()
    fenced = []
    state = SimpleNamespace(check=lambda: None, fence=fenced.append)
    with test.assertRaises(Exception) as failure:
        budget._drive_observed(state, None, context_record=None)
    test.assertIn('caller-owned transaction', str(failure.exception))
    test.assertEqual(fenced, [failure.exception])
    test.assertEqual(db.events, [])
    db.in_transaction = False

    for error, refused in ((ValueError('foreign'), True), (native.StoreCommitUnknown('lost'), False)):
        db.failure = error
        observations = []
        delivery = SimpleNamespace(observed=lambda: observations.append('observed'),
                                   foreign_refused=lambda: observations.append('refused'))
        with test.assertRaises(type(error)) as caught:
            budget._observed_effect(delivery, 'attempt_set', _BUDGET_PORTS['attempt_set'][0], (3, 'ctx', 2))
        test.assertIs(caught.exception, error)
        test.assertEqual(observations, ['observed', 'refused'] if refused else ['observed'])
