"""Original execution-budget reference and explicitly selected native owner.

The hosted reference remains independent for qualification. Selection is latched
for an AgentStore lifetime; a native failure never falls back to this reference.
"""
from __future__ import annotations


def admitted_execution_budget():
    from .hia_execution_budget_native import selected_execution_budget
    return selected_execution_budget()


def execution_budget_store(store, admission):
    if admission is None:
        return _ReferenceExecutionBudgetStore(store)
    from .hia_execution_budget_native import NativeExecutionBudgetStore
    return NativeExecutionBudgetStore(store, admission)


class _ReferenceExecutionBudgetStore:
    def __init__(self, store):
        self.store = store

    def create(self, context):
        self.store.db.execute("INSERT INTO execution_budgets VALUES (?,'0',NULL)", (context,))

    def claim(self, context, owner, maximum, started):
        from .hia_agent_store import reject
        with self.store.transaction():
            row = self.store.db.execute('SELECT * FROM execution_budgets WHERE context_id=?', (context,)).fetchone()
            if row is None:
                reject('E_HIA_BUDGET', 'context lacks an execution budget record', 'execution')
            if row['owner'] is not None:
                reject('E_HIA_BUDGET_BUSY', 'context native budget has a live or uncertain owner; observe that operation',
                       'execution', retry_action='stop')
            used = int(row['used_native_ns'])
            self.store.db.execute('UPDATE execution_budgets SET owner=? WHERE context_id=?', (owner, context))
        return _ReferenceBudgetClaim(self.store, context, owner, used, maximum, started)

    def observe(self, context):
        row = self.store.db.execute('SELECT * FROM execution_budgets WHERE context_id=?', (context,)).fetchone()
        return {'context_id': context, 'record_exists': row is not None,
                'used_native_ns': None if row is None else row['used_native_ns'],
                'owner': None if row is None else row['owner'],
                'historical_completion_receipt': False, 'execution_authority_granted': False}

    def close(self):
        pass


class _ReferenceBudgetClaim:
    def __init__(self, store, context, owner, used, maximum, started):
        self.store, self.context, self.owner = store, context, owner
        self.used, self.native_ns, self.started = used, 0, started
        self.remaining = max(0, maximum - used // 1_000_000)

    def run(self, runner, *args, now, total_ms, **kwargs):
        remaining = min(self.remaining - (now - self.started) // 1_000_000, total_ms)
        outcome = runner(*args, timeout_ms=int(remaining), **kwargs)
        self.native_ns += int(outcome['wall_ns'])
        return outcome

    def complete(self):
        self.store.db.execute('UPDATE execution_budgets SET owner=NULL,used_native_ns=? WHERE context_id=? AND owner=?',
            (str(self.used + self.native_ns), self.context, self.owner))
