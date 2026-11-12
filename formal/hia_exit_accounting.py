"""Independent mathematical ledger model for finite HIA exit observations.

This module deliberately imports no production verifier or runtime. Integers
are mathematical, and the model abstracts object/loan identities to counts.
Each preservation query is induction over one guarded ledger event, not an
enumeration of finitely many sample states and not a compiler refinement proof.
"""
from dataclasses import dataclass, replace

import z3


@dataclass(frozen=True)
class Ledger:
    attempts: object
    allocated: object
    freed: object
    created: object
    dropped: object
    live: object
    bytes: object
    peak: object
    started: object
    ended: object
    loans: object

    @classmethod
    def symbolic(cls, prefix):
        return cls(*(z3.Int(prefix + "_" + field) for field in cls.__dataclass_fields__))

    def values(self):
        return tuple(getattr(self, field) for field in self.__dataclass_fields__)


def invariant(state, heap):
    n = state.allocated - state.freed
    return z3.And(*(value >= 0 for value in state.values()),
        state.freed <= state.allocated, state.allocated <= state.attempts,
        state.allocated <= state.created, state.freed <= state.dropped,
        state.dropped <= state.created, state.live == state.created - state.dropped,
        n <= state.live, n <= state.bytes, (n == 0) == (state.bytes == 0),
        state.ended <= state.started, state.loans == state.started - state.ended,
        z3.Implies(state.loans > 0, state.live > 0), state.bytes <= state.peak,
        state.peak <= heap)


def return_guard(state):
    return z3.And(state.live == 0, state.loans == 0)


def balanced(state):
    return z3.And(state.allocated == state.freed, state.created == state.dropped,
                  state.started == state.ended, state.bytes == 0)


def event_cases(state, heap, size):
    """Guards describe count projections of admitted sequential byte events.

    Removing an owner must not leave loans without any owner. This aggregate
    guard is weaker than proving which owner each loan belongs to; neither
    alias safety nor precise per-owner exclusion is established by this model.
    """
    n = state.allocated - state.freed
    owner_can_leave = z3.Or(state.live > 1, state.loans == 0)
    return (
        ("empty_owner", z3.BoolVal(True),
         replace(state, created=state.created + 1, live=state.live + 1)),
        ("payload_allocation", z3.And(size > 0, state.bytes + size <= heap),
         replace(state, attempts=state.attempts + 1, allocated=state.allocated + 1,
                 created=state.created + 1, live=state.live + 1, bytes=state.bytes + size,
                 peak=z3.If(state.peak >= state.bytes + size, state.peak, state.bytes + size))),
        ("fallible_allocation_failure", z3.BoolVal(True),
         replace(state, attempts=state.attempts + 1, created=state.created + 1, live=state.live + 1)),
        ("infallible_allocation_trap", z3.BoolVal(True),
         replace(state, attempts=state.attempts + 1)),
        ("drop_empty", z3.And(state.live > n, owner_can_leave),
         replace(state, dropped=state.dropped + 1, live=state.live - 1)),
        ("drop_payload", z3.And(n > 0, size > 0, state.bytes - size >= n - 1,
                               (n == 1) == (state.bytes == size), owner_can_leave),
         replace(state, freed=state.freed + 1, dropped=state.dropped + 1,
                 live=state.live - 1, bytes=state.bytes - size)),
        ("borrow", state.live > 0,
         replace(state, started=state.started + 1, loans=state.loans + 1)),
        ("end_loan", state.loans > 0,
         replace(state, ended=state.ended + 1, loans=state.loans - 1)),
        ("scalar_or_control_step", z3.BoolVal(True), state),
        ("program_trap_stop", z3.BoolVal(True), state),
        ("evaluator_quota_stop", z3.BoolVal(True), state),
    )


def obligations():
    state, heap, size = Ledger.symbolic("pre"), z3.Int("heap"), z3.Int("size")
    good = invariant(state, heap)
    zero = Ledger(*(z3.IntVal(0) for _ in Ledger.__dataclass_fields__))
    result = [("initial_state", heap >= 0, invariant(zero, heap))]
    result.extend((name, z3.And(good, guard), invariant(after, heap))
                  for name, guard, after in event_cases(state, heap, size))
    # Normal errors and cooperative cancellation use the very same scalar
    # return guard, after explicit source-level release operations.
    for name in ("normal_return", "error_value_return", "cooperative_cancel_return"):
        result.append((name, z3.And(good, return_guard(state)), balanced(state)))
    return state, heap, size, result


def negative_controls(state, heap):
    good = invariant(state, heap)
    return (
        ("borrow_without_live_loan_increment", z3.And(good, state.live > 0),
         invariant(replace(state, started=state.started + 1), heap)),
        ("trap_erases_retained_payload", z3.And(good, state.bytes > 0),
         invariant(replace(state, bytes=z3.IntVal(0)), heap)),
        ("drop_last_borrowed_owner", z3.And(good, state.live == 1,
                                           state.loans > 0, state.bytes == 0),
         invariant(replace(state, dropped=state.dropped + 1, live=z3.IntVal(0)), heap)),
        ("return_without_release_guard", good, balanced(state)),
    )
