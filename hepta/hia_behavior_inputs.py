"""Request-local immutable inputs for complete behavior observations.

The captured bytes grant no authority. Full current admission creates each
execution plan, and every VM invocation has a fresh machine and original limits.
Selected providers keep their public admission path on fresh private snapshots.
"""
from __future__ import annotations

from functools import partial
import os

from . import hia_program as _program
from . import hia_program_runtime as _runtime
from .hia_program_runtime_batch import prepare_reference_execution


def _bindings():
    return (
        _runtime.execute_program, _runtime.verify_program,
        _runtime._execute_verified_program, _runtime._Machine,
        _program.verify_program, _program._verify_program_reference,
        _program.decode_internal_canonical, _program._VERIFIED_ADMISSION.get(),
    )


def _selectors():
    return tuple(sorted((key, value) for key, value in os.environ.items()
                        if key.startswith('HEPTA_HIA_')))


class BehaviorInputs:
    """Own two byte snapshots and the executions admitted from those snapshots."""

    __slots__ = ('_originals', '_sources', '_programs', '_bindings', '_selectors',
                 '_plans', '_ready', '_unchanged', '_unbound_observation')

    def __init__(self, originals, sources):
        if (type(sources) is not tuple or len(sources) != 2
                or any(type(row) is not tuple or len(row) != 2
                       or type(row[0]) is not bytes
                       or row[1] is not None and type(row[1]) is not bytes
                       for row in sources)):
            raise _program.HIAProgramRejected(
                'behavior inputs require immutable byte snapshots', 'E_HIA_INPUT')
        object.__setattr__(self, '_originals', originals)
        object.__setattr__(self, '_sources', sources)
        # These private providers never alias either caller-owned dataclass.
        object.__setattr__(self, '_programs', tuple(
            _program.VerifiedProgram(canonical, structured)
            for canonical, structured in sources))
        object.__setattr__(self, '_bindings', _bindings())
        object.__setattr__(self, '_selectors', _selectors())
        object.__setattr__(self, '_plans', None)
        object.__setattr__(self, '_ready', False)
        object.__setattr__(self, '_unchanged', True)
        object.__setattr__(self, '_unbound_observation', False)
        self.note()

    def __setattr__(self, name, value):
        raise AttributeError('behavior input snapshots are read-only')

    def __delattr__(self, name):
        raise AttributeError('behavior input snapshots are read-only')

    @property
    def sources(self):
        return self._sources

    @property
    def programs(self):
        return self._programs

    def note(self):
        current = _bindings()
        bindings_match = (len(current) == len(self._bindings)
                          and all(left is right for left, right
                                  in zip(current, self._bindings))
                          and _selectors() == self._selectors)
        bytes_match = all(
            type(item.canonical_bytes) is bytes
            and item.canonical_bytes == canonical
            and (item.structured_bytes is None if structured is None else
                 type(item.structured_bytes) is bytes
                 and item.structured_bytes == structured)
            for group in (self._originals, self._programs)
            for item, (canonical, structured) in zip(group, self._sources))
        if not bindings_match or not bytes_match:
            object.__setattr__(self, '_unchanged', False)
        return self._unchanged

    def current(self):
        return self.note() and not self._unbound_observation

    def prepare(self):
        if self._ready:
            return
        plans = []
        for item, (canonical, structured) in zip(self._programs, self._sources):
            plan = prepare_reference_execution(item)
            if plan is None:
                checked = _runtime.verify_program(item)
                if (type(checked) is not _program.VerifiedProgram
                        or checked.canonical_bytes != canonical
                        or checked.structured_bytes != structured):
                    raise _program.HIAProgramRejected(
                        'behavior admission changed its captured input', 'E_HIA_CORE')
            plans.append(plan)
        object.__setattr__(self, '_plans', tuple(plans))
        object.__setattr__(self, '_ready', True)
        self.note()

    def execute(self, index, function, arguments, **limits):
        if not self._ready or type(index) is not int or index not in (0, 1):
            raise _program.HIAProgramRejected(
                'behavior execution has no admitted snapshot', 'E_HIA_INPUT')
        plan = self._plans[index]
        if plan is not None and limits.get('bounded_resource_limits') is None:
            # The plan's parsed graph belongs to the independent verified copy.
            # A later caller mutation never switches this call to that new input.
            return _runtime._execute_verified_program(
                plan._view, function, arguments, **limits)
        canonical, structured = self._sources[index]
        # Preserve every selected authority/decoder/effect on the public route.
        # Its fresh provider owns the original captured bytes, not mutable input.
        return _runtime.execute_program(
            _program.VerifiedProgram(canonical, structured),
            function, arguments, **limits)

    def bound_observation(self, index, observer, case, *, steps, heap=16 * 1024 * 1024):
        self.note()
        try:
            return observer(self._programs[index], case, steps=steps, heap=heap,
                            _execute=partial(self.execute, index))
        finally:
            self.note()

    def unbound_observation(self, index, observer, case, *, steps):
        self.note()
        object.__setattr__(self, '_unbound_observation', True)
        try:
            return observer(self._programs[index], case, steps=steps)
        finally:
            self.note()

    def observation(self, index, observer, reference, case, *, steps, heap=16 * 1024 * 1024):
        if observer is reference:
            return self.bound_observation(index, observer, case, steps=steps, heap=heap)
        return self.unbound_observation(index, observer, case, steps=steps)
