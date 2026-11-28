"""Request-local preparation for repeated independent scalar VM observations.

Only a fresh full verification can create a plan. The plan owns immutable Core
metadata, while every invocation uses the original runtime's fresh machine and
argument, tick, resource, trap and return checks. No plan is accepted by the
public execute_program boundary, and none is shared between requests.
"""
from __future__ import annotations

import os

from . import hia_program as _program
from . import hia_program_runtime as _runtime
from .hia_program_runtime_prepared import _ordinary_default_program, prepare_runtime_program

_EXECUTE = _runtime.execute_program
_VERIFY = _runtime.verify_program
_PUBLIC_VERIFY = _program.verify_program
_REFERENCE_VERIFY = _program._verify_program_reference
_MACHINE = _runtime._Machine
_PROGRAM_PROPERTIES = tuple((name, vars(_program.VerifiedProgram)[name])
    for name in ('scalar_entrypoints', 'sha256', 'input_sha256'))


def _ordinary_reference(program):
    return (_ordinary_default_program(program)
        and _runtime.execute_program is _EXECUTE
        and _runtime.verify_program is _VERIFY
        and _program.verify_program is _PUBLIC_VERIFY
        and _program._verify_program_reference is _REFERENCE_VERIFY
        and _runtime._Machine is _MACHINE
        and all(vars(_program.VerifiedProgram).get(name) is value
                for name, value in _PROGRAM_PROPERTIES)
        and _program._VERIFIED_ADMISSION.get() is None
        and not any(name.startswith('HEPTA_HIA_') for name in os.environ))


class _ScalarExecutionView:
    __slots__ = ('_metadata', '_entries')

    def __init__(self, metadata, entries):
        object.__setattr__(self, '_metadata', metadata)
        object.__setattr__(self, '_entries', entries)

    def __setattr__(self, name, value):
        raise AttributeError('prepared scalar metadata is read-only')

    def __delattr__(self, name):
        raise AttributeError('prepared scalar metadata is read-only')

    def as_dict(self):
        return self._metadata.as_dict()

    @property
    def scalar_entrypoints(self):
        return self._entries

    @property
    def sha256(self):
        return self._metadata.sha256

    @property
    def input_sha256(self):
        return self._metadata.input_sha256


class _ReferenceExecution:
    __slots__ = ('_program', '_canonical', '_structured', '_view')

    def __init__(self, program, canonical, structured, view):
        object.__setattr__(self, '_program', program)
        object.__setattr__(self, '_canonical', canonical)
        object.__setattr__(self, '_structured', structured)
        object.__setattr__(self, '_view', view)

    def __setattr__(self, name, value):
        raise AttributeError('prepared scalar execution is read-only')

    def __delattr__(self, name):
        raise AttributeError('prepared scalar execution is read-only')

    def current(self):
        return (_ordinary_reference(self._program)
            and self._program.canonical_bytes == self._canonical
            and self._program.structured_bytes == self._structured)

    def __call__(self, function, arguments, **limits):
        if not self.current() or limits.get('bounded_resource_limits') is not None:
            return _runtime.execute_program(self._program, function, arguments, **limits)
        return _runtime._execute_verified_program(self._view, function, arguments, **limits)


def prepare_reference_execution(program):
    """Return a local executor or None when the original dynamic path is needed.

    A VerifiedProgram constructor is not admission. Its current complete bytes
    are fully reverified here. A selected authority, changed decoder, custom
    program or later changed byte binding uses the ordinary public path.
    """
    if not _ordinary_reference(program):
        return None
    canonical, structured = program.canonical_bytes, program.structured_bytes
    checked = _VERIFY(program)
    metadata = prepare_runtime_program(checked)
    view = _ScalarExecutionView(metadata, checked.scalar_entrypoints)
    prepared = _ReferenceExecution(program, canonical, structured, view)
    return prepared if prepared.current() else None
