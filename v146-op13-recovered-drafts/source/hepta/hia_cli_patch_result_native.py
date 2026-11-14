"""Explicit op13 extension over the unchanged R5 inspect/report CLI closure.

The parent still performs op35 and op10 in its original frames. This adapter
reads its fixed witness cell; it adds no IMPORT_NAME/IMPORT_FROM or alias read.
The private domain requires the original selected Inspect CLI and a separate
PatchResult record. Ordinary/default CLI selection is not changed.
"""
from __future__ import annotations

from types import CellType, CodeType, FunctionType
from weakref import ref, ReferenceType

from . import hia_cli_inspect_native as _inspect_adapter
from . import hia_inspect_cli_records as _inspect_records
from .hia_inspect_cli_operand import Import35Port
from .hia_patch_cli_records import (
    selected_record, same_preissued_definition_domain, invoke_captured_patch,
)

_TYPE = type
_BASE = _inspect_adapter.NativeInspectReportCli
_PREPARE = _BASE.prepare
_PREPARE_CODE = _PREPARE.__code__
_GLOBALS = _PREPARE.__globals__
_EFFECT_CODES = tuple(value for value in _PREPARE_CODE.co_consts
                      if _TYPE(value) is CodeType and value.co_name == 'inspect_effect')
_SESSION = _inspect_adapter._SESSION
_EFFECT = _inspect_adapter._EFFECT
_EFFECT_CODE = _EFFECT.__code__
_REPORT_CLOSURE = _inspect_adapter._report_closure
_REPORT_CLOSURE_CODE = _REPORT_CLOSURE.__code__
_FREEVARS = ('held_session', 'port', 'previous', 'record', 'witnessed_record')


def _original_boundaries_current():
    return (_BASE.__dict__.get('prepare') is _PREPARE
            and _PREPARE.__code__ is _PREPARE_CODE
            and _SESSION.__dict__.get('_effect') is _EFFECT
            and _EFFECT.__code__ is _EFFECT_CODE
            and _inspect_adapter._report_closure is _REPORT_CLOSURE
            and _REPORT_CLOSURE.__code__ is _REPORT_CLOSURE_CODE)


def _witness_cell(effect, session, report_owner, record, port):
    """Validate the actual original closure, not a self-reported namespace."""
    if (_TYPE(effect) is not FunctionType or len(_EFFECT_CODES) != 1
            or effect.__code__ is not _EFFECT_CODES[0] or effect.__globals__ is not _GLOBALS
            or effect.__defaults__ is not None or effect.__kwdefaults__ is not None
            or effect.__code__.co_freevars != _FREEVARS or effect.__closure__ is None
            or len(effect.__closure__) != len(_FREEVARS)
            or any(_TYPE(cell) is not CellType for cell in effect.__closure__)
            or _TYPE(port) is not Import35Port or not port.current()):
        return None
    held_cell, port_cell, previous_cell, record_cell, witness = effect.__closure__
    try:
        held = held_cell.cell_contents
        if (_TYPE(held) is not ReferenceType or held() is not session
                or port_cell.cell_contents is not port or record_cell.cell_contents is not record
                or not _REPORT_CLOSURE(previous_cell.cell_contents, session, report_owner)):
            return None
        witness.cell_contents
    except ValueError:
        return None
    return witness


class NativePatchInspectReportCli(_BASE):
    def __init__(self, inspect_cli, patch_record):
        super().__init__(inspect_cli, inspect_cli._inspect_record, inspect_cli._inspect_import35)
        self._patch_record = patch_record

    def prepare(self, argv, cli):
        # The actual R5 method creates its actual report+inspect closure.
        # No op35/op10 body or bytecode is reimplemented by this component.
        session = super().prepare(argv, cli)
        if _TYPE(session) is not _SESSION or not _original_boundaries_current():
            return session
        previous = session.__dict__.get('_effect')
        inspect_record, port = self._inspect_record, self._inspect_import35
        witness = _witness_cell(previous, session, self.verified_report, inspect_record, port)
        if witness is None:
            return session
        patch_record = self._patch_record
        held_session = ref(session)
        report_owner = self.verified_report

        def patch_effect(operation, a, b, c, d):
            if _TYPE(operation) is not int or operation != 13:
                return previous(operation, a, b, c, d)
            current = held_session()
            if (current is None or not _original_boundaries_current()
                    or _witness_cell(previous, current, report_owner, inspect_record, port) is not witness):
                return previous(operation, a, b, c, d)
            # The old report closure is kept as the real delegate, including
            # public provider and permission behavior on every other route.
            if current.discovery_permission is not None:
                return current.discovery_permission.consume_legacy_port(current, operation, a, b, c, d)
            value, register, field, argument = current.value, current.register, current.field, current.argument
            zero = (0, 0, 0)
            # Original public observation order: provider, document, request.
            # Witness selection precedes arguments; definition guards follow
            # both evaluations inside invoke_captured_patch.
            provider = current.common['apply_program_patch']
            revised, receipt = invoke_captured_patch(patch_record, inspect_record,
                witness.cell_contents, (provider, (provider := None))[0], value(a), argument(b, 1))
            return register(revised), register(receipt), 0

        session._effect = patch_effect
        return session


def select_patch_inspect_cli(inspect_cli, definition_record=None):
    """No issuance, mapping, provider lookup or import witness is fabricated."""
    record = selected_record(definition_record)
    if record is None or _TYPE(inspect_cli) is not _BASE or not _original_boundaries_current():
        return inspect_cli
    inspect_record = inspect_cli._inspect_record
    if (_inspect_records.selected_record(inspect_record) is not inspect_record
            or not same_preissued_definition_domain(record, inspect_record)
            or _TYPE(inspect_cli._inspect_import35) is not Import35Port
            or not inspect_cli._inspect_import35.current()):
        return inspect_cli
    return NativePatchInspectReportCli(inspect_cli, record)


def installed_bundle(path, raw, bundle, *, inspect_definition_record=None,
                     patch_definition_record=None, strict=False):
    """Explicit private loader. It preserves the real six-image loader chain."""
    inspect_cli = _inspect_adapter.installed_bundle(path, raw, bundle,
        definition_record=inspect_definition_record, strict=strict)
    return select_patch_inspect_cli(inspect_cli, patch_definition_record)
