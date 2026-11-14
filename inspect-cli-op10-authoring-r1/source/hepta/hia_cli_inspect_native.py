"""Private, explicitly selected report+inspect CLI adapter.

The original report/discovery/parser entry remains the parent. Only op35's
actual import operands and op10's already captured provider are adapted.
This module never issues an inspect record or imports program-tools early.
"""
from __future__ import annotations
from types import CodeType, FunctionType
from weakref import ref, ReferenceType

from .hia_cli_native import CliSession
from .hia_cli_verified_report_native import NativeReportCli
from .hia_inspect_cli_operand import Import35Port
from .hia_inspect_cli_records import (
    selected_record, imported_operand_matches, invoke_captured_inspect,
)

_TYPE = type
_SESSION = CliSession
_EFFECT = CliSession._effect
_EFFECT_CODE = _EFFECT.__code__
_REPORT_PREPARE = NativeReportCli.prepare
_REPORT_PREPARE_CODE = _REPORT_PREPARE.__code__
_REPORT_GLOBALS = _REPORT_PREPARE.__globals__
_REPORT_EFFECT_CODES = tuple(value for value in _REPORT_PREPARE_CODE.co_consts
    if _TYPE(value) is CodeType and value.co_name == 'report_effect')


def _report_closure(current, session, owner):
    if (_TYPE(current) is not FunctionType or len(_REPORT_EFFECT_CODES) != 1
            or current.__code__ is not _REPORT_EFFECT_CODES[0]
            or current.__globals__ is not _REPORT_GLOBALS
            or _REPORT_GLOBALS.get('_ORIGINAL_EFFECT') is not _EFFECT
            or current.__code__.co_freevars != ('held_session', 'report_owner')
            or current.__closure__ is None or len(current.__closure__) != 2):
        return False
    held, report_owner = (cell.cell_contents for cell in current.__closure__)
    return _TYPE(held) is ReferenceType and held() is session and report_owner is owner


class NativeInspectReportCli(NativeReportCli):
    def __init__(self, report_cli, record, port):
        # These are the exact six already admitted owners, not substitutes.
        super().__init__(report_cli, report_cli.discovery, report_cli.routing,
                         report_cli.parser_context, report_cli.verified_report)
        self._inspect_record = record
        self._inspect_import35 = port

    def prepare(self, argv, cli):
        session = super().prepare(argv, cli)
        record = self._inspect_record
        port = self._inspect_import35
        if (_TYPE(session) is not _SESSION or not port.current()
                or NativeReportCli.prepare is not _REPORT_PREPARE
                or _REPORT_PREPARE.__code__ is not _REPORT_PREPARE_CODE
                or _SESSION.__dict__.get('_effect') is not _EFFECT
                or _EFFECT.__code__ is not _EFFECT_CODE):
            return session
        previous = session.__dict__.get('_effect')
        if not _report_closure(previous, session, self.verified_report):
            return session
        held_session = ref(session)
        witnessed_record = None

        def inspect_effect(operation, a, b, c, d):
            nonlocal witnessed_record
            # Preserve the actual existing report closure for op9 and every
            # other operation. No extra session or provider lookup there.
            if _TYPE(operation) is not int or operation not in (10, 35):
                return previous(operation, a, b, c, d)
            current = held_session()
            if current is None or not port.current():
                return previous(operation, a, b, c, d)
            # Exact original effect prefix, including two permission reads.
            if current.discovery_permission is not None:
                return current.discovery_permission.consume_legacy_port(current, operation, a, b, c, d)
            value, register, field, argument = current.value, current.register, current.field, current.argument
            zero = (0, 0, 0)
            if operation == 10:
                # The provider lookup precedes argument evaluation, exactly
                # as in self.common['inspect_program'](value(a)).
                provider = current.common['inspect_program']
                # Transfer the selected provider onto the call stack before
                # document evaluation. The witness belongs to this selection;
                # definition state is still checked after argument evaluation.
                result = invoke_captured_inspect(record, witnessed_record,
                    (provider, (provider := None))[0], value(a))
                return register(result), 0, 0
            carrier = port.entry(current, operation, a, b, c, d,
                                 value, register, field, argument, zero)
            (verify_program, read_bounded, decode_json, inspect_program,
             apply_program_patch, publish_program, operand) = carrier
            carrier = None
            matched = imported_operand_matches(record, operand)
            # No extra attribute read. Release the foreign operand before
            # the original common.update expression and any of its effects.
            operand = None
            current.common.update(verify_program=verify_program, read_bounded=read_bounded,
                                  decode_json=decode_json, inspect_program=inspect_program,
                                  apply_program_patch=apply_program_patch, publish_program=publish_program)
            # A failed or reentrant update never publishes an early witness.
            witnessed_record = record if matched else None
            return zero

        # Only weak session retention, as in the existing report closure.
        session._effect = inspect_effect
        return session


def select_inspect_report_cli(report_cli, definition_record=None):
    """Select with a token issued earlier; absence never creates authority.

    Invalid/unknown/stale records keep the original report CLI. The positive
    path retains its six actual image owners and adds the admitted inspect
    owner. A future qualifier must assert this class and actual HIA entries;
    returning the original CLI is not proof of native inspect activation.
    """
    record = selected_record(definition_record)
    if record is None or _TYPE(report_cli) is not NativeReportCli:
        return report_cli
    if (_SESSION.__dict__.get('_effect') is not _EFFECT
            or _EFFECT.__code__ is not _EFFECT_CODE
            or NativeReportCli.prepare is not _REPORT_PREPARE
            or _REPORT_PREPARE.__code__ is not _REPORT_PREPARE_CODE):
        return report_cli
    try:
        port = Import35Port(_EFFECT)
    except ValueError:
        # Unsupported bytecode/frame ABI is a non-admission, not a failed
        # native entry. No product call has occurred here.
        return report_cli
    return NativeInspectReportCli(report_cli, record, port)


def installed_bundle(path, raw, bundle, *, definition_record=None, strict=False):
    """Explicit private selection over the actual unchanged six-image loader.

    Pass the caller's already captured manifest path/raw/object unchanged.
    No new inspect manifest is read here; its real admission is in the token.
    This function is not installed into the ordinary default selector.
    """
    from .hia_cli_verified_report_native import installed_bundle as load_report
    report_cli = load_report(path, raw, bundle, strict=strict)
    return select_inspect_report_cli(report_cli, definition_record)
