"""Explicit preselection records; the CLI never calls the issuer.

Issuance separately imports and maps the real component. A record establishes
a selected, code-checked namespace; it does not establish historical module
provenance from sys.modules. Passive policy functions below are never called.
"""
from __future__ import annotations
from dataclasses import dataclass
from hashlib import sha256
import sys
from types import CodeType, FunctionType, ModuleType
from weakref import ref

_TYPE = type
_RECORDS = {}
_NEXT_SERIAL = 0
SCHEMA = 'hepta.hia.inspect-cli.preselected-definition.v1'
_CODE_FIELDS = (
    'co_argcount', 'co_posonlyargcount', 'co_kwonlyargcount', 'co_nlocals',
    'co_stacksize', 'co_flags', 'co_code', 'co_names', 'co_varnames',
    'co_freevars', 'co_cellvars', 'co_name', 'co_qualname', 'co_exceptiontable',
)

def _require(value, message):
    if not value:
        raise ValueError(message)

def _constant_equal(left, right):
    if _TYPE(left) is not _TYPE(right):
        return False
    if _TYPE(left) is CodeType:
        return _code_equal(left, right)
    if _TYPE(left) is tuple:
        return (len(left) == len(right)
                and all(_constant_equal(a, b) for a, b in zip(left, right)))
    if left is None or left is Ellipsis:
        return left is right
    if _TYPE(left) in (bool, int, str, bytes):
        return left == right
    return False

def _code_equal(left, right):
    # Only location metadata is excluded. Unknown constant kinds are rejected
    # before their equality protocols could run.
    return (_TYPE(left) is CodeType and _TYPE(right) is CodeType
            and all(_constant_equal(getattr(left, name), getattr(right, name))
                    for name in _CODE_FIELDS)
            and _constant_equal(left.co_consts, right.co_consts))

def _keyword_items_match(value, expected):
    if value is None:
        return not expected
    if _TYPE(value) is not dict or len(value) != len(expected):
        return False
    for (key, item), (wanted, expected_item) in zip(dict.items(value), expected):
        if _TYPE(key) is not str or key != wanted or item is not expected_item:
            return False
    return True

@dataclass(frozen=True, eq=False)
class _Definition:
    function: object
    code: object
    namespace: object
    defaults: object
    kwdefaults: object
    keyword_items: tuple
    builtins: object

    def current(self):
        function = self.function
        return (_TYPE(function) is FunctionType and function.__code__ is self.code
                and function.__globals__ is self.namespace
                and function.__defaults__ is self.defaults
                and function.__kwdefaults__ is self.kwdefaults
                and function.__builtins__ is self.builtins
                and _keyword_items_match(function.__kwdefaults__, self.keyword_items))

class DefinitionRecord:
    """Opaque token. Constructing a lookalike does not register it."""
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs):
        raise TypeError('use the explicit preselection issuer')

@dataclass(frozen=True, eq=False)
class _AdmittedState:
    serial: int
    module: object
    namespace: object
    signature: object
    inspect: object
    admission: object
    owner_class: object
    invoke_function: object
    invoke_code: object
    guard_function: object
    guard_code: object
    image_sha256: str
    source_sha256: str
    entry: object
    mapping: object

    def current(self):
        owner = self.admission.owner
        if _TYPE(owner) is not self.owner_class or _TYPE(self.module) is not ModuleType:
            return False
        values = object.__getattribute__(owner, '__dict__')
        if (_TYPE(values) is not dict or any(_TYPE(key) is not str for key in dict.keys(values))
                or dict.get(values, 'namespace') is not self.namespace
                or dict.get(values, 'builtins') is not self.inspect.builtins
                or dict.get(values, '_entry') is not self.entry
                or dict.get(values, '_mapping') is not self.mapping
                or _TYPE(dict.get(values, 'image_sha256')) is not str
                or dict.get(values, 'image_sha256') != self.image_sha256
                or _TYPE(dict.get(values, '_admitted_source_sha256')) is not str
                or dict.get(values, '_admitted_source_sha256') != self.source_sha256
                or dict.get(values, '_import_builtins_match') is not True):
            return False
        definitions = dict.get(values, '_definitions')
        if (_TYPE(definitions) is not dict
                or any(_TYPE(key) is not str for key in dict.keys(definitions))):
            return False
        for name, saved in (('function_signature', self.signature), ('inspect_program', self.inspect)):
            entry = dict.get(definitions, name)
            if (_TYPE(entry) is not tuple or len(entry) != 6
                    or entry[0] is not saved.function or entry[1] is not saved.code
                    or entry[2] is not saved.defaults or entry[3] is not saved.kwdefaults
                    or entry[5] is not saved.builtins or _TYPE(entry[4]) is not tuple
                    or len(entry[4]) != len(saved.keyword_items)):
                return False
            for item, expected in zip(entry[4], saved.keyword_items):
                if (_TYPE(item) is not tuple or len(item) != 2
                        or _TYPE(item[0]) is not str or item[0] != expected[0]
                        or item[1] is not expected[1]):
                    return False
        methods = self.owner_class.__dict__
        return (all(_TYPE(key) is str for key in methods)
                and self.signature.current() and self.inspect.current()
                and methods.get('invoke_bound_inspect') is self.invoke_function
                and self.invoke_function.__code__ is self.invoke_code
                and methods.get('definition_current') is self.guard_function
                and self.guard_function.__code__ is self.guard_code
                and self.guard_function(owner, 'inspect_program', self.inspect.function)
                and self.guard_function(owner, 'function_signature', self.signature.function))

def _state(record):
    if _TYPE(record) is not DefinitionRecord:
        return None
    entry = _RECORDS.get(id(record))
    return entry[1] if entry is not None and entry[0]() is record else None

def _capture_definition(function, namespace, expected_code, keyword_items):
    _require(_TYPE(function) is FunctionType and function.__globals__ is namespace
             and function.__closure__ is None and function.__defaults__ is None
             and _TYPE(function.__builtins__) is dict
             and _keyword_items_match(function.__kwdefaults__, keyword_items)
             and _code_equal(function.__code__, expected_code),
             'selected function is not the frozen policy definition')
    return _Definition(function, function.__code__, namespace, function.__defaults__,
                       function.__kwdefaults__, keyword_items, function.__builtins__)

def issue_preselected_inspect_record(absolute_manifest):
    """Explicit setup, before selection. Performs real native image admission.

    The independent code templates and the admitted component's complete host
    bytes are the definition authority. Module/anchor shape alone is not.
    This operation has imports, mapping, metadata calls and strong references;
    it is not part of op35 and must be recorded separately by a qualifier.
    """
    global _NEXT_SERIAL
    _require(sys.implementation.name == 'cpython' and sys.version_info[:3] == (3, 14, 4),
             'private definition record requires the specified 3.14.4 ABI')
    from .hia_inspect_program_native import (
        InspectAdmission, NativeInspectProgram, admit_inspect_program,
    )
    admission = admit_inspect_program(absolute_manifest)
    from . import hia_program_tools as selected_module
    _require(_TYPE(admission) is InspectAdmission
             and _TYPE(admission.owner) is NativeInspectProgram
             and _TYPE(selected_module) is ModuleType, 'real component admission required')
    namespace = ModuleType.__getattribute__(selected_module, '__dict__')
    _require(_TYPE(namespace) is dict
             and all(_TYPE(key) is str for key in dict.keys(namespace))
             and admission.owner.namespace is namespace,
             'selected module differs from the independently admitted owner')
    signature = _capture_definition(dict.get(namespace, 'function_signature'), namespace,
                                    _FROZEN_POLICY_CODES[0], (('include_return_loans', False),))
    inspect = _capture_definition(dict.get(namespace, 'inspect_program'), namespace,
                                  _FROZEN_POLICY_CODES[1], ())
    _require(signature.builtins is inspect.builtins
             and signature.builtins is admission.owner.builtins,
             'function builtin mappings differ from the admitted owner')
    methods = NativeInspectProgram.__dict__
    invoke, guard = methods['invoke_bound_inspect'], methods['definition_current']
    _require(_TYPE(invoke) is FunctionType and _TYPE(guard) is FunctionType,
             'inspect owner methods changed')
    state = _AdmittedState(_NEXT_SERIAL + 1, selected_module, namespace,
                           signature, inspect, admission, NativeInspectProgram,
                           invoke, invoke.__code__, guard, guard.__code__,
                           sha256(admission.image_raw).hexdigest(),
                           sha256(admission.source_raw).hexdigest(),
                           admission.owner._entry, admission.owner._mapping)
    _require(state.current(), 'definitions changed during explicit admission')
    token = object.__new__(DefinitionRecord)
    key = id(token)
    def released(reference):
        entry = _RECORDS.get(key)
        if entry is not None and entry[0] is reference:
            del _RECORDS[key]
    _RECORDS[key] = (ref(token, released), state)
    _NEXT_SERIAL += 1
    return token

def selected_record(record):
    """Consume an existing token; no import, mapping, or token issuance."""
    state = _state(record)
    return record if state is not None and state.current() else None

def imported_operand_matches(record, operand):
    """The actual operand is evidence of selection, not a source of authority.

    In particular this performs no module attribute, alias or sys.modules
    lookup. A same-shaped or code-equivalent replacement module is refused.
    """
    state = _state(record)
    return (state is not None and _TYPE(operand) is ModuleType
            and operand is state.module)

def invoke_captured_inspect(record, witnessed_record, provider, document):
    """Exactly one route. Never retry a native entry or exception as foreign."""
    state = _state(record)
    if (state is not None and witnessed_record is record
            and provider is state.inspect.function and state.current()):
        return state.invoke_function(state.admission.owner,
            (provider, (provider := None))[0], (document, (document := None))[0])
    return (provider, (provider := None))[0]((document, (document := None))[0])

def record_receipt(record):
    """Diagnostic copy, never accepted back as an authority token."""
    state = _state(record)
    _require(state is not None, 'unregistered inspect definition record')
    admission = state.admission
    return {
        'schema': SCHEMA, 'serial': state.serial,
        'authority': 'explicit-preselection-component-and-independent-code-templates',
        'manifest_path': admission.manifest_path,
        'manifest_sha256': sha256(admission.manifest_raw).hexdigest(),
        'source_sha256': sha256(admission.source_raw).hexdigest(),
        'image_sha256': sha256(admission.image_raw).hexdigest(),
        'host_sources': dict(admission.host_sources),
        'current': state.current(),
        'module_identity': id(state.module), 'namespace_identity': id(state.namespace),
        'function_identities': [id(state.signature.function), id(state.inspect.function)],
        'code_identities': [id(state.signature.code), id(state.inspect.code)],
        'builtins_identity': id(state.inspect.builtins),
        'historical_module_provenance': False, 'cold_qualification': False,
    }

# PASSIVE_FROZEN_POLICIES: appended mechanically from the two original bodies.


def function_signature(function, *, include_return_loans=False):
    """Detached presentation/interface view of an already verified function."""
    result = {key: copy.deepcopy(function[key]) for key in ("name", "params", "returns", "effects")}
    if include_return_loans:
        result["return_loans"] = copy.deepcopy(function.get("return_loans", [None] * len(function["returns"])))
    return result

def inspect_program(document):
    from .hia_program import verify_program
    verified = verify_program(document)
    data = verified.as_dict()
    return {
        "schema": ("hepta.hia.inspect.v2" if data["schema"] == "hepta.hia.program.v8"
                   else "hepta.hia.inspect.v1"), "ok": True,
        "program_sha256": verified.sha256, "module": data["module"],
        "input_sha256": getattr(verified, "input_sha256", verified.sha256),
        "normalization": getattr(verified, "normalization_report", None),
        "functions": [{
            **function_signature(fn, include_return_loans=data["schema"] == "hepta.hia.program.v8"),
            "blocks": [{"id": block["id"], "params": block["params"],
                        "operations": [{"index": index, **operation}
                                       for index, operation in enumerate(block["ops"])],
                        "term": block["term"]} for block in fn["blocks"]],
        } for fn in data["functions"]],
        "claims": {"native_executed": False, "whole_language_soundness_proved": False},
    }

_FROZEN_POLICY_CODES = (function_signature.__code__, inspect_program.__code__)
