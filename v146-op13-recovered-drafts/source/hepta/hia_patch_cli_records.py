"""Independent preselection authority for the private CLI patch-result route.

Issuance performs actual PatchResult admission before CLI selection. The CLI
never issues a record and never imports a module to manufacture a witness.
This proves the selected definition domain, not historical module provenance.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import sys
from types import FunctionType, ModuleType
from weakref import ref

from . import hia_inspect_cli_records as _inspect_records

_TYPE = type
_RECORDS = {}
_NEXT_SERIAL = 0
SCHEMA = 'hepta.hia.patch-cli.preselected-definition.v1'


def _require(value, message):
    if not value:
        raise ValueError(message)


class PatchDefinitionRecord:
    """Only the issuer can register a token; same-shaped objects have no grant."""
    __slots__ = ('__weakref__',)

    def __new__(cls, *args, **kwargs):
        raise TypeError('use the explicit patch preselection issuer')


@dataclass(frozen=True, eq=False)
class _AdmittedState:
    serial: int
    module: object
    namespace: object
    apply: object
    interface: object
    admission: object
    owner_class: object
    owner_definitions: object
    owner_apply: object
    owner_interface: object
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
                or dict.get(values, 'builtins') is not self.apply.builtins
                or dict.get(values, '_entry') is not self.entry
                or dict.get(values, '_mapping') is not self.mapping
                or _TYPE(dict.get(values, 'image_sha256')) is not str
                or dict.get(values, 'image_sha256') != self.image_sha256
                or _TYPE(dict.get(values, '_admitted_source_sha256')) is not str
                or dict.get(values, '_admitted_source_sha256') != self.source_sha256
                or dict.get(values, '_import_builtins_match') is not True):
            return False
        definitions = dict.get(values, '_definitions')
        if (definitions is not self.owner_definitions or _TYPE(definitions) is not dict
                or any(_TYPE(key) is not str for key in dict.keys(definitions))
                or dict.get(definitions, 'apply_program_patch') is not self.owner_apply
                or dict.get(definitions, '_check_patch_interface') is not self.owner_interface):
            return False
        methods = self.owner_class.__dict__
        return (all(_TYPE(key) is str for key in methods)
                and self.apply.current(self.apply.function)
                and self.interface.current(self.interface.function)
                and methods.get('invoke_bound_apply') is self.invoke_function
                and self.invoke_function.__code__ is self.invoke_code
                and methods.get('definition_current') is self.guard_function
                and self.guard_function.__code__ is self.guard_code
                and self.guard_function(owner, 'apply_program_patch', self.apply.function)
                and self.guard_function(owner, '_check_patch_interface', self.interface.function))


def _state(record):
    if _TYPE(record) is not PatchDefinitionRecord:
        return None
    entry = _RECORDS.get(id(record))
    return entry[1] if entry is not None and entry[0]() is record else None


def issue_preselected_patch_record(absolute_manifest, *, inspect_manifest=None):
    """Perform real admission, then independently capture the original two bodies.

    The unchanged generated host closure includes the strict code templates,
    including exact-slice constants. No caller-supplied owner or dict is an
    authority. Optional signature admission remains the real component's job.
    Setup imports/mapping/strong references occur here, outside CLI op35/op13.
    """
    global _NEXT_SERIAL
    _require(sys.implementation.name == 'cpython' and sys.version_info[:3] == (3, 14, 4),
             'private patch record requires the specified 3.14.4 ABI')
    from .hia_patch_result_native import PatchAdmission, NativePatchResult, admit_patch_result
    from .hia_patch_result_definitions import Definition, capture_definitions
    admission = admit_patch_result(absolute_manifest, inspect_manifest=inspect_manifest)
    from . import hia_program_tools as selected_module
    _require(_TYPE(admission) is PatchAdmission and _TYPE(admission.owner) is NativePatchResult
             and _TYPE(selected_module) is ModuleType, 'actual patch component admission required')
    namespace = ModuleType.__getattribute__(selected_module, '__dict__')
    _require(_TYPE(namespace) is dict and all(_TYPE(key) is str for key in dict.keys(namespace))
             and admission.owner.namespace is namespace,
             'patch module differs from the independently admitted owner')
    independent = capture_definitions(namespace)
    apply, interface = independent['apply_program_patch'], independent['_check_patch_interface']
    _require(_TYPE(apply) is Definition and _TYPE(interface) is Definition
             and apply.builtins is interface.builtins and apply.builtins is admission.owner.builtins,
             'independent patch definitions or builtins differ')
    definitions = admission.owner._definitions
    _require(_TYPE(definitions) is dict and all(_TYPE(key) is str for key in dict.keys(definitions))
             and set(definitions) == {'apply_program_patch', '_check_patch_interface'},
             'patch owner definition inventory differs')
    for name, expected in (('apply_program_patch', apply), ('_check_patch_interface', interface)):
        actual = dict.get(definitions, name)
        _require(_TYPE(actual) is Definition and actual.function is expected.function
                 and actual.code is expected.code and actual.namespace is expected.namespace
                 and actual.builtins is expected.builtins,
                 'admission differs from independent complete definition capture')
    methods = NativePatchResult.__dict__
    invoke, guard = methods['invoke_bound_apply'], methods['definition_current']
    _require(_TYPE(invoke) is FunctionType and _TYPE(guard) is FunctionType,
             'patch owner invocation methods differ')
    state = _AdmittedState(_NEXT_SERIAL + 1, selected_module, namespace, apply, interface,
        admission, NativePatchResult, definitions, definitions['apply_program_patch'],
        definitions['_check_patch_interface'], invoke, invoke.__code__, guard, guard.__code__,
        sha256(admission.image_raw).hexdigest(), sha256(admission.source_raw).hexdigest(),
        admission.owner._entry, admission.owner._mapping)
    _require(state.current(), 'patch definitions changed during explicit admission')
    token = object.__new__(PatchDefinitionRecord)
    key = id(token)
    def released(reference):
        entry = _RECORDS.get(key)
        if entry is not None and entry[0] is reference:
            del _RECORDS[key]
    _RECORDS[key] = (ref(token, released), state)
    _NEXT_SERIAL += 1
    return token


def selected_record(record):
    state = _state(record)
    return record if state is not None and state.current() else None


def same_preissued_definition_domain(record, inspect_record):
    """Relate two independently issued records, without probing public aliases."""
    patch = _state(record)
    inspect = _inspect_records._state(inspect_record)
    return (patch is not None and inspect is not None
            and patch.module is inspect.module and patch.namespace is inspect.namespace)


def invoke_captured_patch(record, inspect_record, witnessed_record, provider, document, request):
    """Use the unchanged op35 witness; one native route or one captured call.

    The existing inspect closure publishes its token only after the actual
    two imports and successful common.update. No module is read/imported here.
    State is checked after document/request evaluation. A native error is
    never retried through the foreign provider.
    """
    state = _state(record)
    if (state is not None and witnessed_record is inspect_record
            and same_preissued_definition_domain(record, inspect_record)
            and provider is state.apply.function and state.current()):
        return state.invoke_function(state.admission.owner,
            (provider, (provider := None))[0], (document, (document := None))[0],
            (request, (request := None))[0])
    return (provider, (provider := None))[0](
        (document, (document := None))[0], (request, (request := None))[0])


def record_receipt(record):
    """A diagnostic copy is never accepted back as record authority."""
    state = _state(record)
    _require(state is not None, 'unregistered patch definition record')
    admission = state.admission
    return {'schema': SCHEMA, 'serial': state.serial,
        'authority': 'actual-patch-admission-and-independent-complete-definition-templates',
        'manifest_path': admission.manifest_path,
        'manifest_sha256': sha256(admission.manifest_raw).hexdigest(),
        'source_sha256': state.source_sha256, 'image_sha256': state.image_sha256,
        'host_sources': dict(admission.host_sources), 'signature_manifest': admission.signature_manifest,
        'module_identity': id(state.module), 'namespace_identity': id(state.namespace),
        'function_identities': [id(state.apply.function), id(state.interface.function)],
        'code_identities': [id(state.apply.code), id(state.interface.code)],
        'entry_identity': id(state.entry), 'mapping_identity': id(state.mapping),
        'current': state.current(), 'historical_module_provenance': False,
        'current_cold': False, 'default_activated': False}
