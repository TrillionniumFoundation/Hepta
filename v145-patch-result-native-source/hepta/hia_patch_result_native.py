"""Explicit HIA patch-result and interface policies over actual providers.

The original public functions, patch byte engines and default callers are not
changed. Admission establishes the current two-function definition domain,
not historical namespace provenance, current cold or whole-runtime closure.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
from types import FunctionType

from .hia_front_runtime import NativeFrontImage, FrontFrame, FrontUnknown
from .hia_front_continuation import _Cell
from .hia_patch_result_definitions import capture_definitions

SCHEMA = 'hepta.hia.patch-result-native.v1'
ARITIES = {'_check_patch_interface': 3, 'apply_program_patch': 2}
SOURCE_NAME = 'patch_result.hepta'
IMAGE_NAME = 'patch-result.image.bin'
CAPACITY = 1048576
HOST_SOURCE_FILES = (
    'hia_program_tools.py', 'hia_program.py', 'hia_schema.py', 'hia_opcodes.py',
    'hia_front_runtime.py', 'hia_front_continuation.py', 'hia_exception_delivery.py',
    'hia_json_preflight_native.py', 'hia_machine_transport.py', 'hia_optional_profiles.py',
    'hia_patch_result_definitions.py', 'hia_patch_result_native.py', 'hia_patch_result_ports.py',
)
_TYPE = type
_UNCONFIRMED_ADMISSIONS = []


class PatchResultFrame(FrontFrame):
    # Construction remains inherited: no extra argument-retaining frame.
    _machine_busy = False

    def _require_machine_idle(self):
        if self._machine_busy is not False:
            raise FrontUnknown('patch machine entry is already active')

    def _invoke(self, command, flag=0, error=0, op=0):
        self._require_machine_idle()
        self._machine_busy = True
        try:
            return super()._invoke(command, flag, error, op)
        finally:
            self._machine_busy = False

    def step(self):
        self._require_machine_idle()
        return super().step()

    def service(self, issued):
        self._require_machine_idle()
        return super().service(issued)

    def drive(self):
        self._require_machine_idle()
        if self.pending is not None and not self.executed:
            self.service(self.pending)
        return super().drive()

    def take(self, *, yielded=False):
        self._require_machine_idle()
        return super().take(yielded=yielded)

    def close(self, *, release=True):
        self._require_machine_idle()
        return super().close(release=release)

    def _retire(self):
        self._require_machine_idle()
        return super()._retire()

    def _effect(self):
        op, destinations, args, raw, vector = self._parts()
        if op == 13 and raw == (4,):
            if len(destinations) != 4 or len(args) != 1 or vector:
                raise FrontUnknown('patch four-result unpack representation differs')
            # Actual UNPACK_SEQUENCE semantics, including the fifth probe and
            # its exact exception, precede all local assignment permissions.
            first, second, third, fourth = self._get(args[0])
            result = (first, second, third, fourth)
            first = second = third = fourth = None
            for index, destination in enumerate(destinations):
                self._set(destination, result[index])
            result = None
            return 0
        return super()._effect()

    def _global_in(self, name, group):
        if _TYPE(group) is not int or group != 0:
            raise FrontUnknown('public-front global namespace differs')
        namespace = self.image.namespace
        if name in namespace:
            value = namespace[name]
            if name == 'function_signature':
                binding = self.image._signature
                if binding is not None and binding.current(value):
                    return self.image._signature_helper
            helper = self.image._helpers.get(name)
            if helper is not None and self.image.definition_current(name, value):
                return helper
            return value
        if name in self.image.builtins:
            return self.image.builtins[name]
        raise NameError("name '" + name + "' is not defined", name=name)

    def _function(self, args, raw, vector):
        mode, generator = raw
        captures = tuple(self.values[slot] for slot in vector)
        if any(_TYPE(cell) is not _Cell for cell in captures):
            raise FrontUnknown('public-front closure captured a non-cell')
        if generator == 1 and len(args) == 1:
            frame = PatchResultFrame(self.image, mode, (self._get(args[0]),), captures,
                                     witness=self.witness)
            def native_generator():
                value = None
                try:
                    while True:
                        value = None
                        if frame.drive() == 0:
                            return
                        value = frame.take(yielded=True)
                        yield value
                finally:
                    value = None
            return native_generator()
        raise FrontUnknown('public-front closure shape is outside its frozen inventory')


@dataclass(frozen=True, eq=False)
class _AdmittedSignature:
    admission: object
    owner_class: object
    provider: object
    namespace: object
    entry: object
    mapping: object
    definition: object
    invoke: object
    invoke_code: object
    guard: object
    guard_code: object

    def current(self, provider):
        owner = self.admission.owner
        if provider is not self.provider or _TYPE(owner) is not self.owner_class:
            return False
        values = object.__getattribute__(owner, '__dict__')
        if (_TYPE(values) is not dict or any(_TYPE(k) is not str for k in dict.keys(values))
                or dict.get(values, 'namespace') is not self.namespace
                or dict.get(values, '_entry') is not self.entry
                or dict.get(values, '_mapping') is not self.mapping
                or dict.get(values, '_import_builtins_match') is not True):
            return False
        definitions = dict.get(values, '_definitions')
        methods = self.owner_class.__dict__
        if (_TYPE(definitions) is not dict
                or any(_TYPE(k) is not str for k in dict.keys(definitions))
                or dict.get(definitions, 'function_signature') is not self.definition
                or any(_TYPE(k) is not str for k in methods)
                or methods.get('invoke_bound_signature') is not self.invoke
                or self.invoke.__code__ is not self.invoke_code
                or methods.get('definition_current') is not self.guard
                or self.guard.__code__ is not self.guard_code):
            return False
        return self.guard(owner, 'function_signature', provider)

    def call(self, provider, function, *, include_return_loans):
        # Argument evaluation can invalidate the admitted dependency after
        # GLOBAL selected a helper. Recheck the captured callable, never fetch
        # the public alias again. A native exception is never retried.
        if self.current(provider):
            return self.invoke(self.admission.owner,
                (provider, (provider := None))[0], (function, (function := None))[0],
                include_return_loans=(include_return_loans, (include_return_loans := None))[0])
        return (provider, (provider := None))[0](
            (function, (function := None))[0],
            include_return_loans=(include_return_loans, (include_return_loans := None))[0])


def _admit_signature(manifest_path, namespace):
    # This is explicit setup. No policy effect or GLOBAL lookup imports or
    # maps a dependency. A caller-supplied owner/record is not an authority.
    from .hia_inspect_program_native import (
        InspectAdmission, NativeInspectProgram, admit_inspect_program,
    )
    admission = admit_inspect_program(manifest_path)
    owner = admission.owner
    if (_TYPE(admission) is not InspectAdmission or _TYPE(owner) is not NativeInspectProgram
            or owner.namespace is not namespace):
        raise ValueError('patch signature dependency needs real same-namespace Inspect admission')
    definition = owner._definitions['function_signature']
    provider = definition[0]
    methods = NativeInspectProgram.__dict__
    invoke, guard = methods['invoke_bound_signature'], methods['definition_current']
    if _TYPE(invoke) is not FunctionType or _TYPE(guard) is not FunctionType:
        raise ValueError('Inspect signature entry methods differ')
    result = _AdmittedSignature(admission, NativeInspectProgram, provider, namespace,
                               owner._entry, owner._mapping, definition,
                               invoke, invoke.__code__, guard, guard.__code__)
    if not result.current(provider):
        raise ValueError('Inspect signature definition changed during explicit admission')
    return result


class NativePatchResult(NativeFrontImage):
    ARITIES = ARITIES

    def _bind_namespace(self, namespace=None):
        from . import hia_patch_result_ports as ports
        from . import hia_program_tools
        actual = vars(hia_program_tools)
        if namespace is not None and namespace is not actual:
            raise TypeError('patch owner requires the actual program-tools namespace')
        definitions = capture_definitions(actual)
        entries = {name: definitions[name].function for name in ARITIES}
        self.PORTS = ports
        # The existing metadata helper accepts a separate exact anchor holder.
        # Never insert, replace or probe a public module attribute to install it.
        self._bind_metadata(actual, {'_PATCH_ENTRIES': entries}, '_PATCH_ENTRIES')
        self._definitions = definitions
        self._import_builtins_match = all(
            _TYPE(function) is FunctionType and function.__builtins__ is self.builtins
            for function in (*self._import_names.values(), *self._import_fields.values()))
        if not self._import_builtins_match:
            raise ValueError('patch import operand templates do not share the original f_builtins')
        self._signature = self._signature_helper = None
        owner = self
        interface_provider = definitions['_check_patch_interface'].function
        apply_provider = definitions['apply_program_patch'].function
        def entry_interface(original, verified, interface_policy):
            return owner.invoke_bound_interface(interface_provider,
                (original, (original := None))[0], (verified, (verified := None))[0],
                (interface_policy, (interface_policy := None))[0])
        def entry_apply(document, request):
            return owner.invoke_bound_apply(apply_provider,
                (document, (document := None))[0], (request, (request := None))[0])
        self._helpers = {'_check_patch_interface': entry_interface,
                         'apply_program_patch': entry_apply}
        self._finish_helper_metadata()

    def definition_current(self, name, provider):
        record = self._definitions.get(name)
        return (record is not None and self._import_builtins_match
                and record.current(provider))

    def prepare(self, name, arguments, *, witness=None):
        mode, arity = self.modes[name]
        if _TYPE(arguments) is not tuple or len(arguments) != arity:
            raise TypeError('front argument binding differs')
        return PatchResultFrame(self, mode, arguments, witness=witness)

    def invoke_bound_apply(self, provider, document, request):
        if not self.definition_current('apply_program_patch', provider):
            return (provider, (provider := None))[0](
                (document, (document := None))[0], (request, (request := None))[0])
        frame = self.prepare('apply_program_patch', (document, request))
        provider = document = request = None
        return self.finish(frame)

    def invoke_bound_interface(self, provider, original, verified, interface_policy):
        if not self.definition_current('_check_patch_interface', provider):
            return (provider, (provider := None))[0](
                (original, (original := None))[0], (verified, (verified := None))[0],
                (interface_policy, (interface_policy := None))[0])
        frame = self.prepare('_check_patch_interface', (original, verified, interface_policy))
        provider = original = verified = interface_policy = None
        return self.finish(frame)


@dataclass(frozen=True, eq=False)
class PatchAdmission:
    owner: object
    manifest_path: str
    manifest_raw: bytes
    source_raw: bytes
    image_raw: bytes
    host_sources: tuple
    signature_manifest: object


def _capture_host_sources():
    from .hia_optional_profiles import _read_bound_file
    from .hia_patch_result_data import HOST_SOURCE_SHA256
    if (_TYPE(HOST_SOURCE_SHA256) is not dict
            or set(HOST_SOURCE_SHA256) != set(HOST_SOURCE_FILES)):
        raise ValueError('patch generated host compatibility inventory differs')
    root = Path(__file__).absolute().parent
    actual = {}
    for name in HOST_SOURCE_FILES:
        raw = _read_bound_file(root, name, limit=CAPACITY)
        actual[name] = sha256(raw).hexdigest()
        if actual[name] != HOST_SOURCE_SHA256[name]:
            raise ValueError('patch host source differs from its generated anchor')
    return actual


def _close_failed_admission(owner):
    if owner is not None:
        owner._entry = None
        for resource in (getattr(owner, '_delivery', None), getattr(owner, '_mapping', None)):
            if resource is not None:
                try:
                    resource.close()
                except BaseException:
                    _UNCONFIRMED_ADMISSIONS.append((owner, resource))


def admit_patch_result(manifest_path, *, inspect_manifest=None):
    """Explicit byte/definition admission; no selector, registry or cold claim.

    The optional signature component is independently admitted here. Without
    it the original function_signature callable is a real foreign dependency.
    """
    from .hia_optional_profiles import _read_bound_file
    from .hia_json_preflight_native import _unique_manifest_pairs
    from .hia_patch_result_data import SOURCE_BYTES, SOURCE_SHA256
    path = Path(manifest_path)
    if not path.is_absolute() or '..' in path.parts:
        raise ValueError('patch component requires an explicit absolute manifest path')
    if (_TYPE(SOURCE_BYTES) is not int or not 0 < SOURCE_BYTES <= CAPACITY
            or _TYPE(SOURCE_SHA256) is not str or len(SOURCE_SHA256) != 64
            or any(c not in '0123456789abcdef' for c in SOURCE_SHA256)):
        raise ValueError('patch generated source anchor differs')
    root, name = path.parent, path.name
    raw = _read_bound_file(root, name, limit=16384)
    value = json.JSONDecoder(object_pairs_hook=_unique_manifest_pairs).decode(raw.decode('utf-8'))
    keys = {'schema', 'source_path', 'source_sha256', 'image_path', 'image_sha256',
            'compiler_sha256', 'host_sources'}
    if (_TYPE(value) is not dict or set(value) != keys or value['schema'] != SCHEMA
            or value['source_path'] != SOURCE_NAME or value['image_path'] != IMAGE_NAME
            or value['source_sha256'] != SOURCE_SHA256 or _TYPE(value['host_sources']) is not dict
            or any(_TYPE(value[key]) is not str or len(value[key]) != 64
                   or any(c not in '0123456789abcdef' for c in value[key])
                   for key in ('source_sha256', 'image_sha256', 'compiler_sha256'))):
        raise ValueError('patch component manifest differs')
    hosts = _capture_host_sources()
    if value['host_sources'] != hosts:
        raise ValueError('patch manifest host compatibility differs')
    source = _read_bound_file(root, SOURCE_NAME, limit=CAPACITY,
                             expected_length=SOURCE_BYTES, expected_sha256=SOURCE_SHA256)
    image = _read_bound_file(root, IMAGE_NAME, limit=CAPACITY,
                            expected_sha256=value['image_sha256'])
    if not image:
        raise ValueError('patch executable is empty')
    owner = None
    try:
        owner = NativePatchResult(image, value['image_sha256'])
        owner._bind_manifest_source(SOURCE_SHA256)
        if inspect_manifest is not None:
            binding = _admit_signature(inspect_manifest, owner.namespace)
            provider = binding.provider
            def entry_signature(function, *, include_return_loans=False):
                return binding.call(provider, (function, (function := None))[0],
                    include_return_loans=(include_return_loans, (include_return_loans := None))[0])
            entry_signature.__name__ = provider.__name__
            entry_signature.__qualname__ = provider.__qualname__
            entry_signature.__module__ = provider.__module__
            owner._signature, owner._signature_helper = binding, entry_signature
        if (_read_bound_file(root, name, limit=16384) != raw
                or _read_bound_file(root, SOURCE_NAME, limit=CAPACITY,
                                   expected_length=SOURCE_BYTES, expected_sha256=SOURCE_SHA256) != source
                or _read_bound_file(root, IMAGE_NAME, limit=CAPACITY,
                                   expected_sha256=value['image_sha256']) != image
                or _capture_host_sources() != hosts
                or any(not owner.definition_current(key, record.function)
                       for key, record in owner._definitions.items())):
            raise ValueError('patch component changed during admission')
        if owner._signature is not None and not owner._signature.current(owner._signature.provider):
            raise ValueError('patch signature dependency changed during admission')
        return PatchAdmission(owner, str(path), raw, source, image, tuple(hosts.items()),
                              None if owner._signature is None else owner._signature.admission.manifest_path)
    except BaseException:
        _close_failed_admission(owner)
        raise


def installed_patch_result(manifest_path, *, inspect_manifest=None):
    return admit_patch_result(manifest_path, inspect_manifest=inspect_manifest).owner
