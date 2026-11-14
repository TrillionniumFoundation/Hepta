"""An explicitly selected HIA owner for real VerifiedProgram report objects.

The complete seven policy bodies are native continuations. Verification, JSON
decoding, hashing, schema providers and mutable foreign replacements remain
their real providers. This component does not grant verification authority.
"""
from __future__ import annotations

from types import FunctionType, MethodType
from .hia_front_runtime import NativeFrontImage, FrontFrame, FrontUnknown
from .hia_front_continuation import _Cell
from .hia_optional_profiles import optional_profile_resource_path

SOURCE = optional_profile_resource_path('hepta.hia.cli-verified-report-bundle.v2',
                                       'examples/hia_bootstrap/verified_report.hepta')
ARITIES = dict.fromkeys(('sha256', 'canonical_json', 'input_sha256',
                        'scalar_entrypoints', 'normalization_report',
                        'as_dict', 'report'), 1)
SCHEMA = 'hepta.hia.verified-report-native.v2'
_TYPE = type
_TYPE_GET = type.__getattribute__
_OBJECT_GET = object.__getattribute__


class VerifiedReportFrame(FrontFrame):
    def _effect(self):
        op, destinations, args, raw, vector = self._parts()
        if op == 3:
            if len(destinations) != 1 or len(args) != 1 or len(raw) != 1 or vector:
                raise FrontUnknown('verified-report ATTR representation differs')
            result = self.image.attribute(self._get(args[0]), self.image.literal(raw[0]), self)
            self._set(destinations[0], result)
            return 0
        return super()._effect()

    def _function(self, args, raw, vector):
        # The original closure construction is unchanged apart from the local
        # frame class, so nested policy generators retain this ATTR dispatch.
        mode, generator = raw
        captures = tuple(self.values[slot] for slot in vector)
        if any(type(cell) is not _Cell for cell in captures):
            raise FrontUnknown('public-front closure captured a non-cell')
        if generator == 1 and len(args) == 1:
            frame = VerifiedReportFrame(self.image, mode, (self._get(args[0]),), captures,
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


class NativeVerifiedReport(NativeFrontImage):
    ARITIES = ARITIES

    def _bind_namespace(self, namespace=None):
        from . import hia_verified_report_ports as ports
        from . import hia_program
        actual = vars(hia_program)
        if namespace is not None and namespace is not actual:
            raise TypeError('verified-report requires the original live program globals')
        self.PORTS = ports
        self._bind_metadata(actual, actual, '_NATIVE_VERIFIED_REPORT_ENTRIES')
        self._class = hia_program._NATIVE_VERIFIED_REPORT_CLASS
        self._definitions = dict(hia_program._NATIVE_VERIFIED_REPORT_ANCHORS)
        self._mro, self._dict_descriptor, self._getattribute = hia_program._NATIVE_VERIFIED_REPORT_LOOKUP
        if (set(self._definitions) != set(ARITIES)
                or self._getattribute is not _OBJECT_GET
                or _TYPE(self._class) is not type):
            raise FrontUnknown('verified-report original class anchors differ')
        for name, (descriptor, function, code) in self._definitions.items():
            if (_TYPE(function) is not FunctionType or function.__globals__ is not actual
                    or self.public_entries[name] is not function):
                raise FrontUnknown('verified-report function anchors differ')
        owner = self

        def entry_0(self):
            frame = owner.prepare('sha256', (self,))
            self = None
            return owner.finish(frame)
        def entry_1(self):
            frame = owner.prepare('canonical_json', (self,))
            self = None
            return owner.finish(frame)
        def entry_2(self):
            frame = owner.prepare('input_sha256', (self,))
            self = None
            return owner.finish(frame)
        def entry_3(self):
            frame = owner.prepare('scalar_entrypoints', (self,))
            self = None
            return owner.finish(frame)
        def entry_4(self):
            frame = owner.prepare('normalization_report', (self,))
            self = None
            return owner.finish(frame)
        def entry_5(self):
            frame = owner.prepare('as_dict', (self,))
            self = None
            return owner.finish(frame)
        def entry_6(self):
            frame = owner.prepare('report', (self,))
            self = None
            return owner.finish(frame)
        self._helpers = dict(zip(ARITIES, (entry_0, entry_1, entry_2, entry_3,
                                         entry_4, entry_5, entry_6)))
        self._finish_helper_metadata()

    def prepare(self, name, arguments, *, witness=None):
        mode, arity = self.modes[name]
        if type(arguments) is not tuple or len(arguments) != arity:
            raise TypeError('front argument binding differs')
        return VerifiedReportFrame(self, mode, arguments, witness=witness)

    def _ordinary_attribute(self, value, name):
        # These guards use saved interpreter descriptors, never user getattr,
        # hash/equality, or an overridable instance attribute. A changed MRO,
        # __getattribute__, __getattr__, descriptor, code or instance shadow
        # always takes the real original attribute operation below.
        if (_TYPE(value) is not self._class
                or _TYPE_GET(self._class, '__mro__') is not self._mro
                or _TYPE_GET(self._class, '__getattribute__') is not self._getattribute):
            return False
        fields = _TYPE_GET(self._class, '__dict__')
        if '__getattr__' in fields:
            return False
        original = self._definitions.get(name)
        if original is None:
            return False
        descriptor, function, code = original
        if fields.get(name) is not descriptor or function.__code__ is not code:
            return False
        if self._dict_descriptor is None:
            # The actual retained class is a frozen slotted dataclass. Exact
            # type plus its unchanged MRO excludes a subclass instance dict.
            return True
        dictionary = self._dict_descriptor.__get__(value, self._class)
        return name not in dictionary

    def attribute(self, value, name, parent):
        if not self._ordinary_attribute(value, name):
            return getattr(value, name)
        descriptor, function, code = self._definitions[name]
        if _TYPE(descriptor) is not property:
            return MethodType(self._helpers[name], value)
        frame = self.prepare(name, (value,), witness=parent.witness)
        value = None
        try:
            return self.finish(frame)
        finally:
            if frame._uncertain:
                parent._uncertain = True

    def invoke_bound_report(self, method):
        # The caller has already performed exactly its original .report
        # lookup. A replacement callable is invoked once, without metadata
        # probing or a second lookup.
        original = self._definitions['report']
        if (_TYPE(method) is not MethodType or method.__func__ is not original[1]
                or original[1].__code__ is not original[2]
                or not self._ordinary_attribute(method.__self__, 'report')):
            # Move the actual callable onto CPython's CALL operand stack. A
            # retained error traceback must not add a new local owner of it.
            return (method, (method := None))[0]()
        frame = self.prepare('report', (method.__self__,))
        method = None
        return self.finish(frame)
