"""Fixed object/exception transport shared by two independent HIA owners.

This file has no assembly, program-tools, backend, original policy or authoring
imports. Each concrete image supplies one actual module namespace and fixed
definition anchors. HIA owns branches, loops and every effect permission.
"""
from __future__ import annotations
from hashlib import sha256
from .hia_front_continuation import ContinuationFrame, NativeContinuationImage, _Cell, _EMPTY

_UNKNOWN = {}
_UNCONFIRMED_IMAGE_CLEANUP = []

class FrontUnknown(RuntimeError):
    """A claimed observation has no confirmed result; it is never replayed."""


def _match_exception(frame, slot):
    try:
        frame.image._delivery.deliver(frame.error)
    except frame._get(slot) as delivered:
        if delivered is not frame.error:
            frame._uncertain = True
            raise
        return 1
    except BaseException as delivered:
        if delivered is not frame.error:
            frame._uncertain = True
            raise
        return 0
    frame._uncertain = True
    raise FrontUnknown('public-front exception delivery returned')


class FrontFrame(ContinuationFrame):
    def _global_in(self, name, group):
        if type(group) is not int or group != 0:
            raise FrontUnknown('public-front global namespace differs')
        namespace = self.image.namespace
        if name in namespace:
            value = namespace[name]
            helper = self.image._helpers.get(name)
            if helper is not None:
                expected = self.image.public_entries.get(name, _EMPTY)
                if value is expected:
                    return helper
            return value
        if name in self.image.builtins:
            return self.image.builtins[name]
        raise NameError("name '"+name+"' is not defined", name=name)

    def _move(self, slot):
        value = self._get(slot)
        self._clear(slot)
        return value

    def _load_named(self, slot, name, role):
        if type(slot) is not int or not 0 <= slot < len(self.values):
            raise FrontUnknown('public-front named slot differs')
        value = self.values[slot]
        if slot in self.cells:
            value = value.value
        return self.image.ports.unbound(name,role) if value is _EMPTY else value

    def _call(self, args, raw):
        if raw == (0,240):
            if len(args) != 1:
                raise FrontUnknown('public-front FORMAT operands differ')
            return self.image.ports.format_value(self,args[0])
        if len(raw) == 2 and raw[1] == 241:
            primitive = self.image.ports.BUILD_STRINGS.get(raw[0])
            if primitive is None or raw[0] != len(args):
                raise FrontUnknown('public-front BUILD_STRING operands differ')
            return primitive(self,args)
        if len(raw) < 2 or len(raw) != 2+raw[1] or len(args) != 1+raw[0]+raw[1]:
            raise FrontUnknown('public-front CALL operands differ')
        key = raw[0], tuple(self.image.literal(i) for i in raw[2:])
        primitive = self.image.ports.CALLS.get(key)
        if primitive is None:
            raise FrontUnknown('public-front CALL outside frozen inventory')
        return primitive(self,args)

    def _function(self, args, raw, vector):
        mode,generator = raw
        captures = tuple(self.values[slot] for slot in vector)
        if any(type(cell) is not _Cell for cell in captures):
            raise FrontUnknown('public-front closure captured a non-cell')
        if generator == 1 and len(args) == 1:
            frame = FrontFrame(self.image,mode,(self._get(args[0]),),captures,
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

    def _effect(self):
        op,destinations,args,raw,vector = self._parts()
        if op == 2:
            if len(raw) != 2 or args or len(destinations) != 1 or vector:
                raise FrontUnknown('public-front GLOBAL representation differs')
            self._set(destinations[0],self._global_in(self.image.literal(raw[0]),raw[1]))
            return 0
        if op == 15 and raw:
            if len(raw) != 2 or len(args) != 1 or len(destinations) != 1 or vector:
                raise FrontUnknown('public-front named-load representation differs')
            self._set(destinations[0],self._load_named(args[0],self.image.literal(raw[0]),raw[1]))
            return 0
        if op == 19:
            if len(raw) < 2 or len(destinations) != 1 or vector:
                raise FrontUnknown('public-front import representation differs')
            if raw[0] == 0 and not args:
                module = self.image.literal(raw[1])
                names = tuple(self.image.literal(i) for i in raw[2:])
                primitive = self.image._import_names.get((module,names))
                if primitive is None:
                    raise FrontUnknown('public-front IMPORT_NAME outside frozen inventory')
                self._set(destinations[0],primitive())
            elif raw[0] == 1 and len(raw) == 2 and len(args) == 1:
                primitive = self.image._import_fields.get(self.image.literal(raw[1]))
                if primitive is None:
                    raise FrontUnknown('public-front IMPORT_FROM outside frozen inventory')
                self._set(destinations[0],primitive(self._get(args[0])))
            else:
                raise FrontUnknown('public-front import phase differs')
            return 0
        if op == 21:
            if len(args) != 1 or destinations or raw or vector:
                raise FrontUnknown('public-front exception match differs')
            return _match_exception(self,args[0])
        return super()._effect()

    def service(self, issued):
        super().service(issued)
        if self._uncertain:
            _UNKNOWN[self.nonce] = self
            self.close(release=False)
            raise FrontUnknown('public-front claimed effect has no confirmed outcome')



class NativeFrontImage(NativeContinuationImage):
    def __init__(self, image, expected_sha256, namespace=None):
        try:
            super().__init__(image, expected_sha256)
            self._bind_namespace(namespace)
        except BaseException:
            self._entry = None
            for resource in (getattr(self, '_delivery', None), getattr(self, '_mapping', None)):
                if resource is not None:
                    try:
                        resource.close()
                    except BaseException:
                        _UNCONFIRMED_IMAGE_CLEANUP.append((self, resource))
            raise

    def _bind_metadata(self, namespace, actual, anchor_name):
        if namespace is None:
            namespace = actual
        if type(namespace) is not dict or type(actual) is not dict:
            raise TypeError('front owner requires its actual module namespace')
        self.namespace = namespace
        self.ports = self.PORTS
        if (tuple(self.ARITIES) != self.ports.ROOT_NAMES
                or self.function_count != self.ports.FUNCTION_COUNT
                or sha256(self.table).hexdigest() != self.ports.TABLE_SHA256):
            raise FrontUnknown('front actual HIA table identity differs')
        self.public_entries = actual[anchor_name]
        if type(self.public_entries) is not dict or set(self.public_entries) != set(self.ARITIES):
            raise FrontUnknown('front fixed definition anchors differ')
        # Definition anchors are actual functions, never late replacement
        # objects. Retain their interpreter builtin mapping, not new globals.
        self.builtins = self.public_entries[next(iter(self.ARITIES))].__builtins__
        self._import_names, self._import_fields = self.ports.import_ports(namespace)
        self.modes = {name: (mode, arity) for mode, (name, arity) in enumerate(self.ARITIES.items(), 1)}
        for mode, arity in self.modes.values():
            if self.function(mode)[2] != arity:
                raise FrontUnknown('front original entry arity differs')
        for mode in range(len(self.ARITIES) + 1, self.function_count + 1):
            info = self.function(mode)[2]
            if info & 65535 != 1 or not info & (1 << 16):
                raise FrontUnknown('front lazy frame arity differs')

    def _finish_helper_metadata(self):
        for name, function in self._helpers.items():
            anchor = self.public_entries[name]
            function.__name__ = anchor.__name__
            function.__qualname__ = anchor.__qualname__
            function.__module__ = anchor.__module__

    def prepare(self, name, arguments, *, witness=None):
        mode, arity = self.modes[name]
        if type(arguments) is not tuple or len(arguments) != arity:
            raise TypeError('front argument binding differs')
        return FrontFrame(self, mode, arguments, witness=witness)

    def finish(self, frame):
        completed = False
        try:
            if frame.drive() != 0:
                raise FrontUnknown('front root unexpectedly yielded')
            completed = True
            return frame.take()
        except BaseException:
            completed = False
            raise
        finally:
            frame.close(release=completed)

    def run(self, name, *arguments, witness=None):
        frame = self.prepare(name, arguments, witness=witness)
        arguments = None
        return self.finish(frame)
