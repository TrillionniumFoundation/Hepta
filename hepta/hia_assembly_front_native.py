"""Complete assembly_front policy in its own fixed HIA image.
JSON and existing semantic providers remain explicit dependencies.
"""
from __future__ import annotations
from .hia_front_runtime import NativeFrontImage
from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/assembly_front.hepta')
SCHEMA = 'hepta.hia.assembly-front-native.v1'
SELECTOR = 'HEPTA_HIA_ASSEMBLY_FRONT_MANIFEST'
ARITIES = {'_reject': 3, '_source': 1, '_items': 2, '_names': 2, '_parameters': 2, '_attrs': 2, '_parse_assembly_document': 1, 'assemble_program': 1, '_render_parameters': 1, '_render_assembly_document': 1, 'render_assembly': 1, 'diagnose_assembly': 1}

class NativeAssemblyFront(NativeFrontImage):
    ARITIES = ARITIES

    def _bind_namespace(self, namespace=None):
        from . import hia_assembly_front_ports as ports
        self.PORTS = ports
        from . import hia_agent_assembly
        self._bind_metadata(namespace, vars(hia_agent_assembly), '_NATIVE_ASSEMBLY_FRONT_ENTRIES')
        owner = self
        def entry_0(message, *, line=None, limit=False):
            frame = owner.prepare('_reject', (message, line, limit))
            message = line = limit = None
            return owner.finish(frame)
        def entry_1(value):
            frame = owner.prepare('_source', (value,))
            value = None
            return owner.finish(frame)
        def entry_2(value, line):
            frame = owner.prepare('_items', (value, line))
            value = line = None
            return owner.finish(frame)
        def entry_3(value, line):
            frame = owner.prepare('_names', (value, line))
            value = line = None
            return owner.finish(frame)
        def entry_4(value, line):
            frame = owner.prepare('_parameters', (value, line))
            value = line = None
            return owner.finish(frame)
        def entry_5(value, line):
            frame = owner.prepare('_attrs', (value, line))
            value = line = None
            return owner.finish(frame)
        def entry_6(source: str | bytes):
            frame = owner.prepare('_parse_assembly_document', (source,))
            source = None
            return owner.finish(frame)
        def entry_7(source: str | bytes):
            frame = owner.prepare('assemble_program', (source,))
            source = None
            return owner.finish(frame)
        def entry_8(parameters):
            frame = owner.prepare('_render_parameters', (parameters,))
            parameters = None
            return owner.finish(frame)
        def entry_9(data: dict):
            frame = owner.prepare('_render_assembly_document', (data,))
            data = None
            return owner.finish(frame)
        def entry_10(document):
            frame = owner.prepare('render_assembly', (document,))
            document = None
            return owner.finish(frame)
        def entry_11(source: str | bytes):
            frame = owner.prepare('diagnose_assembly', (source,))
            source = None
            return owner.finish(frame)
        self._helpers = dict(zip(ARITIES, (entry_0, entry_1, entry_2, entry_3, entry_4, entry_5, entry_6, entry_7, entry_8, entry_9, entry_10, entry_11)))
        self._finish_helper_metadata()

    def finish(self, frame):
        # This application owner can call Core twice for its round trip. The
        # lease does no I/O: the first actual Core call or capability request
        # selects the Core owner, including absence, and subsequent calls hold it.
        from .hia_core_verification_selection import borrow_core_verification_scope
        with borrow_core_verification_scope():
            return super().finish(frame)
