"""Complete core_verification policy in its own fixed HIA image.
JSON and existing semantic providers remain explicit dependencies.
"""
from __future__ import annotations
from .hia_front_runtime import NativeFrontImage
from .hia_json_preflight_native import _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/core_verification.hepta')
SCHEMA = 'hepta.hia.core-verification-native.v1'
SELECTOR = 'HEPTA_HIA_CORE_VERIFICATION_MANIFEST'
ARITIES = {'_reject': 2, 'verify_program': 1}

class NativeCoreVerification(NativeFrontImage):
    ARITIES = ARITIES

    def _bind_namespace(self, namespace=None):
        from . import hia_core_verification_ports as ports
        self.PORTS = ports
        from . import hia_program
        self._bind_metadata(namespace, vars(hia_program), '_NATIVE_CORE_VERIFICATION_ENTRIES')
        owner = self
        def entry_0(message, code='E_HIA_PROGRAM'):
            frame = owner.prepare('_reject', (message, code))
            message = code = None
            return owner.finish(frame)
        def entry_1(program):
            frame = owner.prepare('verify_program', (program,))
            program = None
            return owner.finish(frame)
        self._helpers = dict(zip(ARITIES, (entry_0, entry_1)))
        self._finish_helper_metadata()
