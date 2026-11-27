"""Shared setup for the new complete Slot controller qualification module.

The original separate nine-resource controls and original Slot15 remain intact.
This fixture builds the controller and old decision image with one declared
compiler/current-cold pair. It does not manufacture finite expectations.
"""
from __future__ import annotations
from hashlib import sha256
import json
import os
from pathlib import Path
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PREFIX = 'HEPTA_HIA_SLOT_OPERATIONS_'


def _json(path, value):
    path.write_text(json.dumps(value, ensure_ascii=True, sort_keys=True, indent=2,
                               allow_nan=False) + '\n')


class ComponentFixture:
    @classmethod
    def setUpClass(cls):
        from tools.build_hia_slot_operations import INPUTS, build
        from tools.build_hia_slot_ledger import build as decision_build
        from tools.build_hia_json_preflight import admit_cold_build
        from tools.build_hia_source_build import _check_pack_output
        from tools.qualify_hia_selfhost import compile_stage
        cold = os.environ.get(PREFIX + 'COLD_REPORT')
        development = os.environ.get(PREFIX + 'DEVELOPMENT_COMPILER')
        if bool(cold) == bool(development):
            raise ValueError('choose one exact current cold report or explicit development compiler')
        cls.temporary = None
        evidence = os.environ.get(PREFIX + 'EVIDENCE')
        if evidence:
            cls.folder = Path(evidence) / cls.__name__
            cls.folder.mkdir(mode=0o700, parents=True, exist_ok=False)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix='hia-slot-operation-resources-')
            cls.folder = Path(cls.temporary.name)
        cls.cold_path = Path(cold).resolve(strict=True) if cold else None
        cls.cold_bytes = cls.nested_bytes = cls.nested_path = cls.admitted = None
        if cls.cold_path is not None:
            from tools.hia_cold_compiler import read_cold_build_inputs
            cls.cold_inputs = read_cold_build_inputs(cls.cold_path)
            cls.cold_bytes = cls.cold_inputs.report_bytes
            cls.nested_path = cls.cold_inputs.location_path
            cls.nested_bytes = cls.cold_inputs.location_bytes
            cls.compiler = cls.cold_inputs.compiler
            cls.compiler_bytes = cls.cold_inputs.compiler_bytes
            cls.admitted = admit_cold_build(cls.compiler_bytes, cls.cold_bytes)
        else:
            cls.compiler = Path(development).resolve(strict=True)
            cls.compiler_bytes = cls.compiler.read_bytes()
        cls.inputs = tuple(dict.fromkeys((*INPUTS,
            'examples/hia_bootstrap/slot_ledger.hepta', 'tools/generate_hia_slot_ledger.py',
            'tests/hia_slot_operations_resource_controls.py',
            'tests/test_hia_slot_operation_series_native.py')))
        cls.before = {name: (ROOT / name).read_bytes() for name in cls.inputs}
        cls.controller = build(cls.folder / 'controller', cls.compiler, cls.cold_path,
                               development=cls.cold_path is None)
        if cls.cold_path is not None:
            cls.decision = decision_build(cls.folder / 'decision', cls.compiler, cls.cold_path)
        else:
            target = cls.folder / 'decision'
            target.mkdir(mode=0o700)
            source = cls.before['examples/hia_bootstrap/slot_ledger.hepta']
            image, receipt = compile_stage(target, 'slot_decision', cls.compiler, source)
            image_bytes = image.read_bytes()
            packed = _check_pack_output(receipt, (target / 'slot_decision.output.bin').read_bytes(),
                                        artifact=cls.compiler_bytes, source=source)
            if packed != image_bytes:
                raise AssertionError('actual decision pack and image differ')
            value = {'schema': 'hepta.hia.slot-ledger-native.v1',
                     'source_sha256': sha256(source).hexdigest(), 'image_path': image.name,
                     'image_sha256': sha256(image_bytes).hexdigest(),
                     'compiler_sha256': sha256(cls.compiler_bytes).hexdigest()}
            cls.decision = target / 'manifest.json'
            _json(cls.decision, value)
            _json(target / 'build.json', {
                'scope': 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_COLD_QUALIFIED',
                'manifest': value, 'native_compile_receipt': receipt})
        cls.manifest_bytes = {str(path): path.read_bytes() for path in (cls.controller, cls.decision)}
        cls.image_bytes = {}
        for path in (cls.controller, cls.decision):
            value = json.loads(cls.manifest_bytes[str(path)])
            image = path.parent / value['image_path']
            cls.image_bytes[str(image)] = image.read_bytes()
            if sha256(cls.image_bytes[str(image)]).hexdigest() != value['image_sha256']:
                raise AssertionError('built declared image hash differs')
        cls.check_sources()
        from tests.hia_slot_operations_qualification_support import product_snapshot, write_json, sha
        cls.product_freeze = cls.folder / 'qualification-source-freeze.json'
        write_json(cls.product_freeze, {'schema': 'hepta.slot-operations.qualification-source-freeze.v1',
            'files': product_snapshot(ROOT, cls.inputs),
            'scope': 'declared component INPUTS; matching-cold admission also binds full source'})
        cls.product_freeze_sha256 = sha(cls.product_freeze.read_bytes())
        _json(cls.folder / 'fixture.json', {
            'scope': 'MATCHING_SOURCE_COLD_COMPONENT' if cls.cold_path else 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_COLD_QUALIFIED',
            'cold_report': None if cls.cold_path is None else str(cls.cold_path),
            'compiler_path': str(cls.compiler), 'compiler_sha256': sha256(cls.compiler_bytes).hexdigest(),
            'sources': {name: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()} for name, raw in cls.before.items()},
            'manifests': {path: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()} for path, raw in cls.manifest_bytes.items()},
            'images': {path: {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()} for path, raw in cls.image_bytes.items()},
            'complete_original_cases': 248, 'derived_original_fault_cases': 7574,
            'new_public_inputs': 84, 'new_handled_traceback_inputs': 12,
            'native_test_methods': 6, 'separate_resource_cases': 9,
            'original_248_and_derived_7574_replaced': False,
            'existing_complete_gates_and_deadlines_changed': False,
            'SQL_implemented_by_native': False})

    @classmethod
    def check_sources(cls):
        if cls.compiler.read_bytes() != cls.compiler_bytes:
            raise AssertionError('Slot controller compiler changed')
        if any((ROOT / name).read_bytes() != raw for name, raw in cls.before.items()):
            raise AssertionError('Slot controller/component input changed')
        if cls.cold_path is not None and (
                cls.cold_path.read_bytes() != cls.cold_bytes
                or cls.nested_path.read_bytes() != cls.nested_bytes):
            raise AssertionError('Slot controller matching cold report changed')
        if cls.cold_path is not None:
            cls.cold_inputs.unchanged()
            from tools.build_hia_json_preflight import admit_cold_build, current_sources
            if (admit_cold_build(cls.compiler_bytes, cls.cold_bytes) != cls.admitted
                    or current_sources() != cls.admitted):
                raise AssertionError('Slot control is not bound to this complete current source')
        if hasattr(cls, 'manifest_bytes') and any(Path(path).read_bytes() != raw for path, raw in cls.manifest_bytes.items()):
            raise AssertionError('Slot controller or decision manifest changed')
        if hasattr(cls, 'image_bytes') and any(Path(path).read_bytes() != raw for path, raw in cls.image_bytes.items()):
            raise AssertionError('Slot controller or decision image changed')

    @classmethod
    def tearDownClass(cls):
        try:
            cls.check_sources()
            _json(cls.folder / 'component-custody.json', {
                'source_before': {name: sha256(raw).hexdigest() for name, raw in cls.before.items()},
                'source_after': {name: sha256((ROOT / name).read_bytes()).hexdigest() for name in cls.before},
                'compiler_sha256': sha256(cls.compiler.read_bytes()).hexdigest(),
                'controller_manifest': str(cls.controller), 'decision_manifest': str(cls.decision),
                'scope': 'MATCHING_SOURCE_COLD_COMPONENT' if cls.cold_path else 'EXPLICIT_DEVELOPMENT_COMPONENT_NOT_COLD_QUALIFIED',
                'resource_and_original_caller_gates_remain_separate': True})
        finally:
            if cls.temporary is not None:
                cls.temporary.cleanup()
