"""Actual HIA metadata witnesses with an explicit cold or development compiler.

The original signature and export implementation is a comparison oracle only.
Every policy observation below invokes the actual compiled image.
"""
from __future__ import annotations
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
import ctypes
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_native_metadata_native import (
    FRAMING, HEADER_BYTES, JSON_CORE, JSON_MANIFEST, MAGIC, MAX_JSON,
    MIN_OUTPUT_BYTES, REFUSALS, RESULT_MAGIC, SCHEMA, SELECTOR, SOURCE, STORAGE,
    NativeAgentMetadata, call_admitted_metadata_image, capture_request,
    installed_agent_metadata, prepare_native_metadata, storage_sizes,
    SNAPSHOT_MAGIC, SNAPSHOT_RECORD_BYTES, capture_object_request,
    call_admitted_metadata_object_image,
)
from hepta.hia_program import verify_program
ROOT = Path(__file__).resolve().parents[1]
COLD = 'HEPTA_HIA_AGENT_NATIVE_METADATA_COLD_REPORT'
DEVELOPMENT = 'HEPTA_HIA_AGENT_NATIVE_METADATA_DEVELOPMENT_COMPILER'
EVIDENCE = 'HEPTA_HIA_AGENT_NATIVE_METADATA_EVIDENCE'

def clean_environment():
    return {key: value for key, value in os.environ.items()
            if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}

def json_wire(value):
    return json.dumps(value, ensure_ascii=True, separators=(',', ':'),
                      allow_nan=False).encode('ascii')

def record(path, value):
    with path.open('x', encoding='utf-8') as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write('\n')

def function(name, params=(), returns=('u32',)):
    from tests.test_hia_program import b, c, f, ret
    values = [None if typ == 'unit' else True if typ == 'bool' else 7 for typ in returns]
    operations = [c('result_' + str(index), typ, value)
                  for index, (typ, value) in enumerate(zip(returns, values))]
    return f(name, list(params), list(returns), [], [
        b('entry', list(params), operations,
          ret(*['result_' + str(index) for index in range(len(returns))]))])

def program(*functions):
    from tests.test_hia_program import m
    return m(*functions)

def scalar_cases():
    widths = ('i8', 'i16', 'i32', 'i64', 'u8', 'u16', 'u32', 'u64', 'isize', 'usize', 'bool')
    functions = [function('scalar_' + typ, [('value', typ)], [typ]) for typ in widths]
    functions += [function('empty_result', returns=[]),
                  function('unit_result', returns=['unit']),
                  function('unit_parameter', [('value', 'unit')]),
                  function('two_results', returns=['u32', 'u64']),
                  function('many_parameters', [('p' + str(i), 'u64') for i in range(17)])]
    return program(*functions)

def loan_program():
    return program(function('zeta', [('src', 'readbuf'), ('count', 'u64')]),
                   function('ordinary'),
                   function('alpha', [('src', 'readbuf'), ('dst', 'mutbuf')]),
                   function('eight', [('p' + str(i), 'readbuf') for i in range(8)]),
                   function('nine', [('p' + str(i), 'readbuf') for i in range(9)]),
                   function('wrong_result', [('src', 'readbuf')], ['u64']),
                   function('unit_arg', [('src', 'readbuf'), ('bad', 'unit')]))

def original_metadata(checked, raw_manifest):
    from hepta.hia_agent_service import _signatures
    from hepta.hia_native_byte_abi import normalize_exports
    decoded = json.loads(raw_manifest)
    manifest = (tuple(tuple(pair) if type(pair) is list else pair for pair in decoded)
                if type(decoded) is list else decoded)
    with patch.dict(os.environ, clean_environment(), clear=True):
        exports = normalize_exports(manifest, checked)
        signatures = _signatures(checked, manifest)
    return {'foreign_buffer_exports': [list(pair) for pair in exports],
            'signatures': signatures}


def original_object_metadata(checked, exports):
    from hepta.hia_agent_service import _reference_signatures
    from hepta.hia_native_byte_abi import normalize_exports
    with patch.dict(os.environ, clean_environment(), clear=True):
        normalized = normalize_exports(exports, checked)
        signatures = _reference_signatures(checked, exports)
    return {'foreign_buffer_exports': [list(pair) for pair in normalized],
            'signatures': signatures}

@contextmanager
def no_reference_metadata():
    from contextlib import ExitStack
    with ExitStack() as stack:
        for name in ('hepta.hia_agent_service._reference_signatures',
                     'hepta.hia_native_byte_abi.normalize_exports'):
            stack.enter_context(patch(name, side_effect=AssertionError('reference metadata fallback')))
        yield

def object_cases():
    class Bomb:
        def __len__(self):
            raise AssertionError('foreign length')
        def __iter__(self):
            raise AssertionError('foreign iteration')
        def __str__(self):
            raise AssertionError('foreign string coercion')
        def __int__(self):
            raise AssertionError('foreign integer coercion')
    class TupleSubclass(tuple):
        pass
    class StringSubclass(str):
        pass
    class IntegerSubclass(int):
        pass
    bomb = Bomb()
    return [
        ('empty', ()), ('valid', (('zeta', 1048576), ('alpha', 1))),
        ('list-top', []), ('mapping-top', {}), ('foreign-top', bomb),
        ('tuple-subclass-top', TupleSubclass()), ('top-count', (('alpha', 1),) * 129),
        ('foreign-pair', (bomb,)), ('list-pair', (['alpha', 1],)),
        ('tuple-subclass-pair', (TupleSubclass(('alpha', 1)),)),
        ('empty-pair', ((),)), ('short-pair', (('alpha',),)),
        ('long-pair', (('alpha', 1, 2),)), ('foreign-name', ((bomb, 1),)),
        ('string-subclass-name', ((StringSubclass('alpha'), 1),)),
        ('bytes-name', ((b'alpha', 1),)), ('foreign-extent', (('alpha', bomb),)),
        ('integer-subclass-extent', (('alpha', IntegerSubclass(1)),)),
        ('bool-extent', (('alpha', True),)), ('float-extent', (('alpha', 1.0),)),
        ('nan-extent', (('alpha', float('nan')),)),
        ('infinite-extent', (('alpha', float('inf')),)),
        ('none-extent', (('alpha', None),)), ('string-extent', (('alpha', '1'),)),
        ('zero-extent', (('alpha', 0),)), ('negative-extent', (('alpha', -1),)),
        ('large-word', (('alpha', (1 << 64) - 1),)),
        ('large-positive', (('alpha', 1 << 4096),)),
        ('large-negative', (('alpha', -(1 << 4096)),)),
        ('empty-name', (('', 1),)), ('nonascii-name', (('\u00e9', 1),)),
        ('astral-name', (('\U0001f600', 1),)), ('surrogate-name', (('\ud800', 1),)),
        ('nul-name', (('alpha\0', 1),)), ('long-name', (('x' * 200000, 1),)),
        ('reserved-surrogate', (('__hia_\ud800', 1),)),
        ('reserved-long', (('__hia_' + 'x' * 200000, 1),)),
        ('extent-before-reserved', (('__hia_\ud800', 0),)),
        ('reserved-before-later-invalid', (('abort', 1), (bomb, bomb))),
        ('missing-before-later-invalid', (('\ud800', 1), ('alpha', 0))),
        ('duplicate', (('alpha', 1), ('alpha', 2))),
        ('invalid-before-duplicate', (('alpha', 1), ('alpha', 0))),
        ('wrong-loans', (('nine', 1),)), ('wrong-result', (('wrong_result', 1),)),
    ]


@contextmanager
def no_hosted_metadata():
    from contextlib import ExitStack
    with ExitStack() as stack:
        for name in ('hepta.hia_agent_service._signatures',
                     'hepta.hia_native_byte_abi.normalize_exports'):
            stack.enter_context(patch(name, side_effect=AssertionError('host metadata fallback')))
        yield

@contextmanager
def observe_entry(native, *, before=None):
    """Transparent single entry call; retain the actual buffers and return value."""
    entry = native._entry
    observations = []
    def observed(source, size, output, capacity, workspace, workspace_size):
        frozen = ctypes.string_at(source, size)
        if before is not None:
            before()
        result = entry(source, size, output, capacity, workspace, workspace_size)
        observations.append({"return": result, "input": frozen,
            "input_after": ctypes.string_at(source, size),
            "output": ctypes.string_at(output, capacity),
            "workspace": ctypes.string_at(workspace, workspace_size)})
        return result
    native._entry = observed
    try:
        yield observations
    finally:
        native._entry = entry


def vm_metadata(request, returned_bytes, *, observation=None):
    """Execute the complete HIA; observe actual buffers before their real drops."""
    from tools.hia_selfhost_bulk import Body
    from hepta.hia_agent_assembly import assemble_program
    from hepta.hia_program import execute_program
    from hepta import hia_program_runtime as runtime
    core_size, manifest_size = struct.unpack_from("<2Q", request, 16)
    output_size, workspace_size = storage_sizes(core_size, manifest_size)
    body, owners, views = Body(0), [], []
    for size, initial in ((len(request), request), (output_size, b""), (workspace_size, b"")):
        owner = body.value("buffer", "buffer.new", [body.const("usize", size)])
        view = body.value("mutbuf", "borrow.mut", [owner])
        for offset, value in enumerate(initial):
            if value:
                body.effect("buffer.store", [view, body.const("usize", offset), body.const("u8", value)])
        owners.append(owner)
        views.append(view)
    body.effect("loan.end", [views[0]])
    views[0] = body.value("readbuf", "borrow.read", [owners[0]])
    result = body.value("u32", "call", views, {"function": "f0"})
    for view in views:
        body.effect("loan.end", [view])
    for owner in owners:
        body.effect("owner.drop", [owner])
    wrapper = (
        "hia-asm.v1 hepta.hia.program.v8 agent_metadata_vm\n"
        "fn observe() -> (u32) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n"
        + body.text() + "  ret(" + result + ")\nend\n"
        + SOURCE.read_text().split("\n", 1)[1])
    snapshots = []
    observation_error = None
    original_drop = runtime._Machine.drop
    def observed_drop(machine, owner):
        # Read the actual VM bytes before the original destructor clears them.
        # Even an observation failure cannot prevent or replace the real drop.
        nonlocal observation_error
        snapshot = None
        try:
            if type(owner) is runtime._Owner:
                snapshot = (machine, owner.ident, bytes(owner.data))
        except BaseException as exc:
            if observation_error is None:
                observation_error = exc
        returned = original_drop(machine, owner)
        if snapshot is not None:
            snapshots.append(snapshot)
        return returned
    with patch.object(runtime._Machine, "drop", observed_drop):
        actual = execute_program(assemble_program(wrapper), "observe", [], max_steps=3_000_000)
    if observation_error is not None:
        raise observation_error
    assert actual["status"] == "returned", actual
    resources = actual["resources"]
    assert resources["live_owners"] == resources["live_local_loans"] == 0
    assert resources["owners_created"] == resources["owners_dropped"] == 3
    assert resources["allocations"] == resources["frees"] == 3
    assert len(snapshots) == 3
    machine = snapshots[0][0]
    assert all(entry[0] is machine for entry in snapshots)
    assert resources == machine.resources()
    dropped_ids = [entry[1] for entry in snapshots]
    assert dropped_ids == [1, 2, 3]
    assert snapshots[0][2] == request
    assert len(snapshots[1][2]) == output_size
    assert len(snapshots[2][2]) == workspace_size
    code, = actual["values"]
    raw = snapshots[1][2][:returned_bytes]
    assert len(raw) == returned_bytes
    if observation is not None:
        observation.update({"resources": resources, "dropped_owner_ids": dropped_ids,
            "single_vm_machine_observed": True,
            "input_sha256": sha256(snapshots[0][2]).hexdigest(),
            "output_bytes": len(raw), "output_sha256": sha256(raw).hexdigest(),
            "return": code, "original_drop_called_once_per_owner": True})
    return code, raw

class AgentMetadataFixture:
    """A fixture mixin, deliberately not a TestCase or a discovered parent suite."""
    @classmethod
    def setUpClass(cls):
        cold = os.environ.get(COLD)
        development = os.environ.get(DEVELOPMENT)
        if (COLD in os.environ and not cold) or (DEVELOPMENT in os.environ and not development):
            raise ValueError("empty metadata qualification selector")
        if bool(cold) == bool(development):
            raise ValueError("select exactly one matching metadata cold report or explicit development compiler")
        cls.cold = Path(cold).resolve(strict=True) if cold else None
        if cls.cold is not None:
            from tools.build_hia_json_preflight import admit_cold_build
            cold_bytes = cls.cold.read_bytes()
            report = json.loads(cold_bytes)
            nested = json.loads(Path(report["nested_report"]).read_bytes())
            cls.compiler = Path(nested["generations"][-1]["produced_image"]).resolve(strict=True)
            admit_cold_build(cls.compiler.read_bytes(), cold_bytes)
        else:
            cls.compiler = Path(development).resolve(strict=True)
        cls.temporary = None
        evidence = os.environ.get(EVIDENCE)
        if evidence:
            cls.folder = Path(evidence) / cls.__name__
            cls.folder.mkdir(mode=0o700, parents=True)
        else:
            cls.temporary = tempfile.TemporaryDirectory(prefix="hia-metadata-")
            cls.folder = Path(cls.temporary.name)
        source_bytes = SOURCE.read_bytes()
        compiler_bytes = cls.compiler.read_bytes()
        if cls.cold is not None:
            from tools.build_hia_agent_native_metadata import build
            cls.manifest = build(cls.folder / "qualified", cls.compiler, cls.cold)
            manifest = json.loads(cls.manifest.read_bytes())
            cls.compile_receipt = json.loads((cls.manifest.parent / "build.json").read_bytes())["native_compile_receipt"]
            mode = "MATCHING_CURRENT_SOURCE_COLD_BUILD"
        else:
            from tools.qualify_hia_selfhost import compile_stage
            image, cls.compile_receipt = compile_stage(cls.folder, "agent-native-metadata-development",
                                                       cls.compiler, source_bytes)
            manifest = {"schema": SCHEMA, "source_sha256": sha256(source_bytes).hexdigest(),
                "image_path": image.name, "image_sha256": sha256(image.read_bytes()).hexdigest(),
                "compiler_sha256": sha256(compiler_bytes).hexdigest()}
            cls.manifest = cls.folder / "manifest.json"
            record(cls.manifest, manifest)
            mode = "EXPLICIT_DEVELOPMENT_COMPILER_NOT_CURRENT_COLD"
        image = cls.manifest.parent / manifest["image_path"]
        image_bytes = image.read_bytes()
        if SOURCE.read_bytes() != source_bytes or cls.compiler.read_bytes() != compiler_bytes:
            raise ValueError("metadata fixture compiler/source changed")
        if not 0 < len(image_bytes) <= 1048576:
            raise ValueError("unchanged native image profile exceeded")
        cls.image_path = image
        cls.native = NativeAgentMetadata(image_bytes, manifest["image_sha256"])
        cls.build_mode = mode
        record(cls.folder / "build-observation.json", {
            "schema": "hepta.hia.agent-native-metadata-test-build.v1", "mode": mode,
            "matching_current_source_cold_qualified": cls.cold is not None,
            "manifest": manifest, "compiler_receipt": cls.compile_receipt,
            "original_core_verifier_still_hosted": True,
            "ordinary_default_provisioning_proved": False, "whole_native_closure": False})

    @classmethod
    def tearDownClass(cls):
        if cls.temporary is not None:
            cls.temporary.cleanup()

    def directory(self):
        directory = self.folder / self._testMethodName
        directory.mkdir(mode=0o700)
        return directory


class AgentMetadataSourceTests(unittest.TestCase):
    def test_actual_generator_reproduces_committed_hia(self):
        from tools.generate_hia_agent_native_metadata import document
        from hepta.hia_agent_assembly import render_assembly, assemble_program
        actual = document()
        assembly = render_assembly(actual)
        self.assertEqual(assembly.encode(), SOURCE.read_bytes())
        self.assertEqual(assemble_program(assembly).as_dict(), actual)

    def test_capture_preserves_raw_json_without_host_policy(self):
        checked = verify_program(program(function('plain')))
        raw = b'[["missing",1.5],["abort",2]]'
        with no_hosted_metadata():
            request = capture_request(checked, raw)
        self.assertEqual(request[64:64 + len(checked.canonical_bytes)], checked.canonical_bytes)
        self.assertEqual(request[64 + len(checked.canonical_bytes):], raw)
        self.assertEqual(struct.unpack_from('<8Q', request),
                         (MAGIC, 1, len(checked.canonical_bytes), len(raw), 0, 0, 0, 0))
        for bad in (bytearray(b'[]'), '[]', [], None):
            with self.subTest(type=type(bad).__name__):
                with self.assertRaises(ValueError):
                    capture_request(checked, bad)

    def test_invalid_cold_rejects_before_compile_or_output_creation(self):
        from tools.build_hia_agent_native_metadata import build
        with tempfile.TemporaryDirectory(prefix='hia-metadata-cold-refusal-') as directory:
            root = Path(directory)
            compiler, cold = root / 'compiler.bin', root / 'cold.json'
            compiler.write_bytes(b'never executed')
            cold.write_text('{"schema":"wrong","source_manifest":{}}')
            with patch('tools.qualify_hia_selfhost.compile_stage',
                       side_effect=AssertionError('compiler must not be reached')) as stage:
                with self.assertRaises(ValueError):
                    build(root / 'output', compiler, cold)
            self.assertEqual(stage.call_count, 0)
            self.assertFalse((root / 'output').exists())


    def test_object_snapshot_is_bounded_and_preserves_exact_type_observations(self):
        checked = verify_program(program(function('plain')))
        class Bomb:
            def __len__(self):
                raise AssertionError('foreign length')
            def __str__(self):
                raise AssertionError('foreign string coercion')
        with no_reference_metadata():
            top = capture_object_request(checked, Bomb())
            raw = capture_object_request(checked, (('__hia_\ud800' + 'x' * 10000, 1 << 4096),))
        start = 64 + len(checked.canonical_bytes)
        self.assertEqual(len(top), start + 32)
        self.assertEqual(struct.unpack_from('<4Q', top, start), (SNAPSHOT_MAGIC, 0, 0, 0))
        self.assertEqual(len(raw), start + 32 + SNAPSHOT_RECORD_BYTES)
        base = start + 32
        words = struct.unpack_from('<8Q', raw, base)
        self.assertEqual(words, (1, 2, 1, 10007, 1, 0, 4097, 0))
        self.assertEqual(struct.unpack_from('<I', raw, base + 64 + 6 * 4)[0], 0xd800)


class AgentMetadataNativeTests(AgentMetadataFixture, unittest.TestCase):
    def compare(self, document, raw_manifest):
        checked = verify_program(document)
        expected = original_metadata(checked, raw_manifest)
        request = capture_request(checked, raw_manifest)
        with no_hosted_metadata(), observe_entry(self.native) as calls:
            actual = self.native.transition(request)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]['input'], calls[0]['input_after'])
        self.assertEqual(actual.status, 0)
        self.assertEqual(json.loads(actual.payload_wire), expected)
        self.assertEqual(list(json.loads(actual.payload_wire)['signatures']),
                         list(expected['signatures']))
        return checked, request, actual, calls[0]

    def test_scalar_signatures_and_original_entrypoint_selection(self):
        checked, _, receipt, _ = self.compare(scalar_cases(), b'[]')
        signatures = json.loads(receipt.payload_wire)['signatures']
        self.assertIn('unit_result', signatures)
        self.assertNotIn('unit_parameter', signatures)
        self.assertNotIn('two_results', signatures)
        self.assertEqual(len(signatures['many_parameters']['params']), 17)
        document = program(function('chosen'), function('private'))
        document['exports'] = ['chosen']
        _, _, receipt, _ = self.compare(document, b'[]')
        self.assertEqual(list(json.loads(receipt.payload_wire)['signatures']), ['chosen'])

    def test_borrowed_exports_preserve_scalar_order_and_sorted_manifest(self):
        _, _, receipt, _ = self.compare(
            loan_program(), json_wire([['zeta', 1048576], ['eight', 1], ['alpha', 65536]]))
        payload = json.loads(receipt.payload_wire)
        self.assertEqual(payload['foreign_buffer_exports'],
                         [['alpha', 65536], ['eight', 1], ['zeta', 1048576]])
        self.assertEqual(list(payload['signatures']), ['ordinary', 'zeta', 'alpha', 'eight'])
        self.assertEqual(payload['signatures']['zeta']['abi'],
                         'hepta.hia.agent.borrowed-byte-snapshots.v1')

    def test_manifest_refusals_and_first_failure_order(self):
        checked = verify_program(loan_program())
        cases = [
            ({}, 0xfffffffb), (None, 0xfffffffb), ('bad', 0xfffffffb),
            ([['alpha', 1]] * 129, 0xfffffffb), ([[]], 0xfffffffa),
            ([[1, 1]], 0xfffffffa), ([['alpha', True]], 0xfffffffa),
            ([['alpha', 0]], 0xfffffffa), ([['alpha', -1]], 0xfffffffa),
            ([['alpha', 1048577]], 0xfffffffa),
            ([['alpha', 1], ['alpha', 2]], 0xfffffffa),
            ([['abort', 1], ['missing', 0]], 0xfffffff8),
            ([['__hia_' + 'x' * 200, 1]], 0xfffffff8),
            ([['x' * 129, 1]], 0xfffffff7), ([['absent', 1]], 0xfffffff7),
            ([['ordinary', 1]], 0xfffffff6), ([['nine', 1]], 0xfffffff6),
            ([['wrong_result', 1]], 0xfffffff6), ([['unit_arg', 1]], 0xfffffff6),
            ([['alpha', 1], ['abort', 0]], 0xfffffffa),
            ([['missing', 1], ['alpha', 0]], 0xfffffff7),
        ]
        observations = []
        for manifest, status in cases:
            with self.subTest(manifest=manifest):
                raw = json_wire(manifest)
                with self.assertRaises(ValueError) as expected:
                    original_metadata(checked, raw)
                with no_hosted_metadata(), observe_entry(self.native) as calls:
                    receipt = self.native.transition(capture_request(checked, raw))
                self.assertEqual(len(calls), 1)
                self.assertEqual(receipt.status, status)
                self.assertIn(REFUSALS[status], str(expected.exception))
                self.assertEqual(calls[0]['input'], calls[0]['input_after'])
                observations.append({'manifest_sha256': sha256(raw).hexdigest(),
                                     'native_status': status,
                                     'reference_error': str(expected.exception)})
        record(self.directory() / 'refusals.json', observations)

    def test_nominal_or_explicit_exports_refuse_before_pair_policy(self):
        document = program(function('plain'))
        document['exports'] = ['plain']
        checked = verify_program(document)
        raw = b'[["absent",0]]'
        with self.assertRaises(ValueError) as expected:
            original_metadata(checked, raw)
        self.assertIn(REFUSALS[0xfffffff9], str(expected.exception))
        receipt = self.native.transition(capture_request(checked, raw))
        self.assertEqual(receipt.status, 0xfffffff9)
        # A structured provenance bit is a recorded admission fact. Empty
        # manifests remain permitted; nonempty manifests fail before pairs.
        empty = bytearray(capture_request(checked, b'[]'))
        struct.pack_into('<Q', empty, 32, 1)
        self.assertEqual(self.native.transition(bytes(empty)).status, 0)
        nonempty = bytearray(capture_request(checked, raw))
        struct.pack_into('<Q', nonempty, 32, 1)
        self.assertEqual(self.native.transition(bytes(nonempty)).status, 0xfffffff9)

    def test_raw_standard_number_tags_and_json_syntax(self):
        checked = verify_program(loan_program())
        numbers = [b'1.0', b'1e0', b'1E+0', b'0.1', b'-0.0', b'1e-9999']
        for value in numbers:
            for prefix, status in ((b'', 0xfffffffa), (b'["abort",1],', 0xfffffff8)):
                raw = b'[' + prefix + b'["alpha",' + value + b']]'
                with self.subTest(raw=raw):
                    with self.assertRaises(ValueError) as expected:
                        original_metadata(checked, raw)
                    self.assertIn(REFUSALS[status], str(expected.exception))
                    with no_hosted_metadata():
                        actual = self.native.transition(capture_request(checked, raw))
                    self.assertEqual(actual.status, status)
        for raw in (b'', b'[', b'[["alpha",01]]', b'[["alpha",1.]]',
                    b'[["alpha",1e]]', b'[["alpha",NaN]]',
                    b'[["\xff",1]]', b'[["\\ud800",1]]'):
            with self.subTest(raw=raw):
                self.assertEqual(self.native.transition(capture_request(checked, raw)).status,
                                 JSON_MANIFEST)

    def test_input_function_and_parameter_limits_remain_original(self):
        document = program(*[function('fn_' + str(i)) for i in range(1024)])
        _, _, receipt, _ = self.compare(document, b'[]')
        fields = struct.unpack('<8Q', receipt.raw_header)
        self.assertEqual(fields[2:5], (1024, 1024, 0))
        self.assertEqual(len(json.loads(receipt.payload_wire)['signatures']), 1024)
        _, _, receipt, _ = self.compare(
            program(function('wide', [('p' + str(i), 'u64') for i in range(17)])), b'[]')
        self.assertEqual(len(json.loads(receipt.payload_wire)['signatures']['wide']['params']), 17)

    def test_capacity_canaries_and_read_only_input(self):
        checked = verify_program(program(function('plain')))
        request = capture_request(checked, b'[]')
        output_size, workspace_size = storage_sizes(len(checked.canonical_bytes), 2)
        expected = self.native.transition(request)
        observations = []
        for out_size, work_size, status in (
                (output_size, workspace_size, 64 + len(expected.payload_wire)),
                (output_size, workspace_size - 1, STORAGE),
                (output_size - 1, workspace_size, FRAMING)):
            buffers, pointers = [], []
            for size, initial in ((len(request), request), (out_size, b''), (work_size, b'')):
                buf = ctypes.create_string_buffer(size + 64)
                ctypes.memset(ctypes.addressof(buf), 0xa7, 32)
                ctypes.memset(ctypes.addressof(buf) + 32 + size, 0x5c, 32)
                if initial:
                    ctypes.memmove(ctypes.addressof(buf) + 32, initial, len(initial))
                buffers.append(buf); pointers.append(ctypes.addressof(buf) + 32)
            actual = self.native._entry(pointers[0], len(request), pointers[1], out_size,
                                        pointers[2], work_size)
            self.assertEqual(actual, status)
            self.assertEqual(ctypes.string_at(pointers[0], len(request)), request)
            for buf, size in zip(buffers, (len(request), out_size, work_size)):
                self.assertEqual(buf.raw[:32], b'\xa7' * 32)
                self.assertEqual(buf.raw[32 + size:], b'\x5c' * 32)
            if actual < 0xfffffff0:
                self.assertEqual(ctypes.string_at(pointers[1], actual),
                                 expected.raw_header + expected.payload_wire)
            observations.append({'output_capacity': out_size, 'workspace_capacity': work_size,
                                 'native_return': actual, 'guards_preserved': True})
        record(self.directory() / 'capacity.json', observations)

    def test_full_vm_output_and_actual_resource_destruction(self):
        document = program(function('plain'), function('bytes', [('src', 'readbuf')]))
        checked = verify_program(document)
        observations = []
        for manifest in (b'[]', b'[["bytes",16]]', b'[["bytes",1.5]]'):
            request = capture_request(checked, manifest)
            native = self.native.transition(request)
            expected = native.raw_header + native.payload_wire
            witness = {}
            code, wire = vm_metadata(request, len(expected), observation=witness)
            self.assertEqual(code, 64 + len(native.payload_wire) if native.status == 0 else native.status)
            self.assertEqual(wire, expected)
            self.assertEqual(witness['resources']['loans_started'], 4)
            self.assertEqual(witness['resources']['loans_ended'], 4)
            observations.append(witness)
        record(self.directory() / 'vm-witnesses.json', observations)

    def test_private_buffer_concurrent_calls(self):
        checked = verify_program(loan_program())
        inputs = [json_wire([['alpha', index + 1]]) for index in range(16)]
        expected = [original_metadata(checked, raw) for raw in inputs]
        with no_hosted_metadata(), ThreadPoolExecutor(max_workers=4) as workers:
            results = list(workers.map(lambda raw: self.native.transition(capture_request(checked, raw)), inputs))
        self.assertTrue(all(result.status == 0 for result in results))
        self.assertEqual([json.loads(result.payload_wire) for result in results], expected)
        record(self.directory() / 'concurrent.json', {
            'calls': len(results), 'workers': 4, 'distinct_extents': list(range(1, 17)),
            'all_actual_payloads_match': True})

    def test_typed_snapshot_exact_object_domain_and_first_refusals(self):
        checked = verify_program(loan_program())
        observations = []
        for label, exports in object_cases():
            with self.subTest(label=label):
                error = None
                try:
                    expected = original_object_metadata(checked, exports)
                except ValueError as exc:
                    error = str(exc)
                request = capture_object_request(checked, exports)
                with no_reference_metadata(), observe_entry(self.native) as calls:
                    if error is None:
                        actual = call_admitted_metadata_object_image(self.native, checked, exports)
                        self.assertEqual(actual, expected)
                    else:
                        with self.assertRaises(ValueError) as actual:
                            call_admitted_metadata_object_image(self.native, checked, exports)
                        self.assertEqual(str(actual.exception), error)
                self.assertEqual(len(calls), 1)
                self.assertEqual(calls[0]['input'], request)
                self.assertEqual(calls[0]['input_after'], request)
                observations.append({'case': label, 'reference_error': error,
                    'request_bytes': len(request), 'native_return': calls[0]['return'],
                    'native_input_sha256': sha256(request).hexdigest(),
                    'actual_native_invocations': len(calls)})
        record(self.directory() / 'exact-object-domain.json', observations)

    def test_typed_snapshot_full_payload_vm_and_framing(self):
        checked = verify_program(program(function('plain'), function('bytes', [('src', 'readbuf')])))
        typed = capture_object_request(checked, (('bytes', 16),))
        raw = capture_request(checked, b'[["bytes",16]]')
        expected = self.native.transition(raw)
        actual = self.native.transition(typed)
        self.assertEqual(actual, expected)
        observations = []
        for request in (typed, capture_object_request(checked, (('__hia_\ud800', 1),))):
            native = self.native.transition(request)
            witness = {}
            code, wire = vm_metadata(request, len(native.raw_header + native.payload_wire), observation=witness)
            self.assertEqual(code, 64 + len(native.payload_wire) if native.status == 0 else native.status)
            self.assertEqual(wire, native.raw_header + native.payload_wire)
            self.assertEqual(witness['resources']['loans_started'], 4)
            self.assertEqual(witness['resources']['loans_ended'], 4)
            observations.append(witness)
        start = 64 + len(checked.canonical_bytes)
        for label, offset, value in (('magic', start, 0), ('reserved', start + 24, 1)):
            damaged = bytearray(typed)
            struct.pack_into('<Q', damaged, offset, value)
            with self.subTest(label=label):
                self.assertEqual(self.native.transition(bytes(damaged)).status, FRAMING)
        inconsistent = bytearray(typed)
        struct.pack_into('<Q', inconsistent, start + 32 + 48, 0)
        self.assertEqual(self.native.transition(bytes(inconsistent)).status, 0xfffffffa)
        record(self.directory() / 'typed-vm-witnesses.json', observations)


if __name__ == '__main__':
    unittest.main()
