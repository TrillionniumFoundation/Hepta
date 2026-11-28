"""Typed complete Core identity data: independent VM, native and custody controls."""
from __future__ import annotations
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_program import verify_program, execute_program
from tools.generate_hia_core_host_custody import generated, document
from tools.generate_hia_source_helper_manifest import original
from tools.hia_core_host_custody import (
    ARCHIVE_PATH, DECODER_SOURCE, BAG_MAGIC, RECORD_MAGIC, REQUEST_MAGIC,
    HEADER, MAX_RAW, ENTRIES, encode_record, parse_archive, metadata,
    request, capture_archive, git_blob)
from tools.hia_core_companion_release import COMPANIONS, inputs, manifest_request, check_request

ROOT = Path(__file__).resolve().parents[1]


def archive_from_bodies(bodies):
    records = [encode_record(role, kind, path, raw)
               for (role, kind, path), raw in zip(ENTRIES, bodies, strict=True)]
    return struct.pack('<8sQ', BAG_MAGIC, 6) + b''.join(
        struct.pack('<Q', len(raw)) + raw for raw in records)


def small_archive():
    return archive_from_bodies([bytes((role, kind)) * (kind + 2)
                               for role, kind, _ in ENTRIES])


def damaged_archives(raw):
    """Independent negative corpus; every row, including unselected rows, matters."""
    result = [('short', raw[:15]), ('tail', raw + b'\0'), ('truncated', raw[:-1])]
    for offset, label in ((0, 'bag-magic'), (8, 'bag-count')):
        bad = bytearray(raw); bad[offset] ^= 1
        result.append((label, bytes(bad)))
    cursor, rows = 16, []
    for ordinal in range(6):
        size, = struct.unpack_from('<Q', raw, cursor)
        start = cursor + 8
        rows.append(raw[cursor:start + size])
        for offset, label in ((0, 'record-magic'), (8, 'version'), (16, 'role'),
                              (24, 'kind'), (32, 'mode'), (40, 'path-size'),
                              (48, 'data-size'), (56, 'git-sha1'), (76, 'sha256'),
                              (108, 'reserved'), (128, 'logical-path'),
                              (size - 1, 'body')):
            bad = bytearray(raw); bad[start + offset] ^= 1
            result.append((f'row-{ordinal}-{label}', bytes(bad)))
        for extent in (0, 127, (1 << 64) - 1):
            bad = bytearray(raw); struct.pack_into('<Q', bad, cursor, extent)
            result.append((f'row-{ordinal}-extent-{extent}', bytes(bad)))
        cursor = start + size
    result.append(('record-order', raw[:16] + rows[1] + rows[0] + b''.join(rows[2:])))
    result.append(('duplicate-record', raw[:16] + rows[0] + rows[0] + b''.join(rows[2:])))
    return result


def vm_decode(wire, *, output_size=64, workspace_size=65536):
    """Observe actual owned buffers before the unchanged VM destructor runs."""
    from tools.hia_selfhost_bulk import Body
    from hepta import hia_program_runtime as runtime
    body, owners, views = Body(0), [], []
    for size, initial, fill in ((len(wire), wire, 0), (output_size, b'', 165),
                                (workspace_size, b'', 0)):
        owner = body.value('buffer', 'buffer.new', [body.const('usize', size)])
        view = body.value('mutbuf', 'borrow.mut', [owner])
        body.effect('buffer.fill_range', [view, body.const('usize', 0),
                    body.const('usize', size), body.const('u8', fill)])
        for offset, value in enumerate(initial):
            if value:
                body.effect('buffer.store', [view, body.const('usize', offset),
                                             body.const('u8', value)])
        owners.append(owner); views.append(view)
    body.effect('loan.end', [views[0]])
    views[0] = body.value('readbuf', 'borrow.read', [owners[0]])
    result = body.value('u32', 'call', views, {'function': 'custody'})
    for view in views:
        body.effect('loan.end', [view])
    for owner in owners:
        body.effect('owner.drop', [owner])
    wrapper = ('hia-asm.v1 hepta.hia.program.v8 custody_vm\n'
               'fn observe() -> (u32) effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'
               + body.text() + '  ret(' + result + ')\nend\n'
               + (ROOT / DECODER_SOURCE).read_text().split('\n', 1)[1])
    snapshots, observation_errors = [], []
    old_drop = runtime._Machine.drop
    def observe_drop(machine, owner):
        snapshot = None
        try:
            if type(owner) is runtime._Owner:
                snapshot = bytes(owner.data)
        except BaseException as exc:
            observation_errors.append(exc)
        returned = old_drop(machine, owner)
        if snapshot is not None:
            snapshots.append(snapshot)
        return returned
    with patch.object(runtime._Machine, 'drop', observe_drop):
        actual = execute_program(assemble_program(wrapper), 'observe', [], max_steps=3_000_000)
    if observation_errors:
        raise observation_errors[0]
    assert actual['status'] == 'returned', actual
    resources = actual['resources']
    assert resources['live_owners'] == resources['live_local_loans'] == 0, resources
    assert resources['owners_created'] == resources['owners_dropped'] == 3, resources
    assert resources['allocations'] == resources['frees'] == 3, resources
    assert len(snapshots) == 3
    assert snapshots[0] == wire
    return actual['result'], snapshots[1], snapshots[2]


class CoreHostCustodySourceControls(unittest.TestCase):
    def test_complete_generated_decoder_and_original_primitive_bodies(self):
        self.assertEqual((ROOT / DECODER_SOURCE).read_bytes(), generated())
        model = document(); verify_program(model)
        self.assertLessEqual(len(model['functions']), 128)
        self.assertLessEqual(sum(len(f['blocks']) for f in model['functions']), 1536)
        self.assertLessEqual(sum(len(b['ops']) for f in model['functions'] for b in f['blocks']), 8192)
        prior = {f['name']: f for f in original('stage')['functions']}
        retained = [f for f in model['functions'] if f['name'] in prior]
        self.assertTrue({'f23', 'f24', 'f25', 'f46'} <= {f['name'] for f in retained})
        for fn in retained:
            self.assertEqual(fn, prior[fn['name']])
        self.assertEqual(model['functions'][0]['name'], 'custody')

    def test_complete_current_git_inputs_and_six_full_byte_records(self):
        raw, receipt = capture_archive(ROOT)
        self.assertEqual(raw, (ROOT / ARCHIVE_PATH).read_bytes())
        self.assertTrue(receipt['physical_initial_terminal_identical'])
        self.assertTrue(receipt['git_head_index_and_blob_identical'])
        self.assertFalse(receipt['compiled_or_executed_host_source'])
        rows = parse_archive(raw)
        self.assertEqual([(r['role'], r['kind'], r['path']) for r in rows], list(ENTRIES))
        for row in rows:
            self.assertEqual(row['raw'], (ROOT / row['path']).read_bytes())
            self.assertEqual(row['git_blob_sha1'], git_blob(row['raw']).hex())
            self.assertEqual(row['sha256'], sha256(row['raw']).hexdigest())

    def test_native_source_boundary_and_explicit_data_metadata(self):
        from tools.hia_native_worker_source_authority import checked_paths
        from tools.hia_native_release_dependencies import release_dependencies
        from hepta.hia_agent_contract import NATIVE_SOURCE_FILES
        from tools.hia_selfhost_contract import SOURCE_FILES
        self.assertEqual(checked_paths(sorted((ARCHIVE_PATH, DECODER_SOURCE))),
                         tuple(sorted((ARCHIVE_PATH, DECODER_SOURCE))))
        for _, _, path in ENTRIES:
            with self.assertRaises(ValueError):
                checked_paths([path])
        report = release_dependencies(ROOT)
        self.assertTrue({ARCHIVE_PATH, DECODER_SOURCE} <= set(report['required_sources']))
        data, = report['custody_data']
        self.assertFalse(data['compiled_or_executed'])
        self.assertEqual(data['records'], metadata((ROOT / ARCHIVE_PATH).read_bytes()))
        self.assertEqual(data['decoder'], DECODER_SOURCE)
        for path in (ARCHIVE_PATH, DECODER_SOURCE):
            self.assertIn(path, NATIVE_SOURCE_FILES)
            self.assertIn(path, SOURCE_FILES)

    def test_complete_negative_record_corpus_and_strict_transport_types(self):
        raw = small_archive()
        self.assertEqual(len(parse_archive(raw)), 6)
        for label, bad in damaged_archives(raw):
            with self.subTest(case=label), self.assertRaises(ValueError):
                parse_archive(bad)
        for role, kind in ((True, 1), (11.0, 1), ('11', 1), (11, True), (10, 1), (14, 1), (11, 0), (11, 3)):
            with self.subTest(role=role, kind=kind), self.assertRaises(ValueError):
                request(role, kind, raw)

    def test_vm_all_six_actual_views_and_canary_extents(self):
        raw = small_archive()
        for row in parse_archive(raw):
            wire = request(row['role'], row['kind'], raw)
            result, output, workspace = vm_decode(wire)
            self.assertEqual(result, 0)
            self.assertEqual(output[:row['bytes']], row['raw'])
            self.assertEqual(output[row['bytes']:], b'\xa5' * (len(output) - row['bytes']))
            self.assertEqual(struct.unpack_from('<Q', workspace, 88)[0], row['bytes'])
            self.assertEqual(struct.unpack_from('<Q', workspace, 16)[0], 3)

    def test_vm_rejects_unselected_corruption_and_preserves_output_on_refusal(self):
        raw = small_archive()
        corpus = dict(damaged_archives(raw))
        for name in ('row-5-sha256', 'row-5-git-sha1', 'row-5-body'):
            wire = struct.pack('<8s2Q', REQUEST_MAGIC, 11, 1) + corpus[name]
            result, output, workspace = vm_decode(wire)
            self.assertEqual(result, 16)
            self.assertEqual(output, b'\xa5' * len(output))
            self.assertEqual(struct.unpack_from('<Q', workspace, 16)[0], 0)
        for output_size, workspace_size, code in ((1, 65536, 17), (64, 65535, 16)):
            result, output, workspace = vm_decode(request(11, 1, raw),
                output_size=output_size, workspace_size=workspace_size)
            self.assertEqual(result, code)
            self.assertEqual(output, b'\xa5' * len(output))
            self.assertEqual(struct.unpack_from('<Q', workspace, 16)[0], 0)


ENV = ('HIA_TEST_CORE_CUSTODY_DECODER', 'HIA_TEST_CORE_CUSTODY_OWNER',
       'HIA_TEST_CORE_CUSTODY_CHECKER', 'HIA_TEST_NATIVE_SOURCE_SEED',
       'HIA_TEST_CORE_CUSTODY_EVIDENCE')


@unittest.skipUnless(all(os.environ.get(key) for key in ENV),
                     'requires actual B3-compiled native decoder, owner and independent checker')
class CoreHostCustodyNativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.decoder, cls.owner, cls.checker, cls.seed, cls.evidence = (
            Path(os.environ[key]).resolve() for key in ENV)
        cls.evidence.mkdir(mode=0o700, exist_ok=False)
        cls.serial = 0
        from tools.build_hia_source_build import _named_source_request, _compiled_sources
        named = {Path(inputs(family)[0]).name: (ROOT / inputs(family)[0]).read_bytes()
                 for _, family in COMPANIONS}
        named['selfhost.hepta'] = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        wire = _named_source_request(named)
        p = subprocess.run([str(cls.seed), 'sources'], input=wire, capture_output=True,
                           env={'PATH': ''}, timeout=180)
        for suffix, raw in (('request', wire), ('stdout', p.stdout), ('stderr', p.stderr)):
            (cls.evidence / ('compile.' + suffix)).write_bytes(raw)
        (cls.evidence / 'compile.terminal.json').write_text(
            json.dumps(dict(returncode=p.returncode, seconds_limit=180)) + '\n')
        if p.returncode != 0 or p.stderr:
            raise AssertionError((p.returncode, p.stderr))
        cls.sources = named
        cls.images = _compiled_sources(p.stdout, named)
        cls.compiler = cls.images['selfhost.hepta']
        if sha256(cls.compiler).hexdigest() != 'acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9':
            raise AssertionError('actual development compiler differs from exact B3 identity')
        cls.archive = (ROOT / ARCHIVE_PATH).read_bytes()

    def invoke(self, executable, wire, *, accepted=True):
        type(self).serial += 1
        name = f'{self.serial:04d}-{self._testMethodName}'
        p = subprocess.run([str(executable), 'build'], input=wire, capture_output=True,
                           env={'PATH': ''}, timeout=30)
        for suffix, raw in (('request', wire), ('stdout', p.stdout), ('stderr', p.stderr)):
            (self.evidence / (name + '.' + suffix)).write_bytes(raw)
        (self.evidence / (name + '.terminal.json')).write_text(json.dumps(
            dict(executable=str(executable), returncode=p.returncode,
                 expected_acceptance=accepted, seconds_limit=30), sort_keys=True) + '\n')
        self.assertEqual(p.stderr, b'')
        if accepted:
            self.assertEqual(p.returncode, 0)
        else:
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(p.stdout, b'')
        return p.stdout

    def test_native_all_six_current_full_git_byte_views(self):
        for role, kind, path in ENTRIES:
            with self.subTest(role=role, kind=kind):
                raw = self.invoke(self.decoder, request(role, kind, self.archive))
                self.assertEqual(raw, (ROOT / path).read_bytes())

    def test_native_decoded_inputs_reach_all_three_original_eight_field_manifests(self):
        for role, family in COMPANIONS:
            source_name, abi_name, bridge_name, selection_name = inputs(family)
            source, image = self.sources[Path(source_name).name], self.images[Path(source_name).name]
            abi = (ROOT / abi_name).read_bytes()
            bridge, selection = (self.invoke(self.decoder, request(role, kind, self.archive))
                                 for kind in (1, 2))
            self.assertEqual(bridge, (ROOT / bridge_name).read_bytes())
            self.assertEqual(selection, (ROOT / selection_name).read_bytes())
            raw = self.invoke(self.owner, manifest_request(role, (
                source, image, self.sources['selfhost.hepta'], self.compiler, abi, bridge, selection)))
            expected = dict(schema='hepta.hia.core-' + family + '-native.v1',
                source_sha256=sha256(source).hexdigest(), abi_sha256=sha256(abi).hexdigest(),
                bridge_sha256=sha256(bridge).hexdigest(), selection_sha256=sha256(selection).hexdigest(),
                image_path='core-' + family + '.image.bin', image_sha256=sha256(image).hexdigest(),
                compiler_sha256=sha256(self.compiler).hexdigest())
            self.assertEqual(raw, (json.dumps(expected, sort_keys=True, indent=2) + '\n').encode())
            checked = self.invoke(self.checker, check_request(role, (
                raw, source, image, self.compiler, abi, bridge, selection)))
            self.assertEqual(checked, struct.pack('<8s3Q', b'HIASTOK1', 14, role, len(raw)))
            for changed_bridge, changed_selection in ((bridge + b'\0', selection), (bridge, selection + b'\0')):
                self.invoke(self.checker, check_request(role, (
                    raw, source, image, self.compiler, abi, changed_bridge, changed_selection)), accepted=False)

    def test_native_git_sha1_padding_decimal_lengths_and_full_size_boundary(self):
        sizes = (1, 9, 10, 47, 48, 49, 55, 56, 63, 64, 65, 99, 100, 119, 120,
                 127, 128, 255, 256, 999, 1000, 4096, MAX_RAW)
        for size in sizes:
            body = (bytes(range(256)) * ((size + 255) // 256))[:size]
            raw = archive_from_bodies([body, b'2', b'3', b'4', b'5', b'6'])
            with self.subTest(bytes=size):
                self.assertEqual(self.invoke(self.decoder, request(11, 1, raw)), body)

    def test_native_complete_negative_corpus_including_all_unselected_rows(self):
        raw = small_archive()
        for label, bad in damaged_archives(raw):
            with self.subTest(case=label):
                self.invoke(self.decoder, struct.pack('<8s2Q', REQUEST_MAGIC, 11, 1) + bad,
                            accepted=False)
        valid = request(11, 1, raw)
        for bad in (valid[:39], valid + b'\0', b'HIAHCQR2' + valid[8:],
                    struct.pack('<8s2Q', REQUEST_MAGIC, 10, 1) + raw,
                    struct.pack('<8s2Q', REQUEST_MAGIC, 14, 1) + raw,
                    struct.pack('<8s2Q', REQUEST_MAGIC, 11, 0) + raw,
                    struct.pack('<8s2Q', REQUEST_MAGIC, 11, 3) + raw):
            self.invoke(self.decoder, bad, accepted=False)


if __name__ == '__main__':
    unittest.main()
