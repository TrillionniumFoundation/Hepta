"""Actual native controls for versioned helper production and independent checks."""
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
import unittest

from tools.build_hia_json_preflight import CANDIDATES, _image_manifest
from tools.build_hia_worker_release import INSTALLED_HELPERS, EXTENDED_INSTALLED_HELPERS
from tools.build_hia_source_build import _named_source_request, _compiled_sources
from tests.test_hia_release_stage_plan import frame_request
from tests.test_hia_release_member_check import check_packet

ROOT = Path(__file__).resolve().parents[1]
ENVIRONMENT = ('HIA_TEST_RELEASE_STAGE_PLANNER', 'HIA_TEST_HELPER_MANIFEST_OWNER',
               'HIA_TEST_NATIVE_SOURCE_SEED', 'HIA_TEST_HELPER_EVIDENCE',
               'HIA_TEST_HELPER_EXTENSION_STAGE')


@unittest.skipUnless(all(os.environ.get(k) for k in ENVIRONMENT),
                     'requires the real native helper owner, planner and source compiler')
class HelperCatalogNativeControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.planner = Path(os.environ[ENVIRONMENT[0]]).resolve()
        cls.extension_planner = Path(os.environ[ENVIRONMENT[4]]).resolve()
        cls.owner = Path(os.environ[ENVIRONMENT[1]]).resolve()
        cls.seed = Path(os.environ[ENVIRONMENT[2]]).resolve()
        cls.evidence = Path(os.environ[ENVIRONMENT[3]]).resolve()
        cls.evidence.mkdir(mode=0o700, exist_ok=False)
        cls.serial = 0
        cls.roles = [*enumerate(INSTALLED_HELPERS, 1), *EXTENDED_INSTALLED_HELPERS]
        named = {CANDIDATES[kind][0] + '.hepta':
                 (ROOT / 'examples/hia_bootstrap' / (CANDIDATES[kind][0] + '.hepta')).read_bytes()
                 for _, kind in cls.roles}
        cls.selfhost = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        named['selfhost.hepta'] = cls.selfhost
        request = _named_source_request(named)
        p = subprocess.run([str(cls.seed), 'sources'], input=request, capture_output=True,
                           env={'PATH': ''}, timeout=180)
        (cls.evidence / 'compile.request').write_bytes(request)
        (cls.evidence / 'compile.stdout').write_bytes(p.stdout)
        (cls.evidence / 'compile.stderr').write_bytes(p.stderr)
        (cls.evidence / 'compile.terminal.json').write_text(
            json.dumps({'returncode': p.returncode, 'seconds_limit': 180}) + '\n')
        if p.returncode != 0 or p.stderr != b'':
            raise AssertionError((p.returncode, p.stderr))
        cls.images = _compiled_sources(p.stdout, named)
        cls.compiler = cls.images['selfhost.hepta']
        if sha256(cls.compiler).hexdigest() != 'acb6478d1a466d17210611c5fcbbd5aeec3109b0813e917f0bb5c8419f3c33a9':
            raise AssertionError('development compiler differs from its exact source-built identity')
        cls.sources = named

    def invoke(self, executable, wire, *, accepted=True):
        type(self).serial += 1
        name = f'{self.serial:04d}-{self._testMethodName}'
        p = subprocess.run([str(executable), 'build'], input=wire, capture_output=True,
                           env={'PATH': ''}, timeout=30)
        for suffix, raw in (('request', wire), ('stdout', p.stdout), ('stderr', p.stderr)):
            (self.evidence / (name + '.' + suffix)).write_bytes(raw)
        (self.evidence / (name + '.terminal.json')).write_text(json.dumps(
            {'returncode': p.returncode, 'expected_acceptance': accepted, 'seconds_limit': 30,
             'executable': str(executable)}, sort_keys=True) + '\n')
        self.assertEqual(p.stderr, b'')
        if accepted:
            self.assertEqual(p.returncode, 0)
        else:
            self.assertNotEqual(p.returncode, 0)
            self.assertEqual(p.stdout, b'')
        return p.stdout

    def parts(self, kind):
        name = CANDIDATES[kind][0] + '.hepta'
        return [self.sources[name], self.images[name], self.selfhost, self.compiler]

    def owner_wire(self, magic, role, pieces):
        return struct.pack('<8s5Q', magic, role, *map(len, pieces)) + b''.join(pieces)

    def expected(self, kind):
        source, image, _, compiler = self.parts(kind)
        protocol = CANDIDATES[kind][1]
        return _image_manifest(kind, protocol, source, image, protocol + '.image.bin',
                               sha256(compiler).hexdigest())

    def check(self, mode, role, kind, manifest, *, accepted=True, source=None, image=None, compiler=None):
        parts = self.parts(kind)
        wire = check_packet(mode, role, [manifest, parts[0] if source is None else source,
            parts[1] if image is None else image, parts[3] if compiler is None else compiler])
        planner = self.extension_planner if mode == 13 else self.planner
        result = self.invoke(planner, wire, accepted=accepted)
        if accepted:
            self.assertEqual(result, struct.pack('<8s3Q', b'HIASTOK1', mode, role, len(manifest)))

    def test_original_eight_actual_native_owners_and_checkers(self):
        for role, kind in enumerate(INSTALLED_HELPERS, 1):
            with self.subTest(role=role, component=kind):
                manifest = self.invoke(self.owner, self.owner_wire(b'HIAHLM01', role, self.parts(kind)))
                self.assertEqual(json.loads(manifest), self.expected(kind))
                self.check(5, role, kind, manifest)

    def test_new_four_actual_frames_owners_and_independent_checkers(self):
        for role, kind in EXTENDED_INSTALLED_HELPERS:
            with self.subTest(role=role, component=kind):
                parts = self.parts(kind)
                framed = self.invoke(self.extension_planner, frame_request(4, 2, role, parts))
                self.assertEqual(framed, self.owner_wire(b'HIAHLM02', role, parts))
                manifest = self.invoke(self.owner, framed)
                self.assertEqual(json.loads(manifest), self.expected(kind))
                self.assertEqual(manifest, (json.dumps(self.expected(kind), sort_keys=True, indent=2) + '\n').encode())
                self.check(13, role, kind, manifest)

    def test_original_and_extended_role_domains_are_separate(self):
        parts = self.parts('bounded-read')
        manifest = (json.dumps(self.expected('bounded-read'), sort_keys=True, indent=2) + '\n').encode()
        for role in (0, 9, 10, 11, 12, 13, 14, 15, 16, (1 << 64) - 1):
            self.invoke(self.owner, self.owner_wire(b'HIAHLM01', role, parts), accepted=False)
        for role in (*range(9), 11, 12, 13, 16, (1 << 64) - 1):
            self.invoke(self.owner, self.owner_wire(b'HIAHLM02', role, parts), accepted=False)
            self.invoke(self.extension_planner, frame_request(4, 2, role, parts), accepted=False)
            self.check(13, role, 'bounded-read', manifest, accepted=False)
        self.invoke(self.planner, frame_request(4, 1, 9, parts), accepted=False)
        self.check(5, 9, 'bounded-read', manifest, accepted=False)

    def test_current_owner_refuses_cross_role_source_wrong_image_and_truncation(self):
        for role, kind in EXTENDED_INSTALLED_HELPERS:
            parts = self.parts(kind)
            other = 'json-pretty' if kind != 'json-pretty' else 'bounded-read'
            wrong = list(parts)
            wrong[0] = self.parts(other)[0]
            self.invoke(self.owner, self.owner_wire(b'HIAHLM02', role, wrong), accepted=False)
            wrong = list(parts)
            wrong[1] += b'\0'
            self.invoke(self.owner, self.owner_wire(b'HIAHLM02', role, wrong), accepted=False)
            valid = self.owner_wire(b'HIAHLM02', role, parts)
            self.invoke(self.owner, valid[:-1], accepted=False)
            self.invoke(self.owner, valid + b'\0', accepted=False)

    def test_current_checker_retains_exact_five_fields_and_three_digest_bindings(self):
        for role, kind in EXTENDED_INSTALLED_HELPERS:
            expected = self.expected(kind)
            valid = json.dumps(expected, separators=(',', ':')).encode()
            self.check(13, role, kind, valid)
            # Independent parser retains the complete historical whitespace/order domain.
            reversed_fields = dict(reversed(list(expected.items())))
            self.check(13, role, kind, json.dumps(reversed_fields, indent=4).encode())
            for field in expected:
                bad = dict(expected)
                bad[field] = 'wrong'
                self.check(13, role, kind, json.dumps(bad).encode(), accepted=False)
                bad = dict(expected)
                del bad[field]
                self.check(13, role, kind, json.dumps(bad).encode(), accepted=False)
            bad = dict(expected, unknown='field')
            self.check(13, role, kind, json.dumps(bad).encode(), accepted=False)
            self.check(13, role, kind, valid[:-1] + b',"schema":"duplicate"}', accepted=False)
            self.check(13, role, kind, valid + b'x', accepted=False)
            parts = self.parts(kind)
            self.check(13, role, kind, valid, source=parts[0] + b'\n', accepted=False)
            self.check(13, role, kind, valid, image=parts[1] + b'\0', accepted=False)
            self.check(13, role, kind, valid, compiler=parts[3] + b'\0', accepted=False)


if __name__ == '__main__':
    unittest.main()
