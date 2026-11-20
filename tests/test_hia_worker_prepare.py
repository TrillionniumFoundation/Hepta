"""Compare the standalone HIA encoder to the original byte-level identity rules."""
from __future__ import annotations

from hashlib import sha256
import os
from pathlib import Path
import struct
import subprocess
import unittest

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_worker_prepare import SOURCE_PATH, document


CATALOG = b'0123456789abcdef' * 4
PROFILE = b'{"catalog_sha256":"' + CATALOG + b'","host":"worker"}'
SCHEMA = b'","schema":"hia-agent-worker-request-v1","tool":'
TOOLS = (b'hia_describe', b'hia_artifact', b'hia_read', b'hia_context', b'hia_inspect',
         b'hia_candidate', b'hia_verify', b'hia_emit', b'hia_evaluate', b'hia_adopt',
         b'hia_rollback', b'hia_resource_read')


def text_digest(data):
    return sha256(data).hexdigest().encode('ascii')


def frame(fragments, catalog=CATALOG):
    return struct.pack('<8s5Q64s', b'HIAWPR01', *map(len, fragments), catalog) + b''.join(fragments)


def reference(original, profile, normalized, tool, key):
    profile_pin = text_digest(profile)
    base = (b'{"arguments":' + normalized + b',"catalog_sha256":"' + CATALOG
            + b'","profile_sha256":"' + profile_pin)
    end = SCHEMA + tool + b'}'
    request_pin = text_digest(base + end)
    identity = (b'{"key":' + key if key else b'{"readonly_request_sha256":"' + request_pin + b'"')
    key_pin = text_digest(identity + b',"tool":' + tool + b'}')
    return (b'HIAWPO01' + text_digest(original) + profile_pin + request_pin + key_pin
            + base + b'","request_sha256":"' + request_pin + end + b'\n')


class WorkerPrepareSourceTests(unittest.TestCase):
    def test_checked_in_source_matches_authoring(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual((root / SOURCE_PATH).read_text(), render_assembly(document()))


@unittest.skipUnless(os.environ.get('HIA_TEST_WORKER_PREPARE_EXE'), 'standalone Worker encoder required')
class WorkerPrepareExecutableTests(unittest.TestCase):
    def invoke(self, data):
        return subprocess.run([os.environ['HIA_TEST_WORKER_PREPARE_EXE']], input=data,
                              capture_output=True, timeout=5, env={'PATH': ''})

    def encode(self, fragments):
        result = self.invoke(frame(fragments))
        self.assertEqual((result.returncode, result.stderr), (0, b''))
        self.assertEqual(result.stdout, reference(*fragments))
        return result.stdout

    def test_every_tool_preserves_serde_fragments(self):
        original = ('{"escaped":"\\t\\n\\u0000🌍","number":1e+20,'
                    '"subnormal":5e-324,"zero":-0.0}').encode()
        for tool in TOOLS:
            with self.subTest(tool=tool):
                token = b'"' + tool + b'"'
                self.encode((original, PROFILE, original, token, b''))
                self.encode((original, PROFILE, original, token, '"雪\\tkey"'.encode()))

    def test_identity_separates_original_spelling_from_worker_normalization(self):
        canonical = b'{"source":{"path":"/root/source"}}'
        uri = b'{"source":{"path":"ssh://worker/root/source"}}'
        key = b'"fixed"'
        baseline = self.encode((canonical, PROFILE, canonical, b'"hia_artifact"', key))
        alternate = self.encode((uri, PROFILE, canonical, b'"hia_artifact"', key))
        changed = self.encode((uri, PROFILE, uri, b'"hia_artifact"', key))
        self.assertNotEqual(baseline[8:72], alternate[8:72])
        self.assertEqual(baseline[72:], alternate[72:])
        self.assertNotEqual(alternate[136:200], changed[136:200])
        self.assertEqual(alternate[200:264], changed[200:264])

    def test_readonly_key_follows_payload_and_profile(self):
        original = (b'{}', PROFILE, b'{}', b'"hia_describe"', b'')
        baseline = self.encode(original)
        changed_profile = self.encode((b'{}', b'{"host":"other"}', *original[2:]))
        changed_payload = self.encode((b'{}', PROFILE, b'{"more":true}', *original[3:]))
        self.assertNotEqual(baseline[200:264], changed_profile[200:264])
        self.assertNotEqual(baseline[200:264], changed_payload[200:264])

    def test_size_limit_includes_newline(self):
        raw = b'{"data":""}'
        tool = b'"hia_candidate"'
        overhead = len(reference(raw, PROFILE, raw, tool, b'')[264:])
        exact = b'{"data":"' + b'a' * ((512 << 10) - overhead) + b'"}'
        accepted = self.encode((exact, PROFILE, exact, tool, b''))
        self.assertEqual(len(accepted) - 264, 512 << 10)
        excess = exact[:-2] + b'a"}'
        rejected = self.invoke(frame((excess, PROFILE, excess, tool, b'')))
        self.assertEqual((rejected.returncode, rejected.stdout, rejected.stderr), (3, b'', b''))

    def test_invalid_frames_leave_stdout_empty(self):
        normal = frame((b'{}', PROFILE, b'{}', b'"hia_describe"', b''))
        for invalid in (b'', normal[:111], normal[:-1], normal + b'z',
                        b'notmagic' + normal[8:],
                        normal[:8] + struct.pack('<Q', (1 << 64) - 1) + normal[16:],
                        frame((b'{}', PROFILE, b'{}', b'"hia_describe"', b''), b'G' * 64),
                        frame((b'{}', PROFILE, b'[]', b'"hia_describe"', b'')),
                        frame((b'{}', PROFILE, b'{}', b'hia_describe', b''))):
            with self.subTest(frame_bytes=len(invalid)):
                result = self.invoke(invalid)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b'', b''))


if __name__ == '__main__':
    unittest.main()
