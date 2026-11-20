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

    def test_job_identity_keeps_the_original_durable_binding_bytes(self):
        binding = (b'{"args":["-B","-m","hepta.hia_agent_worker"],'
                   b'"cpu_quota_percent":100,"cwd":"/workspace","env":{"LC_ALL":"C.UTF-8"},'
                   b'"executable":"/python","host":"worker","memory_max_bytes":1073741824,'
                   b'"nice":0,"stdin":"'
                   + b'a' * (1 << 20) + b'","timeout_seconds":120}')
        for body in (binding, binding.replace(b'"worker"', b'"other"'), b'{}'):
            answer = self.invoke(b'HIAJID01' + body)
            self.assertEqual((answer.returncode, answer.stderr), (0, b''))
            self.assertEqual(answer.stdout, b'HIAJDO01' + text_digest(body))
        for body in (b'', b'[]', b'{}\n'):
            answer = self.invoke(b'HIAJID01' + body)
            self.assertEqual((answer.returncode, answer.stdout, answer.stderr), (2, b'', b''))

    def test_job_reuse_requires_both_original_bindings_without_promoting_legacy_records(self):
        digest = text_digest(b'{"binding":"original"}')
        fingerprint = int(digest[:16], 16)
        different_tail = b'1' if digest.endswith(b'0') else b'0'
        for prefix, present, observed, decision in (
            (fingerprint, 1, digest, 0),
            (fingerprint, 1, digest[:-1] + different_tail, 1),
            (fingerprint ^ 1, 1, digest, 1),
            (fingerprint, 1, digest[:-1], 1),
            (fingerprint, 1, b'', 1),
            (fingerprint, 0, b'', 2),
        ):
            with self.subTest(present=present, prefix=prefix, length=len(observed), decision=decision):
                result = self.invoke(struct.pack('<8s2Q', b'HIAJRE01', prefix, present) + digest + observed)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, struct.pack('<8sQ', b'HIAJRO01', decision), b''))
        for invalid in (
            struct.pack('<8s2Q', b'HIAJRE01', fingerprint, 2) + digest,
            struct.pack('<8s2Q', b'HIAJRE01', fingerprint, 0) + digest + b'x',
            struct.pack('<8s2Q', b'HIAJRE01', fingerprint, 1) + b'Z' * 64 + digest,
        ):
            result = self.invoke(invalid)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b'', b''))

    def test_session_scope_never_substitutes_stdio_or_switches_existing_credentials(self):
        owner = text_digest(b'trusted session owner')
        replaced = owner[:-1] + (b'1' if owner.endswith(b'0') else b'0')
        for mode, prior, current, incumbent, verdict in (
            (0, 0, owner, b'', 0), (1, 0, owner, b'', 0),
            (0, 1, owner, owner, 0), (1, 2, owner, owner, 0),
            (0, 2, owner, owner, 3), (1, 1, owner, owner, 3),
            (0, 1, replaced, owner, 3), (1, 2, replaced, owner, 3),
            (1, 2, b'', owner, 1), (0, 1, b'', owner, 2),
            (0, 0, b'G' * 64, b'', 2), (1, 0, b'a' * 65, b'', 1),
        ):
            frame = struct.pack('<8s3Q64s64s', b'HIASCO01', mode, len(current), prior, current, incumbent)
            result = self.invoke(frame)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (0, struct.pack('<8sQ', b'HIASCR01', verdict), b''))
        for invalid in (
            struct.pack('<8s3Q64s64s', b'HIASCO01', 2, 64, 0, owner, b''),
            struct.pack('<8s3Q64s64s', b'HIASCO01', 0, 64, 3, owner, owner),
            struct.pack('<8s3Q64s64s', b'HIASCO01', 0, 64, 1, owner, b'X' * 64),
        ):
            result = self.invoke(invalid)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b'', b''))

    def test_durable_transition_never_relaunches_uncertain_operator_or_observation_paths(self):
        states = (b'launched', b'pending', b'launch_failed', b'launch_unknown', b'cancelled', b'future')
        for flags in range(8):
            for state in states:
                with self.subTest(flags=flags, state=state):
                    wanted = 0
                    if state == b'launched':
                        wanted = 1
                    elif flags == 7 and state in (b'pending', b'launch_failed'):
                        wanted = 2
                    frame = struct.pack('<8s2Q56s', b'HIAJTR01', flags, len(state), state)
                    result = self.invoke(frame)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (0, struct.pack('<8sQ', b'HIAJTO01', wanted), b''))
        for flags, size in ((8, 0), (0, 57)):
            result = self.invoke(struct.pack('<8s2Q56s', b'HIAJTR01', flags, size, b''))
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b'', b''))

    def test_http_auth_returns_only_a_verdict_and_checks_the_entire_digest(self):
        for size in (32, 55, 56, 63, 64, 65, 4096):
            known = (b'isolated-private-header-credential-' * 132)[:size]
            expected = text_digest(known)
            different_digest = expected[:-1] + (b'1' if expected.endswith(b'0') else b'0')
            different_token = known[:-1] + (b'+' if known.endswith(b'-') else b'-')
            for digest, supplied, verdict in (
                    (expected, known, 1), (different_digest, known, 0),
                    (expected, different_token, 0)):
                with self.subTest(length=size, verdict=verdict):
                    result = self.invoke(b'HIAHAT01' + digest + supplied)
                    self.assertEqual((result.returncode, result.stdout, result.stderr),
                                     (0, struct.pack('<8sQ', b'HIAHAO01', verdict), b''))
        for invalid in (b'', b'x' * 31, b'x' * 4097):
            result = self.invoke(b'HIAHAT01' + b'0' * 64 + invalid)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b'', b''))

    def test_launch_ack_binds_whole_job_and_unit_and_distinguishes_unknowns(self):
        job = b'job-' + b'7' * 64
        unit = job + b'.service'

        def frame(flags, backend, *, actual_job=b'', actual_unit=b'', state=b'', pid=0):
            fields = (backend, actual_job, job, actual_unit, unit, state)
            return struct.pack('<8s2Q', b'HIAJAK01', flags, pid) + b''.join(
                struct.pack('<Q256s', len(field), field) for field in fields
            )

        for supplied, wanted in (
            (frame(0, b'systemd', actual_unit=unit), 0),
            (frame(1, b'systemd', actual_unit=unit), 1),
            (frame(1, b'systemd', actual_unit=unit[:-1] + b'X'), 0),
            (frame(1, b'systemd_system'), 0),
            (frame(3, b'systemd_system'), 1),
            (frame(11, b'systemd_system'), 0),
            (frame(11, b'systemd_system', actual_job=job), 1),
            (frame(11, b'systemd_system', actual_job=job[:-1] + b'X'), 0),
            (frame(7, b'systemd_system', state=b'launched'), 1),
            (frame(7, b'systemd_system', state=b'launch_failed'), 2),
            (frame(7, b'systemd_system', state=b'pending'), 3),
            (frame(7, b'systemd_system', state=b'cancelled'), 4),
            (frame(7, b'systemd_system', state=b'cancelledX'), 5),
            (frame(7, b'systemd_system'), 5),
            (frame(1, b'detached', pid=0), 0),
            (frame(1, b'detached', pid=1), 1),
            (frame(1, b'detached', pid=(1 << 31) - 1), 1),
            (frame(1, b'detached', pid=1 << 31), 0),
            (frame(1, b'completed'), 0),
            (frame(5, b'completed'), 1),
            (frame(5, b'launch_failed'), 2),
            (frame(5, b'launch_failedX'), 0),
        ):
            with self.subTest(flags=supplied[8], backend=supplied[32:48], wanted=wanted):
                result = self.invoke(supplied)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (0, struct.pack('<8sQ', b'HIAJAO01', wanted), b''))
        for invalid in (frame(16, b'systemd'), frame(1, b'x' * 257), frame(1, b'systemd')[:-1]):
            result = self.invoke(invalid)
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b'', b''))

    def test_job_poll_obeys_the_original_monotonic_window_and_exact_state(self):
        def poll(stage, wait, age=0, state=b'', size=None, unconfirmed=0):
            extent = len(state) if size is None else size
            return struct.pack('<8s5Q24s', b'HIAJPL01', stage, wait, age, extent, unconfirmed, state)

        for wait in (0, 1, 29, 30, 31, (1 << 64) - 1):
            answer = self.invoke(poll(0, wait))
            self.assertEqual((answer.returncode, answer.stdout, answer.stderr),
                             (0, struct.pack('<8s2Q', b'HIAJPO01', 0, min(wait, 30)), b''))
        for wait, age, state, delay in (
            (0, 0, b'running', 0),
            (1, 0, b'running', 100),
            (1, 999999999, b'running', 100),
            (1, 1000000000, b'running', 0),
            (30, 29999999999, b'running', 100),
            (30, 30000000000, b'running', 0),
            (30, (1 << 64) - 1, b'running', 0),
            (1, 0, b'runningx', 0),
            (1, 0, b'running\x00', 0),
            (1, 0, b'RUNNING', 0),
            (1, 0, b'exited', 0),
            (1, 0, b'', 0),
        ):
            answer = self.invoke(poll(1, wait, age, state))
            self.assertEqual((answer.returncode, answer.stdout, answer.stderr),
                             (0, struct.pack('<8s2Q', b'HIAJPO01', 1, delay), b''))
        for state, age, unconfirmed, decision in (
            (b'activating', 0, 0, 100),
            (b'activating', 1000000000, 0, 0),
            (b'finalizing', 999999999, 0, 100),
            (b'finalizing', 1000000000, 0, 101),
            (b'finalizing', 1000000000, 1, 0),
            (b'completed_unknown', 999999999, 1, 100),
            (b'completed_unknown', 1000000000, 0, 101),
            (b'completed_unknown', 1000000000, 1, 0),
            (b'completed_unknownx', 1000000000, 0, 0),
            (b'owner_unknown', 0, 0, 0),
            (b'publication_pending', 0, 0, 0),
        ):
            answer = self.invoke(poll(2, 1, age, state, unconfirmed=unconfirmed))
            self.assertEqual((answer.returncode, answer.stdout, answer.stderr),
                             (0, struct.pack('<8s2Q', b'HIAJPO01', 2, decision), b''))
        answer = self.invoke(poll(1, 1, 1000000000, b'finalizing'))
        self.assertEqual((answer.returncode, answer.stdout, answer.stderr),
                         (0, struct.pack('<8s2Q', b'HIAJPO01', 1, 0), b''))
        for invalid in (poll(3, 1), poll(0, 1, 1), poll(0, 1, state=b'running'),
                        poll(1, 31), poll(1, 30, size=25), poll(0, 1, unconfirmed=1),
                        poll(2, 1, unconfirmed=2), poll(0, 1)[:-1]):
            answer = self.invoke(invalid)
            self.assertEqual((answer.returncode, answer.stdout, answer.stderr), (2, b'', b''))

    def test_terminal_state_keeps_unknown_precedence_and_legacy_receipts(self):
        for facts, state in (
            ((1, 1, 1, 0, 0, 0), 1),
            ((0, 1, 1, 0, 2, 2), 2),
            ((0, 0, 1, 0, 2, 2), 3),
            ((0, 0, 0, 0, 2, 2), 0),
            ((0, 0, 0, 2, 0, 0), 4),
            ((0, 0, 0, 1, 2, 1), 4),
            ((0, 0, 0, 1, 1, 2), 4),
            ((0, 0, 0, 1, 0, 0), 5),
            ((0, 0, 0, 1, 1, 0), 5),
            ((0, 0, 0, 1, 0, 1), 5),
            ((0, 0, 0, 1, 1, 1), 5),
        ):
            result = self.invoke(struct.pack('<8s6Q', b'HIAJTS01', *facts))
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (0, struct.pack('<8sQ', b'HIAJTV01', state), b''))
        for index, upper in enumerate((1, 1, 1, 2, 2, 2)):
            facts = [0, 0, 0, 1, 0, 0]
            facts[index] = upper + 1
            result = self.invoke(struct.pack('<8s6Q', b'HIAJTS01', *facts))
            self.assertEqual((result.returncode, result.stdout, result.stderr), (2, b'', b''))

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
