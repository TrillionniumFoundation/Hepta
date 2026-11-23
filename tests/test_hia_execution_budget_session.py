"""Exercise the budget state machine across real native process messages."""
from pathlib import Path
import struct
import subprocess
import tempfile
import unittest

from tests.test_hia_execution_budget_native import CONTEXT, OWNER, VM, packet, witnesses
from tools.generate_hia_execution_budget_session import ADAPTER, PACKER, PACK_MAGIC
from tools.generate_hia_native_filter import read_adapter_binding, verify_adapter
from tools.qualify_hia_selfhost import build_seed, compile_stage

ROOT = Path(__file__).resolve().parents[1]
SIZE = struct.Struct('<Q')


def framed(payload):
    return SIZE.pack(len(payload)) + payload


class BudgetSessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        tmp = tempfile.TemporaryDirectory(prefix='hia-budget-session-')
        cls.addClassCleanup(tmp.cleanup)
        root = Path(tmp.name)
        seed, _ = build_seed(root)
        source = (ROOT / 'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first, _ = compile_stage(root, 'B1', seed, source, image_format='seed-shared')
        compiler, _ = compile_stage(root, 'B2', first, source)
        if compiler.read_bytes() != first.read_bytes():
            raise AssertionError('selfhost generations disagree')
        policy, _ = compile_stage(root, 'budget', compiler,
                                  (ROOT / 'examples/hia_bootstrap/execution_budget.hepta').read_bytes())
        packer, _ = compile_stage(root, 'session-packer', compiler, (ROOT / PACKER).read_bytes())
        image = policy.read_bytes()
        cls.session, _ = compile_stage(root, 'session', packer,
                                       struct.pack('<2Q', PACK_MAGIC, len(image)) + image,
                                       output_extension='.elf')
        binding = read_adapter_binding((ROOT / PACKER).read_bytes(), (ROOT / ADAPTER).read_bytes(), calls=1)
        verify_adapter(cls.session.read_bytes(), image, binding, entries=(0,))
        cls.session.chmod(0o500)

    def result(self, data, *args):
        return subprocess.run([self.session, *args], input=data, capture_output=True,
                              env={'PATH': ''}, timeout=10)

    def test_all_original_claim_run_and_completion_receipts(self):
        rows = witnesses(VM())
        expected = b''.join(framed(reply) for _, (_, reply, _) in rows)
        actual = self.result(b''.join(framed(request) for request, _ in rows))
        self.assertEqual((actual.returncode, actual.stdout, actual.stderr), (0, expected, b''))

    def test_loss_of_ack_and_stale_owner_preserve_exact_refusal(self):
        init = packet(0, values=(1, 5, 1000000, len(CONTEXT), len(OWNER)), payload=CONTEXT + OWNER)
        cases = ((init, packet(1, 1, (1,), connection=(99, 100))),
                 (init, packet(1, 1, (0,))), (init, init),
                 (packet(4, 5, (1,)),))
        for events in cases:
            with self.subTest(events=events):
                oracle = VM()
                replies = [oracle.call(event)[1] for event in events]
                expected = b''.join(framed(reply) for reply in replies)
                result = self.result(b''.join(framed(event) for event in events))
                self.assertEqual((result.returncode, result.stdout, result.stderr), (0, expected, b''))
                self.assertNotEqual(struct.unpack_from('<Q', replies[-1], 8)[0], 0)

    def test_partial_or_oversized_frames_never_emit_an_extra_ack(self):
        good = packet(0, values=(2, 0, 0, len(CONTEXT), 0), payload=CONTEXT)
        first = framed(VM().call(good)[1])
        for suffix in (b'\x01', SIZE.pack(127), SIZE.pack(4701), SIZE.pack(128) + b'x' * 127,
                       framed(bytes(128))):
            with self.subTest(suffix=suffix[:8]):
                result = self.result(framed(good) + suffix)
                self.assertEqual((result.returncode, result.stdout, result.stderr), (4, first, b''))
        self.assertEqual(self.result(b'').returncode, 0)
        self.assertEqual(self.result(b'', 'unexpected').returncode, 4)

    def test_one_frame_is_observed_before_stdin_closes(self):
        init = packet(0, values=(2, 0, 0, len(CONTEXT), 0), payload=CONTEXT)
        expected = framed(VM().call(init)[1])
        with subprocess.Popen([self.session], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, env={'PATH': ''}) as proc:
            import select
            try:
                proc.stdin.write(framed(init))
                proc.stdin.flush()
                self.assertTrue(select.select([proc.stdout], [], [], 5)[0])
                self.assertEqual(proc.stdout.read(len(expected)), expected)
                self.assertIsNone(proc.poll())
                proc.stdin.close()
                self.assertEqual(proc.wait(timeout=5), 0)
            finally:
                if proc.poll() is None:
                    proc.kill()
                    proc.wait()
