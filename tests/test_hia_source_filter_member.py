"""Rebuild the ordinary two/three-image Store filters from a qualified native source seed."""
from hashlib import sha256
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory
import unittest

from hepta.hia_agent_assembly import assemble_program

ROOT = Path(__file__).resolve().parents[1]
SOURCES = ROOT / 'examples/hia_bootstrap'
POLICY = SOURCES / 'source_filter_member.hepta'
# The public release names differ from source stems for these three members.
SPECIAL = {
    'hia-evaluate-projector': ('evaluate_reference_wire', 'evaluate_reference_wire_filter_packer'),
    'hia-execution-budget-session': ('execution_budget', 'execution_budget_session_packer'),
    'hia-safe-core-loader': ('safe_core_elf_inventory', 'safe_core_loader_filter_packer'),
}
CANONICAL = {'hia-evaluate-cost-ledger', 'hia-evaluate-run-plan'}
MEMBERS = tuple('hia-evaluate-' + name for name in (
    'budget-observation', 'budget-store', 'cost-ledger', 'cost-ledger-flow', 'measurements',
    'native-report', 'paired-batch', 'publication', 'reference-batch', 'reference-report',
    'report-flow', 'run-plan', 'settlement')) + tuple(SPECIAL)


class SourceFilterMemberTests(unittest.TestCase):
    def test_native_policy_is_valid_assembly(self):
        self.assertGreater(len(assemble_program(POLICY.read_bytes()).as_dict()['functions']), 3)

    @unittest.skipUnless(os.environ.get('HIA_TEST_NATIVE_FILTER_RELEASE'), 'requires a qualified, installed Store')
    def test_from_native_sources_against_every_installed_member(self):
        release = Path(os.environ['HIA_TEST_NATIVE_FILTER_RELEASE']).resolve()
        sources = Path(os.environ.get('HIA_TEST_NATIVE_FILTER_SOURCES', SOURCES)).resolve()
        seed = release / 'hia-source-build'
        with TemporaryDirectory() as temp:
            work = Path(temp)
            def invoke(argv, wire=b'', *, refused=False):
                result = subprocess.run(argv, input=wire, capture_output=True, cwd=work,
                                        env={'PATH': ''}, timeout=120)
                self.assertEqual(result.stderr, b'')
                if refused:
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, b'')
                else:
                    self.assertEqual(result.returncode, 0)
                return result.stdout

            def source_images(directory, named_sources):
                directory.mkdir(mode=0o700)
                for name, path in named_sources.items():
                    member = directory / name
                    member.write_bytes(path.read_bytes())
                    member.chmod(0o400)
                # The native directory packer emits a SHA256 receipt on stderr.
                packed = subprocess.run([release / 'hia-directory-package-build', directory],
                                        capture_output=True, cwd=work, env={'PATH': ''}, timeout=120)
                self.assertEqual(packed.returncode, 0)
                self.assertEqual(packed.stderr, (sha256(packed.stdout).hexdigest() + '\n').encode())
                self.assertEqual(packed.stdout[:8], b'HIAREL01')
                return invoke([seed, 'build'], packed.stdout)

            for name in MEMBERS:
                with self.subTest(member=name):
                    path = work / name
                    path.mkdir(mode=0o700)
                    stem = name[4:].replace('-', '_')
                    app, packer = SPECIAL.get(name, (stem, stem + '_packer'))
                    kit = source_images(path / 'kit', {
                        'source_build_policy.hepta': POLICY, 'selfhost.hepta': sources / 'selfhost.hepta',
                        'source_build_packer.hepta': sources / (packer + '.hepta')})
                    builder = path / 'member-builder'
                    builder.write_bytes(invoke([seed, 'pack'], kit))
                    builder.chmod(0o500)
                    inputs = {app + '.hepta': sources / (app + '.hepta')}
                    if name in CANONICAL:
                        inputs['worker_request.hepta'] = sources / 'worker_request.hepta'
                    images = source_images(path / 'inputs', inputs)
                    self.assertEqual(invoke([builder, 'build'], images), (release / name).read_bytes())
                    for rejected in (images[:-1], images + b'x', b'badmagic' + images[8:],
                                     images[:-1] + bytes((images[-1] ^ 1,))):
                        invoke([builder, 'build'], rejected, refused=True)
                    if name in CANONICAL:
                        alone = source_images(path / 'missing-canonical', {app + '.hepta': inputs[app + '.hepta']})
                        invoke([builder, 'build'], alone, refused=True)
                    if name == 'hia-evaluate-settlement':
                        other = path / 'wrong-role'
                        packet = source_images(other, {'evaluate_measurements.hepta': sources / 'evaluate_measurements.hepta'})
                        invoke([builder, 'build'], packet, refused=True)
                        invoke([builder, 'compile'], images, refused=True)
