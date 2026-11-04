"""Do not accept historical raw binaries or changed build streams as a fresh composition."""
import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import qualify_hia_composition as subject


class RawCompositionIdentityTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix='hia-raw-build-identity-')
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        files = {'rust/hia-ndu-raw-model/Cargo.toml':'locked adapter\n',
                 'rust/hia-ndu-raw-model/src/main.rs':'selected source\n',
                 'tools/build_hia_ndu_bridge.py':'selected builder\n',
                 'build/command-evidence/cargo.stdout':'actual stdout\n',
                 'build/command-evidence/cargo.stderr':'actual stderr\n',
                 'target/release/hia-ndu-bridge':'actual image\n'}
        for name, text in files.items():
            path = self.root/name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        self.tools = {'cargo':{'path':'/fixed/cargo','version':'cargo 1.95.0 (fixed)'},
                      'rustc':{'version':'rustc 1.95.0 (fixed)'}}
        command = {'schema':'hepta.hia.ndu.build-command.v1',
                   'argv':['/fixed/cargo','build','--manifest-path',str(self.root/'build/Cargo.toml'),
                           '-p','hia-ndu-bridge','--locked','--release'],
                   'cwd':str(self.root),'wall_ns':12000,
                   'returncode':0,'launch_error':None,'original_streams_retained':True}
        for stream in ('stdout','stderr'):
            name = 'command-evidence/cargo.'+stream
            path = self.root/'build'/name
            command[stream] = {'path':name,'bytes':path.stat().st_size,'sha256':subject.digest(path)}
        adapter = self.root/'rust/hia-ndu-raw-model'
        self.manifest = {'schema':'hepta.hia.ndu-build.v1',
            'upstream':{'commit':subject.NDU_SOURCE_PIN},
            'original_rust_sources_unchanged':True,'all_original_non_manifest_inputs_unchanged':True,
            'build_inputs_unchanged':True,'locked_dependencies':True,'isolated_production_manifests':True,
            'adapter_files':{str(p.relative_to(adapter)):subject.digest(p) for p in adapter.rglob('*') if p.is_file()},
            'builder_sha256':subject.digest(self.root/'tools/build_hia_ndu_bridge.py'),
            'rustc_version':self.tools['rustc']['version']+'\nfull version receipt',
            'cargo_version':self.tools['cargo']['version'],
            'binary':str(self.root/'target/release/hia-ndu-bridge'),
            'binary_sha256':subject.digest(self.root/'target/release/hia-ndu-bridge'),
            'production_activation':False,
            'build_cost':{'schema':'hepta.hia.ndu.build-cost.v1','completed':True,'wall_ns':12345,
                          'cargo_wall_ns':12000,'parent_cpu_ns':123,'child_cpu_ns':456,
                          'scope':'observed bounded fixture','fully_cold_machine_claim':False,
                          'target_cache_at_start':'absent'},
            'build_command':command['argv'],'build_command_evidence':command}
        self.receipt = self.root/'build/build-receipt.json'

    def validate(self, manifest):
        self.receipt.write_text(json.dumps(manifest))
        with patch.object(subject, 'ROOT', self.root):
            return subject.validate_raw_build(self.receipt,self.tools)

    def test_tool_identity_keeps_symlink_driver_invocation_name(self):
        implementation = self.root/'real-driver'
        implementation.write_text('#!/usr/bin/env python3\nimport sys\nprint(sys.argv[0])\n')
        implementation.chmod(0o755)
        invocation = self.root/'clang++'
        invocation.symlink_to(implementation)
        observed = subject.executable(invocation)
        self.assertEqual(observed['path'],str(invocation))
        self.assertEqual(observed['resolved_path'],str(implementation))
        self.assertEqual(observed['version'],str(invocation))
        self.assertEqual(observed['sha256'],subject.digest(implementation))

    def test_current_bound_manifest_is_accepted(self):
        self.assertEqual(self.validate(self.manifest),self.manifest)

    def test_failed_process_launch_retains_attempt_cost_and_original_streams(self):
        row = subject.run_command(self.root,'missing-compiler',[self.root/'absent-compiler'])
        self.assertIsNone(row['returncode'])
        self.assertEqual(row['launch_error']['type'],'FileNotFoundError')
        self.assertGreater(row['wall_ns'],0)
        saved = json.loads((self.root/'missing-compiler.command.json').read_text())
        self.assertEqual(saved,row)
        self.assertEqual(set(row['logs']),{'missing-compiler.stdout','missing-compiler.stderr'})

    def test_boolean_returncode_and_changed_fixed_argv_are_rejected(self):
        changed = copy.deepcopy(self.manifest)
        changed['build_command_evidence']['returncode'] = False
        with self.assertRaises(ValueError):
            self.validate(changed)
        changed = copy.deepcopy(self.manifest)
        changed['build_command'].append('--offline')
        changed['build_command_evidence']['argv'] = list(changed['build_command'])
        with self.assertRaises(ValueError):
            self.validate(changed)

    def test_historical_or_incomplete_build_cannot_join_composition(self):
        cases = [('rustc_version','rustc 1.96.0 (historical)'),('adapter_files',{}),
                 ('original_rust_sources_unchanged',False),('production_activation',True),
                 ('build_cost',{'completed':True,'wall_ns':0,'target_cache_at_start':'absent'}),
                 ('build_cost',{'completed':True,'wall_ns':True,'target_cache_at_start':'absent'}),
                 ('build_cost',{'completed':True,'wall_ns':12345,'target_cache_at_start':'warm'})]
        for key, value in cases:
            with self.subTest(key=key,value=value),self.assertRaises(ValueError):
                self.validate({**self.manifest,key:value})

    def test_actual_image_and_command_streams_are_rechecked(self):
        for name in ('target/release/hia-ndu-bridge','build/command-evidence/cargo.stdout',
                     'build/command-evidence/cargo.stderr'):
            path = self.root/name
            original = path.read_bytes()
            path.write_bytes(original+b'changed')
            with self.subTest(name=name),self.assertRaises(ValueError):
                self.validate(self.manifest)
            path.write_bytes(original)

    def test_retained_stream_cannot_escape_build_directory(self):
        changed = copy.deepcopy(self.manifest)
        changed['build_command_evidence']['stdout']['path'] = '../target/release/hia-ndu-bridge'
        with self.assertRaises(ValueError):
            self.validate(changed)


if __name__ == '__main__':
    unittest.main()
