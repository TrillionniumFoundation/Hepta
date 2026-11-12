"""No-model argv isolation and bounded original-failure evidence controls."""
from copy import deepcopy
from hashlib import sha256
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_ndu_optimizer import OptimizationRejected, _native_rank
from hepta.hia_rust_crosscheck import HIARustCrosscheckRejected, _run_bounded_shadow
from tools.hia_macro_exec_adapter import (DISABLED_FEATURES, LEGACY_DISABLED_FEATURES,
    ENABLED_DEPENDENCIES, EXACT_SKIP_SKILL_WARNING, adapt, checked_bytes, restrictions)
from tools.hia_macro_multistep_provider import command, validate_launch
from tools import qualify_hia_cli_public_capability as public_pilot


class ExecAdapterTests(unittest.TestCase):
    def setUp(self):
        self.output = Path('/registered/provider-task1-ordinary-2')
        self.config = {'schema':'hepta.hia.explicit-codex-launch-config.v3',
            'model':'codex-auto-review','campaign_root':'/registered','task_ids':['task1'],
            'real_cli':{'path':'/original/codex','sha256':'a'*64,'bytes':10},
            'disabled_features':list(DISABLED_FEATURES),'feature_list_sha256':'b'*64,
            'enabled_dependencies':list(ENABLED_DEPENDENCIES),
            'registered_startup_warnings':[EXACT_SKIP_SKILL_WARNING],
            'host_dependency_identity':{'path':'/original/codex-code-mode-host','sha256':'e'*64,'bytes':12},
            'adapter_module_sha256':'c'*64}
        self.args = command('/launcher','codex-auto-review','low',self.output)

    def test_exact_schema_model_and_local_paths_admitted(self):
        argv, directory = adapt(self.args[1:],self.output/'cwd',self.config)
        self.assertEqual(directory,self.output)
        self.assertEqual(argv[0],'/original/codex')
        self.assertEqual(argv[1:18],self.args[1:-1] + ['--ignore-user-config'])
        self.assertEqual(argv[-1],'-')
        for setting in ('mcp_servers={}','plugins={}','features.browser_use=false',
                        'features.computer_use=false','features.image_generation=false'):
            self.assertIn(setting,argv)
        self.assertFalse(any('guardian' in value for value in restrictions(self.config)))
        self.assertIn('features.code_mode_host=true',argv)
        self.assertNotIn('features.code_mode_host=false',argv)

    def test_legacy_flags_are_reconstructed_only_under_the_explicit_old_version(self):
        old = {**self.config,'schema':'hepta.hia.explicit-codex-launch-config.v2',
            'disabled_features':list(LEGACY_DISABLED_FEATURES)}
        self.assertIn('features.code_mode_host=false',restrictions(old))
        changed = {**old,'schema':'hepta.hia.explicit-codex-launch-config.v3'}
        with self.assertRaises(ValueError):
            restrictions(changed)

    def test_host_dependency_or_additional_allowed_error_cannot_be_substituted(self):
        for field,value in (('enabled_dependencies',[]),
                ('registered_startup_warnings',[EXACT_SKIP_SKILL_WARNING,'Code Mode is unavailable'])):
            with self.assertRaises(ValueError):
                restrictions({**self.config,field:value})

    def test_unregistered_model_effort_schema_state_or_extra_flags_reject(self):
        for index,value in ((8,'/unrelated/schema.json'),(10,'sqlite_home="/unrelated"'),
                            (14,'model_reasoning_effort="high"'),(16,'other-model')):
            args = self.args[:]
            args[index] = value
            with self.assertRaises(ValueError):
                adapt(args[1:],self.output/'cwd',self.config)
        with self.assertRaises(ValueError):
            adapt(self.args[1:]+['--extra'],self.output/'cwd',self.config)

    def test_unregistered_matrix_paths_and_fourth_round_reject(self):
        for output in (Path('/registered/provider-task1-ordinary-4'),
                       Path('/registered/provider-unknown-ordinary-1'),
                       Path('/elsewhere/provider-task1-ordinary-2')):
            args = command('/launcher','codex-auto-review','low',output)
            with self.assertRaises(ValueError):
                adapt(args[1:],output/'cwd',self.config)

    def test_underlying_cli_is_distinct_from_launcher_in_original_receipt(self):
        actual,_ = adapt(self.args[1:],self.output/'cwd',self.config)
        binding = {'configuration':self.config,'underlying_cli':self.config['real_cli'],
                   'launcher':{'path':'/launcher','sha256':'d'*64,'bytes':20}}
        process = {'argv':self.args,'cwd':str(self.output/'cwd'),'pid':42}
        launch = {'schema':'hepta.hia.explicit-codex-exec-adapter.v2','incoming_argv':self.args,
            'actual_exec_argv':actual,'cwd':process['cwd'],'actual_cli':binding['underlying_cli'],
            'adapter_path':'/launcher','adapter_sha256':'d'*64,'adapter_module_sha256':'c'*64,
            'host_dependency_observation':self.config['host_dependency_identity'],
            'capability_restrictions':restrictions(self.config),'registered_feature_list_sha256':'b'*64,
            'pid_before_exec':42,'pgid_before_exec':42,'network_permissions_or_auth_files_modified':False,
            'new_process_group_created_by_adapter':False,'complete_capability_isolation_attested':False}
        validate_launch(launch,process,binding)
        wrong = deepcopy(launch)
        wrong['actual_cli'] = binding['launcher']
        with self.assertRaises(ValueError):
            validate_launch(wrong,process,binding)

    def test_identity_reader_rejects_changed_oversized_or_symlink_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'source'
            path.write_bytes(b'exact')
            expected = sha256(b'exact').hexdigest()
            self.assertEqual(checked_bytes(path,expected,maximum=5),5)
            with self.assertRaises(ValueError):
                checked_bytes(path,expected,maximum=4)
            path.write_bytes(b'other')
            with self.assertRaises(ValueError):
                checked_bytes(path,expected,maximum=5)
            linked = Path(directory)/'symlink'
            linked.symlink_to(path)
            with self.assertRaises(OSError):
                checked_bytes(linked,expected,maximum=5)


@unittest.skipUnless(sys.platform == 'linux','bounded shadow ownership is Linux-specific')
class NativeOriginalObservationTests(unittest.TestCase):
    def test_nonzero_preserves_complete_original_streams_and_old_tuple(self):
        seen = []
        result = _run_bounded_shadow([sys.executable,'-c',
            'import os; os.write(1,b"original-out"); os.write(2,b"original-error"); raise SystemExit(7)'],
            b'original-input',2,observer=seen.append)
        self.assertEqual(result,(b'original-out',b'original-error',7))
        self.assertEqual(len(seen),1)
        self.assertTrue(seen[0]['streams_complete'])
        self.assertTrue(seen[0]['cleanup_confirmed'])
        self.assertEqual(seen[0]['stderr'],b'original-error')

    def test_timeout_preserves_only_observed_prefix_and_original_rejection(self):
        seen = []
        with self.assertRaisesRegex(HIARustCrosscheckRejected,'execution deadline'):
            _run_bounded_shadow([sys.executable,'-c',
                'import os,time; os.write(1,b"prefix"); os.write(2,b"diagnostic"); time.sleep(3)'],
                b'',0.2,observer=seen.append)
        self.assertEqual(len(seen),1)
        self.assertEqual(seen[0]['stdout'],b'prefix')
        self.assertEqual(seen[0]['stderr'],b'diagnostic')
        self.assertFalse(seen[0]['streams_complete'])
        self.assertTrue(seen[0]['cleanup_confirmed'])
        self.assertIn('deadline',seen[0]['error']['message'])

    def test_output_limit_retains_triggering_read_with_a_bounded_prefix(self):
        seen = []
        with self.assertRaisesRegex(HIARustCrosscheckRejected,'output budget'):
            _run_bounded_shadow([sys.executable,'-c','import os; os.write(1,b"x"*5000)'],
                b'',2,maximum_output=100,observer=seen.append)
        self.assertGreaterEqual(len(seen[0]['stdout']),100)
        self.assertLessEqual(len(seen[0]['stdout']),100+4095)
        self.assertFalse(seen[0]['streams_complete'])

    def test_native_rank_keeps_raw_nonzero_rejection_before_validation(self):
        seen = []
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)/'fixture'
            path.write_bytes(b'fixture')
            image = type('Image',(),{'path':path,'data':b'fixture'})()
            native_identity = {'binary_sha256':sha256(b'fixture').hexdigest()}
            def pump(*args,**kwargs):
                kwargs['observer']({'stdout':b'non-json','stderr':b'AbstainInfeasible',
                    'streams_complete':True,'eof':{'stdout':True,'stderr':True},
                    'cleanup_confirmed':True,'returncode':2,'error':None})
                return b'non-json',b'AbstainInfeasible',2
            with patch('hepta.hia_ndu_optimizer._bridge_identity',return_value=(image,native_identity)), \
                 patch('hepta.hia_ndu_optimizer._seal_bridge_image',side_effect=lambda raw:os.open(path,os.O_RDONLY)), \
                 patch('hepta.hia_ndu_optimizer._run_bounded_shadow',side_effect=pump):
                with self.assertRaisesRegex(OptimizationRejected,'failed or exceeded output bounds'):
                    _native_rank({}, {'schema':'authored-test'},timeout_s=2,observer=seen.append)
        self.assertEqual(len(seen),1)
        self.assertEqual(seen[0]['pump']['stderr'],b'AbstainInfeasible')
        self.assertEqual(seen[0]['stdin'],b'{"schema":"authored-test"}')
        self.assertFalse(seen[0]['response_admitted'])
        self.assertEqual(seen[0]['error']['type'],'OptimizationRejected')


class PublicCapabilityPilotTests(unittest.TestCase):
    def prepare_fixture(self, root):
        cli = root/'codex'
        cli.write_bytes(b'authored non-executable CLI identity fixture')
        cli.chmod(0o700)
        host = root/'codex-code-mode-host'
        host.write_bytes(b'authored dependency identity fixture')
        host.chmod(0o700)
        registry = root/'features.txt'
        registry.write_text('\n'.join(name+' stable false'
            for name in (*DISABLED_FEATURES,*ENABLED_DEPENDENCIES,'skip_host_skill_discovery'))+'\n')
        plan_path = root/'PLAN.json'
        plan = public_pilot.prepare(plan_path,real_cli=cli,feature_list=registry,
            execution_directory=root/'execution')
        return plan_path,plan

    def test_public_only_preparation_pins_host_and_explicit_small_budget_without_execution(self):
        with tempfile.TemporaryDirectory() as directory,patch.object(public_pilot,'run_owned') as execute:
            path,plan = self.prepare_fixture(Path(directory))
            self.assertEqual(plan['budget']['cli_sessions'],1)
            self.assertEqual(plan['budget']['wall_seconds'],60)
            self.assertEqual(plan['budget']['conservative_model_tokens'],8192)
            self.assertIn('features.code_mode_host=true',plan['actual_argv'])
            self.assertFalse(plan['private_task_inputs_loaded'])
            self.assertFalse(plan['campaign_restart_authorized_by_pilot'])
            self.assertFalse(Path(plan['execution_directory']).exists())
            execute.assert_not_called()

    def test_unknown_usage_and_original_output_directory_refuse_a_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            path,plan = self.prepare_fixture(Path(directory))
            def no_model(argv,cwd,output,**kwargs):
                output.mkdir()
                for name,raw in {'stdin.raw':kwargs['input_bytes'],'stdout.raw':b'',
                        'stderr.raw':b'authored no-model unknown outcome fixture'}.items():
                    (output/name).write_bytes(raw)
                return {'status':'protocol_violation','pid':123,'returncode':-9,
                    'cleanup_confirmed':True,'leader_reaped':True,'streams_complete':True}
            digest=sha256(path.read_bytes()).hexdigest()
            with patch.object(public_pilot,'run_owned',side_effect=no_model) as execute:
                result=public_pilot.run(path,digest)
                self.assertFalse(result['passed'])
                self.assertIsNone(result['parsed']['usage'])
                self.assertIsNone(result['parsed']['charged_model_tokens'])
                self.assertFalse(result['failed_attempt_retried'])
                with self.assertRaises(FileExistsError):
                    public_pilot.run(path,digest)
                execute.assert_called_once()


if __name__ == '__main__':
    unittest.main()
