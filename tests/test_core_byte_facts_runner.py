"""Mock-only byte-facts Part02 runner checks. No Lean process is launched."""
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from tools import diagnose_core_byte_facts as runner
from tools import check_core_syntax_staged as base
from tools import core_syntax_diagnostic_capture as collector
from tools.core_syntax_partition_sources import build_inputs
from tools.core_byte_facts_diagnostic_sources import build_diagnostic_sources
from tools.core_byte_facts_sources import build_sources


class ByteFactsRunnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.prepared = build_inputs()
        cls.proposal = build_sources(cls.prepared)
        cls.diagnostic = build_diagnostic_sources(cls.prepared, cls.proposal)

    def exercise(self, behavior='success', inspect=None, real_validation=False):
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            executable = home/'pinned/bin/lean'
            executable.parent.mkdir(parents=True)
            executable.write_bytes(b'mocked binary')
            (home/'pinned/lib/lean').mkdir(parents=True)
            from tools import core_byte_facts_sources as facts
            identity = {'mock':'a'*64, facts.HELPER_PATH:base.digest((runner.ROOT/facts.HELPER_PATH).read_bytes())}
            support = {'lib/lean/Init.olean':'b'*64, 'lib/lean/Lean/Elab/Tactic/Omega.olean':'c'*64}
            calls = []
            def invoke(exe, source, output, root):
                calls.append(source.stem)
                stage = next(s for s in self.diagnostic.stages if s.name == source.stem)
                self.assertEqual(source.read_text(),stage.source)
                output.write_bytes(('mock '+stage.name).encode())
                names = sorted(stage.expected_theorems)
                stdout = '\n'.join("'"+n+"' does not depend on any axioms" for n in names)+'\n'
                if stage.name == 'SyntaxData' and behavior == 'old_syntax_inventory':
                    stdout = '\n'.join("'"+n+"' does not depend on any axioms"
                        for n in sorted(self.prepared['stages'][1].expected_theorems))+'\n'
                if stage.name == 'CertPart01':
                    if behavior == 'missing':
                        stdout = stdout.split('\n',1)[1]
                    if behavior == 'extra':
                        stdout += "'extra' does not depend on any axioms\n"
                    if behavior == 'sorry':
                        stdout = stdout.replace('does not depend on any axioms',"depends on axioms: [sorryAx]",1)
                    if behavior.startswith('parent_mutate:'):
                        (root/behavior.split(':',1)[1]).write_bytes(b'changed')
                return dict(returncode=1 if behavior == 'parent_failure' and stage.name == 'CertPart01' else 0,
                            timed_out=behavior == 'parent_timeout' and stage.name == 'CertPart01',
                            incomplete=False, output_truncated=False, stdout=stdout, stderr='')
            def capture(exe, source, output, root, *, safe_root, markers, manifest_reference, target):
                self.assertEqual(target,'CertPart02')
                self.assertEqual(source.read_text(),self.diagnostic.stages[3].source)
                self.assertEqual(manifest_reference['sha256'],self.diagnostic.manifest_sha256)
                if behavior == 'platform':
                    return dict(status='diagnostic_infrastructure_failed', process_started=False,
                                files={},raw_files={},metadata_remaining_bytes=collector.METADATA_LIMIT)
                calls.append(source.stem)
                if behavior == 'uncertain':
                    raise RuntimeError('capture may have launched')
                target_stdout = 'mock output\n'+'\n'.join("'"+n+"' does not depend on any axioms"
                    for n in sorted(self.diagnostic.stages[3].expected_theorems))+'\n'
                if behavior == 'target_missing':
                    target_stdout = target_stdout.split('\n',2)[2]
                if behavior == 'target_extra':
                    target_stdout += "'extra' does not depend on any axioms\n"
                if behavior == 'target_sorry':
                    target_stdout = target_stdout.replace('does not depend on any axioms',"depends on axioms: [sorryAx]",1)
                marker = self.diagnostic.manifest['markers'][0]
                target_stdout = '"'+marker['id']+'" : String\n'+target_stdout
                observed = {k:marker[k] for k in ('id','original_offset','instrumented_offset')}
                observed.update(stream='stdout',byte_offset=0,received_seconds=0.1)
                status = {'timeout':'diagnostic_timeout','limit':'diagnostic_output_limit',
                          'claim_pass':'passed'}.get(behavior,'diagnostic_completed')
                raw_files = {n:dict(path=n,bytes=len(v),sha256=base.digest(v))
                             for n,v in zip(runner.CAPTURE_FILES[:2],(target_stdout.encode(),b''))}
                process = dict(manifest_reference=manifest_reference,status=status,process_started=True,
                               returncode=0,leader_reaped=True,drain_complete=True,cleanup_incomplete=False,
                               output_truncated=False,raw_files=raw_files,marker_count=1,last_observed_marker=observed)
                event_raw = runner._encoded(dict(kind='start',process=dict(manifest_reference=manifest_reference),
                    planned_markers=len(markers),raw_limit=collector.RAW_LIMIT,metadata_limit=collector.METADATA_LIMIT))
                event_raw += runner._encoded(dict(kind='receive',stream='stdout',offset=0,bytes=len(target_stdout.encode()),received_seconds=0.1))
                event_raw += runner._encoded(dict(kind='marker',event=observed,received_seconds=0.1))
                event_raw += runner._encoded(dict(kind='terminal',process=process))
                if behavior == 'partial_capture':
                    event_raw = event_raw.splitlines(keepends=True)[0]
                for name,raw in zip(runner.CAPTURE_FILES,(target_stdout.encode(),b'',event_raw)):
                    safe_root.write(name,raw)
                output.write_bytes(b'untrusted target module')
                if behavior.startswith('target_mutate:'):
                    (root/behavior.split(':',1)[1]).write_bytes(b'changed')
                if behavior == 'fifth':
                    (root/'HiaSyntaxResearch/CertPart03.olean').write_bytes(b'forbidden')
                if behavior == 'binary':
                    executable.write_bytes(b'changed')
                files = {n:dict(path=n,bytes=len((root/n).read_bytes()),sha256=base.digest((root/n).read_bytes()))
                         for n in runner.CAPTURE_FILES}
                if behavior == 'forged_file':
                    files[runner.CAPTURE_FILES[0]]['sha256'] = '0'*64
                if behavior == 'changed_log':
                    (root/runner.CAPTURE_FILES[0]).write_bytes(b'changed after capture')
                return dict(status={'timeout':'diagnostic_timeout','limit':'diagnostic_output_limit',
                                    'claim_pass':'passed'}.get(behavior,'diagnostic_completed'),
                            process_started=True, returncode=0, leader_reaped=True, drain_complete=True,
                            output_truncated=False, cleanup_incomplete=False, files=files,
                            raw_files={n:v for n,v in files.items() if n != runner.CAPTURE_FILES[2]},
                            metadata_remaining_bytes=0 if behavior == 'metadata' else
                            collector.METADATA_LIMIT-len(event_raw))
            # The immutable fixture was fully validated at construction. These
            # process/file tamper cases change only the temporary output tree.
            # One integration control below also runs the real validator in-run.
            from contextlib import nullcontext
            def fixture_validation(prepared, proposal, diagnostic):
                self.assertIs(prepared,self.prepared)
                self.assertIs(proposal,self.proposal)
                self.assertIs(diagnostic,self.diagnostic)
            validation = nullcontext() if real_validation else patch(
                'tools.core_byte_facts_diagnostic_sources.validate_diagnostic_sources',
                side_effect=fixture_validation)
            with validation:
                report = runner.execute_diagnostic(executable,home/'out',self.prepared,self.proposal,self.diagnostic,
                                                   identity,support,lambda:identity,lambda _:support,
                                                   base.digest(executable.read_bytes()),run_process=invoke,capture=capture)
            self.assertEqual(json.loads((home/'out/RESULT.json').read_text()),report)
            self.assertEqual(report['authority'],'DENY_ALL')
            for key,value in runner._denials().items():
                self.assertEqual(report[key],value)
            self.assertEqual(len(report['obligations']),12)
            self.assertLessEqual(report['invocations'],4)
            self.assertLessEqual(len(calls),4)
            self.assertFalse((home/'out/CertPart02.finished.json').exists())
            if inspect:
                inspect(home/'out',report)
            return report,calls

    def test_completion_is_never_admitted_and_never_launches_fifth(self):
        report,calls = self.exercise(real_validation=True)
        self.assertEqual(calls,list(runner.DIAGNOSTIC_NAMES))
        self.assertEqual(report['status'],'diagnostic_completed')
        self.assertNotIn('olean',report['stages'][-1])
        self.assertEqual(len(report['not_scheduled']),7)

    def test_old_syntax_data_inventory_cannot_authorize_third_parent(self):
        report,calls = self.exercise('old_syntax_inventory')
        self.assertEqual(report['status'],'diagnostic_failed')
        self.assertEqual(calls,['Baseline','SyntaxData'])

    def test_all_original_and_transformed_sources_retained_and_bound(self):
        def inspect(path,report):
            run = json.loads((path/'RUN.json').read_text())
            self.assertEqual(run['transformation_manifest_sha256'],self.proposal.manifest_sha256)
            for index,stage in enumerate(self.proposal.stages):
                relative = stage.module_name.replace('.','/')+'.lean' if index < 3 else 'transformed/'+stage.name+'.lean'
                self.assertEqual((path/relative).read_text(),stage.source)
            for stage in self.prepared['stages']:
                self.assertEqual((path/('original/'+stage.name+'.lean')).read_text(),stage.source)
            self.assertEqual(len(json.loads((path/runner.TARGET_INVENTORY).read_text())['inventory']),1298)
        self.exercise(inspect=inspect)

    def test_third_parent_failures_stop_before_target(self):
        for behavior in ('parent_failure','parent_timeout','missing','extra','sorry'):
            with self.subTest(behavior=behavior):
                report,calls = self.exercise(behavior)
                self.assertEqual(report['status'],'diagnostic_failed')
                self.assertEqual(calls,list(runner.DIAGNOSTIC_NAMES[:3]))

    def test_third_parent_cannot_change_frozen_ancestors(self):
        for name in ('RUN.json','IDENTITY.json','original-manifest.json','transformation-manifest.json','diagnostic-manifest.json',
                     'Baseline.started.json','Baseline.finished.json','Baseline.stdout','Baseline.stderr',
                     'HiaSyntaxResearch/SyntaxData.lean','HiaSyntaxResearch/SyntaxData.olean'):
            with self.subTest(name=name):
                report,calls = self.exercise('parent_mutate:'+name)
                self.assertEqual(report['status'],'diagnostic_failed')
                self.assertEqual(len(calls),3)

    def test_target_cannot_change_third_parent_evidence(self):
        for name in ('CertPart01.started.json','CertPart01.finished.json','CertPart01.stdout',
                     'CertPart01.stderr','HiaSyntaxResearch/CertPart01.lean','HiaSyntaxResearch/CertPart01.olean'):
            with self.subTest(name=name):
                self.assertEqual(self.exercise('target_mutate:'+name)[0]['status'],'diagnostic_failed')

    def test_target_timeout_and_output_limit_are_nonaccepting(self):
        for behavior,status in (('timeout','diagnostic_timeout'),('limit','diagnostic_output_limit')):
            report,calls = self.exercise(behavior)
            self.assertEqual(report['status'],status)
            self.assertEqual(len(calls),4)

    def test_forged_capture_and_unexpected_files_fail_closed(self):
        for behavior in ('claim_pass','forged_file','changed_log','metadata','fifth','binary','target_missing','target_extra','target_sorry','partial_capture'):
            with self.subTest(behavior=behavior):
                self.assertEqual(self.exercise(behavior)[0]['status'],'diagnostic_failed')

    def test_spawn_refusal_and_uncertain_capture_accounting(self):
        report,calls = self.exercise('platform')
        self.assertEqual(report['invocations'],3)
        self.assertTrue(report['invocation_count_exact'])
        self.assertEqual(len(calls),3)
        report,calls = self.exercise('uncertain')
        self.assertEqual(report['invocations'],4)
        self.assertFalse(report['invocation_count_exact'])

    def print_bytes(self,path):
        stream = io.BytesIO()
        class Stdout:
            buffer = stream
        with patch('sys.stdout',Stdout()):
            runner.print_events(path)
        return stream.getvalue()

    def test_valid_evidence_displays_once(self):
        def inspect(path,report):
            raw = self.print_bytes(path)
            self.assertEqual(raw.count(b'mock output'),1)
            self.assertIn(b'CertPart01.finished.json\n',raw)
            self.assertIn(b'RESULT.json\n',raw)
            self.assertLessEqual(len(raw),base.MAX_DIAGNOSTIC)
        self.exercise(inspect=inspect)

    def test_changed_frozen_evidence_never_partially_displays(self):
        for name in ('RUN.json','IDENTITY.json','original-manifest.json','transformation-manifest.json','diagnostic-manifest.json',
                     'CertPart01.finished.json','CertPart01.stdout','CertPart01.stderr',
                     'CertPart02.events.jsonl','CertPart02.stdout','EVIDENCE.json',
                     'original/CertPart06.lean','transformed/CertPart06.lean','original/SyntaxData.lean','HiaSyntaxResearch/CertPart01.olean'):
            def inspect(path,report):
                (path/name).write_bytes(b'changed')
                stream=io.BytesIO()
                class Stdout:
                    buffer=stream
                with patch('sys.stdout',Stdout()), self.assertRaises(ValueError):
                    runner.print_events(path)
                self.assertEqual(stream.getvalue(),b'')
            with self.subTest(name=name):
                self.exercise(inspect=inspect)

    def test_rehashed_evidence_omissions_are_rejected(self):
        def inspect(path,report):
            original = (path/'EVIDENCE.json').read_bytes()
            for name in ('HiaSyntaxResearch/CertPart01.olean','CertPart01.stdout',
                         'original/CertPart06.lean','transformed/CertPart02.lean','CertPart02.events.jsonl'):
                evidence = json.loads(original)
                del evidence['sha256'][name]
                removed = (path/name).read_bytes()
                (path/name).unlink()
                rewritten = runner._encoded(evidence)
                (path/'EVIDENCE.json').write_bytes(rewritten)
                report['evidence_sha256'] = base.digest(rewritten)
                (path/'RESULT.json').write_bytes(runner._encoded(report))
                with self.subTest(name=name), self.assertRaises(ValueError):
                    self.print_bytes(path)
                (path/name).write_bytes(removed)
        self.exercise(inspect=inspect)

    def test_missing_result_is_explicitly_incomplete(self):
        with tempfile.TemporaryDirectory() as directory, patch('builtins.print') as printing:
            runner.print_events(directory)
            self.assertIn('Incomplete',printing.call_args.args[0])

    def test_failure_evidence_is_presentable_without_admission(self):
        self.exercise('parent_failure',inspect=lambda path,report:self.assertIn(b'diagnostic_failed',self.print_bytes(path)))

    def test_rehashed_internal_contradictions_refuse_all_presentation(self):
        from copy import deepcopy
        def inspect(path,report):
            originals = {p.relative_to(path).as_posix():p.read_bytes() for p in path.rglob('*') if p.is_file()}
            mutations = ('parent_process','event_manifest','terminal_status','receive_offset','fabricated_marker',
                         'transformation_binding','source_swap','target_promoted','marker_before_receive','receive_time')
            for mutation in mutations:
                for name,raw in originals.items():
                    (path/name).write_bytes(raw)
                changed = deepcopy(report)
                evidence = json.loads(originals['EVIDENCE.json'])
                def rewrite(name,value):
                    raw = runner._encoded(value)
                    (path/name).write_bytes(raw)
                    evidence['sha256'][name] = base.digest(raw)
                if mutation == 'parent_process':
                    name = 'CertPart01.finished.json'
                    receipt = json.loads(originals[name]); receipt['process']['returncode'] = 1
                    rewrite(name,receipt)
                    changed['stages'][2]['receipt_sha256'] = evidence['sha256'][name]
                elif mutation in ('event_manifest','terminal_status','receive_offset','fabricated_marker','marker_before_receive','receive_time'):
                    events = [json.loads(line) for line in originals[runner.CAPTURE_FILES[2]].splitlines()]
                    if mutation == 'event_manifest':
                        events[0]['process']['manifest_reference']['sha256'] = '0'*64
                    elif mutation == 'terminal_status':
                        events[-1]['process']['status'] = 'diagnostic_timeout'
                    elif mutation == 'receive_offset':
                        events[1]['offset'] = 1
                    elif mutation == 'marker_before_receive':
                        events[1],events[2] = events[2],events[1]
                    elif mutation == 'receive_time':
                        events[1]['received_seconds'] = -1
                    else:
                        events.insert(-1,dict(kind='marker',event=dict(id='HIA_DIAG_v1_P02_000',received_seconds=0.1),received_seconds=0.1))
                    raw = b''.join(runner._encoded(e) for e in events)
                    (path/runner.CAPTURE_FILES[2]).write_bytes(raw)
                    evidence['sha256'][runner.CAPTURE_FILES[2]] = base.digest(raw)
                elif mutation == 'transformation_binding':
                    value = json.loads(originals['transformation-manifest.json'])
                    value['original_manifest_sha256'] = '0'*64
                    rewrite('transformation-manifest.json',value)
                    run = json.loads(originals['RUN.json'])
                    run['transformation_manifest_sha256'] = evidence['sha256']['transformation-manifest.json']
                    rewrite('RUN.json',run)
                elif mutation == 'source_swap':
                    name = 'HiaSyntaxResearch/SyntaxData.lean'
                    raw = originals['original/SyntaxData.lean']
                    (path/name).write_bytes(raw); evidence['sha256'][name] = base.digest(raw)
                else:
                    changed['stages'][3]['olean'] = {'path':'fake'}
                evidence_raw = runner._encoded(evidence)
                (path/'EVIDENCE.json').write_bytes(evidence_raw)
                changed['evidence_sha256'] = base.digest(evidence_raw)
                (path/'RESULT.json').write_bytes(runner._encoded(changed))
                stream = io.BytesIO()
                class Stdout:
                    buffer = stream
                with self.subTest(mutation=mutation), patch('sys.stdout',Stdout()), self.assertRaises(ValueError):
                    runner.print_events(path)
                self.assertEqual(stream.getvalue(),b'')
        self.exercise(inspect=inspect)

    def test_partial_capture_and_platform_refusal_display_only_safe_failure(self):
        def partial(path,report):
            output = self.print_bytes(path)
            self.assertIn(b'diagnostic_failed',output)
            self.assertNotIn(b'CertPart02.stdout\n',output)
            self.assertNotIn(b'CertPart02.events.jsonl\n',output)
        self.exercise('partial_capture',inspect=partial)
        self.exercise('platform',inspect=lambda path,report:self.assertIn(b'diagnostic_infrastructure_failed',self.print_bytes(path)))

    def test_forged_qualification_result_is_rejected(self):
        def inspect(path,report):
            report['kernel_core_syntax_connection_checked']=True
            (path/'RESULT.json').write_bytes(runner._encoded(report))
            with self.assertRaises(ValueError):
                self.print_bytes(path)
        self.exercise(inspect=inspect)

    def test_cli_always_exits_nonzero_after_target_completion(self):
        with patch.object(runner,'diagnose',return_value={'status':'diagnostic_completed'}), patch('builtins.print') as printer:
            self.assertEqual(runner.main(['--lean','fake','--output-directory','fake']),1)
            printer.assert_not_called()

    def test_source_identity_includes_inherited_and_transitive_dependencies(self):
        from tools.check_core_syntax_partitioned import source_identity as original
        identity = runner.source_identity()
        self.assertTrue(original().items() <= identity.items())
        for name in ('tools/diagnose_core_byte_facts.py','tools/core_byte_facts_diagnostic_sources.py',
                     'tools/core_byte_facts_sources.py','tools/core_byte_facts_dag.py',
                     'tools/core_byte_facts_verify.py',
                     'experiments/hia_initialization_frontiers_20261103/ByteFactsResearch.lean',
                     'tools/core_syntax_partition_diagnostic_sources.py',
                     'tools/core_syntax_diagnostic_capture.py','tools/core_syntax_declaration_diagnostic_sources.py'):
            self.assertEqual(identity[name],base.digest((runner.ROOT/name).read_bytes()))

    def test_manifest_and_raw_caps_remain_fixed(self):
        with self.assertRaises(ValueError):
            runner._evidence_budget({runner.CAPTURE_FILES[0]:b'x'*(collector.RAW_LIMIT+1)})
        def inspect(path,report):
            (path/'transformation-manifest.json').write_bytes(b' '*(32768+1))
            evidence = json.loads((path/'EVIDENCE.json').read_bytes())
            evidence['sha256']['transformation-manifest.json'] = base.digest((path/'transformation-manifest.json').read_bytes())
            raw = runner._encoded(evidence)
            (path/'EVIDENCE.json').write_bytes(raw)
            report['evidence_sha256'] = base.digest(raw)
            (path/'RESULT.json').write_bytes(runner._encoded(report))
            with self.assertRaises(ValueError):
                self.print_bytes(path)
        self.exercise(inspect=inspect)

    def test_metadata_budget_includes_result_and_events(self):
        with self.assertRaises(ValueError):
            runner._evidence_budget({'RESULT.json':b'x',runner.CAPTURE_FILES[2]:b'x'*collector.METADATA_LIMIT})


if __name__ == '__main__':
    unittest.main()
