"""Adversarial schema/PTY/replay controls; fake Python children only, never Lean."""
from contextlib import ExitStack, contextmanager
from dataclasses import replace
from functools import lru_cache
from pathlib import Path
import copy
import errno
import json
import os
import shutil
import subprocess
import time
import sys
import tempfile
import unittest
from unittest.mock import patch

from tools import core_seven_relocated_part03_plan as p
from tools import core_seven_relocated_part03_capture as c
from tools import core_seven_relocated_part03_replay as replay
from tools import diagnose_core_seven_relocated_part03 as runner
from tools import core_seven_relocation_acceptance_plan as old
from tools import core_seven_acceptance_capture as hardened
from tests.test_core_seven_relocated_part03_sources import fixture

@contextmanager
def installation(behavior=None):
    """Real local Python processes; copied pinned identity and full support set."""
    behavior=behavior or {}
    with tempfile.TemporaryDirectory(prefix='part03-') as directory, ExitStack() as stack:
        home=Path(directory);repo=home/'repo'
        for name in p.source_paths():
            target=repo/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(p.ROOT/name,target)
        executable=home/'pinned/bin/lean';executable.parent.mkdir(parents=True)
        script="#!"+sys.executable+"\n"+FAKE_CHILD.replace("BEHAVIOR_LITERAL",repr(behavior))
        executable.write_text(script);executable.chmod(0o700)
        lock=repo/'formal/toolchain-lock.json'
        data=json.loads(lock.read_text());data['lean_binary_sha256']=p.digest(executable.read_bytes())
        lock.write_text(json.dumps(data))
        for name in p.support_paths():
            target=executable.parent.parent/name;target.parent.mkdir(parents=True,exist_ok=True)
            target.write_bytes(('support:'+name).encode())
        stack.enter_context(patch.object(p,'ROOT',repo))
        yield home,executable

FAKE_CHILD = r"""
import os,pathlib,sys,time
behavior=BEHAVIOR_LITERAL
source=pathlib.Path(sys.argv[-1]);name=source.stem;mode=behavior.get(name)
if mode=='exit':raise SystemExit(7)
scopes=[];out=[]
for line in source.read_text().splitlines():
    if line.startswith('namespace '):scopes.append(line[10:].strip())
    elif line=='mutual' or line=='section' or line.startswith('section '):scopes.append(None)
    elif line=='end' or line.startswith('end '):scopes.pop()
    elif line.startswith('#check '):out.append(line[7:]+' : String\n')
    elif line.startswith('#print axioms '):
        subject=line[len('#print axioms '):]
        if '.' not in subject:subject='.'.join([n for n in scopes if n is not None]+[subject])
        out.append("'"+subject+"' does not depend on any axioms\n")
text=''.join(out)
if mode=='sorry':text=text.replace('does not depend on any axioms','depends on axioms: [sorryAx]',1)
if mode=='missing':text=text.split('\n',1)[1]
if mode=='marker_skip':text=text.replace('"HIA_SEVEN_DIAG_v1_P03_001" : String\n','')
if mode=='marker_stderr':os.write(2,b'"HIA_SEVEN_DIAG_v1_P03_000" : String\n')
if mode=='prefix_error':text=''.join(out[:3])+'error: deliberate fake child failure\n'
if mode=='source':source.write_bytes(source.read_bytes()+b'\n')
if mode=='invalid_utf8':os.write(1,b'\xff');raise SystemExit(1)
if mode=='overflow':text='x'*507393
if mode!='no_module':pathlib.Path(sys.argv[sys.argv.index('-o')+1]).write_bytes(('fake '+name).encode())
os.write(1,text.encode())
if mode=='prefix_error':raise SystemExit(7)
time.sleep(.005)
"""

class Part03SchemaTests(unittest.TestCase):
    def test_json_canonical_and_duplicate_rejection(self):
        for raw in (b'{"a":1,"a":1}\n',b'{"a":NaN}\n',b'{ "a":1}\n',b'[]\n',b'{"a":1}',b'{"a":1}\n\n'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):p.parse(raw)
        self.assertEqual(p.parse(p.encode({'a':1})),{'a':1})

    def test_integer_hash_and_path_domains(self):
        for value in (True,False,None,'1',1.0,-1,12):
            with self.subTest(value=value),self.assertRaises(ValueError):p.integer(value,0,11)
        for value in ('f'*63,'F'*64,None,1):
            with self.assertRaises(ValueError):p.hash_value(value)
        self.assertEqual(p.absolute('/'+'x'*127),'/'+'x'*127)
        for path in ('/'+'x'*128,'/a b','/a/../b','/a//b','/a/','relative','/','/a/./b'):
            with self.assertRaises(ValueError):p.absolute(path)

    def test_limits_unchanged(self):
        self.assertEqual(p.BUDGETS,old.BUDGETS)
        self.assertEqual(p.RAW_GLOBAL,819891)
        self.assertEqual(p.METADATA_RESERVE,224589)
        self.assertEqual(p.cap('IDENTITY.json'),144713)
        self.assertEqual(p.cap('RUN.json'),630)
        self.assertEqual(p.cap('RESULT.json'),7968)
        self.assertEqual(p.cap('RESULT.pending.json'),7968)
        self.assertEqual(p.cap('FAILURE.json'),4096)

    def test_exact_identity_membership(self):
        names=set(p.source_paths())
        self.assertEqual(len(names),247)
        self.assertEqual(names-set(old.source_paths()),{
            'tools/core_seven_relocated_part03_sources.py','tools/core_seven_relocated_part03_plan.py',
            'tools/core_seven_relocated_part03_capture.py','tools/core_seven_relocated_part03_replay.py',
            'tools/diagnose_core_seven_relocated_part03.py','tests/test_core_seven_relocated_part03_sources.py',
            'tests/test_core_seven_relocated_part03_diagnostic.py','docs/seven-relocated-part03-diagnostic.md'})
        self.assertEqual(len(p.support_paths()),780)
        self.assertEqual(set(p.support_paths()),set(old.support_paths()))

    def test_exact_complete_file_membership(self):
        self.assertEqual(len(p.SOURCE_FILES),23)
        self.assertEqual(len(p.FROZEN_FILES),53)
        self.assertEqual(set(p.FIXED_FILES)-set(p.FROZEN_FILES),{'RESULT.json','RESULT.pending.json','FAILURE.json'})
        self.assertIn('relocated/CertPart03.lean',p.SOURCE_FILES)
        self.assertIn('HiaSyntaxResearch/CertPart03.lean',p.SOURCE_FILES)
        for name in p.MODULE_FILES:
            self.assertNotIn('Part04',name)
        self.assertEqual(len(p.MODULE_FILES),5)

    def test_denials_are_exact_and_permanent(self):
        flags=p.flags()
        self.assertIs(flags['acceptance_eligible'],False)
        for name in ('kernel_core_syntax_connection_checked','actual_core_bridge_proved',
                     'python_exporter_refinement_proved','body_prefix_refinement_proved','all_edge_transfer_proved'):
            self.assertIs(flags[name],False)
        self.assertEqual(flags['authority'],old.flags()['authority'])
        self.assertEqual(flags['obligations'],old.flags()['obligations'])

    def test_parent_process_contract_unchanged(self):
        valid=hardened.unspawned_process()
        self.assertEqual(p.validate_process(valid),old.validate_process(valid))
        for key in valid:
            broken=dict(valid);broken.pop(key)
            with self.subTest(key=key),self.assertRaises(ValueError):p.validate_process(broken)
        for key in ('elapsed_ns','cleanup_ns'):
            broken=dict(valid);broken[key]=True
            with self.assertRaises(ValueError):p.validate_process(broken)
        broken=dict(valid,foreign=1)
        with self.assertRaises(ValueError):p.validate_process(broken)

    def test_protocols_are_distinct(self):
        self.assertEqual(p.PROTOCOL,'seven-relocated-part03-diagnostic-v1')
        self.assertNotEqual(p.PROTOCOL,old.PROTOCOL)
        self.assertNotEqual(p.SCHEMA,old.SCHEMA)
        self.assertEqual(p.common('a'*64)['protocol'],p.PROTOCOL)

class Part03RecordTests(unittest.TestCase):
    def result(self,**changes):
        args=dict(status='no_launch',phase='preparation',error_code='preparation_invalid',failed_stage=None,
                  invocations=0,launch_slots_used=0,launch_state='not_attempted',wall_ns=0,receipts=[])
        args.update(changes)
        return replay.make_result('a'*64,{},**args)

    def test_complete_result_cannot_be_synthesized_from_no_launch(self):
        r=self.result()
        for field,value in [('status','diagnostic_completed'),('invocations',True),('invocations',6),
                            ('launch_slots_used',6),('wall_ns',600000000001),('target_marker_count',1),
                            ('acceptance_eligible',True),('kernel_core_syntax_connection_checked',True),
                            ('foreign',0),('launch_state','spawn_outcome_uncertain')]:
            bad=copy.deepcopy(r);bad[field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):p.validate_result(bad)

    def test_uncertain_launch_conservatively_consumes_slot(self):
        r=self.result(status='capture_incomplete',phase='capturing',error_code='capture_incomplete',failed_stage=0,
                      launch_slots_used=1,launch_state='spawn_outcome_uncertain')
        self.assertEqual(p.validate_result(r),r)
        for field,value in [('launch_slots_used',0),('invocations',1),('target_marker_count',1)]:
            bad=copy.deepcopy(r);bad[field]=value
            with self.assertRaises(ValueError):p.validate_result(bad)

    def test_no_launch_cannot_describe_captured_parent(self):
        with self.assertRaises(ValueError):self.result(phase='capturing',error_code='process_failed',failed_stage=0,
            invocations=1,launch_slots_used=1,launch_state='spawned')
        with self.assertRaises(ValueError):self.result(status='parent_failed',phase='capturing',error_code='process_failed',
            failed_stage=0,launch_slots_used=1,launch_state='spawn_outcome_uncertain')

    def test_rejection_summary_suppresses_frontier(self):
        result=self.result()
        summary=p.parse(replay.display(result,markers=[{'untrusted':1}],parents=[{'untrusted':1}]))
        self.assertEqual(summary['parents'],[])
        self.assertEqual(summary['target']['markers'],[])
        self.assertEqual(summary['target']['marker_count'],0)
        self.assertLessEqual(len(p.encode(summary)),4096)
        for key,value in [('acceptance_eligible',True),('kernel_core_syntax_connection_checked',True),
                          ('authority','ALLOW'),('invocations',True),('status','complete_diagnostic_replayed')]:
            bad=copy.deepcopy(summary);bad[key]=value
            with self.assertRaises(ValueError):p.validate_summary(bad)

    def test_preparation_and_current_file_prefixes(self):
        for count in range(29):p.validate_file_prefix(p.PREPARATION_ORDER[:count],0,preparation=True)
        with self.assertRaises(ValueError):p.validate_file_prefix(p.PREPARATION_ORDER[1:3],0,preparation=True)
        prepared=set(p.PREPARATION_ORDER)
        p.validate_file_prefix(prepared,0)
        p.validate_file_prefix(prepared|p.stage_files(0),0,0)
        with self.assertRaises(ValueError):p.validate_file_prefix(prepared|p.stage_files(1),0,0)
        with self.assertRaises(ValueError):p.validate_file_prefix(prepared|{'unknown'},0,0)
        with self.assertRaises(ValueError):p.validate_file_prefix(prepared,1)
        p.validate_file_prefix(p.FROZEN_FILES,4,4)

    def test_raw_and_metadata_caps_charge_all_copies(self):
        self.assertEqual(p.budgets({'Baseline.stdout':b'x'*507392,'SyntaxData.stdout':b'x'*312499})['raw'],819891)
        for files in ({'Baseline.stdout':b'x'*507393},
                      {'Baseline.stdout':b'x'*507392,'Baseline.stderr':b'x'},
                      {'Baseline.stdout':b'x'*507392,'SyntaxData.stdout':b'x'*312500},
                      {'RUN.json':b'x'*631},{'RESULT.pending.json':b'x'*7969},
                      {'RelocatedPart03.events.jsonl':b'x'*8417}, {'unknown':b''}):
            with self.assertRaises(ValueError):p.budgets(files)
        all_metadata={name:b'x'*p.cap(name) for name in p.FIXED_FILES
                      if name not in p.SOURCE_FILES+p.MODULE_FILES+p.LOG_FILES}
        with self.assertRaises(ValueError):p.budgets(all_metadata)
        with self.assertRaises(ValueError):p.budgets({},b'x'*4097)

    def test_snapshot_rejects_rewrite_hardlink_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            try:
                root.write('RUN.json',b'original')
                snapshot=p.Snapshot(root);self.assertEqual(snapshot.read('RUN.json'),b'original')
                (root.path/'RUN.json').write_bytes(b'rewrite!')
                with self.assertRaises(ValueError):snapshot.read('RUN.json')
                os.link(root.path/'RUN.json',root.path/'PLAN.json')
                with self.assertRaises(ValueError):p.Snapshot(root).read('PLAN.json')
                os.symlink(root.path/'RUN.json',root.path/'IDENTITY.json')
                with self.assertRaises((OSError,ValueError)):p.Snapshot(root).read('IDENTITY.json')
            finally:root.close()

class Part03FinalizationTests(unittest.TestCase):
    def result(self):
        return replay.make_result('a'*64,{},status='no_launch',phase='preparation',error_code='preparation_invalid',
            failed_stage=None,invocations=0,launch_slots_used=0,launch_state='not_attempted',wall_ns=0,receipts=[])

    def test_result_atomic_install_is_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            try:
                snapshot=p.Snapshot(root);result=self.result()
                runner.finalize(root,snapshot,result)
                self.assertEqual(snapshot.read('RESULT.json'),p.encode(result))
                self.assertFalse((root.path/'RESULT.pending.json').exists())
                with self.assertRaises(OSError):runner.finalize(root,snapshot,result)
                self.assertEqual(snapshot.read('RESULT.json'),p.encode(result))
                self.assertTrue((root.path/'RESULT.pending.json').exists())
            finally:root.close()

    def test_sync_failure_leaves_pending_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            try:
                snapshot=p.Snapshot(root)
                with patch.object(runner,'sync_file',side_effect=OSError('injected fsync')) as sync:
                    with self.assertRaises(OSError):runner.finalize(root,snapshot,self.result())
                    self.assertEqual(sync.call_count,1)
                self.assertTrue((root.path/'RESULT.pending.json').exists())
                self.assertFalse((root.path/'RESULT.json').exists())
                runner.failure_footer(root,snapshot,'a'*64,{})
                footer=p.parse(snapshot.read('FAILURE.json'))
                self.assertEqual(footer['artifact_state'],'present')
                self.assertIsNotNone(footer['pending_sha256'])
                self.assertIsNone(footer['result_sha256'])
                with self.assertRaises((OSError,ValueError)):replay.verify_evidence(root.path)
            finally:root.close()

    def test_existing_result_cannot_be_claimed_as_new_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            try:
                root.write('RESULT.json',b'preexisting')
                with self.assertRaises(OSError):runner.finalize(root,p.Snapshot(root),self.result())
                self.assertEqual(root.read('RESULT.json',7968),b'preexisting')
            finally:root.close()

    def test_footer_read_uncertainty_is_sticky(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            try:
                root.write('RESULT.json',p.encode(self.result()))
                root.write('RESULT.pending.json',p.encode(self.result()))
                snapshot=p.Snapshot(root);real=snapshot.read;first=True
                def read(name,**kwargs):
                    nonlocal first
                    if name=='RESULT.json' and first:
                        first=False;raise OSError('uncertain result read')
                    return real(name,**kwargs)
                with patch.object(snapshot,'read',side_effect=read):runner.failure_footer(root,snapshot,'a'*64,{})
                footer=p.parse(snapshot.read('FAILURE.json'))
                self.assertEqual(footer['artifact_state'],'uncertain')
                self.assertIsNone(footer['result_sha256'])
                self.assertIsNotNone(footer['pending_sha256'])
                with self.assertRaises(ValueError):replay.verify_evidence(root.path)
            finally:root.close()

    def test_main_replay_never_executes_compiler_and_always_nonzero(self):
        import io
        from types import SimpleNamespace
        output=io.BytesIO()
        with tempfile.TemporaryDirectory() as directory,patch.object(c,'capture',side_effect=AssertionError('compiler')) as target,patch.object(hardened,'capture',side_effect=AssertionError('compiler')) as parent,patch.object(runner.sys,'stdout',SimpleNamespace(buffer=output)):
            self.assertEqual(runner.main(['--replay','--output-directory',directory]),1)
            target.assert_not_called();parent.assert_not_called()
            summary=p.parse(output.getvalue())
            self.assertEqual(summary['status'],'container_unverifiable')
            self.assertEqual(summary['target']['marker_count'],0)

    def test_outer_deadline_does_not_replace_known_launches_with_zero(self):
        import io
        from types import SimpleNamespace
        output=io.BytesIO()
        response=dict(display=runner.rejection_summary('a'*64,invocations=4,launch_state='spawn_outcome_uncertain',execution=True,failed_stage=4),deadline_ns=0)
        with patch.object(runner,'diagnose',return_value=response),patch.object(runner.sys,'stdout',SimpleNamespace(buffer=output)):
            self.assertEqual(runner.main(['--lean','/fake','--output-directory','/fake-output']),1)
            self.assertEqual(output.getvalue(),b'')
        summary=p.parse(response['display'])
        self.assertEqual(summary['invocations'],4)
        self.assertEqual(summary['launch_state'],'spawn_outcome_uncertain')
        self.assertEqual(summary['target']['marker_count'],0)

    def test_summary_output_short_write_is_not_retried(self):
        from types import SimpleNamespace
        class Short:
            def __init__(self):self.calls=0
            def write(self,data):self.calls+=1;return 1
            def flush(self):raise AssertionError('must not flush incomplete write')
        output=Short()
        with tempfile.TemporaryDirectory() as directory,patch.object(runner.sys,'stdout',SimpleNamespace(buffer=output)):
            self.assertEqual(runner.main(['--replay','--output-directory',directory]),1)
            self.assertEqual(output.calls,1)

class Part03RawTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _,_,proposal,marked=fixture()
        cls.source=proposal.stages[4];cls.markers=marked.manifest['markers']
        cls.subjects=p.seven._qualified_prints(cls.source.source)
        cls.rows=[("'"+name+"' does not depend on any axioms\n").encode() for name in cls.subjects]
        cls.lines=[('"HIA_SEVEN_DIAG_v1_P03_%03d" : String\n'%i).encode() for i in range(11)]
        cls.raw=b''.join(cls.lines[:9]+cls.rows[:828]+cls.lines[9:10]+cls.rows[828:]+cls.lines[10:])

    def parse(self,out,err=b'',**kw):
        return c.parse_raw(out,err,self.source,self.markers,**kw)

    def reject(self,out,err=b'',**kw):
        with self.assertRaises((ValueError,UnicodeError)):self.parse(out,err,**kw)

    def test_complete_actual_ordered_inventory(self):
        result=self.parse(self.raw,complete=True)
        self.assertEqual(len(result['markers']),11)
        self.assertEqual(result['subject_count'],1655)
        self.assertEqual(tuple(result['inventory']),self.subjects)
        self.assertEqual(result['stdout'],b''.join(self.rows))
        self.assertEqual(result['markers'][9]['stdout_offset'],len(b''.join(self.lines[:9]+self.rows[:828])))

    def test_prefix_error_is_retained_not_full_inventory(self):
        out=b''.join(self.lines[:3])+b'error: deliberate failure\n'
        result=self.parse(out)
        self.assertEqual(len(result['markers']),3)
        self.assertIsNone(result['inventory'])
        self.assertEqual(result['stdout'],b'error: deliberate failure\n')
        self.reject(out,complete=True)

    def test_each_safe_marker_prefix(self):
        for count in range(10):
            result=self.parse(b''.join(self.lines[:count]))
            self.assertEqual(len(result['markers']),count)
            self.assertEqual(result['subject_count'],0)
        before_final=b''.join(self.lines[:9]+self.rows[:828]+self.lines[9:10]+self.rows[828:])
        self.assertEqual(self.parse(before_final)['subject_count'],1655)
        self.reject(before_final,complete=True)

    def test_inventory_boundary_markers_enforced(self):
        for out in (b''.join(self.lines[:8]+self.rows[:1]),
                    b''.join(self.lines[:9]+self.lines[9:10]),
                    b''.join(self.lines[:9]+self.rows[:827]+self.lines[9:10]),
                    b''.join(self.lines[:9]+self.rows[:829]+self.lines[9:10]),
                    self.raw.replace(self.lines[9],b''),self.raw.replace(self.lines[10],b'')+self.rows[-1]):
            self.reject(out)

    def test_marker_foreign_repeated_reordered_and_partial(self):
        for out in (self.lines[1],self.lines[0]*2,self.lines[0][:-1],
                    self.lines[0].replace(b'P03',b'P04'),self.lines[0].replace(b'String',b'Nat'),
                    b'error: '+self.lines[0],self.raw+self.lines[10],
                    self.lines[0].replace(b'\n',b'\r\n')):
            self.reject(out)

    def test_stderr_never_supplies_marker_or_inventory(self):
        for err in (self.lines[0],self.rows[0],b'error: HIA_SEVEN_DIAG_v1_P03_000\n'):
            self.reject(b'',err)
        self.assertEqual(self.parse(b'',b'error: ordinary failure\n')['markers'],[])

    def test_subject_unknown_duplicate_reordered_missing(self):
        prefix=b''.join(self.lines[:9])
        for rows in ([self.rows[1]],[self.rows[0],self.rows[0]],[self.rows[1],self.rows[0]],
                     [self.rows[0].replace(self.subjects[0].encode(),b'unknown')]):
            self.reject(prefix+b''.join(rows))

    def test_bad_axioms_and_inventory_claims(self):
        prefix=b''.join(self.lines[:9])
        for tail in (self.rows[0].replace(b'does not depend on any axioms',b'depends on axioms: [sorryAx]'),
                     self.rows[0][:-1],b"'unknown' depends on axioms: [\n",
                     b'error: does not depend on any axioms\n'):
            self.reject(prefix+tail)
        out=self.raw.replace(b'does not depend on any axioms',b'depends on axioms: [propext, Quot.sound]',1)
        self.assertEqual(self.parse(out,complete=True)['inventory'][self.subjects[0]],['propext','Quot.sound'])

    def test_events_bound_to_actual_offsets_and_count(self):
        parsed=self.parse(self.raw)
        events=[dict(event,received_ns=i) for i,event in enumerate(parsed['markers'])]
        self.assertEqual(self.parse(self.raw,events=events)['markers'],parsed['markers'])
        for key,value in [('stdout_offset',True),('stdout_offset',1),('received_ns',True),('received_ns',600000000001),('extra',0)]:
            bad=copy.deepcopy(events);bad[0][key]=value;self.reject(self.raw,events=bad)
        self.reject(self.raw,events=events[:-1])
        self.reject(self.raw,events=events[::-1])

    def test_strict_utf8_and_raw_bound(self):
        self.reject(b'\xff')
        self.reject(b'',b'\xff')
        self.reject(b'x'*507393)
        self.reject(b'x'*507392,b'x')

    def test_complete_rejects_error_text(self):
        self.reject(self.raw+b'error: failure\n',complete=True)
        self.reject(self.raw,b'error: failure\n',complete=True)

class Part03IntegrationTests(unittest.TestCase):
    def test_actual_full_run_and_replay_nonaccepting(self):
        # Genuine preparation, complete inverse and independent replay. Only the
        # compiler binary and required platform observation are test fixtures.
        with installation() as (home,exe),patch.object(c,'platform_observation',return_value=dict(c.PLATFORM)):
            output=runner.execute(exe,home/'out')
            self.assertEqual(output['exit_code'],1)
            self.assertEqual(output.get('result',{}).get('status'),'diagnostic_completed',output)
            summary=p.parse(output['display'])
            self.assertEqual(summary['status'],'complete_diagnostic_replayed')
            self.assertEqual(summary['invocations'],5)
            self.assertEqual(summary['target']['marker_count'],11)
            self.assertFalse(summary['acceptance_eligible'])
            self.assertFalse(summary['kernel_core_syntax_connection_checked'])
            self.assertEqual(summary['authority'],'DENY_ALL')
            self.assertEqual(len(list((home/'out').rglob('*'))),57) #54 files +3 directories
            self.assertFalse((home/'out/HiaSyntaxResearch/CertPart04.olean').exists())
            self.assertFalse((home/'out/RelocatedPart03.finished.json').exists())
            verified=replay.verify_evidence(home/'out')
            self.assertEqual(verified.result,output['result'])

@contextmanager
def cached_semantic_fixture():
    """Only branch controls skip repeated semantic construction.

    fixture() performs the genuine original/inverse gate once. Byte snapshots,
    External reads, process capture, inventory/ancestry, publication and replay
    logic remain real. The separately named full integration has no such patch.
    """
    prepared,previous,proposal,marked=fixture()
    def derive(identity,executable,root):
        plan=p._derive_plan(identity['run_id'],identity,executable,root,prepared,proposal,marked)
        return prepared,proposal,marked,plan
    with patch.object(p,'prepare_plan',side_effect=derive),patch.object(p,'reconstruct_plan',side_effect=lambda snapshot,identity,executable,root:derive(identity,executable,root)):
        yield

class Part03BranchTests(unittest.TestCase):
    def execute(self,behavior=None):
        return installation(behavior)

    def test_parent_uncertain_popen_stops_after_one_slot(self):
        with cached_semantic_fixture(),self.execute() as (home,exe):
            captured=dict(process=hardened.unspawned_process(),logs=None,error_code='process_failed')
            with patch.object(hardened,'capture',return_value=captured) as parent,patch.object(c,'capture',side_effect=AssertionError('target forbidden')) as target:
                output=runner.execute(exe,home/'out')
            self.assertEqual(parent.call_count,1);target.assert_not_called()
            result=output['result']
            self.assertEqual(result['launch_slots_used'],1)
            self.assertEqual(result['invocations'],0)
            self.assertEqual(result['launch_state'],'spawn_outcome_uncertain')
            summary=p.parse(output['display'])
            self.assertEqual(summary['launch_state'],'spawn_outcome_uncertain')
            self.assertEqual(summary['target']['marker_count'],0)
            self.assertFalse((home/'out/SyntaxData.started.json').exists())

    def test_target_nonzero_reports_only_safe_prefix(self):
        with cached_semantic_fixture(),self.execute({'CertPart03':'prefix_error'}) as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
            output=runner.execute(exe,home/'out');summary=p.parse(output['display'])
            self.assertEqual(output['result']['status'],'target_nonzero',output)
            self.assertEqual(summary['status'],'bounded_failure_replayed',output)
            self.assertEqual(summary['target']['marker_count'],3)
            self.assertEqual(summary['invocations'],5)
            self.assertFalse(summary['acceptance_eligible'])
            self.assertEqual(output['exit_code'],1)
            self.assertEqual(replay.verify_evidence(home/'out').result,output['result'])

    def test_target_invalid_marker_has_no_frontier(self):
        with cached_semantic_fixture(),self.execute({'CertPart03':'marker_skip'}) as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
            output=runner.execute(exe,home/'out');summary=p.parse(output['display'])
            self.assertNotEqual(output.get('result',{}).get('status'),'diagnostic_completed')
            self.assertEqual(summary['target']['marker_count'],0)
            self.assertEqual(summary['target']['markers'],[])
            self.assertEqual(output['exit_code'],1)

    def test_parent_nonzero_never_starts_child(self):
        with cached_semantic_fixture(),self.execute({'Baseline':'exit'}) as (home,exe),patch.object(c,'capture',side_effect=AssertionError('target forbidden')):
            output=runner.execute(exe,home/'out')
            self.assertEqual(output['result']['invocations'],1)
            self.assertEqual(output['result']['status'],'parent_failed')
            self.assertFalse((home/'out/SyntaxData.started.json').exists())
            self.assertEqual(p.parse(output['display'])['target']['marker_count'],0)

    def test_full_fake_replay_rejects_rehashed_result_contradictions(self):
        with cached_semantic_fixture(),self.execute() as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
            output=runner.execute(exe,home/'out')
            self.assertEqual(output.get('result',{}).get('status'),'diagnostic_completed',output)
            root=home/'out';original=(root/'RESULT.json').read_bytes()
            mutations=[('error_code','process_failed'),('launch_state','not_spawned'),('phase','capturing'),
                       ('failed_stage',4),('launch_slots_used',4),('invocations',4)]
            for field,value in mutations:
                result=p.parse(original);result[field]=value;(root/'RESULT.json').write_bytes(p.encode(result))
                with self.subTest(field=field),self.assertRaises(ValueError):replay.verify_evidence(root)
            (root/'RESULT.json').write_bytes(original)
            (root/'RESULT.pending.json').write_bytes(original)
            with self.assertRaises(ValueError):replay.verify_evidence(root)

    def test_rehashed_parent_receipt_cannot_change_ancestry(self):
        with cached_semantic_fixture(),self.execute() as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
            output=runner.execute(exe,home/'out');self.assertEqual(output['result']['status'],'diagnostic_completed')
            root=home/'out';result=p.parse((root/'RESULT.json').read_bytes())
            finish=p.parse((root/'SyntaxData.finished.json').read_bytes());finish['started_sha256']='0'*64
            (root/'SyntaxData.finished.json').write_bytes(p.encode(finish))
            files={str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*') if path.is_file() and path.name!='RESULT.json'}
            result['frozen_files_sha256']=replay.frozen_commitment(files)
            result['committed_parent_receipt_sha256'][1]=p.commitment(finish)
            (root/'RESULT.json').write_bytes(p.encode(result))
            with self.assertRaises(ValueError):replay.verify_evidence(root)

    def test_receipt_failure_preserves_confirmed_parent_count(self):
        with cached_semantic_fixture(),self.execute() as (home,exe):
            real=runner.sync_file
            def sync(root,name):
                if name=='SyntaxData.started.json':raise OSError('injected receipt persistence')
                return real(root,name)
            with patch.object(runner,'sync_file',side_effect=sync):output=runner.execute(exe,home/'out')
            summary=p.parse(output['display'])
            self.assertEqual(summary['invocations'],1)
            self.assertEqual(summary['target']['marker_count'],0)
            self.assertFalse((home/'out/CertPart01.started.json').exists())

    def test_changed_actual_source_blocks_next_parent(self):
        with cached_semantic_fixture(),self.execute({'Baseline':'source'}) as (home,exe):
            output=runner.execute(exe,home/'out');summary=p.parse(output['display'])
            self.assertEqual(summary['invocations'],1)
            self.assertEqual(summary['target']['marker_count'],0)
            self.assertFalse((home/'out/SyntaxData.started.json').exists())

class CaptureLifecycleTests(unittest.TestCase):
    def invoke(self, script='raise SystemExit(3)', popen_failure=False, delay=0, read_mode=None, signal_failure=False, reap_failure=False, timeout_clock=False, pty_failure=False, terminal_failure=False):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            plan=dict(process_spec=dict(root=str(root.path)),target=dict(name=c.TARGET,capture_protocol=c.CAPTURE_PROTOCOL,diagnostic_manifest_sha256='a'*64,module_path='HiaSyntaxResearch/CertPart03.olean',source_path='HiaSyntaxResearch/CertPart03.lean'))
            plan['process_spec']['executable']=sys.executable
            plan['process_spec']['sysroot']=str(Path(sys.executable).parent.parent)
            run=dict(p.common('a'*64));start=dict(p.common('a'*64),remaining_launch_ns=540000000000)
            data={'PLAN.json':c.encode(plan),'RUN.json':c.encode(run),c.TARGET+'.started.json':c.encode(start)}
            class Snapshot:
                def __init__(self,root):pass
                def read(self,name):return data.get(name,b'')
            real=subprocess.Popen
            def spawn(argv,**kwargs):
                if popen_failure:raise OSError('uncertain synthetic spawn')
                child=real([sys.executable,'-c',script],**kwargs)
                if delay:time.sleep(delay)
                return child
            real_read=os.read; real_signal=os.killpg; real_reap=os.waitpid
            seen=0; reaped=False
            def read(fd,size):
                nonlocal seen
                if read_mode and os.isatty(fd):
                    seen+=1
                    if seen==1:raise OSError(errno.EIO,'synthetic early EIO')
                    if read_mode=='reopen':return b'x'
                    time.sleep(.055)
                    raise OSError(errno.EIO,'synthetic expired EIO')
                return real_read(fd,size)
            def group(pid,sig):
                if signal_failure and sig:raise PermissionError('synthetic signal denial')
                return real_signal(pid,sig)
            def reap(pid,options):
                nonlocal reaped
                if reap_failure and not reaped:
                    reaped=True;raise ChildProcessError('synthetic reap ambiguity')
                return real_reap(pid,options)
            real_clock=time.monotonic_ns; shift=0
            real_identity=c.hardened._leader_identity
            def identity(pid):
                nonlocal shift
                value=real_identity(pid)
                if timeout_clock:shift=c.PROCESS_NS
                return value
            real_event=c._Sink.event
            def event(sink,value):
                if terminal_failure and value['kind']=='terminal':
                    raise OSError(errno.EIO,'synthetic terminal persistence failure')
                return real_event(sink,value)
            try:
                launch=time.monotonic_ns()+(5_000_000 if delay else 2_000_000_000)
                if timeout_clock:launch=real_clock()+540_000_000_000
                with ExitStack() as stack, patch.object(p,'Snapshot',Snapshot),patch.object(c,'platform_observation',return_value=c.PLATFORM),patch.object(c.subprocess,'Popen',side_effect=spawn),patch.object(c.os,'read',side_effect=read),patch.object(c.os,'killpg',side_effect=group),patch.object(c.os,'waitpid',side_effect=reap):
                    stack.enter_context(patch.object(c.time,'monotonic_ns',side_effect=lambda:real_clock()+shift))
                    stack.enter_context(patch.object(c.hardened,'_leader_identity',side_effect=identity))
                    stack.enter_context(patch.object(c._Sink,'event',event))
                    if pty_failure:stack.enter_context(patch.object(c.termios,'tcsetattr',side_effect=OSError('synthetic PTY refusal')))
                    result=c.collect(root,plan,run,start,launch_deadline_ns=launch,outer_deadline_ns=real_clock()+600_000_000_000)
                if result['terminal'] is not None:
                    raw=root.read(c.EVENTS,c.EVENT_STREAM_LIMIT)
                    c.validate_events(raw,plan,run,start,c.RAW_GLOBAL)
                    self.event_fixture=(raw,plan,run,start)
                return result
            finally:root.close()


    def test_nonzero_python_child_safely_reaped(self):
        result=self.invoke()
        self.assertEqual(result['status'],'target_nonzero')
        self.assertTrue(result['process']['leader_reaped'])
        self.assertEqual(result['process']['post_reap_group_probe'],'esrch')
        self.assertTrue(result['process']['stdout_eof'])
        self.assertEqual(result['process']['pre_reap_group_signal'],'sigkill_sent')
        self.assertIsNotNone(result['terminal'])

    def test_uncertain_popen_is_not_retried_or_recast(self):
        result=self.invoke(popen_failure=True)
        self.assertEqual(result['launch_state'],'spawn_outcome_uncertain')
        self.assertFalse(result['process']['spawned'])
        self.assertEqual(result['error_code'],'capture_incomplete')
        self.assertIsNotNone(result['terminal']['spawn_offset_ns'])

    def test_adjacent_postspawn_deadline_fails_closed(self):
        result=self.invoke('import time;time.sleep(.5)',delay=.02)
        self.assertEqual(result['launch_state'],'spawned')
        self.assertTrue(result['process']['incomplete'])
        self.assertNotEqual(result['status'],'diagnostic_completed')
        self.assertTrue(result['process']['leader_reaped'])

    def test_pending_eio_expiry_cannot_become_eof(self):
        result=self.invoke("import time;print('x',flush=True);time.sleep(.1);raise SystemExit(3)",read_mode='expire')
        self.assertTrue(result['process']['incomplete'])
        self.assertFalse(result['process']['stdout_eof'])
        self.assertIsNone(result['terminal']['eio_confirmed_ns'])

    def test_pending_eio_reopened_data_cannot_become_eof(self):
        result=self.invoke("import time;print('x',flush=True);time.sleep(.1);raise SystemExit(3)",read_mode='reopen')
        self.assertTrue(result['process']['incomplete'])
        self.assertFalse(result['process']['stdout_eof'])
        self.assertGreater(result['terminal']['observed_bytes']['stdout'],0)

    def test_signal_failure_never_claims_safe_cleanup(self):
        result=self.invoke(signal_failure=True)
        self.assertEqual(result['process']['pre_reap_group_signal'],'failed')
        self.assertFalse(c.reportable(result['process'],result['logs'],result['terminal']['observed_bytes']))

    def test_reap_ambiguity_never_claims_safe_prefix(self):
        result=self.invoke(reap_failure=True)
        self.assertTrue(result['process']['incomplete'])
        self.assertFalse(c.reportable(result['process'],result['logs'],result['terminal']['observed_bytes']))

    def test_rehashed_event_clock_mutations_rejected(self):
        self.invoke()
        raw,plan,run,start=self.event_fixture
        original=[p.parse(line) for line in raw.splitlines(keepends=True)]
        for field,value in [('spawn_offset_ns',500000000000),('receipt_elapsed_ns',True),
                            ('pending_eio_ns',50000001),('marker_count',1),('extra',0)]:
            records=copy.deepcopy(original);records[-1][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                c.validate_events(b''.join(p.encode(r) for r in records),plan,run,start,c.RAW_GLOBAL)
        records=copy.deepcopy(original)
        records[0]['remaining_launch_ns']=1
        records[-1]['spawn_offset_ns']=records[0]['received_ns']+2
        with self.assertRaises(ValueError):
            c.validate_events(b''.join(p.encode(r) for r in records),plan,run,start,c.RAW_GLOBAL)

    def test_rehashed_process_cleanup_claims_rejected(self):
        self.invoke()
        raw,plan,run,start=self.event_fixture
        original=[p.parse(line) for line in raw.splitlines(keepends=True)]
        for field,value in [('leader_pid',True),('original_pgid',0),('cleanup_ns',2000000000),
                            ('post_reap_group_probe','group_exists')]:
            records=copy.deepcopy(original);records[-1]['process'][field]=value
            with self.subTest(field=field),self.assertRaises(ValueError):
                c.validate_events(b''.join(p.encode(r) for r in records),plan,run,start,c.RAW_GLOBAL)

    def test_failed_signal_never_creates_reportable_frontier(self):
        result=self.invoke()
        terminal=copy.deepcopy(result['terminal'])
        terminal['process']['pre_reap_group_signal']='failed'
        self.assertFalse(replay.safe_prefix(terminal))
        self.assertFalse(c.reportable(terminal['process'],terminal['logs'],terminal['observed_bytes']))

    def test_partial_writes_remain_charged(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run');sink=c._Sink(root,100)
            real=os.write;calls=0
            def partial(fd,data):
                nonlocal calls
                calls+=1
                if calls==2:raise OSError(errno.EIO,'synthetic write failure')
                return real(fd,data[:2])
            try:
                with patch.object(c.os,'write',side_effect=partial):
                    with self.assertRaises(OSError):sink.append(c.TARGET+'.stdout',b'abcdef')
                self.assertEqual(sink.raw_written,2)
                self.assertEqual(sink.logs()['stdout']['bytes'],2)
                self.assertEqual(root.read(c.TARGET+'.stdout',100),b'ab')
            finally:sink.close();root.close()

    def test_event_terminal_reservation_precedes_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run');sink=c._Sink(root,100)
            try:
                sink.metadata_written=c.EVENT_STREAM_LIMIT-c.TERMINAL_LIMIT
                with self.assertRaises(c.CaptureFailure):sink.reserve(1,metadata=True)
                self.assertEqual(root.read(c.EVENTS,100),b'')
            finally:sink.close();root.close()


    def test_actual_raw_overflow_observes_one_sentinel(self):
        result=self.invoke("import os;os.write(1,b'x'*600000)")
        self.assertTrue(result['process']['output_truncated'])
        self.assertLessEqual(sum(x['bytes'] for x in result['logs'].values()),c.RAW_STAGE)
        self.assertEqual(sum(result['terminal']['observed_bytes'].values()),c.RAW_STAGE+1)
        self.assertFalse(c.reportable(result['process'],result['logs'],result['terminal']['observed_bytes']))

    def test_invalid_utf8_never_gets_reporting_frontier(self):
        result=self.invoke("import os;os.write(1,bytes([255]));raise SystemExit(3)")
        self.assertTrue(result['process']['incomplete'])
        self.assertNotEqual(result['status'],'diagnostic_completed')

    def test_fixed_sixty_second_timeout_with_clock_observation(self):
        before=time.monotonic()
        result=self.invoke('import time;time.sleep(.5)',timeout_clock=True)
        self.assertLess(time.monotonic()-before,3)
        self.assertEqual(result['status'],'target_timeout')
        self.assertTrue(result['process']['timed_out'])
        self.assertGreaterEqual(result['process']['elapsed_ns'],c.PROCESS_NS)
        self.assertTrue(result['process']['leader_reaped'])

    def test_pty_refusal_launches_nothing(self):
        result=self.invoke(pty_failure=True)
        self.assertEqual(result['launch_state'],'not_spawned')
        self.assertEqual(result['error_code'],'pty_invalid')
        self.assertFalse(result['process']['spawned'])

    def test_terminal_persistence_failure_is_not_retried(self):
        result=self.invoke(terminal_failure=True)
        self.assertEqual(result['status'],'finalization_failed')
        self.assertIsNone(result['terminal'])
        self.assertIsNone(result['events_sha256'])


if __name__=='__main__':unittest.main()
