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

from tools import core_seven_completion_part03_plan as p
from tools import core_seven_completion_part03_capture as c
from tools import core_seven_completion_part03_replay as replay
from tools import diagnose_core_seven_completion_part03 as runner
from tools import core_seven_relocation_acceptance_plan as old
from tools import core_seven_relocated_part03_plan as previous
from tools import core_seven_acceptance_capture as hardened
from tests.test_core_seven_completion_part03_sources import fixture

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
if mode=='marker_skip':text=text.replace('"HIA_SEVEN_COMP_v1_P03_001" : String\n','')
if mode=='marker_stderr':os.write(2,b'"HIA_SEVEN_COMP_v1_P03_000" : String\n')
if mode=='prefix_error':text=''.join(out[:3])+'error: deliberate fake child failure\n'
if mode=='error_zero':text+='error: checked-chain fallback-like failure\n'
if mode=='missing_original':
    text=text.replace(next(row for row in out if row.startswith("'Hia")), '', 1)
if mode in ('killed_before','killed_after','timeout_before','timeout_after'):
    boundary=text.index("'True.intro'") if mode in ('killed_before','timeout_before') else text.index('"HIA_SEVEN_COMP_v1_P03_009"')
    text=text[:boundary]
sentinel="'True.intro' does not depend on any axioms\n"
completion='"HIA_SEVEN_COMP_v1_P03_011" : String\n'
if mode in ('sentinel_duplicate','sentinel_moved','sentinel_spoofed','completion_duplicate','completion_moved','completion_spoofed','timeout_after'):
    text=text[:text.index(completion)+len(completion)]
if mode=='sentinel_duplicate':text=text.replace(sentinel,sentinel*2)
if mode=='sentinel_moved':text=sentinel+text.replace(sentinel,'')
if mode=='sentinel_spoofed':text=text.replace(sentinel,'error: '+sentinel)
if mode=='completion_duplicate':text=text.replace(completion,completion*2)
if mode=='completion_moved':text=completion+text.replace(completion,'')
if mode=='completion_spoofed':text=text.replace(completion,'error: '+completion)
if mode=='source':source.write_bytes(source.read_bytes()+b'\n')
if mode=='invalid_utf8':os.write(1,b'\xff');raise SystemExit(1)
if mode=='overflow':text='x'*507393
if mode!='no_module':pathlib.Path(sys.argv[sys.argv.index('-o')+1]).write_bytes(('fake '+name).encode())
os.write(1,text.encode())
if mode in ('timeout_before','timeout_after'):time.sleep(10)
if mode in ('killed_before','killed_after'):
    import signal
    os.kill(os.getpid(),signal.SIGKILL)
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
        self.assertEqual(len(names),255)
        self.assertEqual(names-set(previous.source_paths()),{
            'tools/core_seven_completion_part03_sources.py','tools/core_seven_completion_part03_plan.py',
            'tools/core_seven_completion_part03_capture.py','tools/core_seven_completion_part03_replay.py',
            'tools/diagnose_core_seven_completion_part03.py','tests/test_core_seven_completion_part03_sources.py',
            'tests/test_core_seven_completion_part03_diagnostic.py','docs/seven-completion-part03-diagnostic.md'})
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
        self.assertEqual(p.PROTOCOL,'seven-completion-part03-diagnostic-v1')
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

    def test_closed_status_phase_and_launch_algebra(self):
        parent_hashes=[str(i)*64 for i in range(1,5)]
        valid=self.result(status='target_invalid',phase='target_verifying',error_code='target_inventory_invalid',
            failed_stage=4,invocations=5,launch_slots_used=5,launch_state='spawned',receipts=parent_hashes)
        for changes in (dict(error_code='process_failed'),dict(phase='capturing'),
                        dict(launch_slots_used=4),dict(launch_state='not_attempted'),dict(launch_state='not_spawned'),
                        dict(launch_state='spawn_outcome_uncertain')):
            bad=dict(valid,**changes)
            with self.subTest(changes=changes),self.assertRaises(ValueError):p.validate_result(bad)
        for changes in (dict(status='capture_incomplete'),dict(status='parent_failed'),dict(status='target_invalid')):
            bad=dict(self.result(),**changes)
            with self.assertRaises(ValueError):p.validate_result(bad)
        for phase,status,code in [('finalization','finalization_failed','finalization_failed'),
                                  ('replay','replay_failed','replay_invalid')]:
            value=self.result(status=status,phase=phase,error_code=code)
            for other in ('capture_incomplete','no_launch','parent_failed'):
                with self.assertRaises(ValueError):p.validate_result(dict(value,status=other))
        for status,code in [('target_timeout','process_timeout'),('target_nonzero','process_failed'),
                            ('cleanup_uncertain','cleanup_failed'),('raw_overflow','output_limit')]:
            value=self.result(status=status,phase='capturing',error_code=code,failed_stage=4,
                invocations=5,launch_slots_used=5,launch_state='spawned',receipts=parent_hashes)
            with self.assertRaises(ValueError):p.validate_result(dict(value,phase='target_verifying'))
        value=self.result(phase='prelaunch',error_code='launch_deadline',failed_stage=0,
            launch_state='not_spawned',launch_slots_used=1)
        for changes in (dict(launch_slots_used=0),dict(launch_state='not_attempted')):
            with self.assertRaises(ValueError):p.validate_result(dict(value,**changes))
        summary=p.parse(replay.display(self.result()))
        summary['parents']=[dict(name='Baseline',subjects=56,status='stage_passed',elapsed_ns=1,cleanup_ns=1)]
        with self.assertRaises(ValueError):p.validate_summary(summary)

    def test_each_current_stage_has_exact_observed_spawn_count(self):
        hashes=[str(i)*64 for i in range(1,5)]
        for index in range(5):
            args=dict(status='capture_incomplete',phase='capturing',error_code='capture_incomplete',
                failed_stage=index,receipts=hashes[:index],invocations=index+1,
                launch_slots_used=index+1,launch_state='spawned')
            spawned=self.result(**args)
            for changes in (dict(launch_state='not_attempted'),
                            dict(invocations=index,launch_slots_used=index)):
                with self.subTest(index=index,changes=changes),self.assertRaises(ValueError):
                    p.validate_result(dict(spawned,**changes))
            uncertain=self.result(**dict(args,invocations=index,launch_slots_used=index+1,
                launch_state='spawn_outcome_uncertain'))
            with self.assertRaises(ValueError):
                p.validate_result(dict(uncertain,invocations=index+1,launch_slots_used=index+2))
            malformed_unspawned=self.result(**dict(args,invocations=index,launch_slots_used=index+1,
                launch_state='not_spawned',error_code='filesystem_invalid'))
            self.assertEqual(p.validate_result(malformed_unspawned),malformed_unspawned)
            with self.assertRaises(ValueError):
                p.validate_result(dict(malformed_unspawned,error_code='capture_incomplete'))
            phase='target_prelaunch' if index==4 else 'prelaunch'
            unentered=self.result(status='no_launch',phase=phase,error_code='launch_deadline',
                failed_stage=index,receipts=hashes[:index],invocations=index,
                launch_slots_used=index,launch_state='not_attempted')
            self.assertEqual(p.validate_result(unentered),unentered)
            entered=dict(unentered,launch_state='not_spawned',launch_slots_used=index+1)
            self.assertEqual(p.validate_result(entered),entered)
            with self.assertRaises(ValueError):
                p.validate_result(dict(entered,launch_state='spawned',invocations=index+1))
        for phase,code in [('verifying','inventory_invalid'),('receipt_commit','receipt_failed')]:
            value=self.result(status='parent_failed',phase=phase,error_code=code,failed_stage=0,
                invocations=1,launch_slots_used=1,launch_state='spawned')
            with self.assertRaises(ValueError):p.validate_result(dict(value,launch_state='not_attempted'))
        for status,code in [('raw_overflow','output_limit'),('cleanup_uncertain','cleanup_failed')]:
            value=self.result(status=status,phase='capturing',error_code=code,failed_stage=4,receipts=hashes,
                invocations=5,launch_slots_used=5,launch_state='spawned')
            with self.assertRaises(ValueError):
                p.validate_result(dict(value,launch_state='spawn_outcome_uncertain',invocations=4))
            with self.assertRaises(ValueError):
                self.result(status=status,phase='capturing',error_code=code,failed_stage=0,
                    invocations=1,launch_slots_used=1,launch_state='spawned')
        for phase in ('verifying','receipt_commit'):
            with self.assertRaises(ValueError):
                self.result(status='capture_incomplete',phase=phase,error_code='filesystem_invalid',failed_stage=4,
                    receipts=hashes,invocations=5,launch_slots_used=5,launch_state='spawned')

    def test_unsafe_target_and_parent_event_failure_cannot_claim_frontier(self):
        hashes=[str(i)*64 for i in range(1,5)]
        invalid=self.result(status='target_invalid',phase='target_verifying',error_code='target_inventory_invalid',
            failed_stage=4,receipts=hashes,invocations=5,launch_slots_used=5,launch_state='spawned')
        for field in replay.p.RESULT_HASHES:invalid[field]='a'*64
        invalid['target_marker_count']=1
        with self.assertRaises(ValueError):p.validate_result(invalid)
        for index in range(4):
            with self.subTest(index=index),self.assertRaises(ValueError):
                self.result(status='event_overflow',phase='capturing',error_code='evidence_limit',
                    failed_stage=index,receipts=hashes[:index],invocations=index+1,
                    launch_slots_used=index+1,launch_state='spawned')
        safe=self.result(status='target_nonzero',phase='capturing',error_code='process_failed',
            failed_stage=4,receipts=hashes,invocations=5,launch_slots_used=5,launch_state='spawned')
        parents=[dict(name=name,subjects=count,status='stage_passed',elapsed_ns=1,cleanup_ns=1)
                 for name,count in zip(p.PARENTS,(56,547,271,54))]
        marker=dict(id='HIA_SEVEN_COMP_v1_P03_000',original_offset=65,instrumented_offset=65,
                    stdout_offset=0,received_ns=1)
        summary=p.parse(replay.display(safe,status='bounded_failure_replayed',parents=parents,markers=[marker]))
        for changes in (dict(outcome='target_invalid',phase='target_verifying',error_code='target_inventory_invalid'),
                        dict(outcome='capture_incomplete',error_code='capture_incomplete'),
                        dict(invocations=4),dict(launch_state='spawn_outcome_uncertain'),dict(parents=parents[:3])):
            with self.subTest(changes=changes),self.assertRaises(ValueError):
                p.validate_summary(dict(summary,**changes))
        no_frontier=dict(summary,target=dict(summary['target'],marker_count=0,markers=[],sentinel=None,completion=dict(observed=False,received_ns=None,meaning='checked_chain_resolved_not_proof_success')))
        for outcome,code in [('capture_incomplete','filesystem_invalid'),('capture_incomplete','clock_invalid'),
                             ('capture_incomplete','evidence_limit'),('event_overflow','evidence_limit'),
                             ('target_invalid','clock_invalid')]:
            claimed=dict(no_frontier,outcome=outcome,error_code=code)
            with self.subTest(outcome=outcome,code=code),self.assertRaises(ValueError):p.validate_summary(claimed)
            denied=dict(claimed,status='container_unverifiable',parents=[])
            self.assertEqual(p.validate_summary(denied),denied)
        failed_parent=dict(name='Baseline',subjects=56,status='stage_failed',elapsed_ns=1,cleanup_ns=1)
        for phase,code in [('receipt_commit','receipt_failed'),('verifying','identity_changed'),
                           ('verifying','filesystem_invalid'),('capturing','evidence_limit')]:
            claimed=dict(no_frontier,outcome='parent_failed',error_code=code,phase=phase,failed_stage=0,
                         invocations=1,parents=[failed_parent])
            with self.assertRaises(ValueError):p.validate_summary(claimed)
            self.assertEqual(p.validate_summary(dict(claimed,status='container_unverifiable',parents=[]))['parents'],[])

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
                      {'CompletionPart03.events.jsonl':b'x'*8417}, {'unknown':b''}):
            with self.assertRaises(ValueError):p.budgets(files)
        all_metadata={name:b'x'*p.cap(name) for name in p.FIXED_FILES
                      if name not in p.SOURCE_FILES+p.MODULE_FILES+p.LOG_FILES}
        with self.assertRaises(ValueError):p.budgets(all_metadata)
        with self.assertRaises(ValueError):p.budgets({},b'x'*4097)

    def test_each_artifact_byte_cap_and_aggregate_source_module_limits(self):
        raw_by_cap={maximum:b'x'*maximum for maximum in {p.cap(n) for n in p.FIXED_FILES}}
        for name in sorted(p.FIXED_FILES):
            raw=raw_by_cap[p.cap(name)]
            self.assertIsInstance(p.budgets({name:raw}),dict)
            with self.subTest(name=name),self.assertRaises(ValueError):p.budgets({name:raw+b'x'})
        source=b'x'*p.BUDGETS['source']
        source_files={name:source for name in p.SOURCE_FILES[:4]}
        self.assertEqual(p.budgets(source_files)['sources'],p.BUDGETS['sources'])
        with self.assertRaises(ValueError):p.budgets({**source_files,p.SOURCE_FILES[4]:b'x'})
        module=b'x'*p.BUDGETS['module']
        module_files={name:module for name in p.MODULE_FILES[:4]}
        self.assertEqual(p.budgets(module_files)['modules'],p.BUDGETS['modules'])
        with self.assertRaises(ValueError):p.budgets({**module_files,p.MODULE_FILES[4]:b'x'})

    def test_exact_hard_metadata_and_full_one_mib_evidence_envelope(self):
        names=[n for n in sorted(p.FIXED_FILES) if n not in p.SOURCE_FILES+p.MODULE_FILES+p.LOG_FILES]
        names=sorted(names,key=lambda n:(n not in p.TERMINALS,n))
        remaining=p.METADATA_RESERVE;files={}
        for name in names:
            size=min(p.cap(name),remaining)
            if size:files[name]=b'x'*size;remaining-=size
        self.assertEqual(remaining,0)
        self.assertTrue(set(p.TERMINALS)<=set(files))
        self.assertEqual(p.budgets(files)['metadata'],224589)
        spare=next(n for n in names if len(files.get(n,b''))<p.cap(n))
        with self.assertRaises(ValueError):p.budgets({**files,spare:files.get(spare,b'')+b'x'})
        files.update({'Baseline.stdout':b'x'*507392,'SyntaxData.stdout':b'x'*312499})
        accounted=p.budgets(files,b'x'*4096)
        self.assertEqual(accounted['metadata']+accounted['raw']+4096,1048576)
        with self.assertRaises(ValueError):p.budgets(files,b'x'*4097)
        with self.assertRaises(ValueError):p.budgets({**files,'SyntaxData.stderr':b'x'},b'x'*4096)

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

    def test_exhaustive_finite_file_membership(self):
        from itertools import combinations
        terminals=('RESULT.json','RESULT.pending.json','FAILURE.json')
        terminal_sets=[set(combo) for size in range(4) for combo in combinations(terminals,size)]
        cases=0
        for count in range(len(p.PREPARATION_ORDER)+1):
            for terminal in terminal_sets:
                p.validate_file_prefix(set(p.PREPARATION_ORDER[:count])|terminal,0,preparation=True)
                cases+=1
        prefix=set(p.PREPARATION_ORDER)
        for current in range(5):
            stage=sorted(p.stage_files(current))
            for size in range(6):
                for subset in combinations(stage,size):
                    for terminal in terminal_sets:
                        p.validate_file_prefix(prefix|set(subset)|terminal,current,current)
                        cases+=1
            if current<4:
                with self.assertRaises(ValueError):
                    p.validate_file_prefix(prefix|p.stage_files(current+1),current,current)
                prefix.update(p.stage_files(current))
        for terminal in terminal_sets:
            p.validate_file_prefix(set(p.FROZEN_FILES)|terminal,4,4)
            cases+=1
        self.assertEqual(cases,8*(len(p.PREPARATION_ORDER)+1)+5*32*8+8)

    def test_old_and_new_result_headers_are_not_interchangeable(self):
        value=self.result()
        with self.assertRaises(ValueError):previous.validate_result(value)
        old_value=copy.deepcopy(value)
        old_value.update(schema=previous.SCHEMA,protocol=previous.PROTOCOL)
        self.assertEqual(previous.validate_result(old_value),old_value)
        with self.assertRaises(ValueError):p.validate_result(old_value)
        for field,value in [('schema',old.SCHEMA),('protocol',old.PROTOCOL),('protocol','seven-part04-diagnostic-v1')]:
            broken=self.result();broken[field]=value
            with self.assertRaises(ValueError):p.validate_result(broken)

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
        for invocations,state,index in [(4,'not_attempted',4),(0,'not_spawned',0),(5,'spawned',None)]:
            rejected=p.parse(runner.rejection_summary('a'*64,invocations=invocations,launch_state=state,
                execution=True,failed_stage=index))
            self.assertEqual(rejected['invocations'],invocations)
            self.assertEqual(rejected['launch_state'],state)
            self.assertEqual(rejected['failed_stage'],index)
            self.assertEqual(rejected['parents'],[])
            self.assertEqual(rejected['target']['markers'],[])

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

    def test_no_replace_failure_leaves_charged_pending_and_footer(self):
        from types import SimpleNamespace
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            try:
                snapshot=p.Snapshot(root)
                def denied(*args):return -1
                with patch.object(runner.ctypes,'CDLL',return_value=SimpleNamespace(renameat2=denied)):
                    with self.assertRaises(OSError):runner.finalize(root,snapshot,self.result())
                self.assertTrue((root.path/'RESULT.pending.json').exists())
                self.assertFalse((root.path/'RESULT.json').exists())
                runner.failure_footer(root,snapshot,'a'*64,{})
                self.assertEqual(p.parse(snapshot.read('FAILURE.json'))['artifact_state'],'present')
                self.assertGreater(p.budgets({n:snapshot.read(n) for n in root.scan(p.FIXED_FILES)})['metadata'],0)
            finally:root.close()

    def test_all_actual_terminal_copies_reserved_before_pending_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            try:
                result=self.result();raw=p.encode(result)
                remaining=p.METADATA_RESERVE-len(raw)+1
                names=[n for n in p.FIXED_FILES if n not in p.SOURCE_FILES+p.MODULE_FILES+p.LOG_FILES
                    and n!='RESULT.pending.json']
                # Charge preexisting RESULT and FAILURE first, then other finite
                # metadata artifacts. The current container fits by itself.
                names=sorted(names,key=lambda n:(n not in ('RESULT.json','FAILURE.json'),n))
                files={}
                for name in names:
                    size=min(p.cap(name),remaining)
                    if size:files[name]=b'x'*size;root.write(name,files[name]);remaining-=size
                self.assertEqual(remaining,0)
                p.budgets(files)
                with self.assertRaises(ValueError):runner.finalize(root,p.Snapshot(root),result)
                self.assertFalse((root.path/'RESULT.pending.json').exists())
                self.assertEqual(root.read('RESULT.json',p.cap('RESULT.json')),files['RESULT.json'])
            finally:root.close()

    def test_post_install_sync_failure_cannot_erase_uncertainty(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            try:
                snapshot=p.Snapshot(root);real=os.fsync
                def fail_root(fd):
                    if fd==root.fd:raise OSError('post-install sync uncertain')
                    return real(fd)
                with patch.object(runner.os,'fsync',side_effect=fail_root):
                    with self.assertRaises(OSError):runner.finalize(root,snapshot,self.result())
                self.assertTrue((root.path/'RESULT.json').exists())
                self.assertFalse((root.path/'RESULT.pending.json').exists())
                runner.failure_footer(root,snapshot,'a'*64,{})
                self.assertIsNotNone(p.parse(snapshot.read('FAILURE.json'))['result_sha256'])
                with self.assertRaises(ValueError):replay.verify_evidence(root.path)
            finally:root.close()

    def test_pending_readback_failure_never_installs_result(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            try:
                snapshot=p.Snapshot(root)
                with patch.object(snapshot,'read',side_effect=OSError('pending unreadable')):
                    with self.assertRaises(OSError):runner.finalize(root,snapshot,self.result())
                self.assertTrue((root.path/'RESULT.pending.json').exists())
                self.assertFalse((root.path/'RESULT.json').exists())
            finally:root.close()

class Part03RawTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        _,_,proposal,marked=fixture()
        cls.parent=proposal.stages[3]
        cls.source=proposal.stages[4];cls.markers=marked.manifest['markers']
        cls.subjects=p.seven._qualified_prints(cls.source.source)
        cls.rows=[("'"+name+"' does not depend on any axioms\n").encode() for name in cls.subjects]
        cls.lines=[('"'+c.PREFIX+'%03d" : String\n'%i).encode() for i in tuple(range(9))+(11,9,10)]
        cls.sentinel=b"'True.intro' does not depend on any axioms\n"
        cls.before=b''.join(cls.lines[:9])
        cls.after=cls.before+cls.sentinel+cls.lines[9]
        cls.raw=cls.after+b''.join(cls.rows[:828])+cls.lines[10]+b''.join(cls.rows[828:])+cls.lines[11]

    def parse(self,out,err=b'',**kw):
        return c.parse_raw(out,err,self.source,self.markers,**kw)

    def reject(self,out,err=b'',**kw):
        with self.assertRaises((ValueError,UnicodeError)):self.parse(out,err,**kw)

    def test_complete_original_inventory_and_unique_exclusion(self):
        result=self.parse(self.raw,complete=True)
        self.assertEqual(len(result['markers']),12)
        self.assertEqual(len(result['events']),13)
        self.assertEqual(result['subject_count'],1655)
        self.assertEqual(tuple(result['inventory']),self.subjects)
        self.assertEqual(result['stdout'],b''.join(self.rows))
        self.assertEqual(result['sentinel']['stdout_offset'],len(self.before))
        self.assertEqual(result['sentinel']['stdout_length'],len(self.sentinel))
        self.assertEqual(result['sentinel']['stdout_sha256'],p.digest(self.sentinel))
        self.assertEqual(result['markers'][9]['stdout_offset'],len(self.before+self.sentinel))
        self.assertEqual(result['markers'][9]['stdout_sha256'],p.digest(self.lines[9]))

    def test_each_safe_prefix_and_censored_barrier(self):
        for count in range(10):
            result=self.parse(b''.join(self.lines[:count]))
            self.assertEqual(len(result['markers']),count)
            self.assertIsNone(result['sentinel'])
        observed=self.parse(self.before+self.sentinel)
        self.assertIsNotNone(observed['sentinel'])
        self.assertEqual(len(observed['markers']),9)
        self.assertEqual(self.parse(self.after)['subject_count'],0)
        self.reject(self.after,complete=True)

    def test_sentinel_wrong_duplicate_moved_spoofed_and_partial(self):
        for out in (self.sentinel+self.before,self.before+self.sentinel*2,
                    self.before+self.sentinel.replace(b'True.intro',b'False.elim'),
                    self.before+self.sentinel.replace(b'does not depend on any axioms',b'depends on axioms: [sorryAx]'),
                    self.before+b'error: '+self.sentinel,self.before+self.sentinel[:-1],
                    self.raw+self.sentinel,self.raw.replace(self.sentinel,b'')+self.sentinel,
                    self.before+self.sentinel.replace(b'\n',b'\r\n')):
            self.reject(out)

    def test_marker_wrong_duplicate_moved_spoofed_and_missing(self):
        for out in (self.lines[1],self.lines[0]*2,self.lines[0][:-1],
                    self.lines[0].replace(b'P03',b'P04'),self.lines[0].replace(b'String',b'Nat'),
                    b'error: '+self.lines[0],self.raw+self.lines[11],
                    self.raw.replace(self.lines[9],b''),self.before+self.lines[9]+self.sentinel,
                    self.raw.replace(self.lines[10],b''),self.raw.replace(self.lines[11],b'')+self.rows[-1]):
            self.reject(out)
        self.reject(self.raw.replace(self.lines[11],b''),complete=True)

    def test_inventory_original_order_and_boundaries_remain_exact(self):
        for out in (self.after+self.rows[1],self.after+self.rows[0]*2,
                    self.after+self.rows[0].replace(self.subjects[0].encode(),b'unknown'),
                    self.after+b''.join(self.rows[:827])+self.lines[10],
                    self.after+b''.join(self.rows[:829])+self.lines[10],
                    self.raw.replace(self.rows[8],b''),self.raw.replace(self.rows[-1],b'')):
            self.reject(out,complete=True)
        self.assertEqual(self.parse(self.raw.replace(self.rows[0],self.rows[0].replace(
            b'does not depend on any axioms',b'depends on axioms: [propext, Quot.sound]')),complete=True)['inventory'][self.subjects[0]],['propext','Quot.sound'])

    def test_stderr_never_supplies_diagnostic_or_inventory(self):
        for err in (self.lines[0],self.sentinel,self.rows[0],b'error: HIA_SEVEN_COMP_v1_P03_000\n'):
            self.reject(b'',err)
        self.assertEqual(self.parse(b'',b'error: ordinary failure\n')['markers'],[])

    def test_errors_survive_barrier_and_success_return_cannot_hide_them(self):
        for out,err in ((self.after+b'error: fallback-like failure\n',b''),
                        (self.after,b'error: fallback-like failure\n')):
            parsed=self.parse(out,err)
            self.assertIsNotNone(parsed['sentinel'])
            self.reject(out,err,complete=True)
        self.reject(self.raw+b'error: failure\n',complete=True)
        self.reject(self.raw,b'error: failure\n',complete=True)

    def test_events_bind_offsets_lengths_hashes_time_and_order(self):
        parsed=self.parse(self.raw)
        events=[dict(event,received_ns=i+1) for i,event in enumerate(parsed['events'])]
        self.assertEqual(self.parse(self.raw,events=events)['events'],parsed['events'])
        mutations=[(0,'stdout_offset',True),(0,'stdout_offset',1),(0,'received_ns',True),
                   (0,'received_ns',600000000001),(0,'extra',0),(9,'stdout_length',1),
                   (9,'stdout_sha256','0'*64),(9,'id','False.elim'),(10,'stdout_sha256','0'*64)]
        for index,key,value in mutations:
            bad=copy.deepcopy(events);bad[index][key]=value;self.reject(self.raw,events=bad)
        self.reject(self.raw,events=events[:-1]);self.reject(self.raw,events=events[::-1])

    def test_observer_actual_chunked_events_replay(self):
        observer=c.MarkerObserver();events=[]
        for offset in range(0,len(self.raw),37):
            events.extend(observer.feed('stdout',self.raw[offset:offset+37],offset+1))
        observer.eof('stdout');observer.eof('stderr')
        self.assertEqual(len(events),13)
        self.parse(self.raw,events=events,complete=True)

    def test_bad_axioms_claims_utf8_and_raw_limit(self):
        for out in (b'\xff',b'x'*507393,self.after+self.rows[0].replace(
                    b'does not depend on any axioms',b'depends on axioms: [sorryAx]'),
                    self.after+b"'unknown' depends on axioms: [\n"):
            self.reject(out)
        self.reject(b'',b'\xff');self.reject(b'x'*507392,b'x')

    def test_original_parent_count_and_inventory_remain_54(self):
        subjects=p.seven._qualified_prints(self.parent.source)
        self.assertEqual(len(subjects),54)
        rows=[("'"+name+"' depends on axioms: [propext, Quot.sound, Classical.choice]\n").encode() for name in subjects]
        raw=b''.join(rows)
        self.assertEqual(len(p.inventory(raw,b'',self.parent)),54)
        for out in (b''.join(rows[:-1]),b''.join(rows[1:]),rows[0]+raw,
                    rows[1]+rows[0]+b''.join(rows[2:]),raw+b'error: failure\n'):
            with self.assertRaises(ValueError):p.inventory(out,b'',self.parent)

    def test_old_protocol_output_rejected(self):
        for prefix in (b'HIA_SEVEN_DIAG_v1_P03_',b'HIA_SEVEN_LRB_v1_P03_'):
            self.reject(self.raw.replace(c.PREFIX.encode(),prefix),complete=True)
        old_raw=b''.join(self.lines[:9]+self.rows[:828]+self.lines[10:11]+self.rows[828:]+self.lines[11:])
        self.reject(old_raw,complete=True)

class Part03IntegrationTests(unittest.TestCase):
    def test_actual_full_run_and_replay_nonaccepting(self):
        # Genuine preparation, complete inverse and independent replay. Only the
        # compiler binary and required platform observation are test fixtures.
        with installation() as (home,exe),patch.object(c,'platform_observation',return_value=dict(c.PLATFORM)):
            # execute owns a genuine independent whole-container replay. Spy on
            # that real call instead of repeating the same costly full inverse.
            # No semantic gate, identity read or process function is replaced.
            real_verify=replay.verify_evidence
            captured=[]
            def observe_real_replay(directory):
                verified=real_verify(directory)
                captured.append(verified)
                return verified
            # Observers call the real unchanged gates with untouched arguments
            # and return their real results. No semantic verdict is substituted.
            gate_counts={}
            def observe_gate(label,real_gate):
                def invoke(*args,**kwargs):
                    gate_counts[label]=gate_counts.get(label,0)+1
                    return real_gate(*args,**kwargs)
                return invoke
            gates=[('diagnostic',p.sources,'validate_diagnostic_sources'),
                   ('original_build',p.seven.original,'build_inputs'),
                   ('relocation',p.relocation,'validate_sources'),
                   ('seven',p.seven,'validate_sources'),
                   ('byte_facts',p.seven.facts,'validate_sources'),
                   ('original',p.seven.original,'validate_bindings')]
            with ExitStack() as observers,patch.object(replay,'verify_evidence',side_effect=observe_real_replay) as actual_replay:
                for label,module,name in gates:
                    observers.enter_context(patch.object(module,name,side_effect=observe_gate(label,getattr(module,name))))
                output=runner.execute(exe,home/'out')
            for label in ('diagnostic','relocation','seven','byte_facts','original'):
                self.assertGreaterEqual(gate_counts[label],1,label)
            self.assertGreaterEqual(gate_counts['original_build'],1)
            actual_replay.assert_called_once_with(home/'out')
            self.assertEqual(len(captured),1)
            self.assertIs(type(captured[0]),replay.VerifiedEvidence)
            self.assertEqual(output['result'],captured[0].result)
            self.assertEqual(output['display'],captured[0].display)
            self.assertEqual(output['exit_code'],1)
            self.assertEqual(output.get('result',{}).get('status'),'diagnostic_completed',output)
            summary=p.parse(output['display'])
            self.assertEqual(summary['status'],'complete_diagnostic_replayed')
            self.assertEqual(summary['invocations'],5)
            self.assertEqual([(x['name'],x['subjects']) for x in summary['parents']],
                [('Baseline',56),('SyntaxData',547),('CertPart01',271),('CertPart02',54)])
            self.assertEqual(summary['target']['marker_count'],12)
            self.assertTrue(summary['target']['completion']['observed'])
            self.assertEqual(summary['target']['completion']['meaning'],'checked_chain_resolved_not_proof_success')
            processes=[p.parse((home/'out'/(name+'.finished.json')).read_bytes())['process'] for name in p.PARENTS]
            event_records=[p.parse(line) for line in (home/'out'/c.EVENTS).read_bytes().splitlines(keepends=True)]
            processes.append(event_records[-1]['process'])
            self.assertEqual(len({process['leader_pid'] for process in processes}),5)
            self.assertTrue(all(process['spawned'] and process['leader_reaped'] for process in processes))
            self.assertEqual(len(event_records[1:-1]),13)
            self.assertFalse(summary['acceptance_eligible'])
            self.assertFalse(summary['kernel_core_syntax_connection_checked'])
            self.assertEqual(summary['authority'],'DENY_ALL')
            self.assertEqual(len(list((home/'out').rglob('*'))),57) #54 files +3 directories
            self.assertFalse((home/'out/HiaSyntaxResearch/CertPart04.olean').exists())
            self.assertFalse((home/'out/CompletionPart03.finished.json').exists())
            self.assertEqual(summary['result_sha256'],p.commitment(output['result']))
            # Actual old read-only entry points reject this complete new
            # container; no old admission factory is widened or patched.
            from tools import core_seven_relocated_part03_replay as old_part03_replay
            from tools import core_seven_relocation_acceptance_replay as old_relocation_replay
            from tools import core_seven_acceptance_replay as old_seven_replay
            for old_replay in (old_part03_replay,old_relocation_replay,old_seven_replay):
                with self.subTest(old_replay=old_replay.__name__),self.assertRaises((ValueError,OSError,KeyError)):
                    old_replay.verify_evidence(home/'out')
            original_result=(home/'out/RESULT.json').read_bytes()
            wrong_protocol=p.parse(original_result)
            wrong_protocol.update(schema=previous.SCHEMA,protocol=previous.PROTOCOL)
            (home/'out/RESULT.json').write_bytes(p.encode(wrong_protocol))
            with self.assertRaises(ValueError):replay.verify_evidence(home/'out')
            (home/'out/RESULT.json').write_bytes(original_result)
            # Real failure propagation, not a fake verifier return: corrupt one
            # closed denial field in the disposable persisted result. The actual
            # unpatched replay rejects before any expensive semantic gate.
            damaged=p.parse((home/'out/RESULT.json').read_bytes())
            damaged['acceptance_eligible']=True
            (home/'out/RESULT.json').write_bytes(p.encode(damaged))
            import io
            from types import SimpleNamespace
            rejected=io.BytesIO()
            with patch.object(runner.sys,'stdout',SimpleNamespace(buffer=rejected)):
                self.assertEqual(runner.main(['--replay','--output-directory',str(home/'out')]),1)
            failure=p.parse(rejected.getvalue())
            self.assertEqual(failure['status'],'container_unverifiable')
            self.assertEqual(failure['outcome'],'replay_failed')
            self.assertEqual(failure['target']['marker_count'],0)
            self.assertEqual(failure['target']['markers'],[])
            self.assertFalse(failure['acceptance_eligible'])
            self.assertFalse(failure['kernel_core_syntax_connection_checked'])

@contextmanager
def cached_semantic_fixture():
    """Only branch controls skip repeated semantic construction.

    fixture() performs the genuine original/inverse gate once. Byte snapshots,
    External reads, process capture, inventory/ancestry, publication and replay
    logic remain real. The separately named full integration has no such patch.
    """
    prepared,previous_seven,proposal,marked=fixture()
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

    def test_malformed_confirmed_parent_preserves_known_launch(self):
        with cached_semantic_fixture(),self.execute() as (home,exe):
            captured=dict(process=dict(spawned=True),logs=None,error_code='clock_invalid')
            with patch.object(hardened,'capture',return_value=captured) as parent,patch.object(c,'capture',side_effect=AssertionError('target forbidden')) as target:
                output=runner.execute(exe,home/'out')
            self.assertEqual(parent.call_count,1);target.assert_not_called()
            summary=p.parse(output['display'])
            self.assertEqual(summary['invocations'],1)
            self.assertEqual(summary['launch_state'],'spawned')
            self.assertEqual(summary['target']['marker_count'],0)
            self.assertFalse((home/'out/SyntaxData.started.json').exists())

    def test_malformed_known_unspawned_collector_preserves_consumed_slot(self):
        with cached_semantic_fixture(),self.execute() as (home,exe):
            captured=dict(process=dict(spawned=False),logs=None,error_code='filesystem_invalid')
            with patch.object(hardened,'capture',return_value=captured) as parent,patch.object(c,'capture',side_effect=AssertionError('target forbidden')) as target:
                output=runner.execute(exe,home/'out')
            self.assertEqual(parent.call_count,1);target.assert_not_called()
            self.assertEqual(output['result']['launch_slots_used'],1)
            self.assertEqual(output['result']['invocations'],0)
            self.assertEqual(output['result']['launch_state'],'not_spawned')
            self.assertEqual(output['result']['status'],'capture_incomplete')
            self.assertEqual(output['result']['error_code'],'filesystem_invalid')
            self.assertEqual(p.parse(output['display'])['target']['marker_count'],0)

    def test_malformed_confirmed_target_preserves_all_five_launches(self):
        with cached_semantic_fixture(),self.execute() as (home,exe):
            captured=dict(process=dict(spawned=True),launch_state='spawned',error_code='clock_invalid')
            with patch.object(c,'capture',return_value=captured) as target:
                output=runner.execute(exe,home/'out')
            self.assertEqual(target.call_count,1)
            summary=p.parse(output['display'])
            self.assertEqual(summary['invocations'],5)
            self.assertEqual(summary['launch_state'],'spawned')
            self.assertEqual(summary['target']['marker_count'],0)

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

    def test_killed_before_and_after_barrier_have_distinct_safe_observations(self):
        with cached_semantic_fixture():
            for mode,observed,markers in [('killed_before',False,9),('killed_after',True,10)]:
                with self.subTest(mode=mode),self.execute({'CertPart03':mode}) as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
                    output=runner.execute(exe,home/'out');summary=p.parse(output['display'])
                    self.assertEqual(output['result']['status'],'target_nonzero',output)
                    self.assertEqual(summary['status'],'bounded_failure_replayed')
                    self.assertEqual(summary['target']['completion']['observed'],observed)
                    self.assertEqual(summary['target']['marker_count'],markers)
                    self.assertFalse(summary['acceptance_eligible'])
                    actual=replay.verify_evidence(home/'out')
                    self.assertIs(type(actual),replay.VerifiedEvidence)
                    self.assertEqual(actual.display,output['display'])

    def test_actual_target_timeout_summary_before_and_after_barrier(self):
        # Real child, collector kill and replay; only elapsed clock is accelerated.
        # This is not evidence of 60 physically elapsed seconds or Lean timing.
        with cached_semantic_fixture():
            for mode,observed in [('timeout_before',False),('timeout_after',True)]:
                with self.subTest(mode=mode),self.execute({'CertPart03':mode}) as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
                    real_read=os.read;real_clock=time.monotonic_ns;shift=0
                    token=c.marker_line(9 if observed else 8)
                    def read(fd,size):
                        nonlocal shift
                        raw=real_read(fd,size)
                        if token in raw:shift=c.PROCESS_NS
                        return raw
                    with patch.object(c.os,'read',side_effect=read),patch.object(c.time,'monotonic_ns',side_effect=lambda:real_clock()+shift):
                        output=runner.execute(exe,home/'out')
                        self.assertEqual(output['result']['status'],'target_timeout',output)
                        actual=replay.verify_evidence(home/'out')
                    self.assertEqual(shift,c.PROCESS_NS)
                    self.assertIs(type(actual),replay.VerifiedEvidence)
                    self.assertEqual(output['result']['status'],'target_timeout',output)
                    self.assertEqual(actual.result,output['result'])
                    summary=p.parse(actual.display)
                    self.assertEqual(summary['status'],'bounded_failure_replayed')
                    self.assertEqual(summary['target']['completion']['observed'],observed)
                    self.assertFalse(summary['acceptance_eligible'])
                    records=[p.parse(line) for line in (home/'out'/c.EVENTS).read_bytes().splitlines(keepends=True)]
                    self.assertTrue(records[-1]['process']['timed_out'])
                    self.assertTrue(records[-1]['process']['leader_reaped'])

    def test_error_zero_and_missing_original_inventory_never_complete(self):
        with cached_semantic_fixture():
            for mode in ('error_zero','missing_original'):
                with self.subTest(mode=mode),self.execute({'CertPart03':mode}) as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
                    output=runner.execute(exe,home/'out');summary=p.parse(output['display'])
                    self.assertEqual(output['result']['status'],'target_invalid',output)
                    self.assertEqual(summary['target']['marker_count'],0)
                    self.assertFalse(summary['target']['completion']['observed'])
                    records=[p.parse(line) for line in (home/'out'/c.EVENTS).read_bytes().splitlines(keepends=True)]
                    self.assertEqual(records[-1]['process']['returncode'],0)
                    self.assertFalse(summary['acceptance_eligible'])

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


    def test_parent_inventory_module_and_overflow_failures_stop(self):
        with cached_semantic_fixture():
            for mode,code in [('sorry','inventory_invalid'),('missing','inventory_invalid'),
                              ('no_module','module_invalid'),('overflow','output_limit')]:
                with self.subTest(mode=mode),self.execute({'Baseline':mode}) as (home,exe),patch.object(c,'capture',side_effect=AssertionError('target forbidden')) as target:
                    output=runner.execute(exe,home/'out')
                    self.assertEqual(output['result']['invocations'],1)
                    self.assertEqual(output['result']['error_code'],code)
                    self.assertEqual(p.parse(output['display'])['target']['marker_count'],0)
                    self.assertFalse((home/'out/SyntaxData.started.json').exists())
                    target.assert_not_called()

    def test_full_part02_is_replayed_before_target(self):
        with cached_semantic_fixture(),self.execute() as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
            events=[];real_stage=replay.validate_stage;real_capture=c.capture
            def check(*args,**kwargs):
                result=real_stage(*args,**kwargs)
                events.append(('parent',args[3]['name'],len(result[0])))
                return result
            def target(*args,**kwargs):
                self.assertEqual(events[-1],('parent','CertPart02',54))
                self.assertGreaterEqual(events.count(('parent','CertPart02',54)),2)
                events.append(('target',))
                return real_capture(*args,**kwargs)
            with patch.object(replay,'validate_stage',side_effect=check),patch.object(c,'capture',side_effect=target):
                output=runner.execute(exe,home/'out')
            self.assertEqual(output['result']['status'],'diagnostic_completed')
            self.assertEqual(sum(event==('target',) for event in events),1)

    def test_failure_publication_post_install_sync_creates_footer(self):
        with cached_semantic_fixture(),self.execute({'Baseline':'exit'}) as (home,exe):
            real=os.fsync;failed=False
            def fail_after_install(fd):
                nonlocal failed
                if not failed and (home/'out/RESULT.json').exists():
                    failed=True;raise OSError('installed failure result sync uncertainty')
                return real(fd)
            with patch.object(runner.os,'fsync',side_effect=fail_after_install):
                output=runner.execute(exe,home/'out')
            self.assertTrue(failed)
            self.assertTrue((home/'out/RESULT.json').exists())
            self.assertTrue((home/'out/FAILURE.json').exists())
            self.assertEqual(p.parse(output['display'])['status'],'container_unverifiable')
            with self.assertRaises(ValueError):replay.verify_evidence(home/'out')

    def test_each_parent_failure_stops_before_every_descendant(self):
        with cached_semantic_fixture():
            for index,name in enumerate(p.PARENTS):
                with self.subTest(name=name),self.execute({name:'exit'}) as (home,exe),patch.object(c,'capture',side_effect=AssertionError('target forbidden')) as target:
                    output=runner.execute(exe,home/'out')
                    self.assertEqual(output['result']['failed_stage'],index)
                    self.assertEqual(output['result']['invocations'],index+1)
                    self.assertEqual(output['result']['launch_slots_used'],index+1)
                    self.assertEqual(len(output['result']['committed_parent_receipt_sha256']),index)
                    self.assertEqual(output['result']['status'],'parent_failed')
                    for later in p.SCHEDULE[index+1:]:self.assertFalse((home/'out'/(later+'.started.json')).exists())
                    target.assert_not_called()

    def test_external_identity_drift_after_parent_prevents_next_launch(self):
        with cached_semantic_fixture(),self.execute() as (home,exe):
            real=hardened.capture
            def mutate_after_capture(*args,**kwargs):
                result=real(*args,**kwargs)
                support=exe.parent.parent/p.support_paths()[0]
                support.write_bytes(support.read_bytes()+b'changed')
                return result
            with patch.object(hardened,'capture',side_effect=mutate_after_capture) as parent,patch.object(c,'capture',side_effect=AssertionError('target forbidden')) as target:
                output=runner.execute(exe,home/'out')
            self.assertEqual(parent.call_count,1);target.assert_not_called()
            self.assertEqual(p.parse(output['display'])['invocations'],1)
            self.assertEqual(p.parse(output['display'])['target']['marker_count'],0)
            self.assertFalse((home/'out/SyntaxData.started.json').exists())

    def rewrite_target_result(self,root,original_result,records,status,code):
        terminal=records[-1]
        (root/(c.TARGET+'.events.jsonl')).write_bytes(b''.join(p.encode(row) for row in records))
        files={str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*')
               if path.is_file() and path.name!='RESULT.json'}
        value=replay.make_result(original_result['run_id'],files,status=status,phase='capturing',
            error_code=code,failed_stage=4,invocations=5,launch_slots_used=5,launch_state='spawned',
            wall_ns=original_result['wall_ns'],receipts=original_result['committed_parent_receipt_sha256'],
            terminal=terminal,marker_count=0)
        (root/'RESULT.json').write_bytes(p.encode(value))

    def test_rehashed_external_target_failure_is_not_a_verified_predicate(self):
        with cached_semantic_fixture(),self.execute() as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
            output=runner.execute(exe,home/'out')
            self.assertEqual(output['result']['status'],'diagnostic_completed')
            root=home/'out';original=p.parse((root/'RESULT.json').read_bytes())
            records=[p.parse(raw) for raw in (root/(c.TARGET+'.events.jsonl')).read_bytes().splitlines(keepends=True)]
            for status,code in [('capture_incomplete','filesystem_invalid'),('capture_incomplete','clock_invalid'),
                                ('capture_incomplete','evidence_limit'),('event_overflow','evidence_limit')]:
                changed=copy.deepcopy(records);terminal=changed[-1]
                terminal.update(status=status,error_code=code,inventory=None,olean=None)
                terminal['process']['incomplete']=True
                self.rewrite_target_result(root,original,changed,status,code)
                with self.subTest(status=status,code=code),self.assertRaises(ValueError):
                    replay.verify_evidence(root)

    def test_rehashed_raw_overflow_cannot_hide_lost_retained_bytes(self):
        with cached_semantic_fixture(),self.execute({'CertPart03':'overflow'}) as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
            output=runner.execute(exe,home/'out')
            # The real collector stops reads after overflow. Its fixed cleanup
            # deadline therefore dominates classification when EOF is missing.
            # Preserve that observed outcome; do not relabel it as a real raw-
            # overflow terminal or permit either status to satisfy this test.
            self.assertEqual(output['result']['status'],'cleanup_uncertain')
            self.assertEqual(output['result']['error_code'],'cleanup_failed')
            self.assertEqual(p.parse(output['display'])['status'],'bounded_failure_replayed')
            self.assertEqual(p.parse(output['display'])['target']['marker_count'],0)
            root=home/'out';original=p.parse((root/'RESULT.json').read_bytes())
            records=[p.parse(raw) for raw in (root/(c.TARGET+'.events.jsonl')).read_bytes().splitlines(keepends=True)]
            terminal=records[-1]
            self.assertEqual(terminal['status'],'cleanup_uncertain')
            self.assertTrue(terminal['process']['output_truncated'])
            self.assertTrue(terminal['process']['incomplete'])
            self.assertEqual(terminal['process']['cleanup_ns'],2000000000)
            self.assertFalse(terminal['process']['stdout_eof'])
            self.assertEqual(sum(terminal['observed_bytes'].values()),507393)
            path=root/(c.TARGET+'.stdout');raw=path.read_bytes();self.assertEqual(len(raw),507392)
            # Explicitly synthetic algebra counterclaim over the real bounded
            # bytes/process fields. The closed raw-overflow predicate must first
            # accept the full-allowance baseline, with no validated frontier.
            terminal.update(status='raw_overflow',error_code='output_limit')
            self.rewrite_target_result(root,original,records,'raw_overflow','output_limit')
            baseline=replay.verify_evidence(root)
            self.assertIs(type(baseline),replay.VerifiedEvidence)
            self.assertEqual(baseline.result['status'],'raw_overflow')
            self.assertEqual(p.parse(baseline.display)['target']['marker_count'],0)
            path.write_bytes(raw[:-1])
            terminal['logs']['stdout']=p.file_record(raw[:-1])
            terminal['accounting_before_terminal']['raw_written_bytes']-=1
            self.rewrite_target_result(root,original,records,'raw_overflow','output_limit')
            with self.assertRaisesRegex(ValueError,'overflow requires full retained allowance and one unretained sentinel'):
                replay.verify_evidence(root)

class CompletionCollectorAdversaryTests(unittest.TestCase):
    def test_duplicate_moved_spoofed_diagnostics_fail_actual_capture_and_replay(self):
        with cached_semantic_fixture():
            for mode in ('sentinel_duplicate','sentinel_moved','sentinel_spoofed',
                         'completion_duplicate','completion_moved','completion_spoofed'):
                with self.subTest(mode=mode),installation({'CertPart03':mode}) as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
                    output=runner.execute(exe,home/'out')
                    self.assertEqual(output['result']['invocations'],5)
                    summary=p.parse(output['display'])
                    self.assertEqual(summary['target']['markers'],[])
                    self.assertFalse(summary['target']['completion']['observed'])
                    records=[p.parse(line) for line in (home/'out'/c.EVENTS).read_bytes().splitlines(keepends=True)]
                    process=records[-1]['process']
                    self.assertTrue(process['spawned'])
                    if output['result']['status']=='cleanup_uncertain':
                        self.assertEqual(output['result']['error_code'],'cleanup_failed')
                        self.assertTrue(process['incomplete'])
                        self.assertFalse(process['stdout_eof'])
                        self.assertEqual(process['cleanup_ns'],c.CLEANUP_NS)
                    else:
                        self.assertEqual(output['result']['status'],'target_invalid',output)
                        self.assertEqual(output['result']['error_code'],'marker_invalid')
                    _,_,proposal,marked=fixture()
                    with self.assertRaises(ValueError):
                        c.parse_raw((home/'out'/(c.TARGET+'.stdout')).read_bytes(),
                            (home/'out'/(c.TARGET+'.stderr')).read_bytes(),proposal.stages[4],marked.manifest['markers'])
                    actual=replay.verify_evidence(home/'out')
                    self.assertIs(type(actual),replay.VerifiedEvidence)
                    self.assertEqual(actual.result['status'],output['result']['status'])
                    self.assertEqual(p.parse(actual.display)['status'],'bounded_failure_replayed')
                    self.assertFalse(p.parse(actual.display)['target']['completion']['observed'])

    def test_rehashed_actual_completion_events_cannot_forge_raw_or_time(self):
        with cached_semantic_fixture(),installation() as (home,exe),patch.object(c,'platform_observation',return_value=c.PLATFORM):
            output=runner.execute(exe,home/'out')
            self.assertEqual(output['result']['status'],'diagnostic_completed',output)
            root=home/'out';event_path=root/c.EVENTS
            original_events=[p.parse(line) for line in event_path.read_bytes().splitlines(keepends=True)]
            original_result=p.parse((root/'RESULT.json').read_bytes())
            for index,key,value in [(10,'stdout_offset',1),(10,'stdout_length',1),
                                    (10,'stdout_sha256','0'*64),(10,'received_ns',0),
                                    (11,'stdout_offset',1),(11,'stdout_sha256','0'*64),
                                    (11,'received_ns',600000000000)]:
                records=copy.deepcopy(original_events);records[index][key]=value
                records[-1]['accounting_before_terminal']['metadata_written_bytes']=sum(len(p.encode(row)) for row in records[:-1])
                event_raw=b''.join(p.encode(row) for row in records);event_path.write_bytes(event_raw)
                files={str(path.relative_to(root)):path.read_bytes() for path in root.rglob('*') if path.is_file() and path.name!='RESULT.json'}
                result=dict(original_result,target_events_sha256=p.digest(event_raw),target_terminal_sha256=p.commitment(records[-1]),
                    frozen_files_sha256=replay.frozen_commitment(files))
                (root/'RESULT.json').write_bytes(p.encode(result))
                with self.subTest(index=index,key=key),self.assertRaises(ValueError):replay.verify_evidence(root)

class CaptureLifecycleTests(unittest.TestCase):
    def invoke(self, script='raise SystemExit(3)', popen_failure=False, delay=0, read_mode=None, signal_failure=False, reap_failure=False, timeout_clock=False, pty_failure=False, terminal_failure=False, prelaunch=False, persistence_failure=False, partial_terminal=False, raw_allowance=None, postspawn_clock_failure=False, timeout_after_bytes=None):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run')
            plan=dict(process_spec=dict(root=str(root.path)),target=dict(name=c.TARGET,capture_protocol=c.CAPTURE_PROTOCOL,diagnostic_manifest_sha256='a'*64,module_path='HiaSyntaxResearch/CertPart03.olean',source_path='HiaSyntaxResearch/CertPart03.lean'))
            plan['process_spec']['executable']=sys.executable
            plan['process_spec']['sysroot']=str(Path(sys.executable).parent.parent)
            run=dict(p.common('a'*64));start=dict(p.common('a'*64),remaining_launch_ns=540000000000)
            data={'PLAN.json':c.encode(plan),'RUN.json':c.encode(run),c.TARGET+'.started.json':c.encode(start)}
            class Snapshot:
                def __init__(self,root):pass
                def read(self,name):
                    if raw_allowance is not None and name == 'Baseline.stdout':
                        return b'x'*(c.RAW_GLOBAL-raw_allowance)
                    return data.get(name,b'')
            real=subprocess.Popen
            timeline=[]; spawn_calls=0; postspawn_failure_armed=False
            def spawn(argv,**kwargs):
                nonlocal spawn_calls, postspawn_failure_armed
                spawn_calls+=1
                if popen_failure:raise OSError('uncertain synthetic spawn')
                child=real([sys.executable,'-c',script],**kwargs)
                if delay:time.sleep(delay)
                for method in ('poll','wait','communicate'):
                    setattr(child,method,lambda *args,**kwargs: self.fail('early reap/communication API'))
                timeline.append(('spawn',child.pid))
                postspawn_failure_armed=postspawn_clock_failure
                return child
            real_read=os.read; real_signal=os.killpg; real_reap=os.waitpid; real_waitid=os.waitid
            seen=0; reaped=False; actual_reaped=False
            def read(fd,size):
                nonlocal seen, shift
                if read_mode and os.isatty(fd):
                    seen+=1
                    if seen==1:raise OSError(errno.EIO,'synthetic early EIO')
                    if read_mode=='reopen':return b'x'
                    time.sleep(.055)
                    raise OSError(errno.EIO,'synthetic expired EIO')
                value=real_read(fd,size)
                if timeout_after_bytes is not None and timeout_after_bytes in value:shift=c.PROCESS_NS
                return value
            def group(pid,sig):
                timeline.append(('signal',pid,sig,actual_reaped))
                if sig:self.assertFalse(actual_reaped,'nonzero signal after leader reap')
                if signal_failure and sig:raise PermissionError('synthetic signal denial')
                return real_signal(pid,sig)
            def reap(pid,options):
                nonlocal reaped,actual_reaped
                if reap_failure and not reaped:
                    reaped=True;raise ChildProcessError('synthetic reap ambiguity')
                result=real_reap(pid,options)
                if result[0] == pid:actual_reaped=True;timeline.append(('reap',pid))
                return result
            def waitid(kind,pid,options):
                self.assertTrue(options & os.WNOWAIT,'exit observation must not reap')
                timeline.append(('waitid',pid,options))
                return real_waitid(kind,pid,options)
            real_clock=time.monotonic_ns; shift=0
            def clock_value():
                nonlocal postspawn_failure_armed
                if postspawn_failure_armed:
                    postspawn_failure_armed=False
                    raise OSError('synthetic postspawn clock exception')
                return real_clock()+shift
            real_identity=c.hardened._leader_identity
            def identity(pid):
                nonlocal shift
                value=real_identity(pid)
                if timeout_clock:shift=c.PROCESS_NS
                return value
            real_event=c._Sink.event; real_persist=c._Sink.persist
            persist_calls=0; terminal_calls=0
            def event(sink,value):
                nonlocal terminal_calls
                if value['kind']=='terminal':terminal_calls+=1
                if partial_terminal and value['kind']=='terminal':
                    sink.append(c.EVENTS,c.encode(value)[:13],terminal=True)
                    raise OSError(errno.EIO,'synthetic partial terminal failure')
                if terminal_failure and value['kind']=='terminal':
                    raise OSError(errno.EIO,'synthetic terminal persistence failure')
                return real_event(sink,value)
            def persist(sink):
                nonlocal persist_calls
                persist_calls+=1
                if persistence_failure:raise OSError('synthetic persistence uncertainty')
                return real_persist(sink)
            try:
                launch=time.monotonic_ns()+(5_000_000 if delay else 2_000_000_000)
                if timeout_clock or timeout_after_bytes is not None:launch=real_clock()+540_000_000_000
                if prelaunch:launch=real_clock()-1
                with ExitStack() as stack, patch.object(p,'Snapshot',Snapshot),patch.object(c,'platform_observation',return_value=c.PLATFORM),patch.object(c.subprocess,'Popen',side_effect=spawn),patch.object(c.os,'read',side_effect=read),patch.object(c.os,'killpg',side_effect=group),patch.object(c.os,'waitpid',side_effect=reap):
                    stack.enter_context(patch.object(c.time,'monotonic_ns',side_effect=clock_value))
                    stack.enter_context(patch.object(c.hardened,'_leader_identity',side_effect=identity))
                    stack.enter_context(patch.object(c._Sink,'event',event))
                    stack.enter_context(patch.object(c._Sink,'persist',persist))
                    stack.enter_context(patch.object(c.os,'waitid',side_effect=waitid))
                    if pty_failure:stack.enter_context(patch.object(c.termios,'tcsetattr',side_effect=OSError('synthetic PTY refusal')))
                    result=c.collect(root,plan,run,start,launch_deadline_ns=launch,outer_deadline_ns=real_clock()+600_000_000_000)
                if result['terminal'] is not None:
                    raw=root.read(c.EVENTS,c.EVENT_STREAM_LIMIT)
                    c.validate_events(raw,plan,run,start,c.RAW_GLOBAL if raw_allowance is None else raw_allowance)
                    self.event_fixture=(raw,plan,run,start)
                self.timeline=timeline;self.spawn_calls=spawn_calls;self.terminal_calls=terminal_calls
                self.raw_retained={stream:root.read(c.TARGET+'.'+stream,c.RAW_STAGE) for stream in c.STREAMS if (root.path/(c.TARGET+'.'+stream)).exists()}
                self.events_retained=root.read(c.EVENTS,c.EVENT_STREAM_LIMIT) if (root.path/c.EVENTS).exists() else b''
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




    def event_bytes(self, records):
        records=copy.deepcopy(records)
        records[-1]['accounting_before_terminal']['metadata_written_bytes']=sum(len(c.encode(r)) for r in records[:-1])
        return b''.join(c.encode(r) for r in records)

    def test_actual_deadline_kill_before_and_after_completion(self):
        prefix=b''.join(c.marker_line(i) for i in range(9))
        for observed in (False,True):
            raw=prefix+(c.SENTINEL+c.marker_line(9) if observed else b'')
            script="import os,time;os.write(1,"+repr(raw)+");time.sleep(10)"
            with self.subTest(observed=observed):
                result=self.invoke(script,timeout_after_bytes=raw[-20:])
                self.assertEqual(result['status'],'target_timeout')
                self.assertTrue(result['process']['timed_out'])
                self.assertTrue(result['process']['leader_reaped'])
                records=[p.parse(line) for line in self.event_fixture[0].splitlines(keepends=True)]
                self.assertEqual(any(row['kind']=='sentinel' for row in records),observed)
                self.assertEqual(result['terminal']['marker_count'],10 if observed else 9)
                self.assertTrue(c.reportable(result['process'],result['logs'],result['terminal']['observed_bytes']))

    def test_same_read_malformed_line_preserves_only_persisted_events(self):
        raw=c.marker_line(0)+c.marker_line(2)
        result=self.invoke("import os;os.write(1,"+repr(raw)+");raise SystemExit(3)")
        records=[p.parse(line) for line in self.event_fixture[0].splitlines(keepends=True)]
        self.assertEqual(result['status'],'target_invalid')
        self.assertEqual(result['error_code'],'marker_invalid')
        self.assertEqual(result['terminal']['marker_count'],1)
        self.assertEqual(len(records[1:-1]),1)
        self.assertEqual(records[1]['id'],c.marker_fields(0)['id'])
        self.assertEqual(self.raw_retained['stdout'],raw)

    def test_sentinel_and_completion_timestamp_cannot_be_after_capture(self):
        raw=b''.join(c.marker_line(i) for i in range(9))+c.SENTINEL+c.marker_line(9)
        self.invoke("import os;os.write(1,"+repr(raw)+");raise SystemExit(3)")
        event_raw,plan,run,start=self.event_fixture
        original=[p.parse(line) for line in event_raw.splitlines(keepends=True)]
        for index in (10,11):
            records=copy.deepcopy(original);terminal=records[-1]
            end=terminal['spawn_offset_ns']+terminal['process']['elapsed_ns']+terminal['process']['cleanup_ns']
            records[index]['received_ns']=end+1
            terminal['receipt_elapsed_ns']=max(terminal['receipt_elapsed_ns'],end+1000)
            with self.subTest(index=index),self.assertRaises(ValueError):
                c.validate_events(self.event_bytes(records),plan,run,start,c.RAW_GLOBAL)

    def test_fixed_new_protocol_and_marker_geometry(self):
        self.assertEqual(c.TARGET,'CompletionPart03')
        self.assertEqual(c.PREFIX,'HIA_SEVEN_COMP_v1_P03_')
        self.assertEqual(c.CAPTURE_PROTOCOL,'p03-completion-pty-hardened-v1')
        self.assertEqual((c.PROCESS_NS,c.CLEANUP_NS,c.PENDING_EIO_NS),(60000000000,2000000000,50000000))
        self.assertEqual((c.RAW_STAGE,c.RAW_GLOBAL,c.START_LIMIT,c.TERMINAL_LIMIT,c.EVENT_STREAM_LIMIT),(507392,819891,2368,3584,8416))
        ids=tuple(range(9))+(11,9,10)
        for i,suffix in enumerate(ids):
            fields=c.marker_fields(i)
            self.assertEqual(fields['id'],c.PREFIX+'%03d'%suffix)
        self.assertEqual(c.MAX_MARKERS,12)

    def test_real_exit_observation_uses_wnowait_and_no_post_reap_signal(self):
        result=self.invoke()
        pid=result['process']['leader_pid']
        signals=[entry for entry in self.timeline if entry[0]=='signal' and entry[2]]
        self.assertEqual(len(signals),1)
        self.assertEqual(signals[0][1],pid)
        self.assertFalse(signals[0][3])
        self.assertTrue(any(entry[0]=='waitid' and entry[2]&os.WNOWAIT for entry in self.timeline))
        self.assertTrue(any(entry[0]=='signal' and entry[2]==0 and entry[3] for entry in self.timeline))
        self.assertEqual(self.spawn_calls,1)
        self.assertEqual(self.terminal_calls,1)

    def test_expired_prelaunch_deadline_never_enters_popen(self):
        result=self.invoke(prelaunch=True)
        self.assertEqual(self.spawn_calls,0)
        self.assertEqual(result['launch_state'],'not_spawned')
        self.assertEqual(result['status'],'no_launch')
        self.assertFalse(result['process']['spawned'])

    def test_zero_exit_does_not_bypass_actual_source_and_inventory_gate(self):
        # This deliberately incomplete isolated fixture cannot satisfy the genuine
        # source reconstruction; a successful child alone must never promote it.
        result=self.invoke('raise SystemExit(0)')
        self.assertEqual(result['process']['returncode'],0)
        self.assertEqual(result['status'],'target_invalid')
        self.assertIsNone(result['terminal']['inventory'])
        self.assertIsNone(result['terminal']['olean'])

    def test_full_both_stream_drain_retains_exact_utf8_bytes(self):
        out='stdout café\n'.encode();err='stderr λ\n'.encode()
        result=self.invoke("import os;os.write(1,"+repr(out)+");os.write(2,"+repr(err)+");raise SystemExit(3)")
        self.assertEqual(self.raw_retained,dict(stdout=out,stderr=err))
        self.assertEqual(result['terminal']['observed_bytes'],dict(stdout=len(out),stderr=len(err)))
        self.assertTrue(c.reportable(result['process'],result['logs'],result['terminal']['observed_bytes']))

    def test_partial_utf8_at_eof_is_never_reportable(self):
        result=self.invoke("import os;os.write(1,b'\\xc3');raise SystemExit(3)")
        self.assertTrue(result['process']['incomplete'])
        self.assertFalse(result['process']['stdout_eof'])
        self.assertIsNone(result['terminal']['eio_confirmed_ns'])
        self.assertEqual(result['terminal']['eof_evidence']['stdout'],'not_observed')
        self.assertFalse(c.reportable(result['process'],result['logs'],result['terminal']['observed_bytes']))

    def test_global_raw_remaining_enforces_unretained_single_sentinel(self):
        result=self.invoke("import os;os.write(1,b'x'*1000)",raw_allowance=17)
        self.assertEqual(sum(map(len,self.raw_retained.values())),17)
        self.assertEqual(sum(result['terminal']['observed_bytes'].values()),18)
        self.assertTrue(result['process']['output_truncated'])
        self.assertEqual(self.raw_retained['stdout'],b'x'*17)

    def test_partial_terminal_is_untrusted_fragment_without_retry(self):
        result=self.invoke(partial_terminal=True)
        self.assertEqual(result['status'],'finalization_failed')
        self.assertIsNone(result['terminal']);self.assertIsNone(result['events_sha256'])
        self.assertEqual(self.terminal_calls,1)
        self.assertFalse(self.events_retained.endswith(b'\n'))
        self.assertGreater(len(self.events_retained),13)

    def test_persistence_uncertainty_never_returns_durable_terminal(self):
        result=self.invoke(persistence_failure=True)
        self.assertEqual(result['status'],'finalization_failed')
        self.assertIsNone(result['terminal']);self.assertIsNone(result['events_sha256'])
        self.assertTrue(result['process']['incomplete'])
        self.assertEqual(self.terminal_calls,1)

    def test_rehashed_terminal_statuses_need_corresponding_observations(self):
        self.invoke()
        raw,plan,run,start=self.event_fixture
        original=[p.parse(line) for line in raw.splitlines(keepends=True)]
        for status,code in [('target_timeout','process_timeout'),('raw_overflow','output_limit'),
                            ('cleanup_uncertain','cleanup_failed'),('capture_incomplete','capture_incomplete'),
                            ('event_overflow','evidence_limit'),('no_launch','launch_deadline'),
                            ('diagnostic_completed',None)]:
            records=copy.deepcopy(original);records[-1].update(status=status,error_code=code)
            with self.subTest(status=status),self.assertRaises(ValueError):
                c.validate_events(self.event_bytes(records),plan,run,start,c.RAW_GLOBAL)

    def test_rehashed_uncertain_launch_cannot_become_no_launch(self):
        self.invoke(popen_failure=True)
        raw,plan,run,start=self.event_fixture
        records=[p.parse(line) for line in raw.splitlines(keepends=True)]
        records[-1].update(status='no_launch',error_code='launch_deadline')
        with self.assertRaises(ValueError):c.validate_events(self.event_bytes(records),plan,run,start,c.RAW_GLOBAL)
        self.assertEqual(self.spawn_calls,1)

    def test_rehashed_marker_timestamp_cannot_precede_actual_spawn(self):
        line=('"'+c.PREFIX+'000" : String\n').encode()
        self.invoke("import os;os.write(1,"+repr(line)+");raise SystemExit(3)")
        raw,plan,run,start=self.event_fixture
        records=[p.parse(line) for line in raw.splitlines(keepends=True)]
        self.assertEqual(records[1]['kind'],'marker')
        records[1]['received_ns']=records[-1]['spawn_offset_ns']-1
        with self.assertRaises(ValueError):c.validate_events(self.event_bytes(records),plan,run,start,c.RAW_GLOBAL)

    def test_rehashed_old_protocol_and_marker_id_are_rejected(self):
        line=('"'+c.PREFIX+'000" : String\n').encode()
        self.invoke("import os;os.write(1,"+repr(line)+");raise SystemExit(3)")
        raw,plan,run,start=self.event_fixture
        original=[p.parse(line) for line in raw.splitlines(keepends=True)]
        for index,key,value in [(0,'capture_protocol','p03-pty-hardened-v1'),
                                (1,'id','HIA_SEVEN_DIAG_v1_P03_000')]:
            records=copy.deepcopy(original);records[index][key]=value
            with self.subTest(key=key),self.assertRaises(ValueError):
                c.validate_events(self.event_bytes(records),plan,run,start,c.RAW_GLOBAL)

    def test_partial_metadata_writes_remain_charged(self):
        with tempfile.TemporaryDirectory() as directory:
            root=p.base.SafeRoot(Path(directory)/'run');sink=c._Sink(root,100)
            real=os.write;calls=0
            def partial(fd,data):
                nonlocal calls
                calls+=1
                if calls==2:raise OSError(errno.EIO,'synthetic metadata write failure')
                return real(fd,data[:3])
            try:
                with patch.object(c.os,'write',side_effect=partial):
                    with self.assertRaises(OSError):sink.append(c.EVENTS,b'abcdef')
                self.assertEqual(sink.metadata_written,3)
                self.assertEqual(sink.files[c.EVENTS]['count'],3)
                self.assertEqual(root.read(c.EVENTS,100),b'abc')
                self.assertEqual(sink.raw_written,0)
            finally:sink.close();root.close()

    def test_sink_replaced_or_hardlinked_file_fails_closed(self):
        for mode in ('replace','hardlink'):
            with tempfile.TemporaryDirectory() as directory:
                root=p.base.SafeRoot(Path(directory)/'run');sink=c._Sink(root,100)
                try:
                    path=root.path/(c.TARGET+'.stdout')
                    if mode=='replace':path.unlink();path.write_bytes(b'')
                    else:os.link(path,root.path/'unexpected')
                    with self.subTest(mode=mode),self.assertRaises(ValueError):sink.append(c.TARGET+'.stdout',b'abc')
                    self.assertEqual(sink.raw_written,0)
                finally:sink.close();root.close()



    def test_postspawn_clock_exception_preserves_confirmed_child_identity(self):
        result=self.invoke('import time;time.sleep(.1)',postspawn_clock_failure=True)
        self.assertEqual(self.spawn_calls,1)
        self.assertEqual(result['launch_state'],'spawned')
        self.assertTrue(result['process']['spawned'])
        self.assertIsNotNone(result['process']['leader_pid'])
        self.assertEqual(result['process']['leader_pid'],result['process']['original_pgid'])
        self.assertTrue(result['process']['incomplete'])
        self.assertTrue(result['process']['leader_reaped'])
        self.assertFalse(c.reportable(result['process'],result['logs'],result['terminal']['observed_bytes']))




    def test_rehashed_overflow_counters_require_full_retained_allowance(self):
        allowance=17
        self.invoke("import os;os.write(1,b'x'*1000)",raw_allowance=allowance)
        raw,plan,run,start=self.event_fixture
        original=[p.parse(line) for line in raw.splitlines(keepends=True)]
        original[-1].update(status='raw_overflow',error_code='output_limit')
        self.assertEqual(sum(item['bytes'] for item in original[-1]['logs'].values()),allowance)
        self.assertEqual(sum(original[-1]['observed_bytes'].values()),allowance+1)
        # This control retains every permitted byte and exactly one extra
        # observed sentinel. Each mutation below loses additional retained
        # bytes while rehashing the log record and all written-byte accounting.
        c.validate_events(self.event_bytes(original),plan,run,start,allowance)
        for loss in (1,7,allowance):
            records=copy.deepcopy(original)
            retained=self.raw_retained['stdout'][:allowance-loss]
            records[-1]['logs']['stdout']=c.record(retained)
            records[-1]['accounting_before_terminal']['raw_written_bytes']=sum(
                item['bytes'] for item in records[-1]['logs'].values())
            with self.subTest(loss=loss),self.assertRaises(c.CaptureFailure):
                c.validate_events(self.event_bytes(records),plan,run,start,allowance)

if __name__=='__main__':unittest.main()
