"""Independent concurrent resource audit: operand effects and malformed graphs."""
import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest

from hepta.concurrent_ir import verify_concurrent_ir
from hepta.pipeline import analyze, concurrent_ir_analysis
from tests.test_concurrent_ir import SOURCE, adversarial_graphs, graph, operations

ROOT = Path(__file__).resolve().parents[1]

INVALID_SOURCES = {
    "group_joined_in_timeout_operand": """fn f()->Unit effects {alloc,block,panic,write} {
      let group=task_group(0,0,1);let mut out:u64=0;
      let status=group_receive_timeout(read group,mut out,group_cancel_and_join(move group).sum);
    }""",
    "left_joined_in_select_operand": """fn f()->Unit effects {alloc,block,panic,write} {
      let left=task_group(0,0,1);let right=task_group(0,0,1);let mut out:u64=0;
      let status=group_select_receive(read left,read right,mut out,false,group_cancel_and_join(move left).sum);
      let report=group_cancel_and_join(move right);
    }""",
    "right_joined_in_select_operand": """fn f()->Unit effects {alloc,block,panic,write} {
      let left=task_group(0,0,1);let right=task_group(0,0,1);let mut out:u64=0;
      let status=group_select_receive(read left,read right,mut out,false,group_cancel_and_join(move right).sum);
      let report=group_cancel_and_join(move left);
    }""",
    "group_joined_in_budget_configuration": """fn f()->Unit effects {alloc,block,panic,write} {
      let mut group=task_group(0,0,1);
      let configured=group_budget_configure(mut group,1,1,1,131072,group_cancel_and_join(move group).sum as usize);
    }""",
    "buffer_dropped_by_index_computation": """fn dispose(b:take Buffer<u8>)->usize effects {alloc,block} {release(move b);return 0;}
      fn f()->Unit effects {alloc,block,panic} {let b=buffer(2);let value=b[dispose(move b)];}""",
    "buffer_dropped_by_assignment_index": """fn dispose(b:take Buffer<u8>)->usize effects {alloc,block} {release(move b);return 0;}
      fn f()->Unit effects {alloc,block,panic,write} {let mut b=buffer(2);b[dispose(move b)]=7;}""",
    "buffer_dropped_by_assignment_rhs": """fn dispose(b:take Buffer<u8>)->u8 effects {alloc,block} {release(move b);return 7;}
      fn f()->Unit effects {alloc,block,panic,write} {let mut b=buffer(2);b[0]=dispose(move b);}""",
    "earlier_call_borrow_consumed_by_later_argument": """fn read_at(b:read Buffer<u8>,i:usize)->u8 effects {panic} {return b[i];}
      fn dispose(b:take Buffer<u8>)->usize effects {alloc,block} {release(move b);return 0;}
      fn f()->Unit effects {alloc,block,panic} {let b=buffer(2);let value=read_at(read b,dispose(move b));}""",
}

VALID_SOURCES = {
    "index_consumes_other_buffer": """fn dispose(b:take Buffer<u8>)->usize effects {alloc,block} {release(move b);return 0;}
      fn f()->Unit effects {alloc,block,panic} {let b=buffer(2);let other=buffer(3);let value=b[dispose(move other)];release(move b);}""",
    "assignment_rhs_and_index_complete_before_store": """fn dispose(b:take Buffer<u8>)->usize effects {alloc,block} {release(move b);return 0;}
      fn f()->Unit effects {alloc,block,panic,write} {let mut b=buffer(2);let other=buffer(3);b[dispose(move other)]=b[1];release(move b);}""",
    "group_operand_joins_another_group": """fn f()->Unit effects {alloc,block,panic,write} {
      let group=task_group(0,0,1);let other=task_group(0,0,1);let mut out:u64=0;
      let status=group_receive_timeout(read group,mut out,group_cancel_and_join(move other).sum);
      let report=group_cancel_and_join(move group);
    }""",
    "snapshot_then_join": """fn f()->u64 effects {alloc,block,panic,write} {let group=task_group(0,0,1);
      let total=wrapping_add(group_snapshot(read group).sum,group_cancel_and_join(move group).sum);return total;}""",
    "loop_condition_only_borrows_then_final_join": """fn f()->Unit effects {alloc,block,panic,write} {
      let mut group=task_group(0,0,1);let mut stop:bool=false;
      while !stop&&group_snapshot(read group).active_tasks==0 {group_cancel(mut group);stop=true;}
      let report=group_cancel_and_join(move group);
    }""",
}


class ConcurrentOperandAudit(unittest.TestCase):
    def test_later_operand_cannot_consume_an_owner_used_by_the_operation(self):
        for label,source in INVALID_SOURCES.items():
            with self.subTest(label=label):
                frontend=analyze(source,native=False)
                self.assertTrue(frontend.report['ok'],frontend.report)
                exported=concurrent_ir_analysis(frontend)
                self.assertFalse(exported['ok'],exported)
                self.assertEqual(exported['verifier']['diagnostics'][0]['code'],'E_CIR_USE_AFTER_MOVE',exported)
                native=analyze(source,rustc=os.environ.get('RUSTC'))
                self.assertFalse(native.report['ok'],native.report)
                self.assertEqual(native.report['checks']['rust_borrows_types'],'rejected')
                self.assertTrue(any(d.get('phase')=='backend' and d['code'] in {'E0505','E0382'} for d in native.report['diagnostics']))

    def test_distinct_resources_and_completed_reads_remain_valid(self):
        for label,source in VALID_SOURCES.items():
            with self.subTest(label=label):
                native=analyze(source,rustc=os.environ.get('RUSTC'))
                self.assertTrue(native.report['ok'],native.report)
                exported=concurrent_ir_analysis(native)
                self.assertTrue(exported['ok'],exported)

    def test_select_and_shared_budget_projects_have_independent_graphs(self):
        for name in ('select_pipeline','shared_budget'):
            with self.subTest(name=name):
                analysis=analyze((ROOT/'examples/groups'/f'{name}.hepta').read_text(),native=False)
                exported=concurrent_ir_analysis(analysis)
                self.assertTrue(exported['ok'],exported)

    def test_no_parser_checker_import_in_standalone_verifier(self):
        process=subprocess.run([sys.executable,'-c',"import sys;import hepta.concurrent_ir;assert 'hepta.parser' not in sys.modules;assert 'hepta.checker' not in sys.modules"],cwd=ROOT,capture_output=True,text=True,timeout=10)
        self.assertEqual(process.returncode,0,process.stderr)

    def test_additional_malformed_graph_and_scope_controls(self):
        original=graph()
        cases=[]
        def add(label,mutate):
            document=copy.deepcopy(original);mutate(document);cases.append((label,document))
        add('worker_returns_task',lambda d:d['functions'][0].update(returns='Task<u64>'))
        add('worker_input_is_borrowed',lambda d:d['functions'][0]['params'][0].update(mode='read'))
        add('cancellation_forged_local',lambda d:d['functions'][0]['slots'].update(invented='Cancellation'))
        add('buffer_forged_as_group',lambda d:d['functions'][0]['slots'].update(v0='TaskGroup'))
        add('nonboolean_claim',lambda d:d['claims'].update(normal_exit_join_obligations_verified=1))
        add('duplicate_block',lambda d:d['functions'][-1]['blocks'].append(copy.deepcopy(d['functions'][-1]['blocks'][0])))
        add('empty_function_graph',lambda d:d['functions'][-1].update(blocks=[]))
        add('empty_function_list',lambda d:d.update(functions=[]))
        add('extra_parameter_owner',lambda d:d['functions'][0]['params'].append({'id':'extra','type':'Buffer<u8>','mode':'take'}))
        add('missing_worker_release',lambda d:operations(d,'work').pop())
        add('invented_group',lambda d:next(op for op in operations(d) if op['op']=='spawn').update(group='invented'))
        add('group_spawn_escapes_task',lambda d:next(op for op in operations(d) if op['op']=='spawn').update(task='escaped'))
        add('source_boolean',lambda d:d.update(source_sha256=True))
        add('project_short_hash',lambda d:d.update(project_sha256='abc'))
        add('slot_name_unbounded',lambda d:d['functions'][-1]['slots'].update({'a'*257:'Buffer<u8>'}))
        add('unknown_terminator',lambda d:d['functions'][-1]['blocks'][0].update(terminator={'op':'ignore_resources'}))
        add('return_conceals_owner',lambda d:d['functions'][-1]['blocks'][0].update(terminator={'op':'return','owner':'v0'}))
        add('edge_not_hashable',lambda d:d['functions'][-1]['blocks'][0].update(terminator={'op':'jump','targets':[[]]}))
        add('operations_not_list',lambda d:d['functions'][-1]['blocks'][0].update(operations={}))
        add('owner_overwrite',lambda d:operations(d).insert(1,copy.deepcopy(operations(d)[0])))
        for label,document in cases:
            with self.subTest(label=label):self.assertFalse(verify_concurrent_ir(document)['ok'],label)


if __name__=='__main__':unittest.main()
