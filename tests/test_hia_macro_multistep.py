"""Synthetic no-provider controls for the v2 matched search and strict adapter."""
from copy import deepcopy
from contextlib import ExitStack
from hashlib import sha256
import json
import sys
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_ndu_optimizer import ns_to_ms_q32
from tools.hia_macro_multistep_provider import (RESPONSE_SCHEMA, command, parse_stream,
    request_document, prompt_bytes, StructuredProvider)
from tools import hia_macro_multistep_provider as provider_module
from tools.prepare_hia_followup_tasks import task_documents, mathematical_value
from tools.qualify_hia_macro_multistep import (checked_pool_selection, calibration_forecast,
    protocol, proposal_admission, run_cell)
from tools.qualify_hia_macro_campaign import Evidence
from hepta.hia_agent_macro_policy import ledger_totals
from tools import qualify_hia_macro_multistep as campaign_module

USAGE = {'input_tokens':100,'cached_input_tokens':75,'cache_write_input_tokens':0,
         'output_tokens':10,'reasoning_output_tokens':2}


def stream(text, *, extra=(), usage=None):
    rows = [{'type':'thread.started','thread_id':'authored-test'}, {'type':'turn.started'}, *extra,
        {'type':'item.completed','item':{'id':'answer','type':'agent_message','text':text}},
        {'type':'turn.completed','usage':USAGE if usage is None else usage}]
    return b''.join(json.dumps(row).encode()+b'\n' for row in rows)


class StructuredOutputTests(unittest.TestCase):
    def test_valid_envelope_does_not_skip_core_checker(self):
        row = parse_stream(stream(json.dumps({'assembly':'not a program'})))
        self.assertTrue(row['stream_valid'])
        self.assertEqual(row['charged_model_tokens'],112)
        with self.assertRaises(ValueError):
            assemble_program(row['answer']['assembly'])

    def test_bad_json_retains_usage_and_is_only_a_planned_round_rejection(self):
        for text in ('{"assembly" "missing-colon"}', '```json\n{"assembly":"x"}\n```',
                     '{"assembly":"a","assembly":"b"}', '{"candidate":{}}'):
            row = parse_stream(stream(text))
            self.assertTrue(row['stream_valid'])
            self.assertTrue(row['content_rejected_with_known_usage'])
            self.assertEqual(row['usage'],USAGE)
            self.assertIsNone(row['answer'])

    def test_unknown_usage_is_not_zero_or_recoverable(self):
        row = parse_stream(stream('{"assembly":"x"}',usage={'input_tokens':10,'output_tokens':1}))
        self.assertFalse(row['stream_valid'])
        self.assertIsNone(row['charged_model_tokens'])
        self.assertFalse(row['content_rejected_with_known_usage'])

    def test_foreign_tool_is_protocol_failure_not_content_retry(self):
        row = parse_stream(stream('{"assembly":"x"}',extra=[{'type':'item.completed',
            'item':{'id':'tool','type':'command_execution','command':'authored fixture'}}]))
        self.assertFalse(row['stream_valid'])
        self.assertFalse(row['content_rejected_with_known_usage'])
        self.assertEqual(row['usage'],USAGE)

    def test_actual_output_schema_flag_and_model_are_frozen_arguments(self):
        args = command('/fake-codex','explicit-model','low',Path('/trial/round-1'))
        at = args.index('--output-schema')
        self.assertEqual(args[at+1],'/trial/round-1/response-schema.json')
        self.assertEqual(args[-3:],['-m','explicit-model','-'])
        self.assertEqual(RESPONSE_SCHEMA['required'],['assembly'])
        self.assertFalse(RESPONSE_SCHEMA['additionalProperties'])

    def test_hidden_task_fields_cannot_enter_public_prompt(self):
        public = {'id':'fixture','instruction':'maintain','specification':{},'baseline_assembly':'public',
            'objective':{},'provenance':{},'hidden_oracle':'DO_NOT_SEND_ORACLE',
            'feasibility_assembly':'DO_NOT_SEND_TEACHER'}
        request = request_document(public,[],{'original':{'wall_ns':180_000_000_000}})
        raw = prompt_bytes(request)
        self.assertNotIn(b'DO_NOT_SEND_ORACLE',raw)
        self.assertNotIn(b'DO_NOT_SEND_TEACHER',raw)
        self.assertFalse(request['arm_identity_disclosed_to_proposer'])
        with self.assertRaisesRegex(ValueError,'history'):
            request_document(public,[{}, {}, {}],{})

    def test_post_dispatch_observation_exception_freezes_later_cells(self):
        public = {'id':'fixture','instruction':'maintain','specification':{},
            'baseline_assembly':'public','objective':{},'provenance':{}}
        request = request_document(public,[],{'original':{'wall_ns':180_000_000_000}})
        original_read = Path.read_bytes
        for phase in ('transport','read','save','parse','launcher'):
            with self.subTest(phase=phase), tempfile.TemporaryDirectory() as temporary:
                provider = StructuredProvider(str(Path(sys.executable).absolute()),'fixture')
                # A validated launcher is already frozen before dispatch. This
                # fixture reaches only its observer; no executable is launched.
                if phase == 'launcher':
                    provider.launcher_binding = {'authored_no_exec_fixture':True}
                failure = RuntimeError('authored '+phase+' observation failure')
                dispatched, save_failed = [], []
                class Evidence:
                    def put(self,value,*,binary=False):
                        if dispatched and phase == 'save' and not save_failed:
                            save_failed.append(True)
                            raise failure
                        raw = value if binary else json.dumps(value,sort_keys=True).encode()
                        return sha256(raw).hexdigest()
                def no_process(argv,cwd,output,**kwargs):
                    dispatched.append(True)
                    output = Path(output)
                    output.mkdir()
                    for name,raw in {'stdin.raw':kwargs['input_bytes'],
                            'stdout.raw':stream('{"assembly":"fixture"}'),'stderr.raw':b''}.items():
                        (output/name).write_bytes(raw)
                    (output.parent/'LAUNCH-ADAPTER.json').write_text('{}')
                    if phase == 'transport':
                        raise failure
                    return {'argv':argv,'cwd':str(cwd),'status':'exited','returncode':0,
                        'cleanup_confirmed':True,'leader_reaped':True,'streams_complete':True,'wall_ns':1}
                def read(path):
                    if dispatched and phase == 'read' and path.name == 'stdout.raw':
                        raise failure
                    return original_read(path)
                with ExitStack() as stack:
                    invoke = stack.enter_context(patch.object(provider_module,'run_owned',side_effect=no_process))
                    stack.enter_context(patch.object(Path,'read_bytes',read))
                    if phase == 'parse':
                        stack.enter_context(patch.object(provider_module,'parse_stream',side_effect=failure))
                    if phase == 'launcher':
                        stack.enter_context(patch.object(provider_module,'validate_launch',side_effect=failure))
                    with self.assertRaises(RuntimeError) as caught:
                        provider.invoke(request,Evidence(),Path(temporary)/'first',
                            remaining_wall_ns=1_000_000_000,remaining_tokens=32768)
                    self.assertIs(caught.exception,failure)
                    self.assertIsNotNone(provider.blocked_reason)
                    later = provider.invoke(request,Evidence(),Path(temporary)/'later',
                        remaining_wall_ns=1_000_000_000,remaining_tokens=32768)
                    self.assertEqual(later['status'],'not_attempted')
                    self.assertIsNone(later['process'])
                    self.assertEqual(invoke.call_count,1)
                    self.assertFalse((Path(temporary)/'later').exists())


class ProposalReservationTests(unittest.TestCase):
    def costs(self, remaining=100, *, complete=True):
        observed = ledger_totals([])
        observed['complete'] = complete
        return {'original':{'wall_ns':180_000_000_000,'model_tokens':32768},
            'observed':observed,'remaining_wall_ns':1_000_000_000,'remaining_tokens':remaining}

    def test_previous_actual_bill_is_an_estimate_with_an_exact_equality_boundary(self):
        prior = {'status':'completed','charged_model_tokens':100}
        snapshot = deepcopy(prior)
        self.assertEqual(proposal_admission(self.costs(99),prior,'a'*64)['action'],'stop_proposals')
        decision = proposal_admission(self.costs(100),prior,'a'*64)
        self.assertEqual(decision['action'],'dispatch')
        self.assertEqual(decision['estimated_next_round_tokens'],100)
        self.assertFalse(decision['estimate_is_hard_mid_turn_cap'])
        self.assertEqual(prior,snapshot)

    def test_unknown_or_unsettled_previous_attempt_freezes_even_with_positive_allowance(self):
        for prior in ({'status':'completed','charged_model_tokens':None},
                      {'status':'failed','charged_model_tokens':100}, None):
            decision = proposal_admission(self.costs(),prior,'a'*64)
            self.assertEqual(decision['action'],'freeze')
            self.assertFalse(decision['unknown_cost_is_zero'])
        self.assertEqual(proposal_admission(self.costs(complete=False))['action'],'freeze')
        known_rejection = {'status':'failed','recoverable_content_rejection':True,'charged_model_tokens':101}
        self.assertEqual(proposal_admission(self.costs(),known_rejection,'a'*64)['action'],'stop_proposals')

    def fake_cell(self, directory, arm, provider):
        """Only controller flow: all domain/native operations are authored fakes."""
        evidence = Evidence(directory)
        used = []
        images = {'baseline':b'BASELINE','candidate':b'NEW'}
        def ref(name):
            return {'id':name,'sha256':sha256(images.get(name,name.encode())).hexdigest(),
                    'uri':'hia://artifacts/'+name}
        class Client:
            records = []
            def result(self, tool, arguments):
                used.append(tool)
                if tool == 'hia_adopt':
                    return {'current':{'generation':'1','epoch':'1'},'previous':{'generation':'0','epoch':'0'}}
                return {'current':{'generation':'0','epoch':'2'}}
        client = Client()
        class Session:
            def __init__(self,*args,**kwargs):
                self.client,self.discovery,self.imported = client,{'fixture':True},0
            def freeze(self,*args,**kwargs): return {'fixture':True}
            def import_program(self,*args):
                self.imported += 1
                return ref('baseline' if self.imported == 1 else 'candidate')
            def verify(self,*args,**kwargs):
                return {'checks':[{'status':'proved'}],'verification_receipt':ref('proof')}
            def emit(self,program,**kwargs):
                return {'native_artifact':program,'build_receipt':ref('build')}
            def encoding(self,*args): return {'verification_receipt':ref('encoding')}
            def evaluate(self,*args,**kwargs):
                return {'planned_workload_complete':True,'outcome':'improved','evaluation_receipt':ref('evaluation')}
            def read(self,artifact): return images[artifact['id']]
            def harvest(self,*args): pass
            def arguments(self,**kwargs): return kwargs
        public = {'id':'authored-control','instruction':'fixture','specification':{},'baseline':{},
            'baseline_assembly':'fixture','objective':{},'provenance':{'authored_test_only':True}}
        hidden = {'cases':[{'function':'transform','arguments':[x]} for x in range(256)]}
        registration = {'budget':{'wall_ns':180_000_000_000,'model_tokens':32768},
            'installation':{'fixture':True},'tool_objective':{},'objective_sha256':'a'*64}
        with ExitStack() as stack:
            stack.enter_context(patch.object(campaign_module,'HIAAgentService',return_value=SimpleNamespace(
                identities={'fixture':True},call=None,close=lambda:None)))
            stack.enter_context(patch.object(campaign_module,'ToolClient',return_value=client))
            stack.enter_context(patch.object(campaign_module,'CapturingSession',Session))
            stack.enter_context(patch.object(campaign_module,'assemble_program',
                return_value=SimpleNamespace(as_dict=lambda:{'authored_fixture':True})))
            stack.enter_context(patch.object(campaign_module,'_native_result_correct',return_value=True))
            stack.enter_context(patch.object(campaign_module,'run_native_batch',return_value={
                'termination_confirmed':True,'wall_ns':1,'report':{'total_native_ns':'1'}}))
            stack.enter_context(patch.object(campaign_module,'_native_rank',
                return_value=({'advisory_recommendation':'abstain'},{'authored_fixture':True})))
            row,summary = run_cell(evidence,public,hidden,{'input_sha256':'b'*64,
                'qualification_receipt_sha256':'c'*64},arm,registration,provider=provider,
                bridge={'authored_fixture':True},state_parent=Path(directory)/'unused-state',calibration=[])
        result = json.loads((evidence.root/'objects'/row['result_receipt_sha256']).read_bytes())
        admissions = [json.loads((evidence.root/'objects'/key).read_bytes())['output']
                      for key in result['proposal_admission_receipts']]
        return row,result,admissions,used

    def test_qualified_pool_survives_known_insufficient_tokens_without_a_second_dispatch(self):
        class Provider:
            blocked_reason = None
            def __init__(self): self.calls = 0
            def invoke(self,*args,**kwargs):
                self.calls += 1
                return {'status':'completed','charged_model_tokens':20000,'answer':{'assembly':'fixture'}}
        for arm in ('fixed','greedy','ordinary','ndu'):
            with self.subTest(arm=arm), tempfile.TemporaryDirectory() as directory:
                provider = Provider()
                row,result,admissions,used = self.fake_cell(Path(directory)/'evidence',arm,provider)
                self.assertEqual(provider.calls,1)
                self.assertIsNone(provider.blocked_reason)
                self.assertEqual([a['action'] for a in admissions],['dispatch','stop_proposals'])
                self.assertEqual(admissions[-1]['cost_state']['remaining_tokens'],12768)
                self.assertEqual(admissions[-1]['estimated_next_round_tokens'],20000)
                self.assertTrue(row['correct'])  # Authored flow fixture; no native/model qualification.
                self.assertEqual(result['selected_id'],'candidate.1')
                self.assertEqual(used,['hia_adopt','hia_rollback'])
                self.assertEqual(ledger_totals(row['ledger'])['observed_model_tokens'],20000)

    def test_unknown_second_attempt_keeps_first_pool_unqualified_and_blocks_later_cells(self):
        class Provider:
            blocked_reason = None
            def __init__(self): self.calls = 0
            def invoke(self,*args,**kwargs):
                self.calls += 1
                if self.calls == 2:
                    raise RuntimeError('authored unsettled provider attempt')
                return {'status':'completed','charged_model_tokens':100,'answer':{'assembly':'fixture'}}
        with tempfile.TemporaryDirectory() as directory:
            provider = Provider()
            row,result,admissions,used = self.fake_cell(Path(directory)/'first','ordinary',provider)
            self.assertEqual(provider.calls,2)
            self.assertEqual(len(result['pool']),1)
            self.assertFalse(row['correct'])
            self.assertEqual(used,[])
            self.assertFalse(ledger_totals(row['ledger'])['complete'])
            self.assertIsNotNone(provider.blocked_reason)
            later,_,_,later_used = self.fake_cell(Path(directory)/'later','ordinary',provider)
            self.assertEqual(provider.calls,2)
            self.assertFalse(later['correct'])
            self.assertEqual(later_used,[])


class MatchedStrongControlTests(unittest.TestCase):
    def row(self, name, immediate, remaining, *, quality=True, uncertainty=0):
        return {'id':name,'quality_complete':quality,'immediate_ns':immediate,
            'remaining_cost_ns':remaining,'uncertainty_ns':uncertainty,'support_sha256':'a'*64,
            'artifact_sha256':'b'*64,'artifact_bytes':100}

    def select(self, arm, pool, remaining=1_000_000_000):
        return checked_pool_selection(arm,pool,remaining_wall_ns=remaining,bridge=None,
            objective_sha256='c'*64,generation=1)

    def test_full_ordinary_considers_every_complete_continuation(self):
        rows = [self.row('candidate.1',1,300),self.row('candidate.2',5,100)]
        self.assertEqual(self.select('fixed',rows)['selected_id'],'candidate.1')
        self.assertEqual(self.select('greedy',rows)['selected_id'],'candidate.1')
        self.assertEqual(self.select('ordinary',rows)['selected_id'],'candidate.2')
        self.assertEqual(self.select('ordinary',list(reversed(rows)))['selected_id'],'candidate.2')

    def test_incomplete_cheapest_candidate_is_never_a_delivered_control(self):
        rows = [self.row('candidate.1',0,0,quality=False),self.row('candidate.2',1,100)]
        for arm in ('fixed','greedy','ordinary'):
            self.assertEqual(self.select(arm,rows)['selected_id'],'candidate.2')
            self.assertIsNone(self.select(arm,rows[:1])['selected_id'])

    def test_uncertainty_and_original_remaining_budget_bind_ordinary(self):
        rows = [self.row('candidate.1',1,10,uncertainty=100),self.row('candidate.2',2,99)]
        self.assertEqual(self.select('ordinary',rows,remaining=100)['selected_id'],'candidate.2')
        self.assertIsNone(self.select('ordinary',rows,remaining=98)['selected_id'])

    def test_native_receives_same_cost_rows_and_an_actual_feasible_incumbent(self):
        rows = [self.row('candidate.1',1,300),self.row('candidate.2',5,100)]
        seen = []
        def native(bridge,request,*,timeout_s):
            seen.append(deepcopy(request))
            return {'advisory_recommendation':'candidate.2'},{'fixture':True}
        with patch('tools.qualify_hia_macro_multistep._native_rank',side_effect=native):
            result = checked_pool_selection('ndu',rows,remaining_wall_ns=1000,
                bridge={'authored':'fixture'},objective_sha256='c'*64,generation=1)
        self.assertEqual(result['selected_id'],self.select('ordinary',rows,remaining=1000)['selected_id'])
        self.assertFalse(seen[0]['candidates'][0]['hard_violation'])
        self.assertEqual(seen[0]['candidates'][0]['cost_q32'],ns_to_ms_q32(300))
        self.assertEqual(seen[0]['candidates'][1]['cost_q32'],ns_to_ms_q32(100))
        self.assertEqual(result['feasible_incumbent_id'],'candidate.1')
        self.assertFalse(result['net_benefit_established'])

    def test_native_abstain_maps_only_to_actual_qualified_candidate(self):
        rows = [self.row('candidate.1',0,0,quality=False),self.row('candidate.2',5,100)]
        with patch('tools.qualify_hia_macro_multistep._native_rank',
                return_value=({'advisory_recommendation':'abstain'},{'fixture':True})):
            result = checked_pool_selection('ndu',rows,remaining_wall_ns=1000,
                bridge={'authored':'fixture'},objective_sha256='c'*64,generation=1)
        self.assertEqual(result['selected_id'],'candidate.2')
        with patch('tools.qualify_hia_macro_multistep._native_rank',side_effect=AssertionError('must not run')):
            result = self.select('ndu',rows[:1])
        self.assertIsNone(result['selected_id'])
        self.assertFalse(result['native_ndu_evaluated'])

    def test_no_python_substitute_for_missing_native_ndu(self):
        with self.assertRaisesRegex(ValueError,'stand-in'):
            self.select('ndu',[self.row('candidate.1',1,10)])

    def test_calibration_does_not_consume_heldout_or_failed_observations(self):
        prior = [{'quality_complete':False,'adoption_and_rollback_wall_ns':1},
                 {'quality_complete':True,'adoption_and_rollback_wall_ns':7}]
        result = calibration_forecast(prior)
        self.assertEqual(result['observations'],[7])
        self.assertEqual(result['transition_ns'],7)
        self.assertFalse(result['forecast_is_observation'])
        self.assertEqual(calibration_forecast([])['transition_ns'],2_000_000)
        with self.assertRaisesRegex(ValueError,'two'):
            calibration_forecast(prior+[prior[0]])

    def test_unchanged_registered_budget_applies_to_all_arms(self):
        p = protocol()
        self.assertEqual(p['per_cell']['wall_ns'],180_000_000_000)
        self.assertEqual(p['per_cell']['model_tokens'],32768)
        self.assertEqual(p['per_cell']['max_provider_turns'],3)
        self.assertEqual(p['arms'],['fixed','greedy','ordinary','ndu'])


if __name__ == '__main__':
    unittest.main()
