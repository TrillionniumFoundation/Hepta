"""Synthetic no-provider controls for the v2 matched search and strict adapter."""
from copy import deepcopy
from hashlib import sha256
import json
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

from hepta.hia_agent_assembly import assemble_program
from hepta.hia_ndu_optimizer import ns_to_ms_q32
from tools.hia_macro_multistep_provider import (RESPONSE_SCHEMA, command, parse_stream,
    request_document, prompt_bytes)
from tools.prepare_hia_followup_tasks import task_documents, mathematical_value
from tools.qualify_hia_macro_multistep import checked_pool_selection, calibration_forecast, protocol

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
