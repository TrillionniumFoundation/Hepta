"""Regress actual decoder order; public grammar never grants program admission."""
import copy
import hashlib
import inspect
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from experiments.hia_agent_structured_v7_20261029 import contracts, contracts_v2, editing
from experiments.hia_agent_structured_v7_20261029.rust_syntax import SCALARS, SyntaxRejected
from experiments.hia_agent_toolstudy_v8_20261029 import references
from experiments.hia_agent_toolstudy_v8_20261029.engine import ToolStudyEngine as OriginalEngine
from experiments.hia_agent_toolstudy_v12_20261030 import support as previous
from experiments.hia_agent_toolstudy_v13_20261030 import prompts, study, support
from experiments.hia_agent_toolstudy_v13_20261030.engine import ToolStudyEngine, response_schema
from tools.provider_adapter.llama_cpp_engine import canonical


class SelectionFirstContractTests(unittest.TestCase):
    def queries(self):
        for stage in ('calibration', 'main'):
            for task, arm in support.cells(stage):
                session = support.session_for(task, arm)
                yield task, arm, session, session.query()

    def test_retained_actual_v12_grammar_exposes_replacement_before_node(self):
        path = Path(__file__).parent / 'fixtures/hia_agent_toolstudy_v13/v12-selection-after-changes.json'
        record = json.loads(path.read_text())
        schema = record['actual_schema']
        item = schema['properties']['edits']['items']
        item['properties'] = {k: item['properties'][k] for k in ('node', 'changes')}
        contracts_v2.require_selection_first(schema)
        with self.assertRaisesRegex(ValueError, 'ACTUAL_GRAMMAR_ORDER'):
            contracts_v2.check_actual_grammar(schema, record['actual_grammar'])
        # This is the retained model output, not a manufactured success.
        self.assertLess(record['actual_model_output'].index('"changes"'), record['actual_model_output'].index('"node"'))

    def test_wire_preserves_schema_node_order_while_legacy_and_full_bytes_stay_exact(self):
        with tempfile.TemporaryDirectory() as directory:
            owner = ToolStudyEngine.__new__(ToolStudyEngine)
            owner.output = Path(directory)
            owner.generation_count = 0
            legacy = OriginalEngine.__new__(OriginalEngine)
            for task, arm, _, query in self.queries():
                language, interface = support.language_interface(arm)
                payload = {'prompt': [1, 2], 'json_schema': response_schema(language, interface, query)}
                owner.generation_count += 1
                wire = owner.completion_body(payload)
                self.assertEqual(json.loads(wire), payload)
                self.assertEqual(legacy.completion_body(payload), canonical(payload))
                if interface == 'node':
                    contracts_v2.require_selection_first(json.loads(wire)['json_schema'])
                    self.assertNotEqual(wire, canonical(payload))
                else:
                    self.assertEqual(wire, canonical(payload))
                retained = owner.output / f'transport-{owner.generation_count:03d}.request.body.json'
                self.assertEqual(retained.read_bytes(), wire)
                self.assertEqual(owner.actual_wire_sha256, hashlib.sha256(wire).hexdigest())

    def test_all_public_nodes_retained_and_rust_types_follow_public_language_only(self):
        for task, arm, _, query in self.queries():
            with self.subTest(task=task['id'], arm=arm):
                schema = contracts_v2.response_schema(query)
                contracts_v2.require_selection_first(schema)
                represented = {}
                for variant in contracts_v2.variants(schema):
                    for ident in variant['properties']['node']['enum']:
                        self.assertNotIn(ident, represented)
                        represented[ident] = variant['properties']['changes']
                nodes = {n['id']: n for n in query['edit_query']['nodes'] if n['fields']}
                self.assertEqual(set(represented), set(nodes))
                if query['language'] == 'rust':
                    for ident, node in nodes.items():
                        typ = represented[ident]['properties']['text']
                        expected = {'enum': sorted([*SCALARS, 'Vec<u8>'])} if node['category'] == 'type' else {'type': 'string'}
                        self.assertEqual(typ, expected)
                else:
                    self.assertEqual(schema, contracts.response_schema(query))
        source = inspect.getsource(contracts_v2)
        for forbidden in ('import references', 'import fixtures', 'import calibration', 'task['):
            self.assertNotIn(forbidden, source)

    def test_actual_reference_values_survive_grammar_order_rendering_all_19_controls(self):
        count = 0
        for task, arm, session, query in self.queries():
            language, interface = support.language_interface(arm)
            answer = references.reference(session, query, task) if interface == 'node' else {'files': task['correct_' + language]}
            rendered = study.control_response_text(query, language, interface, answer)
            self.assertEqual(json.loads(rendered), answer)
            self.assertTrue(study.decoder_control(query, language, interface, answer)['public_contract_reference_valid'])
            if interface == 'node':
                for edit in json.loads(rendered)['edits']:
                    self.assertEqual(list(edit), ['node', 'changes'])
            self.assertEqual(query, previous.session_for(task, arm).query())
            count += 1
        self.assertEqual(count, 19)

    def test_type_schema_refuses_declarations_but_expression_still_requires_real_parser(self):
        task, arm = support.cells('calibration')[1]
        session = support.session_for(task, arm); query = session.query()
        schema = response_schema('rust', 'node', query)
        nodes = query['edit_query']['nodes']
        typ = next(n for n in nodes if n['fields'] and n['category'] == 'type')
        expr = next(n for n in nodes if n['fields'] and n['category'] == 'expression')
        value = 'pub fn changed(a:u32)->u32 { a }'
        self.assertFalse(study._accepts(schema, {'edits': [{'node': typ['id'], 'changes': {'text': value}}]}))
        # Open expression text does not grant admission or imply a valid repair.
        self.assertTrue(study._accepts(schema, {'edits': [{'node': expr['id'], 'changes': {'text': value}}]}))
        with self.assertRaises(SyntaxRejected) as error:
            editing.propose_rust(session.files, query['edit_query'], editing.response_for(query['edit_query'],
                [{'node': expr['id'], 'changes': {'text': value}}]),
                editable_symbols=query['edit_query']['editable_symbols'], interface_policy='migrate')
        self.assertIn(expr['id'], str(error.exception))
        self.assertIn('expected one complete expression fragment', str(error.exception))
        self.assertNotIn(value, str(error.exception))

    def test_actual_grammar_order_gate_requires_every_variant_and_rejects_missing_or_reversed(self):
        task, arm = support.cells('calibration')[1]
        schema = response_schema('rust', 'node', support.session_for(task, arm).query())
        count = len(contracts_v2.variants(schema))
        rules = [f'edits-item-{i} ::= edits-item-{i}-node-kv edits-item-{i}-changes-kv' for i in range(count)]
        self.assertEqual(contracts_v2.check_actual_grammar(schema, '\n'.join(rules))['edit_object_rules'], count)
        for grammar in (None, '', '\n'.join(rules[:-1]), '\n'.join(r.replace('-node-kv', '-temp-kv').replace('-changes-kv', '-node-kv').replace('-temp-kv', '-changes-kv') for r in rules)):
            with self.assertRaises(ValueError):
                contracts_v2.check_actual_grammar(schema, grammar)

    def test_generic_guidance_does_not_depend_on_references_or_hidden_task_fields(self):
        for task, arm, _, query in self.queries():
            actual = prompts.prompt(task, arm, query)
            other = copy.deepcopy(task)
            for key in list(other):
                if 'correct_' in key or 'hidden_' in key:
                    other[key] = 'FORBIDDEN_REFERENCE'
            self.assertEqual(actual, prompts.prompt(other, arm, query))
            self.assertIn(prompts.PUBLIC_REVIEW, actual)
            if arm == 'calibration' or arm.endswith('_node'):
                self.assertIn(prompts.PUBLIC_NODE_GUIDE, actual)

    def test_model_budget_task_and_strict_gates_unchanged_and_protocol_tamper_refused(self):
        current, old = support.protocol(), previous.protocol()
        for key in ('model', 'runtime', 'generation', 'history', 'budget', 'arms', 'tasks', 'capacity_gate', 'advantage_gate'):
            self.assertEqual(current[key], old[key])
        self.assertEqual(current['qualification']['tasks'], old['qualification']['tasks'])
        self.assertTrue(current['prospective_amendment']['task_initial_prompts_and_messages_changed'])
        original = Path.read_text
        def changed(path, *args, **kwargs):
            text = original(path, *args, **kwargs)
            if path == support.HERE / 'PROTOCOL.json':
                value = json.loads(text); value['generation']['attempts_per_cell'] += 1
                return json.dumps(value)
            return text
        with patch.object(Path, 'read_text', changed), self.assertRaisesRegex(ValueError, 'UNAUTHORIZED'):
            support.protocol()


if __name__ == '__main__':
    unittest.main()
