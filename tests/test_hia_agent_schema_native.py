"""Check native Agent schemas and discovery against the existing service behavior."""
from __future__ import annotations

import argparse
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from hepta.hia_agent_contract import VERSION, catalog, validate
from hepta import hia_agent_describe_answer_native as describe_answer
from hepta import hia_agent_discovery_native as discovery
from hepta import hia_agent_inspection_native as inspection
from hepta.hia_agent_schema_native import SELECTOR, SOURCE, installed_agent_schema
from hepta import hia_agent_payload_schema_native as payloads
from hepta import hia_agent_response_schema_native as responses
from hepta import hia_agent_verify_response_schema_native as proofs
from hepta.hia_agent_service import HIAAgentService
from hepta.hia_agent_store import AgentRejected


class AgentSchemaSourceTests(unittest.TestCase):
    def test_generated_source_matches_catalog(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_agent_schema import document
        self.assertEqual(SOURCE.read_text(), render_assembly(document()))
        self.assertEqual(responses.SOURCE.read_text(), render_assembly(document(profile='response')))
        self.assertEqual(proofs.SOURCE.read_text(), render_assembly(document(profile='verify')))
        self.assertEqual(payloads.SOURCE.read_text(), render_assembly(document(profile='payload')))


    def test_generated_discovery_matches_current_opcodes(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_agent_discovery import answer_source, document, source_program
        self.assertEqual(discovery.SOURCE.read_text(),
                         render_assembly(document(source_program(), 'agent_discovery')))
        self.assertEqual(describe_answer.SOURCE.read_text(),
                         render_assembly(document(answer_source(), 'agent_describe_answer')))


    def test_generated_inspection_matches_current_core_renderer(self):
        from hepta.hia_agent_assembly import render_assembly
        from tools.generate_hia_agent_inspection import document, source_program
        self.assertEqual(inspection.SOURCE.read_text(),
                         render_assembly(document(source_program(), 'agent_inspection')))


class AgentInspectionNativeTests(unittest.TestCase):
    manifest = None
    native_release = None
    test_root = None

    def setUp(self):
        if self.manifest is None:
            self.skipTest('provide the matching native Agent inspection image')

    def test_ordinary_lowering_reports_use_exact_native_text_digest_and_store_refs(self):
        from tools.hia_agent_native_qualification import (
            Session, ToolClient, add_program, branch_program, exhaustive_u8_workload,
        )

        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            service = HIAAgentService(Path(temporary) / 'state')
            try:
                session = Session(ToolClient(service.call, validate=False))
                session.freeze(exhaustive_u8_workload())
                store_json = service.store.json

                def forbid_host_projection(value, kind):
                    self.assertNotEqual(kind, 'inspection', 'hosted lowering serialization entered')
                    return store_json(value, kind)

                for source in (add_program(), branch_program()):
                    args = session.arguments(mutable=False, program=session.artifact(source), view='lowering')
                    reference = service.call('hia_inspect', args)
                    self.assertEqual(reference['status'], 'completed', reference)
                    with (patch.dict('os.environ', {inspection.SELECTOR: str(self.manifest)}),
                          patch.object(service.store, 'json', side_effect=forbid_host_projection)):
                        selected = service.call('hia_inspect', args)
                    self.assertEqual(selected, reference)
                    result = selected['result']['view_artifact']
                    receipt, _ = service.store.get_json(result, kind='inspection')
                    artifact, _ = service.store.get(receipt['object'], kind='lowering-object')
                    self.assertTrue(artifact.startswith(b'\x7fELF'))
            finally:
                service.close()

    def test_ordinary_summary_retains_exact_nominal_origin_without_hosted_renderer(self):
        from tools.hia_agent_native_qualification import (
            Session, ToolClient, add_program, exhaustive_u8_workload,
        )
        root = Path(__file__).resolve().parents[1]
        nominal = (root / 'examples/hia_program/generic_owned_enum.hepta').read_bytes()
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            service = HIAAgentService(Path(temporary) / 'state')
            try:
                session = Session(ToolClient(service.call, validate=False))
                session.freeze(exhaustive_u8_workload())
                sources = (session.artifact(add_program()), service.store.put(nominal, 'input'))
                for source in sources:
                    args = session.arguments(mutable=False, program=source, view='summary')
                    reference = service.call('hia_inspect', args)
                    self.assertEqual(reference['status'], 'completed', reference)
                    with (patch.dict('os.environ', {inspection.SELECTOR: str(self.manifest)}),
                          patch('hepta.hia_program_tools.inspect_program',
                                side_effect=AssertionError('hosted summary entered'))):
                        self.assertEqual(service.call('hia_inspect', args), reference)
            finally:
                service.close()

    def test_ordinary_candidate_ingress_and_diagnostics_without_hosted_admission(self):
        if self.native_release is None:
            self.skipTest('provide the matching release for candidate import')
        from hashlib import sha256
        from hepta.hia_agent_assembly import render_assembly
        from hepta.hia_agent_candidate_native import NativeAgentCandidateImport, IMPORT_EXECUTABLES
        from hepta.hia_agent_store_native import capture_release_image
        from hepta import hia_program
        from hepta.hia_program import HIAProgramRejected, VerifiedProgram, native_verified_program_scope, verify_program
        from tools.hia_agent_native_qualification import (
            Session, ToolClient, add_program, exhaustive_u8_workload,
        )
        root = Path(__file__).resolve().parents[1]
        captures = []
        for name, limit in IMPORT_EXECUTABLES.values():
            pin = sha256((self.native_release / name).read_bytes()).hexdigest()
            captures.append(capture_release_image(self.native_release, name, limit, pin))
        importer = NativeAgentCandidateImport(*captures, str(self.manifest))
        nominal = (root / 'examples/hia_program/generic_owned_enum.hepta').read_text()
        primitive = {**add_program(), 'schema': 'hepta.hia.program.v6'}
        sources = ((primitive, 'core-json'), (render_assembly(primitive), 'hia-asm.v1'),
                   (nominal, 'core-json'), ('{"a":1,"a":2}', 'core-json'),
                   ('invalid assembly', 'hia-asm.v1'))
        with tempfile.TemporaryDirectory(dir=self.test_root) as temporary:
            state = Path(temporary) / 'state'
            ordinary = HIAAgentService(state)
            try:
                session = Session(ToolClient(ordinary.call, validate=False))
                session.freeze(exhaustive_u8_workload())
                controls = []
                nominal_ref = session.artifact(nominal)
                nominal_program = verify_program(nominal)
                primitive_ref = session.artifact(primitive)
                lowering = session.arguments(mutable=False, program=primitive_ref, view='lowering')
                expected_lowering = ordinary.call('hia_inspect', lowering)
                self.assertEqual(expected_lowering['status'], 'completed', expected_lowering)
                for raw, source_format in sources:
                    source = session.artifact(raw)
                    args = session.arguments(change={'kind': 'import', 'format': source_format, 'source': source})
                    reply = ordinary.call('hia_candidate', args)
                    controls.append((args, reply))
            finally:
                ordinary.close()
            selected = HIAAgentService(state, native_candidate_import=importer)
            try:
                with patch.object(HIAAgentService, '_reference_import',
                                  side_effect=AssertionError('hosted retained Core entered')):
                    confirmed = selected._program(nominal_ref)
                    self.assertEqual(confirmed, nominal_program)
                    explanation = selected.call('hia_inspect', session.arguments(
                        mutable=False, program=nominal_ref, view='summary'))
                    self.assertEqual(explanation['status'], 'completed', explanation)

                reference = hia_program._verify_program_reference

                def forbid_host_consumer_recheck(program):
                    self.assertNotIsInstance(program, VerifiedProgram, 'hosted consumer Core recheck entered')
                    return reference(program)

                with patch.object(hia_program, '_verify_program_reference',
                                  side_effect=forbid_host_consumer_recheck):
                    self.assertEqual(selected.call('hia_inspect', lowering), expected_lowering)
                    with (patch.object(importer, 'retained_program', wraps=importer.retained_program) as owner,
                          native_verified_program_scope(importer.recheck_for_request())):
                        self.assertEqual(verify_program(nominal_program), nominal_program)
                        self.assertEqual(verify_program(nominal_program), nominal_program)
                        forged = VerifiedProgram(verify_program(primitive).canonical_bytes,
                                                 nominal_program.structured_bytes)
                        with self.assertRaisesRegex(HIAProgramRejected, 'structured input and executable core differ'):
                            verify_program(forged)
                        owner.assert_called_once_with(nominal_program.structured_bytes)
                for index, (args, expected) in enumerate(controls):
                    args = {**args, 'request_key': args['request_key'] + '/native'}
                    if index < 3:
                        self.assertEqual(expected['status'], 'completed', expected)
                        with patch.object(HIAAgentService, '_reference_import',
                                          side_effect=AssertionError('hosted import entered')):
                            result = selected.call('hia_candidate', args)
                        self.assertEqual(result['result'], expected['result'])
                    else:
                        self.assertEqual(expected['status'], 'rejected', expected)
                        result = selected.call('hia_candidate', args)
                        self.assertEqual(result['error'], expected['error'])
            finally:
                selected.close()

    def test_ordinary_function_and_block_artifact_bytes_without_host_projection(self):
        from hepta.hia_agent_store import wire
        from hepta.hia_program import VerifiedProgram, verify_program
        from tools.hia_agent_native_qualification import (
            Session, ToolClient, add_program, branch_program, exhaustive_u8_workload,
        )
        with tempfile.TemporaryDirectory(dir=self.test_root) as root:
            service = HIAAgentService(Path(root) / 'state')
            try:
                session = Session(ToolClient(service.call, validate=False))
                session.freeze(exhaustive_u8_workload())
                for source in (add_program(), branch_program()):
                    verified = verify_program(source)
                    issued = service.store.put(verified.canonical_bytes, 'core')
                    fn = source['functions'][0]
                    shared = session.arguments(mutable=False, program=issued)
                    cases = [
                        (dict(shared, view='function', selector={'function': fn['name']}), fn),
                        (dict(shared, view='function', selector={'function': fn['name'] + ' '}),
                         'function is not in this program'),
                        (dict(shared, view='block', selector={'block': 'entry'}),
                         'function view requires an exact function'),
                        (dict(shared, view='block', selector={'function': fn['name'], 'block': '否' * 128}),
                         'block is not in this function'),
                        (dict(shared, view='block', selector={'function': fn['name']}),
                         'block is not in this function'),
                    ]
                    cases.extend((dict(shared, view='block', selector={'function': fn['name'], 'block': b['id']}), b)
                                 for b in fn['blocks'])
                    expected = [service.call('hia_inspect', args) for args, _ in cases]
                    with (patch.dict('os.environ', {inspection.SELECTOR: str(self.manifest)}),
                          patch.object(VerifiedProgram, 'as_dict',
                                       side_effect=AssertionError('hosted projection entered'))):
                        for (args, body), reference in zip(cases, expected):
                            with self.subTest(args=args):
                                result = service.call('hia_inspect', args)
                                self.assertEqual(result, reference)
                                if type(body) is str:
                                    self.assertEqual(result['error']['message'], body)
                                else:
                                    raw, _ = service.store.get(result['result']['view_artifact'], kind='inspection')
                                    self.assertEqual(raw, wire(body))
            finally:
                service.close()


class AgentDiscoveryNativeTests(unittest.TestCase):
    manifest = None
    answer_manifest = None
    test_root = None

    def setUp(self):
        if self.manifest is None:
            self.skipTest('provide the matching native Agent discovery image')

    def test_profiles_initialize_and_reopen_without_hosted_discovery_documents(self):
        from hepta.hia_agent_store import wire
        from hepta.hia_schema import schema_registry

        expected_registry = wire(schema_registry())
        with tempfile.TemporaryDirectory(dir=self.test_root) as root:
            state = Path(root) / 'state'
            roots = (Path(root) / 'input', Path(root) / '制品')
            for path in roots:
                path.mkdir()

            def startup_documents(service):
                refs = (service.manifest, *service.profile_artifacts.values(), *service.resources.values())
                return {ref['id']: service.store.get(ref)[0] for ref in refs}

            original = HIAAgentService(state, artifact_roots=roots)
            try:
                expected_refs = (original.manifest, original.profiles, original.profile_artifacts, original.resources)
                expected_documents = startup_documents(original)
            finally:
                original.close()

            with (patch.dict('os.environ', {discovery.SELECTOR: str(self.manifest)}),
                  patch('hepta.hia_schema.schema_registry', side_effect=AssertionError('hosted registry used')),
                  patch('hepta.hia_opcodes.opcode_catalog', side_effect=AssertionError('hosted opcodes used')),
                  patch('hepta.hia_agent_service._profile_documents', side_effect=AssertionError('hosted profiles used')),
                  patch('hepta.hia_agent_service._manifest_document', side_effect=AssertionError('hosted manifest used')),
                  patch.object(HIAAgentService, '_reference_resource_documents',
                               side_effect=AssertionError('hosted discovery resources used')),
                  patch('hepta.hia_agent_macro_discovery.macro_policy_guidance',
                        side_effect=AssertionError('hosted macro guidance used'))):
                for _ in range(2):
                    service = HIAAgentService(state, artifact_roots=roots)
                    try:
                        self.assertEqual((service.manifest, service.profiles, service.profile_artifacts,
                                          service.resources), expected_refs)
                        self.assertEqual(startup_documents(service), expected_documents)
                        reply = service.call('hia_describe', {'section': 'language'})
                        self.assertEqual(reply['status'], 'completed', reply)
                        ref = reply['result']['resources'][0]
                        self.assertEqual(ref, service.resources['schema_registry'])
                        raw, _ = service.store.get(ref, kind='discovery')
                        self.assertEqual(raw, expected_registry)
                    finally:
                        service.close()

    def test_exact_issued_resources_and_canonical_catalog_for_all_versions(self):
        from hepta.hia_agent_store import wire
        from hepta.hia_opcodes import opcode_catalog
        sections = ('manifest', 'language', 'backend', 'examples', 'diagnostics', 'plans')
        with tempfile.TemporaryDirectory(dir=self.test_root) as root:
            service = HIAAgentService(Path(root) / 'state')
            try:
                backend = service.profiles['backend']['id']
                cases = [{'section': section, 'language_schema': version,
                          'backend_profile': backend, 'max_bytes': 512}
                         for version in discovery.VERSIONS for section in sections]
                cases.extend({'section': section} for section in sections)
                cases += [
                    {'section': 'language', 'language_schema': '否' * 128},
                    {'section': 'language', 'backend_profile': '不存在', 'language_schema': 'bad'},
                    {'section': 'language', 'backend_profile': 'bad',
                     'language_schema': 'bad', 'cursor': 'cursor'},
                ]
                reference = [service.call('hia_describe', case) for case in cases]
                catalogs = {version: wire(opcode_catalog(version)) for version in discovery.VERSIONS}
                selectors = {discovery.SELECTOR: str(self.manifest)}
                if self.answer_manifest is not None:
                    selectors[describe_answer.SELECTOR] = str(self.answer_manifest)
                with (patch.dict('os.environ', selectors),
                      patch.object(service, '_reference_describe', side_effect=AssertionError('host routing used')),
                      patch('hepta.hia_opcodes.opcode_catalog', side_effect=AssertionError('host catalog used'))):
                    for args, expected in zip(cases, reference):
                        with self.subTest(args=args):
                            result = service.call('hia_describe', args)
                            self.assertEqual(result, expected)
                            if args['section'] == 'language' and result['status'] == 'completed':
                                body = result['result']
                                raw, _ = service.store.get(body['resources'][-1], kind='profile')
                                self.assertEqual(raw, catalogs[body['language_catalogs'][0]['id']])
            finally:
                service.close()


class AgentSchemaNativeTests(unittest.TestCase):
    manifest = None
    payload_manifest = None
    test_root = None

    def setUp(self):
        if self.manifest is None:
            self.skipTest('provide the matching native Agent input schema image')
        self.image = installed_agent_schema(str(self.manifest))

    def test_every_tool_valid_and_mutated_arguments_match_reference(self):
        doc, pin = catalog()
        common = {'catalog_sha256': pin, 'request_key': 'fixture:request'}
        context = {'id': 'fixture:context', 'sha256': 'c' * 64}
        profile = {'id': 'fixture:profile', 'sha256': 'b' * 64}
        ref = {'id': 'fixture:artifact', 'sha256': 'a' * 64,
               'uri': 'hia://artifacts/fixture-artifact'}
        current = {'generation': '1', 'epoch': '2'}
        bound = {**common, 'context': context}
        tools = {
            'hia_describe': {'section': 'manifest'},
            'hia_artifact': {**common, 'artifact_profile': profile,
                             'source': {'kind': 'utf8', 'text': '葡萄'}},
            'hia_read': {'catalog_sha256': pin, 'artifact': ref, 'max_bytes': 512.0},
            'hia_context': {**common, 'compiler_profile': profile, 'target_profile': profile,
                             'baseline_program': None, 'workload': ref, 'objective': ref,
                             'budget': {'max_candidates': 8, 'max_model_tokens': -0.0,
                                        'max_total_wall_ms': 60000, 'max_native_wall_ms': 1000,
                                        'max_memory_bytes': '16777216', 'cost_policy': ref}},
            'hia_inspect': {'catalog_sha256': pin, 'context': context,
                             'program': ref, 'view': 'summary'},
            'hia_candidate': {**bound, 'change': {'kind': 'patch', 'base_program': ref,
                             'patch_schema': 'hepta.hia.patch.v2', 'patch': ref}},
            'hia_verify': {**bound, 'candidate': ref, 'base_program': ref,
                           'validation_profile': profile, 'subject': {'kind': 'core'},
                           'claims': ['core_admission', 'behavior_equivalence']},
            'hia_emit': {**bound, 'candidate': ref, 'backend_profile': profile, 'output_kind': 'object',
                         'codegen': {'kind': 'canonical', 'lowering_profile': profile},
                         'verification_receipts': [ref]},
            'hia_evaluate': {**bound, 'baseline_artifact': ref, 'candidate_artifact': ref,
                             'build_receipt': ref, 'verification_receipts': [ref]},
            'hia_adopt': {**bound, 'target_slot': 'fixture:slot', 'expected_current': current,
                          'candidate_artifact': ref, 'evaluation_receipt': ref,
                          'verification_receipts': [ref]},
            'hia_rollback': {**bound, 'target_slot': 'fixture:slot', 'expected_current': current,
                             'retained_generation': '1', 'reason': 'fixture only'},
        }
        self.assertEqual(set(tools), {tool['name'] for tool in doc['tools']})
        for role, tool in enumerate(doc['tools'], 1):
            name, schema = tool['name'], tool['inputSchema']
            args = tools[name]
            self.assertTrue(self.image.accepts(args, role, pin), name)
            cases = [args, [], None, dict(args, not_a_catalog_field=3)]
            for key in args:
                cases.append({k: v for k, v in args.items() if k != key})
                cases += [dict(args, **{key: value}) for value in (None, [], {}, False, '\n', 512.5)]
            if name == 'hia_read':
                cases.extend(dict(args, max_bytes=value) for value in (0, 511.99, 512, 65536.0,
                             65536.00000000001, True, 1 << 91, 5e-324))
                cases.append(dict(args, artifact=dict(ref, sha256='a' * 64 + '\n')))
            if name == 'hia_verify':
                cases += [dict(args, claims=['core_admission', 'core_admission']),
                          dict(args, claims=['behavior_equivalence'], base_program=None)]
            for case in cases:
                try:
                    validate(case, schema)
                except AgentRejected:
                    expected = False
                else:
                    expected = True
                with self.subTest(name=name, case=case):
                    self.assertEqual(self.image.accepts(case, role, pin), expected)
        with self.assertRaisesRegex(ValueError, 'authenticate'):
            self.image.accepts(tools['hia_describe'], 1, '0' * 64)

    def test_issued_evaluation_inputs_match_reference(self):
        from hepta.hia_agent_contract import COST_POLICY_SCHEMA, OBJECTIVE_SCHEMA, WORKLOAD_SCHEMA
        from hepta.hia_agent_payload_schema_native import COST_POLICY_ROLE, OBJECTIVE_ROLE, WORKLOAD_ROLE
        from hepta.hia_agent_store import decode_data, wire

        if self.payload_manifest is None:
            self.skipTest('provide the matching evaluation payload image')
        image = payloads.installed_agent_payload_schema(str(self.payload_manifest))
        _, pin = catalog()
        example = HIAAgentService._examples()
        workload, objective, policy = (example[name] for name in ('workload', 'objective', 'cost_policy'))
        case = workload['cases'][0]
        buffer = {'function': 'take', 'arguments': [{'bytes_hex': '00ff'}]}
        buffers = {**workload, 'schema': 'hepta.hia.agent.workload.v2', 'cases': [buffer],
                   'foreign_buffer_exports': [{'function': 'take', 'max_buffer_bytes': 1048576}]}
        cases = (
            (WORKLOAD_ROLE, WORKLOAD_SCHEMA, [
                workload, buffers, dict(workload, cases=[]),
                *(dict(workload, cases=[dict(case, arguments=[n, -n])])
                  for n in (0.0, 1.0, 1.5, 2.**52 - 0.5, 2.**53, 1e300, 10**100, 5e-324)),
                *(dict(buffers, cases=[dict(buffer, arguments=[{'bytes_hex': data}])])
                  for data in ('', 'ff', 'f', 'FF', '00 ff', '00\n', '0\n', '00\n\n')),
                dict(buffers, cases=[dict(buffer, arguments=[{'byte_length': 1048577, 'fill_byte': 0}])]),
                dict(buffers, cases=[dict(buffer, arguments=[{'byte_length': 1048576.0, 'fill_byte': 255}])]),
            ]),
            (OBJECTIVE_ROLE, OBJECTIVE_SCHEMA, [
                objective, dict(objective, required_claims=['encoding_check']),
                dict(objective, required_claims=['core_admission', 'core_admission']),
                *(dict(objective, min_improvement_ratio=n)
                  for n in (False, -0.0, -5e-324, 5e-324, 0.5, 1, 1.0000000000000002, 1 << 80)),
            ]),
            (COST_POLICY_ROLE, COST_POLICY_SCHEMA, [
                policy, dict(policy, expected_invocations='09'),
                dict(policy, external_costs={**policy['external_costs'], 'model_tokens': 1e8}),
                dict(policy, external_costs={**policy['external_costs'], 'model_tokens': 1e8 + 1}),
            ]),
        )
        for role, schema, values in cases:
            for value in values:
                raw = b' \n' + wire(value) + b'\n '
                with self.subTest(role=role, value=value):
                    try:
                        validate(decode_data(raw), schema)
                    except AgentRejected:
                        expected = False
                    else:
                        expected = True
                    self.assertEqual(image.accepts_wire(raw, role, pin), expected)

    def test_selected_service_admits_frozen_evaluation_inputs_natively(self):
        from tools.hia_agent_native_qualification import Session, ToolClient

        if self.payload_manifest is None:
            self.skipTest('provide the matching evaluation payload image')
        with tempfile.TemporaryDirectory(dir=self.test_root) as root:
            service = HIAAgentService(Path(root) / 'state')
            try:
                session = Session(ToolClient(service.call, validate=False))
                example = service._examples()

                def result_only(value, schema, label='arguments'):
                    if label != 'result':
                        raise AssertionError('hosted validator selected for admitted evaluation input: ' + label)
                    return validate(value, schema, label)

                with (patch.dict('os.environ', {SELECTOR: str(self.manifest),
                                                payloads.SELECTOR: str(self.payload_manifest)}),
                      patch('hepta.hia_agent_service.validate', result_only)):
                    session.freeze(example['workload'], objective=example['objective'])
                    self.assertEqual(service._context(session.context)['ref'], session.context)
            finally:
                service.close()

    def test_selected_ordinary_service_uses_native_decisions(self):
        with tempfile.TemporaryDirectory(dir=self.test_root) as root:
            service = HIAAgentService(Path(root) / 'state')
            try:
                bad = {'section': 'nonsense'}
                old = service.call('hia_describe', bad)
                with patch.dict('os.environ', {SELECTOR: str(self.manifest)}):
                    self.assertEqual(service.call('hia_describe', bad), old)

                    def output_only(value, schema, label='arguments'):
                        if label != 'result':
                            raise AssertionError('hosted input validator selected for admitted request')
                        return validate(value, schema, label)

                    with patch('hepta.hia_agent_service.validate', output_only):
                        result = service.call('hia_describe', {'section': 'manifest'})
                        self.assertEqual(result['status'], 'completed', result)
                with patch.dict('os.environ', {SELECTOR: str(Path(root) / 'missing.json')}):
                    result = service.call('hia_describe', {'section': 'manifest'})
                    self.assertEqual(result['status'], 'rejected')
            finally:
                service.close()


class AgentResponseSchemaNativeTests(unittest.TestCase):
    manifest = None
    response_manifest = None
    proof_manifest = None
    test_root = None

    def setUp(self):
        if self.response_manifest is None or self.proof_manifest is None:
            self.skipTest('provide both matching native response schema images')

    def test_response_shape_and_rejected_proof_shape_match_catalog(self):
        response = responses.installed_agent_response_schema(str(self.response_manifest))
        proof = proofs.installed_agent_verify_response_schema(str(self.proof_manifest))
        doc, pin = catalog()
        rejected = {'contract_version': VERSION, 'request_id': 'test',
                    'status': 'rejected', 'error': {
                        'code': 'E_HIA_PROOF_SCOPE', 'phase': 'verification',
                        'message': 'A declared proof obligation is missing',
                        'retry_action': 'correct_input', 'details_artifact': None}}
        for role, tool in enumerate(doc['tools'], 1):
            checker = proof if tool['name'] == 'hia_verify' else response
            schema = tool['outputSchema']
            self.assertTrue(checker.accepts(rejected, role, pin))
            for value in ([], dict(rejected, status='completed'),
                          dict(rejected, result={}), dict(rejected, extra=1),
                          dict(rejected, error=dict(rejected['error'], phase=False))):
                with self.assertRaises(AgentRejected):
                    validate(value, schema, 'result')
                self.assertFalse(checker.accepts(value, role, pin))

    def test_selected_service_uses_native_schemas_for_completed_result(self):
        paths = {SELECTOR: str(self.manifest), responses.SELECTOR: str(self.response_manifest),
                 proofs.SELECTOR: str(self.proof_manifest)}
        with tempfile.TemporaryDirectory(dir=self.test_root) as root:
            service = HIAAgentService(Path(root) / 'state')
            try:
                arguments = {'section': 'manifest'}
                original = service.call('hia_describe', arguments)
                self.assertEqual(original['status'], 'completed', original)
                with (patch.dict('os.environ', paths),
                      patch('hepta.hia_agent_service.validate',
                            side_effect=AssertionError('hosted schema validator selected'))):
                    self.assertEqual(service.call('hia_describe', arguments), original)
                bad = dict(original, result=dict(original['result'], resources=False))
                with self.assertRaises(AgentRejected) as expected:
                    service._validate_tool_response('hia_describe', bad)
                with patch.dict('os.environ', paths), self.assertRaises(AgentRejected) as actual:
                    service._validate_tool_response('hia_describe', bad)
                self.assertEqual(str(actual.exception), str(expected.exception))
            finally:
                service.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, required=True)
    parser.add_argument('--test-root', type=Path, required=True)
    parser.add_argument('--payload-manifest', type=Path)
    parser.add_argument('--response-manifest', type=Path)
    parser.add_argument('--proof-manifest', type=Path)
    parser.add_argument('--discovery-manifest', type=Path)
    parser.add_argument('--describe-answer-manifest', type=Path)
    parser.add_argument('--inspection-manifest', type=Path)
    parser.add_argument('--native-release', type=Path)
    args = parser.parse_args()
    AgentSchemaNativeTests.manifest = args.manifest.resolve()
    AgentSchemaNativeTests.payload_manifest = args.payload_manifest
    AgentSchemaNativeTests.test_root = args.test_root.resolve()
    AgentResponseSchemaNativeTests.manifest = AgentSchemaNativeTests.manifest
    AgentResponseSchemaNativeTests.response_manifest = args.response_manifest
    AgentResponseSchemaNativeTests.proof_manifest = args.proof_manifest
    AgentResponseSchemaNativeTests.test_root = AgentSchemaNativeTests.test_root
    AgentDiscoveryNativeTests.manifest = args.discovery_manifest
    AgentDiscoveryNativeTests.answer_manifest = args.describe_answer_manifest
    AgentDiscoveryNativeTests.test_root = AgentSchemaNativeTests.test_root
    AgentInspectionNativeTests.manifest = args.inspection_manifest
    AgentInspectionNativeTests.test_root = AgentSchemaNativeTests.test_root
    AgentInspectionNativeTests.native_release = args.native_release
    loader = unittest.defaultTestLoader
    suite = unittest.TestSuite(loader.loadTestsFromTestCase(cls)
                              for cls in (AgentSchemaSourceTests, AgentSchemaNativeTests,
                                          AgentResponseSchemaNativeTests, AgentDiscoveryNativeTests,
                                          AgentInspectionNativeTests))
    return 0 if unittest.TextTestRunner(verbosity=2).run(suite).wasSuccessful() else 1


if __name__ == '__main__':
    raise SystemExit(main())
