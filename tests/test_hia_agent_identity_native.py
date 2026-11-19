"""Actual native Agent scalar identities, independent bytes before native seed."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import ctypes,json,os,random,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from hepta.hia_agent_identity_native import SOURCE,SCHEMA,MAGIC,RESULT_MAGIC,NativeAgentIdentity,installed_agent_identity,SELECTOR
from hepta.hia_agent_identity_native import (DECLARED_OBSERVATION, REFERENCE_OBSERVATION, NATIVE_OBSERVATION,
    CLAIM_NOT_QUALIFIED, CLAIM_QUALIFIED, CLAIM_BUILD_RECHECK, EXACT_COMPARISON_CHUNK)
from hepta.hia_agent_store import AgentRejected,uint64,canonical_digest
ROOT=Path(__file__).resolve().parents[1]
def packet(kind,value):return struct.pack('<2Q',MAGIC,kind)+value
def expected(valid,value=0):return struct.pack('<3Q',RESULT_MAGIC,valid,value)

def comparison(mode, fields, operation=7):
    return packet(operation, struct.pack('<Q', mode) + b''.join(
        struct.pack('<2Q', len(left), len(right)) + left + right for left, right in fields))

def proof_request(claim, kind, planned, checks, scope):
    fields = b''.join(struct.pack('<2Q', len(left), len(right)) + left + right for left, right in scope)
    return packet(10, struct.pack('<4Q', claim, kind, planned, len(checks)) + bytes(checks) + fields)

def vm(wire,workspace,capacity=24):
 from tools.hia_selfhost_bulk import Body
 from hepta.hia_agent_assembly import assemble_program
 from hepta.hia_program import execute_program
 b=Body(0);owners=[];views=[]
 for size,initial in ((len(wire),wire),(capacity,b''),(workspace,b'')):
  owner=b.value('buffer','buffer.new',[b.const('usize',size)]);view=b.value('mutbuf','borrow.mut',[owner])
  for i,value in enumerate(initial):
   if value:b.effect('buffer.store',[view,b.const('usize',i),b.const('u8',value)])
  owners.append(owner);views.append(view)
 b.effect('loan.end',[views[0]]);views[0]=b.value('readbuf','borrow.read',[owners[0]])
 code=b.value('u32','call',views,{'function':'f0'});raw=[b.value('u8','buffer.load',[views[1],b.const('usize',i)]) for i in range(capacity)]
 for view in views:b.effect('loan.end',[view])
 for owner in owners:b.effect('owner.drop',[owner])
 source=('hia-asm.v1 hepta.hia.program.v8 agent_identity_reference\nfn observe() -> (u32,'+','.join(['u8']*capacity)+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+b.text()+'  ret('+','.join([code,*raw])+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
 row=execute_program(assemble_program(source),'observe',[],max_steps=2000000);assert row['status']=='returned',row
 code,*raw=row['values'];return code,bytes(raw)

def witnesses():
    values=[(packet(0,b'18446744073709551615'),expected(1,(1<<64)-1)),
        (packet(0,b'18446744073709551616'),expected(0)),(packet(1,b'0'*64),expected(1)),
        (packet(2,struct.pack('<3Q',64<<20,500,500)),expected(1)),
        (packet(2,struct.pack('<3Q',(64<<20)-1,500,501)),expected(1,1)),
        (packet(2,struct.pack('<3Q',4<<30,500,501)),expected(1,2)),
        (packet(3,struct.pack('<4Q',0,1,6,1)),expected(1,3)),
        (packet(3,struct.pack('<4Q',1,1,6,1)),expected(1,4)),
        (packet(4,struct.pack('<33Q',*([1<<20]*32),1)),expected(1,5)),
        (packet(5,struct.pack('<2QdQ',3,2,0.0,6)),
         expected(4,struct.unpack('<Q',struct.pack('<d',1/3))[0]))]
    for wire,result in values:assert vm(wire,0)==(24,result)
    return values

class AgentIdentitySourceTests(unittest.TestCase):
    def test_exact_source_and_complete_VM_bytes_before_any_native(self):
        from tools.generate_hia_agent_identity import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        self.assertEqual(len(witnesses()),10)

    def test_observation_protocol_distinguishes_omission_and_reference_ledger(self):
        fields = [(b'returned', b'returned'), (b'[1]', b'[1]'), (b'[]', b''),
                  (b'null', b'null'), (b'{"live":0}', b'{"live":1}')]
        self.assertEqual(vm(comparison(DECLARED_OBSERVATION, fields), 0), (24, expected(1, 1)))
        self.assertEqual(vm(comparison(NATIVE_OBSERVATION, fields), 0), (24, expected(1, 0)))
        fields[2] = (b'[]', b'[]')
        self.assertEqual(vm(comparison(NATIVE_OBSERVATION, fields), 0), (24, expected(1, 1)))
        self.assertEqual(vm(comparison(REFERENCE_OBSERVATION, fields), 0), (24, expected(1, 0)))

    def test_authority_protocol_preserves_identity_precedence_and_optional_kind(self):
        fields = [(b'id', b'id'), (b'sha', b'sha'), (b'uri', b'uri'), (b'', b'input')]
        self.assertEqual(vm(comparison(1, fields, 8), 0), (24, expected(1, 0)))
        fields[-1] = (b'proof', b'input')
        self.assertEqual(vm(comparison(1, fields, 8), 0), (24, expected(1, 2)))
        self.assertEqual(vm(comparison(0, fields, 8), 0), (24, expected(1, 1)))
        fields[2] = (b'uri', b'different')
        self.assertEqual(vm(comparison(1, fields, 8), 0), (24, expected(1, 1)))

    def test_wall_clock_keeps_exact_expiration_and_remaining_in_vm(self):
        for now, expired, remaining in ((999_999, 0, 9), (2_000_001, 0, 7),
                                         (10_000_000, 0, 0), (10_000_001, 1, 0)):
            wire = packet(9, struct.pack('<3Q', 2_000_000, now, 8))
            self.assertEqual(vm(wire, 0, 32),
                             (32, struct.pack('<4Q', RESULT_MAGIC, expired, remaining, 0)))

    def test_claim_eligibility_uses_the_requested_proved_scope_in_vm(self):
        scope = [(b'base', b'another'), (b'artifact', b'artifact'), (b'plan', b'plan')]
        for claim, kind, planned, checks, decision in (
            (0, 0, 0, [4], CLAIM_QUALIFIED),
            (1, 0, 0, [5], CLAIM_NOT_QUALIFIED),
            (2, 1, 0, [6], CLAIM_BUILD_RECHECK),
            (2, 2, 1, [6], CLAIM_QUALIFIED),
            (2, 2, 0, [6], CLAIM_NOT_QUALIFIED),
            (3, 2, 1, [7], CLAIM_NOT_QUALIFIED),
            (3, 1, 1, [6, 3], CLAIM_NOT_QUALIFIED),
        ):
            request = proof_request(claim, kind, planned, checks, scope)
            self.assertEqual(vm(request, 0), (24, expected(1, decision)))

    def test_builder_refuses_bad_cold_before_any_output_or_compilation(self):
        from copy import deepcopy
        from tools.build_hia_agent_identity import build
        checks=('export_manifest_matches_qualification','isolated_python_without_site',
            'nested_full_qualification_pass','nested_process_exit_zero','no_ancestor_git_identity',
            'no_bytecode_cache_created','no_inherited_home_or_python_cache','no_inherited_seed_or_successor_images',
            'origin_hashes_preserved','owned_process_tree_cleanup_confirmed','source_export_hashes_preserved')
        with tempfile.TemporaryDirectory(prefix='hia-agent-identity-invalid-cold-') as directory:
            folder=Path(directory);compiler=folder/'compiler.bin';compiler.write_bytes(b'not a qualified native compiler')
            h=sha256(compiler.read_bytes()).hexdigest()
            base={'schema':'hepta.hia.selfhost-cold-replay.v1','status':'COLD_SELFHOST_REPLAY_PASS',
                'returncode':0,'checks':dict.fromkeys(checks,True),'generation_sha256':[h]*3}
            cases=[]
            for key,value in [('schema','wrong'),('status','FAIL'),('returncode',False),('returncode',1),('generation_sha256',[h,h,'0'*64]),('generation_sha256',[h,h])]:
                row=deepcopy(base);row[key]=value;cases.append(row)
            row=deepcopy(base);row['checks']['owned_process_tree_cleanup_confirmed']=False;cases.append(row)
            row=deepcopy(base);del row['checks']['origin_hashes_preserved'];cases.append(row)
            for index,row in enumerate(cases):
                cold=folder/('bad-'+str(index)+'.json');cold.write_text(json.dumps(row));output=folder/('output-'+str(index))
                with patch('tools.qualify_hia_selfhost.compile_stage',side_effect=AssertionError('invalid cold launched compiler')):
                    with self.assertRaisesRegex(ValueError,'completed matching native cold'):build(output,compiler,cold)
                self.assertFalse(output.exists())


class AgentIdentityNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.witnesses=witnesses()
        from tools.qualify_hia_selfhost import build_seed,compile_stage
        cls.temp=tempfile.TemporaryDirectory(prefix='hia-agent-identity-');cls.folder=Path(cls.temp.name)
        seed,_=build_seed(cls.folder);compiler=(ROOT/'examples/hia_bootstrap/selfhost.hepta').read_bytes()
        first,_=compile_stage(cls.folder,'B1',seed,compiler,image_format='seed-shared')
        second,_=compile_stage(cls.folder,'B2',first,compiler)
        assert first.read_bytes()==second.read_bytes()
        image,cls.receipt=compile_stage(cls.folder,'agent-identity',second,SOURCE.read_bytes())
        cls.native=NativeAgentIdentity(image.read_bytes(),sha256(image.read_bytes()).hexdigest())
        cls.manifest=cls.folder/'manifest.json';cls.manifest.write_text(json.dumps({
            'schema':SCHEMA,'source_sha256':sha256(SOURCE.read_bytes()).hexdigest(),
            'image_path':image.name,'image_sha256':sha256(image.read_bytes()).hexdigest(),
            'compiler_sha256':sha256(second.read_bytes()).hexdigest()}))
    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    def raw(self,wire,capacity=24):
        source=ctypes.create_string_buffer(wire,max(1,len(wire)))
        output=ctypes.create_string_buffer(b'\xa5'*(capacity+8),capacity+8)
        workspace=ctypes.create_string_buffer(b'\x5a'*8,8)
        result=self.native._entry(source,len(wire),output,capacity,workspace,0)
        self.assertEqual(source.raw,wire or b'\x00');self.assertEqual(output.raw[capacity:],b'\xa5'*8)
        self.assertEqual(workspace.raw,b'\x5a'*8)
        if result>capacity:self.assertEqual(output.raw,b'\xa5'*(capacity+8))
        return result,output.raw[:capacity]

    def test_native_matches_full_byte_interpreter_and_no_foreign_compiler(self):
        for wire,result in self.witnesses:self.assertEqual(self.raw(wire),(24,result))
        self.assertEqual(self.receipt['forbidden_compiler_modules_loaded'],[])

    def test_uint64_boundary_and_random_independent_integer_oracle(self):
        values=['','0','00','01','-0','-1','+1','1.0','1e1',' 1','1\n',str((1<<64)-1),str(1<<64),'9'*20,'0'*21,'١','１２',None,True,4]
        rng=random.Random(0x1de1717)
        values += [str(rng.randrange(-(1<<65),1<<65)) for _ in range(4000)]
        for text in values:
            wanted=int(text) if (type(text)is str and 0<len(text)<=20 and all('0'<=x<='9' for x in text) and (text=='0' or text[0]!='0') and int(text)<1<<64) else None
            self.assertEqual(self.native.uint64(text),wanted,repr(text))
        for ch in range(256):
            wire=packet(0,b'1'+bytes([ch]))
            good=48<=ch<=57
            self.assertEqual(self.raw(wire),(24,expected(int(good),10+ch-48 if good else 0)))

    def test_digest_exact_ascii_and_all_byte_mutations(self):
        valid='0123456789abcdef'*4
        self.assertTrue(self.native.digest(valid))
        for ch in range(256):
            good=48<=ch<=57 or 97<=ch<=102
            self.assertEqual(self.raw(packet(1,valid[:17].encode()+bytes([ch])+valid[18:].encode())),(24,expected(int(good))))
        for value in ['',valid[:-1],valid+'a',valid.upper(),valid+'\n','é'*64,None,42,True]:
            self.assertFalse(self.native.digest(value))

    def test_malformed_transport_short_output_and_poisoned_canaries(self):
        for wire in [b'',b'0'*15,packet(2,b'0'),packet((1<<64)-1,b''),b'0'*16,packet(0,b'0'*65),
                     packet(3,struct.pack('<4Q',1,1,1,0)),packet(4,b'0'),
                     packet(4,struct.pack('<Q',(1<<20)+1)),packet(5,struct.pack('<2QdQ',3,2,1.1,6)),
                     packet(5,struct.pack('<2QdQ',3,2,0.0,32))]:
            self.assertEqual(self.raw(wire)[0],0xfffffffd)
        self.assertEqual(self.raw(packet(0,b'0'),23)[0],0xfffffffe)
        with self.assertRaises(ValueError):self.native.scalar('1',False)

    def test_native_proof_eligibility_matches_reference_and_checks_transport(self):
        from itertools import product
        from hepta.hia_agent_service import HIAAgentService

        claims = ('core_admission', 'behavior_equivalence', 'lowering_refinement', 'encoding_check')
        for claim, kind, planned, match, status in product(
            claims, ('core_program', 'agent_machine_plan', 'native_artifact'),
            (False, True), (False, True), ('proved', 'unknown', 'refuted'),
        ):
            candidate = {'id': 'candidate', 'sha256': 'digest'}
            other = {'sha256': 'digest', 'id': 'other'}
            plan = {'sha256': 'plan digest', 'id': 'plan'}
            observed = dict(reversed(list(candidate.items()))) if match else other
            subject = {'kind': kind}
            if kind == 'native_artifact':
                subject['native_artifact'] = observed
            if kind == 'agent_machine_plan':
                subject['plan'] = plan if match else other
            receipt = {'subject': subject, 'base_core_sha256': 'base' if match else 'different',
                       'checks': [{'claim': claim, 'status': status}]}
            native = {'machine_plan': {} if planned else None, 'codegen': {'plan': plan}}
            wanted = HIAAgentService._reference_claim_eligibility(claim, receipt, candidate, native, 'base')
            self.assertEqual(self.native.claim_eligibility(claim, receipt, candidate, native, 'base'),
                             wanted, (claim, kind, planned, match, status))
        scope = [(b'x', b'x')] * 3
        wire = proof_request(3, 1, 0, [7], scope)
        for malformed in (wire[:-1], wire + b'x', proof_request(4, 1, 0, [7], scope),
                          proof_request(3, 3, 0, [7], scope), proof_request(3, 1, 2, [7], scope),
                          proof_request(3, 1, 0, [8], scope), proof_request(3, 1, 0, [7] * 5, scope)):
            self.assertEqual(self.raw(malformed)[0], 0xfffffffd)
        self.assertEqual(self.raw(wire, 23)[0], 0xfffffffe)

    def test_native_proof_evidence_preserves_types_and_evidence_precedence(self):
        from hepta.hia_agent_identity_native import PROOF_EVIDENCE_METHODS
        from hepta.hia_agent_store import AgentRejected
        from hepta.hia_proof_contract import _CHECKERS, _reference_method

        core = {'kind': 'core', 'candidate_core_sha256': 'c' * 64,
                'base_core_sha256': 'b' * 64, 'base_program': {'id': 'base'}}
        admitted = {'checker': _CHECKERS['core_admission'], 'core_sha256': 'c' * 64}
        identity = {'method': 'canonical_core_identity', 'base_sha256': 'c' * 64,
                    'candidate_sha256': 'c' * 64, 'all_inputs': True}
        finite = {'method': 'finite_domain', 'checked': 4096, 'required': 4096, 'complete': True,
                  'candidate_sha256': 'c' * 64, 'base_sha256': 'b' * 64,
                  'all_inputs_in_declared_widths': True, 'transcript_sha256': 't' * 64}
        image = dict(core, kind='native_artifact', native_artifact={'sha256': 'a' * 64})
        encoding = {'method': 'complete_native_rederivation', 'actual_sha256': 'a' * 64,
                    'bytes_equal': True, 'object_identity_equal': True}
        plan = {'method': 'checked_explicit_machine_choices',
                'core_sha256': 'c' * 64, 'plan': {'core_sha256': 'c' * 64}}
        cases = [
            ('core_admission', 'proved', core, admitted),
            ('core_admission', 'unknown', core, admitted),
            ('core_admission', 'proved', core, dict(admitted, core_sha256='other')),
            ('behavior_equivalence', 'proved', dict(core, base_core_sha256='c' * 64), identity),
            ('behavior_equivalence', 'proved', core, identity),
            ('behavior_equivalence', 'unknown', core, {'method': 'context_budget_exhausted'}),
            ('behavior_equivalence', 'proved', core, finite),
            ('behavior_equivalence', 'proved', core, dict(finite, checked=4096.0)),
            ('behavior_equivalence', 'proved', core, dict(finite, required=4097)),
            ('behavior_equivalence', 'proved', core, dict(finite, all_inputs_in_declared_widths=1)),
            ('behavior_equivalence', 'unknown', core, dict(finite, complete=False)),
            ('behavior_equivalence', 'unknown', core, dict(finite, complete=False, counterexample=None)),
            ('lowering_refinement', 'unsupported', dict(core, kind='canonical_lowering'), {'reason': ''}),
            ('lowering_refinement', 'proved', dict(core, kind='agent_machine_plan'), plan),
            ('lowering_refinement', 'proved', dict(core, kind='agent_machine_plan'), dict(plan, plan=[])),
            ('encoding_check', 'proved', image, encoding),
            ('encoding_check', 'refuted', image, dict(encoding, bytes_equal=False)),
            ('encoding_check', 'proved', image, dict(encoding, bytes_equal=1)),
        ]
        for index, args in enumerate(cases):
            with self.subTest(index=index):
                try:
                    expected = _reference_method(*args)
                except AgentRejected:
                    expected = ''
                decision = self.native.proof_evidence(*args, admission_checker=_CHECKERS['core_admission'])
                self.assertEqual(PROOF_EVIDENCE_METHODS[decision], expected)

        header = packet(15, struct.pack('<10Q', 1, 1, 1, 0, 0, 0, 0, 0, 0, 0))
        pair = struct.pack('<2Q', 1, 1) + bytes(2)
        valid_frame = header + pair * 7
        self.assertEqual(self.raw(valid_frame)[0], 24)
        for malformed in (valid_frame[:-1], valid_frame + b'x',
                          header + struct.pack('<2Q', 0, 1) + pair * 6):
            self.assertEqual(self.raw(malformed)[0], 0xfffffffd)

    def test_call_scalar_gate_preserves_exact_frozen_types_and_ranges(self):
        from hepta.hia_agent_buffers import validate_arguments
        from hepta.hia_agent_identity_native import ABI_SCALAR_IDS
        from hepta.hia_opcodes import WIDTHS, scalar_value_valid

        for typ in (*WIDTHS, 'bool', 'unit', 'missing'):
            width = WIDTHS.get(typ, 1)
            boundary = 1 << (width - 1)
            samples = (None, False, True, -0.0, 1.0, '0', 0, -1, 1,
                       -boundary - 1, -boundary, -boundary + 1, boundary - 1,
                       boundary, (1 << width) - 1, 1 << width, 1 << 200)
            for value in samples:
                with self.subTest(typ=typ, value=value):
                    self.assertEqual(self.native.abi_scalar(value, typ), scalar_value_valid(value, typ))
        encoded = packet(14, struct.pack('<3Q', ABI_SCALAR_IDS['u64'], 3, (1 << 64) - 1))
        self.assertEqual(self.raw(encoded), (24, expected(1, 1)))
        self.assertEqual(self.raw(encoded[:-1])[0], 0xfffffffd)
        self.assertEqual(self.raw(encoded + b'\0')[0], 0xfffffffd)
        self.assertEqual(self.raw(encoded, 23)[0], 0xfffffffe)
        signature = {'params': ('u64', 'i64', 'bool', 'unit')}
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch('hepta.hia_program.scalar_value_valid', side_effect=AssertionError('host range used'))):
            self.assertEqual(validate_arguments(signature, [(1 << 64) - 1, -(1 << 63), True, None]), 0)
            with self.assertRaises(AgentRejected) as error:
                validate_arguments(signature, [1 << 64, -(1 << 63), True, None])
            self.assertEqual(error.exception.code, 'E_HIA_ARGUMENTS')

    def test_native_exact_byte_comparison_across_chunks_and_bad_framing(self):
        prefix = bytes(range(256)) * (EXACT_COMPARISON_CHUNK // 256)
        for left, right in (
            (b'', b''), (b'', b'\x00'), (b'\xff\x00', b'\xff\x00'),
            (prefix, prefix), (prefix, prefix + b'\x00'),
            (prefix + b'\xff\x00', prefix + b'\xff\x00'),
            (prefix + b'\xff\x00', prefix + b'\xff\x01'),
        ):
            with self.subTest(lengths=(len(left), len(right)), expected=left == right):
                self.assertEqual(self.native.exact_bytes_equal(left, right), left == right)
        framed = packet(13, struct.pack('<2Q', 1, 1) + b'\x00\x00')
        self.assertEqual(self.raw(framed), (24, expected(1, 1)))
        for bad in (framed[:-1], framed + b'\x00', packet(13, b''),
                    packet(13, struct.pack('<2Q', EXACT_COMPARISON_CHUNK + 1, 0)),
                    packet(13, struct.pack('<2Q', 0, (1 << 64) - 1))):
            self.assertEqual(self.raw(bad)[0], 0xfffffffd)
        self.assertEqual(self.raw(framed, 23)[0], 0xfffffffe)

    def test_required_claims_recheck_every_qualifying_build_in_order(self):
        from unittest.mock import Mock, call
        from hepta.hia_agent_service import HIAAgentService

        service = Mock()
        context = {'ref': 'context', 'objective': 'objective'}
        artifact = {'id': 'selected'}
        native = {'candidate': 'program', 'machine_plan': None}
        objective = {'required_claims': ['encoding_check']}
        service._native.return_value = (b'native', native, None)
        service.store.get_json.return_value = (objective, None)
        service._verification.side_effect = [
            {'subject': {'kind': 'native_artifact', 'native_artifact': subject, 'build_receipt': build},
             'base_core_sha256': None, 'checks': [{'claim': 'encoding_check', 'status': 'proved'}]}
            for subject, build in ((artifact, 'build-1'), ({'id': 'another'}, 'skip'), (artifact, 'build-2'))
        ]
        service._reference_claim_eligibility.side_effect = AssertionError('host proof policy executed')
        with patch('hepta.hia_agent_store._native_agent_identity', return_value=self.native):
            actual = HIAAgentService._required_claims(service, context, artifact, ['r1', 'r2', 'r3'])
        self.assertIs(actual, objective)
        self.assertEqual(service._verification.call_args_list,
                         [call('r1', 'context', 'program'), call('r2', 'context', 'program'),
                          call('r3', 'context', 'program')])
        self.assertEqual(service._build_receipt.call_args_list,
                         [call('build-1', 'context', artifact), call('build-2', 'context', artifact)])

    def test_native_observation_agreement_matches_host_policy_and_rejects_bad_framing(self):
        from hepta.hia_agent_service import HIAAgentService

        original = HIAAgentService._reference_observation_agreement
        buffers = [{'argument': 0, 'kind': 'mutbuf', 'sha256': 'ab' * 32, 'byte_length': 3}]
        returned = {'status': 'returned', 'values': [True], 'buffers': buffers,
                    'ledger': {'resources': {'live': 0, 'allocated': 3}}}
        trapped = {'status': 'trapped', 'trap_code': 'E_HIA_BOUNDS', 'buffers': buffers,
                   'ledger': {'resources': {'live': 1, 'allocated': 3}}}
        cases = [
            (DECLARED_OBSERVATION, returned, {'status': 'returned', 'values': [1]}),
            (DECLARED_OBSERVATION, returned, {'status': 'returned', 'values': [0]}),
            (DECLARED_OBSERVATION, trapped, {'status': 'trapped'}),
            (REFERENCE_OBSERVATION, returned, {**returned, 'values': [1]}),
            (REFERENCE_OBSERVATION, returned, {**returned, 'ledger': {'resources': {'live': 1, 'allocated': 3}}}),
            (REFERENCE_OBSERVATION, trapped, {**trapped, 'trap_code': 'E_HIA_DIVISION'}),
            (NATIVE_OBSERVATION, trapped, {**trapped, 'trap_code': 'different', 'ledger': {}}),
            (NATIVE_OBSERVATION, trapped, {**trapped, 'buffers': [{**buffers[0], 'sha256': 'ba' * 32}]}),
            (NATIVE_OBSERVATION, returned, trapped),
        ]
        for mode, left, right in cases:
            with self.subTest(mode=mode, right=right):
                self.assertEqual(self.native.observation_agreement(left, right, mode=mode),
                                 original(left, right, mode=mode))
        empty = [(b'', b'')] * 5
        accepted = comparison(0, empty)
        self.assertEqual(self.raw(accepted), (24, expected(1, 1)))
        for malformed in (accepted[:-1], accepted + b'X', comparison(3, empty),
                          packet(7, struct.pack('<3Q', 0, (1 << 64) - 1, 10))):
            self.assertEqual(self.raw(malformed)[0], 0xfffffffd)

    def test_real_evaluation_distinguishes_trap_writes_without_host_comparison(self):
        from hepta.hia_agent_service import HIAAgentService
        from tests.test_hia_agent_buffer_lifecycle import trap_program, workload
        from tools.hia_agent_native_qualification import Session, ToolClient

        with (tempfile.TemporaryDirectory(prefix='hia-agent-observation-') as directory,
              patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(HIAAgentService, '_reference_observation_agreement',
                           side_effect=AssertionError('host comparison used'))):
            service = HIAAgentService(directory)
            try:
                for prefix, written, expected_outcome in (('identical', 91, 'unchanged'),
                                                          ('different', 92, 'incorrect')):
                    session = Session(ToolClient(service.call), prefix=prefix)
                    session.freeze(workload([{'function': 'write_then_trap',
                        'arguments': [{'bytes_hex': '010203'}], 'expected': {'status': 'trapped'}}],
                        function='write_then_trap'))
                    base, candidate = [session.import_program(trap_program(value))
                                       for value in (91, written)]
                    verification = session.verify(candidate)['verification_receipt']
                    base_image, candidate_image = session.emit(base), session.emit(candidate, receipts=[verification])
                    encoding = session.encoding(candidate, candidate_image)['verification_receipt']
                    evaluation = session.evaluate(base_image, candidate_image, receipts=[verification, encoding])
                    self.assertTrue(evaluation['planned_workload_complete'])
                    self.assertEqual(evaluation['outcome'], expected_outcome)
            finally:
                service.close()

    def test_actual_store_callers_disable_reference_and_keep_errors(self):
        from hepta import hia_agent_store as store
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)}),patch.object(store,'_reference_uint64',side_effect=AssertionError('host numeric fallback')),patch.object(store,'_reference_digest',side_effect=AssertionError('host regex fallback')):
            self.assertEqual(uint64('0','epoch'),0);self.assertEqual(uint64(str((1<<64)-1),'epoch'),(1<<64)-1)
            self.assertTrue(canonical_digest('f'*64));self.assertFalse(canonical_digest('F'*64))
            for value in ['00','-1',str(1<<64),False,None]:
                with self.assertRaises(AgentRejected) as raised:uint64(value,'epoch')
                self.assertEqual(raised.exception.code,'E_HIA_RANGE')
                self.assertEqual(str(raised.exception),'epoch must be a canonical u64 decimal string')
            self.assertEqual(list(ThreadPoolExecutor(8).map(lambda i:uint64(str(i),'epoch'),range(128))),list(range(128)))

    def test_store_authorizes_artifact_and_cursor_through_installed_policy(self):
        from hepta import hia_agent_store as store
        from hepta.hia_agent_service import HIAAgentService

        fields = [(b'', b'')] * 4
        complete = comparison(1, fields, 8)
        for malformed in (complete[:-1], complete + b'X', comparison(2, fields, 8),
                          packet(8, struct.pack('<3Q', 1, (1 << 64) - 1, 0))):
            self.assertEqual(self.raw(malformed)[0], 0xfffffffd)
        with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
              patch.object(store, '_reference_record_authority',
                           side_effect=AssertionError('host authority policy used'))):
            service = HIAAgentService(self.folder / 'record-authority')
            try:
                original = service.store.put(b'x' * 520, 'input')
                alternate = service.store.put(b'other', 'input')
                self.assertEqual(service.store.get(original, kind='input')[0], b'x' * 520)
                unissued = {**original, 'id': 'not-issued'}
                changed = {**original, 'uri': alternate['uri']}
                for supplied, code in ((original, 'E_HIA_ARTIFACT_AUTHORITY'),
                                       (unissued, 'E_HIA_ARTIFACT_IDENTITY'),
                                       (changed, 'E_HIA_ARTIFACT_IDENTITY'),
                                       ({**original, 'sha256': 1}, 'E_HIA_ARTIFACT_IDENTITY')):
                    with self.subTest(code=code, supplied=supplied), self.assertRaises(AgentRejected) as raised:
                        service.store.get(supplied, kind='proof')
                    self.assertEqual(raised.exception.code, code)
                page = service._hia_read({'artifact': original, 'max_bytes': 512})
                query = {'artifact': original, 'cursor': page['next_cursor'], 'max_bytes': 512}
                self.assertEqual(service._hia_read(query)['content'], 'x' * 8)
                for invalid in ({**query, 'artifact': alternate}, {**query, 'cursor': 'unissued'}):
                    with self.assertRaises(AgentRejected) as raised:
                        service._hia_read(invalid)
                    self.assertEqual(raised.exception.code, 'E_HIA_CURSOR')
            finally:
                service.close()

    def test_native_wall_window_matches_absolute_deadline_without_overflow(self):
        from hepta.hia_agent_service import _reference_wall_window

        end = (1 << 64) - 1
        samples = [(0, 0, 0), (1, 0, end), (400_000_000, 0, end), (0, end, 0),
                   (0, end, end), (end, end - 999_999, 0), (100, 1_000_101, 1)]
        rng = random.Random(0xa651f)
        samples += [tuple(rng.getrandbits(64) for _ in range(3)) for _ in range(256)]
        high = 1 << 200
        samples += [(high, high + change, budget)
                    for change in (-1_000_001, -1_000_000, -1, 0, 1, 1_000_000, 1_000_001)
                    for budget in (-1, 0, 1)]
        samples += [tuple(rng.choice((-1, 1)) * rng.getrandbits(rng.randrange(9000))
                          for _ in range(3)) for _ in range(256)]
        for created, now, budget in samples:
            self.assertEqual(self.native.wall_window(created, now, budget),
                             _reference_wall_window(created, now, budget))
        wire = packet(9, struct.pack('<3Q', 0, 0, 1))
        self.assertEqual(self.raw(wire[:-1], 32)[0], 0xfffffffd)
        self.assertEqual(self.raw(wire, 31)[0], 0xfffffffe)
        wide = packet(18, struct.pack('<Q3I', 1, 0, 0, 0))
        self.assertEqual(self.raw(wide[:-1], 20)[0], 0xfffffffd)
        self.assertEqual(self.raw(wide, 19)[0], 0xfffffffe)
        self.assertEqual(self.raw(packet(18, struct.pack('<Q3I', 1, 0, 0, 1)), 20)[0], 0xfffffffd)

    def test_native_finite_domain_matches_scalar_cfg_and_width_boundaries(self):
        from hepta.hia_agent_service import _reference_finite_function
        from hepta.hia_opcodes import OPCODES, WIDTHS

        def function(successors, *, entry=0, effects=(), operations=('int.add.wrap',)):
            blocks = []
            for index, targets in enumerate(successors):
                term = {'op': 'ret'}
                if len(targets) == 1:
                    term = {'op': 'jump', 'target': targets[0]}
                elif len(targets) == 2:
                    term = {'op': 'branch', 'then': {'target': targets[0]}, 'else': {'target': targets[1]}}
                blocks.append({'id': index, 'term': term,
                               'ops': [{'op': name} for name in operations] if index == 0 else []})
            return {'entry': entry, 'blocks': blocks, 'effects': list(effects)}

        rng = random.Random(0xF117E)
        cases = [function([(1,), (), (2,)]), function([(1,), (), (2,)], entry=2)]
        for count in (1, 2, 127, 128, 129):
            route = [(i + 1,) for i in range(count - 1)]
            cases.extend((function([*route, ()]), function([*route, (0,)])))
        for opcode in OPCODES:
            cases.append(function([()], operations=[opcode]))
        for effects in (('trap',), ('read',), ('write',), ('alloc',)):
            cases.append(function([()], effects=effects))
        cases.extend(function([()], operations=['const'] * size) for size in (4096, 4097))
        for _ in range(150):
            size = rng.randint(1, 16)
            cases.append(function([tuple(rng.randrange(size) for _ in range(rng.randrange(3)))
                                   for _ in range(size)], entry=rng.randrange(size)))
        for shape in cases:
            self.assertEqual(self.native.finite_function(shape), _reference_finite_function(shape), shape)

        samples = [([], 4095), ([], 4096), (['bool'] * 12, 0), (['bool'] * 12, 1),
                   (['bool'] * 13, 0), (['i8', 'bool'], 4096 - 512),
                   (['i8', 'bool'], 4096 - 511), (['unit'], 0), (['u64', 'bool'], 0)]
        for parameters, used in samples:
            bits = sum(1 if name == 'bool' else WIDTHS.get(name, 1_000_000) for name in parameters)
            needed = 1 << bits if bits <= 12 and (1 << bits) <= 4096 - used else 0
            self.assertEqual(self.native.finite_domain(parameters, used), (needed, used + needed))

    def test_real_context_admission_uses_hia_for_clock_window_and_binding(self):
        from hepta import hia_agent_service as hosted, hia_agent_store as store
        from tests.test_hia_agent_buffer_lifecycle import workload
        from tools.hia_agent_native_qualification import Session, ToolClient

        service = hosted.HIAAgentService(self.folder / 'wall-window')
        try:
            with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
                  patch.object(store, '_reference_record_authority',
                               side_effect=AssertionError('host context identity used')),
                  patch.object(hosted, '_reference_wall_window',
                               side_effect=AssertionError('host clock budget used'))):
                session = Session(ToolClient(service.call))
                session.freeze(workload([{'function': 'take', 'arguments': [{'bytes_hex': '00'}]}],
                                        function='take'))
                ref = session.context
                with self.assertRaises(AgentRejected) as raised:
                    service._context({**ref, 'sha256': 'f' * 64})
                self.assertEqual(raised.exception.code, 'E_HIA_CONTEXT_IDENTITY')
                context = service._context(ref)
                issued = service.store.db.execute('SELECT created_ns FROM contexts WHERE id=?',
                                                  (ref['id'],)).fetchone()
                deadline = int(issued['created_ns']) + context['budget']['max_total_wall_ms'] * 1_000_000
                with patch.object(hosted.time, 'time_ns', return_value=deadline):
                    self.assertEqual(service._remaining_ms(context), 0)
                    service._budget(context, candidate=True)
                with (patch.object(hosted.time, 'time_ns', return_value=deadline + 1),
                      patch.object(service, '_consume_attempt',
                                   side_effect=AssertionError('expired context advanced a candidate'))):
                    self.assertEqual(service._remaining_ms(context), 0)
                    with self.assertRaises(AgentRejected) as raised:
                        service._budget(context, candidate=True)
                    self.assertEqual(raised.exception.code, 'E_HIA_BUDGET')
                for historical in (-(1 << 200), (1 << 200) + 17):
                    service.store.db.execute('UPDATE contexts SET created_ns=? WHERE id=?',
                                             (str(historical), ref['id']))
                    limit = context['budget']['max_total_wall_ms']
                    with patch.object(hosted.time, 'time_ns', return_value=historical + limit * 1_000_000):
                        self.assertEqual(service._wall_window(context), (False, 0))
                    with patch.object(hosted.time, 'time_ns', return_value=historical + limit * 1_000_000 + 1):
                        self.assertEqual(service._wall_window(context), (True, 0))
        finally:
            service.close()

    def test_public_context_limits_match_reference_and_use_native_decisions(self):
        from hepta.hia_agent_service import HIAAgentService
        from tools.hia_agent_native_qualification import Session, ToolClient

        service = HIAAgentService(self.folder/'frozen-context')
        try:
            session = Session(ToolClient(service.call, validate=False))
            objective = session.artifact({
                'schema': 'hepta.hia.agent.objective.v1', 'metric': 'artifact_bytes',
                'required_claims': ['core_admission'], 'allow_unchanged': False,
                'min_improvement_ratio': 0})
            cost = {'schema': 'hepta.hia.agent.cost-policy.v1', 'expected_invocations': '1',
                    'external_costs_complete': True, 'external_costs': {
                        'model_tokens': 1, 'model_wall_ns': '0', 'discovery_wall_ns': '0'}}
            workload = {
                'schema': 'hepta.hia.agent.workload.v2', 'warmup_iterations': 0, 'repetitions': 1,
                'foreign_buffer_exports': [{'function': 'take', 'max_buffer_bytes': 1<<20}],
                'cases': [{'function': 'take', 'arguments': [{'byte_length': 1<<20, 'fill_byte': 0}]}]}
            equal_snapshot = session.artifact({**workload, 'cases': workload['cases']*32})
            excessive_snapshot = session.artifact({**workload, 'cases': workload['cases']*33})
            exact_cost = session.artifact(cost)
            missing_cost = session.artifact({**cost,
                'external_costs': {**cost['external_costs'], 'discovery_wall_ns': None}})
            standard = {'max_candidates': 1, 'max_model_tokens': 1, 'max_total_wall_ms': 500,
                        'max_native_wall_ms': 500, 'max_memory_bytes': str(64<<20), 'cost_policy': exact_cost}
            cases = ((equal_snapshot, {}, None), (equal_snapshot, {'max_memory_bytes': str(4<<30)}, None),
                     (equal_snapshot, {'max_memory_bytes': str((64<<20)-1)}, 1),
                     (equal_snapshot, {'max_total_wall_ms': 499}, 2),
                     (equal_snapshot, {'max_model_tokens': 0, 'cost_policy': missing_cost}, 3),
                     (equal_snapshot, {'cost_policy': missing_cost}, 4),
                     (excessive_snapshot, {'max_memory_bytes': '0'}, 5))
            from hepta.hia_agent_identity_native import CONTEXT_REFUSALS
            for workload_ref, overrides, refusal in cases:
                with self.subTest(overrides=overrides, refusal=refusal):
                    args = session.arguments(context=False, compiler_profile=session.profiles['compiler'],
                        target_profile=session.profiles['target'], baseline_program=None,
                        workload=workload_ref, objective=objective, budget={**standard, **overrides})
                    sampled = '2026-11-19T00:01:02.345678+00:00'
                    with patch('hepta.hia_agent_service._now', return_value=sampled):
                        reference = service.call('hia_context', args)
                    args['request_key'] = session.key('native')
                    image = installed_agent_identity(str(self.manifest))
                    with (patch.dict(os.environ, {SELECTOR:str(self.manifest)}),
                          patch('hepta.hia_agent_service._now', return_value=sampled),
                          patch.object(service, '_reference_context_manifest',
                                       side_effect=AssertionError('host context manifest entered')),
                          patch.object(service, '_reference_context_receipt',
                                       side_effect=AssertionError('host context receipt entered')),
                          patch.object(image, '_context', wraps=image._context) as selected_calls):
                        selected = service.call('hia_context', args)
                    self.assertEqual(selected['status'], reference['status'])
                    if refusal is None:
                        self.assertEqual(selected['status'], 'completed', selected)
                        original, actual = reference['result'], selected['result']
                        self.assertEqual(original['manifest'], actual['manifest'])
                        self.assertEqual(original['context']['sha256'], actual['context']['sha256'])
                        self.assertRegex(actual['context']['id'], r'^ctx-[0-9a-f]{32}$')
                        self.assertNotEqual(original['context']['id'], actual['context']['id'])
                        self.assertEqual({**actual, 'context': original['context']}, original)
                        self.assertEqual(service.call('hia_context', args), selected)
                    else:
                        self.assertEqual(selected['status'], 'rejected', selected)
                        self.assertEqual(selected['error'], reference['error'])
                        code, message = CONTEXT_REFUSALS[refusal]
                        self.assertEqual((selected['error']['code'], selected['error']['message']), (code, message))
                    # The current source-bound image is pinned once per lookup.
                    self.assertIn(4, [call.args[0] for call in selected_calls.call_args_list])
        finally:
            service.close()

    def test_evaluation_ratios_match_binary64_and_preserve_outcome_priority(self):
        from hepta.hia_agent_service import HIAAgentService

        limit = (1 << 64) - 1
        cases = [(0, 0), (0, 1), (1, limit), (limit, 1), (limit, limit-1), (limit, limit),
                 (3, 2), (3, 7), (1<<54, (1<<53)-1), (1<<54, (1<<53)-3)]
        reference = HIAAgentService._reference_evaluation_measurement
        flags = ('budget_exceeded', 'correct', 'complete', 'latency', 'trapping')

        def exact(before, after, threshold, mask):
            status = {name: bool(mask & (1 << index)) for index, name in enumerate(flags)}
            expected_ratio, expected_outcome = reference(before, after, threshold, **status)
            actual_ratio, actual_outcome = self.native.evaluation_measurement(before, after, threshold, **status)
            self.assertEqual(struct.pack('<d', actual_ratio), struct.pack('<d', expected_ratio),
                             (before, after, threshold, mask))
            self.assertEqual(actual_outcome, expected_outcome, (before, after, threshold, mask))

        for before, after in cases:
            for threshold in (-0.0, 0.0, 0.1, 0.5, 1.0):
                for mask in range(32):
                    exact(before, after, threshold, mask)
        random_values = random.Random(0x484941)
        for _ in range(4000):
            before = random_values.getrandbits(random_values.randrange(65))
            after = random_values.getrandbits(random_values.randrange(65))
            exact(before, after, random_values.random(), random_values.randrange(32))

    def test_observed_costs_exact_by_scope_with_wide_carry_and_historical_values(self):
        from hepta.hia_agent_service import HIAAgentService

        maximal = (1 << 64) - 1
        rows = [{'context_id': 'mine' if index % 3 else None, 'wall_ns': str(maximal)}
                for index in range(10000)]
        reference = HIAAgentService._reference_observed_cost_totals
        self.assertEqual(self.native.observed_cost_totals(rows, 'mine'), reference(rows, 'mine'))
        self.assertEqual(self.native.observed_cost_totals([], 'mine'), (0, 0))

        historical = [
            {'context_id': 'mine', 'wall_ns': str(2**260 + 7)},
            {'context_id': 'mine', 'wall_ns': str(-2**260 + 13)},
            {'context_id': 'mine', 'wall_ns': ' +١_٢ '},
            {'context_id': None, 'wall_ns': str(-2**390 + 15)},
            {'context_id': None, 'wall_ns': str(2**128 + maximal)},
            {'context_id': 'other', 'wall_ns': 'unused input'},
        ]
        self.assertEqual(self.native.observed_cost_totals(historical, 'mine'), reference(historical, 'mine'))
        self.assertEqual(self.raw(packet(6, b''), 40), (40, struct.pack('<5Q', RESULT_MAGIC, 0, 0, 0, 0)))
        self.assertEqual(self.raw(packet(6, b''), 39)[0], 0xfffffffe)
        for invalid in (b'1', struct.pack('<2Q', 2, 0), bytes(160016)):
            self.assertEqual(self.raw(packet(6, invalid), 40)[0], 0xfffffffd)

    def test_native_cost_receipt_distinguishes_zero_unknown_and_truncated_history(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_store import wire

        context = {'id': 'ctx-observed', 'sha256': 'a' * 64, 'uri': 'hia://context/observed'}
        policy = {'external_costs': {'model_tokens': 0, 'discovery_wall_ns': '0', 'model_wall_ns': '12'},
                  'expected_invocations': '17'}
        totals = (2**200, -2**140)
        for count in (0, 1, 9999, 10000, 10001):
            retained = self.native.cost_window(count)
            self.assertEqual(retained, min(count, 10000))
            for complete in (False, True):
                frozen = {**policy, 'external_costs_complete': complete}
                expected = HIAAgentService._reference_cost_receipt(
                    context, [], count > retained, frozen, totals, 8, 3)
                expected.pop('entries')
                self.assertEqual(self.native.cost_ledger_header(context, count, frozen, totals, 8, 3), expected)
        self.assertEqual(self.raw(packet(17, struct.pack('<Q', 10002)))[0], 0xfffffffd)
        fragments = (context, '0', '0', '0', 0, '0', '1', '0', '0')
        payload = packet(16, struct.pack('<2Q', 0, 1) + b''.join(
            struct.pack('<Q', len(raw)) + raw for raw in map(wire, fragments)))
        for malformed in (payload[:-1], payload + b'X', packet(16, bytes(16))):
            self.assertEqual(self.raw(malformed, 1024)[0], 0xfffffffd)
        self.assertEqual(self.raw(payload, 63)[0], 0xfffffffe)

    def test_ordinary_cost_ledger_uses_installed_receipt_with_no_reference_policy(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_store import wire

        service = HIAAgentService(self.folder / 'cost-ledger')
        try:
            policy = {'external_costs': {'model_tokens': 0, 'discovery_wall_ns': '0', 'model_wall_ns': None},
                      'expected_invocations': '18', 'external_costs_complete': False}
            context_ref = {'id': 'mine', 'sha256': 'a' * 64, 'uri': 'hia://ctx/mine'}
            context = {'ref': context_ref, 'budget': {'cost_policy': service.store.json(policy, 'input')}}
            details = wire({'error': {'message': '保留失败'}, 'replayed': False}).decode()
            service.store.db.executemany('INSERT INTO costs'
                ' (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)',
                [(scope, 'hia_test', 'request-' + str(index), str(time_ns), 'rejected', details)
                 for index, (scope, time_ns) in enumerate((('other', 7), (None, 3), ('mine', 2**90), ('mine', -9)))])
            expected = service._cost_ledger(context, 13, 5)
            with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
                  patch.object(service, '_reference_cost_receipt', side_effect=AssertionError('host cost receipt')),
                  patch.object(service, '_reference_observed_cost_totals', side_effect=AssertionError('host aggregation'))):
                selected = service._cost_ledger(context, 13, 5)
            self.assertEqual(wire(selected), wire(expected))
            self.assertEqual([entry['request_id'] for entry in selected['entries']],
                             ['request-1', 'request-2', 'request-3'])
            self.assertEqual(selected['context_tool_wall_ns_before_evaluation'], str(2**90 - 9))
            self.assertEqual(selected['external_costs'], dict.fromkeys(policy['external_costs']))
        finally:
            service.close()

    def test_issued_page_and_candidate_receipts_are_canonical_and_inert(self):
        from hepta.hia_agent_store import wire

        artifact = {"id": "issued", "sha256": "a" * 64, "uri": "hia://artifact/issued"}
        diagnostics = {**artifact, "id": "diagnostic"}
        cursor = "page-" + "b" * 64
        for content, encoding, next_cursor in (('你"\n\x00', 'utf8', cursor), ('AAE=', 'base64', None)):
            fields = (artifact, content, encoding, next_cursor)
            expected = wire(dict(zip(('artifact', 'content', 'encoding', 'next_cursor'), fields)))
            request = packet(24, b''.join(struct.pack('<Q', len(wire(value))) + wire(value) for value in fields))
            self.assertEqual(self.raw(request, len(expected)), (len(expected), expected))
            self.assertEqual(self.raw(request, len(expected) - 1)[0], 0xfffffffe)
            self.assertEqual(self.raw(request[:-1], len(expected))[0], 0xfffffffd)
            self.assertEqual(wire(self.native.page_receipt(*fields)), expected)
        for base in (None, artifact):
            self.assertEqual(self.native.candidate_receipt(base, artifact, diagnostics), {
                "adopted": False, "base_program": base, "behavior_equivalence_proved": False,
                "candidate": artifact, "core_admitted": True, "diagnostics": diagnostics,
            })

    def test_issued_verification_and_build_records_survive_service_restart(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_store import wire
        from tools.hia_agent_native_qualification import Session, ToolClient, add_program, exhaustive_u8_workload

        state = self.folder / "issued-verification-and-build"
        service = HIAAgentService(state)
        try:
            session = Session(ToolClient(service.call, validate=False))
            session.freeze(exhaustive_u8_workload())
            candidate = session.import_program(add_program())
            hosted = session.verify(candidate)
            verification = session.arguments(candidate=candidate, base_program=None,
                validation_profile=session.profiles["validation"], subject={"kind": "core"},
                claims=["core_admission"])
            stored_json = service.store.json

            def retain_json(value, kind, *args):
                self.assertNotIn(kind, ("verification-receipt", "build-receipt"))
                return stored_json(value, kind, *args)

            with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
                  patch.object(service.store, "json", side_effect=retain_json)):
                accepted = service.call("hia_verify", verification)
                self.assertEqual(accepted["result"], hosted)
                build = session.arguments(candidate=candidate, backend_profile=session.backend, output_kind="object",
                    codegen={"kind": "canonical", "lowering_profile": session.profiles["lowering"]},
                    verification_receipts=[hosted["verification_receipt"]])
                emitted = service.call("hia_emit", build)
                self.assertEqual(emitted["status"], "completed", emitted)
                result = emitted["result"]
                self.assertIs(result["linker_used"], False)
                self.assertIs(result["adopted"], False)
                self.assertIs(result["native_execution_observed"], False)
                record, _, raw = service.store.get_json_with_wire(result["build_receipt"], kind="build-receipt")
                self.assertEqual(raw, wire(record))
                self.assertEqual(record["candidate"], candidate)
                self.assertEqual(record["native_artifact"], result["native_artifact"])
                self.assertEqual(record["verification_receipts"], build["verification_receipts"])
                self.assertEqual(record["object_sha256"], sha256(session.read(result["native_artifact"])).hexdigest())
        finally:
            service.close()
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            reopened = HIAAgentService(state)
            try:
                self.assertEqual(reopened.call("hia_verify", verification), accepted)
                self.assertEqual(reopened.call("hia_emit", build), emitted)
            finally:
                reopened.close()

    def test_native_slot_receipts_and_failed_rollback_preserve_the_transaction(self):
        from hepta.hia_agent_service import HIAAgentService
        from hepta.hia_agent_store import wire
        from tools.hia_agent_native_qualification import Session, ToolClient, scripted_loop

        state = self.folder / "issued-slot-receipts"
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            service = HIAAgentService(state)
            try:
                session = Session(ToolClient(service.call, validate=False))
                stored_json = service.store.json

                def retain_json(value, kind, *args):
                    self.assertNotIn(kind, ("adoption-receipt", "rollback-receipt"))
                    return stored_json(value, kind, *args)

                with patch.object(service.store, "json", side_effect=retain_json):
                    result = scripted_loop(session, target_slot="issued-slots")
                adopted, rolled = result["adoption"], result["rollback"]
                for kind, issued in (("adoption", adopted), ("rollback", rolled)):
                    record, _, raw = service.store.get_json_with_wire(
                        issued[kind + "_receipt"], kind=kind + "-receipt")
                    self.assertEqual(raw, wire(record))
                    for field in ("active_artifact", "current", "future_calls_only", "previous", "target_slot"):
                        self.assertEqual(record[field], issued[field])
                    self.assertIs(record["in_flight_versions_retained"], True)
                self.assertIs(rolled["past_effects_reversed"], False)

                current = service._slot_snapshot("issued-slots")
                request = session.arguments(target_slot="issued-slots", expected_current=rolled["current"],
                    retained_generation=adopted["current"]["generation"], reason="receipt publication fails")
                with patch.object(NativeAgentIdentity, "rollback_result", side_effect=ValueError("receipt failure")):
                    rejected = service.call("hia_rollback", request)
                self.assertEqual(rejected["status"], "rejected")
                self.assertEqual(service._slot_snapshot("issued-slots"), current)
            finally:
                service.close()
            reopened = HIAAgentService(state)
            try:
                self.assertEqual(reopened._slot_snapshot("issued-slots"), current)
                self.assertEqual(reopened.call("hia_rollback", request), rejected)
            finally:
                reopened.close()

    def test_store_issues_native_artifact_identity_and_reuses_it_without_new_nonces(self):
        from uuid import UUID
        from hepta.hia_agent_store import AgentStore, wire

        data = b"native artifact reference"
        digest = sha256(data).hexdigest()
        a = UUID(bytes=bytes(range(16)))
        b = UUID(bytes=bytes(range(240, 256)))
        expected = {"id": "a-" + a.hex, "sha256": digest, "uri": "hia://artifacts/" + b.hex}
        expected_wire = wire(expected)
        request = packet(30, digest.encode("ascii") + a.bytes + b.bytes)
        self.assertEqual(self.raw(request, len(expected_wire)), (len(expected_wire), expected_wire))
        self.assertEqual(self.raw(request, len(expected_wire) - 1)[0], 0xfffffffe)
        self.assertEqual(self.raw(request[:-1], len(expected_wire))[0], 0xfffffffd)
        self.assertEqual(self.raw(packet(30, b"A" + request[17:]), len(expected_wire))[0], 0xfffffffd)
        root = self.folder / "native-artifact-reference"
        with patch.dict(os.environ, {SELECTOR: str(self.manifest)}):
            store = AgentStore(root)
            try:
                # Legacy file custody consumes a nonce for the temporary file
                # before either of the two public reference observations.
                with patch("hepta.hia_agent_store.uuid.uuid4", side_effect=(UUID(int=1), a, b)) as nonce:
                    self.assertEqual(store.put(data, "input"), expected)
                    self.assertEqual(store.put(data, "input"), expected)
                    self.assertEqual(nonce.call_count, 3)
            finally:
                store.close()
            reopened = AgentStore(root)
            try:
                self.assertEqual(reopened.resolve_uri(expected["uri"]), expected)
                self.assertEqual(reopened.get(expected), (data, {}))
            finally:
                reopened.close()

    def test_artifact_packets_keep_exact_utf8_and_refuse_invalid_scalars(self):
        rng = random.Random(3027)
        boundary = '\x00\x7f\x80\u07ff\u0800\ud7ff\ue000\uffff\U00010000\U0010ffff'
        random_scalars = ''.join(chr(code) for code in rng.choices(
            range(0x110000), k=2048) if not 0xd800 <= code <= 0xdfff)
        for value in ('', boundary, random_scalars, '\U00010000' * 65536):
            self.assertEqual(self.native.artifact_input({'kind': 'utf8', 'text': value}),
                             (value.encode('utf-8'), None))
        for limit in (1, 4096, 8388608):
            self.assertEqual(self.native.artifact_input({'kind': 'path', 'max_bytes': limit}),
                             (None, limit))
        for payload, capacity, code in (
            (b'utf8' + struct.pack('<I', 0xd800), 32, 4294967293),
            (b'utf8' + struct.pack('<I', 0x110000), 32, 4294967293),
            (b'utf8x', 32, 4294967293),
            (b'path' + struct.pack('<Q', 0), 32, 4294967293),
            (b'path' + struct.pack('<Q', 8388609), 32, 4294967293),
            (b'utf8' + struct.pack('<I', 0x10000), 19, 4294967294),
        ):
            status, output = self.raw(packet(19, payload), capacity)
            self.assertEqual((status, output), (code, b'\xa5' * capacity))

    def test_public_artifact_uses_hia_inputs_and_inert_receipts(self):
        from hepta.hia_agent_service import HIAAgentService

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            files = root / 'files'
            files.mkdir()
            path = files / '测量.hepta'
            path.write_bytes(b'\x00\xff\n')
            service = HIAAgentService(root / 'state', artifact_roots=(files,))
            try:
                policy = {'artifact_profile': service.profiles['artifact'],
                          'catalog_sha256': service.catalog_sha256}
                with (patch.dict(os.environ, {SELECTOR: str(self.manifest)}),
                      patch.object(service, '_reference_artifact',
                                   side_effect=AssertionError('reference artifact flow entered'))):
                    for key, source, data in (
                        ('empty', {'kind': 'utf8', 'text': ''}, b''),
                        ('unicode', {'kind': 'utf8', 'text': '雪\x00🧪'}, '雪\x00🧪'.encode()),
                        ('path', {'kind': 'path', 'path': str(path), 'max_bytes': 3,
                                  'expected_sha256': sha256(path.read_bytes()).hexdigest()},
                         path.read_bytes()),
                    ):
                        args = dict(policy, request_key=key, source=source)
                        response = service.call('hia_artifact', args)
                        self.assertEqual(response['status'], 'completed', response)
                        result = response['result']
                        self.assertEqual(result['byte_length'], str(len(data)))
                        self.assertIs(result['content_admitted_as_program'], False)
                        self.assertIs(result['execution_authority_granted'], False)
                        self.assertEqual(service.store.get(result['artifact']), (data, {}))
                        if key == 'path':
                            path.write_bytes(b'new')
                        self.assertEqual(service.call('hia_artifact', args), response)
            finally:
                service.close()

    def test_manifest_selected_rejects_corruption_without_fallback(self):
        bad=self.folder/'bad.json';bad.write_text('{}')
        with patch.dict(os.environ,{SELECTOR:str(bad)}):
            with self.assertRaises(ValueError):uint64('1','epoch')
            with self.assertRaises(ValueError):canonical_digest('a'*64)
        self.assertIsNotNone(installed_agent_identity(str(self.manifest)))

    def test_real_worker_admission_and_response_with_host_predicates_disabled(self):
        from io import BytesIO,StringIO
        from types import SimpleNamespace
        from hepta import hia_agent_worker as worker,hia_agent_store as store
        from hepta.hia_agent_contract import installation_manifest
        identities=installation_manifest()
        from hepta.hia_native_helpers import SCHEMA as BUNDLE_SCHEMA, TARGET, ABI
        bundle=self.folder/'worker-helpers.json'
        bundle.write_text(json.dumps({'schema':BUNDLE_SCHEMA,'target':TARGET,'abi':ABI,
            'helpers':[{'selector':SELECTOR,'manifest_path':self.manifest.name,
                        'manifest_sha256':sha256(self.manifest.read_bytes()).hexdigest()}]}),
            encoding='utf-8')
        bundle_sha256=sha256(bundle.read_bytes()).hexdigest()
        helper_flags=['--native-helpers-manifest',str(bundle),
                      '--expected-native-helpers-sha256',bundle_sha256]
        clean_env={key:value for key,value in os.environ.items()
                   if not (key.startswith('HEPTA_HIA_') and key.endswith('_MANIFEST'))}
        def run(name,tool,digest_override=None):
            state=self.folder/name
            request={'schema':'hia-agent-worker-request-v1','tool':tool,
                'arguments':{'section':'language'},
                'profile_sha256':'a'*64,'catalog_sha256':identities['catalog_sha256']}
            request['request_sha256']=sha256(store.wire(request)).hexdigest() if digest_override is None else digest_override
            output=BytesIO();error=StringIO()
            with patch.object(worker.sys,'stdin',SimpleNamespace(buffer=BytesIO(store.wire(request)))),patch.object(worker.sys,'stdout',SimpleNamespace(buffer=output)),patch.object(worker.sys,'stderr',error):
                code=worker.main(['--state-root',str(state),'--request-json-stdin',*helper_flags])
            return code,json.loads(output.getvalue()),state
        with patch.dict(os.environ,clean_env,clear=True),patch.object(store,'_reference_digest',side_effect=AssertionError('host digest fallback')),patch.object(store,'_reference_uint64',side_effect=AssertionError('host integer fallback')):
            code,report,state=run('real-worker-valid','hia_describe')
            self.assertEqual(code,0);self.assertTrue(report['complete']);self.assertEqual(report['response']['status'],'completed',report)
            self.assertTrue(state.is_dir())
            code,report,state=run('real-worker-invalid','hia_describe','F'*64)
            self.assertEqual(code,0);self.assertEqual(report['response']['error']['code'],'E_HIA_WORKER_IDENTITY')
            self.assertFalse(state.exists())

            # A fresh real worker must not acquire the frozen language or
            # foreign comparison backend merely to describe HIA capabilities.
            import subprocess,sys
            from tests.test_hia_agent_entry import CHILD
            prefix=CHILD.split('from hepta.cli import')[0]
            child='import sys\nsys.path.insert(0,sys.argv[1])\n'+prefix+"from hepta.hia_agent_worker import main\nresult=main(['--state-root',sys.argv[2],'--request-json-stdin','--native-helpers-manifest',sys.argv[3],'--expected-native-helpers-sha256',sys.argv[4]])\nassert not blocked.intersection(sys.modules)\nraise SystemExit(result)\n"
            req={'schema':'hia-agent-worker-request-v1','tool':'hia_describe',
                 'arguments':{'section':'language'},'profile_sha256':'a'*64,
                 'catalog_sha256':identities['catalog_sha256']}
            req['request_sha256']=sha256(store.wire(req)).hexdigest()
            result=subprocess.run([sys.executable,'-I','-S','-B','-c',child,str(ROOT),str(self.folder/'fresh-worker'),str(bundle),bundle_sha256],input=store.wire(req),capture_output=True,timeout=15,cwd=self.folder,
                env={'PATH':'','LANG':'C','LC_ALL':'C'})
            self.assertEqual(result.returncode,0,result.stderr.decode(errors='replace'))
            self.assertEqual(result.stderr,b'')
            self.assertEqual(json.loads(result.stdout)['response']['status'],'completed')
