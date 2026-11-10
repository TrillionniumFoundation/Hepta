"""Actual native Agent scalar identities, independent bytes before native seed."""
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256
import ctypes,json,os,random,struct,tempfile,unittest
from pathlib import Path
from unittest.mock import patch
from hepta.hia_agent_identity_native import SOURCE,SCHEMA,MAGIC,RESULT_MAGIC,NativeAgentIdentity,installed_agent_identity,SELECTOR
from hepta.hia_agent_store import AgentRejected,uint64,canonical_digest
ROOT=Path(__file__).resolve().parents[1]
def packet(kind,value):return struct.pack('<2Q',MAGIC,kind)+value
def expected(valid,value=0):return struct.pack('<3Q',RESULT_MAGIC,valid,value)
def vm(wire,workspace):
 from tools.hia_selfhost_bulk import Body
 from hepta.hia_agent_assembly import assemble_program
 from hepta.hia_program import execute_program
 b=Body(0);owners=[];views=[]
 for size,initial in ((len(wire),wire),(24,b''),(workspace,b'')):
  owner=b.value('buffer','buffer.new',[b.const('usize',size)]);view=b.value('mutbuf','borrow.mut',[owner])
  for i,value in enumerate(initial):
   if value:b.effect('buffer.store',[view,b.const('usize',i),b.const('u8',value)])
  owners.append(owner);views.append(view)
 b.effect('loan.end',[views[0]]);views[0]=b.value('readbuf','borrow.read',[owners[0]])
 code=b.value('u32','call',views,{'function':'f0'});raw=[b.value('u8','buffer.load',[views[1],b.const('usize',i)]) for i in range(24)]
 for view in views:b.effect('loan.end',[view])
 for owner in owners:b.effect('owner.drop',[owner])
 source=('hia-asm.v1 hepta.hia.program.v8 agent_identity_reference\nfn observe() -> (u32,'+','.join(['u8']*24)+') effects(alloc,read,write,trap) entry(b0)\nblock b0()\n'+b.text()+'  ret('+','.join([code,*raw])+')\nend\n'+SOURCE.read_text().split('\n',1)[1])
 row=execute_program(assemble_program(source),'observe',[],max_steps=2000000);assert row['status']=='returned',row
 code,*raw=row['values'];return code,bytes(raw)

def witnesses():
    values=[(packet(0,b'18446744073709551615'),expected(1,(1<<64)-1)),
        (packet(0,b'18446744073709551616'),expected(0)),(packet(1,b'0'*64),expected(1))]
    for wire,result in values:assert vm(wire,0)==(24,result)
    return values

class AgentIdentitySourceTests(unittest.TestCase):
    def test_exact_source_and_complete_VM_bytes_before_any_native(self):
        from tools.generate_hia_agent_identity import document
        from hepta.hia_agent_assembly import render_assembly
        self.assertEqual(SOURCE.read_text(),render_assembly(document()))
        self.assertEqual(len(witnesses()),3)

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
        seed,_=build_seed(cls.folder);compiler=(ROOT/'examples/hia_bootstrap/selfhost.hiaasm').read_bytes()
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
        if result!=24:self.assertEqual(output.raw,b'\xa5'*(capacity+8))
        return result,output.raw[:24]

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
        for wire in [b'',b'0'*15,packet(2,b'0'),packet((1<<64)-1,b''),b'0'*16,packet(0,b'0'*65)]:
            self.assertEqual(self.raw(wire)[0],0xfffffffd)
        self.assertEqual(self.raw(packet(0,b'0'),23)[0],0xfffffffe)
        with self.assertRaises(ValueError):self.native.scalar('1',False)

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
        def run(name,tool,digest_override=None):
            state=self.folder/name
            request={'schema':'hia-agent-worker-request-v1','tool':tool,
                'arguments':{'section':'language'},
                'profile_sha256':'a'*64,'catalog_sha256':identities['catalog_sha256']}
            request['request_sha256']=sha256(store.wire(request)).hexdigest() if digest_override is None else digest_override
            output=BytesIO();error=StringIO()
            with patch.object(worker.sys,'stdin',SimpleNamespace(buffer=BytesIO(store.wire(request)))),patch.object(worker.sys,'stdout',SimpleNamespace(buffer=output)),patch.object(worker.sys,'stderr',error):
                code=worker.main(['--state-root',str(state),'--request-json-stdin'])
            return code,json.loads(output.getvalue()),state
        with patch.dict(os.environ,{SELECTOR:str(self.manifest)}),patch.object(store,'_reference_digest',side_effect=AssertionError('host digest fallback')),patch.object(store,'_reference_uint64',side_effect=AssertionError('host integer fallback')):
            code,report,state=run('real-worker-valid','hia_describe')
            self.assertEqual(code,0);self.assertTrue(report['complete']);self.assertEqual(report['response']['status'],'completed',report)
            self.assertTrue(state.is_dir())
            code,report,state=run('real-worker-invalid','hia_describe','F'*64)
            self.assertEqual(code,0);self.assertEqual(report['response']['error']['code'],'E_HIA_WORKER_IDENTITY')
            self.assertFalse(state.exists())
