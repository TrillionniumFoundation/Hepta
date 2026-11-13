"""First explicit finite native varint experiment on ai395; no SQLite database."""
from pathlib import Path
import ctypes,hashlib,importlib,json,os,resource,sys,time,traceback,unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common,matrix,trace,support
ROOT=support.ROOT
CTX=None
class COracle:
    def __init__(self,version,path,pin):
        actual,raw=common.read(path,1<<20)
        common.require(all(actual[k]==pin[k] for k in ('bytes','sha256','git_blob','identity')),'new C oracle binary pin')
        self.version=version;self.path=Path(path);self.pin=actual
        self.library=ctypes.CDLL(str(path),mode=os.RTLD_LOCAL|os.RTLD_NOW)
        self.get=self.library.hia_reference_get
        self.get.argtypes=[ctypes.c_void_p,ctypes.c_void_p];self.get.restype=ctypes.c_uint
        self.put=self.library.hia_reference_put
        self.put.argtypes=[ctypes.c_void_p,ctypes.c_uint64];self.put.restype=ctypes.c_uint
    def call(self,spec):
        expected=spec['expected']['oracle']
        if expected is None:return {'version':self.version,'called':False}
        if expected['operation']=='get':
            raw=bytes.fromhex(expected['raw_hex']);initial=raw+b'\x5a'*(9-len(raw))+matrix.CANARY
            before=b'\xa5'*8+matrix.CANARY
            source=ctypes.create_string_buffer(initial,len(initial))
            out=ctypes.create_string_buffer(before,len(before))
            alignment=ctypes.addressof(out)%8
            common.require(alignment==0,'C u64 destination alignment')
            count=self.get(source,out)
            return {'version':self.version,'called':True,'operation':'get','returned':count,
                    'value':int.from_bytes(out.raw[:8],'little'),'input_before_hex':initial.hex(),
                    'input_after_hex':source.raw.hex(),'output_before_hex':before.hex(),
                    'output_after_hex':out.raw.hex(),'output_alignment_mod8':alignment}
        before=b'\xa5'*9+matrix.CANARY
        out=ctypes.create_string_buffer(before,len(before))
        value=expected['value'];count=self.put(out,value)
        return {'version':self.version,'called':True,'operation':'put','returned':count,
                'value':value,'output_before_hex':before.hex(),'output_after_hex':out.raw.hex()}
class Context:
    def __init__(self,request,output,spec):
        self.request=request;self.output=output;self.spec=spec;self.label=None;self.method=None
        self.sequence=iter(matrix.specifications(ROOT));self.started=self.returned=0
        self.by_method={x:0 for x in matrix.IDS};self.original=matrix.original_rows(ROOT)
        self.behavior=[];self.secondary=[];self.writer=trace.Writer(output/'trace')
        sys.path.insert(0,str(ROOT/'source-base'))
        import hepta
        hepta.__path__.insert(0,str(ROOT/'candidate/inputs/hepta'))
        from hepta import hia_sqlite_varint_native as bridge
        self.bridge=bridge
        p,b=common.read(spec['image']['path'],1<<20)
        common.require(all(p[k]==spec['image'][k] for k in ('bytes','sha256','git_blob','identity')),'same-owner compiled HIA image')
        self.codec=bridge.NativeSQLiteVarint(b,p['sha256']);self.original_entry=self.codec._entry
        self.oracles=[COracle(v,Path(spec['oracles'][v]['path']),spec['oracles'][v]) for v in matrix.VERSIONS]
        self.installed_entry=self.entry;self.codec._entry=self.installed_entry
    def entry(self,source,size,out,capacity,control,control_size):
        spec=next(self.sequence)
        self.started+=1
        common.require(spec['index']==self.started and self.method==spec['method'] and self.label==spec['label'],
                       'actual native case/order differs from frozen matrix')
        extents=[size,capacity,control_size]
        common.require(all(type(v)is int for v in extents) and 0<=size<=10 and 0<=capacity<=10
            and 0<=control_size<=17,'finite raw extents')
        before=[ctypes.string_at(p,n+64) for p,n in zip((source,out,control),extents)]
        pre={'event':'pre','index':self.started,'method':self.method,'label':self.label,
             'lengths':extents,'buffers_hex':[b.hex() for b in before]}
        wanted_pre,wanted_post=trace.expected_records(spec)
        common.require(pre==wanted_pre,'actual full raw PRE buffers differ')
        self.writer.write(pre)
        post={'event':'post','index':self.started,'actual_returned':False}
        try:
            status=self.original_entry(source,size,out,capacity,control,control_size)
            post.update(actual_returned=True,status=status,
                buffers_hex=[ctypes.string_at(p,n+64).hex() for p,n in zip((source,out,control),extents)])
            post['oracles']=[o.call(spec) for o in self.oracles]
            self.writer.write(post)
            common.require(post==wanted_post,'actual native/C whole POST observation differs')
            self.returned+=1;self.by_method[self.method]+=1
            return status
        except BaseException as e:
            if 'oracles' not in post:
                post['exception_type']=type(e).__module__+'.'+type(e).__qualname__
                try:self.writer.write(post)
                except BaseException as second:self.secondary.append(type(second).__name__+': '+str(second)[:256])
            raise
    def raw(self,label,source,output,cmd):
        self.label=label
        arrays=[ctypes.create_string_buffer(x+matrix.CANARY,len(x)+64) for x in (source,output,cmd)]
        return self.entry(arrays[0],len(source),arrays[1],len(output),arrays[2],len(cmd))
    def full_finished(self):
        try:next(self.sequence)
        except StopIteration:pass
        else:raise RuntimeError('not all finite native cases executed')
        common.require(self.started==self.returned==sum(matrix.COUNTS) and list(self.by_method.values())==list(matrix.COUNTS),
                       'actual finite native return denominator')
class SQLiteVarintNativeTests(unittest.TestCase):
    def setUp(self):
        CTX.method=self.id()
    def test_01_original_1618_complete_VM_buffers(self):
        for i,r in enumerate(CTX.original,1):
            source,output,command=(bytes.fromhex(r[k]) for k in ('source_before_hex','output_before_hex','workspace_before_hex'))
            self.assertEqual(CTX.raw('vm-%04d'%i,source,output,command),r['status'])
    def test_02_all_65536_initialized_two_byte_prefixes(self):
        for prefix in range(65536):
            raw=prefix.to_bytes(2,'big')+b'\x80'*6+b'\x55'
            CTX.raw('prefix-%04x'%prefix,raw,b'\xa5'*8,matrix.command(1))
    def test_03_fixed_4096_full_u64_roundtrips(self):
        for i,v in enumerate(matrix.random_values()):
            CTX.raw('random-%04d-put'%i,v.to_bytes(8,'little'),b'\xa5'*9,matrix.command(2))
            CTX.raw('random-%04d-get'%i,matrix.encode(v),b'\xa5'*8,matrix.command(1))
    def test_04_public_bridge_boundaries_and_nonminimal(self):
        for i,v in enumerate(matrix.boundary_values()):
            raw=matrix.encode(v)
            CTX.label='public-%03d-encode'%i
            self.assertEqual(CTX.codec.encode(v),raw)
            CTX.label='public-%03d-decode'%i
            self.assertEqual(CTX.codec.decode_from(b'prefix'+raw+b'tail',6),(v,len(raw)))
            target=bytearray(b'prefix'+b'\x5a'*16+b'tail');before=bytes(target)
            CTX.label='public-%03d-into'%i
            self.assertEqual(CTX.codec.encode_into(v,target,6,16),len(raw))
            self.assertEqual(bytes(target),before[:6]+raw+before[6+len(raw):])
        for size in range(2,10):
            for terminal in (0,1,127):
                raw=b'\x80'*(size-1)+bytes([terminal]);CTX.label='nonminimal-%d-%d'%(size,terminal)
                self.assertEqual(CTX.codec.decode_from(b'prefix'+raw+b'tail',6),matrix.decode(raw))
    def test_05_public_truncation_and_capacity(self):
        for size in range(9):
            for b in (128,255):
                CTX.label='truncated-%d-%d'%(size,b)
                with self.assertRaises(CTX.bridge.SQLiteVarintTruncated):CTX.codec.decode_from(bytes([b])*size)
        for count in range(1,10):
            value=0 if count==1 else 1<<(7*(count-1))
            expected=matrix.encode(value)
            for cap in range(10):
                target=bytearray(b'prefix'+b'\x5a'*19+b'suffix');before=bytes(target)
                CTX.label='capacity-%d-%d'%(count,cap)
                if cap<count:
                    with self.assertRaises(CTX.bridge.SQLiteVarintCapacity):CTX.codec.encode_into(value,target,6,cap)
                    self.assertEqual(bytes(target),before)
                else:
                    self.assertEqual(CTX.codec.encode_into(value,target,6,cap),count)
                    self.assertEqual(bytes(target),before[:6]+expected+before[6+count:])
    def test_06_foreign_types_exception_identity_and_canaries(self):
        class I(int):pass
        class B(bytes):pass
        class A(bytearray):pass
        codec=CTX.codec;start=CTX.started
        cases=[]
        for value in (-1,1<<64,True,1.0,None,I(1)):
            cases.append(('encode-type',ValueError,lambda value=value:codec.encode(value)))
        for value in (None,'x',memoryview(b'x'),B(b'x')):
            cases.append(('decode-type',TypeError,lambda value=value:codec.decode_from(value)))
        for value in (True,1.0,I(0)):
            cases.append(('offset-type',TypeError,lambda value=value:codec.decode_from(b'\1',value)))
        for value in (-1,2):
            cases.append(('offset-range',ValueError,lambda value=value:codec.decode_from(b'\1',value)))
        for value in (b'xx',None,A(b'xx')):
            cases.append(('target-type',TypeError,lambda value=value:codec.encode_into(1,value)))
        for value in (-1,3,True,1.0):
            cases.append(('capacity-type',ValueError,lambda value=value:codec.encode_into(1,bytearray(2),0,value)))
        self.assertEqual(len(cases),22)
        for number,(label,error,call) in enumerate(cases,1):
            with self.assertRaises(error):call()
            CTX.behavior.append({'kind':'early-refusal','ordinal':number,'label':label,'exception_type':error.__name__})
        self.assertEqual(CTX.started,start)
        target=bytearray(b'\x5a'*16);observed_entry=codec._entry
        try:
            for error in (MemoryError('native leaf'),KeyboardInterrupt('native leaf'),SystemExit('native leaf')):
                def fail(*args,error=error):raise error
                codec._entry=fail
                with self.assertRaises(type(error)) as caught:codec.encode_into(128,target,2)
                self.assertIs(caught.exception,error);self.assertEqual(target,bytearray(b'\x5a'*16))
                CTX.behavior.append({'kind':'exception-identity','type':type(error).__name__,'same_object':True})
            for status in (True,0,10,matrix.PROTOCOL):
                codec._entry=lambda *args,status=status:status
                with self.assertRaises(CTX.bridge.SQLiteVarintProtocolError):codec.encode(1)
                CTX.behavior.append({'kind':'invalid-return','type':type(status).__name__,'value':status})
        finally:codec._entry=observed_entry
        self.assertEqual(CTX.started,start)
        for kind in ('source','command','tail'):
            CTX.label='caught-canary-'+kind
            def mutate(*args,kind=kind):
                status=observed_entry(*args)
                index=0 if kind=='source' else 4 if kind=='command' else 2
                offset=args[3] if kind=='tail' else 0
                ctypes.memset(ctypes.cast(args[index],ctypes.c_void_p).value+offset,0xff,1)
                return status
            codec._entry=mutate
            try:
                with self.assertRaises(CTX.bridge.SQLiteVarintProtocolError):codec.encode_into(128,target,2)
                self.assertEqual(target,bytearray(b'\x5a'*16))
                CTX.behavior.append({'kind':'post-native-canary-refusal','buffer':kind,'target_unchanged':True})
            finally:codec._entry=observed_entry
        self.assertEqual(CTX.started-start,3)
    def test_07_two_original_C_oracles_and_sources(self):
        self.assertEqual(len(support.inspect_official_oracles()),2)
        for oracle in CTX.oracles:
            pin,_=common.read(oracle.path,1<<20)
            self.assertEqual(pin,oracle.pin)
    def test_08_original_caps_and_source_population(self):
        caps=support.inspect_caps_and_retained()
        self.assertEqual(caps['existing_persistence_methods_preserved_not_executed'],59)
        self.assertEqual(len(CTX.original),1618)
SQLiteVarintNativeTests.__module__='tests.hia_sqlite_varint_native_finite_r2'
class Result(unittest.TextTestResult):
    def __init__(self,*a,**k):
        super().__init__(*a,**k);self.actual=[];self.success=[];self.failure_ids=[];self.error_ids=[]
    def startTest(self,test):self.actual.append(test.id());super().startTest(test)
    def addSuccess(self,test):self.success.append(test.id());super().addSuccess(test)
    def addFailure(self,test,err):self.failure_ids.append(test.id());super().addFailure(test,err)
    def addError(self,test,err):self.error_ids.append(test.id());super().addError(test,err)
def main():
    global CTX
    request_path=Path(sys.argv[1]);expected_sha=sys.argv[2]
    pin,raw=common.read(request_path)
    common.require(pin['sha256']==expected_sha,'finite child request SHA')
    request=json.loads(raw);output=Path(request['output'])/'native'
    common.require(output.is_dir(),'worker-created native directory')
    report={'schema':'hia.sqlite.varint.finite-native-result.v2','status':'HOLD','expected_ids':list(matrix.IDS),
            'started_ids':[],'actual_ids':[],'success_ids':[],'denied_effects':[],
            'exception':None,'secondary_errors':[],'native_returns':0,'database_opened':False,
            'network_used':False,'source8_reexecuted':False,'matching_cold_qualification':False}
    started=time.monotonic_ns();index_complete=False
    try:
        report['runtime']=support.runtime(request)
        report['inputs_before']=support.input_records(request)
        report['source_before']=support.source_records(request)
        _,spec=support.read_json(output/'NATIVE-INPUTS.json')
        CTX=Context(request,output,spec)
        own_maps={v['path']:v for v in spec['oracles'].values()}
        report['mapped_files_before']=support.loaded_file_maps(request,own_maps,CTX.codec,CTX.original_entry,
            CTX.installed_entry,spec['image'],output/'mapping-before')
        resource.setrlimit(resource.RLIMIT_CORE,(0,0))
        resource.setrlimit(resource.RLIMIT_CPU,(180,180))
        resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
        resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20))
        resource.setrlimit(resource.RLIMIT_FSIZE,(4<<20,4<<20))
        forbidden=('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty','pty.spawn','mmap.__new__','socket.','sqlite3.connect','ctypes.dlopen','ctypes.dlsym')
        def audit(event,args):
            if any(event==x or event.startswith(x) for x in forbidden):
                report['denied_effects'].append(event);raise RuntimeError('finite child forbidden effect: '+event)
        sys.addaudithook(audit)
        common.require(not any(n.startswith(('hepta.hia_program','hepta.hia_agent_assembly','generate_hia_')) for n in sys.modules),
            'host assembler/VM/compiler module loaded in native child')
        suite=unittest.TestSuite(SQLiteVarintNativeTests(n) for n in matrix.NAMES)
        report['loaded_ids']=[t.id() for t in suite]
        common.require(report['loaded_ids']==list(matrix.IDS),'exact eight native method order')
        with (output/'unittest.log').open('x',encoding='utf-8') as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
        report.update(actual_ids=result.actual,success_ids=result.success,tests_run=result.testsRun,
            failures=result.failure_ids,errors=result.error_ids,skipped=[(x.id(),why) for x,why in result.skipped],
            expected_failures=[x.id() for x,_ in result.expectedFailures],
            unexpected_successes=[x.id() for x in result.unexpectedSuccesses],
            native_returns=CTX.returned,actual_native_starts=CTX.started,
            native_counts=CTX.by_method,bridge_control_observations=CTX.behavior)
        common.require(result.actual==result.success==list(matrix.IDS) and result.testsRun==8
            and not(result.failure_ids or result.error_ids or result.skipped or result.expectedFailures or result.unexpectedSuccesses),
            'whole finite native method population did not pass')
        CTX.full_finished();CTX.writer.finish(True);index_complete=True
        _,expected=support.read_json(ROOT/'EXPECTED-MATRIX.json')
        report['full_trace_readback']=trace.inspect(ROOT,output/'trace',expected)
        report['imports']=support.current_imports(request)
        report['mapped_files_after']=support.loaded_file_maps(request,own_maps,CTX.codec,CTX.original_entry,
            CTX.installed_entry,spec['image'],output/'mapping-after')
        common.require(report['mapped_files_before']['files']==report['mapped_files_after']['files'],
                       'trusted mapped file set changed after poison')
        common.require(report['mapped_files_before']['image_binding']==report['mapped_files_after']['image_binding'],
                       'current HIA image object/entry/segment changed after finite calls')
        report['inputs_after']=support.input_records(request)
        report['source_after']=support.source_records(request)
        common.require(report['inputs_after']==report['inputs_before'] and report['source_after']==report['source_before']
            and report['denied_effects']==[] and CTX.secondary==[],'finite inputs/source stability or audit failure')
        report['status']='FINITE_NATIVE_AND_TWO_C_ORACLES_PASS_ONLY'
    except BaseException as e:
        report['status']='HOLD';report['exception']=type(e).__module__+'.'+type(e).__qualname__+': '+str(e)[:1024]
        report['traceback']=traceback.format_exc()
    finally:
        if CTX is not None and not CTX.writer.closed:
            try:CTX.writer.finish(False)
            except BaseException as e:report['secondary_errors'].append(type(e).__name__+': '+str(e)[:256])
        if CTX is not None:
            report['native_returns']=CTX.returned;report['actual_native_starts']=CTX.started
            report['bridge_control_observations']=CTX.behavior
        report['elapsed_ns']=time.monotonic_ns()-started
        if report['exception'] is not None or report['secondary_errors']:report['status']='HOLD'
        common.create(output/'REPORT.json',report)
    return 0 if report['status']=='FINITE_NATIVE_AND_TWO_C_ORACLES_PASS_ONLY' and report['exception'] is None and not report['secondary_errors'] else 1
if __name__=='__main__':raise SystemExit(main())
