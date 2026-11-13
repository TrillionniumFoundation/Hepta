"""Original ten WAL methods with one actual HIA entry and two separately built C oracles."""
from pathlib import Path
import ctypes,hashlib,importlib,importlib.util,json,mmap,os,resource,socket,subprocess,sys,time,traceback,unittest
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
        self.checksum=self.library.oracle_checksum
        self.checksum.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
        self.checksum.restype=ctypes.c_int
        self.header=self.library.oracle_header
        self.header.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_void_p];self.header.restype=ctypes.c_int
        self.frame=self.library.oracle_frame
        self.frame.argtypes=[ctypes.c_void_p,ctypes.c_size_t,ctypes.c_int,ctypes.c_uint32,
            ctypes.c_uint32,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_uint32,ctypes.c_void_p]
        self.frame.restype=ctypes.c_int
    def call(self,spec):
        expected=spec['expected']['oracle']
        if expected is None:return {'version':self.version,'called':False,'reason':'outside_original_C_and_HIA_transport_domain'}
        raw=bytes.fromhex(spec['source_hex']);cmd=bytes.fromhex(spec['command_hex'])
        common.require(len(cmd)==64,'C domain is checked before ctypes conversion')
        magic,op,order,s0,s1,page,salt0,salt1=fields=__import__('struct').unpack('<8Q',cmd)
        common.require(magic==matrix.MAGIC and all(type(x)is int for x in fields)
            and order in (0,1) and all(0<=x<=0xffffffff for x in (s0,s1,page,salt0,salt1)),
            'no ctypes integer truncation in original C domain')
        if expected['operation']=='checksum':
            common.require(op==1 and 8<=len(raw)<=65536 and len(raw)%8==0 and page==salt0==salt1==0,'C checksum safe domain')
            count=2
        elif expected['operation']=='header':
            common.require(op==2 and len(raw)==32 and order==s0==s1==page==salt0==salt1==0,'C header safe domain');count=12
        else:
            common.require(expected['operation']=='frame' and op==3 and matrix.valid_page(page)
                and len(raw)==page+24,'C frame safe domain');count=4
        before_source=raw+matrix.CANARY;before=b'\xa5'*(count*4)+matrix.CANARY
        source=ctypes.create_string_buffer(before_source,len(before_source))
        out=ctypes.create_string_buffer(before,len(before))
        sa,oa=ctypes.addressof(source)%4,ctypes.addressof(out)%4
        common.require(sa==oa==0,'C u32-buffer actual alignment')
        if op==1:rc=self.checksum(source,len(raw),order,s0,s1,out)
        elif op==2:rc=self.header(source,len(raw),out)
        else:rc=self.frame(source,len(raw),order,page,s0,s1,salt0,salt1,out)
        observed=out.raw;words=[int.from_bytes(observed[i:i+4],'little') for i in range(0,count*4,4)]
        record={'version':self.version,'called':True,'operation':expected['operation'],
                'returned':rc,'seed_before':[s0,s1] if op!=2 else [0,0],'output_words':words,
                'input_before_hex':before_source.hex(),'input_after_hex':source.raw.hex(),
                'output_before_hex':before.hex(),'output_after_hex':observed.hex(),
                'input_alignment_mod4':sa,'output_alignment_mod4':oa}
        # Preserve actual raw state before independently deriving the HIA refusal projection.
        record['derived_projection']=matrix.project_oracle(spec,rc,words)
        return record
class Context:
    def __init__(self,request,output,spec):
        self.request=request;self.output=output;self.spec=spec
        self.sequence=iter(matrix.specifications(ROOT));self.started=self.returned=0
        self.by_method={x:0 for x in matrix.IDS};self.secondary=[];self.method=None
        self.writer=trace.Writer(output/'trace');self.backend=None
        sys.path.insert(0,request['source_root'])
        import hepta,tools,tests
        hepta.__path__.insert(0,str(ROOT/'candidate/inputs/hepta'))
        tools.__path__=[str(ROOT/'candidate/inputs/tools'),*list(tools.__path__)]
        tests.__path__.insert(0,str(ROOT/'candidate/inputs/tests'))
        from hepta import hia_sqlite_wal_native as bridge
        self.bridge=bridge
        p,b=common.read(spec['image']['path'],1<<20)
        common.require(all(p[k]==spec['image'][k] for k in ('bytes','sha256','git_blob','identity')),'same-owner generated HIA image')
        self.codec=bridge.NativeSQLiteWal(b,p['sha256']);self.original_entry=self.codec._entry
        self.oracles=[COracle(v,Path(spec['oracles'][v]['path']),spec['oracles'][v]) for v in matrix.VERSIONS]
        self.installed_entry=self.entry;self.codec._entry=self.installed_entry
    def entry(self,source,size,out,capacity,control,control_size):
        spec=next(self.sequence);self.started+=1
        common.require(self.backend is not None and spec['index']==self.started
            and self.method==self.backend.label==spec['method'],'original native method and ordered call')
        extents=[size,capacity,control_size]
        common.require(all(type(x)is int for x in extents) and 0<=size<=65560
            and 0<=capacity<=33 and 0<=control_size<=65,'finite original raw extents')
        pointers=(source,out,control)
        before=[ctypes.string_at(p,n+64) for p,n in zip(pointers,extents)]
        pre={'event':'pre','index':self.started,'method':self.method,'label':spec['label'],
             'lengths':extents,'buffers_hex':[b.hex() for b in before]}
        wanted_pre,wanted_post=trace.expected_records(spec)
        common.require(matrix.wire(pre)==matrix.wire(wanted_pre),'actual complete original PRE differs')
        self.writer.write(pre);post={'event':'post','index':self.started,'actual_returned':False};written=False
        try:
            status=self.original_entry(source,size,out,capacity,control,control_size)
            post.update(actual_returned=True,status=status,
                buffers_hex=[ctypes.string_at(p,n+64).hex() for p,n in zip(pointers,extents)],oracles=[])
            for oracle in self.oracles:post['oracles'].append(oracle.call(spec))
            self.writer.write(post);written=True
            common.require(matrix.wire(post)==matrix.wire(wanted_post),'actual HIA/C full POST and seed projection differ')
            self.returned+=1;self.by_method[self.method]+=1
            return status
        except BaseException as exc:
            if not written:
                post['exception_type']=type(exc).__module__+'.'+type(exc).__qualname__
                try:self.writer.write(post)
                except BaseException as second:self.secondary.append(type(second).__name__+': '+str(second)[:256])
            raise
    def full_finished(self):
        try:next(self.sequence)
        except StopIteration:pass
        else:raise RuntimeError('missing original native calls')
        common.require(self.started==self.returned==238 and list(self.by_method.values())==list(matrix.COUNTS),
                       'complete original native denominator')
class NativeImage:
    """Substitutes only the original VM transport class; all ten methods stay byte-exact."""
    def __init__(self,program):
        common.require(CTX.backend is None,'single original setUpClass backend')
        _,expected=support.read_json(Path(CTX.request['output'])/'source-generation/PROGRAM.json')
        common.require(program.as_dict()==expected,'class verified program differs from actual compiler source')
        self.program=program;self.calls=[];self.label='unlabelled';CTX.backend=self
    def raw(self,source,output,control):
        arrays=[ctypes.create_string_buffer(b+matrix.CANARY,len(b)+64) for b in (source,output,control)]
        status=CTX.installed_entry(arrays[0],len(source),arrays[1],len(output),arrays[2],len(control))
        return status,arrays[1].raw[:len(output)],arrays[2].raw[:len(control)]
    def _entry(self,s,n,o,m,w,k):return CTX.installed_entry(s,n,o,m,w,k)
class Result(unittest.TextTestResult):
    def __init__(self,*a,**k):
        super().__init__(*a,**k);self.actual=[];self.success=[];self.failure_ids=[];self.error_ids=[]
    def startTest(self,test):
        CTX.method=test.id();self.actual.append(test.id());super().startTest(test)
    def addSuccess(self,test):self.success.append(test.id());super().addSuccess(test)
    def addFailure(self,test,err):self.failure_ids.append(test.id());super().addFailure(test,err)
    def addError(self,test,err):self.error_ids.append(test.id());super().addError(test,err)
def main():
    global CTX
    path=Path(sys.argv[1]);pin,raw=common.read(path)
    common.require(path==ROOT/'REQUEST.json' and pin['sha256']==sys.argv[2],'exact WAL finite child request')
    request=json.loads(raw);output=Path(request['output'])/'native'
    common.require(output.is_dir() and dict(os.environ)==request['environment']
        and 'HEPTA_SQLITE_WAL_SOURCE_EVIDENCE' not in os.environ,'new native-only output/environment')
    report={'schema':'hia.sqlite.wal.native-result.v1','status':'HOLD','expected_ids':list(matrix.IDS),
            'started_ids':[],'actual_ids':[],'success_ids':[],'denied_effects':[],
            'exception':None,'secondary_errors':[],'native_returns':0,'database_opened':False,
            'network_used':False,'source10_VM_reexecuted':False,'matching_cold_qualification':False,
            'backend':'NativeImage with original 10 unchanged method bodies'}
    started=time.monotonic_ns()
    try:
        report['runtime']=support.runtime(request)
        report['inputs_before']=support.input_records(request);report['source_before']=support.source_records(request)
        _,spec=support.read_json(output/'NATIVE-INPUTS.json');CTX=Context(request,output,spec)
        own_maps={v['path']:v for v in spec['oracles'].values()}
        resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_CPU,(180,180))
        resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
        resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20));resource.setrlimit(resource.RLIMIT_FSIZE,(4<<20,4<<20))
        # Load standard effect modules before denying any later subprocess/library/socket activity.
        forbidden=('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty',
                   'pty.spawn','mmap.__new__','socket.','sqlite3.connect','ctypes.dlopen','ctypes.dlsym')
        def audit(event,args):
            if any(event==x or event.startswith(x) for x in forbidden):
                report['denied_effects'].append(event);raise RuntimeError('finite child forbidden effect: '+event)
        sys.addaudithook(audit)
        runtime=importlib.import_module('hepta.hia_program_runtime')
        def forbidden_VM(*args,**kwargs):
            report['denied_effects'].append('hepta.hia_program_runtime._Machine')
            raise RuntimeError('VM execution forbidden in this native request')
        runtime._Machine=forbidden_VM
        module=importlib.import_module('tests.test_hia_sqlite_wal_source')
        common.require(module.EXPECTED_NAMES==matrix.NAMES and module._Machine is forbidden_VM,
                       'exact original test module and explicit VM poison')
        original_VM=module.VMImage;module.VMImage=NativeImage;module._Machine=forbidden_VM
        report['mapped_files_before']=support.loaded_file_maps(request,own_maps,CTX.codec,CTX.original_entry,
            CTX.installed_entry,spec['image'],output/'mapping-before')
        suite=unittest.TestSuite(module.SQLiteWalSourceTests(name) for name in matrix.NAMES)
        report['loaded_ids']=[x.id() for x in suite]
        common.require(report['loaded_ids']==list(matrix.IDS),'original ten IDs/order unchanged')
        with (output/'unittest.log').open('x',encoding='utf-8') as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
        report.update(actual_ids=result.actual,success_ids=result.success,tests_run=result.testsRun,
            failures=result.failure_ids,errors=result.error_ids,skipped=[(x.id(),why) for x,why in result.skipped],
            expected_failures=[x.id() for x,_ in result.expectedFailures],
            unexpected_successes=[x.id() for x in result.unexpectedSuccesses],
            native_returns=CTX.returned,actual_native_starts=CTX.started,native_counts=CTX.by_method)
        common.require(result.actual==result.success==list(matrix.IDS) and result.testsRun==10
            and not(result.failure_ids or result.error_ids or result.skipped or result.expectedFailures or result.unexpectedSuccesses),
            'complete original ten methods did not pass')
        common.require(module.VMImage is NativeImage and module._Machine is runtime._Machine is forbidden_VM
            and CTX.backend.calls==[],'native transport replacement or VM poison changed')
        assembly=common.read(Path(request['output'])/'source-generation/sqlite_wal.hiaasm',1<<20)[1]
        _,document=support.read_json(Path(request['output'])/'source-generation/CORE.json')
        common.require(module.SQLiteWalSourceTests.assembly.encode()==assembly
            and module.SQLiteWalSourceTests.document==document,'new setup source exactly matches actual compiled input')
        CTX.full_finished();CTX.writer.finish(True)
        _,expected=support.read_json(ROOT/'EXPECTED-MATRIX.json')
        report['full_trace_readback']=trace.inspect(ROOT,output/'trace',expected)
        report['imports']=support.current_imports(request)
        report['mapped_files_after']=support.loaded_file_maps(request,own_maps,CTX.codec,CTX.original_entry,
            CTX.installed_entry,spec['image'],output/'mapping-after')
        common.require(report['mapped_files_before']['files']==report['mapped_files_after']['files']
            and report['mapped_files_before']['image_binding']==report['mapped_files_after']['image_binding'],
            'bound image object/entry/maps or trusted file set changed')
        report['inputs_after']=support.input_records(request);report['source_after']=support.source_records(request)
        common.require(report['inputs_after']==report['inputs_before'] and report['source_after']==report['source_before']
            and report['denied_effects']==[] and CTX.secondary==[],'finite inputs or denied effect')
        report['status']='FINITE_NATIVE_AND_TWO_C_ORACLES_PASS_ONLY'
    except BaseException as exc:
        report['status']='HOLD';report['exception']=type(exc).__module__+'.'+type(exc).__qualname__+': '+str(exc)[:1024]
        report['traceback']=traceback.format_exc()
    finally:
        if CTX is not None and not CTX.writer.closed:
            try:CTX.writer.finish(False)
            except BaseException as exc:report['secondary_errors'].append(type(exc).__name__+': '+str(exc)[:256])
        if CTX is not None:
            report['native_returns']=CTX.returned;report['actual_native_starts']=CTX.started
        report['elapsed_ns']=time.monotonic_ns()-started
        if report['exception'] is not None or report['secondary_errors']:report['status']='HOLD'
        common.create(output/'REPORT.json',report)
    return 0 if report['status']=='FINITE_NATIVE_AND_TWO_C_ORACLES_PASS_ONLY' and report['exception'] is None and not report['secondary_errors'] else 1
if __name__=='__main__':raise SystemExit(main())
