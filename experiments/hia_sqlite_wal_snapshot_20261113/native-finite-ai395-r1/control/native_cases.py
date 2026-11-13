"""One actual HIA image, original12 bodies/608 calls, and separate full-page cases."""
from pathlib import Path
import ctypes,hashlib,importlib,importlib.util,json,mmap,os,resource,socket,subprocess,sys,time,traceback,unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
import common,matrix,model,trace,support
ROOT=support.ROOT
CTX=None

class COracle:
    def __init__(self,version,pin):
        actual,_=common.read(pin['path'],1<<20)
        common.require(all(actual[k]==pin[k]for k in ('bytes','sha256','git_blob','identity')),'new complete C image')
        self.version=version;self.pin=actual
        self.library=ctypes.CDLL(pin['path'],mode=os.RTLD_LOCAL|os.RTLD_NOW)
        self.function=self.library.oracle_wal_recover_find
        self.function.argtypes=[ctypes.c_void_p,ctypes.c_uint64,ctypes.c_uint64,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint64]
        self.function.restype=ctypes.c_uint32;self.started=0;self.returned=0
    def call(self,spec,actual_view):
        common.require(type(actual_view)is bytes and actual_view==spec['view'] and len(actual_view)<=8<<20
            and type(spec['target'])is int and 0<=spec['target']<=0xffffffff,'frozen finite C domain before ctypes')
        wanted_pre,wanted_post=matrix.oracle_records(spec,self.version)
        n=len(actual_view);read_words=2*(n//536+2)
        before=[actual_view+matrix.CANARY,b'\xa5'*256+matrix.CANARY,b'\xa5'*(read_words*8)+matrix.CANARY]
        arrays=[ctypes.create_string_buffer(b,len(b))for b in before]
        alignment=[ctypes.addressof(a)%8 for a in arrays[1:]]
        common.require(alignment==[0,0],'C actual u64 alignment')
        pre={'event':'pre','drive_index':spec['index'],'method':spec['method'],'label':spec['label'],
             'version':self.version,'target':spec['target'],'lengths':[n,256,read_words*8],
             'alignment_mod8':alignment,'buffers_hex':[a.raw.hex()for a in arrays]}
        CTX.c_writer.write(pre)
        common.require(matrix.wire(pre)==matrix.wire(wanted_pre),'actual C complete PRE differs')
        post={'event':'post','drive_index':spec['index'],'version':self.version,'actual_returned':False};written=False
        try:
            self.started+=1
            rc=self.function(arrays[0],n,spec['target'],arrays[1],arrays[2],read_words)
            self.returned+=1
            words=list(__import__('struct').unpack('<32Q',arrays[1].raw[:256]))
            post.update(actual_returned=True,adapter_return=rc,raw_words=words,buffers_hex=[a.raw.hex()for a in arrays])
            # All raw C words/read pairs/source/canaries reach disk before either
            # exact comparison or the separate pager-domain projection can raise.
            CTX.c_writer.write(post);written=True
            common.require(matrix.wire(post)==matrix.wire(wanted_post),'whole raw C return/buffers/read sequence differs')
            projection=model.c_projection(words,actual_view,spec['target'],spec['base_size'],spec['base_pages'])
            return {'version':self.version,'raw_words':words,'raw_trace_retained_before_projection':True,
                    'projection':projection}
        except BaseException as exc:
            if not written:
                post['exception_type']=type(exc).__module__+'.'+type(exc).__qualname__
                post['buffers_hex']=[a.raw.hex()for a in arrays]
                try:CTX.c_writer.write(post)
                except BaseException as second:CTX.secondary.append('C failure record: '+type(second).__name__+': '+str(second)[:256])
            raise

class Context:
    def __init__(self,request,output,spec):
        self.request=request;self.output=output;self.spec=spec;self.method=None;self.backend=None
        self.started=0;self.returned=0;self.validated=0;self.by_method={x:0 for x in matrix.IDS}
        self.sequence=iter(matrix.hia_calls(ROOT));self.drive_sequence=iter(matrix.drives())
        self.drives=[];self.secondary=[];self.drive_active=False
        budget=trace.Budget();(output/'trace').mkdir(mode=0o700)
        self.hia_writer=trace.Writer(output/'trace/hia','hia',budget)
        self.c_writer=trace.Writer(output/'trace/C','C',budget)
        sys.path.insert(0,request['source_root'])
        import hepta,tools,tests
        hepta.__path__.insert(0,str(ROOT/'candidate/inputs/hepta'))
        tools.__path__=[str(ROOT/'candidate/inputs/tools'),*list(tools.__path__)]
        tests.__path__.insert(0,str(ROOT/'candidate/inputs/tests'))
        from hepta import hia_sqlite_wal_snapshot_native as bridge
        self.bridge=bridge
        pin,image=common.read(spec['image']['path'],1<<20)
        common.require(all(pin[k]==spec['image'][k]for k in ('bytes','sha256','git_blob','identity')),'exact actual HIA image')
        self.codec=bridge.NativeSQLiteWalSnapshot(image,pin['sha256']);self.original_entry=self.codec._entry
        self.oracles=[COracle(v,spec['oracles'][v])for v in matrix.VERSIONS]
        self.installed_entry=self.entry;self.codec._entry=self.installed_entry
    def entry(self,s,n,o,m,w,k):
        expected=next(self.sequence)
        common.require(self.backend is not None and self.method==self.backend.label==expected['case']
            and expected['index']==self.validated+1,'fixed ordered actual HIA case')
        lengths=[n,m,k]
        common.require(all(type(x)is int for x in lengths) and 0<=n<=65576 and m==128 and k==256,'actual HIA extents')
        before=[ctypes.string_at(p,length+64)for p,length in zip((s,o,w),lengths)]
        pre={'event':'pre','index':expected['index'],'method':self.method,'population':expected['population'],
             'lengths':lengths,'buffers_hex':[b.hex()for b in before]}
        wanted_pre,wanted_post=matrix.hia_records(expected)
        self.hia_writer.write(pre)
        common.require(matrix.wire(pre)==matrix.wire(wanted_pre),'actual HIA complete PRE differs')
        post={'event':'post','index':expected['index'],'actual_returned':False};written=False
        try:
            self.started+=1;status=self.original_entry(s,n,o,m,w,k);self.returned+=1
            after=[ctypes.string_at(p,length+64)for p,length in zip((s,o,w),lengths)]
            post.update(actual_returned=True,status=status,buffers_hex=[b.hex()for b in after])
            self.hia_writer.write(post);written=True
            common.require(matrix.wire(post)==matrix.wire(wanted_post),'actual HIA full output/state/canary differs')
            self.validated+=1;self.by_method[self.method]+=1
            if expected['population']=='original12':
                # Keep original test09's real loop over all already-observed
                # bounded spans; the native replacement does not make it empty.
                record={'case':self.method,'actual_returned':True,'status':status}
                for name,b,a in zip(('source','output','state'),before,after):
                    record[name+'_before_hex']=b[:-64].hex();record[name+'_after_hex']=a[:-64].hex()
                self.backend.calls.append(record)
            return status
        except BaseException as exc:
            if not written:
                post['exception_type']=type(exc).__module__+'.'+type(exc).__qualname__
                post['buffers_hex']=[ctypes.string_at(p,length+64).hex()for p,length in zip((s,o,w),lengths)]
                try:self.hia_writer.write(post)
                except BaseException as second:self.secondary.append('HIA failure record: '+type(second).__name__+': '+str(second)[:256])
            raise
    def begin_drive(self,raw,kwargs):
        common.require(not self.drive_active,'no unrelated or recursive finite drive')
        spec=next(self.drive_sequence)
        common.require(self.method==spec['method'] and type(raw)is bytes and raw==spec['raw'],'actual finite whole WAL input order')
        snapshot=kwargs.get('snapshot');page=kwargs.get('page')
        common.require((page is None and spec['target']==0)or(type(page)is int and page==spec['target']),'frozen drive target')
        if spec['snapshot']is None:
            common.require(snapshot is None and kwargs.get('base_page_size',512)==spec['base_size']
                and kwargs.get('base_page_count',9)==spec['base_pages'],'frozen scan geometry')
        else:
            common.require(type(snapshot)is self.bridge.WalSnapshot
                and all(getattr(snapshot,k)==v for k,v in model.snapshot_fields(spec['snapshot']).items()),
                'actual captured immutable snapshot differs')
        self.drive_active=True
        return spec
    def end_drive(self,spec,raw,result,error):
        record=matrix.metadata(spec);record['actual_C']=[]
        record['actual_native_first']=spec.get('actual_native_first')
        record['actual_native_last']=self.validated
        if error is not None:
            record['actual_exception']={'type':type(error).__module__+'.'+type(error).__qualname__,
                                        'status':getattr(error,'status',None)}
        else:
            value,reads=result
            record['actual_exception']=None
            record['actual_result']=(model.snapshot_fields({k:getattr(value,k)for k in
                ('page_size','database_pages','committed_frame','committed_end_offset','valid_frames_scanned','stop_reason')})
                if spec['target']==0 else {k:getattr(value,k)for k in
                ('source','offset','size','frame_number','page_number','database_pages','committed_frame',
                 'committed_end_offset','checksum_before','checksum_after')})
            record['actual_read_requests']=[{'kind':x.kind,'offset':x.offset,'size':x.size,'frame_number':x.frame_number}for x in reads]
        self.drives.append(record)
        try:
            # The input view was frozen independently before this execution.
            view=raw[:len(spec['view'])]
            for oracle in self.oracles:record['actual_C'].append(oracle.call(spec,view))
            if spec['expected_error']is None:common.require(error is None,'unexpected actual drive exception')
            else:common.require(type(error)is self.bridge.SQLiteWalSnapshotRejected
                                and error.status==spec['expected_error'],'original rejection differs')
            if error is None:
                effective=(model.parse(spec['raw'],spec['base_size'],spec['base_pages']) if spec['snapshot']is None else spec['snapshot'])
                value,reads=result
                if spec['target']==0:
                    common.require(all(getattr(value,k)==v for k,v in model.snapshot_fields(effective).items()),'actual HIA snapshot semantic fields')
                else:
                    wanted=model.location(effective,spec['target'])
                    actual={k:(list(getattr(value,k))if k.startswith('checksum_')else getattr(value,k))for k in wanted}
                    common.require(actual==wanted,'actual HIA fixed-view page location')
            record['semantic_comparison_passed']=True
        finally:self.drive_active=False
    def finish(self,expected):
        for iterator in (self.sequence,self.drive_sequence):
            try:next(iterator)
            except StopIteration:pass
            else:raise RuntimeError('missing native call or finite C drive')
        common.require(self.started==self.returned==self.validated==expected['native_returns']==2704
            and self.by_method==expected['counts'] and len(self.drives)==expected['C_calls_each']==639
            and all(x.started==x.returned==639 for x in self.oracles)
            and not self.secondary and not self.drive_active,'actual complete fixed denominator')
        self.hia_writer.finish(True);self.c_writer.finish(True)

class NativeImage:
    def __init__(self,program):
        common.require(CTX.backend is None,'one original class backend')
        _,doc=support.read_json(ROOT/'reference/source12-actual/CORE.json')
        from hepta.hia_program import verify_program
        common.require(program.as_dict()==verify_program(doc).as_dict(),'original class program equals actual compiled source')
        self.program=program;self.calls=[];self.label='unlabelled';CTX.backend=self
    def raw(self,source,output,state):
        arrays=[ctypes.create_string_buffer(b+matrix.CANARY,len(b)+64)for b in (source,output,state)]
        status=CTX.installed_entry(arrays[0],len(source),arrays[1],len(output),arrays[2],len(state))
        return status,arrays[1].raw[:len(output)],arrays[2].raw[:len(state)]
    def _entry(self,s,n,o,m,w,k):return CTX.installed_entry(s,n,o,m,w,k)

class Result(unittest.TextTestResult):
    def __init__(self,*a,**k):
        super().__init__(*a,**k);self.actual=[];self.success=[];self.failure_ids=[];self.error_ids=[]
    def startTest(self,test):
        CTX.method=test.id();self.actual.append(test.id());super().startTest(test)
    def addSuccess(self,test):self.success.append(test.id());super().addSuccess(test)
    def addFailure(self,test,err):self.failure_ids.append(test.id());super().addFailure(test,err)
    def addError(self,test,err):self.error_ids.append(test.id());super().addError(test,err)

class FullPageSizesNativeTests(unittest.TestCase):
    def setUp(self):
        CTX.backend.label=self.id()
    def test_13_complete_frames_lookup_and_recovery_all_page_sizes(self):
        for g in matrix.full_page_groups():
            with self.subTest(page_size=g['page_size'],order=g['order'],scenario=g['label']):
                self.kernel=CTX.original_class.kernel
                snapshot,_=self.drive(g['raw'],base_page_size=g['page_size'],base_page_count=g['base_pages'])
                wanted=model.parse(g['raw'],g['page_size'],g['base_pages'])
                for key,value in model.snapshot_fields(wanted).items():self.assertEqual(getattr(snapshot,key),value)
                for page in g['pages']:
                    actual,reads=self.drive(g['raw'],snapshot=snapshot,page=page)
                    expected=model.location(wanted,page)
                    self.assertEqual({k:list(getattr(actual,k))if k.startswith('checksum_')else getattr(actual,k)for k in expected},expected)
                    if reads:self.assertLessEqual(max(r.offset+r.size for r in reads),snapshot.committed_end_offset)
FullPageSizesNativeTests.__module__='tests.hia_wal_snapshot_native_pages_r1'

def main():
    global CTX
    path=Path(sys.argv[1]);pin,raw=common.read(path)
    common.require(path==ROOT/'REQUEST.json' and pin['sha256']==sys.argv[2],'exact snapshot native request')
    request=json.loads(raw);output=Path(request['output'])/'native'
    common.require(output.is_dir() and dict(os.environ)==request['environment']
        and 'HEPTA_SQLITE_WAL_SNAPSHOT_SOURCE_EVIDENCE'not in os.environ,'native output/env and no source evidence replay')
    report={'schema':'hia.wal-snapshot.native-result.v1','status':'HOLD','expected_ids':list(matrix.IDS),
        'exception':None,'secondary_errors':[],'denied_effects':[],'database_opened':False,'network_used':False,
        'source12_VM_reexecuted':False,'matching_cold_qualification':False,'original_methods':12,'added_methods':1}
    started=time.monotonic_ns()
    try:
        report['runtime']=support.runtime(request)
        before=support.input_records(request);source_before=support.source_records(request)
        report['inputs_before']=common.create(output/'INPUTS-BEFORE.json',before)
        report['source_before']=common.create(output/'SOURCE-BEFORE.json',source_before)
        _,spec=support.read_json(output/'NATIVE-INPUTS.json');CTX=Context(request,output,spec)
        _,expected=support.read_json(ROOT/'EXPECTED-MATRIX.json')
        own={v['path']:v for v in spec['oracles'].values()}
        resource.setrlimit(resource.RLIMIT_CORE,(0,0));resource.setrlimit(resource.RLIMIT_CPU,(180,180))
        resource.setrlimit(resource.RLIMIT_AS,(256<<20,256<<20))
        resource.setrlimit(resource.RLIMIT_STACK,(8<<20,8<<20));resource.setrlimit(resource.RLIMIT_FSIZE,(4<<20,4<<20))
        forbidden=('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.fork','os.forkpty',
                   'pty.spawn','mmap.__new__','socket.','sqlite3.connect','ctypes.dlopen','ctypes.dlsym')
        def audit(event,args):
            if any(event==x or event.startswith(x)for x in forbidden):
                report['denied_effects'].append(event);raise RuntimeError('finite child forbidden effect: '+event)
        sys.addaudithook(audit)
        runtime=importlib.import_module('hepta.hia_program_runtime')
        def forbidden_VM(*a,**k):
            report['denied_effects'].append('hepta.hia_program_runtime._Machine')
            raise RuntimeError('original VM execution forbidden in finite native request')
        runtime._Machine=forbidden_VM
        name='tests.hia_sqlite_wal_snapshot_source_r1'
        module_spec=importlib.util.spec_from_file_location(name,ROOT/'candidate/inputs/tests/test_hia_sqlite_wal_snapshot_source.py')
        module=importlib.util.module_from_spec(module_spec);sys.modules[name]=module;module_spec.loader.exec_module(module)
        common.require(module.EXPECTED_NAMES==matrix.NAMES and module._Machine is forbidden_VM,'original twelve module/VM poison')
        original_class=module.SQLiteWalSnapshotSourceTests;CTX.original_class=original_class
        original_drive=original_class.drive
        def observed_drive(self,raw,**kwargs):
            spec=CTX.begin_drive(raw,kwargs);spec['actual_native_first']=CTX.validated+1
            try:result=original_drive(self,raw,**kwargs)
            except BaseException as exc:
                try:CTX.end_drive(spec,raw,None,exc)
                except BaseException as secondary:
                    CTX.secondary.append('drive record: '+type(secondary).__name__+': '+str(secondary)[:512])
                    CTX.drive_active=False
                raise
            else:
                try:CTX.end_drive(spec,raw,result,None)
                except BaseException as secondary:
                    CTX.secondary.append('drive record: '+type(secondary).__name__+': '+str(secondary)[:512])
                    CTX.drive_active=False
                return result
        module.VMImage=NativeImage;original_class.drive=observed_drive;FullPageSizesNativeTests.drive=observed_drive
        report['mapped_files_before']=support.loaded_file_maps(request,own,CTX.codec,CTX.original_entry,
            CTX.installed_entry,spec['image'],output/'mapping-before')
        suite=unittest.TestSuite([*(original_class(n)for n in matrix.NAMES),
            FullPageSizesNativeTests('test_13_complete_frames_lookup_and_recovery_all_page_sizes')])
        report['loaded_ids']=[t.id()for t in suite]
        common.require(report['loaded_ids']==list(matrix.IDS),'fixed original12 plus separate native group')
        with (output/'unittest.log').open('x',encoding='utf-8')as stream:
            result=unittest.TextTestRunner(stream=stream,verbosity=2,resultclass=Result).run(suite)
        report.update(actual_ids=result.actual,success_ids=result.success,tests_run=result.testsRun,
            failures=[t.id()for t,_ in result.failures],errors=[t.id()for t,_ in result.errors],skipped=[(t.id(),why)for t,why in result.skipped],
            expected_failures=[t.id()for t,_ in result.expectedFailures],unexpected_successes=[t.id()for t in result.unexpectedSuccesses],
            native_returns=CTX.returned,actual_native_starts=CTX.started,validated_native_returns=CTX.validated,native_counts=CTX.by_method)
        common.require(result.actual==result.success==list(matrix.IDS) and result.testsRun==13
            and not(result.failures or result.errors or result.skipped or result.expectedFailures or result.unexpectedSuccesses),
            'complete original12 and separate full-page method failed')
        common.require(module.VMImage is NativeImage and module._Machine is runtime._Machine is forbidden_VM
            and original_class.drive is FullPageSizesNativeTests.drive is observed_drive
            and original_class.assembly.encode()==common.read(ROOT/'reference/source12-actual/sqlite_wal_snapshot.hiaasm',1<<20)[1]
            and original_class.document==support.read_json(ROOT/'reference/source12-actual/CORE.json')[1],
            'original independent author re-emission or native transport differs')
        common.require(CTX.backend.calls==list(matrix.original_calls(ROOT)),'all608 actual native spans equal original VM bodies')
        CTX.finish(expected)
        report['drive_results']=common.create(output/'DRIVES.json',CTX.drives)
        report['full_trace_readback']=trace.inspect(ROOT,output/'trace',expected)
        report['imports']=support.current_imports(request)
        report['mapped_files_after']=support.loaded_file_maps(request,own,CTX.codec,CTX.original_entry,
            CTX.installed_entry,spec['image'],output/'mapping-after')
        common.require(report['mapped_files_before']['files']==report['mapped_files_after']['files']
            and report['mapped_files_before']['image_binding']==report['mapped_files_after']['image_binding'],'exact current image and actual mapped closure unchanged')
        after=support.input_records(request);source_after=support.source_records(request)
        report['inputs_after']=common.create(output/'INPUTS-AFTER.json',after)
        report['source_after']=common.create(output/'SOURCE-AFTER.json',source_after)
        common.require(before==after and source_before==source_after and not report['denied_effects']and not CTX.secondary,'all immutable inputs and no forbidden effects')
        report['status']='FINITE_NATIVE_SNAPSHOT_AND_TWO_C_ORACLES_PASS_ONLY'
    except BaseException as exc:
        report['status']='HOLD';report['exception']=type(exc).__module__+'.'+type(exc).__qualname__+': '+str(exc)[:1024]
        report['traceback']=traceback.format_exc()
    finally:
        if CTX is not None:
            for writer in (CTX.hia_writer,CTX.c_writer):
                if not writer.closed:
                    try:writer.finish(False)
                    except BaseException as exc:report['secondary_errors'].append('partial trace: '+type(exc).__name__+': '+str(exc)[:256])
            if not (output/'DRIVES.json').exists():
                try:report['partial_drives']=common.create(output/'DRIVES.partial.json',CTX.drives)
                except BaseException as exc:report['secondary_errors'].append('partial drives: '+type(exc).__name__)
            report.update(native_returns=CTX.returned,actual_native_starts=CTX.started,validated_native_returns=CTX.validated,
                          native_counts=CTX.by_method,C_counts={o.version:{'started':o.started,'returned':o.returned}for o in CTX.oracles},
                          observation_errors=CTX.secondary)
        report['elapsed_ns']=time.monotonic_ns()-started
        if report['exception']is not None or report['secondary_errors']or report.get('observation_errors'):
            report['status']='HOLD'
        common.create(output/'REPORT.json',report)
    return 0 if report['status']=='FINITE_NATIVE_SNAPSHOT_AND_TWO_C_ORACLES_PASS_ONLY'else 1
if __name__=='__main__':raise SystemExit(main())
