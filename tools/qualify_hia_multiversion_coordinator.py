"""Original-API QA for the HIA coordinator, never a production adapter.

Only the candidate sequencing, generation selection, retirement handoff, locks,
lease transitions and event history are executed by the HIA coordinator and
retention machine images. This external QA harness supplies the original real
Core verification, fresh Z3 proof, Clang build, sealed loader, mapping checks,
VM probes and retirement effects. Those host facts are NOT reported as a
native implementation of the remaining runtime. The production adapter is a
separate HIA-owned implementation with closed mechanical primitives.
"""
from pathlib import Path
from collections import Counter,deque
import argparse,copy,ctypes,hashlib,json,os,struct,sys,threading,time,traceback,unittest
from hepta import hia_multiversion as original
from hepta.hia_program import verify_program
from hepta.hia_scalar_profile_native import REASONS
from tools.qualify_hia_multiversion_components import Image,get,put,U64
MAGIC=int.from_bytes(b'HIAMVC01','little');RETENTION=int.from_bytes(b'HIAGRQ01','little')
IMAGES={};COUNTS=Counter();FAULT=None
ERRORS={1:'runtime instance identity differs',2:'runtime instance identity is empty',3:'translation validation timeout must be 1..30000 milliseconds',4:'live generation limit must be 2..64',10:'Core admission refused',11:'scalar profile refused',12:'private directory unavailable',13:'native preparation failed',14:'monotonic clock unavailable',15:'conditional publication needs exact snapshot, budget and cancellation types',16:'preparation handoff must be an earlier exact monotonic timestamp',17:'native lock unavailable',18:'runtime is closed',19:'stale generation or selection epoch',20:'actual preparation budget exceeded before selection',21:'publication cancelled before selection',22:'publication cancellation token was already committed',23:'native measurement refused publication',24:'independent translation validation did not prove the exact pair',25:'publication commit acknowledgement interrupted',26:'live artifact budget exhausted; existing generations remain selected',27:'generation ownership is inconsistent',28:'generation number storage unavailable',29:'native lease allocation unavailable',30:'native generation retention refused',31:'lease belongs to another runtime',32:'generation lease is closed',33:'native call refused',34:'directory cleanup failed',35:'retirement interrupted',36:'snapshot refused',37:'cancellation owner unavailable',127:'private continuation refused'}

def reject(text):raise original.MultiversionRejected('E_HIA_MULTIVERSION: '+text)
class Retention:
    def __init__(self):
        self.token=struct.unpack('<2Q',os.urandom(16));self.task=struct.unpack('<2Q',os.urandom(16));self.buffer=ctypes.create_string_buffer(65);self.keep=[]
        assert self.call(0)==0
    def call(self,event,lease=None):
        token=lease._identity if lease is not None else self.task if event==4 else (0,0)
        out=lease._cell if lease is not None else ctypes.create_string_buffer(64)
        wire=struct.pack('<8Q',RETENTION,event,*self.token,*token,0,0)
        rc=IMAGES['generation_retention'](wire,out,self.buffer)
        if rc==4294967288:
            assert event==1
            prior=self.buffer;self.buffer=ctypes.create_string_buffer(64+(len(prior)-64)*2);ctypes.memmove(self.buffer,prior,len(prior));self.keep.append(prior)
            return self.call(event,lease)
        return rc
    def references(self):return int.from_bytes(self.buffer.raw[64:64+get(self.buffer,32)],'little')

class Lease:
    def __init__(self,runtime,state,slot,epoch):
        self._runtime,self._generation,self._slot=runtime,state,slot;self.selection_epoch=epoch;self._lock=threading.RLock();self._identity=struct.unpack('<2Q',os.urandom(16));self._cell=ctypes.create_string_buffer(64);self._retention=runtime._retentions[state.info.generation]
    @property
    def info(self):return self._generation.info
    def call(self,function,arguments):return self._runtime._drive(4,lease=self,function=function,arguments=arguments)
    def close(self):return self._runtime._drive(5,lease=self)
    def __enter__(self):
        with self._lock:
            if self._retention.call(6,self)!=1:reject('generation lease is closed')
        return self
    def __exit__(self,*args):self.close()
    def __copy__(self):reject('leases have one close owner; acquire another lease instead of copying')
    def __deepcopy__(self,memo):return self.__copy__()

class ComponentRuntime(original.ScalarMultiversionRuntime):
    """QA compatibility facade; not installed and not an implementation claim."""
    def __init__(self,baseline,directory,**options):
        self._component_ready=False
        super().__init__(baseline,directory,**options)
        self._state=ctypes.create_string_buffer(24576);self._instance=struct.unpack('<2Q',os.urandom(16));self._retentions={0:Retention()};self._images_by_slot={0:self._states[0]};self._all_images={0:self._states[0]};self._slot_generation={0:0};self._active_cells={};self._fact_lock=threading.RLock();self._component_ready=True
        self._drive(0,candidate=baseline,baseline=True)
    def _sync(self):
        with self._lock:
            return self._sync_locked()
    def _sync_locked(self):
        if not self._component_ready:return
        selected={}
        for slot,state in tuple(self._images_by_slot.items()):
            row=512+slot*256;kind=get(self._state,row)
            if kind&2 and get(self._state,row+8)==state.info.generation:selected[state.info.generation]=state
            retention=self._retentions.get(state.info.generation)
            if retention is not None:
                flags=retention.call(5);state._reference_leases=retention.references();state._reference_retired=bool(flags&1)
        self._states.clear();self._states.update(selected)
        self._closed=bool(get(self._state,24));self._next=get(self._state,32);self._epoch=get(self._state,40);slot=get(self._state,48);self._current=None if slot==U64 else get(self._state,512+slot*256+8)
        count=get(self._state,104);head=get(self._state,112);events=[]
        for n in range(count):
            at=17408+((head-count+n)%128)*48;kind,number,epoch,elapsed,budget,_=struct.unpack_from('<6Q',self._state,at);row={'event':{1:'publish',2:'publish_if_current',3:'rollback',4:'retire'}[kind],'generation':number,'epoch':epoch}
            if kind==2:row.update(prepare_ns=elapsed,max_prepare_ns=budget)
            events.append(row)
        self._events=deque(events,maxlen=128)
    def _facts_profile(self,ctx):
        program=ctx['program'];data=program.as_dict();raw=json.dumps(data,separators=(',',':'),ensure_ascii=True).encode()
        out=ctypes.create_string_buffer(8<<20);work=ctypes.create_string_buffer(32<<20);answer=ctypes.create_string_buffer(b'\xa5'*144,144);state=ctypes.create_string_buffer(8192)
        for phase in (0,1):
            put(out,0,int(self._prove_total));put(out,8,phase);put(out,16,int(program.structured_bytes is not None));n=IMAGES['multiversion_profile'](raw,out,work)
            if n>=0xfffffff0 or n>len(out):raise RuntimeError('native Core fact projection refused')
            rc=IMAGES['scalar_profile'](out.raw[:n],answer,state)
            if rc in REASONS:reject(REASONS[rc])
            assert rc==(17 if phase==0 else 0),(rc,phase)
        count=get(answer,8);functions=data['functions'];abi=tuple(original.ScalarABI(functions[get(answer,16+i*8)]['name'],tuple(p['type'] for p in functions[get(answer,16+i*8)]['params']),functions[get(answer,16+i*8)]['returns'][0]) for i in range(count))
        if abi!=self._abi:reject('candidate scalar ABI differs from the immutable baseline')
        ctx['abi']=abi;ctx['totality']=()
        if self._prove_total:
            _p,_abi,totality=original._admit(program,prove_total=True,timeout_ms=self._timeout);assert _abi==abi;ctx['totality']=totality
    def _drive(self,op,**ctx):
        if not self._component_ready:raise RuntimeError('component owner not initialized')
        output=ctypes.create_string_buffer(4096)
        if op==0:a,b,c=self._timeout,self._max_live,int(self._prove_total)
        elif op in (4,5,6):a,b=ctx['lease']._identity;c=0
        else:a=ctx.get('expected_generation',0);b=ctx.get('expected_epoch',0);c=ctx.get('max_prepare_ns',0)
        earlier=ctx.get('preparation_started_ns');wire=struct.pack('<12Q',MAGIC,op,*self._instance,a,b,c,id(ctx.get('token')) if ctx.get('token') is not None else 0,int(ctx.get('measured') is not None),U64 if earlier is None else earlier,0,0)
        ctx.update(op=op,output=output,exception=None);iterations=0
        while True:
            iterations+=1
            if iterations>4096:raise AssertionError(('continuation did not settle',op,get(output,0)))
            rc=IMAGES['multiversion_coordinator'](wire,output,self._state)
            if rc==100:continue
            if rc==101:
                self._sync();error=get(output,120)
                if error:
                    if ctx['exception'] is not None:raise ctx['exception']
                    reject(ERRORS.get(error,'native continuation error '+str(error)))
                if op in (0,1):return self._all_images[get(output,136)].info
                if op==2:
                    result={'generation':self._all_images[get(output,136)].info.as_dict(),'selection_epoch':get(self._state,40),'prepare_ns':get(output,176)-get(output,72),'max_prepare_ns':c}
                    if 'admission' in ctx:result['measurement_admission']=ctx['admission']
                    return result
                if op==3:return ctx['lease']
                if op==7:return self._all_images[0].info
                if op in (9,10):return ctx['result']
                if op==11:return bool(get(output,240))
                return ctx.get('result')
            if rc>=0xfffffff0:raise AssertionError(('coordinator ABI refused',op,get(output,0),rc))
            action=get(output,160);a=get(output,168);b=get(output,248);COUNTS[action]+=1
            assert action==rc,(action,rc)
            put(output,8,0)
            try:
                if FAULT is not None:FAULT(self,ctx,action,a,b,'before')
                self._action(ctx,action,a,b)
                if FAULT is not None:FAULT(self,ctx,action,a,b,'after')
            except BaseException as error:
                ctx['exception']=error;put(output,8,1)
                if action==23:
                    number=get(output,136);task=self._cleanup_pending.get(number);put(output,264,2 if task is not None else 0)
                if action==26:
                    number=get(self._state,512+get(output,32)*256+8) if b not in (1,) else get(output,136)
                    put(output,280,int(number in self._cleanup_pending));put(output,216,int(number not in self._cleanup_pending and b in (1,2,3)))
                if action==35 and ctx.get('token') is not None:put(output,192,int(ctx['token']._committed))
    def _action(self,ctx,action,a,b):
        o=ctx['output'];op=ctx['op']
        if action in (1,2):
            lock={1:self._writer,2:self._lock,3:ctx.get('lease')._lock if ctx.get('lease') is not None else None,4:ctx.get('token')._lock if ctx.get('token') is not None else None}[a]
            if lock is None:raise RuntimeError('missing owned lock')
            if action==1:lock.acquire()
            else:lock.release()
            if action==1 and a==4:put(o,184,int(ctx['token'].cancelled()));put(o,192,int(ctx['token']._committed))
            return
        if action==20:
            ctx['program']=self._baseline if op==0 else verify_program(ctx['candidate']);return
        if action==21:self._facts_profile(ctx);return
        if action==22:original._prove(self._baseline,ctx['program'],ctx['abi'],self._timeout);return
        if action==23:
            number=get(o,136);slot=get(o,40)
            state=self._all_images[0] if op==0 else self._prepare(ctx['program'],number,len(ctx['abi']),totality=ctx['totality'])
            self._images_by_slot[slot]=state;self._all_images[number]=state;self._slot_generation[slot]=number
            if number not in self._retentions:self._retentions[number]=Retention()
            ctx['prepared']=state;put(o,264,1);return
        if action==24:
            self._sync();measured=ctx['measured'];current=self._states[self._current].info
            if b!=get(o,40):raise AssertionError('measurement wrong candidate')
            if a==0:
                if (measured['before_sha256']!=current.program_sha256 or measured['after_sha256']!=ctx['program'].sha256 or measured['before_artifact_sha256']!=current.artifact_sha256 or measured['function'] not in {x.function for x in ctx['abi']}):reject('measurement does not bind current Core, candidate, artifact and export')
                cost=time.perf_counter_ns()-get(o,72)
            else:
                state=ctx['prepared']
                if measured['before_artifact_sha256']!=current.artifact_sha256 or measured['after_artifact_sha256']!=state.info.artifact_sha256:reject('measurement native identity differs from the actual freshly built artifacts')
                cost=get(o,176)-get(o,72)
            verdict=original._assess_measurement(measured,prepare_ns=cost)
            if not verdict['eligible']:reject('native measurement refused publication: '+','.join(verdict['reasons']))
            if a==1:ctx['admission']=verdict
            return
        if action==25:
            lease=ctx.get('lease') if op in (3,4,5,6) and b in (1,2,6) else None
            number=lease.info.generation if lease is not None else get(self._state,512+a*256+8)
            retention=self._retentions[number];rc=retention.call(b,lease);put(o,8,rc)
            state=self._all_images[number];state._reference_leases=retention.references();state._reference_retired=bool(retention.call(5)&1)
            if b==2 and lease is not None:self._active_cells.pop(lease._identity,None)
            if b==3 and rc==0:self._collect(state)
            return
        if action==26:
            slot=get(o,40) if b==1 else a;number=get(self._state,512+slot*256+8);state=self._all_images.get(number)
            if b in (0,1):
                if state is None:raise AssertionError(('missing native prepared image',slot,number))
                task=self._retirement_task(number,state.library,state.functions,state.fd,state.artifact,state.inode,state.identity_pin,cause='prepared_but_not_selected' if b==1 and op==2 else 'prepared_but_not_published' if b==1 else 'retired_generation')
                put(o,280,1)
                if b==0:return
            task=self._cleanup_pending[number]
            self._sync()
            if state is not None:state.library=None
            self._attempt_cleanup(task);put(o,216,int(task.complete));return
        if action==30:put(o,176,time.perf_counter_ns());return
        if action==38:
            ctx['token']=original.PublicationCancellation();put(o,80,id(ctx['token']));return
        if action==31:
            state=self._images_by_slot[a];lease=Lease(self,state,a,b);ctx['lease']=lease;self._active_cells[lease._identity]=lease;return
        if action==32:
            lease=ctx['lease'];function=ctx['function'];arguments=ctx['arguments'];signatures={x.function:x for x in lease.info.abi}
            if type(function) is not str or function not in signatures:reject('unknown function in this generation')
            signature=signatures[function]
            if type(arguments) not in (tuple,list):reject('native arguments must be an exact scalar list or tuple')
            arguments=tuple(arguments)
            if len(arguments)!=len(signature.parameters) or any(not original.scalar_value_valid(v,t) for v,t in zip(arguments,signature.parameters)):reject('native arguments differ from the exact scalar ABI')
            ctx['result']=lease._generation.functions[function](*arguments);return
        if action==33:return
        if action==34:
            lease=ctx['lease']
            if lease._runtime is not self or lease._identity!=(a,b):reject('lease belongs to another runtime')
            put(o,200,lease._slot);put(o,272,lease.info.generation);return
        if action==35:
            token=ctx['token']
            if b==1:
                # Original actual insertion/return is retained only as the QA
                # fault boundary. HIA has already selected the prepared record;
                # a failed acknowledgement is resolved from this real marker.
                previous,epoch=self._commit_prepared(ctx['prepared'],token)
                assert self._current==get(self._state,512+get(self._state,48)*256+8) and epoch==get(self._state,40)
            elif b==2:token._event.set()
            put(o,184,int(token.cancelled()));put(o,192,int(token._committed));return
        if action==36:self._sync();self._remove_directory();return
        if action==37:
            self._sync();ctx['result']=self._cleanup_snapshot() if op==9 else super().snapshot();return
        raise AssertionError(('unexpected native action',action,a,b))
    def _collect(self,state):
        # Original private hook is retained only to inject the same exception
        # before HIA's retirement-ready query. It performs no policy/effect.
        if not self._component_ready:return super()._collect(state)
    def publish(self,candidate):return self._drive(1,candidate=candidate)
    def publish_if_current(self,candidate,expected_generation,*,expected_epoch,max_prepare_ns,cancellation,preparation_started_ns=None,measurement=None):
        measured=original._measurement_snapshot(measurement) if measurement is not None else None
        if measured is not None and preparation_started_ns is not None:reject('measured publication cannot use an earlier preparation handoff')
        if (type(expected_generation) is not int or expected_generation<0 or type(expected_epoch) is not int or expected_epoch<0 or type(max_prepare_ns) is not int or not 0<=max_prepare_ns<2**63 or type(cancellation) is not original.PublicationCancellation):reject('conditional publication needs exact snapshot, budget and cancellation types')
        if preparation_started_ns is not None and (type(preparation_started_ns) is not int or not 0<=preparation_started_ns<=time.perf_counter_ns()):reject('preparation handoff must be an earlier exact monotonic timestamp')
        if expected_generation>U64 or expected_epoch>U64:reject('stale generation or selection epoch')
        return self._drive(2,candidate=candidate,expected_generation=expected_generation,expected_epoch=expected_epoch,max_prepare_ns=max_prepare_ns,token=cancellation,preparation_started_ns=preparation_started_ns,measured=measured)
    def lease(self):return self._drive(3)
    def call(self,function,arguments):
        with self.lease() as lease:return lease.call(function,arguments)
    def rollback(self):return self._drive(7)
    def close(self):
        if not self._component_ready:return super().close()
        return self._drive(8)
    def retry_cleanup(self):return self._drive(9)
    def snapshot(self):return self._drive(10)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--components',type=Path,required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args();args.output.mkdir(parents=True,exist_ok=True)
    IMAGES.update({role:Image(args.components/f'{role}.flat') for role in ('multiversion_coordinator','multiversion_profile','scalar_profile','generation_retention')})
    from tests import test_hia_multiversion as old
    from tests import test_hia_publication_interruptions as interruptions
    assert old._NATIVE,'original real Clang/Z3 oracle unavailable'
    raw=Path(old.__file__).read_bytes();original_source=Path(original.__file__).read_bytes();runs=[]
    for label,cls in [('original',original.ScalarMultiversionRuntime),('native-coordinator-component',ComponentRuntime)]:
        old.ScalarMultiversionRuntime=cls;interruptions.ScalarMultiversionRuntime=cls
        cases=unittest.TestSuite([unittest.defaultTestLoader.loadTestsFromModule(old),unittest.defaultTestLoader.loadTestsFromModule(interruptions)])
        path=args.output/(label+'.log')
        with path.open('w') as log:
            t=time.monotonic_ns();result=unittest.TextTestRunner(stream=log,verbosity=2).run(cases)
        runs.append({'label':label,'tests':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'elapsed_ns':time.monotonic_ns()-t,'log_sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        print('ORIGINAL_API_RUN',json.dumps(runs[-1]),flush=True)
    report={'schema':'hepta.hia.multiversion-coordinator-component-qualification.v1','scope':'original public API with real original proof/build/load/probe effects; HIA coordinator/profile/retention ownership only; not complete native runtime','whole_native':False,'original_tests_sha256':hashlib.sha256(raw).hexdigest(),'original_runtime_source_sha256':hashlib.sha256(original_source).hexdigest(),'components':[v.pin for v in IMAGES.values()],'runs':runs,'action_counts':dict(COUNTS)}
    (args.output/'qualification.json').write_text(json.dumps(report,indent=2)+'\n')
    if any(r['failures'] or r['errors'] or r['skipped'] for r in runs):raise SystemExit(1)
if __name__=='__main__':main()
