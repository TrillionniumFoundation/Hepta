"""Actual fixed eight-image DataJSON executable, no Python runtime dispatch.

The retained Python oracle executes only before the independent native process;
Graph materialization below is test observation after that process has exited.
Original component test counts are not imported as this executable's evidence.
"""
from __future__ import annotations
import ast,ctypes,json,math,os,resource,signal,stat,struct,subprocess,sys,time,traceback,zlib
from contextlib import ExitStack
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch
WORK=Path(sys.argv[1]).resolve();BUILD=Path(sys.argv[2]).resolve()
OUT=Path(sys.argv[3]).resolve();GROUP=sys.argv[4]
REFERENCE_HARNESS=Path(sys.argv[5]).resolve() if len(sys.argv)>5 else None
REFERENCE=WORK/'Hepta-agent-edit-native';ROOT=WORK/'native-agent-default-json-fixed-next'
sys.path[:0]=[str(ROOT/'tools'),str(REFERENCE)]
from hepta import hia_agent_store as store
from hepta.hia_json_preflight_native import NativeHiaJsonImage
import agent_default_json_fixed_common as common
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
M=lambda s:int.from_bytes(s,'little')
pack=lambda *values:struct.pack('<'+'Q'*len(values),*values)
BAD=0xfffffffd;CANARY=bytes(range(64));COMPILER='0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8'
OUT.mkdir(parents=True,exist_ok=False);(OUT/'cas').mkdir()
pins={};modes={};saved=set();status='FAIL';failure=None;cases=0;planned=0;native_processes=0;private_entries=0;component_entries={}
rows=(OUT/'cases.jsonl').open('w');ledger=(OUT/'private-entries.jsonl').open('w')
component_ledger=(OUT/'component-byte-reference-entries.jsonl').open('w')
PARENT_PID=os.getpid()
started=time.monotonic_ns()
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+'\n')
def read(path):
    path=Path(path).resolve();raw=path.read_bytes();mode=stat.S_IMODE(path.stat().st_mode)
    if path in pins:assert pins[path]==raw and modes[path]==mode
    pins[path]=raw;modes[path]=mode;return raw
def unchanged():
    return all(path.is_file() and path.read_bytes()==raw and
        stat.S_IMODE(path.stat().st_mode)==modes[path] for path,raw in pins.items())
def pinrows():
    return [dict(path=str(path),bytes=len(raw),sha256=digest(raw),mode=modes[path])
        for path,raw in pins.items()]
def cas(raw):
    raw=bytes(raw);h=digest(raw)
    if h not in saved:
        path=OUT/'cas'/(h+'.zlib');path.write_bytes(zlib.compress(raw,1))
        assert zlib.decompress(path.read_bytes())==raw;saved.add(h)
    return dict(bytes=len(raw),sha256=h)

def oracle(payload):
    float_calls=[];masked=[]
    loads=json.loads;preflight=store.preflight_hia_json
    def observing_preflight(text,**kwargs):
        masked.append(text.encode('utf-8'))
        return preflight(text,**kwargs)
    def observing_loads(*args,**kwargs):
        floating=kwargs.get('parse_float')
        if floating is not None:
            def observed(text):
                float_calls.append(text.encode('ascii'))
                return floating(text)
            kwargs=dict(kwargs);kwargs['parse_float']=observed
        return loads(*args,**kwargs)
    try:
        with patch.dict(os.environ,{'HEPTA_HIA_AGENT_DATA_JSON_MANIFEST':'',
              'HEPTA_HIA_AGENT_BINARY64_MANIFEST':'','HEPTA_HIA_JSON_PREFLIGHT_MANIFEST':''}),\
              patch.object(store,'preflight_hia_json',new=observing_preflight),\
              patch('json.loads',new=observing_loads):
            value=store.decode_data(payload)
        result=dict(value=value)
    except Exception as exc:
        result=dict(error_class=type(exc).__name__,error=str(exc),code=getattr(exc,'code',None))
        if isinstance(exc,(UnicodeDecodeError,UnicodeEncodeError)):result.update(start=exc.start,end=exc.end)
        if isinstance(exc,json.JSONDecodeError):result.update(pos=exc.pos,lineno=exc.lineno,colno=exc.colno)
    return result,float_calls,masked

def clean(value):
    if value is None or type(value) is bool:return value
    if type(value) is int:
        n=abs(value);return dict(integer_le=n.to_bytes((n.bit_length()+7)//8,'little').hex(),negative=value<0)
    if type(value) is float:return dict(binary64=struct.pack('<d',value).hex())
    if type(value) is str:return value
    if type(value) is list:return [clean(x) for x in value]
    assert type(value) is dict
    return dict(ordered_items=[[k,clean(v)] for k,v in value.items()])
def graph_value(raw):
    magic,lease,n,root,e,pool,total,reserved=struct.unpack_from('<8Q',raw)
    assert (magic,lease,total,reserved)==(M(b'HIAGRF01'),93,len(raw),0) and 1<=root<=n
    edgebase=64+n*64;database=edgebase+e*8;assert database+pool==len(raw)
    def row(identifier):
        assert 1<=identifier<=n
        return struct.unpack_from('<8Q',raw,64+(identifier-1)*64)
    for identifier in range(1,n+1):
        kind,at,size,first,count,identity,aux,res=row(identifier)
        assert res==0
        if kind in (2,3,4):
            assert database<=at<=len(raw) and size<=len(raw)-at and first==count==identity==0
        if kind==0:assert (at,size,first,count,identity,aux)==(0,0,0,0,0,0)
        elif kind==1:assert (at,size,first,count,identity)==(0,0,0,0,0) and aux in (0,1)
        elif kind==2:
            assert aux in (0,1) and (size!=0 or aux==0)
            assert size==0 or raw[at+size-1]!=0
        elif kind==3:assert size==8 and aux==0
        elif kind==4:assert len(raw[at:at+size].decode('utf-8'))==aux
        elif kind in (5,6):
            assert at==size==aux==0 and identity!=0 and first<=e and count*(2 if kind==6 else 1)<=e-first
        else:raise AssertionError(kind)
    active=set()
    def value(identifier):
        assert identifier not in active
        active.add(identifier)
        kind,at,size,first,count,identity,aux,res=row(identifier)
        if kind==0:result=None
        elif kind==1:result=bool(aux)
        elif kind==2:
            result=int.from_bytes(raw[at:at+size],'little')
            if aux:result=-result
        elif kind==3:result=struct.unpack_from('<d',raw,at)[0]
        elif kind==4:result=raw[at:at+size].decode('utf-8')
        else:
            ids=struct.unpack_from('<'+'Q'*(count*(2 if kind==6 else 1)),raw,edgebase+first*8)
            if kind==5:result=[value(x) for x in ids]
            else:
                result={}
                for i in range(0,len(ids),2):
                    key=value(ids[i]);assert type(key) is str and key not in result
                    result[key]=value(ids[i+1])
        active.remove(identifier);return result
    return value(root)

def transport(payload):
    if type(payload) is bytes:return payload,9
    if type(payload) is str:return payload.encode('utf-8','surrogatepass'),4
    return b'',0

def native_limits():
    # A timed-out outer CI owner may kill this test process group. The new
    # child session must not survive its owner; arm this before exec and close
    # the fork/death race. No language quota or expected outcome is changed.
    libc=ctypes.CDLL(None,use_errno=True)
    observed=ctypes.c_int()
    if libc.prctl(1,signal.SIGKILL,0,0,0)!=0 or libc.prctl(2,ctypes.byref(observed),0,0,0)!=0:
        os._exit(126)
    if observed.value!=signal.SIGKILL or os.getppid()!=PARENT_PID:
        os._exit(126)
    resource.setrlimit(resource.RLIMIT_CPU,(90,90))
    resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
    resource.setrlimit(resource.RLIMIT_CORE,(0,0))
def actual_process(label,wire):
    global native_processes
    target=OUT/'processes'/label;target.mkdir(parents=True,exist_ok=False)
    info=dict(label=label,argv=[str(executable)],input=cas(wire),
        environment=dict(PATH='',HOME='/nonexistent/hia-default-json-native-home',LC_ALL='C',TZ='UTC'),
        timeout_seconds=180,limits=dict(cpu_seconds=90,address_space_bytes=1<<30,core_bytes=0),
        executable_sha256=bundle['executable_sha256'],status='INCOMPLETE')
    save(target/'process.json',info)
    before=resource.getrusage(resource.RUSAGE_CHILDREN);t=time.monotonic_ns();proc=None
    stdout=b'';stderr=b''
    try:
        proc=subprocess.Popen([str(executable)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,env=info['environment'],cwd=target,
            start_new_session=True,preexec_fn=native_limits)
        stdout,stderr=proc.communicate(wire,timeout=180)
        info['timed_out']=False
    except subprocess.TimeoutExpired:
        info['timed_out']=True
        os.killpg(proc.pid,signal.SIGKILL)
        stdout,stderr=proc.communicate()
    except BaseException as exc:
        info['transport_exception']=dict(error_class=type(exc).__name__,error=str(exc))
        if proc is not None:
            if proc.poll() is None:os.killpg(proc.pid,signal.SIGKILL)
            stdout,stderr=proc.communicate()
        raise
    finally:
        after=resource.getrusage(resource.RUSAGE_CHILDREN)
        if proc is not None:
            info.update(returncode=proc.returncode,stdout=cas(stdout),stderr=cas(stderr),
                elapsed_ns=time.monotonic_ns()-t,
                cpu_seconds=(after.ru_utime+after.ru_stime-before.ru_utime-before.ru_stime),
                maxrss_kib=after.ru_maxrss,status='COMPLETE')
            save(target/'process.json',info)
    native_processes+=1
    assert not info['timed_out'],label
    return info,stdout,stderr
def input_frame(payload,digits=4300):
    wire,kind=transport(payload)
    return pack(M(b'HIAGFI01'),1,31,73,92,93,kind,digits,91,94,len(wire),0,0,0,0,0)+wire
def actual_outcome(raw,kind,digits,returncode):
    assert len(raw)>=256
    f=struct.unpack_from('<32Q',raw)
    assert f[0]==M(b'HIAGDE01') and f[2:4]==(31,73) and f[4]>0
    assert f[5:9]==(92,93,kind,digits) and f[31]==0
    assert f[10]==0 and f[11:21]==(0,)*10
    payload=raw[256:];assert f[23]==len(payload)
    if returncode==0:
        assert f[1]==0 and f[9]==90 and f[21]==2 and f[24:31]==(0,)*7
        return dict(value=graph_value(payload)),f,payload
    assert returncode==1 and f[1]==3 and f[9]==91 and f[21]==1
    assert 0<len(payload)<=1024 and 1<=f[24]<=7
    cls={1:'AgentRejected',2:'ValueError',3:'OverflowError',4:'UnicodeDecodeError',
         5:'UnicodeEncodeError',6:'JSONDecodeError',7:'RuntimeError'}[f[24]]
    result=dict(error_class=cls,error=payload.decode('utf-8'),code='E_HIA_JSON' if f[24]==1 else None)
    if f[24] in (4,5):result.update(start=f[26],end=f[27])
    if f[24]==6:result.update(pos=f[26],lineno=f[29],colno=f[30])
    return result,f,payload

def component_byte_oracle(wire,kind,digits,label):
    """Independent complete actual seven-image component execution for six views.

    These are new byte-correspondence observations, not inherited nine-group
    component qualification. The original fixture is admitted by complete bytes.
    """
    assert REFERENCE_HARNESS is not None
    original=read(REFERENCE_HARNESS)
    assert (len(original),digest(original))==(30925,'8fc80813b37970f917940549345d880de1115603ce93e31019300e97187b7065')
    keep={'Buffer','View','invoke','grow','configured','frame','values_service',
          'issue_peer','drive'}
    parsed=ast.parse(original)
    selected=[node for node in parsed.body
        if isinstance(node,(ast.FunctionDef,ast.ClassDef)) and node.name in keep]
    assert {node.name for node in selected}==keep
    actual_roles={1:'default_json_raw',2:'default_json_services',3:'default_json_late'}
    values={row['role']:(read(row['image_path']),row['image_sha256'])
        for key,row in bundle['roles'].items() if key!='8'}
    actual_images={name:NativeHiaJsonImage(*value) for name,value in values.items()}
    counts={name:0 for name in actual_images}
    def disabled(*args,**kwargs):
        raise AssertionError('former hosted semantic owner entered component-byte observation')
    namespace=dict(ctypes=ctypes,struct=struct,ExitStack=ExitStack,patch=patch,
        Buffer=Buffer,save=save,cas=cas,OUT=OUT,entries=counts,images=actual_images,
        CANARY=CANARY,BAD=BAD,FBASE=2048,FEND=2304,M=M,pack=pack,ROLES=actual_roles,
        disabled=disabled,json=json,ledger=component_ledger)
    exec(compile(ast.Module(body=selected,type_ignores=[]),str(REFERENCE_HARNESS),'exec'),namespace)
    context=namespace['drive'](wire,kind,digits,label+'.component-byte-oracle')
    assert not context.get('terminal_bad')
    event=context['terminal'];owner,at,size=event[21:24]
    buffer=context['w'] if owner==1 else context['r'] if owner==2 else None
    assert buffer is not None and at<=buffer.n and size<=buffer.n-at
    result=context['w'].raw()[2048:2304]+buffer.raw()[at:at+size]
    for name,count in counts.items():component_entries[name]=component_entries.get(name,0)+count
    # No callback/controller fixture is called by the independent ELF above.
    return result
def byte_reference_cases():
    for i,value in enumerate((b'null',b'{"z":1.25,"a":[-0.0,5e-324]}',
        '{"中":"é😀","s":"1e9999"}',b'[1e9999,1-2.5]',b'',
        b'1'+b'0'*640)):
        yield ('component-complete-bytes-'+str(i),value,640)

def normalized(result):
    if 'value' in result:
        encoded=json.dumps(clean(result['value']),ensure_ascii=True,separators=(',',':')).encode()
        return dict(value=cas(encoded))
    return result
def check(label,payload,digits=4300):
    global cases
    print(json.dumps(dict(event='FIXED_DEFAULT_CASE_START',group=GROUP,label=label,ordinal=cases+1)),flush=True)
    previous=sys.get_int_max_str_digits();sys.set_int_max_str_digits(digits)
    try:
        expected,expected_floats,expected_masks=oracle(payload)
        raw,kind=transport(payload);wire=input_frame(payload,digits)
        process,stdout,stderr=actual_process(label,wire)
        assert stderr==b'',(label,stderr)
        actual,event,result_bytes=actual_outcome(stdout,kind,digits,process['returncode'])
        if GROUP=='byte-reference':
            assert stdout==component_byte_oracle(raw,kind,digits,label),(label,'complete native component bytes')
        if 'value' in expected:
            assert 'value' in actual,(label,expected,actual)
            assert clean(actual['value'])==clean(expected['value']),label
        else:assert actual==expected,(label,expected,actual)
        row=dict(case=cases+1,label=label,input_kind=kind,digits=digits,wire=cas(wire),
            expected=normalized(expected),actual=normalized(actual),actual_event=list(event),
            complete_stdout=cas(stdout),complete_stderr=cas(stderr),result=cas(result_bytes),
            expected_float_lexemes=[cas(x) for x in expected_floats],
            expected_masked_preflight=[cas(x) for x in expected_masks],
            original_oracle_outside_native_process=True)
        rows.write(json.dumps(row,sort_keys=True,ensure_ascii=True)+'\n');rows.flush();cases+=1
        print(json.dumps(dict(event='FIXED_DEFAULT_CASE_PASS',label=label,ordinal=cases)),flush=True)
    finally:sys.set_int_max_str_digits(previous)
def semantic_cases():
    for i,wire in enumerate((b'null',b'true',b'false',b'0',b'-0',b'-18446744073709551617',
        b'1.25',b'-0.0',b'5e-324',b'1e-4000',b'1.7976931348623157e308',
        b'[]',b'{}',b'[1,2.5,true,null,"x"]',b'{"z":1,"a":-0.0,"s":"1e9999"}',
        b'"\\u0000\\ud83d\\ude00"',b'"quote:\\" slash:\\\\ newline:\\n"')):
        yield ('accepted-'+str(i),wire)
    for i,text in enumerate(('é中😀','"é中😀"','{"中":1.5,"😀":[0,-2]}')):
        yield ('unicode-text-'+str(i),text)
        yield ('unicode-bytes-'+str(i),text.encode('utf-8'))
    for i,wire in enumerate((b'',b' ',b'01',b'1.',b'1e',b'NaN',b'Infinity',b'[0,NaN]',
        b'{"a":1,"a":2}',b'"\\ud800"',b'"\\x"',b'[1,]',b'{"a":}',
        b'1e9999',b'[1e9999,1-2.5]',b'[1e-9999,1-2.5]',b'[1-2.5,1e9999]',
        b'{"a":1e9999,"b":1-2.5}',b'{"a":1-2.5,"b":1e9999}',b'[1e9999]x')):
        yield ('ordered-refusal-'+str(i),wire)
    for i,value in enumerate((None,0,1.0,[],{},bytearray(b'0'))):
        yield ('wrong-input-type-'+str(i),value)
def unicode_cases():
    values=(b'\xff',b'\xc0\x80',b'\xc2',b'\xc2A',b'\xe0\xa0',b'\xe0\xa0A',
        b'\xed\xa0\x80',b'\xf0\x90\x80',b'\xf4\x90\x80\x80',
        b'abc\xff',b'"\xc3\xa9\xff',b'\xef\xbb\xbf0')
    for i,value in enumerate(values):yield ('raw-utf8-'+str(i),value)
    for i,value in enumerate(('\ud800','\udfff','x\ud800\udfffz','é😀\udc80','"é\ud800"')):
        yield ('text-surrogate-'+str(i),value)
def boundaries():
    for digits in (640,4300):
        for count in (digits-1,digits,digits+1):
            yield ('decimal-'+str(digits)+'-'+str(count),b'1'+b'0'*(count-1),digits)
        long=b'1'+b'0'*digits
        yield ('decimal-before-syntax-'+str(digits),long+b'-2.5',digits)
        yield ('float-before-decimal-'+str(digits),b'[1e9999,'+long+b']',digits)
    yield ('no-decimal-limit',b'1'+b'0'*9999,0)
    for depth in (127,128,129):
        yield ('array-depth-'+str(depth),b'['*depth+b'0'+b']'*depth)
        yield ('object-depth-'+str(depth),b'{"a":'*depth+b'0'+b'}'*depth)
    yield ('depth-before-float',b'['*129+b'1e9999'+b']'*129)
def large_cases():
    if GROUP=='large-values':
        yield ('exact-eight-mib-string',b'"'+b'x'*(8388608-2)+b'"')
    elif GROUP=='large-order':
        yield ('over-budget-utf8-first',b'x'*8388608+b'\xff')
        yield ('over-budget-valid-text','é'*(4194304+1))
    elif GROUP=='large-nodes':
        yield ('exact-262144-nodes',b'['+b'0,'*262142+b'0]')
        yield ('nodes-plus-one',b'['+b'0,'*262143+b'0]')
    else:raise AssertionError(GROUP)
class Buffer:
    def __init__(self,n,raw=b''):
        self.n=n;self.buf=ctypes.create_string_buffer(n+128)
        self.p=ctypes.addressof(self.buf)+64
        ctypes.memmove(self.p-64,CANARY,64);ctypes.memmove(self.p+n,CANARY,64)
        if raw:ctypes.memmove(self.p,raw,len(raw))
    def raw(self):return ctypes.string_at(self.p,self.n)
    def write(self,at,raw):
        assert 0<=at<=self.n and len(raw)<=self.n-at
        if raw:ctypes.memmove(self.p+at,raw,len(raw))
    def guard(self):
        assert ctypes.string_at(self.p-64,64)==CANARY and ctypes.string_at(self.p+self.n,64)==CANARY
def controller(image,label,command,w,n=None,o_size=128):
    global private_entries
    source=Buffer(len(command),command);o=Buffer(o_size)
    sb,wb=source.raw(),w.raw();n=w.n if n is None else n
    save(OUT/'pending-private-entry.json',dict(label=label,ordinal=private_entries+1,
        source=cas(sb),workspace_before=cas(wb),advertised_workspace=n,output_bytes=o_size))
    actual=int(image._entry(source.p,source.n,o.p,o.n,w.p,n));private_entries+=1
    assert source.raw()==sb
    for b in (source,o,w):b.guard()
    ledger.write(json.dumps(dict(entry=private_entries,label=label,returned=actual,
        source=cas(sb),workspace_before=cas(wb),workspace_after=cas(w.raw()),
        output_after=cas(o.raw()),advertised_workspace=n),sort_keys=True)+'\n');ledger.flush()
    return actual,o.raw()
def protocol_cases():
    global cases,planned
    start=pack(M(b'HIAWDI01'),1,129,0,0,0,0,0)
    accepted_header=input_frame(b'0')[:128]
    original=pack(M(b'HIACDA01'),1,1,14,0,0,128,0)+accepted_header
    tests=[]
    for index,value in ((0,0),(1,2),(2,0),(3,1),(4,1),(5,1),(6,127),(7,1)):
        changed=bytearray(original);struct.pack_into('<Q',changed,index*8,value)
        tests.append(('ack-'+str(index),bytes(changed)))
    for index,value in ((0,0),(1,2),(2,0),(3,0),(4,0),(5,0),(7,639),(8,0),(9,0),
                        (10,2),(11,1),(12,1),(13,1),(14,1),(15,1)):
        changed=bytearray(original);struct.pack_into('<Q',changed,64+index*8,value)
        tests.append(('private-header-'+str(index),bytes(changed)))
    tests.append(('short-ack',original[:-1]));tests.append(('long-ack',original+b'\0'))
    planned=len(tests)+3
    image=NativeHiaJsonImage(driver_image,driver_row['image_sha256'])
    for label,command in tests:
        w=Buffer(65536)
        status,event=controller(image,label+'.initial',start,w)
        assert status==128 and struct.unpack_from('<4Q',event)==(M(b'HIACDE01'),14,1,1)
        assert controller(image,label,command,w)[0]==BAD
        poisoned=w.raw()
        assert controller(image,label+'.poison',original,w)[0]==BAD and w.raw()==poisoned
        rows.write(json.dumps(dict(label=label,status='PASS',private_foreign_ack_fixture=True))+'\n');rows.flush();cases+=1
    w=Buffer(65536);before=w.raw()
    assert controller(image,'short-workspace',start,w,65535)[0]==BAD and w.raw()==before
    rows.write(json.dumps(dict(label='short-workspace-retired',status='PASS',native_poison_not_claimed=True))+'\n');cases+=1
    w=Buffer(65536)
    assert controller(image,'short-output',start,w,o_size=127)[0]==BAD
    assert controller(image,'short-output-poison',start,w)[0]==BAD
    rows.write(json.dumps(dict(label='short-output',status='PASS'))+'\n');cases+=1
    w=Buffer(65536)
    assert controller(image,'valid-initial',start,w)[0]==128
    status,event=controller(image,'valid-header',original,w)
    assert status==128 and struct.unpack_from('<6Q',event)==(M(b'HIACDE01'),2,1,2,4,1)
    wrong=pack(M(b'HIACDA01'),1,1,2,0,0,0,0)
    assert controller(image,'wrong-next-sequence',wrong,w)[0]==BAD
    rows.write(json.dumps(dict(label='valid-prefix-then-replayed-sequence',status='PASS'))+'\n');cases+=1
def framing_cases():
    good=input_frame(b'0');values=[('empty-input',b''),('short-header',good[:127]),
        ('missing-body',good[:-1]),('extra-body',good+b'0')]
    for word,value in ((0,0),(1,2),(2,0),(3,0),(4,0),(5,0),(7,639),(8,0),(9,0),
                       (10,0),(11,1),(12,1),(13,1),(14,1),(15,1)):
        changed=bytearray(good);struct.pack_into('<Q',changed,word*8,value)
        values.append(('private-field-'+str(word),bytes(changed)))
    return values
try:
    read(__file__)
    for path in sorted((ROOT/'tools').glob('*')):
        if path.is_file():read(path)
    for relative in ('hepta/hia_agent_store.py','hepta/hia_json_preflight.py',
        'hepta/hia_json_preflight_native.py','hepta/hia_agent_data_json_native.py',
        'hepta/hia_agent_binary64_native.py'):
        read(REFERENCE/relative)
    bundle=json.loads(read(BUILD/'bundle.json'))
    assert bundle['schema']=='hia-default-json-fixed-development-bundle-v1' and bundle['status']=='PASS'
    assert set(bundle['roles'])==set(map(str,range(1,9))) and bundle['compiler_sha256']==COMPILER
    for role,row in bundle['roles'].items():
        source=read(row['source_path']);image=read(row['image_path']);receipt=json.loads(read(row['receipt_path']))
        assert (len(source),digest(source))==(row['source_bytes'],row['source_sha256'])
        assert (len(image),digest(image))==(row['image_bytes'],row['image_sha256'])
        assert receipt['input_sha256']==digest(source) and receipt['produced_sha256']==digest(image)
        assert receipt['image_sha256']==COMPILER
    executable=Path(bundle['executable_path']).resolve();raw=read(executable)
    assert (len(raw),digest(raw))==(bundle['executable_bytes'],bundle['executable_sha256'])
    assert modes[executable]==0o755
    read(bundle['executor_path']);assert digest(read(bundle['executor_path']))==bundle['executor_sha256']
    driver_row=bundle['roles']['8'];driver_image=read(driver_row['image_path'])
    assert unchanged();save(OUT/'source-before.json',pinrows())
    if GROUP=='protocol':protocol_cases()
    elif GROUP=='framing':
        values=framing_cases();planned=len(values)
        for label,wire in values:
            process,stdout,stderr=actual_process(label,wire)
            assert (process['returncode'],stdout,stderr)==(126,b'',b''),label
            rows.write(json.dumps(dict(case=cases+1,label=label,status='PASS',input=cas(wire)))+'\n')
            rows.flush();cases+=1
    else:
        factories={'semantic':semantic_cases,'unicode':unicode_cases,'boundaries':boundaries,
                   'byte-reference':byte_reference_cases}
        values=list(factories[GROUP]() if GROUP in factories else large_cases());planned=len(values)
        for row in values:check(*row)
    assert cases==planned
    status='PASS'
except BaseException as exc:
    failure=dict(error_class=type(exc).__name__,error=str(exc));traceback.print_exc()
finally:
    rows.close();ledger.close();component_ledger.close();same=unchanged()
    if not same:status='FAIL'
    summary=dict(status=status,group=GROUP,cases=cases,planned_cases=planned,
        actual_native_processes=native_processes,actual_private_controller_entries=private_entries,
        new_component_byte_oracle_entries=component_entries,
        failure=failure,source_unchanged=same,elapsed_ns=time.monotonic_ns()-started,
        original_limits=dict(child_cpu_seconds=90,child_wall_seconds=180,address_space_bytes=1<<30),
        empty_PATH_HOME=True,runtime_python_dispatch=False,whole_worker_closed=False,
        namespace_effects=0,production_activation=False,previous_component_results_inherited=False)
    save(OUT/'source-after.json',pinrows());save(OUT/'summary.json',summary)
    print(json.dumps(summary,sort_keys=True),flush=True)
if status!='PASS':raise SystemExit(1)
