"""Independent packet semantics; consumes no producer expectations."""
import base64,binascii,bisect,random
SENTINEL=0xFFEEDDCCBBAA9988
MAX=(1<<64)-1

def expected(wire,start,end,scratch_size,scalar_size,query):
    scratch=[165]*scratch_size; scalars=[SENTINEL]*scalar_size
    def result(stage,count=0,lower=0,upper=0):
        return {'stage':stage,'count':count,'lower':lower,'upper':upper,'scratch':scratch,'scalars':scalars}
    if not 0<=start<=end<=len(wire):return result(1)
    segment=wire[start:end]
    try:raw=base64.b64decode(segment,validate=True)
    except (ValueError,binascii.Error):return result(1)
    if base64.b64encode(raw)!=segment or scratch_size<1 or len(raw)>scratch_size-1:return result(1)
    scratch[1:1+len(raw)]=raw
    if len(raw)<2:return result(2)
    if int.from_bytes(raw[:2],'big')!=len(raw)-2:return result(3)
    try:text=raw[2:].decode('utf8','strict')
    except UnicodeDecodeError:return result(4)
    if scalar_size<1 or len(text)>scalar_size-1:return result(5)
    values=sorted(map(ord,text));scalars[1:1+len(values)]=values
    return result(0,len(text),1+bisect.bisect_left(values,query),1+bisect.bisect_right(values,query))

def raw_case(raw,query=0,scratch=None,scalars=20):
    wire=b'\xff'+base64.b64encode(raw)+b'\xff'
    return (wire,1,len(wire)-1,len(raw)+3 if scratch is None else scratch,scalars,query)

def cases():
    out=[];rng=random.Random(708709)
    pool=[0,1,97,233,127,128,2047,2048,0xD7FF,0xE000,0xFFFF,0x10000,0x10FFFF]
    for n in range(64):
        text=''.join(chr(rng.choice(pool)) for _ in range(n%13))
        raw=text.encode();out.append(raw_case(len(raw).to_bytes(2,'big')+raw,rng.choice(pool+[MAX]),scalars=len(text)+3))
    for raw in [b'',b'\0',b'\0\1',b'\0\0x',b'\xff\xffx']:
        out.append(raw_case(raw))
    for bad in [b'\x80',b'\xc0\x80',b'\xe0\x80\x80',b'\xed\xa0\x80',b'\xf4\x90\x80\x80',b'\xf5\x80\x80\x80',b'\xe2\x82']:
        for prefix in [b'',b'valid']:
            raw=prefix+bad;out.append(raw_case(len(raw).to_bytes(2,'big')+raw))
    for segment in [b'A',b'AA',b'AAA',b'AA-_',b'AA==AAAA',b'Zh==',b'Zm9=',b'AA==\n',b'AAAA====',b'A\xffAA']:
        w=b'\xff'+segment+b'\xff';out.append((w,1,len(w)-1,24,20,0))
    for text in ['', 'a','éa😀']:
        raw=text.encode();data=len(raw).to_bytes(2,'big')+raw
        for scratch in range(1,len(data)+3):
            for scalar in range(1,len(text)+3):out.append(raw_case(data,97,scratch,scalar))
    w=base64.b64encode(b'\0\1a')
    for start,end in [(2,1),(0,len(w)+1),(MAX,MAX),(MAX,0),(0,MAX),(0,0),(len(w),len(w))]:out.append((w,start,end,10,5,97))
    return out

# Native harness keeps every aggregate inside Hepta and exposes only process
# status. All observed fields, payloads, and buffer elements are scalar checks.
def case_source(case,index):
    wire,start,end,ns,nv,query=case; want=expected(*case)
    arr=lambda xs:'['+','.join(map(str,xs))+']'
    s=[f'fn case{index}() -> Unit effects {{ panic, write }} {{',
       f'let input: [u8; {len(wire)}] = {arr(wire)};',
       f'let mut scratch: [u8; {ns}] = {arr([165]*ns)};',
       f'let mut scalars: [u64; {nv}] = {arr([SENTINEL]*nv)};',
       f'let result = typed::index_packet(read input, {start}, {end}, mut scratch, mut scalars, {query});',
       'match result {',
       f'Result::Ok(c) => {{ let done = c.done; assert({str(want["stage"]==0).lower()}); assert(c.value.scalars == {want["count"]}); assert(c.value.lower == {want["lower"]}); assert(c.value.upper == {want["upper"]}); }},',
       'Result::Err(e) => { match e {']
    for stage,variant in enumerate(['Decode','ShortHeader','LengthMismatch','InvalidText','ScalarCapacity'],1):
        payload=f'assert(p == {nv});' if stage==5 else 'let unit = p;'
        s.append(f'typed::PacketError::{variant}(p) => {{ {payload} assert({str(want["stage"]==stage).lower()}); }},')
    s+=['} }','}']
    for name,values in [('input',wire),('scratch',want['scratch']),('scalars',want['scalars'])]:
        s += [f'assert({name}[{i}] == {v});' for i,v in enumerate(values)]
    return '\n'.join(s+['}'])

def source(cases):
    return 'import typed;\n'+'\n'.join(case_source(c,i) for i,c in enumerate(cases))+'\nfn main() -> Unit effects { panic, write } {\n'+'\n'.join(f'case{i}();' for i in range(len(cases)))+'\n}\n'

def run(root):
    import collections,hashlib,json,os,pathlib,shutil,signal,subprocess,sys,tempfile
    root=pathlib.Path(root).resolve();sys.path.insert(0,str(root))
    from hepta.pipeline import analyze_project
    from hepta.packages import write_lock
    from hepta.c_backend import compile_c
    receipts=[];data=cases()
    bound=[root/'examples/packages/typed_packet/src/lib.hepta',root/'examples/packages/typed_packet/src/packet.hepta']
    bound += sorted((root/'stdlib').glob('*/src/lib.hepta'))
    before={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in bound}
    with tempfile.TemporaryDirectory(prefix='hepta-independent-typed-') as tmp:
        p=pathlib.Path(tmp);shutil.copytree(root/'stdlib',p/'stdlib')
        shutil.copytree(root/'examples/packages/typed_packet',p/'examples/packages/typed_packet')
        app=p/'examples/packages/typed_text';(app/'src').mkdir(parents=True)
        (app/'hepta.toml').write_text('[package]\nname="independent_typed"\nversion="0.1.0"\nkind="bin"\n[dependencies]\ntyped={path="../typed_packet"}\n')
        wrapper=p/'examples/packages/typed_packet/src/lib.hepta';original=wrapper.read_text()
        def execute(vectors,label,negative=False):
            (app/'src/main.hepta').write_text(source(vectors));write_lock(app)
            analysis=analyze_project(app,backend='c',locked=True,crate_type='bin')
            assert analysis.report['ok'],analysis.report
            for optimize in (False,True):
                build=compile_c(analysis.c,output=p/'probe',optimize=optimize,sanitize=True)
                assert build['ok'],build
                assert '-fsanitize=undefined' in build['flags'] and '-fno-sanitize-recover=all' in build['flags']
                result=subprocess.run([str(p/'probe')],capture_output=True,timeout=30)
                assert (result.returncode,result.stdout,result.stderr)==(-signal.SIGABRT if negative else 0,b'',b''),(label,result.returncode,result.stdout,result.stderr)
                receipts.append({'label':label,'vectors':len(vectors),'optimized':optimize,'negative':negative,'returncode':result.returncode,'artifact_sha256':build['artifact_sha256'],'source_sha256':build.get('source_sha256'),'flags':build['flags'],'toolchain':build['toolchain']})
        for i in range(0,len(data),16):execute(data[i:i+16],f'cases-{i}-{min(i+16,len(data))}')
        controls=[
            ('success-bound','lower: result.lower','lower: result.lower + 1',next(c for c in data if expected(*c)['stage']==0)),
            ('error-tag','PacketError::Decode(done())','PacketError::ShortHeader(done())',next(c for c in data if expected(*c)['stage']==1)),
            ('error-payload','ScalarCapacity(len(read scalars))','ScalarCapacity(len(read scalars) + 1)',next(c for c in data if expected(*c)['stage']==5)),
            ('prefix-canary','assert(result.stage == 0);','assert(result.stage == 0); scratch[0] = 0;',next(c for c in data if expected(*c)['stage']==0)),
        ]
        for label,old,new,case in controls:
            assert original.count(old)==1
            wrapper.write_text(original.replace(old,new));execute([case],label,negative=True);wrapper.write_text(original)
    assert before=={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in bound}
    report={'complete_pass':True,'python':sys.version,'vectors':len(data),'stages':dict(collections.Counter(expected(*c)['stage'] for c in data)),'native_runs':len(receipts),'negative_controls':4,'source_sha256':before,'receipts':receipts}
    print(json.dumps(report,sort_keys=True));return report

if __name__=='__main__':
    import pathlib,sys
    if not __debug__:raise SystemExit('Assertions must remain enabled')
    run(sys.argv[1] if len(sys.argv)>1 else pathlib.Path(__file__).resolve().parents[1])
