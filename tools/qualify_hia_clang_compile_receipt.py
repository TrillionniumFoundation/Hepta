"""Native Clang-success receipt vs the exact original Python return expression.

These are deterministic formatter gates over captured-state fixtures. They do
not claim that fixture bytes were compiled, loaded or executed. The enclosing
Clang producer has separate mandatory native process/inventory/publication gates.
"""
from pathlib import Path
from types import SimpleNamespace
import argparse,ast,copy,ctypes as C,hashlib,inspect,json,mmap,struct,sys
import hepta.hia_program_llvm as original
from hepta.hia_entry_layout import CANONICAL,LAYOUT
from tools import generate_hia_clang_compile_common as common
from tools import qualify_hia_generation_lease_owner as native
K=common.C
BAD=4294967293;SHORT=4294967294
TARGETS=[original.TARGET,original.TARGET_AARCH64,original.TARGET_RISCV64]
def pin(b):return dict(bytes=len(b),sha256=hashlib.sha256(b).hexdigest())
def u64(b,at):return struct.unpack_from('<Q',b,at)[0]
def word(b,at,v):struct.pack_into('<Q',b,at,v)
def raw_name(value):return value if isinstance(value,bytes)else value.encode('ascii')
def names(values):return b''.join(struct.pack('<Q',len(raw_name(v)))+raw_name(v)for v in values)
def return_expression(function):
    node=ast.parse(inspect.getsource(function)).body[0]
    values=[n.value for n in node.body if isinstance(n,ast.Return)]
    assert len(values)==1
    return compile(ast.Expression(copy.deepcopy(values[0])),inspect.getsourcefile(function),'eval')
RETURN=return_expression(original.compile_program_llvm)
INVENTORY_RETURN=return_expression(original.inspect_owned_shared_elf)
HOST_NODE=ast.parse(inspect.getsource(original.native_host_profile)).body[0]
HOST_CODE=compile(ast.Module(body=[HOST_NODE],type_ignores=[]),inspect.getsourcefile(original.native_host_profile),'exec')
def host_oracle(machine):
    namespace=dict(platform=SimpleNamespace(machine=lambda:machine,system=lambda:'Linux'),ctypes=C,sys=sys,
                   TARGET=original.TARGET,TARGET_AARCH64=original.TARGET_AARCH64,_reject=original._reject)
    exec(HOST_CODE,namespace)
    return namespace['native_host_profile']()
def profile(schema,target):
    if target==2:return original._RISCV64_PROFILES[schema]
    prefix='PROFILE_AARCH64'if target==1 else'PROFILE'
    return getattr(original,prefix+('_V'+str(schema)if schema!=1 else''))
class Fixture:
    def __init__(self,*,schema=1,target=0,host=0,kind=0,layout=0,multicall=0,input_present=1,
                 exports=('alpha','omega'),imports=('abort','malloc'),inv_exports=None,
                 compiler=b'/usr/bin/clang-actual',destination=b'/tmp/hia-output/result.so',
                 version=b'clang version 20.1.0\nTarget: x86_64-pc-linux-gnu\n',driver=None,machine=None,artifact_n=4096):
        self.schema=schema;self.target=target;self.host=host;self.kind=kind;self.layout=layout
        self.multicall=multicall;self.input_present=input_present;self.exports=list(exports);self.imports=list(imports)
        self.compiler=compiler;self.destination=destination;self.version=version
        self.driver=driver if driver is not None else (b'x86_64-pc-linux-gnu\n'if host==0 else b'aarch64-unknown-linux-gnu\n')
        self.machine=machine or('x86_64'if host==0 else'aarch64')
        self.artifact_n=artifact_n;self.work=mmap.mmap(-1,K['P_WORK'])
        self.hashes={name:hashlib.sha256((name+str((schema,target,kind,layout))).encode()).digest()
                     for name in ['P_CORE_SHA','P_IR_SHA','P_IMPL_SHA','P_TOOL_SHA','P_ART_SHA','P_INPUT_SHA']}
        for name,data in self.hashes.items():self.work[K[name]:K[name]+32]=data
        actual_exports=self.exports if inv_exports is None else list(inv_exports)
        inv_body=names(actual_exports)+names(self.imports)
        inv=struct.pack('<8Q',int.from_bytes(b'HIAINV01','little'),len(actual_exports),len(self.imports),64+len(inv_body),0,0,0,0)+inv_body
        comp_at=0;dest_at=len(compiler);inv_at=(dest_at+len(destination)+7)&-8
        self.data=bytearray(compiler+destination+bytes(inv_at-dest_at-len(destination))+inv)
        meta_body=names(self.exports);meta=struct.pack('<8Q',K['META_REPLY'],schema,target,layout,len(self.exports),12345,len(meta_body),0)+meta_body
        self.work[K['P_META']:K['P_META']+len(meta)]=meta
        self.work[K['P_VERSION']:K['P_VERSION']+len(version)]=version
        self.work[K['P_DRIVER']:K['P_DRIVER']+len(self.driver)]=self.driver
        uname=b''.join(x.ljust(65,b'\0')for x in [b'Linux',b'actual-test-host',b'6.test',b'native-format-fixture',self.machine.encode(),b'(none)'])
        assert len(uname)==390;self.work[K['P_UNAME']:K['P_UNAME']+390]=uname
        for key,value in dict(P_SCHEMA=schema,P_TARGET=target,P_HOST=host,P_KIND=kind,P_LAYOUT=layout,
             P_MULTICALL=multicall,P_INPUT_HASH_PRESENT=input_present,P_ART_N=artifact_n,
             P_COMPILER_OFF=comp_at,P_COMPILER_N=len(compiler),P_DEST_OFF=dest_at,P_DEST_N=len(destination),
             P_INV_OFF=inv_at,P_INV_N=len(inv),P_META_N=len(meta),P_IR_N=12345,
             P_VERSION_N=len(version),P_DRIVER_N=len(self.driver)).items():word(self.work,K[key],value)
    def close(self):self.work.close()
    def snapshot(self):
        return [bytes(self.work[a:a+n])for a,n in [(0,2048),(K['P_UNAME'],390),(K['P_META'],65536),(K['P_VERSION'],196608),(K['P_DRIVER'],196608)]]
    def oracle(self):
        h=host_oracle(self.machine);target=TARGETS[self.target]
        flags=['--target='+target,'-x','ir','-O3','-fPIC','-shared'if self.kind==0 else'-c']
        if self.target==2:flags+=['-march=rv64gc','-mabi=lp64d']
        compiler=self.compiler.decode('utf-8','surrogateescape');destination=self.destination.decode('utf-8','surrogateescape')
        invocation=[compiler]+(['clang']if self.multicall else[])
        if self.kind==0:
            inventory=eval(INVENTORY_RETURN,{},dict(exports=set(self.exports),undefined=set(self.imports)))
        else:inventory=dict(defined=sorted(self.exports),undefined=sorted(self.imports))
        ir=SimpleNamespace(profile=profile(self.schema,self.target),target=target,
                           layout=CANONICAL if self.layout==0 else LAYOUT,core_sha256=self.hashes['P_CORE_SHA'].hex(),
                           input_sha256=self.hashes['P_INPUT_SHA'].hex()if self.input_present else None,
                           sha256=self.hashes['P_IR_SHA'].hex(),implementation_sha256=self.hashes['P_IMPL_SHA'].hex(),
                           exports=tuple(self.exports))
        values=dict(ir=ir,kind='shared'if self.kind==0 else'object',destination=destination,host=h,
                    published=dict(sha256=self.hashes['P_ART_SHA'].hex(),bytes=self.artifact_n),
                    inventory=inventory,compiler=compiler,compiler_digest=self.hashes['P_TOOL_SHA'].hex(),
                    invocation=invocation,version=SimpleNamespace(stdout=self.version.decode('utf-8')),
                    target=SimpleNamespace(stdout=self.driver.decode('utf-8')),flags=flags)
        return eval(RETURN,{},values)
class Runner:
    def __init__(self,flat):
        self.image=native.old.Image(flat);self.calls=0;self.comparisons=0
    def call(self,fixture,capacity=1048576,work_n=None):
        source=C.create_string_buffer(bytes(fixture.data));output=C.create_string_buffer(bytes([165])*(capacity+16))
        before=fixture.snapshot()
        rc=int(self.image.entry(source,len(fixture.data),output,capacity,native.address(fixture.work),
                                K['P_WORK']if work_n is None else work_n));self.calls+=1
        assert source.raw==bytes(fixture.data)+b'\0' and output.raw[capacity:capacity+16]==bytes([165])*16
        assert fixture.snapshot()==before,'native formatter changed captured producer observations'
        if rc in(BAD,SHORT):
            assert output.raw[:capacity]==bytes([165])*capacity,'rejected receipt wrote public output'
            return rc,b''
        assert 0<rc<=capacity,(rc,capacity)
        return rc,output.raw[:rc]
    def equal(self,fixture):
        rc,raw=self.call(fixture);actual=json.loads(raw);expected=fixture.oracle()
        assert actual==expected,dict(actual=actual,expected=expected,rc=rc)
        assert actual['claims']['native_execution_qualified']is False
        assert actual['claims']['backend_refinement_proved']is False
        self.comparisons+=1
        return rc,pin(raw)
def matrix(run):
    checked=[]
    for schema in range(1,10):
        for target in range(3):
            for host in range(2):
                for kind in range(2):
                    if target!=0 and kind==0:continue
                    if host!=0 and kind==0:continue
                    for layout in range(2 if target==0 else 1):
                        f=Fixture(schema=schema,target=target,host=host,kind=kind,layout=layout,
                                  multicall=(schema+target+host+kind+layout)%2,input_present=schema%2)
                        try:n,digest=run.equal(f)
                        finally:f.close()
                        checked.append(dict(schema=schema,target=target,host=host,kind=kind,layout=layout,bytes=n))
    return dict(passed=True,comparisons=len(checked),profiles_and_targets=checked)
def unicode_fields(run):
    rows=[]
    samples=[
        dict(compiler=b'/tmp/quote"back\\slash/llvm',destination=b'/tmp/line\nbreak/tab\tresult.so',multicall=1),
        dict(compiler=b'/tmp/raw-\xff-\xed\xa0\x80/clang',destination=b'/tmp/raw-\x80-\xc0\xaf-output.so'),
        dict(compiler='/tmp/编译器-🦉/clang'.encode(),destination='/tmp/目录/é-🙂.so'.encode()),
        dict(version='clang version 20.1.0\u0085second line'.encode(),driver='\u3000\u0085x86_64-pc-linux-gnu\u2007\u202f'.encode()),
        dict(version='clang version 20.1.0\u2028second line'.encode(),driver='\x1cx86_64-pc-linux-gnu\x1f'.encode()),
        dict(version='\nclang version 20.1.0'.encode(),driver=b'  x86_64-pc-linux-gnu \r\n'),
        dict(version='clang version 20.1.0\x00with NUL\nignored'.encode(),driver=b'x86_64-pc-linux-gnu\n'),
        dict(machine='AMD64'),dict(host=1,target=1,kind=1,machine='ARM64'),
        dict(version=b'clang version 20.0.0 '+b'\xef\xbf\xbd'*(65536-21)),
        dict(version=b'clang version 20.0.0 '+b'\xef\xbf\xbd'*(65536-21),driver=b'x86_64-pc-linux-gnu'+b'\xef\xbf\xbd'*(65536-19))
    ]
    for i,kwargs in enumerate(samples):
        f=Fixture(**kwargs)
        try:n,d=run.equal(f)
        finally:f.close()
        rows.append(dict(index=i,bytes=n,receipt=d))
    return dict(passed=True,comparisons=len(rows),cases=rows,fs_surrogateescape=True,unicode_splitlines_and_strip=True)
def inventory_limits(run):
    rows=[]
    for count in (0,1,128):
        exports=tuple('fn_%03d_'%i+'x'*100 for i in range(count))
        f=Fixture(exports=exports,imports=(),kind=1,artifact_n=67108864)
        try:n,d=run.equal(f)
        finally:f.close()
        rows.append(dict(exports=count,bytes=n,receipt=d))
    f=Fixture(imports=('A"quote','B\\backslash','abort'))
    try:n,d=run.equal(f)
    finally:f.close()
    rows.append(dict(import_escaping=True,receipt=d))
    return dict(passed=True,comparisons=len(rows),cases=rows)
def invalid_inputs(run):
    rows=[]
    configs=[
      ('schema-zero',dict(schema=0)),('schema-ten',dict(schema=10)),('target-three',dict(target=3)),
      ('host-two',dict(host=2)),('kind-two',dict(kind=2)),('layout-two',dict(layout=2)),
      ('cross-shared',dict(target=1,kind=0)),('arm-outline',dict(target=1,kind=1,layout=1)),
      ('host-arm-shared',dict(host=1,kind=0)),('multicall-two',dict(multicall=2)),
      ('input-presence-two',dict(input_present=2)),('artifact-small',dict(artifact_n=63)),
      ('artifact-large',dict(artifact_n=67108865)),('compiler-relative',dict(compiler=b'clang')),
      ('compiler-nul',dict(compiler=b'/tmp/a\0b')),('destination-relative',dict(destination=b'result.so')),
      ('version-empty',dict(version=b'')),('version-invalid-utf8',dict(version=b'clang \xff')),
      ('driver-empty',dict(driver=b'')),('driver-whitespace',dict(driver='\u3000\u0085'.encode())),
      ('driver-invalid-utf8',dict(driver=b'x86_64-\xed\xa0\x80')),
      ('host-mismatch',dict(machine='aarch64')),('unknown-machine',dict(machine='mips64')),
      ('meta-unsorted',dict(exports=('omega','alpha'))),('meta-duplicate',dict(exports=('alpha','alpha'))),
      ('meta-nonidentifier',dict(exports=('alpha-bad',))),('meta-too-many',dict(exports=tuple('f%03d'%i for i in range(129)))),
      ('inventory-unsorted',dict(inv_exports=('omega','alpha'))),('inventory-mismatch',dict(inv_exports=('alpha','sigma'))),
      ('import-duplicate',dict(imports=('abort','abort'))),('import-unsorted',dict(imports=('malloc','abort'))),
      ('import-invalid-ascii',dict(imports=(b'\xffbad',))),('import-nul',dict(imports=(b'a\0b',)))
    ]
    for name,kwargs in configs:
        f=Fixture(**kwargs)
        try:rc,_=run.call(f);assert rc==BAD,(name,rc)
        finally:f.close()
        rows.append(name)
    mutations=[
       ('producer-error',lambda f:word(f.work,16,7)),
       ('compiler-overflow',lambda f:word(f.work,K['P_COMPILER_OFF'],(1<<64)-1)),
       ('destination-overflow',lambda f:word(f.work,K['P_DEST_N'],(1<<64)-1)),
       ('meta-magic',lambda f:word(f.work,K['P_META'],0)),
       ('meta-reserved',lambda f:word(f.work,K['P_META']+56,1)),
       ('meta-length',lambda f:word(f.work,K['P_META_N'],63)),
       ('meta-body-length',lambda f:word(f.work,K['P_META']+48,1)),
       ('meta-target-mismatch',lambda f:word(f.work,K['P_META']+16,1)),
       ('meta-layout-mismatch',lambda f:word(f.work,K['P_META']+24,1)),
       ('meta-ir-length',lambda f:word(f.work,K['P_META']+40,123)),
       ('meta-name-overflow',lambda f:word(f.work,K['P_META']+64,(1<<64)-1)),
       ('inventory-offset-overflow',lambda f:word(f.work,K['P_INV_OFF'],(1<<64)-1)),
       ('inventory-length-overflow',lambda f:word(f.work,K['P_INV_N'],(1<<64)-1)),
       ('inventory-magic',lambda f:word(f.data,u64(f.work,K['P_INV_OFF']),0)),
       ('inventory-reserved',lambda f:word(f.data,u64(f.work,K['P_INV_OFF'])+32,1)),
       ('inventory-size',lambda f:word(f.data,u64(f.work,K['P_INV_OFF'])+24,64)),
       ('inventory-count',lambda f:word(f.data,u64(f.work,K['P_INV_OFF'])+16,(1<<64)-1)),
       ('inventory-name-overflow',lambda f:word(f.data,u64(f.work,K['P_INV_OFF'])+64,(1<<64)-1)),
       ('version-beyond-region',lambda f:word(f.work,K['P_VERSION_N'],196609)),
       ('driver-beyond-region',lambda f:word(f.work,K['P_DRIVER_N'],196609)),
       ('non-linux',lambda f:f.work.__setitem__(K['P_UNAME'],ord('W')))]
    for name,mutate in mutations:
        f=Fixture()
        try:
            mutate(f);rc,_=run.call(f);assert rc==BAD,(name,rc)
        finally:f.close()
        rows.append(name)
    return dict(passed=True,controls=len(rows),cases=rows,rejected_without_public_output_writes=True)
def capacities(run):
    f=Fixture()
    try:
        n,_=run.equal(f)
        rc,raw=run.call(f,n);assert rc==n and json.loads(raw)==f.oracle()
        for size in (0,1,n-1):
            rc,_=run.call(f,size);assert rc==SHORT,(size,rc)
        rc,_=run.call(f,1048577);assert rc==BAD
        rc,_=run.call(f,work_n=K['P_WORK']-1);assert rc==BAD
    finally:f.close()
    large=Fixture(compiler=b'/tmp/'+b'\xff'*100000+b'/clang')
    try:rc,_=run.call(large);assert rc==SHORT,rc
    finally:large.close()
    return dict(passed=True,exact_capacity=n,short_capacities=[0,1,n-1],output_limit=1048576,
                no_partial_output_on_capacity_failure=True,full_captured_state_unchanged=True)
def source_shape(run):
    f=Fixture(version=b'clang version 20.0.0\r\nTarget: x86_64\n',driver=b'\tx86_64-pc-linux-gnu\t')
    try:n,d=run.equal(f)
    finally:f.close()
    return dict(passed=True,receipt=d,exact_original_return_expression=True,
                native_implementation_sha_is_captured_catalog_digest=True,
                success_receipt_grants_no_execution_or_refinement_qualification=True)
CASES={'matrix':matrix,'unicode-fields':unicode_fields,'inventory-limits':inventory_limits,
       'invalid-inputs':invalid_inputs,'capacities':capacities,'source-shape':source_shape}
def main():
    p=argparse.ArgumentParser();p.add_argument('--flat',type=Path,required=True);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cases',default=','.join(CASES));a=p.parse_args();a.output.mkdir(parents=True,exist_ok=False)
    run=Runner(a.flat.read_bytes());rows={}
    for name in a.cases.split(','):
        print('CLANG_RECEIPT_CASE_BEGIN',name,flush=True);row=CASES[name](run);rows[name]=row
        (a.output/(name+'.json')).write_text(json.dumps(row,indent=2)+'\n');print('CLANG_RECEIPT_CASE_PASS',name,flush=True)
    source=Path(original.__file__).read_bytes();inventory_source=Path(inspect.getsourcefile(original.inspect_owned_shared_elf)).read_bytes()
    report=dict(schema='hia.native-clang-compile-receipt.qualification.v1',passed=True,complete=set(rows)==set(CASES),
                flat=pin(a.flat.read_bytes()),cases=rows,native_calls=run.calls,original_oracle_comparisons=run.comparisons,
                oracle_python=sys.version.split()[0],original_llvm_source=pin(source),original_inventory_source=pin(inventory_source),
                native_formatter_qualified=True,uses_captured_state_fixtures=True,host_runtime_receipt_callback=False,
                actual_clang_outer_qualified=False,whole_public_runtime_qualified=False)
    (a.output/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(passed=True,groups=len(rows),comparisons=run.comparisons,native_calls=run.calls)),flush=True)
if __name__=='__main__':main()
