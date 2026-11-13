"""Finite arithmetic expectations, authored independently of HIA and SQLite C."""
from pathlib import Path
import hashlib,json,struct
MASK=(1<<64)-1
MAGIC=int.from_bytes(b'HIASVR01','little')
PROTOCOL,TRUNCATED,CAPACITY=0xfffffffd,0xfffffffe,0xfffffffc
CANARY=bytes(range(64))
NAMES=(
 'test_01_original_1618_complete_VM_buffers',
 'test_02_all_65536_initialized_two_byte_prefixes',
 'test_03_fixed_4096_full_u64_roundtrips',
 'test_04_public_bridge_boundaries_and_nonminimal',
 'test_05_public_truncation_and_capacity',
 'test_06_foreign_types_exception_identity_and_canaries',
 'test_07_two_original_C_oracles_and_sources',
 'test_08_original_caps_and_source_population')
IDS=tuple('tests.hia_sqlite_varint_native_finite_r2.SQLiteVarintNativeTests.'+x for x in NAMES)
COUNTS=(1618,65536,8192,597,108,3,0,0)
VERSIONS=('3.46.0','3.53.2')
def wire(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def encode(value):
    if type(value)is not int or not 0<=value<=MASK:raise ValueError('u64')
    if value>=1<<56:
        top,last=divmod(value,256);result=[]
        for _ in range(8):
            top,digit=divmod(top,128);result.append(128+digit)
        return bytes(reversed(result))+bytes([last])
    result=[]
    while True:
        value,digit=divmod(value,128);result.append(digit)
        if not value:break
    digits=list(reversed(result))
    return bytes(d+(128 if i+1<len(digits) else 0) for i,d in enumerate(digits))
def decode(raw):
    value=0
    for index,b in enumerate(raw[:8]):
        value=value*128+(b%128)
        if b<128:return value,index+1
    if len(raw)<9:return None
    return value*256+raw[8],9
def expected(source,output,command):
    status=PROTOCOL;after=output;oracle=None
    if len(command)==16:
        magic,op=struct.unpack('<QQ',command)
        if magic==MAGIC and op==1 and len(source)<=9 and len(output)==8:
            v=decode(source)
            if v is None:status=TRUNCATED
            else:
                value,status=v;after=value.to_bytes(8,'little')
                oracle={'operation':'get','raw_hex':source.hex(),'value':value,'count':status}
        elif magic==MAGIC and op==2 and len(source)==8 and len(output)<=9:
            value=int.from_bytes(source,'little');raw=encode(value)
            oracle={'operation':'put','value':value,'encoded_hex':raw.hex(),'count':len(raw)}
            if len(output)<len(raw):status=CAPACITY
            else:status=len(raw);after=raw+output[len(raw):]
    return {'status':status,'source_after_hex':source.hex(),'output_after_hex':after.hex(),
            'command_after_hex':command.hex(),'oracle':oracle}
def command(op):return struct.pack('<QQ',MAGIC,op)
def boundary_values():
    result={0,1,MASK-1,MASK}
    for bit in range(64):
        for delta in (-1,0,1):
            v=(1<<bit)+delta
            if 0<=v<=MASK:result.add(v)
    return tuple(sorted(result))
def random_values():
    state=0x4853494153514c56
    for _ in range(4096):
        state=(state+0x9e3779b97f4a7c15)&MASK
        z=state;z=((z^(z>>30))*0xbf58476d1ce4e5b9)&MASK
        z=((z^(z>>27))*0x94d049bb133111eb)&MASK
        yield (z^(z>>31))&MASK
def original_rows(root):
    doc=json.loads((Path(root)/'reference/source8-actual/tests/VM-RAW.json').read_bytes())
    if doc['schema']!='hia.sqlite-varint.source-vm-raw.v1' or len(doc['calls'])!=1618:raise ValueError('original VM set')
    return doc['calls']
def specifications(root):
    ordinal=0
    def row(method,label,source,output,cmd):
        nonlocal ordinal
        ordinal+=1
        return {'index':ordinal,'method':IDS[method-1],'label':label,'source_hex':source.hex(),
                'output_hex':output.hex(),'command_hex':cmd.hex(),'expected':expected(source,output,cmd)}
    for i,r in enumerate(original_rows(root),1):
        a,b,c=(bytes.fromhex(r[k]) for k in ('source_before_hex','output_before_hex','workspace_before_hex'))
        e=expected(a,b,c)
        if (r['actual_returned'] is not True or r['status']!=e['status'] or
            r['source_after_hex']!=e['source_after_hex'] or r['output_after_hex']!=e['output_after_hex']
            or r['workspace_after_hex']!=e['command_after_hex']):raise ValueError('original VM arithmetic mismatch')
        yield row(1,'vm-%04d'%i,a,b,c)
    for prefix in range(65536):
        yield row(2,'prefix-%04x'%prefix,prefix.to_bytes(2,'big')+b'\x80'*6+b'\x55',b'\xa5'*8,command(1))
    for i,v in enumerate(random_values()):
        raw=encode(v)
        yield row(3,'random-%04d-put'%i,v.to_bytes(8,'little'),b'\xa5'*9,command(2))
        yield row(3,'random-%04d-get'%i,raw,b'\xa5'*8,command(1))
    vals=boundary_values()
    if len(vals)!=191:raise ValueError('boundary denominator')
    for i,v in enumerate(vals):
        raw=encode(v)
        yield row(4,'public-%03d-encode'%i,v.to_bytes(8,'little'),b'\xa5'*9,command(2))
        yield row(4,'public-%03d-decode'%i,(raw+b'tail')[:9],b'\xa5'*8,command(1))
        yield row(4,'public-%03d-into'%i,v.to_bytes(8,'little'),b'\xa5'*9,command(2))
    for size in range(2,10):
        for terminal in (0,1,127):
            raw=b'\x80'*(size-1)+bytes([terminal])
            yield row(4,'nonminimal-%d-%d'%(size,terminal),(raw+b'tail')[:9],b'\xa5'*8,command(1))
    for size in range(9):
        for b in (128,255):
            yield row(5,'truncated-%d-%d'%(size,b),bytes([b])*size,b'\xa5'*8,command(1))
    for count in range(1,10):
        v=0 if count==1 else 1<<(7*(count-1))
        for cap in range(10):
            yield row(5,'capacity-%d-%d'%(count,cap),v.to_bytes(8,'little'),b'\xa5'*cap,command(2))
    for kind in ('source','command','tail'):
        yield row(6,'caught-canary-'+kind,(128).to_bytes(8,'little'),b'\xa5'*9,command(2))
def manifest(root):
    counts={k:0 for k in IDS};c={'get':0,'put':0,'not_called':0};digest=hashlib.sha256()
    for row in specifications(root):
        counts[row['method']]+=1;digest.update(wire(row))
        oracle=row['expected']['oracle'];c[oracle['operation'] if oracle else 'not_called']+=1
    if list(counts.values())!=list(COUNTS):raise ValueError('finite method denominator')
    return {'schema':'hia.sqlite.varint.native-finite-matrix.v2','ids':list(IDS),'counts':counts,
            'native_returns':sum(COUNTS),'oracle_calls_each':c,
            'oracle_versions':list(VERSIONS),'source8_original_vectors':1618,
            'ordered_expected_rows_sha256':digest.hexdigest(),'splitmix64_seed':0x4853494153514c56,
            'boundary_values':list(boundary_values()),'fixed_random_values':list(random_values()),
            'scope':'finite domains only; not exhaustive all 2**64 inputs or SQL/durability'}
