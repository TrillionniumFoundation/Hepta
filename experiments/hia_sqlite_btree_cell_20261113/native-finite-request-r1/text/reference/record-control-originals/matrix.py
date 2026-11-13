"""Original twelve record methods, complete byte expectations; no HIA/VM/C execution."""
import hashlib,json,math,struct
MAGIC=int.from_bytes(b'HIASRC01','little')
PROTOCOL,TRUNCATED,CAPACITY,FORMAT,RESERVED,LIMIT=0xfffffffd,0xfffffffe,0xfffffffc,0xfffffffb,0xfffffffa,0xfffffff9
REFUSALS=(PROTOCOL,TRUNCATED,CAPACITY,FORMAT,RESERVED,LIMIT)
MAX_PAYLOAD=1<<20
MAX_FIELDS=2000
MAX_OUTPUT=80032
CANARY=bytes(range(64))
NAMES=(
'test_01_Core_roundtrip_and_original_caps',
'test_02_every_signed_storage_width_and_boundaries',
'test_03_binary64_patterns_and_nan_null_classification',
'test_04_mixed_fields_and_opaque_text_encodings',
'test_05_header_size_boundaries_and_field_order',
'test_06_nonminimal_header_and_serial_varints',
'test_07_all_selected_truncations_and_header_boundary_refusals',
'test_08_protocol_extent_magic_format_and_reserved_controls',
'test_09_reserved_types_schema_versions_capacity_and_trailing_bytes',
'test_10_declared_payload_field_limits_and_empty_extension',
'test_11_public_bridge_types_and_foreign_custody_refusals',
'test_12_complete_upstream_sources_and_oracle_excerpts')
MODULE='tests.hia_sqlite_record_source_r1'
IDS=tuple(MODULE+'.SQLiteRecordSourceTests.'+x for x in NAMES)
COUNTS=(0,42,18,10,7,18,29,11,17,4,3,0)
VERSIONS=('3.46.0','3.53.2')
def wire(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def command(file_format=4,magic=MAGIC,operation=1,reserved=0):
    return struct.pack('<4Q',magic,operation,file_format,reserved)
def varint(value,width=None):
    if type(value)is not int or not 0<=value<1<<64:raise ValueError('fixture exact u64')
    minimum=9 if value>=1<<56 else max(1,(value.bit_length()+6)//7)
    width=minimum if width is None else width
    if type(width)is not int or not minimum<=width<=9:raise ValueError('fixture varint extent')
    if width==9:
        return bytes([128|(((value>>8)>>(7*i))&127) for i in range(7,-1,-1)]+[value&255])
    return bytes([((value>>(7*i))&127)|(128 if i else 0) for i in range(width-1,-1,-1)])
def record(fields,header_width=None,serial_widths=None):
    widths=[None]*len(fields) if serial_widths is None else serial_widths
    if len(widths)!=len(fields):raise ValueError('fixture serial count')
    serials=b''.join(varint(serial,width) for (serial,_),width in zip(fields,widths))
    header=len(serials)+(1 if header_width is None else header_width)
    while True:
        prefix=varint(header,header_width)
        measured=len(prefix)+len(serials)
        if measured==header:return prefix+serials+b''.join(b for _,b in fields),header
        header=measured
def serial_length(serial):
    if serial<12:return (0,1,2,3,4,6,8,8,0,0,0,0)[serial]
    return (serial-12)//2
def field_scalar(serial,raw):
    if serial==0:return 0,0,1
    if 1<=serial<=6:return int.from_bytes(raw,'big',signed=True)%(1<<64),1,4
    if serial in (8,9):return serial-8,1,4
    if serial==7:
        bits=int.from_bytes(raw,'big')
        nan=math.isnan(struct.unpack('>d',raw)[0])
        return bits,0 if nan else 2,1 if nan else 8
    return 0,3 if serial%2 else 4,0x4002 if serial%2 else 0x4010
def read_varint(raw,offset,end):
    value=0
    for i in range(9):
        if offset+i>=end:return None
        byte=raw[offset+i]
        if i==8:return value*256+byte,9
        value=value*128+(byte%128)
        if byte<128:return value,i+1
    raise AssertionError('unreachable')
def expected(raw,out,cmd):
    """Independent complete-payload parser; no generator/test helper import."""
    def refuse(code):return {'status':code,'source_after_hex':raw.hex(),'output_after_hex':out.hex(),
        'command_after_hex':cmd.hex(),'fields':None,'header_bytes':None,'schema_format':None}
    if len(cmd)!=32:return refuse(PROTOCOL)
    magic,op,version,reserved=struct.unpack('<4Q',cmd)
    if magic!=MAGIC or op!=1 or not 1<=version<=4 or reserved or len(raw)>MAX_PAYLOAD or len(out)>MAX_OUTPUT:
        return refuse(PROTOCOL)
    first=read_varint(raw,0,len(raw))
    if first is None:return refuse(TRUNCATED)
    header,prefix=first
    if header<prefix:return refuse(FORMAT)
    if header>len(raw):return refuse(TRUNCATED)
    at=prefix;body=header;fields=[]
    while at<header:
        part=read_varint(raw,at,header)
        if part is None:return refuse(FORMAT)
        serial,width=part
        if serial in (10,11):return refuse(RESERVED)
        if serial in (8,9) and version<4:return refuse(FORMAT)
        n=serial_length(serial)
        if n>len(raw)-body:return refuse(TRUNCATED)
        bits,kind,flags=field_scalar(serial,raw[body:body+n])
        fields.append({'serial_type':serial,'offset':body,'length':n,'bits':bits,'kind':kind,'C_flags':flags})
        at+=width;body+=n
        if len(fields)>MAX_FIELDS:return refuse(LIMIT)
    if body!=len(raw):return refuse(FORMAT)
    used=32+40*len(fields)
    if len(out)<used:return refuse(CAPACITY)
    result=bytearray(struct.pack('<4Q',len(fields),header,len(raw)-header,len(raw)))
    for f in fields:result.extend(struct.pack('<5Q',*(f[k] for k in ('serial_type','offset','length','bits','kind'))))
    return {'status':used,'source_after_hex':raw.hex(),'output_after_hex':(bytes(result)+out[used:]).hex(),
            'command_after_hex':cmd.hex(),'fields':fields,'header_bytes':header,'schema_format':version}
def project_field(field,returned,words):
    if type(returned)is not int or returned!=0 or type(words)is not list or len(words)!=4 \
       or any(type(x)is not int or not 0<=x<1<<64 for x in words):
        raise ValueError('C field result exact scalar types/arity/status')
    length,bits,kind,flags=words
    if length!=field['length'] or kind not in (0,1,2,3,4):raise ValueError('C field descriptor domain')
    return {'content_length':length,'scalar_bits':bits,'kind':kind,
            'original_Mem_flags':flags,'whole_record_validity_claim':False}
def specifications(root=None):
    ordinal=0;per=[0]*12
    def row(method,raw,out,cmd):
        nonlocal ordinal
        ordinal+=1;per[method-1]+=1
        return {'index':ordinal,'method':IDS[method-1],'label':'m%02d-%04d'%(method,per[method-1]),
                'source_hex':raw.hex(),'output_hex':out.hex(),'command_hex':cmd.hex(),
                'expected':expected(raw,out,cmd)}
    def accepted(method,fields,header_width=None,serial_widths=None,capacity=None,version=4):
        raw,_=record(fields,header_width,serial_widths)
        if capacity is None:capacity=32+40*len(fields)+5
        return row(method,raw,b'\xa5'*capacity,command(version))
    def rejected(method,raw,capacity=77,cmd=None):
        return row(method,raw,b'\xa5'*capacity,command() if cmd is None else cmd)
    for serial,size in enumerate((1,2,3,4,6,8),1):
        edge=1<<(8*size-1)
        for value in (-edge,1-edge,-1,0,1,edge-2,edge-1):
            yield accepted(2,[(serial,value.to_bytes(size,'big',signed=True))])
    patterns=(0,1<<63,0x3ff0000000000000,0xbff0000000000000,1,0x8000000000000001,
        0x000fffffffffffff,0x0010000000000000,0x7fefffffffffffff,0xffefffffffffffff,
        0x7ff0000000000000,0xfff0000000000000,0x7ff8000000000000,0xfff8000000000000,
        0x7ff0000000000001,0xfff0000000000001,0x7fffffffffffffff,0xffffffffffffffff)
    for bits in patterns:yield accepted(3,[(7,bits.to_bytes(8,'big'))])
    for version in (1,2,3,4):yield accepted(4,[(0,b''),(12,b''),(13,b'')],version=version)
    for payload in (b'abc',b'\xff\x00\x80','中文'.encode('utf-8'),'中文'.encode('utf-16le'),'中文'.encode('utf-16be')):
        yield accepted(4,[(0,b''),(2,b'\xff\xfe'),(12+2*len(payload),payload),
                          (13+2*len(payload),payload),(8,b''),(9,b'')])
    yield accepted(4,[(s,b'') for s in (9,8,0,13,12)])
    for count in (1,8,126,127,128,255,2000):yield accepted(5,[(0,b'')]*count,capacity=32+40*count)
    for width in range(1,10):yield accepted(6,[(1,b'\x80')],header_width=width)
    for width in range(1,10):yield accepted(6,[(1,b'\x7f')],serial_widths=[width])
    raw,_=record([(1,b'\x7f'),(6,b'\x80'+b'\0'*7),(23,b'abcde')])
    if len(raw)!=18:raise ValueError('original truncation fixture extent')
    for n in range(len(raw)):yield rejected(7,raw[:n])
    for width in range(1,9):yield rejected(7,b'\x80'*width)
    for raw in (b'\x02\x80',b'\x03\x80\x80',b'\x09'+b'\x80'*8):yield rejected(7,raw)
    raw,_=record([(1,b'\x01')])
    for cmd in (b'',command()[:-1],command()+b'\0',command(magic=0),command(operation=0),
                command(operation=2),command(file_format=0),command(file_format=5),command(reserved=1)):
        yield rejected(8,raw,cmd=cmd)
    yield rejected(8,b'\0'*(MAX_PAYLOAD+1))
    yield rejected(8,raw,capacity=MAX_OUTPUT+1)
    for serial in (10,11):yield rejected(9,record([(serial,b'')])[0])
    for version in (1,2,3):
        for serial in (8,9):yield rejected(9,record([(serial,b'')])[0],cmd=command(version))
    for raw in (b'\0',b'\x80\0',b'\x01\0'):yield rejected(9,raw)
    raw,_=record([(1,b'\x01')])
    for cap in (0,1,31,32,71):yield rejected(9,raw,capacity=cap)
    serial=varint((1<<64)-1)
    yield rejected(9,varint(1+len(serial))+serial)
    yield accepted(10,[],capacity=32)
    yield accepted(10,[],header_width=9,capacity=32)
    yield rejected(10,record([(0,b'')]*2001)[0],capacity=MAX_OUTPUT)
    payload=b'\x5a'*(MAX_PAYLOAD-5)
    raw,header=record([(12+2*len(payload),payload)])
    if (len(raw),header)!=(MAX_PAYLOAD,5):raise ValueError('maximum original payload')
    yield accepted(10,[(12+2*len(payload),payload)],capacity=72)
    fields=[(1,b'\xff'),(7,bytes.fromhex('7ff8000000000001')),(19,b'abc')]
    raw,_=record(fields)
    yield row(11,raw,b'\xa5'*MAX_OUTPUT,command())
    yield rejected(11,b'\x02\x80',capacity=MAX_OUTPUT)
    yield row(11,b'\x01',b'\xa5'*MAX_OUTPUT,command())
    if tuple(per)!=COUNTS or ordinal!=159:raise ValueError('original full record population')
def manifest(root=None):
    counts={k:0 for k in IDS};oracle={'field_calls':0,'accepted_records':0,'empty_record_extensions':0,
                                     'refused_records_not_called':0}
    statuses={};digest=hashlib.sha256()
    for row in specifications(root):
        digest.update(wire(row));counts[row['method']]+=1
        e=row['expected'];statuses[str(e['status'])]=statuses.get(str(e['status']),0)+1
        if e['fields'] is None:oracle['refused_records_not_called']+=1
        else:
            oracle['accepted_records']+=1
            if not e['fields']:oracle['empty_record_extensions']+=1
            for field in e['fields']:
                words=[field['length'],field['bits'],field['kind'],field['C_flags']]
                projection=project_field(field,0,words)
                if projection['content_length']!=field['length'] or projection['scalar_bits']!=field['bits'] \
                    or projection['kind']!=field['kind']:raise ValueError('C field reference projection')
                oracle['field_calls']+=1
    if list(counts.values())!=list(COUNTS) or oracle!={'field_calls':2774,'accepted_records':100,
            'empty_record_extensions':3,'refused_records_not_called':59}:
        raise ValueError('original HIA and new field-only C denominator')
    return {'schema':'hia.sqlite.record.native-matrix.v1','ids':list(IDS),'counts':counts,
        'native_returns':159,'oracle_calls_each':oracle,'oracle_versions':list(VERSIONS),
        'status_counts':statuses,'ordered_expected_rows_sha256':digest.hexdigest(),
        'original_methods_unchanged':12,'backend':'NativeImage; original _Machine denied, no VM rerun',
        'scope':'Finite strict record byte kernel; C fields only, no whole-record C admission oracle, SQL, database or durability'}
