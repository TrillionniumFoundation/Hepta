"""Fixed original ten-method WAL population; no HIA, VM, C or database execution."""
import hashlib,json,struct
MASK=(1<<32)-1
MAGIC=int.from_bytes(b'HIASWL01','little')
PROTOCOL,FORMAT,CHECKSUM,SALT,VERSION=0xfffffffd,0xfffffffc,0xfffffffb,0xfffffffa,0xfffffff9
CANARY=bytes(range(64))
NAMES=(
'test_01_Core_roundtrip_and_original_caps',
'test_02_both_orders_seeds_and_independent_weighted_checksums',
'test_03_incremental_composition_across_every_eight_byte_cut',
'test_04_header_all_page_sizes_and_both_checksum_orders',
'test_05_protocol_refusals_leave_all_spans_unchanged',
'test_06_header_magic_size_checksum_and_version_precedence',
'test_07_frame_chain_and_commit_marker_are_exact_bytes',
'test_08_frame_corruption_salts_seed_and_zero_page_refuse',
'test_09_bridge_types_bounds_and_foreign_custody_failures',
'test_10_two_complete_original_oracles_remain_independent')
IDS=tuple('tests.test_hia_sqlite_wal_source.SQLiteWalSourceTests.'+x for x in NAMES)
COUNTS=(0,46,56,16,54,32,8,26,0,0)
VERSIONS=('3.46.0','3.53.2')
def wire(v):return (json.dumps(v,sort_keys=True,separators=(',',':'),allow_nan=False)+'\n').encode()
def command(operation=1,order=0,seed=(0,0),page=0,salts=(0,0),magic=MAGIC):
    return struct.pack('<8Q',magic,operation,order,*seed,page,*salts)
def checksum(raw,order,seed=(0,0)):
    # Matrix-vector arithmetic in unbounded Python integers with explicit u32 projection.
    if len(raw)<8 or len(raw)%8:raise ValueError('checksum domain')
    a,b=seed
    for offset in range(0,len(raw),8):
        x=int.from_bytes(raw[offset:offset+4],order)
        y=int.from_bytes(raw[offset+4:offset+8],order)
        a,b=(a+b+x)&MASK,(a+2*b+x+y)&MASK
    return a,b
def header(order='little',page_size=512,checkpoint=0,salts=(0x12345678,0xabcdef01),version=3007000,magic=None):
    magic=0x377f0682+int(order=='big') if magic is None else magic
    raw=struct.pack('>6I',magic,version,page_size,checkpoint,*salts)
    return raw+struct.pack('>2I',*checksum(raw,order))
def frame(page,initial,order='little',page_number=1,commit=0,salts=(0x12345678,0xabcdef01)):
    prefix=struct.pack('>2I',page_number,commit)
    pair=checksum(prefix+page,order,initial)
    return prefix+struct.pack('>4I',*salts,*pair)+page,pair
def valid_page(p):return 512<=p<=65536 and p&(p-1)==0
def expected(raw,out,cmd):
    status=PROTOCOL;after=out;oracle=None
    if len(cmd)==64:
        magic,op,order,s0,s1,page,salt0,salt1=struct.unpack('<8Q',cmd)
        if magic==MAGIC and op==1 and len(out)==8 and 8<=len(raw)<=65536 and len(raw)%8==0 and order<=1 and s0<=MASK and s1<=MASK and page==salt0==salt1==0:
            pair=checksum(raw,'big' if order else 'little',(s0,s1))
            status=8;after=struct.pack('<2I',*pair)
            oracle={'operation':'checksum','returned':1,'output_words':list(pair),'seed_before':[s0,s1]}
        elif magic==MAGIC and op==2 and len(raw)==len(out)==32 and order==s0==s1==page==salt0==salt1==0:
            m,v,p,ck,a,b,c0,c1=struct.unpack('>8I',raw)
            words=[0,0,m,p,0,0,0,0,0,0,0,0]
            status=FORMAT
            if m&0xfffffffe==0x377f0682 and valid_page(p):
                order=m&1;pair=checksum(raw[:24],'big' if order else 'little')
                words[5:]=[*pair,ck,a,b,order,p]
                status=CHECKSUM
                if pair==(c0,c1):
                    words[4]=v;status=VERSION
                    if v!=3007000:words[1]=14
                    else:
                        words[0]=1;status=32
                        after=struct.pack('<8I',*pair,p,ck,a,b,order,v)
            oracle={'operation':'header','returned':words[0],'output_words':words,'seed_before':[0,0]}
        elif magic==MAGIC and op==3 and len(out)==16 and order<=1 and max(s0,s1,salt0,salt1)<=MASK and valid_page(page) and len(raw)==page+24:
            pg,commit,a,b,c0,c1=struct.unpack('>6I',raw[:24])
            words=[s0,s1,0,0];rc=0;status=SALT
            if (a,b)==(salt0,salt1):
                status=FORMAT
                if pg:
                    pair=checksum(raw[:8]+raw[24:],'big' if order else 'little',(s0,s1))
                    words[:2]=pair;status=CHECKSUM
                    if pair==(c0,c1):
                        rc=1;words[2:]=[pg,commit];status=16;after=struct.pack('<4I',*words)
            oracle={'operation':'frame','returned':rc,'output_words':words,'seed_before':[s0,s1]}
    return {'status':status,'source_after_hex':raw.hex(),'output_after_hex':after.hex(),
            'command_after_hex':cmd.hex(),'oracle':oracle}
def project_oracle(spec,returned,words):
    """Project preserved actual C state; never rewrite a failed C seed."""
    raw=bytes.fromhex(spec['source_hex']);out=bytes.fromhex(spec['output_hex'])
    fields=struct.unpack('<8Q',bytes.fromhex(spec['command_hex']))
    _,op,order,s0,s1,page,salt0,salt1=fields
    if type(returned)is not int or any(type(x)is not int or not 0<=x<=MASK for x in words):raise ValueError('C exact scalar types')
    if op==1:
        if returned!=1 or len(words)!=2:raise ValueError('C checksum result')
        status=8;after=struct.pack('<2I',*words);seed=words
    elif op==2:
        if len(words)!=12 or returned!=words[0] or returned not in (0,1):raise ValueError('C header result')
        magic,version,p,checkpoint,a,b,c0,c1=struct.unpack('>8I',raw)
        seed=words[5:7]
        if magic&0xfffffffe!=0x377f0682 or not valid_page(p):status=FORMAT
        elif seed!=[c0,c1]:status=CHECKSUM
        elif words[4]!=3007000:status=VERSION
        else:status=32
        if (status==32)!=bool(returned):raise ValueError('C header admission')
        after=struct.pack('<8I',*seed,p,checkpoint,a,b,magic&1,version) if status==32 else out
    elif op==3:
        if len(words)!=4 or returned not in (0,1):raise ValueError('C frame result')
        pg,commit,a,b,c0,c1=struct.unpack('>6I',raw[:24]);seed=words[:2]
        if (a,b)!=(salt0,salt1):status=SALT
        elif pg==0:status=FORMAT
        elif seed!=[c0,c1]:status=CHECKSUM
        else:status=16
        if (status==16)!=bool(returned):raise ValueError('C frame admission')
        after=struct.pack('<4I',*words) if status==16 else out
    else:raise ValueError('oracle operation outside admitted C domain')
    before=[s0,s1] if op!=2 else [0,0]
    return {'hia_status':status,'hia_output_hex':after.hex(),
            'C_seed_before':before,'C_seed_after':seed,
            'C_seed_changed_on_HIA_refusal':status in (PROTOCOL,FORMAT,CHECKSUM,SALT,VERSION) and seed!=before,
            'C_raw_output_preserved':True,'HIA_control_immutable':True}
def specifications(root=None):
    ordinal=0;per=[0]*10
    def row(method,raw,out,cmd):
        nonlocal ordinal
        ordinal+=1;per[method-1]+=1
        return {'index':ordinal,'method':IDS[method-1],
                'label':'m%02d-%04d'%(method,per[method-1]),
                'source_hex':raw.hex(),'output_hex':out.hex(),'command_hex':cmd.hex(),
                'expected':expected(raw,out,cmd)}
    def success(method,raw,cmd,n):return row(method,raw,b'\xa5'*n,cmd)
    for order in ('little','big'):
        code=int(order=='big');prefix='>' if code else '<'
        for raw,seed in ((struct.pack(prefix+'2I',1,2),(0,0)),
                         (struct.pack(prefix+'4I',1,2,3,4),(0,0)),(b'\xff'*8,(MASK,MASK))):
            yield success(2,raw,command(order=code,seed=seed),8)
        for n in (8,16,24,64,128):
            for seed in ((0,0),(1,2),(MASK,0),(MASK,MASK)):
                yield success(2,bytes((i*73+19)%256 for i in range(n)),command(order=code,seed=seed),8)
    raw=bytes((i*91+177)%256 for i in range(64))
    for order in ('little','big'):
        for seed in ((0,0),(0x80000000,MASK)):
            for cut in range(8,len(raw),8):
                middle=checksum(raw[:cut],order,seed)
                yield success(3,raw[:cut],command(order=int(order=='big'),seed=seed),8)
                yield success(3,raw[cut:],command(order=int(order=='big'),seed=middle),8)
    for order in ('little','big'):
        for exponent in range(9,17):
            yield success(4,header(order,1<<exponent,MASK,(0,MASK)),command(2),32)
    raw=b'\x11'*8;cmd=command()
    for n in (0,1,7,9,15,65537):yield success(5,b'\0'*n,cmd,8)
    for n in (0,1,7,9,16):yield success(5,raw,cmd,n)
    for invalid in (b'',cmd[:8],cmd[:63],cmd+b'\0',command(magic=0),command(operation=0),command(operation=4),
                    command(order=2),command(seed=(1<<32,0)),command(seed=(0,1<<32)),command(page=512),
                    command(salts=(1,0)),command(salts=(0,1))):
        yield success(5,raw,invalid,8)
    hdr=header()
    for n in (0,1,23,24,31,33):yield success(5,(hdr+b'\0')[:n],command(2),32)
    for n in (0,8,31,33):yield success(5,hdr,command(2),n)
    for offset in (16,24,32,40,48,56):
        invalid=bytearray(command(2));invalid[offset]=1
        yield success(5,hdr,bytes(invalid),32)
    frm,_=frame(b'\0'*512,(0,0));cmd=command(3,page=512,salts=(0x12345678,0xabcdef01))
    for n in (0,23,24,535,537):yield success(5,(frm+b'\0')[:n],cmd,16)
    for p in (0,1,511,513,65537):yield success(5,frm,command(3,page=p),16)
    for invalid in (command(3,order=2,page=512),command(3,seed=(1<<32,0),page=512),
                    command(3,page=512,salts=(1<<32,0)),command(3,page=512,salts=(0,1<<32))):
        yield success(5,frm,invalid,16)
    for magic in (0,0x377f0680,0x377f0681,0x377f0684,MASK):
        yield success(6,header(magic=magic),command(2),32)
    for p in (0,1,511,513,65535,65537,MASK):
        yield success(6,header(page_size=p),command(2),32)
    for order in ('little','big'):
        hdr=header(order)
        for offset in (12,16,20,24,28,31):
            changed=bytearray(hdr);changed[offset]^=1
            yield success(6,bytes(changed),command(2),32)
        for version in (0,3007001,MASK):
            yield success(6,header(order,version=version),command(2),32)
        unsupported=bytearray(header(order,version=0));unsupported[24]^=1
        yield success(6,bytes(unsupported),command(2),32)
    salts=(0x12345678,0xabcdef01)
    for order in ('little','big'):
        hdr=header(order);seed=checksum(hdr[:24],order)
        yield success(7,hdr,command(2),32)
        for index,pg in enumerate((1,2,MASK)):
            page=bytes((i*17+index*53)%256 for i in range(512));commit=0 if index<2 else 3
            frm,pair=frame(page,seed,order,pg,commit,salts)
            yield success(7,frm,command(3,int(order=='big'),seed,512,salts),16)
            seed=pair
    page=bytes(range(256))*2;seed=(0xdeadbeef,MASK)
    for order in ('little','big'):
        frm,_=frame(page,seed,order,1,2,salts);cmd=command(3,int(order=='big'),seed,512,salts)
        for offset in (8,12,15):
            changed=bytearray(frm);changed[offset]^=1
            yield success(8,bytes(changed),cmd,16)
        for offset in (4,7,16,20,23,24,len(frm)-1):
            changed=bytearray(frm);changed[offset]^=1
            yield success(8,bytes(changed),cmd,16)
        zero,_=frame(page,seed,order,0,2,salts)
        yield success(8,zero,cmd,16)
        yield success(8,frm,command(3,int(order=='big'),(seed[0]^1,seed[1]),512,salts),16)
        yield success(8,frm,command(3,int(order!='big'),seed,512,salts),16)
    if tuple(per)!=COUNTS or ordinal!=238:raise ValueError('original complete method population')
def manifest(root=None):
    counts={k:0 for k in IDS};oracle={'checksum':0,'header':0,'frame':0,'not_called':0}
    digest=hashlib.sha256();status_counts={};rejected_seed_changes=0
    for row in specifications(root):
        digest.update(wire(row));counts[row['method']]+=1
        e=row['expected'];status_counts[str(e['status'])]=status_counts.get(str(e['status']),0)+1
        o=e['oracle'];oracle[o['operation'] if o else 'not_called']+=1
        if o:
            projection=project_oracle(row,o['returned'],o['output_words'])
            if projection['hia_status']!=e['status'] or projection['hia_output_hex']!=e['output_after_hex']:
                raise ValueError('original C full-state projection differs')
            rejected_seed_changes+=int(projection['C_seed_changed_on_HIA_refusal'])
    if list(counts.values())!=list(COUNTS) or oracle!={'checksum':102,'header':50,'frame':32,'not_called':54}:
        raise ValueError('fixed original native/C denominator')
    return {'schema':'hia.sqlite.wal.native-matrix.v1','ids':list(IDS),'counts':counts,
            'native_returns':238,'oracle_calls_each':oracle,'oracle_versions':list(VERSIONS),
            'status_counts':status_counts,'oracle_changed_seeds_on_HIA_refusal_each':rejected_seed_changes,
            'ordered_expected_rows_sha256':digest.hexdigest(),'original_methods_unchanged':10,
            'backend':'NativeImage, original _Machine denied; no VM reexecution',
            'scope':'finite WAL byte kernel; no SQL, file I/O, lock, transaction, recovery, or checkpoint'}
