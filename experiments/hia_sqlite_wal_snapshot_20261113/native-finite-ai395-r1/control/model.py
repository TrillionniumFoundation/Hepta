"""Finite-format reference and explicit ABI rows, with no HIA/VM/C imports.

This model describes only the frozen valid-shape full-page extension. Original
608 protocol/exception calls instead use their independently retained VM bytes.
"""
import struct
MASK=(1<<32)-1
U64=(1<<64)-1
CM=int.from_bytes(b'HIASWS01','little')
SM=int.from_bytes(b'HIASWT01','little')
RM=int.from_bytes(b'HIASWR01','little')
CANARY=bytes(range(64))

def checksum(raw,order,seed=(0,0)):
    if len(raw)<8 or len(raw)%8:raise ValueError('format checksum domain')
    # Pair matrix [[1,1],[1,2]]; arithmetic is independent of the HIA builder.
    a,b=seed
    for k in range(0,len(raw),8):
        x=int.from_bytes(raw[k:k+4],order);y=int.from_bytes(raw[k+4:k+8],order)
        a,b=(a+b+x)&MASK,(a+2*b+x+y)&MASK
    return a,b

def header(order='little',page_size=512,checkpoint=0,salts=(0x12345678,0xabcdef01),version=3007000,magic=None):
    magic=0x377f0682+int(order=='big') if magic is None else magic
    b=struct.pack('>6I',magic,version,page_size,checkpoint,*salts)
    return b+struct.pack('>2I',*checksum(b,order))

def wal(specs,order='little',page_size=512):
    h=header(order,page_size);seed=checksum(h[:24],order);chunks=[h]
    for pg,commit,fill in specs:
        page=bytes((fill,))*page_size;first=struct.pack('>2I',pg,commit)
        after=checksum(first+page,order,seed)
        chunks.append(first+struct.pack('>4I',0x12345678,0xabcdef01,*after)+page);seed=after
    return b''.join(chunks)

def parse(raw,base_size=512,base_pages=9):
    """Whole finite input reference; no current HIA status chooses this domain."""
    d={'raw_bytes':len(raw),'base_size':base_size,'base_pages':base_pages,
       'page_size':base_size,'database_pages':base_pages,'committed_frame':0,
       'committed_end_offset':0,'valid_frames_scanned':0,'stop_reason':1,
       'header':None,'frames':[],'reads':[],'unsupported':False,'bad_index':None}
    if len(raw)<=32:return d
    h=struct.unpack('>8I',raw[:32]);d['reads'].append((0,32));d['header']=h
    magic,version,size,ck,s0,s1,c0,c1=h
    if magic not in (0x377f0682,0x377f0683) or not 512<=size<=65536 or size&(size-1):
        d['stop_reason']=3;return d
    order='big' if magic&1 else 'little';pair=checksum(raw[:24],order)
    if pair!=(c0,c1):d['stop_reason']=4;return d
    if version!=3007000:d['unsupported']=True;return d
    width=size+24;d['stop_reason']=2 if (len(raw)-32)%width else 0
    for i in range((len(raw)-32)//width):
        off=32+i*width;data=raw[off:off+width];d['reads'].append((off,width))
        pg,commit,a,b,e0,e1=struct.unpack('>6I',data[:24])
        bad=5 if (a,b)!=(s0,s1) else (6 if pg==0 else 0)
        after=pair if bad else checksum(data[:8]+data[24:],order,pair)
        if not bad and after!=(e0,e1):bad=7
        if bad:d['stop_reason']=bad;d['bad_index']=i+1;break
        row={'number':i+1,'page':pg,'commit':commit,'offset':off,'before':pair,'after':after}
        d['frames'].append(row);d['valid_frames_scanned']=i+1;pair=after
        if commit:
            d.update(page_size=size,database_pages=commit,committed_frame=i+1,
                     committed_end_offset=off+width)
    return d

def snapshot_fields(d):
    return {k:d[k] for k in ('page_size','database_pages','committed_frame',
            'committed_end_offset','valid_frames_scanned','stop_reason')}

def location(d,page):
    base={'source':'missing','offset':0,'size':0,'frame_number':0,'page_number':page,
          'database_pages':d['database_pages'],'committed_frame':d['committed_frame'],
          'committed_end_offset':d['committed_end_offset'],'checksum_before':[0,0],'checksum_after':[0,0]}
    if page>d['database_pages']:return base
    base.update(source='database',offset=(page-1)*d['page_size'],size=d['page_size'])
    matches=[f for f in d['frames'] if f['number']<=d['committed_frame'] and f['page']==page]
    if matches:
        f=matches[-1];base.update(source='wal',offset=f['offset']+24,frame_number=f['number'],
                                 checksum_before=list(f['before']),checksum_after=list(f['after']))
    return base

def c_words(raw,target):
    """Expected complete raw state of the fixed heap-memory recovery adapter."""
    if not 0<=len(raw)<=8<<20 or type(target)is not int or not 0<=target<=MASK:raise ValueError('finite C domain')
    d=parse(raw);h=d['header'];r=[0]*32;r[1]=U64;r[20]=1;r[21]=1
    raw_salt=b'\0'*8;seed=(0,0);encoded=0;mx=0;npage=0
    valid_format=h is not None and h[0] in (0x377f0682,0x377f0683) and 512<=h[2]<=65536 and h[2]&(h[2]-1)==0
    if valid_format:
        r[4]=h[2];r[6]=h[0]&1;r[7]=h[3];r[10:12]=h[4:6];raw_salt=raw[16:24]
        if d['unsupported']:
            r[0]=14;seed=checksum(raw[:24],'big' if h[0]&1 else 'little')
    if not r[0]:
        mx=d['committed_frame'];npage=d['database_pages'] if mx else 0
        if mx:
            seed=d['frames'][mx-1]['after'];encoded=(h[2]&0xff00)|(h[2]>>16)
        r[12]=1;r[13]=3007000
        hdr=struct.pack('<IIIBBH4I',3007000,0,0,1,r[6],encoded,mx,npage,*seed)+raw_salt
        if len(hdr)!=40:raise ValueError('raw WalIndexHdr prefix layout')
        r[14:16]=checksum(hdr,'little')
        if target:
            r[1]=0
            matches=[f for f in d['frames'] if f['number']<=mx and f['page']==target]
            if matches:r[16]=matches[-1]['number'];r[17]=matches[-1]['offset']+24
    r[2]=mx;r[3]=npage;r[5]=encoded;r[8:10]=seed
    reads=d['reads'];r[18]=len(reads);r[19]=sum(n for _,n in reads)
    if reads:r[22:24]=reads[-1]
    # Every frozen finite case uses at most five frames; this adapter still has
    # the separately declared 8 MiB C-only transport domain.
    if h and valid_format and (len(raw)-32)//(h[2]+24)>5:raise ValueError('unfrozen C population')
    return r,reads,d

def c_projection(words,raw,target,base_size,base_pages):
    if len(words)!=32 or any(type(x)is not int or not 0<=x<=U64 for x in words):raise ValueError('C raw exact scalar domain')
    if words[0]:
        if words[0]!=14:raise ValueError('C unexpected recovery error')
        return {'kind':'unsupported_version','raw_recovery_rc':14}
    p=words[4] if words[2] else base_size
    count=words[3] if words[2] else base_pages
    end=32+words[2]*(p+24) if words[2] else 0
    result={'page_size':p,'database_pages':count,'committed_frame':words[2],
            'committed_end_offset':end,'committed_checksum':words[8:10]}
    if target:
        result['location']='missing' if target>count else ('wal' if words[16] else 'database')
        result['offset']=0 if target>count else (words[17] if words[16] else (target-1)*p)
        result['size']=0 if target>count else p
        result['frame_number']=0 if target>count else words[16]
    return result

def pack_state(words):return struct.pack('<32Q',*words)

def reply(w):
    """Decode the public ABI into one complete expected reply; no author import."""
    phase,mode=w[1:3];page=w[5]
    if phase!=2 and w[16]==0:page=w[27]
    a=3;off=count=0;frame=w[14];before=after=(0,0)
    if phase==1:a=1;count=32;frame=0
    elif phase==2:a=2;off=w[15];count=w[5]+24;frame+=1
    elif phase==3 and mode==2:a=4
    elif phase==4:a=5
    elif phase==5:
        a=6;frame=0
        if w[28]==1:off=(w[22]-1)*page;count=page
        elif w[28]==2:off=w[24]+24;count=page;frame=w[23];before=w[29:31];after=w[25:27]
    return struct.pack('<16Q',RM,a,off,count,frame,page,w[17],w[16],w[20],w[21],w[22],w[28],*before,*after)

def full_page_protocol(raw,pages,base_size,base_pages):
    """Finite admitted scan/lookup rows derived from parsed frame metadata.

    New full-page cases use no malformed commands, changed snapshots or sparse
    extents. Their original counterparts are retained in the 608 VM oracle.
    """
    d=parse(raw,base_size,base_pages)
    if d['unsupported'] or d['header'] is None or d['stop_reason'] in (3,4):raise ValueError('full-page model domain')
    h=d['header'];ps=h[2];width=ps+24
    w=[0]*32;rows=[];drive_ranges=[]
    def emit(op,fields=(),payload=b'',update=None):
        before=pack_state(w);packet=struct.pack('<'+'Q'*(2+len(fields)),CM,op,*fields)+payload
        if update:update()
        rows.append({'source_before_hex':packet.hex(),'source_after_hex':packet.hex(),
             'output_before_hex':(b'\xa5'*128).hex(),'output_after_hex':reply(w).hex(),
             'state_before_hex':before.hex(),'state_after_hex':pack_state(w).hex(),
             'actual_returned':True,'status':128})
    def assign(pairs):
        for i,value in pairs.items():w[i]=value
    begin=len(rows)
    emit(1,(len(raw),base_pages,base_size),update=lambda:assign({0:SM,1:1,2:1,3:len(raw),4:base_pages,15:32,17:base_pages,27:base_size}))
    emit(2,payload=raw[:32],update=lambda:assign({1:2 if len(raw)-32>=width else 3,5:ps,6:h[0]&1,
         7:h[4],8:h[5],9:h[3],10:h[6],11:h[7],12:h[6],13:h[7],21:0 if len(raw)-32>=width else 2}))
    for index,(off,n) in enumerate(d['reads'][1:],1):
        if d['bad_index']==index:
            emit(3,payload=raw[off:off+n],update=lambda:assign({1:3,21:d['stop_reason']}))
            break
        f=d['frames'][index-1]
        def advance(f=f):
            assign({12:f['after'][0],13:f['after'][1],14:f['number'],15:f['offset']+width})
            if f['commit']:assign({16:f['number'],17:f['commit'],18:f['after'][0],19:f['after'][1],20:f['offset']+width})
            remaining=len(raw)-w[15]
            if remaining<width:assign({1:3,21:2 if remaining else 0})
        emit(3,payload=raw[off:off+n],update=advance)
    emit(5,update=lambda:assign({1:4}));saved=list(w)
    drive_ranges.append((begin,len(rows)))
    for page in pages:
        w[:]=saved;begin=len(rows)
        def init_lookup():
            assign({1:3 if page>w[17] or w[16]==0 else 1,2:2,12:w[10],13:w[11],14:0,15:32,22:page,28:0 if page>w[17] else 1})
        emit(4,(page,),update=init_lookup)
        if w[1]==1:
            emit(2,payload=raw[:32],update=lambda:assign({1:2,12:h[6],13:h[7]}))
            for f in d['frames'][:d['committed_frame']]:
                def advance_lookup(f=f):
                    assign({12:f['after'][0],13:f['after'][1],14:f['number'],15:f['offset']+width})
                    if f['page']==page:assign({23:f['number'],24:f['offset'],25:f['after'][0],26:f['after'][1],
                                              29:f['before'][0],30:f['before'][1],28:2})
                    if f['number']==w[16]:w[1]=3
                emit(3,payload=raw[f['offset']:f['offset']+width],update=advance_lookup)
        emit(5,update=lambda:assign({1:5}));drive_ranges.append((begin,len(rows)))
    return rows,drive_ranges,d
