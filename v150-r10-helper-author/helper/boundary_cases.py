"""Finite added private-helper cases and an independent byte-sequence oracle.

No HIA module is imported here. This is an oracle for the five explicitly
selected private ABIs, not a replacement implementation of the checker.
"""
MASK=(1<<64)-1
WIDTHS={'f22':8,'f23':8,'f24':4,'f25':4,'f92':2}
VALUES=(0,1,255,256,65535,65536,(1<<32)-1,1<<32,1<<63,MASK,
        0x0123456789ABCDEF,0xFEDCBA9876543210)

def initial(size,pattern=0):
    if pattern==1:return bytes(size)
    if pattern==2:return bytes([255])*size
    if pattern==3:return bytes([128])*size
    if pattern==4:return bytes((index%8 for index in range(size)))
    return bytes(((37*index+0xA5)&255 for index in range(size)))

def cases():
    rows=[]
    def add(group,fn,offset,value,size,pattern=0,view='mutable',flag=None):
        raw=bytearray(initial(size,pattern))
        if flag is not None and len(raw)>40:raw[40]=flag
        rows.append({'id':group+'/'+str(len(rows)).zfill(4),'group':group,'function':fn,
            'offset':offset,'value':value,'initial_hex':bytes(raw).hex(),'view':view})
    for fn in ('f22','f24'):
        for value in VALUES:
            for offset in (0,1,3,7,16):add('write_full_word',fn,offset,value,80)
        for remaining in range(WIDTHS[fn]):
            for value in (0,MASK,0x0123456789ABCDEF):
                add('write_short',fn,3,value,3+remaining)
    for fn in ('f23','f25'):
        for pattern in range(5):
            for offset in (0,1,3,7,16):add('read_full_word',fn,offset,None,80,pattern)
        for remaining in range(WIDTHS[fn]):
            for pattern in (0,1,2):add('read_short',fn,3,None,3+remaining,pattern)
    for fn in WIDTHS:
        for offset in (65535,65536,(1<<32)-1,1<<32,1<<63,(1<<64)-WIDTHS[fn],MASK):
            add('high_offset',fn,offset,None if fn in ('f23','f25') else 65535,256)
    for value in (0,255,256,65535):
        for offset in (0,1,39,40,46,100,104,111):add('cp16_success','f92',offset,value,128)
        for remaining in range(2):add('cp16_success','f92',3,value,3+remaining)
    lengths=sorted(set((0,24,39,128)+tuple(range(40,50))+tuple(range(103,114))))
    for value in (65536,1<<32,1<<63,MASK):
        for size in lengths:
            for flag in (0,0x7F):add('cp16_refusal','f92',MASK,value,size,flag=flag)
    for fn in WIDTHS:
        for view in ('readonly','expired_view','expired_owner'):
            for offset in (0,MASK):
                add('borrow_failure',fn,offset,None if fn in ('f23','f25') else 65535,128,view=view)
    for view in ('readonly','expired_view','expired_owner'):
        for flag in (0,0x7F):add('borrow_failure','f92',MASK,MASK,128,view=view,flag=flag)
    assert len({r['id'] for r in rows})==len(rows)
    assert {r['group'] for r in rows}=={'write_full_word','write_short','read_full_word','read_short',
        'high_offset','cp16_success','cp16_refusal','borrow_failure'}
    return rows

class ExpectedStop(Exception):
    def __init__(self,error):self.error=error

def oracle(case):
    buffer=bytearray.fromhex(case['initial_hex']);events=[]
    def fail(type_name,code,message):
        raise ExpectedStop({'type':type_name,'code':code,'message':message})
    def byte(op,index,value=None):
        event={'op':op,'index':index}
        if op=='buffer.store':event['value']=value
        events.append(event)
        try:
            if case['view']=='expired_view':
                fail('HIAProgramRejected','E_HIA_RUNTIME_INVARIANT','E_HIA_RUNTIME_INVARIANT: expired/cyclic runtime view')
            if case['view']=='expired_owner':
                fail('HIAProgramRejected','E_HIA_RUNTIME_INVARIANT','E_HIA_RUNTIME_INVARIANT: expired runtime owner')
            if op=='buffer.store' and case['view']=='readonly':
                fail('HIAProgramRejected','E_HIA_RUNTIME_INVARIANT','E_HIA_RUNTIME_INVARIANT: write through non-mutable view')
            if index>=len(buffer):
                label='load' if op=='buffer.load' else 'store'
                fail('HIAProgramTrap','bounds','E_HIA_TRAP_BOUNDS: byte '+label+' outside the borrowed buffer')
            if op=='buffer.store':buffer[index]=value;result=None
            else:result=buffer[index];event['loaded']=result
            event['outcome']='completed';return result
        except ExpectedStop as stopped:
            event['outcome']='raised';event['error']=stopped.error;raise
    def put(offset,value,width):
        # Independent direct little-endian byte oracle: no rewritten SSA or
        # incremental-address implementation is reused here.
        for index in range(width):byte('buffer.store',(offset+index)&MASK,(value>>(8*index))&255)
    def get(offset,width):
        observed=[byte('buffer.load',(offset+index)&MASK) for index in range(width)]
        return int.from_bytes(bytes(observed),'little')
    values=[];error=None;status='returned'
    try:
        fn=case['function'];offset=case['offset'];value=case['value']
        if fn in ('f22','f24'):put(offset,value,WIDTHS[fn]);values=[0]
        elif fn in ('f23','f25'):values=[get(offset,WIDTHS[fn])]
        elif fn=='f92':
            if value<=65535:put(offset,value,2)
            elif byte('buffer.load',40)==0:
                put(40,69,8)
                cursor=get(24,4)
                put(104,cursor,8)
            values=[0]
        else:raise AssertionError(fn)
    except ExpectedStop as stopped:
        error=stopped.error
        status='trapped' if error['type']=='HIAProgramTrap' else 'rejected'
    return {'status':status,'values':values,'error':error,'events':events,'after_hex':bytes(buffer).hex()}
