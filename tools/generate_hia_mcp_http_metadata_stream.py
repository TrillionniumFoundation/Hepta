"""Author bounded native HTTP metadata files, complete SSE and cache replay.

Only held metadata tasks may admit the larger diagnostic frame.  Existing
ordinary response limits and all connection/session generation checks remain.
"""
import ast


def once(source, old, new):
    if source.count(old) != 1:
        raise ValueError('HTTP metadata integration shape changed: '+old[:96])
    return source.replace(old, new, 1)


COMMON = r'''
def respond_file(w:mutbuf,status:u64,fd:u64,offset:u64,size:u64,kind:u64,lead:u64,module:u64,phase:u64) -> u32:
    put(w,H_HTTP_CONTINUE_MODULE,module)
    put(w,H_HTTP_CONTINUE_PHASE,phase)
    put(w,H_HTTP_STATUS,status)
    put(w,H_HTTP_SIZE,size)
    put(w,H_HTTP_TYPE,choose(kind==1,2,3))
    put(w,H_HTTP_ALLOW,0)
    put(w,H_HTTP_FILE_MODE,kind)
    put(w,H_HTTP_FILE_FD,fd)
    put(w,H_HTTP_FILE_START,offset)
    put(w,H_HTTP_FILE_LEAD_N,lead)
    put(w,H_HTTP_FILE_APPEND,0)
    return enter(w,HTTP_RESPONSE,0)

def append_file(w:mutbuf,fd:u64,offset:u64,size:u64,module:u64,phase:u64) -> u32:
    put(w,H_HTTP_CONTINUE_MODULE,module)
    put(w,H_HTTP_CONTINUE_PHASE,phase)
    put(w,H_HTTP_SIZE,size)
    put(w,H_HTTP_TYPE,3)
    put(w,H_HTTP_FILE_MODE,2)
    put(w,H_HTTP_FILE_FD,fd)
    put(w,H_HTTP_FILE_START,offset)
    put(w,H_HTTP_FILE_LEAD_N,0)
    put(w,H_HTTP_FILE_APPEND,1)
    return enter(w,HTTP_RESPONSE,110)
'''


RESPONSE = r'''
def file_failed(w:mutbuf) -> u32:
    return close_conn_to(w,get(w,H_HTTP_CONTINUE_MODULE),get(w,H_HTTP_CONTINUE_PHASE))

def file_valid(w:mutbuf) -> bool:
    mode=get(w,H_HTTP_FILE_MODE)
    size=get(w,H_HTTP_SIZE)
    start=get(w,H_HTTP_FILE_START)
    lead=get(w,H_HTTP_FILE_LEAD_N)
    if mode<1 or mode>2 or get(w,H_HTTP_FILE_FD)<3 or get(w,H_HTTP_FILE_FD)==NONE:
        return False
    if size==0 or size>METADATA_REPLY_MAX+128 or start>NONE-size or lead>256:
        return False
    if mode==1 and lead!=0:
        return False
    return True

def file_prepare(w:mutbuf) -> u64:
    put(w,H_HTTP_FILE_STAGE,0)
    put(w,H_HTTP_FILE_CHUNK_USED,0)
    put(w,H_HTTP_USED,0)
    put(w,H_HTTP_FILE_PREFIX_N,0)
    put(w,H_HTTP_FILE_SUFFIX_N,0)
    size=get(w,H_HTTP_SIZE)+get(w,H_HTTP_FILE_LEAD_N)
    if get(w,H_HTTP_FILE_MODE)==2 and get(w,CR_VERSION)!=1:
        at=H_FILE_PREFIX
        shift=60
        while shift>0 and (size>>shift)&15==0:
            shift=shift-4
        left=shift//4+1
        while left>0:
            value=(size>>((left-1)*4))&15
            store(w,at,choose(value<10,48+value,55+value))
            at=at+1
            left=left-1
        store(w,at,13)
        store(w,at+1,10)
        put(w,H_HTTP_FILE_PREFIX_N,at+2-H_FILE_PREFIX)
        store(w,H_FILE_SUFFIX,13)
        store(w,H_FILE_SUFFIX+1,10)
        store(w,H_FILE_SUFFIX+2,48)
        store(w,H_FILE_SUFFIX+3,13)
        store(w,H_FILE_SUFFIX+4,10)
        store(w,H_FILE_SUFFIX+5,13)
        store(w,H_FILE_SUFFIX+6,10)
        put(w,H_HTTP_FILE_SUFFIX_N,7)
    return size+get(w,H_HTTP_FILE_PREFIX_N)+get(w,H_HTTP_FILE_SUFFIX_N)

def file_body(o:mutbuf,w:mutbuf) -> u32:
    stage=get(w,H_HTTP_FILE_STAGE)
    if stage==0:
        if get(w,H_HTTP_FILE_PREFIX_N)!=0:
            return file_piece(o,w,112,H_FILE_PREFIX,get(w,H_HTTP_FILE_PREFIX_N),0)
        put(w,H_HTTP_FILE_STAGE,1)
        put(w,H_HTTP_FILE_CHUNK_USED,0)
        stage=1
    if stage==1:
        if get(w,H_HTTP_FILE_LEAD_N)!=0:
            return file_piece(o,w,113,H_FILE_LEAD,get(w,H_HTTP_FILE_LEAD_N),get(w,H_HTTP_FILE_PREFIX_N))
        put(w,H_HTTP_FILE_STAGE,2)
        put(w,H_HTTP_FILE_CHUNK_USED,0)
        stage=2
    if stage==2:
        if get(w,H_HTTP_USED)<get(w,H_HTTP_SIZE):
            return file_read(o,w)
        put(w,H_HTTP_FILE_STAGE,3)
        put(w,H_HTTP_FILE_CHUNK_USED,0)
        stage=3
    if stage==3:
        if get(w,H_HTTP_FILE_SUFFIX_N)!=0:
            offset=get(w,H_HTTP_FILE_PREFIX_N)+get(w,H_HTTP_FILE_LEAD_N)+get(w,H_HTTP_SIZE)
            return file_piece(o,w,116,H_FILE_SUFFIX,get(w,H_HTTP_FILE_SUFFIX_N),offset)
        put(w,H_HTTP_FILE_STAGE,4)
    if get(w,H_HTTP_FILE_APPEND)==1:
        put(w,CR_FLAGS,get(w,CR_FLAGS)&(NONE-256))
        put(w,CR_TASK_SLOT,NONE)
        put(w,CR_TASK_GENERATION,0)
        return call(o,w,117,72,get(w,CR_REPLY_FD),1033,15,0,0,0,0)
    return call(o,w,5,72,get(w,CR_REPLY_FD),1033,15,0,0,0,0)

def file_piece(o:mutbuf,w:mutbuf,phase:u64,source:u64,size:u64,offset:u64) -> u32:
    used=get(w,H_HTTP_FILE_CHUNK_USED)
    return call(o,w,phase,18,get(w,CR_REPLY_FD),source+used,size-used,get(w,H_HTTP_HEADER_N)+offset+used,0,0,12)

def file_read(o:mutbuf,w:mutbuf) -> u32:
    used=get(w,H_HTTP_USED)
    size=get(w,H_HTTP_SIZE)-used
    if size>65536:
        size=65536
    return call(o,w,114,17,get(w,H_HTTP_FILE_FD),H_FILE_BUFFER,size,get(w,H_HTTP_FILE_START)+used,0,0,12)

def file_write(o:mutbuf,w:mutbuf) -> u32:
    used=get(w,H_HTTP_FILE_CHUNK_USED)
    offset=get(w,H_HTTP_HEADER_N)+get(w,H_HTTP_FILE_PREFIX_N)+get(w,H_HTTP_FILE_LEAD_N)+get(w,H_HTTP_USED)+used
    return call(o,w,115,18,get(w,CR_REPLY_FD),H_FILE_BUFFER+used,get(w,H_HTTP_FILE_CHUNK)-used,offset,0,0,12)

def file_step(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==110:
        if file_valid(w)==False or get(w,CR_REPLY_FD)==NONE:
            return file_failed(w)
        put(w,H_HTTP_HEADER_N,get(w,CR_REPLY_N))
        size=file_prepare(w)
        if get(w,H_HTTP_HEADER_N)>NONE-size:
            return file_failed(w)
        put(w,H_HTTP_REPLY_N,get(w,H_HTTP_HEADER_N)+size)
        return file_body(o,w)
    if phase==114:
        if result==NEG4:
            return file_read(o,w)
        if failed(result) or result==0 or result>65536 or result>get(w,H_HTTP_SIZE)-get(w,H_HTTP_USED):
            return file_failed(w)
        put(w,H_HTTP_FILE_CHUNK,result)
        put(w,H_HTTP_FILE_CHUNK_USED,0)
        return file_write(o,w)
    if phase==115:
        if result==NEG4:
            return file_write(o,w)
        if failed(result) or result==0 or result>get(w,H_HTTP_FILE_CHUNK)-get(w,H_HTTP_FILE_CHUNK_USED):
            return file_failed(w)
        put(w,H_HTTP_FILE_CHUNK_USED,get(w,H_HTTP_FILE_CHUNK_USED)+result)
        if get(w,H_HTTP_FILE_CHUNK_USED)!=get(w,H_HTTP_FILE_CHUNK):
            return file_write(o,w)
        put(w,H_HTTP_USED,get(w,H_HTTP_USED)+get(w,H_HTTP_FILE_CHUNK))
        return file_body(o,w)
    if phase==117:
        if failed(result):
            return file_failed(w)
        put(w,CR_REPLY_N,get(w,H_HTTP_REPLY_N))
        put(w,CR_STATUS,3)
        return epoll_conn(o,w,6,8196)
    if phase==112 or phase==113 or phase==116:
        if result==NEG4:
            return file_body(o,w)
        size=get(w,H_HTTP_FILE_PREFIX_N)
        if phase==113:
            size=get(w,H_HTTP_FILE_LEAD_N)
        elif phase==116:
            size=get(w,H_HTTP_FILE_SUFFIX_N)
        if failed(result) or result==0 or result>size-get(w,H_HTTP_FILE_CHUNK_USED):
            return file_failed(w)
        put(w,H_HTTP_FILE_CHUNK_USED,get(w,H_HTTP_FILE_CHUNK_USED)+result)
        if get(w,H_HTTP_FILE_CHUNK_USED)==size:
            put(w,H_HTTP_FILE_STAGE,get(w,H_HTTP_FILE_STAGE)+1)
            put(w,H_HTTP_FILE_CHUNK_USED,0)
        return file_body(o,w)
    return 0
'''


def response_source(source):
    before, separator, after = source.partition('    if phase==100:\n')
    if not separator or before.count('return close_conn(w)') != 6:
        raise ValueError('HTTP response publication failure shape changed')
    before = before.replace('return close_conn(w)', 'return response_failed(w)')
    before = once(before, '    if phase==1:\n        if failed(result):\n            return 0',
                  '    if phase==1:\n        if failed(result):\n'
                  '            if get(w,H_HTTP_FILE_MODE)!=0:\n                return file_failed(w)\n'
                  '            return 0')
    source = before+separator+after
    source = once(source, '    if phase==0:\n        if get(w,H_HTTP_SIZE)>16777728:\n            return 0',
                  '    if phase>=110 and phase<=117:\n        return file_step(o,w,phase,result)\n'
                  '    if phase==0:\n        if get(w,H_HTTP_FILE_MODE)!=0:\n'
                  '            if file_valid(w)==False:\n                return file_failed(w)\n'
                  '        elif get(w,H_HTTP_SIZE)>16777728:\n            return 0')
    source = once(source, '        put(w,H_HTTP_REPLY_N,get(w,H_HTTP_HEADER_N))\n        if get(w,CR_HEAD)==0:\n            put(w,H_HTTP_REPLY_N,get(w,H_HTTP_REPLY_N)+get(w,H_HTTP_SIZE))',
                  '        put(w,H_HTTP_REPLY_N,get(w,H_HTTP_HEADER_N))\n'
                  '        size=get(w,H_HTTP_SIZE)\n'
                  '        if get(w,H_HTTP_FILE_MODE)!=0:\n            size=file_prepare(w)\n'
                  '        if get(w,CR_HEAD)==0:\n            put(w,H_HTTP_REPLY_N,get(w,H_HTTP_REPLY_N)+size)')
    source = once(source, 'def write_body(o:mutbuf,w:mutbuf) -> u32:\n',
                  'def write_body(o:mutbuf,w:mutbuf) -> u32:\n'
                  '    if get(w,H_HTTP_FILE_MODE)!=0 and get(w,CR_HEAD)==0:\n        return file_body(o,w)\n')
    return source+RESPONSE+r'''
def response_failed(w:mutbuf) -> u32:
    if get(w,H_HTTP_FILE_MODE)!=0:
        return file_failed(w)
    return close_conn(w)
'''


DELIVERY = r'''
def large_prefix_read(o:mutbuf,w:mutbuf) -> u32:
    used=get(w,H_D_USED)
    size=get(w,H_LARGE_PREFIX_N)-used
    if size>65536:
        size=65536
    return call(o,w,110,17,get(w,task_row(get(w,H_D_SLOT))+40),SESSION_OUT+used,size,used,0,0,12)

def large_delivery(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    row=task_row(get(w,H_D_SLOT))
    if phase==110:
        if result==NEG4:
            return large_prefix_read(o,w)
        if failed(result) or result==0 or result>65536 or result>get(w,H_LARGE_PREFIX_N)-get(w,H_D_USED):
            return enter(w,HTTP_DELIVERY,900)
        put(w,H_D_USED,get(w,H_D_USED)+result)
        if get(w,H_D_USED)!=get(w,H_LARGE_PREFIX_N):
            return large_prefix_read(o,w)
        return call(o,w,111,17,get(w,row+40),H_IO,1,get(w,row+48)-1,0,0,12)
    if result==NEG4:
        return call(o,w,111,17,get(w,row+40),H_IO,1,get(w,row+48)-1,0,0,12)
    if result!=1 or byte(w,H_IO)!=10:
        return enter(w,HTTP_DELIVERY,900)
    put(w,H_D_N,get(w,row+48)-1)
    return enter(w,HTTP_EVENTS,100)
'''


def delivery_source(source):
    source = once(source, '    if phase==100:\n        put(w,H_D_USED,0)\n        return response_read(o,w)',
                  '    if phase==110 or phase==111:\n        return large_delivery(o,w,phase,result)\n'
                  '    if phase==100:\n        put(w,H_D_USED,0)\n        put(w,H_LARGE_REPLY,0)\n'
                  '        row=task_row(get(w,H_D_SLOT))\n'
                  '        if get(w,row+48)>16777216:\n'
                  '            if get(w,row+248)!=1:\n                return enter(w,HTTP_DELIVERY,900)\n'
                  '            put(w,H_LARGE_REPLY,1)\n            put(w,H_LARGE_PREFIX_N,8389120)\n'
                  '            return large_prefix_read(o,w)\n        return response_read(o,w)')
    source = once(source, '    if kind==0 and (size==0 or size>16777216):\n        return False',
                  '    maximum=choose(get(w,row+248)==1,METADATA_REPLY_MAX,16777216)\n'
                  '    if kind==0 and (size==0 or size>maximum):\n        return False')
    return source+DELIVERY


EVENTS = r'''
def large_event_begin(o:mutbuf,w:mutbuf) -> u32:
    row=task_row(get(w,H_E_SLOT))
    put(w,H_LARGE_STATUS,200)
    if get(w,H_E_FLAGS)&2!=0:
        return enter(w,HTTP_DELIVERY,900)
    if get(w,H_E_FLAGS)&32!=0:
        status=response_status(w,SESSION_OUT,get(w,H_LARGE_PREFIX_N),get(w,row+168))
        put(w,H_LARGE_STATUS,status)
        if status!=200:
            return find_connection(w)
    put(w,H_LARGE_CACHE_START,get(w,SR_CACHE_N)+64)
    put(w,H_LARGE_SOURCE_FD,get(w,task_row(get(w,H_D_SLOT))+40))
    end=text_data(w,H_EVENT_PREFIX)
    put(w,H_LARGE_HEAD_N,end-H_EVENT_PREFIX)
    end=text_lf(w,H_EVENT_SUFFIX)
    if get(w,H_E_FLAGS)&32==0:
        end=text_id_one(w,end)
        end=decimal(w,end,get(w,H_E_STREAM))
        end=text_lf(w,end)
    end=text_lf(w,end)
    put(w,H_LARGE_TAIL_N,end-H_EVENT_SUFFIX)
    put(w,H_E_PLAIN_N,get(w,H_LARGE_HEAD_N)+get(w,H_D_N)+get(w,H_LARGE_TAIL_N))
    put(w,H_IO,LARGE_CACHE_MAGIC)
    put(w,H_IO+8,get(w,H_E_STREAM))
    put(w,H_IO+16,get(w,H_NOW))
    put(w,H_IO+24,get(w,H_E_PLAIN_N))
    put(w,H_IO+32,0)
    put(w,H_IO+40,0)
    put(w,H_IO+48,0)
    put(w,H_IO+56,0)
    put(w,H_LARGE_USED,0)
    put(w,H_LARGE_RAW_USED,0)
    return large_event_piece(o,w,500,H_IO,64,get(w,SR_CACHE_N))

def large_event_piece(o:mutbuf,w:mutbuf,phase:u64,at:u64,size:u64,offset:u64) -> u32:
    used=get(w,H_LARGE_USED)
    return call(o,w,phase,18,get(w,SR_CACHE_FD),at+used,size-used,offset+used,0,0,12)

def large_event_read(o:mutbuf,w:mutbuf) -> u32:
    used=get(w,H_LARGE_RAW_USED)
    size=get(w,H_D_N)-used
    if size>65536:
        size=65536
    return call(o,w,502,17,get(w,H_LARGE_SOURCE_FD),H_FILE_BUFFER,size,used,0,0,12)

def large_event_step(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if phase==502:
        if result==NEG4:
            return large_event_read(o,w)
        if failed(result) or result==0 or result>65536 or result>get(w,H_D_N)-get(w,H_LARGE_RAW_USED):
            return enter(w,HTTP_DELIVERY,900)
        put(w,H_LARGE_CHUNK,result)
        put(w,H_LARGE_USED,0)
        offset=get(w,H_LARGE_CACHE_START)+get(w,H_LARGE_HEAD_N)+get(w,H_LARGE_RAW_USED)
        return large_event_piece(o,w,503,H_FILE_BUFFER,result,offset)
    at=H_IO
    size=64
    offset=get(w,SR_CACHE_N)
    if phase==501:
        at=H_EVENT_PREFIX
        size=get(w,H_LARGE_HEAD_N)
        offset=get(w,H_LARGE_CACHE_START)
    elif phase==503:
        at=H_FILE_BUFFER
        size=get(w,H_LARGE_CHUNK)
        offset=get(w,H_LARGE_CACHE_START)+get(w,H_LARGE_HEAD_N)+get(w,H_LARGE_RAW_USED)
    elif phase==504:
        at=H_EVENT_SUFFIX
        size=get(w,H_LARGE_TAIL_N)
        offset=get(w,H_LARGE_CACHE_START)+get(w,H_LARGE_HEAD_N)+get(w,H_D_N)
    if result==NEG4:
        return large_event_piece(o,w,phase,at,size,offset)
    if failed(result) or result==0 or result>size-get(w,H_LARGE_USED):
        return enter(w,HTTP_DELIVERY,900)
    put(w,H_LARGE_USED,get(w,H_LARGE_USED)+result)
    if get(w,H_LARGE_USED)!=size:
        return large_event_piece(o,w,phase,at,size,offset)
    put(w,H_LARGE_USED,0)
    if phase==500:
        return large_event_piece(o,w,501,H_EVENT_PREFIX,get(w,H_LARGE_HEAD_N),get(w,H_LARGE_CACHE_START))
    if phase==501:
        return large_event_read(o,w)
    if phase==503:
        put(w,H_LARGE_RAW_USED,get(w,H_LARGE_RAW_USED)+get(w,H_LARGE_CHUNK))
        if get(w,H_LARGE_RAW_USED)!=get(w,H_D_N):
            return large_event_read(o,w)
        offset=get(w,H_LARGE_CACHE_START)+get(w,H_LARGE_HEAD_N)+get(w,H_D_N)
        return large_event_piece(o,w,504,H_EVENT_SUFFIX,get(w,H_LARGE_TAIL_N),offset)
    put(w,SR_CACHE_N,get(w,H_LARGE_CACHE_START)+get(w,H_E_PLAIN_N))
    return save_session(w,HTTP_EVENTS,140)

def large_event_publish(w:mutbuf) -> u32:
    if get(w,H_E_FLAGS)&32!=0:
        put(w,CR_SESSION,NONE)
        put(w,CR_TASK_SLOT,NONE)
        put(w,CR_TASK_GENERATION,0)
        if get(w,H_LARGE_STATUS)!=200:
            fd=get(w,task_row(get(w,H_D_SLOT))+40)
            return respond_file(w,get(w,H_LARGE_STATUS),fd,0,get(w,H_D_N),1,0,HTTP_DELIVERY,200)
        return respond_file(w,200,get(w,SR_CACHE_FD),get(w,H_LARGE_CACHE_START),get(w,H_E_PLAIN_N),2,0,HTTP_DELIVERY,200)
    if get(w,CR_REPLY_FD)==NONE:
        return enter(w,HTTP_DELIVERY,200)
    return append_file(w,get(w,SR_CACHE_FD),get(w,H_LARGE_CACHE_START),get(w,H_E_PLAIN_N),HTTP_DELIVERY,200)

def large_cached_response(w:mutbuf) -> u32:
    lead=0
    if get(w,H_E_INDEX)==0:
        end=priming(w,H_FILE_LEAD,get(w,H_E_STREAM),0)
        lead=end-H_FILE_LEAD
    return respond_file(w,200,get(w,SR_CACHE_FD),get(w,H_E_SCAN)+64,get(w,H_E_PLAIN_N),2,lead,HTTP_IO,3)
'''


def events_source(source):
    source = once(source, '    if phase==0:\n',
                  '    if phase>=500 and phase<=504:\n        return large_event_step(o,w,phase,result)\n'
                  '    if phase==0:\n')
    source = once(source, '        put(w,H_E_CONN,get(w,row+24))\n        if get(w,H_E_FLAGS)&32!=0:',
                  '        put(w,H_E_CONN,get(w,row+24))\n'
                  '        if get(w,H_LARGE_REPLY)==1:\n            return large_event_begin(o,w)\n'
                  '        if get(w,H_E_FLAGS)&32!=0:')
    source = once(source, '            return enter(w,HTTP_DELIVERY,200)\n        if get(w,H_E_FLAGS)&32!=0:',
                  '            return enter(w,HTTP_DELIVERY,200)\n'
                  '        if get(w,H_LARGE_REPLY)==1:\n            return large_event_publish(w)\n'
                  '        if get(w,H_E_FLAGS)&32!=0:')
    source = once(source, '        if get(w,H_IO)!=CACHE_MAGIC or size>16777728 or size>get(w,SR_CACHE_N)-get(w,H_E_SCAN)-64:',
                  '        magic=get(w,H_IO)\n'
                  '        maximum=16777728\n'
                  '        if magic==LARGE_CACHE_MAGIC:\n'
                  '            maximum=METADATA_REPLY_MAX+128\n'
                  '            if get(w,H_IO+32)!=0 or get(w,H_IO+40)!=0 or get(w,H_IO+48)!=0 or get(w,H_IO+56)!=0:\n'
                  '                return enter(w,HTTP_DELIVERY,900)\n'
                  '        elif magic!=CACHE_MAGIC:\n            return enter(w,HTTP_DELIVERY,900)\n'
                  '        if size>maximum or size>get(w,SR_CACHE_N)-get(w,H_E_SCAN)-64:')
    source = once(source, '            put(w,H_E_PLAIN_N,size)\n            put(w,H_E_USED,0)\n            return cached_body(o,w)',
                  '            put(w,H_E_PLAIN_N,size)\n            put(w,H_E_USED,0)\n'
                  '            if size>16777728:\n                return large_cached_response(w)\n'
                  '            return cached_body(o,w)')
    return source+EVENTS


def post_source(source):
    return once(source, '        put(w,row+168,get(w,H_REQUEST_DESCRIPTOR+104))',
                '        put(w,row+168,get(w,H_REQUEST_DESCRIPTOR+104))\n'
                '        tool=get(w,H_REQUEST_DESCRIPTOR+56)\n'
                '        metadata=kind==1 and role==5 and tool>=12 and tool<=14\n'
                '        put(w,row+248,choose(metadata,1,0))')
