"""Stream exact large serde diagnostics into the request's private reply file.

The scheduler publishes only after the worker exits successfully and the file
is sealed. Neither the SDK input limits nor the fixed process arena grow.
"""

C = {'D_STATE': (128 << 20)+65536, 'D_BUFFER': 112 << 20}
TEXT = {
    'diagnostic_envelope': ',"error":{"code":-32602,"message":"',
    'diagnostic_close': '"}}\n',
}

SOURCE = r'''
def history_stream_begin(w:mutbuf,source:u64,size:u64,kind:u64,expected:u64) -> u64:
    put(w,D_STATE,source)
    put(w,D_STATE+8,size)
    put(w,D_STATE+16,kind)
    put(w,D_STATE+24,expected)
    put(w,D_STATE+32,0)
    put(w,D_STATE+40,0)
    put(w,D_STATE+48,0)
    if kind == 2:
        history_debug_init(w)
    return 3

def history_stream(o:mutbuf,w:mutbuf,phase:u64,result:u64) -> u32:
    if get(w,184) != 1:
        return 0
    if phase == 51:
        if result == NEG4:
            return history_stream_write(o,w)
        if failed(result) or result == 0 or result > get(w,D_STATE+56)-get(w,D_STATE+64):
            return 0
        put(w,D_STATE+64,get(w,D_STATE+64)+result)
        if get(w,D_STATE+64) != get(w,D_STATE+56):
            return history_stream_write(o,w)
    if get(w,D_STATE+40) == 6:
        return enter(w,2,30)
    size = history_stream_chunk(w)
    if size == 0 or size > 65536:
        return 0
    put(w,D_STATE+56,size)
    put(w,D_STATE+64,0)
    return history_stream_write(o,w)

def history_stream_write(o:mutbuf,w:mutbuf) -> u32:
    used = get(w,D_STATE+64)
    return call(o,w,51,1,1,D_BUFFER+used,get(w,D_STATE+56)-used,0,0,0,12)

def history_stream_chunk(w:mutbuf) -> u64:
    stage = get(w,D_STATE+40)
    at = D_BUFFER
    if stage == 0:
        at = text_control_prefix(w, at)
        put(w,D_STATE+40,1)
        return at-D_BUFFER
    if stage == 1:
        used = get(w,D_STATE+48)
        size = get(w,S_REQUEST_ID+8)-used
        if size > 65536:
            size = 65536
        copy_state(w,get(w,S_REQUEST_ID)+used,at,size)
        put(w,D_STATE+48,used+size)
        if used+size == get(w,S_REQUEST_ID+8):
            put(w,D_STATE+40,2)
        return size
    if stage == 2:
        at = text_diagnostic_envelope(w, at)
        end = text_history_param_prefix(w, PURE_INPUT)
        if get(w,D_STATE+16) == 1:
            end = text_history_param_unknown(w, end)
        else:
            end = text_history_param_type(w, end)
            end = text_history_param_string(w, end)
            store(w,end,34)
            end = end+1
        at = history_json_range(w,at,PURE_INPUT,end-PURE_INPUT)
        put(w,D_STATE+40,3)
        return at-D_BUFFER
    if stage == 3:
        source = get(w,D_STATE)
        size = get(w,D_STATE+8)
        index = get(w,D_STATE+32)
        while index < size and at-D_BUFFER < 65520:
            if get(w,D_STATE+16) == 1:
                at = history_json_byte(w,at,byte(w,source+index))
                index = index+1
            else:
                first = byte(w,source+index)
                count = 1
                point = first
                if first >= 192:
                    count = choose(first < 224,2,choose(first < 240,3,4))
                    point = first & choose(count == 2,31,choose(count == 3,15,7))
                    next = 1
                    while next < count:
                        point = (point << 6) | (byte(w,source+index+next) & 63)
                        next = next+1
                at = history_stream_point(w,at,source+index,count,point)
                index = index+count
        put(w,D_STATE+32,index)
        if index == size:
            put(w,D_STATE+40,4)
        return at-D_BUFFER
    if stage == 4:
        end = PURE_INPUT
        if get(w,D_STATE+16) == 1:
            if get(w,264) == 15:
                end = text_usage_param_fields(w, end)
            else:
                end = text_history_param_fields(w, end)
        else:
            store(w,end,34)
            end = end+1
            if get(w,D_STATE+24) == 1:
                end = text_history_param_u16(w, end)
            else:
                end = text_history_param_text(w, end)
        at = history_json_range(w,at,PURE_INPUT,end-PURE_INPUT)
        at = text_diagnostic_close(w, at)
        put(w,D_STATE+40,6)
        return at-D_BUFFER
    return 0

def history_stream_point(w:mutbuf,at:u64,source:u64,count:u64,point:u64) -> u64:
    if point == 0 or point == 9 or point == 10 or point == 13:
        at = history_json_byte(w,at,92)
        return history_json_byte(w,at,choose(point == 0,48,choose(point == 9,116,choose(point == 10,110,114))))
    if point == 34 or point == 92:
        at = history_json_byte(w,at,92)
        return history_json_byte(w,at,point)
    if history_debug_escape(w,point):
        at = history_json_byte(w,at,92)
        store(w,at,117)
        store(w,at+1,123)
        at = at+2
        shift = 20
        while shift > 0 and ((point >> shift) & 15) == 0:
            shift = shift-4
        emitting = True
        while emitting:
            store(w,at,hex_digit((point >> shift) & 15))
            at = at+1
            if shift == 0:
                emitting = False
            else:
                shift = shift-4
        store(w,at,125)
        return at+1
    return history_json_range(w,at,source,count)

def history_json_range(w:mutbuf,at:u64,source:u64,size:u64) -> u64:
    index = 0
    while index < size:
        at = history_json_byte(w,at,byte(w,source+index))
        index = index+1
    return at

def history_json_byte(w:mutbuf,at:u64,ch:u64) -> u64:
    if ch == 34 or ch == 92:
        store(w,at,92)
        store(w,at+1,ch)
        return at+2
    if ch == 8 or ch == 9 or ch == 10 or ch == 12 or ch == 13:
        store(w,at,92)
        store(w,at+1,choose(ch == 8,98,choose(ch == 9,116,choose(ch == 10,110,choose(ch == 12,102,114)))))
        return at+2
    if ch < 32:
        store(w,at,92)
        store(w,at+1,117)
        store(w,at+2,48)
        store(w,at+3,48)
        store(w,at+4,hex_digit(ch >> 4))
        store(w,at+5,hex_digit(ch & 15))
        return at+6
    store(w,at,ch)
    return at+1
'''
