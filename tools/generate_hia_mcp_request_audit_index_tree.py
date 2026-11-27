"""Versioned native disk-page policy for the disposable retained-record index.

All ordering, allocation, splitting, immutable record transitions and transaction
roots are HIA. An external observer or the mechanical native syscall capsule
only executes the emitted complete-page reads/writes. A transaction never edits
pages reachable from its previous committed root.
"""
from tools.generate_hia_mcp_request_audit_common import authored
from tools.generate_hia_mcp_request_audit_index_state import SOURCE as INDEX_STATE

C = {
    'TREE_BYTES': 65536, 'T_ENTRY': 256, 'T_PROMOTE': 640, 'T_PATH': 1024,
    'T_NODE': 4096, 'T_RIGHT': 12288, 'T_HEADER': 20480,
    'T_LOW': 24576, 'T_HIGH': 24640, 'T_LOWER': 24704, 'T_UPPER': 24712,
    'T_PAGE_MAGIC': int.from_bytes(b'HIARIP01', 'little'),
    'T_FILE_MAGIC': int.from_bytes(b'HIARIX01', 'little'),
    'T_MAX_PAGE': (1 << 51)-1,
}

SOURCE = r'''
def advance(s:readbuf,o:mutbuf,w:mutbuf) -> u32:
    if length(w) < TREE_BYTES or length(o) < 4160 or length(s) < 64:
        return 4294967295
    phase = get(w,0)
    if phase == 0:
        operation = uint(s,0)
        if operation == 0:
            if length(s) != 64 or get(w,184) != 0:
                return tree_error(o,w,1)
            put(w,184,1)
            return tree_read(o,w,1,0)
        # The owner may discard an uncommitted COW cohort after a refused
        # record or I/O. Previously committed data pages were never changed.
        if operation == 5:
            if get(w,80) == 0 or length(s) != 64:
                return tree_error(o,w,1)
            put(w,8,get(w,56))
            put(w,16,get(w,64))
            put(w,24,get(w,72))
            put(w,80,0)
            put(w,184,2)
            return tree_done(o,w,0,0)
        if get(w,184) != 2:
            return tree_error(o,w,1)
        if operation == 3:
            if get(w,80) != 0 or length(s) != 64:
                return tree_error(o,w,1)
            put(w,56,get(w,8))
            put(w,64,get(w,16))
            put(w,72,get(w,24))
            put(w,80,1)
            return tree_done(o,w,0,0)
        if operation == 4:
            if get(w,80) == 0 or length(s) != 64:
                return tree_error(o,w,1)
            tree_header(w)
            return tree_write(o,w,40,0,T_HEADER)
        if operation == 1:
            if length(s) != 128:
                return tree_error(o,w,1)
            copy_input(s,w,64,T_ENTRY,64)
            if lowerhex(w,T_ENTRY,64) == False:
                return tree_error(o,w,1)
        elif operation == 2:
            if length(s) != 448 or get(w,80) == 0:
                return tree_error(o,w,1)
            copy_input(s,w,64,T_ENTRY,384)
            if tree_record_valid(w,T_ENTRY) == False:
                return tree_error(o,w,1)
        else:
            return tree_error(o,w,1)
        put(w,32,operation)
        put(w,40,0)
        put(w,120,0)
        put(w,144,0)
        put(w,T_LOWER,0)
        put(w,T_UPPER,0)
        return tree_read(o,w,10,get(w,8))
    result = uint(s,0)
    if phase == 1:
        if result == 0 and length(s) == 64:
            put(w,8,1)
            put(w,16,2)
            put(w,24,0)
            tree_new_page(w,T_NODE,1)
            return tree_write(o,w,2,1,T_NODE)
        if result != 4096 or length(s) != 4160:
            return tree_error(o,w,2)
        copy_input(s,w,64,T_HEADER,4096)
        if get(w,T_HEADER) != T_FILE_MAGIC or get(w,T_HEADER+8) != 1:
            return tree_error(o,w,2)
        root = get(w,T_HEADER+16)
        next = get(w,T_HEADER+24)
        if root == 0 or root >= next or next > T_MAX_PAGE:
            return tree_error(o,w,2)
        at = 48
        while at < 4096:
            if byte(w,T_HEADER+at) != 0:
                return tree_error(o,w,2)
            at = at+1
        put(w,8,root)
        put(w,16,next)
        put(w,24,get(w,T_HEADER+32))
        put(w,176,get(w,T_HEADER+40))
        put(w,184,2)
        return tree_done(o,w,0,0)
    if phase == 2:
        if result != 4096 or length(s) != 64:
            return tree_error(o,w,2)
        tree_header(w)
        return tree_write(o,w,3,0,T_HEADER)
    if phase == 3 or phase == 40:
        if result != 4096 or length(s) != 64:
            return tree_error(o,w,2)
        if phase == 40:
            put(w,80,0)
            put(w,176,get(w,176)+1)
        put(w,184,2)
        return tree_done(o,w,0,0)
    if phase == 10 or phase == 30:
        if result != 4096 or length(s) != 4160:
            return tree_error(o,w,2)
        copy_input(s,w,64,T_NODE,4096)
        fill_range(w,T_NODE+4096,4096,0)
        if tree_page_valid(w,T_NODE,get(w,16)) == False:
            return tree_error(o,w,2)
        if phase == 30:
            return tree_parent(o,w)
        if tree_range_valid(w) == False:
            return tree_error(o,w,2)
        if get(w,T_NODE+8) == 2:
            depth = get(w,40)
            if depth == 32:
                return tree_error(o,w,2)
            index = tree_child(w,T_NODE,T_ENTRY)
            if index != 0:
                copy_state(w,T_NODE+72+(index-1)*72,T_LOW,64)
                put(w,T_LOWER,1)
            if index < get(w,T_NODE+16):
                copy_state(w,T_NODE+72+index*72,T_HIGH,64)
                put(w,T_UPPER,1)
            put(w,T_PATH+depth*16,get(w,48))
            put(w,T_PATH+depth*16+8,index)
            put(w,40,depth+1)
            child = get(w,T_NODE+64+index*72)
            if child == get(w,48):
                return tree_error(o,w,2)
            return tree_read(o,w,10,child)
        at = tree_leaf_find(w,T_NODE,T_ENTRY)
        present = at < get(w,T_NODE+16)
        if present:
            present = index_key_order(w,T_NODE+64+at*384,T_ENTRY) == 1
        if get(w,32) == 1:
            if present:
                return tree_done(o,w,1,T_NODE+64+at*384)
            return tree_done(o,w,0,0)
        action = tree_leaf_put(w,T_NODE,T_ENTRY)
        if action >= 3:
            return tree_error(o,w,action)
        if action == 0:
            return tree_done(o,w,0,0)
        if action == 2:
            if get(w,24) == NONE:
                return tree_error(o,w,2)
            put(w,120,1)
        put(w,96,get(w,48))
        put(w,128,tree_writable(w,get(w,48)))
        if get(w,128) == NONE:
            return tree_error(o,w,2)
        if get(w,T_NODE+16) == 11:
            tree_leaf_split(w)
            put(w,104,tree_allocate(w))
            if get(w,104) == NONE:
                return tree_error(o,w,2)
            put(w,144,1)
        else:
            put(w,144,0)
        return tree_write(o,w,20,get(w,128),T_NODE)
    if phase == 20:
        if result != 4096 or length(s) != 64:
            return tree_error(o,w,2)
        if get(w,144) != 0:
            return tree_write(o,w,21,get(w,104),T_RIGHT)
        return tree_ascend(o,w)
    if phase == 21:
        if result != 4096 or length(s) != 64:
            return tree_error(o,w,2)
        return tree_ascend(o,w)
    if phase == 31:
        if result != 4096 or length(s) != 64:
            return tree_error(o,w,2)
        return tree_finish_update(o,w)
    return tree_error(o,w,1)

def tree_read(o:mutbuf,w:mutbuf,phase:u64,page:u64) -> u32:
    if page > T_MAX_PAGE:
        return tree_error(o,w,2)
    put(w,0,phase)
    put(w,48,page)
    fill_output(o,64,0)
    word_store(o,0,1)
    word_store(o,8,page)
    return 64

def tree_write(o:mutbuf,w:mutbuf,phase:u64,page:u64,at:u64) -> u32:
    if page > T_MAX_PAGE:
        return tree_error(o,w,2)
    put(w,0,phase)
    fill_output(o,64,0)
    word_store(o,0,2)
    word_store(o,8,page)
    emit_state(o,w,at,64,4096)
    return 4160

def tree_done(o:mutbuf,w:mutbuf,status:u64,entry:u64) -> u32:
    put(w,0,0)
    fill_output(o,64,0)
    word_store(o,0,0)
    word_store(o,8,status)
    word_store(o,16,get(w,8))
    word_store(o,24,get(w,16))
    word_store(o,32,get(w,24))
    word_store(o,40,get(w,80))
    if entry != 0:
        emit_state(o,w,entry,64,384)
        return 448
    return 64

def tree_error(o:mutbuf,w:mutbuf,error:u64) -> u32:
    put(w,0,0)
    put(w,184,3)
    fill_output(o,64,0)
    word_store(o,0,3)
    word_store(o,8,error)
    return 64

def tree_allocate(w:mutbuf) -> u64:
    page = get(w,16)
    if page >= T_MAX_PAGE:
        return NONE
    put(w,16,page+1)
    return page

def tree_writable(w:mutbuf,page:u64) -> u64:
    if page >= get(w,64):
        return page
    return tree_allocate(w)

def tree_header(w:mutbuf) -> u64:
    fill_range(w,T_HEADER,4096,0)
    put(w,T_HEADER,T_FILE_MAGIC)
    put(w,T_HEADER+8,1)
    put(w,T_HEADER+16,get(w,8))
    put(w,T_HEADER+24,get(w,16))
    put(w,T_HEADER+32,get(w,24))
    return put(w,T_HEADER+40,get(w,176)+choose(get(w,80) != 0,1,0))

def tree_ascend(o:mutbuf,w:mutbuf) -> u32:
    depth = get(w,40)
    if depth != 0:
        depth = depth-1
        put(w,40,depth)
        put(w,112,get(w,T_PATH+depth*16+8))
        return tree_read(o,w,30,get(w,T_PATH+depth*16))
    if get(w,144) != 0:
        tree_new_page(w,T_NODE,2)
        put(w,T_NODE+16,1)
        put(w,T_NODE+64,get(w,128))
        copy_state(w,T_PROMOTE,T_NODE+72,64)
        put(w,T_NODE+136,get(w,104))
        page = tree_allocate(w)
        if page == NONE:
            return tree_error(o,w,2)
        put(w,128,page)
        return tree_write(o,w,31,page,T_NODE)
    return tree_finish_update(o,w)

def tree_finish_update(o:mutbuf,w:mutbuf) -> u32:
    put(w,8,get(w,128))
    put(w,24,get(w,24)+get(w,120))
    return tree_done(o,w,1,0)

def tree_parent(o:mutbuf,w:mutbuf) -> u32:
    index = get(w,112)
    if get(w,T_NODE+8) != 2 or index > get(w,T_NODE+16) or get(w,T_NODE+64+index*72) != get(w,96):
        return tree_error(o,w,2)
    put(w,T_NODE+64+index*72,get(w,128))
    if get(w,144) != 0:
        tree_inner_insert(w,T_NODE,index,T_PROMOTE,get(w,104))
    put(w,96,get(w,48))
    put(w,128,tree_writable(w,get(w,48)))
    if get(w,128) == NONE:
        return tree_error(o,w,2)
    if get(w,T_NODE+16) == 56:
        tree_inner_split(w)
        put(w,104,tree_allocate(w))
        if get(w,104) == NONE:
            return tree_error(o,w,2)
        put(w,144,1)
    else:
        put(w,144,0)
    return tree_write(o,w,20,get(w,128),T_NODE)

def tree_new_page(w:mutbuf,at:u64,kind:u64) -> u64:
    fill_range(w,at,8192,0)
    put(w,at,T_PAGE_MAGIC)
    return put(w,at+8,kind)

def tree_record_valid(w:mutbuf,at:u64) -> bool:
    if lowerhex(w,at,64) == False or lowerhex(w,at+64,64) == False:
        return False
    size = get(w,at+192)
    if size == 0 or size > 64 or get(w,at+200) > 2 or get(w,at+224) > 1:
        return False
    if get(w,at+224) == 0 and get(w,at+232) != 0:
        return False
    index = 0
    while index < 64:
        ch = byte(w,at+128+index)
        if index < size:
            if (ch >= 48 and ch <= 57) == False and (ch >= 65 and ch <= 90) == False and (ch >= 97 and ch <= 122) == False and ch != 95:
                return False
        elif ch != 0:
            return False
        index = index+1
    return True

def tree_page_valid(w:mutbuf,at:u64,next:u64) -> bool:
    if get(w,at) != T_PAGE_MAGIC:
        return False
    kind = get(w,at+8)
    count = get(w,at+16)
    if (kind != 1 and kind != 2) or (kind == 1 and count > 10) or (kind == 2 and (count == 0 or count > 55)):
        return False
    offset = 24
    while offset < 64:
        if byte(w,at+offset) != 0:
            return False
        offset = offset+1
    index = 0
    if kind == 1:
        while index < count:
            row = at+64+index*384
            if tree_record_valid(w,row) == False:
                return False
            if index != 0 and index_key_order(w,row-384,row) != 0:
                return False
            index = index+1
        offset = 64+count*384
    else:
        while index <= count:
            child = get(w,at+64+index*72)
            if child == 0 or child >= next:
                return False
            if index < count:
                row = at+72+index*72
                if lowerhex(w,row,64) == False:
                    return False
                if index != 0 and index_key_order(w,row-72,row) != 0:
                    return False
            index = index+1
        offset = 72+count*72
    while offset < 4096:
        if byte(w,at+offset) != 0:
            return False
        offset = offset+1
    return True

def tree_leaf_find(w:mutbuf,page:u64,key:u64) -> u64:
    low = 0
    high = get(w,page+16)
    while low < high:
        middle = low+(high-low)//2
        if index_key_order(w,page+64+middle*384,key) == 0:
            low = middle+1
        else:
            high = middle
    return low

def tree_range_valid(w:mutbuf) -> bool:
    count = get(w,T_NODE+16)
    if count == 0:
        return True
    first = T_NODE+64
    last = first+(count-1)*384
    if get(w,T_NODE+8) == 2:
        first = T_NODE+72
        last = first+(count-1)*72
    if get(w,T_LOWER) != 0 and index_key_order(w,first,T_LOW) == 0:
        return False
    if get(w,T_UPPER) != 0 and index_key_order(w,last,T_HIGH) != 0:
        return False
    return True

def tree_child(w:mutbuf,page:u64,key:u64) -> u64:
    low = 0
    high = get(w,page+16)
    while low < high:
        middle = low+(high-low)//2
        if index_key_order(w,key,page+72+middle*72) == 0:
            high = middle
        else:
            low = middle+1
    return low

def tree_leaf_put(w:mutbuf,page:u64,entry:u64) -> u64:
    count = get(w,page+16)
    at = tree_leaf_find(w,page,entry)
    if at < count:
        row = page+64+at*384
        if index_key_order(w,row,entry) == 1:
            change = index_transition(w,row,entry)
            if change == 0:
                return 0
            if change >= 2:
                return change+1
            copy_state(w,entry,row,384)
            return 1
    move = count
    while move > at:
        copy_state(w,page+64+(move-1)*384,page+64+move*384,384)
        move = move-1
    copy_state(w,entry,page+64+at*384,384)
    put(w,page+16,count+1)
    return 2

def tree_leaf_split(w:mutbuf) -> u64:
    tree_new_page(w,T_RIGHT,1)
    put(w,T_RIGHT+16,6)
    copy_state(w,T_NODE+64+5*384,T_RIGHT+64,6*384)
    copy_state(w,T_RIGHT+64,T_PROMOTE,64)
    put(w,T_NODE+16,5)
    fill_range(w,T_NODE+64+5*384,8192-64-5*384,0)
    return 0

def tree_inner_insert(w:mutbuf,page:u64,at:u64,key:u64,right:u64) -> u64:
    count = get(w,page+16)
    move = count
    while move > at:
        copy_state(w,page+72+(move-1)*72,page+72+move*72,72)
        move = move-1
    copy_state(w,key,page+72+at*72,64)
    put(w,page+136+at*72,right)
    return put(w,page+16,count+1)

def tree_inner_split(w:mutbuf) -> u64:
    tree_new_page(w,T_RIGHT,2)
    put(w,T_RIGHT+16,27)
    put(w,T_RIGHT+64,get(w,T_NODE+64+29*72))
    copy_state(w,T_NODE+72+29*72,T_RIGHT+72,27*72)
    copy_state(w,T_NODE+72+28*72,T_PROMOTE,64)
    put(w,T_NODE+16,28)
    fill_range(w,T_NODE+72+28*72,8192-72-28*72,0)
    return 0

def fill_output(o:mutbuf,size:u64,value:u64) -> u64:
    at = 0
    while at < size:
        store(o,at,value)
        at = at+1
    return at

def emit_state(o:mutbuf,w:mutbuf,source:u64,destination:u64,size:u64) -> u64:
    at = 0
    while at < size:
        word_store(o,destination+at,get(w,source+at))
        at = at+8
    return size
'''


def source():
    return authored(SOURCE+'\n'+INDEX_STATE, extra=C)
