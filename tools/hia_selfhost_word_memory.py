"""Self-hosted byte and v9 word access with complete bounds before access.

This authoring fragment lowers to ordinary HIA v8 assembly. Successor
compilers implement these checks and emit the instructions themselves.
"""

SCHEMA_STATE = 1016592  # Eight unused bytes following the complete export table.

SOURCE = r'''
def word_memory(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    word = op >= @buffer.load.u64.le@
    if word and get(w, SCHEMA_STATE) != @hepta.hia.program.v9@:
        return fail(w, 68)
    loan_access(w, a)
    if (at != 6 and at != 7) or bt != 2:
        return fail(w, 29)
    is_load = op == @buffer.load@ or op == @buffer.load.u64.le@ or op == @buffer.load.u64.be@
    value_type = choose(word, 1, 4)
    if is_load:
        if n != 2 or t != value_type:
            return fail(w, 30)
    else:
        if n != 3 or t != 0 or at != 7 or variable(w, get(w, ARGS + 16)) != value_type:
            return fail(w, 30)
    load_var(o, w, 1, b, 0)
    load_var(o, w, 2, a, 1)
    if word:
        # cmp rcx,rdx; jbe +2; ud2.
        emit_bytes(o, w, 0x0b0f0276d13948, 7)
        # sub rdx,rcx; cmp rdx,8; jae +2; ud2.
        emit8(o, w, 0x7308fa8348ca2948)
        emit_bytes(o, w, 0x0b0f02, 3)
    else:
        # Original byte access: cmp rcx,rdx; jb +2; ud2.
        emit_bytes(o, w, 0x0b0f0272d13948, 7)
    load_var(o, w, 0, a, 0)
    # The base+offset calculation occurs only after both guards.
    emit_bytes(o, w, 0xc80148, 3)
    if is_load:
        if word:
            emit_bytes(o, w, 0x008b48, 3)
            if op == @buffer.load.u64.be@:
                emit_bytes(o, w, 0xc80f48, 3)
        else:
            emit_bytes(o, w, 0x00b60f, 3)
    else:
        load_var(o, w, 2, get(w, ARGS + 16), 0)
        if word:
            if op == @buffer.store.u64.be@:
                emit_bytes(o, w, 0xca0f48, 3)
            emit_bytes(o, w, 0x108948, 3)
        else:
            emit_bytes(o, w, 0x1088, 2)
    return 0
'''
