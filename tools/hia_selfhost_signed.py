"""HIA-authored signed scalar checks and direct x86 arithmetic emission."""
SOURCE = r'''
def integer_type(t:u64) -> u64:
    if (t >= 1 and t <= 4) or (t >= 10 and t <= 15):
        return 1
    return 0

def signed_type(t:u64) -> u64:
    if t >= 11 and t <= 15:
        return 1
    return 0

def scalar_type(t:u64) -> u64:
    if integer_type(t) == 1 or t == 5 or t == 16:
        return 1
    return 0

def integer_width(t:u64) -> u64:
    width = 64
    if t == 4 or t == 14:
        width = 8
    if t == 10 or t == 15:
        width = 16
    if t == 3 or t == 13:
        width = 32
    return width

def scalar_literal(s:readbuf, w:mutbuf, t:u64) -> u64:
    if t == 5:
        if get(w, 8) == @true@:
            next_token(s, w)
            return 1
        expect(s, w, @false@)
        return 0
    if t == 16:
        expect(s, w, @null@)
        return 0
    if integer_type(t) != 1:
        return fail(w, 22)
    negative = 0
    x = 0
    width = integer_width(t)
    limit = 0
    if get(w, 8) == 45:
        negative = 1
        next_token(s, w)
        adjacent(w)
    x = expect(s, w, 259)
    if signed_type(t) == 1:
        limit = 1 << (width - 1)
        if negative == 1:
            if x > limit:
                return fail(w, 22)
            return 0 - x
        if x >= limit:
            return fail(w, 22)
    else:
        if negative == 1:
            return fail(w, 22)
        if width < 64:
            if x >= (1 << width):
                return fail(w, 22)
    return x

def signed_integer(o:mutbuf, w:mutbuf, op:u64, n:u64, a:u64, b:u64, at:u64, bt:u64, t:u64) -> u64:
    if t != at:
        return fail(w, 34)
    if op == @bit.not@ or op == @int.neg.checked@:
        if n != 1:
            return fail(w, 31)
        load_var(o, w, 0, a, 0)
        emit(o, w, 72)
        emit(o, w, 247)
        if op == @bit.not@:
            emit(o, w, 208)
            normalize(o, w, t)
            return 0
        emit(o, w, 216)
    else:
        if n != 2 or at != bt:
            return fail(w, 34)
        load_var(o, w, 0, a, 0)
        load_var(o, w, 1, b, 0)
        if op == @int.div.checked@ or op == @int.rem.checked@:
            # test rcx,rcx; jne +2; ud2. Reject zero before IDIV.
            emit_bytes(o, w, 3112727984309576, 7)
            # The Core rejects MIN/-1 for both quotient and remainder at every
            # width, not just the hardware's 64-bit quotient overflow.
            emit(o, w, 72)
            emit(o, w, 186)
            emit8(o, w, 0 - (1 << (integer_width(t) - 1)))
            # cmp rax,rdx; jne +8; cmp rcx,-1; jne +2; ud2
            emit_bytes(o, w, 17979293338566670664, 8)
            emit_bytes(o, w, 47496459775, 5)
            # cqo; idiv rcx
            emit_bytes(o, w, 1073595586888, 5)
            if op == @int.rem.checked@:
                emit_bytes(o, w, 13666632, 3)
            return 0
        emit(o, w, 72)
        if op == @int.mul.checked@:
            emit(o, w, 15)
            emit(o, w, 175)
            emit(o, w, 193)
        else:
            if op == @int.add.checked@:
                emit(o, w, 1)
            else:
                if op != @int.sub.checked@:
                    return fail(w, 36)
                emit(o, w, 41)
            emit(o, w, 200)
    # jno +2; ud2. OF is consumed immediately after add/sub/imul/neg.
    emit_bytes(o, w, 185533041, 4)
    # Preserve the exact full result, then require narrow sign normalization
    # not to change it. This also checks subtraction and unary negation.
    emit_bytes(o, w, 12683592, 3)
    normalize(o, w, t)
    emit_bytes(o, w, 3112727967447368, 7)
    return 0
'''
