"""HIA-owned sealed subprocess transport for fixed roles and OpenSSH."""
from tools.generate_hia_mcp_job_bridge_common import authored

TEXT=dict(frame='hia-mcp-job-frame',helper='hia-mcp-job-helper',ssh='ssh',
          ssh_t='-T',option='-o',batch='BatchMode=yes',connect='ConnectTimeout=8',
          strict='StrictHostKeyChecking=yes',forward='ForwardAgent=no')
SOURCE=r'''
def advance(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    phase = get(w, 0)
    result = get(w, 8)
    if phase == 0:
        if get(w, 528) < 1 or get(w, 528) > 12 or get(w, 536) > 16777216 or get(w, 544) > 8388608 or get(w, 552) > 8388608 or get(w, 560) == 0 or get(w, 560) > 30000000000:
            return 0
        put(w, 600, 0)
        put(w, 608, 0)
        put(w, 616, 0)
        put(w, 624, 0)
        put(w, 632, 0)
        put(w, 640, 0)
        put(w, 648, 0)
        put(w, 688, 0)
        at = text_frame(w, 65536)
        store(w, at, 0)
        return call(o, w, 1, 319, 65536, 3, 0, 0, 0, 0, 3)
    if phase == 1:
        if failed(result) or result < 3:
            return 0
        put(w, 576, result)
        return frame_write(o, w)
    if phase == 2:
        if result == NEG4:
            return frame_write(o, w)
        if failed(result) or result == 0 or result > get(w, 536) - get(w, 688):
            return 0
        put(w, 688, get(w, 688) + result)
        if get(w, 688) < get(w, 536):
            return frame_write(o, w)
        return call(o, w, 3, 8, get(w, 576), 0, 0, 0, 0, 0, 0)
    if phase == 3:
        if result != 0:
            return 0
        return call(o, w, 4, 72, get(w, 576), 1033, 15, 0, 0, 0, 0)
    if phase == 4:
        if failed(result):
            return 0
        return call(o, w, 5, 72, get(w, 576), 1034, 0, 0, 0, 0, 0)
    if phase == 5:
        if result != 15:
            return 0
        return call(o, w, 6, 293, 8192, 524288, 0, 0, 0, 0, 3)
    if phase == 6:
        if failed(result):
            return 0
        put(w, 656, getn(w, 8192, 4))
        put(w, 664, getn(w, 8196, 4))
        return call(o, w, 7, 72, get(w, 656), 4, 2048, 0, 0, 0, 0)
    if phase == 7:
        if failed(result):
            return 0
        return call(o, w, 8, 293, 8200, 524288, 0, 0, 0, 0, 3)
    if phase == 8:
        if failed(result):
            return 0
        put(w, 672, getn(w, 8200, 4))
        put(w, 680, getn(w, 8204, 4))
        return call(o, w, 9, 72, get(w, 672), 4, 2048, 0, 0, 0, 0)
    if phase == 9:
        if failed(result):
            return 0
        return argv(o, w)
    if phase == 10:
        if failed(result):
            return 0
        if get(w, 528) == 11:
            return relocate(o, w, 11, 53248, get(w, 104) + 1, 55296)
        put(w, 55296, 0)
        return call(o, w, 12, 228, 1, 8224, 0, 0, 0, 0, 12)
    if phase == 11:
        if failed(result):
            return 0
        return call(o, w, 12, 228, 1, 8224, 0, 0, 0, 0, 12)
    if phase == 12:
        if failed(result):
            return 0
        now = get(w, 8224) * 1000000000 + get(w, 8232)
        deadline = now + get(w, 560)
        if deadline > get(w, 48):
            deadline = get(w, 48)
        if deadline <= now:
            put(w, 608, 1)
            return cleanup(o, w)
        put(w, 592, deadline)
        return call(o, w, 22, 39, 0, 0, 0, 0, 0, 0, 0)
    if phase == 22:
        if failed(result):
            return 0
        put(w, 736, result)
        return call(o, w, 13, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 13:
        if failed(result):
            return 0
        if result == 0:
            return call(o, w, 60, 157, 1, 9, 0, 0, 0, 0, 0)
        put(w, 584, result)
        return call(o, w, 14, 3, get(w, 664), 0, 0, 0, 0, 0, 0)
    if phase == 14:
        if failed(result):
            return abort(o, w, 3)
        return call(o, w, 15, 3, get(w, 680), 0, 0, 0, 0, 0, 0)
    if phase == 15:
        if failed(result):
            return abort(o, w, 3)
        return read_pipe(o, w, 0)
    if phase == 16 or phase == 17:
        which = phase - 16
        if result == NEG4:
            return read_pipe(o, w, which)
        if result == NEG11:
            result = 0
        elif failed(result):
            return abort(o, w, 3)
        else:
            slot = choose(which == 0, 624, 616)
            cap = get(w, 544 + which * 8)
            if result > cap - get(w, slot):
                return abort(o, w, 2)
            if result == 0:
                put(w, 640 + which * 8, 1)
            else:
                put(w, slot, get(w, slot) + result)
        if which == 0:
            return read_pipe(o, w, 1)
        if get(w, 632) == 0:
            return call(o, w, 18, 61, get(w, 584), 8256, 1, 0, 0, 0, 12)
        return progress(o, w)
    if phase == 18:
        if result == NEG4:
            return call(o, w, 18, 61, get(w, 584), 8256, 1, 0, 0, 0, 12)
        if failed(result) or (result != 0 and result != get(w, 584)):
            return abort(o, w, 3)
        if result != 0:
            put(w, 632, 1)
            put(w, 600, getn(w, 8256, 4))
        return progress(o, w)
    if phase == 19:
        if failed(result):
            return abort(o, w, 3)
        if get(w, 8224) * 1000000000 + get(w, 8232) >= get(w, 592):
            return abort(o, w, 1)
        put(w, 8288, choose(get(w, 640) != 0, 4294967295, get(w, 656)) | 4294967296)
        put(w, 8296, choose(get(w, 648) != 0, 4294967295, get(w, 672)) | 4294967296)
        return call(o, w, 20, 7, 8288, 2, 10, 0, 0, 0, 3)
    if phase == 20:
        if failed(result) and result != NEG4:
            return abort(o, w, 3)
        return read_pipe(o, w, 0)
    if phase == 30:
        return call(o, w, 31, 61, get(w, 584), 8256, 0, 0, 0, 0, 12)
    if phase == 31:
        if result == NEG4:
            return call(o, w, 31, 61, get(w, 584), 8256, 0, 0, 0, 0, 12)
        if result == get(w, 584):
            put(w, 632, 1)
            put(w, 600, getn(w, 8256, 4))
        return cleanup(o, w)
    if phase == 40:
        return call(o, w, 41, 3, get(w, 672), 0, 0, 0, 0, 0, 0)
    if phase == 41:
        return call(o, w, 42, 3, get(w, 576), 0, 0, 0, 0, 0, 0)
    if phase == 42:
        return enter(w, get(w, 512), get(w, 520))
    if phase >= 50 and phase <= 62:
        return child_setup(o, w, phase, result)
    return 0

def frame_write(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 536) == 0:
        return call(o, w, 3, 8, get(w, 576), 0, 0, 0, 0, 0, 0)
    return call(o, w, 2, 1, get(w, 576), CHILD_IN + get(w, 688), get(w, 536) - get(w, 688), 0, 0, 0, 12)

def argv(o:mutbuf, w:mutbuf) -> u32:
    start = 65536
    if get(w, 528) == 11:
        start = text_ssh(w, start)
    else:
        start = text_helper(w, start)
    store(w, start, 0)
    put(w, 40960, 65536)
    count = 1
    at = start + 1
    if get(w, 528) == 11:
        put(w, 40968, at)
        at = text_ssh_t(w, at)
        store(w, at, 0)
        at = at + 1
        index = 0
        while index < 4:
            put(w, 40976 + index * 16, at)
            at = text_option(w, at)
            store(w, at, 0)
            at = at + 1
            put(w, 40984 + index * 16, at)
            if index == 0:
                at = text_batch(w, at)
            elif index == 1:
                at = text_connect(w, at)
            elif index == 2:
                at = text_strict(w, at)
            else:
                at = text_forward(w, at)
            store(w, at, 0)
            at = at + 1
            index = index + 1
        put(w, 41040, at)
        at = cp(w, S_SSH_TARGET, at)
        store(w, at, 0)
        at = at + 1
        put(w, 41048, at)
        at = cp(w, S_REMOTE_COMMAND, at)
        store(w, at, 0)
        count = 12
    put(w, 40960 + count * 8, NONE)
    store(w, 25000, 0)
    return relocate(o, w, 10, 40960, count + 1, 45056)

def read_pipe(o:mutbuf, w:mutbuf, which:u64) -> u32:
    slot = choose(which == 0, 624, 616)
    maximum = get(w, 544 + which * 8)
    fd = choose(which == 0, get(w, 656), get(w, 672))
    size = maximum - get(w, slot)
    target = choose(which == 0, CHILD_OUT, CHILD_ERR) + get(w, slot)
    if size == 0:
        size = 1
        target = 24700 + which
    return call(o, w, 16 + which, 0, fd, target, size, 0, 0, 0, 12)

def progress(o:mutbuf, w:mutbuf) -> u32:
    if get(w, 632) != 0 and get(w, 640) != 0 and get(w, 648) != 0:
        return cleanup(o, w)
    return call(o, w, 19, 228, 1, 8224, 0, 0, 0, 0, 12)

def abort(o:mutbuf, w:mutbuf, cause:u64) -> u32:
    put(w, 608, cause)
    if get(w, 632) != 0:
        return cleanup(o, w)
    return call(o, w, 30, 62, get(w, 584), 9, 0, 0, 0, 0, 0)

def cleanup(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 40, 3, get(w, 656), 0, 0, 0, 0, 0, 0)

def child_setup(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if failed(result):
        return call(o, w, 59, 60, 127, 0, 0, 0, 0, 0, 0)
    if phase == 60:
        return call(o, w, 61, 110, 0, 0, 0, 0, 0, 0, 0)
    if phase == 61:
        if result != get(w, 736):
            return call(o, w, 59, 60, 127, 0, 0, 0, 0, 0, 0)
        return call(o, w, 50, 33, get(w, 576), 0, 0, 0, 0, 0, 0)
    if phase == 50:
        descriptor = choose(get(w, 568) == NONE, get(w, 664), get(w, 568))
        return call(o, w, 51, 33, descriptor, 1, 0, 0, 0, 0, 0)
    if phase == 51:
        return call(o, w, 52, 33, get(w, 680), 2, 0, 0, 0, 0, 0)
    if phase == 52:
        return call(o, w, 53, 436, 3, 4294967295, 4, 0, 0, 0, 0)
    if phase == 53:
        return call(o, w, 54, 322, get(w, 4096 + (get(w, 528) - 1) * 64), 25000, 45056, 55296, 4096, 0, 252)
    return call(o, w, 59, 60, 127, 0, 0, 0, 0, 0, 0)
'''

def source():
    return authored(SOURCE,text=TEXT)
