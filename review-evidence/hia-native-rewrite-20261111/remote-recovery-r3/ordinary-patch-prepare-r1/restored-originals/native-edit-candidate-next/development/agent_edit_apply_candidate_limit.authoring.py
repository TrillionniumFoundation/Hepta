def edit_apply(s: readbuf, o: mutbuf, w: mutbuf) -> u32:
    if length(w) != 1048576:
        return 4294967293
    if length(o) < 128:
        return refuse(w, 1620)
    if get(w, 0) != 3544424455130401096 or acknowledge(s, w, 59) == 0:
        return refuse(w, 1621)
    while get(w, 8200) == 1:
        phase = get(w, 32)
        if phase >= 300 and phase < 320:
            result = import_hash_step(o, w)
        elif phase >= 40000 and phase < 40100:
            result = edit_simple_step(o, w)
        elif phase >= 42000 and phase < 42100:
            result = edit_bound_step(o, w)
        elif phase >= 45000 and phase < 45100:
            result = edit_publish_step(o, w)
        elif phase >= 61000 and phase < 61100:
            result = apply_copy_step(o, w)
        elif phase == 62000:
            result = apply_release_step(o, w)
        elif phase >= 63000 and phase < 63100:
            result = apply_merge_step(o, w)
        elif phase >= 64000 and phase < 64100:
            result = apply_admit_step(o, w)
        elif phase >= 60100 and phase < 60200:
            result = apply_patch_step(o, w)
        elif phase >= 60200 and phase < 60300:
            result = apply_receipt_step(o, w)
        else:
            result = apply_flow_step(o, w)
        if result != 0:
            return result
    return refuse(w, 1622)

def apply_flow_step(o: mutbuf, w: mutbuf) -> u64:
    phase = get(w, 32)
    if phase == 60000:
        mode = get(w, 16384)
        if mode != 1 and mode != 2:
            return refuse(w, 1623)
        if cap(w, 8) < 82 or cap(w, 7) < 2 or cap(w, 15) == 0:
            return refuse(w, 1624)
        return view(o, w, 5, 0, 64, 60001)
    if phase == 60001:
        if apply_graph_header(w, 5) == 0:
            return refuse(w, 1625)
        policy = 1
        if get(w, 16384) == 2:
            policy = 3
        result = edit_bound_start(w, 5, get(w, 512 + 24), policy, 17, 18, 59, 60002)
        if result != 0:
            return result
        return switch(o, w, 58, 50000)
    if phase == 60002:
        return grow(o, w, 9, 64, 60003)
    if phase == 60003:
        request = advance(w, 16400)
        if request == 0:
            return 4294967293
        wire8(w, 3544406880308775240, 1, 17, request, 0, 0, 0, 0)
        return copy(o, w, 2, 2048, 9, 0, 64, 60004)
    if phase == 60004:
        return edit_simple_start(w, 47, 8, 0, cap(w, 8), 9, 64, 10, 512, 3544409079332030792, 256, 9, 64, 60005)
    if phase == 60005:
        if get(w, 17152 + 8) != 0 or get(w, 17152 + 56) < 128:
            return refuse(w, 1626)
        return apply_copy_start(w, 10, get(w, 17152 + 48), 25, get(w, 17152 + 56), 60006)
    if phase == 60006:
        return apply_release_start(w, 1536, 60007)
    if phase == 60007:
        return apply_merge_start(w, 25, 14, 26, 60008)
    if phase == 60008:
        base = get(w, 24240)
        nodes = get(w, 24256)
        query = get(w, 24248)
        if base > 18446744073709551615 - 2 or nodes > 18446744073709551615 - 2 or query > 18446744073709551615 - nodes - 2:
            return refuse(w, 1627)
        put(w, 24000, base + 2)
        put(w, 24008, nodes)
        put(w, 24016, query + nodes + 2)
        return apply_merge_start(w, 26, 18, 27, 60009)
    if phase == 60009:
        nodes = get(w, 24256)
        root = get(w, 24248)
        if nodes == 18446744073709551615 or root > 18446744073709551615 - nodes - 1:
            return refuse(w, 1628)
        put(w, 24024, root + nodes + 1)
        return hash_start(w, 15, cap(w, 15), 16992, 60010)
    if phase == 60010:
        return hash_start(w, 17, cap(w, 17), 17024, 60011)
    if phase == 60011:
        return grow(o, w, 9, 192, 60012)
    if phase == 60012:
        request = advance(w, 16400)
        if request == 0:
            return 4294967293
        zero(w, 2048, 192)
        wire8(w, 3544406854555748680, 1, 43, request, 0, get(w, 16384), get(w, 24000), get(w, 24016))
        put(w, 2048 + 64, get(w, 24024))
        put(w, 2048 + 72, cap(w, 17))
        copy_digest(w, 2048 + 128, 16992)
        copy_digest(w, 2048 + 160, 17024)
        return copy(o, w, 2, 2048, 9, 0, 192, 60013)
    if phase == 60013:
        return edit_simple_start(w, 50, 27, 0, cap(w, 27), 9, 192, 10, 1024, 3544409053579004232, 256, 9, 192, 60014)
    if phase == 60014:
        if get(w, 17152 + 8) == 2:
            return apply_error(w, 1, get(w, 17152 + 64))
        if get(w, 17152 + 8) != 0 or get(w, 17152 + 56) < 128:
            return refuse(w, 1629)
        put(w, 24032, get(w, 17152 + 80))
        put(w, 24040, get(w, 17152 + 88))
        if get(w, 24032) == 0 or get(w, 24040) == 0:
            return refuse(w, 1630)
        return apply_copy_start(w, 10, get(w, 17152 + 48), 19, get(w, 17152 + 56), 60015)
    if phase == 60015:
        return apply_release_start(w, 1536 | 234881024, 60016)
    if phase == 60016:
        if cap(w, 7) > 8388608:
            return refuse(w, 1631)
        return grow(o, w, 9, 64 + cap(w, 7), 60017)
    if phase == 60017:
        request = advance(w, 16400)
        if request == 0:
            return 4294967293
        put(w, 24328, request)
        wire8(w, 3544406871735617864, 109, request, get(w, 24032), cap(w, 7), get(w, 16392), 0, 0)
        return copy(o, w, 2, 2048, 9, 0, 64, 60018)
    if phase == 60018:
        return copy(o, w, 7, 0, 9, 64, cap(w, 7), 60019)
    if phase == 60019:
        result = edit_service_start(w, 4, 19, 0, cap(w, 19), 9, 0, cap(w, 9), 1024, 59, 60020)
        if result != 0:
            return result
        return switch(o, w, 58, 50000)
    if phase == 60020:
        if apply_service_check(w, 4, 3544409070758873416, 109, get(w, 24328)) == 0:
            return refuse(w, 1632)
        action = get(w, 28800 + 8)
        offset = get(w, 28800 + 72)
        size = get(w, 28800 + 80)
        if inside(w, get(w, 28760), offset, size) == 0 or size == 0:
            return refuse(w, 1633)
        if action == 3:
            return edit_error_start(w, 1, 204, get(w, 28800 + 88), get(w, 28760), offset, size)
        if action != 0 or size > 16777219:
            return refuse(w, 1634)
        put(w, 24072, size)
        return apply_copy_start(w, get(w, 28760), offset, 20, size, 60021)
    if phase == 60021:
        return apply_release_start(w, 1125895611875328 | 1536, 60100)
    return refuse(w, 1635)

def apply_patch_step(o: mutbuf, w: mutbuf) -> u64:
    phase = get(w, 32)
    if phase == 60100:
        size = get(w, 24072)
        if size != cap(w, 20) or size > 16777219:
            return refuse(w, 1640)
        bound = (size + 1 >> 1) + 1
        if bound > 524289:
            bound = 524289
        keys = (size >> 2) + 1
        if keys > 524289:
            keys = 524289
        slots = 2
        while slots < keys * 2:
            slots = slots * 2
        put(w, 24080, maximum(8192, maximum(size + 32, slots * 8)))
        put(w, 24088, maximum(8192, 64 + bound * 56 + size + 8192))
        return grow(o, w, 25, get(w, 24080), 60101)
    if phase == 60101:
        return grow(o, w, 26, get(w, 24088), 60102)
    if phase == 60102:
        return invoke(o, w, 60, 20, 0, get(w, 24072), 25, cap(w, 25), 26, cap(w, 26), 25, 0, 32, 60103)
    if phase == 60103:
        result = get(w, 56)
        if result >= 4294967282 and result <= 4294967295:
            return apply_error(w, 2, result)
        if result < 34 or result > cap(w, 25) or result > 8388608 + 32:
            return refuse(w, 1641)
        if get(w, 512) != 3544425546236643656 or get(w, 512 + 8) != 0 or get(w, 512 + 16) != 0 or (get(w, 512 + 24) != 0):
            return refuse(w, 1642)
        put(w, 24064, result - 32)
        return protect(o, w, 25, 1, 60104)
    if phase == 60104:
        return apply_admit_start(w, 25, 32, get(w, 24064), 60105)
    if phase == 60105:
        return apply_release_start(w, 100663296, 60106)
    if phase == 60106:
        return grow(o, w, 25, 16777248, 60107)
    if phase == 60107:
        return grow(o, w, 26, get(w, 24088), 60108)
    if phase == 60108:
        put(w, 2048, 2)
        put(w, 2048 + 8, 1)
        return copy(o, w, 2, 2048, 26, 0, 16, 60109)
    if phase == 60109:
        return invoke(o, w, 60, 20, 0, get(w, 24072), 25, 16777248, 26, cap(w, 26), 25, 0, 32, 60110)
    if phase == 60110:
        result = get(w, 56)
        if get(w, 512) == 3544405802271983944:
            if result != 4294967294 or get(w, 512 + 8) != 1 or get(w, 512 + 24) != 1:
                return refuse(w, 1697)
            if get(w, 512 + 16) <= 8388608 or get(w, 512 + 16) > 16777248 - 32:
                return refuse(w, 1698)
            return apply_error(w, 5, 4294967294)
        if result == 4294967281:
            return apply_error(w, 3, result)
        if result >= 4294967282 and result <= 4294967295:
            return apply_error(w, 2, result)
        if result < 36 or result > 16777248 or get(w, 512) != 3544423347213388104 or (get(w, 512 + 24) != 0):
            return refuse(w, 1643)
        candidate = get(w, 512 + 8)
        receipt = get(w, 512 + 16)
        if candidate < 2 or candidate > 8388608 or receipt < 2 or (receipt > 8388608) or (result != 32 + candidate + receipt):
            return refuse(w, 1644)
        put(w, 24096, candidate)
        put(w, 24104, receipt)
        return protect(o, w, 25, 1, 60111)
    if phase == 60111:
        return apply_copy_start(w, 25, 32, 21, get(w, 24096), 60112)
    if phase == 60112:
        return apply_copy_start(w, 25, 32 + get(w, 24096), 22, get(w, 24104), 60113)
    if phase == 60113:
        return apply_release_start(w, 100663296, 60114)
    if phase == 60114:
        return apply_admit_start(w, 21, 0, get(w, 24096), 60200)
    return refuse(w, 1645)

def apply_receipt_step(o: mutbuf, w: mutbuf) -> u64:
    phase = get(w, 32)
    if phase == 60200:
        request = advance(w, 16400)
        if request == 0:
            return 4294967293
        put(w, 24328, request)
        wire8(w, 3544406892992350536, 41, request, 9, 4300, 0, 0, 0)
        result = edit_service_start(w, 2, 22, 0, get(w, 24104), 2, 2048, 64, 512, 59, 60201)
        if result != 0:
            return result
        return switch(o, w, 58, 50000)
    if phase == 60201:
        if apply_service_check(w, 2, 3544409066346465608, 41, get(w, 24328)) == 0:
            return refuse(w, 1646)
        if get(w, 28800 + 8) != 0 or get(w, 28800 + 120) < 128:
            return refuse(w, 1647)
        return apply_copy_start(w, get(w, 28760), get(w, 28800 + 112), 25, get(w, 28800 + 120), 60202)
    if phase == 60202:
        return apply_release_start(w, 1125895611875328, 60203)
    if phase == 60203:
        return apply_merge_start(w, 25, 19, 26, 60204)
    if phase == 60204:
        nodes = get(w, 24256)
        root = get(w, 24240)
        metadata = get(w, 24040)
        if root == 18446744073709551615 or nodes == 18446744073709551615 or metadata > 18446744073709551615 - nodes - 1:
            return refuse(w, 1648)
        put(w, 24112, root + 1)
        put(w, 24040, metadata + nodes + 1)
        return grow(o, w, 9, 192, 60205)
    if phase == 60205:
        request = advance(w, 16400)
        if request == 0:
            return 4294967293
        zero(w, 2048, 192)
        wire8(w, 3544406927570192712, 1, 107, request, 0, get(w, 16384), get(w, 24112), get(w, 24040))
        copy_digest(w, 2048 + 128, 16768)
        return copy(o, w, 2, 2048, 9, 0, 192, 60206)
    if phase == 60206:
        return edit_simple_start(w, 53, 26, 0, cap(w, 26), 9, 192, 10, 1024, 3544409126593448264, 256, 9, 192, 60207)
    if phase == 60207:
        if get(w, 17152 + 8) != 0 or get(w, 17152 + 56) < 128 or get(w, 17152 + 72) == 0:
            return refuse(w, 1649)
        put(w, 24128, get(w, 17152 + 72))
        return apply_copy_start(w, 10, get(w, 17152 + 48), 27, get(w, 17152 + 56), 60208)
    if phase == 60208:
        return apply_release_start(w, 1536, 60209)
    if phase == 60209:
        return view(o, w, 27, 0, 64, 60210)
    if phase == 60210:
        if apply_graph_header(w, 27) == 0 or get(w, 24128) > get(w, 512 + 16):
            return refuse(w, 1650)
        put(w, 24136, get(w, 512 + 8))
        request = advance(w, 16400)
        if request == 0:
            return 4294967293
        put(w, 24328, request)
        wire8(w, 3544406948877257032, get(w, 24136), request, get(w, 24128), 8388608, 3, 4300, 0)
        result = edit_service_start(w, 1, 27, 0, cap(w, 27), 2, 2048, 64, 32768, 59, 60211)
        if result != 0:
            return result
        return switch(o, w, 58, 50000)
    if phase == 60211:
        if apply_service_check(w, 1, 3544409147900512584, get(w, 24136), get(w, 24328)) == 0:
            return refuse(w, 1651)
        if get(w, 28800 + 32) != get(w, 24128) or get(w, 28800 + 40) != 8388608 or get(w, 28800 + 48) != 3 or (get(w, 28800 + 56) != 4300):
            return refuse(w, 1652)
        if get(w, 28800 + 8) != 0 or get(w, 28800 + 64) != 0 or get(w, 28800 + 72) != 0 or (get(w, 28800 + 120) != 0):
            return refuse(w, 1653)
        size = get(w, 28800 + 96)
        if size == 0 or size > 8388608:
            return refuse(w, 1654)
        return apply_copy_start(w, get(w, 28760), get(w, 28800 + 88), 23, size, 60212)
    if phase == 60212:
        return apply_release_start(w, 1125895611875328, 60213)
    if phase == 60213:
        return edit_result_start(w, 21, 0, get(w, 24096), 23, 0, cap(w, 23), 15, 0, cap(w, 15))
    return refuse(w, 1655)

def apply_graph_header(w: mutbuf, slot: u64) -> u64:
    if get(w, 512) != 3544410225937303880 or get(w, 512 + 8) == 0 or get(w, 512 + 16) == 0:
        return 0
    if get(w, 512 + 24) == 0 or get(w, 512 + 24) > get(w, 512 + 16) or get(w, 512 + 48) != cap(w, slot) or (get(w, 512 + 56) != 0):
        return 0
    return 1

def apply_copy_start(w: mutbuf, source: u64, at: u64, target: u64, size: u64, next: u64) -> u64:
    if target < 4 or target >= 64 or target == source or (cap(w, target) != 0) or (size == 0) or (inside(w, source, at, size) == 0):
        return refuse(w, 1600)
    put(w, 24144, source)
    put(w, 24152, at)
    put(w, 24160, target)
    put(w, 24168, size)
    put(w, 24176, next)
    put(w, 32, 61000)
    return 0

def apply_copy_step(o: mutbuf, w: mutbuf) -> u64:
    phase = get(w, 32)
    if phase == 61000:
        return grow(o, w, get(w, 24160), get(w, 24168), 61001)
    if phase == 61001:
        return copy(o, w, get(w, 24144), get(w, 24152), get(w, 24160), 0, get(w, 24168), 61002)
    if phase == 61002:
        return protect(o, w, get(w, 24160), 1, get(w, 24176))
    return refuse(w, 1601)

def apply_release_start(w: mutbuf, mask: u64, next: u64) -> u64:
    if mask & 15 != 0:
        return refuse(w, 1602)
    put(w, 24184, mask)
    put(w, 24192, 4)
    put(w, 24200, next)
    put(w, 32, 62000)
    return 0

def apply_release_step(o: mutbuf, w: mutbuf) -> u64:
    slot = get(w, 24192)
    while slot < 64:
        put(w, 24192, slot + 1)
        if get(w, 24184) & 1 << slot != 0:
            return release(o, w, slot, 62000)
        slot = slot + 1
    put(w, 32, get(w, 24200))
    return 0

def apply_merge_start(w: mutbuf, left: u64, right: u64, target: u64, next: u64) -> u64:
    if cap(w, left) < 128 or cap(w, right) < 128 or cap(w, target) != 0 or (cap(w, 9) != 0) or (cap(w, 10) != 0):
        return refuse(w, 1603)
    put(w, 24208, left)
    put(w, 24216, right)
    put(w, 24224, target)
    put(w, 24232, next)
    put(w, 32, 63000)
    return 0

def apply_merge_step(o: mutbuf, w: mutbuf) -> u64:
    phase = get(w, 32)
    if phase == 63000:
        return view(o, w, get(w, 24208), 0, 64, 63001)
    if phase == 63001:
        if apply_graph_header(w, get(w, 24208)) == 0 or cap(w, get(w, 24208)) > 18446744073709551615 - 128:
            return refuse(w, 1604)
        put(w, 24240, get(w, 512 + 24))
        put(w, 24256, get(w, 512 + 16))
        put(w, 24272, cap(w, get(w, 24208)) + 128)
        return view(o, w, get(w, 24216), 0, 64, 63002)
    if phase == 63002:
        if apply_graph_header(w, get(w, 24216)) == 0:
            return refuse(w, 1605)
        put(w, 24248, get(w, 512 + 24))
        put(w, 24264, get(w, 512 + 16))
        return grow(o, w, 9, get(w, 24272), 63003)
    if phase == 63003:
        request = advance(w, 16400)
        if request == 0:
            return 4294967293
        zero(w, 2048, 128)
        wire8(w, 3544406905927584072, 1, 41, request, 0, get(w, 24240), get(w, 24248), 0)
        return copy(o, w, 2, 2048, 9, 0, 128, 63004)
    if phase == 63004:
        return copy(o, w, get(w, 24208), 0, 9, 128, cap(w, get(w, 24208)), 63005)
    if phase == 63005:
        return edit_simple_start(w, 48, 9, 0, get(w, 24272), get(w, 24216), cap(w, get(w, 24216)), 10, 512, 3544409104950839624, 256, 9, get(w, 24272), 63006)
    if phase == 63006:
        if get(w, 17152 + 8) != 0 or get(w, 17152 + 56) < 128:
            return refuse(w, 1606)
        return apply_copy_start(w, 10, get(w, 17152 + 48), get(w, 24224), get(w, 17152 + 56), 63007)
    if phase == 63007:
        return apply_release_start(w, 1536, get(w, 24232))
    return refuse(w, 1607)

def apply_service_check(w: mutbuf, kind: u64, magic: u64, lease: u64, request: u64) -> u64:
    if get(w, 28672) != 2 or get(w, 28680) != kind or get(w, 28776) != 128 or (get(w, 28792) != 128):
        return 0
    if get(w, 28800) != magic or get(w, 28800 + 16) != lease or get(w, 28800 + 24) != request:
        return 0
    if get(w, 28760) < 32 or get(w, 28760) >= 50 or cap(w, get(w, 28760)) != get(w, 28768):
        return 0
    return 1

def apply_admit_start(w: mutbuf, source: u64, at: u64, size: u64, next: u64) -> u64:
    if size < 2 or size > 8388608 or inside(w, source, at, size) == 0:
        return refuse(w, 1608)
    if cap(w, 50) != 0 or cap(w, 51) != 0 or cap(w, 52) != 0:
        return refuse(w, 1609)
    put(w, 24280, source)
    put(w, 24288, at)
    put(w, 24296, size)
    put(w, 24304, next)
    put(w, 32, 64000)
    return 0

def apply_admission_status(status: u64) -> u64:
    if status >= 4294967285 and status <= 4294967295 and (status != 4294967293):
        return 1
    if status >= 4294967280 and status <= 4294967284 and (status != 4294967281):
        return 1
    if status == 4294967279 or status == 4294967278:
        return 1
    return 0

def apply_diag_header(w: mutbuf) -> u64:
    if get(w, 512) != 3544425558903441736 or get(w, 512 + 8) != 1 or get(w, 512 + 16) != get(w, 24312):
        return 0
    message = get(w, 512 + 24)
    size = get(w, 512 + 32)
    needed = get(w, 512 + 40)
    nodes = get(w, 512 + 48)
    if message == 0 or message > 92 or size == 0 or (size > 8651776 - 64):
        return 0
    if needed != size + 64 or nodes == 0 or nodes > 262144 or (get(w, 512 + 56) != 0):
        return 0
    if needed > get(w, 24296) + nodes + 1024:
        return 0
    return 1

def apply_admit_step(o: mutbuf, w: mutbuf) -> u64:
    phase = get(w, 32)
    if phase == 64000:
        return grow(o, w, 50, 67108864, 64001)
    if phase == 64001:
        return grow(o, w, 51, 33554432, 64002)
    if phase == 64002:
        return invoke(o, w, 27, get(w, 24280), get(w, 24288), get(w, 24296), 50, 67108864, 51, 33554432, 0, 0, 0, 64003)
    if phase == 64003:
        status = get(w, 56)
        if status == 0:
            return apply_release_start(w, 3377699720527872, get(w, 24304))
        if apply_admission_status(status) == 0:
            return refuse(w, 1610)
        put(w, 24312, status)
        return protect(o, w, 50, 1, 64004)
    if phase == 64004:
        return protect(o, w, 51, 1, 64005)
    if phase == 64005:
        return grow(o, w, 52, 64, 64006)
    if phase == 64006:
        return invoke(o, w, 55, 51, 0, 33554432, 50, 67108864, 52, 64, 52, 0, 64, 64007)
    if phase == 64007:
        if get(w, 56) != 4294967294 or apply_diag_header(w) == 0:
            return refuse(w, 1611)
        put(w, 24320, get(w, 512 + 40))
        copy_local(w, 26880, 512, 64)
        return grow(o, w, 52, get(w, 24320), 64008)
    if phase == 64008:
        return invoke(o, w, 55, 51, 0, 33554432, 50, 67108864, 52, cap(w, 52), 52, 0, 64, 64009)
    if phase == 64009:
        if get(w, 56) != get(w, 24320) or cap(w, 52) != get(w, 24320):
            return refuse(w, 1612)
        i = 0
        while i < 64:
            if byte(w, 26880 + i) != byte(w, 512 + i):
                return refuse(w, 1613)
            i = i + 1
        return protect(o, w, 52, 1, 64010)
    if phase == 64010:
        return apply_release_start(w, 3377699720527872, 64011)
    if phase == 64011:
        return edit_error_start(w, 2, 8, get(w, 24312), 52, 64, get(w, 24320) - 64)
    return refuse(w, 1614)

def apply_error(w: mutbuf, stage: u64, code: u64) -> u64:
    if stage == 1 and code == 1:
        put(w, 2048 + 0, 6147799700344430405)
        put(w, 2048 + 8, 8315177769752941125)
        put(w, 2048 + 16, 7020303014240874352)
        put(w, 2048 + 24, 7161124112489914489)
        put(w, 2048 + 32, 8367821614270586981)
        put(w, 2048 + 40, 7162249965381641576)
        put(w, 2048 + 48, 8391171928515437940)
        put(w, 2048 + 56, 2336927755366790514)
        store(w, 2048 + 64, 102)
        store(w, 2048 + 65, 105)
        store(w, 2048 + 66, 101)
        store(w, 2048 + 67, 108)
        store(w, 2048 + 68, 100)
        store(w, 2048 + 69, 115)
        return edit_error_start(w, 1, 201, code, 2, 2048, 70)
    if stage == 1 and code == 2:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 5207098233433576521)
        put(w, 2048 + 16, 7957702707512483898)
        put(w, 2048 + 24, 7599104626777941363)
        put(w, 2048 + 32, 7161137258227262834)
        put(w, 2048 + 40, 8388346166453562484)
        store(w, 2048 + 48, 115)
        return edit_error_start(w, 1, 201, code, 2, 2048, 49)
    if stage == 1 and code == 3:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 5207098233433576521)
        put(w, 2048 + 16, 2340027261499285562)
        put(w, 2048 + 24, 7234316346692756851)
        put(w, 2048 + 32, 8461454895015883552)
        put(w, 2048 + 40, 8247607571316241523)
        put(w, 2048 + 48, 8749496146259895584)
        store(w, 2048 + 56, 32)
        store(w, 2048 + 57, 111)
        store(w, 2048 + 58, 110)
        store(w, 2048 + 59, 99)
        store(w, 2048 + 60, 101)
        return edit_error_start(w, 1, 201, code, 2, 2048, 61)
    if stage == 1 and code == 4:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 5207098233433576521)
        put(w, 2048 + 16, 7594306061618716730)
        put(w, 2048 + 24, 8244249722772136052)
        put(w, 2048 + 32, 8386654100814590821)
        put(w, 2048 + 40, 2334399978113366380)
        put(w, 2048 + 48, 7953753191867510369)
        store(w, 2048 + 56, 103)
        store(w, 2048 + 57, 101)
        store(w, 2048 + 58, 115)
        return edit_error_start(w, 1, 201, code, 2, 2048, 59)
    if stage == 1 and code == 5:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 5207098233433576521)
        put(w, 2048 + 16, 7163375912571117626)
        put(w, 2048 + 24, 7575180394847630433)
        put(w, 2048 + 32, 8295740917569123950)
        store(w, 2048 + 40, 105)
        store(w, 2048 + 41, 116)
        store(w, 2048 + 42, 101)
        return edit_error_start(w, 1, 201, code, 2, 2048, 43)
    if stage == 1 and code == 6:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 5207098233433576521)
        put(w, 2048 + 16, 7306930285074128954)
        put(w, 2048 + 24, 7234299854336630899)
        put(w, 2048 + 32, 7310577382390592288)
        put(w, 2048 + 40, 8314889994848575588)
        return edit_error_start(w, 1, 201, code, 2, 2048, 48)
    if stage == 2 and code == 4294967295:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7022922066722182217)
        put(w, 2048 + 16, 5642820435954657644)
        put(w, 2048 + 24, 2339727159116526368)
        put(w, 2048 + 32, 8026374883499864687)
        store(w, 2048 + 40, 100)
        store(w, 2048 + 41, 101)
        return edit_error_start(w, 1, 202, code, 2, 2048, 42)
    if stage == 2 and code == 4294967294:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7166460041258226761)
        put(w, 2048 + 16, 3203314360716435560)
        put(w, 2048 + 24, 7214815417035877920)
        put(w, 2048 + 32, 2338053341540806757)
        put(w, 2048 + 40, 7142837056756282735)
        put(w, 2048 + 48, 2340029477383401569)
        put(w, 2048 + 56, 7234298763096062053)
        return edit_error_start(w, 1, 202, code, 2, 2048, 64)
    if stage == 2 and code == 4294967293:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7598805596895859785)
        put(w, 2048 + 16, 7521983764480681334)
        put(w, 2048 + 24, 7521983764518630176)
        put(w, 2048 + 32, 8031728383256850208)
        put(w, 2048 + 40, 8079579156292329827)
        put(w, 2048 + 48, 8223684435877719922)
        store(w, 2048 + 56, 101)
        store(w, 2048 + 57, 102)
        store(w, 2048 + 58, 117)
        store(w, 2048 + 59, 115)
        store(w, 2048 + 60, 101)
        store(w, 2048 + 61, 100)
        return edit_error_start(w, 1, 202, code, 2, 2048, 62)
    if stage == 2 and code == 4294967292:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7813874426385683529)
        put(w, 2048 + 16, 6001645073540932457)
        put(w, 2048 + 24, 7236270204636909135)
        return edit_error_start(w, 1, 202, code, 2, 2048, 32)
    if stage == 2 and code == 4294967291:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7166460041258226761)
        put(w, 2048 + 16, 8028903795027419240)
        put(w, 2048 + 24, 7594793497469674864)
        put(w, 2048 + 32, 7310011937178545253)
        put(w, 2048 + 40, 7235433442201987360)
        return edit_error_start(w, 1, 202, code, 2, 2048, 48)
    if stage == 2 and code == 4294967290:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7022922066722182217)
        put(w, 2048 + 16, 7309474570952796524)
        put(w, 2048 + 24, 7020675452077700195)
        put(w, 2048 + 32, 7594230556110910320)
        store(w, 2048 + 40, 103)
        store(w, 2048 + 41, 101)
        store(w, 2048 + 42, 115)
        store(w, 2048 + 43, 116)
        return edit_error_start(w, 1, 202, code, 2, 2048, 44)
    if stage == 2 and code == 4294967289:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7809651266647905353)
        put(w, 2048 + 16, 8295742059845918821)
        store(w, 2048 + 24, 110)
        store(w, 2048 + 25, 97)
        store(w, 2048 + 26, 112)
        store(w, 2048 + 27, 115)
        store(w, 2048 + 28, 104)
        store(w, 2048 + 29, 111)
        store(w, 2048 + 30, 116)
        return edit_error_start(w, 1, 202, code, 2, 2048, 31)
    if stage == 2 and code == 4294967288:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7166460041258226761)
        put(w, 2048 + 16, 2338323018191609960)
        put(w, 2048 + 24, 7234223785059954225)
        store(w, 2048 + 32, 105)
        store(w, 2048 + 33, 116)
        store(w, 2048 + 34, 115)
        return edit_error_start(w, 1, 202, code, 2, 2048, 35)
    if stage == 2 and code == 4294967287:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7956574616011035721)
        put(w, 2048 + 16, 8388346166452844399)
        store(w, 2048 + 24, 32)
        store(w, 2048 + 25, 97)
        store(w, 2048 + 26, 99)
        store(w, 2048 + 27, 116)
        store(w, 2048 + 28, 105)
        store(w, 2048 + 29, 111)
        store(w, 2048 + 30, 110)
        return edit_error_start(w, 1, 202, code, 2, 2048, 31)
    if stage == 2 and code == 4294967286:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7022922066722182217)
        put(w, 2048 + 16, 8314314652890982764)
        put(w, 2048 + 24, 7214892424658972261)
        put(w, 2048 + 32, 7310575174727528565)
        put(w, 2048 + 40, 8028075781168391712)
        put(w, 2048 + 48, 7598819853036232814)
        store(w, 2048 + 56, 116)
        store(w, 2048 + 57, 121)
        return edit_error_start(w, 1, 202, code, 2, 2048, 58)
    if stage == 2 and code == 4294967285:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7022922066722182217)
        put(w, 2048 + 16, 6998719642544138604)
        put(w, 2048 + 24, 7809840388254298978)
        put(w, 2048 + 32, 7954874719498101615)
        store(w, 2048 + 40, 116)
        store(w, 2048 + 41, 105)
        store(w, 2048 + 42, 116)
        store(w, 2048 + 43, 121)
        return edit_error_start(w, 1, 202, code, 2, 2048, 44)
    if stage == 2 and code == 4294967284:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7022922066722182217)
        put(w, 2048 + 16, 8243118315558693228)
        put(w, 2048 + 24, 7955925875414365281)
        store(w, 2048 + 32, 100)
        store(w, 2048 + 33, 101)
        store(w, 2048 + 34, 120)
        return edit_error_start(w, 1, 202, code, 2, 2048, 35)
    if stage == 2 and code == 4294967283:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 8243124912625701961)
        put(w, 2048 + 16, 2334956330951926124)
        put(w, 2048 + 24, 7596570320960516719)
        put(w, 2048 + 32, 7594306061468983651)
        store(w, 2048 + 40, 116)
        store(w, 2048 + 41, 115)
        return edit_error_start(w, 1, 202, code, 2, 2048, 42)
    if stage == 2 and code == 4294967282:
        put(w, 2048 + 0, 4919442901979127621)
        put(w, 2048 + 8, 7310589492920472649)
        put(w, 2048 + 16, 7521891422469973618)
        put(w, 2048 + 24, 7306367055897783905)
        put(w, 2048 + 32, 7596570333862196068)
        put(w, 2048 + 40, 7863340432320915811)
        put(w, 2048 + 48, 8079569282028169065)
        store(w, 2048 + 56, 111)
        store(w, 2048 + 57, 108)
        store(w, 2048 + 58, 105)
        store(w, 2048 + 59, 99)
        store(w, 2048 + 60, 121)
        return edit_error_start(w, 1, 202, code, 2, 2048, 61)
    if stage == 3 and code == 4294967281:
        put(w, 2048 + 0, 4706366344609161029)
        put(w, 2048 + 8, 4992314212300112724)
        put(w, 2048 + 16, 7166460041258221901)
        put(w, 2048 + 24, 7018413018159587432)
        put(w, 2048 + 32, 7306640048292656227)
        put(w, 2048 + 40, 2336646318805513074)
        put(w, 2048 + 48, 7234314139196417380)
        put(w, 2048 + 56, 8295745289980047392)
        store(w, 2048 + 64, 99)
        store(w, 2048 + 65, 104)
        store(w, 2048 + 66, 101)
        store(w, 2048 + 67, 109)
        store(w, 2048 + 68, 97)
        return edit_error_start(w, 4, 203, code, 2, 2048, 69)
    if stage == 5 and code == 4294967294:
        put(w, 2048 + 0, 5281701197005741893)
        put(w, 2048 + 8, 8030604369274882381)
        put(w, 2048 + 16, 7167589996908606055)
        put(w, 2048 + 24, 8392847272096064869)
        put(w, 2048 + 32, 8387223562211172453)
        put(w, 2048 + 40, 2334397804646326816)
        put(w, 2048 + 48, 7453010313431182949)
        return edit_error_start(w, 2, 205, code, 2, 2048, 56)
    return refuse(w, 1699)

def maximum(a: u64, b: u64) -> u64:
    if a > b:
        return a
    return b

def edit_service_start(w: mutbuf, kind: u64, source: u64, offset: u64, size: u64, command: u64, command_at: u64, command_bytes: u64, initial: u64, driver: u64, phase: u64) -> u64:
    if kind < 1 or kind > 6 or initial < 128:
        return refuse(w, 1001)
    if driver != 56 and driver != 57 and (driver != 59):
        return refuse(w, 1002)
    if inside(w, source, offset, size) == 0 or inside(w, command, command_at, command_bytes) == 0:
        return refuse(w, 1003)
    slot = 32
    while slot < 50:
        if cap(w, slot) != 0:
            return refuse(w, 1004)
        slot = slot + 1
    if get(w, 28672) == 1:
        return refuse(w, 1005)
    zero(w, 28672, 384)
    put(w, 28672, 1)
    put(w, 28680, kind)
    put(w, 28688, source)
    put(w, 28696, offset)
    put(w, 28704, size)
    put(w, 28712, command)
    put(w, 28720, command_at)
    put(w, 28728, command_bytes)
    put(w, 28736, initial)
    put(w, 28744, driver)
    put(w, 28752, phase)
    return 0

def edit_simple_start(w: mutbuf, image: u64, first: u64, offset: u64, size: u64, second: u64, secondbytes: u64, work: u64, initial: u64, magic: u64, event_at: u64, command: u64, commandbytes: u64, next: u64) -> u64:
    if work < 4 or work >= 64 or cap(w, work) != 0 or (initial < event_at + 128):
        return refuse(w, 1010)
    if get(w, 30464) == 1 or commandbytes < 64 or inside(w, command, 0, commandbytes) == 0:
        return refuse(w, 1011)
    if command != first and command != second:
        return refuse(w, 1012)
    if inside(w, first, offset, size) == 0 or inside(w, second, 0, secondbytes) == 0:
        return refuse(w, 1013)
    zero(w, 30464, 160)
    put(w, 30464, 1)
    put(w, 30472, image)
    put(w, 30480, first)
    put(w, 30488, offset)
    put(w, 30496, size)
    put(w, 30504, second)
    put(w, 30512, secondbytes)
    put(w, 30520, work)
    put(w, 30528, initial)
    put(w, 30536, magic)
    put(w, 30544, event_at)
    put(w, 30552, command)
    put(w, 30560, commandbytes)
    put(w, 30568, next)
    put(w, 32, 40000)
    return 0

def edit_simple_step(o: mutbuf, w: mutbuf) -> u64:
    phase = get(w, 32)
    if get(w, 30464) != 1:
        return refuse(w, 1014)
    if phase == 40000:
        return view(o, w, get(w, 30552), 0, 64, 40001)
    if phase == 40001:
        if get(w, 512 + 8) != 1 or get(w, 512 + 16) == 0 or get(w, 512 + 24) == 0 or (get(w, 512 + 32) != 0):
            return refuse(w, 1015)
        put(w, 30576, get(w, 512 + 16))
        put(w, 30584, get(w, 512 + 24))
        return grow(o, w, get(w, 30520), get(w, 30528), 40002)
    if phase == 40002:
        return invoke(o, w, get(w, 30472), get(w, 30480), get(w, 30488), get(w, 30496), get(w, 30504), get(w, 30512), get(w, 30520), cap(w, get(w, 30520)), get(w, 30520), get(w, 30544), 128, 40003)
    if phase == 40003:
        if get(w, 56) != get(w, 30544) + 128 or get(w, 512) != get(w, 30536):
            return refuse(w, 1016)
        if get(w, 512 + 16) != get(w, 30576) or get(w, 512 + 24) != get(w, 30584) or get(w, 30592) == 18446744073709551615 or (get(w, 512 + 32) != get(w, 30592) + 1):
            return refuse(w, 1017)
        put(w, 30592, get(w, 512 + 32))
        action = get(w, 512 + 8)
        if action == 1:
            if get(w, 512 + 40) <= cap(w, get(w, 30520)):
                return refuse(w, 1018)
            put(w, 30608, get(w, 512 + 40))
            return protect(o, w, get(w, 30552), 0, 40004)
        if action != 0 and action != 2:
            return refuse(w, 1019)
        copy_local(w, 17152, 512, 128)
        put(w, 30464, 2)
        put(w, 32, get(w, 30568))
        return 0
    if phase == 40004:
        put(w, 2048, 2)
        return copy(o, w, 2, 2048, get(w, 30552), 8, 8, 40005)
    if phase == 40005:
        put(w, 2048, get(w, 30592))
        return copy(o, w, 2, 2048, get(w, 30552), 32, 8, 40006)
    if phase == 40006:
        return grow(o, w, get(w, 30520), get(w, 30608), 40002)
    return refuse(w, 1020)

def copy_local(w: mutbuf, to: u64, at: u64, size: u64) -> u64:
    i = 0
    while i < size:
        store(w, to + i, byte(w, at + i))
        i = i + 1
    return 0

def copy_digest(w: mutbuf, to: u64, at: u64) -> u64:
    return copy_local(w, to, at, 32)

def hash_start(w: mutbuf, slot: u64, size: u64, to: u64, next: u64) -> u64:
    return hash_view_start(w, slot, 0, size, to, next)

def hash_view_start(w: mutbuf, slot: u64, at: u64, size: u64, to: u64, next: u64) -> u64:
    if inside(w, slot, at, size) == 0 or size == 18446744073709551615:
        return refuse(w, 1021)
    put(w, 31232, slot)
    put(w, 31280, at)
    put(w, 31240, size)
    put(w, 31248, to)
    put(w, 31256, next)
    put(w, 31264, 0)
    put(w, 32, 300)
    return 0

def edit_result_start(w: mutbuf, first: u64, first_at: u64, first_bytes: u64, second: u64, second_at: u64, second_bytes: u64, third: u64, third_at: u64, third_bytes: u64) -> u64:
    if inside(w, first, first_at, first_bytes) == 0 or inside(w, second, second_at, second_bytes) == 0 or inside(w, third, third_at, third_bytes) == 0:
        return refuse(w, 1030)
    if first == 30 or second == 30 or third == 30 or (cap(w, 30) != 0):
        return refuse(w, 1031)
    if first_bytes > 18446744073709551615 - 64 or second_bytes > 18446744073709551615 - 64 - first_bytes or third_bytes > 18446744073709551615 - 64 - first_bytes - second_bytes:
        return refuse(w, 1032)
    put(w, 28000, first)
    put(w, 28008, first_at)
    put(w, 28016, first_bytes)
    put(w, 28024, second)
    put(w, 28032, second_at)
    put(w, 28040, second_bytes)
    put(w, 28048, third)
    put(w, 28056, third_at)
    put(w, 28064, third_bytes)
    put(w, 28072, 64 + first_bytes + second_bytes + third_bytes)
    put(w, 28080, 0)
    put(w, 28088, 0)
    put(w, 28096, 0)
    put(w, 32, 45000)
    return 0

def edit_error_start(w: mutbuf, domain: u64, stage: u64, code: u64, source: u64, offset: u64, size: u64) -> u64:
    if domain == 0 or domain > 4 or inside(w, source, offset, size) == 0 or (source == 30) or (cap(w, 30) != 0):
        return refuse(w, 1033)
    put(w, 28080, domain)
    put(w, 28088, stage)
    put(w, 28096, code)
    put(w, 28104, source)
    put(w, 28112, offset)
    put(w, 28120, size)
    put(w, 28072, size)
    put(w, 32, 45010)
    return 0

def edit_publish_step(o: mutbuf, w: mutbuf) -> u64:
    phase = get(w, 32)
    if phase == 45000:
        return grow(o, w, 30, get(w, 28072), 45001)
    if phase == 45001:
        wire8(w, 3544423359913740616, get(w, 16384), get(w, 28016), get(w, 28040), get(w, 28064), 0, 0, 0)
        return copy(o, w, 2, 2048, 30, 0, 64, 45002)
    if phase == 45002:
        return copy(o, w, get(w, 28000), get(w, 28008), 30, 64, get(w, 28016), 45003)
    if phase == 45003:
        return copy(o, w, get(w, 28024), get(w, 28032), 30, 64 + get(w, 28016), get(w, 28040), 45004)
    if phase == 45004:
        return copy(o, w, get(w, 28048), get(w, 28056), 30, 64 + get(w, 28016) + get(w, 28040), get(w, 28064), 45005)
    if phase == 45005:
        return protect(o, w, 30, 1, 45006)
    if phase == 45006:
        return edit_terminal(o, w)
    if phase == 45010:
        if get(w, 28072) == 0:
            return edit_terminal(o, w)
        return grow(o, w, 30, get(w, 28072), 45011)
    if phase == 45011:
        return copy(o, w, get(w, 28104), get(w, 28112), 30, 0, get(w, 28120), 45005)
    return refuse(w, 1034)

def edit_terminal(o: mutbuf, w: mutbuf) -> u32:
    if get(w, 8200) != 1 or get(w, 40) != 0:
        return refuse(w, 1035)
    put(w, 8200, 2)
    zero(o, 0, 128)
    put(o, 0, 3544409066229025096)
    put(o, 8, 7)
    put(o, 16, get(w, 16))
    put(o, 24, get(w, 24))
    put(o, 32, get(w, 28080))
    put(o, 40, get(w, 28096))
    if get(w, 28072) != 0:
        put(o, 48, 30)
        put(o, 64, get(w, 28072))
    put(o, 72, get(w, 16384))
    put(o, 80, get(w, 28088))
    return 128

def edit_bound_start(w: mutbuf, source: u64, root: u64, policy: u64, raw_target: u64, graph_target: u64, driver: u64, next: u64) -> u64:
    if policy < 1 or policy > 5 or root == 0 or (cap(w, source) < 128):
        return refuse(w, 1040)
    if raw_target != 0 and (raw_target < 4 or raw_target >= 64 or cap(w, raw_target) != 0):
        return refuse(w, 1041)
    if graph_target != 0 and (graph_target < 4 or graph_target >= 64 or cap(w, graph_target) != 0):
        return refuse(w, 1042)
    if raw_target != 0 and raw_target == graph_target:
        return refuse(w, 1043)
    request = advance(w, 16400)
    if request == 0:
        return 4294967293
    put(w, 18000, policy)
    put(w, 18008, raw_target)
    put(w, 18016, graph_target)
    put(w, 18024, driver)
    put(w, 18032, next)
    put(w, 18040, request)
    wire8(w, 3544406949045029192, 101, request, root, policy, get(w, 16392), 0, 0)
    return edit_service_start(w, 3, source, 0, cap(w, source), 2, 2048, 64, 1024, driver, 42000)

def edit_bound_step(o: mutbuf, w: mutbuf) -> u64:
    phase = get(w, 32)
    if phase == 42000:
        if get(w, 28672) != 2 or get(w, 28680) != 3 or get(w, 28776) != 128 or (get(w, 28792) != 128):
            return refuse(w, 1044)
        if get(w, 28800) != 3544409148068284744 or get(w, 28800 + 16) != 101 or get(w, 28800 + 24) != get(w, 18040):
            return refuse(w, 1045)
        action = get(w, 28800 + 8)
        if action != 0 and action != 3:
            return refuse(w, 1046)
        if get(w, 28800 + 112) != 1024 or get(w, 28800 + 120) != 96 or cap(w, get(w, 28760)) != get(w, 28768):
            return refuse(w, 1047)
        put(w, 18104, action)
        return view(o, w, get(w, 28760), 1024, 96, 42001)
    if phase == 42001:
        if get(w, 512) != 3544420143184562504 or get(w, 512 + 8) != get(w, 18000):
            return refuse(w, 1048)
        put(w, 18136, get(w, 512 + 16))
        put(w, 18112, get(w, 512 + 24))
        put(w, 18120, get(w, 512 + 32))
        put(w, 18128, get(w, 512 + 88))
        put(w, 18048, get(w, 512 + 40))
        put(w, 18056, get(w, 512 + 48))
        put(w, 18064, get(w, 512 + 56))
        put(w, 18072, get(w, 512 + 64))
        put(w, 18080, get(w, 512 + 72))
        put(w, 18088, get(w, 512 + 80))
        if inside(w, get(w, 28760), get(w, 18048), get(w, 18056)) == 0 or inside(w, get(w, 28760), get(w, 18064), get(w, 18072)) == 0 or inside(w, get(w, 28760), get(w, 18080), get(w, 18088)) == 0:
            return refuse(w, 1049)
        if get(w, 18104) == 3:
            if get(w, 18136) != 1 and get(w, 18136) != 2:
                return refuse(w, 1050)
            if get(w, 18112) == 0 or get(w, 18088) == 0:
                return refuse(w, 1051)
            domain = 1
            if get(w, 18136) == 2:
                domain = 3
            return edit_error_start(w, domain, get(w, 18000), get(w, 18112), get(w, 28760), get(w, 18080), get(w, 18088))
        if get(w, 18136) != 0 or get(w, 18112) != 0 or get(w, 18120) != 0 or (get(w, 18088) != 0) or (get(w, 18128) != 0):
            return refuse(w, 1052)
        if get(w, 18008) != 0:
            if get(w, 18056) == 0:
                return refuse(w, 1053)
            return grow(o, w, get(w, 18008), get(w, 18056), 42002)
        put(w, 32, 42004)
        return 0
    if phase == 42002:
        return copy(o, w, get(w, 28760), get(w, 18048), get(w, 18008), 0, get(w, 18056), 42003)
    if phase == 42003:
        return protect(o, w, get(w, 18008), 1, 42004)
    if phase == 42004:
        if get(w, 18016) != 0:
            if get(w, 18072) < 128:
                return refuse(w, 1054)
            return grow(o, w, get(w, 18016), get(w, 18072), 42005)
        put(w, 32, 42007)
        return 0
    if phase == 42005:
        return copy(o, w, get(w, 28760), get(w, 18064), get(w, 18016), 0, get(w, 18072), 42006)
    if phase == 42006:
        return protect(o, w, get(w, 18016), 1, 42007)
    if phase == 42007:
        put(w, 18096, 32)
        put(w, 32, 42008)
        return 0
    if phase == 42008:
        slot = get(w, 18096)
        if slot == 50:
            put(w, 32, get(w, 18032))
            return 0
        put(w, 18096, slot + 1)
        return release(o, w, slot, 42008)
    return refuse(w, 1055)

def import_hash_step(o: mutbuf, w: mutbuf) -> u64:
    phase = get(w, 32)
    if phase == 300:
        return grow(o, w, 61, minimum(get(w, 31240), 8388608) + 1, 301)
    if phase == 301:
        return grow(o, w, 62, 32, 302)
    if phase == 302:
        return grow(o, w, 63, 1184, 303)
    if phase == 303:
        store(w, 2048, 0)
        return invoke(o, w, 22, 2, 2048, 1, 62, 32, 63, 1184, 0, 0, 0, 304)
    if phase == 304:
        if get(w, 56) != 0:
            return refuse(w, 821)
        store(w, 2048, 1)
        return copy(o, w, 2, 2048, 61, 0, 1, 305)
    if phase == 305:
        chunk = minimum(get(w, 31240) - get(w, 31264), 8388608)
        put(w, 31272, chunk)
        return copy(o, w, get(w, 31232), get(w, 31280) + get(w, 31264), 61, 1, chunk, 306)
    if phase == 306:
        return invoke(o, w, 22, 61, 0, get(w, 31272) + 1, 62, 32, 63, 1184, 0, 0, 0, 307)
    if phase == 307:
        if get(w, 56) != 0:
            return refuse(w, 822)
        put(w, 31264, get(w, 31264) + get(w, 31272))
        if get(w, 31264) < get(w, 31240):
            put(w, 32, 305)
            return 0
        store(w, 2048, 2)
        return invoke(o, w, 22, 2, 2048, 1, 62, 32, 63, 1184, 62, 0, 32, 308)
    if phase == 308:
        if get(w, 56) != 32:
            return refuse(w, 823)
        copy_digest(w, get(w, 31248), 512)
        return release(o, w, 61, 309)
    if phase == 309:
        return release(o, w, 62, 310)
    if phase == 310:
        return release(o, w, 63, 311)
    if phase == 311:
        put(w, 32, get(w, 31256))
        return 0
    return refuse(w, 824)

def word(s: readbuf, at: u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | byte(s, at + i) << i * 8
        i = i + 1
    return value

def get(w: mutbuf, at: u64) -> u64:
    i = 0
    value = 0
    while i < 8:
        value = value | byte(w, at + i) << i * 8
        i = i + 1
    return value

def put(w: mutbuf, at: u64, value: u64) -> u64:
    i = 0
    while i < 8:
        store(w, at + i, value >> i * 8 & 255)
        i = i + 1
    return 0

def zero(w: mutbuf, at: u64, size: u64) -> u64:
    i = 0
    while i < size:
        store(w, at + i, 0)
        i = i + 1
    return 0

def refuse(w: mutbuf, reason: u64) -> u32:
    put(w, 8192, 3544424459542808904)
    put(w, 8200, 3)
    put(w, 472, reason)
    return 4294967293

def args(w: mutbuf, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64, i: u64, j: u64, k: u64, l: u64) -> u64:
    put(w, 1024, a)
    put(w, 1024 + 8, b)
    put(w, 1024 + 16, c)
    put(w, 1024 + 24, d)
    put(w, 1024 + 32, e)
    put(w, 1024 + 40, f)
    put(w, 1024 + 48, g)
    put(w, 1024 + 56, h)
    put(w, 1024 + 64, i)
    put(w, 1024 + 72, j)
    put(w, 1024 + 80, k)
    put(w, 1024 + 88, l)
    return 0

def event(o: mutbuf, w: mutbuf, opcode: u64, phase: u64) -> u32:
    seq = get(w, 24)
    if get(w, 8200) != 1 or get(w, 40) != 0 or seq == 18446744073709551615:
        return refuse(w, 1)
    put(w, 24, seq + 1)
    put(w, 40, opcode)
    put(w, 48, phase)
    put(o, 0, 3544409066229025096)
    put(o, 8, opcode)
    put(o, 16, get(w, 16))
    put(o, 24, seq + 1)
    i = 0
    while i < 96:
        store(o, 32 + i, byte(w, 1024 + i))
        i = i + 1
    return 128

def acknowledge(s: readbuf, w: mutbuf, driver: u64) -> u64:
    if get(w, 8192) != 3544424459542808904 or get(w, 8200) != 1:
        return 0
    pending = get(w, 40)
    if pending == 0 or length(s) < 64:
        return 0
    if get(w, 8208) != driver:
        if pending != 8 or get(w, 8216) != driver:
            return 0
    elif pending == 8:
        return 0
    observed = get(w, 64)
    if observed > 256 or length(s) != 64 + observed:
        return 0
    if word(s, 0) != 3544404668182513992 or word(s, 8) != get(w, 16) or word(s, 16) != get(w, 24):
        return 0
    if word(s, 24) != pending or word(s, 32) != 0 or word(s, 48) != observed or (word(s, 56) != 0):
        return 0
    if pending != 1 and pending != 14 and (pending != 15) and (word(s, 40) != 0):
        return 0
    if pending == 14 and word(s, 40) != 0:
        return 0
    if pending == 2:
        put(w, 4096 + get(w, 72) * 8, get(w, 80))
    if pending == 5:
        put(w, 4096 + get(w, 1024) * 8, 0)
    if pending == 8:
        put(w, 8208, driver)
        put(w, 8216, 0)
    put(w, 56, word(s, 40))
    i = 0
    while i < observed:
        store(w, 512 + i, byte(s, 64 + i))
        i = i + 1
    put(w, 40, 0)
    put(w, 32, get(w, 48))
    put(w, 64, 0)
    return 1

def cap(w: mutbuf, slot: u64) -> u64:
    if slot >= 64:
        return 0
    return get(w, 4096 + slot * 8)

def inside(w: mutbuf, slot: u64, offset: u64, size: u64) -> u64:
    extent = cap(w, slot)
    if slot >= 64 or offset > extent or size > extent - offset:
        return 0
    return 1

def grow(o: mutbuf, w: mutbuf, slot: u64, size: u64, phase: u64) -> u32:
    if slot == 0 or slot == 1 or slot == 2 or (slot >= 64) or (size == 0):
        return refuse(w, 2)
    if cap(w, slot) >= size:
        put(w, 32, phase)
        return 0
    put(w, 72, slot)
    put(w, 80, size)
    put(w, 64, 0)
    args(w, slot, size, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 2, phase)

def release(o: mutbuf, w: mutbuf, slot: u64, phase: u64) -> u32:
    if slot < 4 or slot >= 64:
        return refuse(w, 3)
    if cap(w, slot) == 0:
        put(w, 32, phase)
        return 0
    put(w, 64, 0)
    args(w, slot, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 5, phase)

def copy(o: mutbuf, w: mutbuf, source: u64, at: u64, target: u64, to: u64, size: u64, phase: u64) -> u32:
    if source == target or target < 4 or inside(w, source, at, size) == 0 or (inside(w, target, to, size) == 0):
        return refuse(w, 5)
    put(w, 64, 0)
    args(w, source, at, target, to, size, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 4, phase)

def protect(o: mutbuf, w: mutbuf, slot: u64, readonly: u64, phase: u64) -> u32:
    if slot < 4 or slot >= 64 or cap(w, slot) == 0 or (readonly > 1):
        return refuse(w, 6)
    put(w, 64, 0)
    args(w, slot, readonly, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 6, phase)

def invoke(o: mutbuf, w: mutbuf, image: u64, first: u64, at: u64, size: u64, second: u64, secondsize: u64, work: u64, worksize: u64, observe: u64, offset: u64, count: u64, phase: u64) -> u32:
    if first == second or first == work or second == work or (image == 0) or (image > 63) or (image >= 40 and image <= 46) or (image >= 56 and image <= 59):
        return refuse(w, 7)
    if inside(w, first, at, size) == 0 or inside(w, second, 0, secondsize) == 0 or inside(w, work, 0, worksize) == 0:
        return refuse(w, 8)
    if count > 256 or inside(w, observe, offset, count) == 0:
        return refuse(w, 9)
    put(w, 64, count)
    args(w, image, first, at, size, second, secondsize, work, worksize, observe, offset, count, 0)
    return event(o, w, 1, phase)

def view(o: mutbuf, w: mutbuf, slot: u64, offset: u64, count: u64, phase: u64) -> u32:
    if count > 256 or inside(w, slot, offset, count) == 0:
        return refuse(w, 10)
    put(w, 64, count)
    args(w, slot, offset, count, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 14, phase)

def switch(o: mutbuf, w: mutbuf, target: u64, phase: u64) -> u32:
    if target < 56 or target > 59 or target == get(w, 8208):
        return refuse(w, 11)
    put(w, 8216, target)
    put(w, 64, 0)
    args(w, target, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
    return event(o, w, 8, phase)

def wire8(w: mutbuf, a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64) -> u64:
    put(w, 2048, a)
    put(w, 2048 + 8, b)
    put(w, 2048 + 16, c)
    put(w, 2048 + 24, d)
    put(w, 2048 + 32, e)
    put(w, 2048 + 40, f)
    put(w, 2048 + 48, g)
    put(w, 2048 + 56, h)
    return 0

def minimum(left: u64, right: u64) -> u64:
    if left < right:
        return left
    return right

def advance(w: mutbuf, field: u64) -> u64:
    value = get(w, field)
    if value == 18446744073709551615:
        refuse(w, 18)
        return 0
    value = value + 1
    put(w, field, value)
    return value
