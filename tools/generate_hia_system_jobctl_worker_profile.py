"""HIA admission of one administrator-pinned Worker and its managed state domain.

This source is composed into the existing control owner, not a new syscall
adapter. No request can supply a systemd property or an arbitrary state path.
The profile is an optional field of the root-owned administrator policy.
"""
CONSTANTS = dict(
    WP_PATH=73728, WP_CONFIGURED=77824, WP_SELECTED=77832, WP_PATH_SIZE=77840,
    WP_PRINCIPAL=77848, WP_WIRE_SIZE=77856, WP_NAME_SIZE=77864, WP_STATE_SIZE=77872,
    WP_DIRECTORY_FD=77880, WP_NEXT_FD=77888, WP_FILE_FD=77896, WP_CURSOR=77904,
    WP_FILE_SIZE=77912, WP_READ_SIZE=77920,
    WP_NAME=78336, WP_STATE_PATH=78592, WP_PIN=78848, WP_IDENTITY=78880,
    WP_STAT=78912, WP_FIELDS=79104, WP_WIRE=118 << 20, WP_IMAGE=(68 << 20) + 1,
    WP_SHA_STATE=106 << 20, WP_SHA_OUT=33024, WP_IMAGE_LIMIT=4 << 20,
    WP_SUDO_KEY=int.from_bytes(b'SUDO_UID', 'little'),
    WP_STATE_KEY=int.from_bytes(b'--state-', 'little'),
)
TEXT = {
    'wp_root': '/', 'wp_domain': 'HIAWS001',
    'wp_name': 'hepta-hia-worker-', 'wp_private': '/var/lib/private/',
}
KEYS = ('executable', 'sha256', 'principal_uid', 'state_identity')

POLICY = r'''
def worker_profile_policy(w:mutbuf, profile:u64) -> u64:
    put(w, WP_CONFIGURED, 0)
    put(w, WP_SELECTED, 0)
    if profile == NONE:
        return 1
    if node(w, profile, 0) != 6 or node(w, profile, 32) != 4:
        return 0
    index = 0
    while index < 4:
        put(w, WP_FIELDS + index * 8, NONE)
        index = index + 1
    mask = 0
    child = node(w, profile, 24)
    while child != NONE:
        key = worker_profile_key(w, ARENA + node(w, child, 40), node(w, child, 48))
        if key == 0 or mask & (1 << (key - 1)) != 0:
            return 0
        mask = mask | (1 << (key - 1))
        put(w, WP_FIELDS + (key - 1) * 8, child)
        child = node(w, child, 16)
    if mask != 15:
        return 0
    child = get(w, WP_FIELDS)
    if node(w, child, 0) != 4:
        return 0
    source = ARENA + node(w, child, 24)
    size = node(w, child, 32)
    if worker_path(w, source, size) == 0:
        return 0
    copy(w, WP_PATH, source, size)
    store(w, WP_PATH + size, 0)
    put(w, WP_PATH_SIZE, size)
    if worker_pin(w, get(w, WP_FIELDS + 8), WP_PIN) == 0:
        return 0
    if worker_pin(w, get(w, WP_FIELDS + 24), WP_IDENTITY) == 0:
        return 0
    child = get(w, WP_FIELDS + 16)
    if node(w, child, 0) != 3:
        return 0
    principal = file_integer(w, child)
    if get(w, ERROR) != 0 or principal >= 4294967295:
        return 0
    put(w, WP_PRINCIPAL, principal)
    put(w, WP_CONFIGURED, 1)
    return 1

def worker_path(w:mutbuf, source:u64, size:u64) -> u64:
    if size < 2 or size > 4095 or byte(w, source) != 47:
        return 0
    start = 1
    at = 1
    while at <= size:
        point = choose(at == size, 47, byte(w, source + at))
        if point == 0:
            return 0
        if point == 47:
            width = at - start
            if width == 0 or (width == 1 and byte(w, source + start) == 46):
                return 0
            if width == 2 and byte(w, source + start) == 46 and byte(w, source + start + 1) == 46:
                return 0
            start = at + 1
        at = at + 1
    return 1

def worker_pin(w:mutbuf, child:u64, target:u64) -> u64:
    if child == NONE or node(w, child, 0) != 4 or node(w, child, 32) != 64:
        return 0
    source = ARENA + node(w, child, 24)
    index = 0
    while index < 32:
        high = worker_hex_value(byte(w, source + index * 2))
        low = worker_hex_value(byte(w, source + index * 2 + 1))
        if high > 15 or low > 15:
            return 0
        store(w, target + index, high * 16 + low)
        index = index + 1
    return 1

def worker_hex_value(value:u64) -> u64:
    if value >= 48 and value <= 57:
        return value - 48
    if value >= 97 and value <= 102:
        return value - 87
    return 16

def worker_equal(w:mutbuf, left:u64, left_size:u64, right:u64, right_size:u64) -> u64:
    if left_size != right_size:
        return 0
    index = 0
    while index < left_size:
        if byte(w, left + index) != byte(w, right + index):
            return 0
        index = index + 1
    return 1

def worker_principal(s:readbuf, w:mutbuf) -> u64:
    at = 32
    index = 0
    while index < uint(s, 8):
        if at > length(s) or length(s) - at < 9:
            return 0
        size = uint(s, at)
        if size >= length(s) - at - 8:
            return 0
        at = at + size + 9
        index = index + 1
    index = 0
    matches = 0
    principal = 0
    count = uint(s, 16)
    if count > 262143:
        return 0
    while index < count:
        if at > length(s) or length(s) - at < 9:
            return 0
        size = uint(s, at)
        if size >= length(s) - at - 8 or byte(s, at + 8 + size) != 0:
            return 0
        start = at + 8
        if size >= 9 and uint(s, start) == WP_SUDO_KEY and byte(s, start + 8) == 61:
            if matches != 0 or size < 10 or size > 19:
                return 0
            if size > 10 and byte(s, start + 9) == 48:
                return 0
            cursor = 9
            while cursor < size:
                point = byte(s, start + cursor)
                if point < 48 or point > 57:
                    return 0
                principal = principal * 10 + point - 48
                if principal >= 4294967295:
                    return 0
                cursor = cursor + 1
            matches = 1
        at = at + size + 9
        index = index + 1
    if at != length(s):
        return 0
    if matches == 0:
        return choose(get(w, WP_PRINCIPAL) == 0, 1, 0)
    return choose(principal == get(w, WP_PRINCIPAL), 1, 0)

def worker_begin(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    put(w, WP_SELECTED, 0)
    if get(w, WP_CONFIGURED) == 0:
        return begin_lock(o, w, 300)
    executable = get(w, TABLE + 16)
    if executable == NONE or node(w, executable, 0) != 4:
        return 0
    if worker_equal(w, ARENA + node(w, executable, 24), node(w, executable, 32), WP_PATH, get(w, WP_PATH_SIZE)) == 0:
        return begin_lock(o, w, 300)
    if get(w, 40) != 1 or worker_principal(s, w) == 0:
        return 0
    size = get(w, 2056)
    if size == 0 or size >= 1048576:
        return 0
    at = text_wp_domain(w, WP_WIRE + 1)
    put(w, at, size)
    copy(w, at + 8, PWORK, size)
    at = at + 8 + size
    put(w, at, get(w, WP_PRINCIPAL))
    copy(w, at + 8, WP_IDENTITY, 32)
    put(w, WP_WIRE_SIZE, at + 40 - WP_WIRE - 1)
    return worker_hash(o, w, 80, 0, WP_WIRE, 1)

def worker_hash(o:mutbuf, w:mutbuf, next:u64, command:u64, source:u64, size:u64) -> u32:
    store(w, source, command)
    put(w, 0, next)
    put(o, 0, source)
    put(o, 8, size)
    put(o, 16, WP_SHA_OUT)
    put(o, 24, WP_SHA_STATE)
    return 10

def worker_state_argument(w:mutbuf) -> u64:
    parent = get(w, TABLE + 24)
    if parent == NONE or node(w, parent, 0) != 5:
        return 0
    child = node(w, parent, 24)
    matches = 0
    while child != NONE:
        if node(w, child, 0) != 4:
            return 0
        at = ARENA + node(w, child, 24)
        size = node(w, child, 32)
        if size == 12 and getn(w, at, 8) == WP_STATE_KEY and getn(w, at + 8, 4) == 1953460082:
            if matches != 0:
                return 0
            value = node(w, child, 16)
            if value == NONE or node(w, value, 0) != 4:
                return 0
            if worker_equal(w, ARENA + node(w, value, 24), node(w, value, 32), WP_STATE_PATH, get(w, WP_STATE_SIZE)) == 0:
                return 0
            matches = 1
        child = node(w, child, 16)
    return matches

def worker_admission(o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 80:
        if result != 0:
            return 0
        return worker_hash(o, w, 81, 1, WP_WIRE, get(w, WP_WIRE_SIZE) + 1)
    if phase == 81:
        if result != 0:
            return 0
        return worker_hash(o, w, 82, 2, WP_WIRE, 1)
    if phase == 82:
        if result != 32:
            return 0
        at = text_wp_name(w, WP_NAME)
        index = 0
        while index < 32:
            value = byte(w, WP_SHA_OUT + index)
            store(w, at + index * 2, worker_hex_digit(value >> 4))
            store(w, at + index * 2 + 1, worker_hex_digit(value & 15))
            index = index + 1
        size = at + 64 - WP_NAME
        put(w, WP_NAME_SIZE, size)
        store(w, WP_NAME + size, 0)
        at = text_wp_private(w, WP_STATE_PATH)
        copy(w, at, WP_NAME, size)
        put(w, WP_STATE_SIZE, at + size - WP_STATE_PATH)
        store(w, at + size, 0)
        if worker_state_argument(w) == 0:
            return 0
        put(w, WP_CURSOR, 1)
        store(w, TEMP_PATH, 47)
        store(w, TEMP_PATH + 1, 0)
        return call(o, w, 83, 257, NEG100, TEMP_PATH, 720896, 0, 0, 0, 12)
    if phase == 83:
        if failed(result) or result < 3:
            return 0
        put(w, WP_DIRECTORY_FD, result)
        return call(o, w, 84, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 84:
        if result != 0 or worker_directory(w) == 0:
            return 0
        return worker_component(o, w)
    if phase == 85:
        if failed(result) or result < 3:
            return 0
        put(w, WP_NEXT_FD, result)
        return call(o, w, 86, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 86:
        if result != 0 or worker_directory(w) == 0:
            return 0
        return call(o, w, 87, 3, get(w, WP_DIRECTORY_FD), 0, 0, 0, 0, 0, 0)
    if phase == 87:
        if result != 0:
            return 0
        put(w, WP_DIRECTORY_FD, get(w, WP_NEXT_FD))
        return worker_component(o, w)
    if phase == 88:
        if failed(result) or result < 3:
            return 0
        put(w, WP_FILE_FD, result)
        return call(o, w, 89, 5, result, STAT, 0, 0, 0, 0, 12)
    if phase == 89:
        mode = getn(w, STAT + 24, 4)
        size = get(w, STAT + 48)
        if result != 0 or mode & 61440 != 32768 or mode & 146 != 0 or mode & 5 != 5:
            return 0
        if getn(w, STAT + 28, 4) != 0 or get(w, STAT + 16) != 1 or size < 64 or size > WP_IMAGE_LIMIT:
            return 0
        copy(w, WP_STAT, STAT, 144)
        put(w, WP_FILE_SIZE, size)
        put(w, WP_READ_SIZE, 0)
        return worker_read(o, w)
    if phase == 90:
        if result == NEG4:
            return worker_read(o, w)
        if failed(result) or result == 0 or result > get(w, WP_FILE_SIZE) - get(w, WP_READ_SIZE):
            return 0
        put(w, WP_READ_SIZE, get(w, WP_READ_SIZE) + result)
        if get(w, WP_READ_SIZE) < get(w, WP_FILE_SIZE):
            return worker_read(o, w)
        return call(o, w, 91, 5, get(w, WP_FILE_FD), STAT, 0, 0, 0, 0, 12)
    if phase == 91:
        if result != 0 or worker_same_file(w) == 0 or worker_native_elf(w) == 0:
            return 0
        return worker_hash(o, w, 92, 0, WP_IMAGE - 1, 1)
    if phase == 92:
        if result != 0:
            return 0
        return worker_hash(o, w, 93, 1, WP_IMAGE - 1, get(w, WP_FILE_SIZE) + 1)
    if phase == 93:
        if result != 0:
            return 0
        return worker_hash(o, w, 94, 2, WP_IMAGE - 1, 1)
    if phase == 94:
        if result != 32 or worker_equal(w, WP_SHA_OUT, 32, WP_PIN, 32) == 0:
            return 0
        return call(o, w, 95, 3, get(w, WP_FILE_FD), 0, 0, 0, 0, 0, 0)
    if phase == 95:
        if result != 0:
            return 0
        return call(o, w, 96, 3, get(w, WP_DIRECTORY_FD), 0, 0, 0, 0, 0, 0)
    if phase == 96:
        if result != 0:
            return 0
        put(w, WP_SELECTED, 1)
        return begin_lock(o, w, 300)
    return 0

def worker_hex_digit(value:u64) -> u64:
    return choose(value < 10, value + 48, value + 87)

def worker_directory(w:mutbuf) -> u64:
    mode = getn(w, STAT + 24, 4)
    if mode & 61440 != 16384 or mode & 18 != 0 or mode & 1 != 1:
        return 0
    return choose(getn(w, STAT + 28, 4) == 0, 1, 0)

def worker_component(o:mutbuf, w:mutbuf) -> u32:
    start = get(w, WP_CURSOR)
    stop = start
    while stop < get(w, WP_PATH_SIZE) and byte(w, WP_PATH + stop) != 47:
        stop = stop + 1
    size = stop - start
    if size == 0 or size > 4095:
        return 0
    copy(w, TEMP_PATH, WP_PATH + start, size)
    store(w, TEMP_PATH + size, 0)
    put(w, WP_CURSOR, stop + 1)
    if stop == get(w, WP_PATH_SIZE):
        return call(o, w, 88, 257, get(w, WP_DIRECTORY_FD), TEMP_PATH, 657408, 0, 0, 0, 12)
    return call(o, w, 85, 257, get(w, WP_DIRECTORY_FD), TEMP_PATH, 720896, 0, 0, 0, 12)

def worker_read(o:mutbuf, w:mutbuf) -> u32:
    remaining = get(w, WP_FILE_SIZE) - get(w, WP_READ_SIZE)
    size = choose(remaining < 65536, remaining, 65536)
    return call(o, w, 90, 17, get(w, WP_FILE_FD), WP_IMAGE + get(w, WP_READ_SIZE), size, get(w, WP_READ_SIZE), 0, 0, 12)

def worker_same_file(w:mutbuf) -> u64:
    at = 0
    while at < 120:
        if at < 72 or at >= 88:
            if get(w, STAT + at) != get(w, WP_STAT + at):
                return 0
        at = at + 8
    return 1
'''


def source_program():
    from tools.generate_hia_native_filter import elf_header
    header = elf_header()
    if len(header) != 176:
        raise ValueError('Worker profile requires the canonical two-PHDR ELF')
    lines = ['def worker_native_elf(w:mutbuf) -> u64:']
    for at in range(0, len(header), 8):
        if at not in (96, 104):
            word = int.from_bytes(header[at:at + 8], 'little')
            lines += [f'    if get(w, WP_IMAGE + {at}) != {word}:', '        return 0']
    lines += ['    if get(w, WP_IMAGE + 96) != get(w, WP_FILE_SIZE) or get(w, WP_IMAGE + 104) != get(w, WP_FILE_SIZE):',
              '        return 0', '    return 1']
    return POLICY + '\n' + '\n'.join(lines) + '\n'
