"""HIA v25 status snapshot extension for the native observation owner."""

import ast

from tools.generate_hia_agent_binary64 import source_program as binary64_source

# Frozen Unicode 16 decimal-zero ranges of the retained host metadata oracle.
# This is an authored table, not a runtime dependency on a host Unicode library.
DECIMAL_ZEROES = (
    48, 1632, 1776, 1984, 2406, 2534, 2662, 2790, 2918, 3046, 3174, 3302,
    3430, 3558, 3664, 3792, 3872, 4160, 4240, 6112, 6160, 6470, 6608, 6784,
    6800, 6992, 7088, 7232, 7248, 42528, 43216, 43264, 43472, 43504, 43600,
    44016, 65296, 66720, 68912, 68928, 69734, 69872, 69942, 70096, 70384,
    70736, 70864, 71248, 71360, 71376, 71386, 71472, 71904, 72016, 72688,
    72784, 73040, 73120, 73552, 90416, 92768, 92864, 93008, 93552, 118000,
    120782, 120792, 120802, 120812, 120822, 123200, 123632, 124144, 124401,
    125264, 130032,
)

STATUS_FIELDS = (
    'terminal_publication_protocol', 'launch_nonce', 'backend',
    'supervisor_uid', 'supervisor_pid', 'supervisor_identity', 'kind', 'value',
    'invocation_id', 'effect_outcome', 'timed_out', 'cancelled', 'exit_code',
    'output_complete', 'output_durable', 'exit_sha256',
    'LoadState', 'ActiveState', 'SubState', 'Result', 'ExecMainPID',
    'ExecMainCode', 'ExecMainStatus', 'InvocationID', 'Description',
    'XDG_RUNTIME_DIR', 'DBUS_SESSION_BUS_ADDRESS', 'active', 'activating',
    'exited', 'dead', 'proc_start_ticks', 'systemd', 'unknown',
)

STATUS_TEXT = {
    'started_name': 'started.json', 'witness_name': 'exit.witness.json',
    'pending_open': '{"state":"finalizing","outcome":"unknown","reason":',
    'pending_end': ',"terminal_publication_confirmed":false,"status_authoritative":false,"automatic_retry":false',
    'owner_unknown': '{"state":"owner_unknown","reason":"frozen supervisor binding unavailable","status_authoritative":false,"automatic_retry":false',
    'job_id': ',"job_id":', 'quote': '"', 'null': 'null', 'comma': ',',
    'unsupported': 'terminal publication protocol is unsupported',
    'unsafe_receipt': 'terminal receipt is unavailable or unsafe',
    'missing_receipt': 'supervisor disappeared without a confirmed terminal receipt',
    'detached_backend': '"detached"',
    'terminal_open': '{"_hia_terminal":{"receipt":',
    'witness_open': ',"confirmed":false,"witness":{"protocol":[',
    'request_nonce': '],"request_nonce":',
    'witness_job': ',"job":', 'nonce': ',"nonce":', 'digest': ',"digest":',
    'raw': ',"raw":"', 'witness_end': '"}}',
    'facts': ',"facts":[', 'facts_end': '],"confirmed":false}',
    'lifecycle_open': '{"_hia_lifecycle":{"observations":{"starter_uid":',
    'effective_uid': ',"effective_uid":', 'starter_pid': ',"starter_pid":',
    'request_job': ',"request_job":', 'starter_job': ',"starter_job":',
    'owner_request_nonce': ',"request_nonce":', 'starter_nonce': ',"starter_nonce":',
    'expected_kind': ',"expected_kind":"proc_start_ticks","starter_kind":',
    'starter_identity': ',"starter_identity":', 'starter_invocation': ',"starter_invocation":',
    'request_witness': ',"request_witness":', 'observed_uid': ',"observed_uid":',
    'observed_kind': ',"observed_kind":', 'observed_identity': ',"observed_identity":',
    'proc_kind': '"proc_start_ticks"', 'systemd': '},"systemd":',
    'object_open': '{', 'object_close': '}', 'colon': ':',
    'detached_open': '{"state":', 'running': '"running"', 'lost': '"lost"',
    'backend': ',"backend":', 'pid': ',"pid":', 'identity': ',"identity":',
    'identity_open': '{"kind":"proc_start_ticks","value":',
    'proc': '/proc/', 'proc_stat': 'stat', 'boot': '/proc/sys/kernel/random/boot_id',
    'systemctl': '/usr/bin/systemctl', 'user': '--user', 'show': 'show',
    'no_pager': '--no-pager',
    'properties': '--property=LoadState,ActiveState,SubState,Result,ExecMainPID,ExecMainCode,ExecMainStatus,InvocationID,Description',
    'path_env': 'PATH=/usr/bin:/bin', 'xdg_env': 'XDG_RUNTIME_DIR=/run/user/',
    'bus_env': 'DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/', 'bus_end': '/bus',
    'devnull': '/dev/null',
}

STATUS = r'''
def status_metadata(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    which = get(w, 88)
    present = get(w, 192)
    if which == 0:
        put(w, 200, protocol(w, lookup(w, 6)))
        nonce = lookup(w, 7)
        size = field_string(w, nonce, 32768, 128)
        put(w, 400, size)
        valid_nonce = size == 32 and lowercase_hex(w, 32768, 32)
        put(w, 208, choose(valid_nonce, 1, 0))
        put(w, 408, copy_field_raw(w, nonce, 226492416) - 226492416)
        put(w, 88, 1)
        return open_metadata(o, w)
    if which == 1:
        field = NONE
        if present != 0:
            field = lookup(w, 8)
        put(w, 216, choose(field_is(w, field, 38), 1, 0))
        if get(w, 216) == 0:
            if field == NONE:
                at = text_detached_backend(w, 226492416)
            else:
                at = copy_field_raw(w, field, 226492416)
            put(w, 224, at - 226492416)
        put(w, 88, 2)
        return open_metadata(o, w)
    if which == 2 or which == 5:
        if get(w, 200) == 2:
            return pending(s, o, w, 0)
        if present == 0:
            if which == 2 and get(w, 216) != 0:
                return systemctl_start(s, o, w)
            put(w, 88, 3)
            return open_metadata(o, w)
        if getn(w, 4120, 4) & 4095 != 384 or get(w, 104) > 1048576 or get(w, 104) != get(w, 4144):
            return pending(s, o, w, 1)
        put(w, 240, get(w, 104))
        put(w, 248, get(w, 232))
        copy_state(w, META, 12582912, get(w, 104))
        copy_state(w, RAW_JSON, 9437184, get(w, 232))
        put(w, 256, protocol(w, lookup(w, 6)))
        if get(w, 200) == 0 and get(w, 256) == 0:
            return legacy_terminal(s, o, w)
        put(w, 88, 4)
        return open_metadata(o, w)
    if which == 4:
        return witness_reply(s, o, w, choose(present == 0, 3, protocol(w, lookup(w, 6))))
    if which == 3:
        return lifecycle_start(s, o, w, present != 0)
    return 0

def observation_limit(w:mutbuf) -> u64:
    which = get(w, 88)
    if which == 3:
        return 16384
    if which == 4:
        return 4096
    if which == 5:
        return 1048576
    return 4194304

def metadata_failure(s:readbuf, o:mutbuf, w:mutbuf, malformed:bool) -> u32:
    which = get(w, 88)
    if uint(s, 8) == 1:
        if which == 4:
            put(w, 192, 0)
            return witness_reply(s, o, w, 3)
        if which == 5:
            return pending(s, o, w, 1)
        if which == 3 and malformed:
            return lifecycle_start(s, o, w, False)
    return 0

def protocol(w:mutbuf, record:u64) -> u64:
    if record == NONE:
        return 0
    if get(w, record) == 3 and get(w, record + 32) == 1 and byte(w, RAW_JSON + get(w, record + 24)) == 49:
        return 1
    return 2

def lookup_in(w:mutbuf, parent:u64, field:u64) -> u64:
    if parent == NONE or get(w, parent) != 6:
        return NONE
    child = get(w, parent + 24)
    found = NONE
    while child != NONE:
        record = ARENA + 64 + child * 72
        if key_id(w, ARENA + get(w, record + 40), get(w, record + 48)) == field:
            found = record
        child = get(w, record + 16)
    return found

def copy_state(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    index = 0
    while index < size:
        store(w, target + index, byte(w, source + index))
        index = index + 1
    return target + size

def copy_field(w:mutbuf, record:u64, target:u64) -> u64:
    if record == NONE:
        return text_null(w, target)
    kind = get(w, record)
    if kind < 4:
        return copy_json(w, RAW_JSON + get(w, record + 24), target, get(w, record + 32))
    return copy_json(w, RAW_JSON + get(w, record + 56), target, get(w, record + 64))

def copy_field_raw(w:mutbuf, record:u64, target:u64) -> u64:
    if record == NONE:
        return text_null(w, target)
    kind = get(w, record)
    if kind < 4:
        return copy_state(w, RAW_JSON + get(w, record + 24), target, get(w, record + 32))
    return copy_state(w, RAW_JSON + get(w, record + 56), target, get(w, record + 64))

def copy_json(w:mutbuf, source:u64, target:u64, size:u64) -> u64:
    index = 0
    while index < size:
        c = byte(w, source + index)
        surrogate = False
        cp = 0
        if c == 237 and index + 2 < size:
            middle = byte(w, source + index + 1)
            last = byte(w, source + index + 2)
            if middle >= 160 and middle <= 191 and last >= 128 and last <= 191:
                surrogate = True
                cp = 53248 | ((middle & 63) << 6) | (last & 63)
        if surrogate:
            target = escaped_scalar(w, target, cp)
            index = index + 3
        else:
            store(w, target, c)
            target = target + 1
            index = index + 1
    return target

def field_string(w:mutbuf, record:u64, target:u64, maximum:u64) -> u64:
    if record == NONE or get(w, record) != 4:
        return 0
    size = get(w, record + 32)
    if size > maximum * 4:
        return 0
    source = ARENA + get(w, record + 24)
    index = 0
    points = 0
    while index < size:
        if byte(w, source + index) & 192 != 128:
            points = points + 1
        index = index + 1
    if points > maximum:
        return 0
    copy_state(w, source, target, size)
    return size

def field_word(w:mutbuf, record:u64, size:u64) -> u64:
    if record == NONE or get(w, record) != 4 or get(w, record + 32) != size:
        return NONE
    return getn(w, ARENA + get(w, record + 24), size)

def field_is(w:mutbuf, record:u64, value:u64) -> bool:
    return record != NONE and get(w, record) == 4 and key_id(w, ARENA + get(w, record + 24), get(w, record + 32)) == value

def lowercase_hex(w:mutbuf, at:u64, size:u64) -> bool:
    index = 0
    while index < size:
        c = byte(w, at + index)
        if (c < 48 or c > 57) and (c < 97 or c > 102):
            return False
        index = index + 1
    return True

def decimal_field(w:mutbuf, record:u64) -> u64:
    if record == NONE or get(w, record) != 3:
        return NONE
    size = get(w, record + 32)
    source = RAW_JSON + get(w, record + 24)
    if size == 0 or size > 20:
        return NONE
    index = 0
    value = 0
    while index < size:
        c = byte(w, source + index)
        if c < 48 or c > 57 or value > 1844674407370955161 or (value == 1844674407370955161 and c > 53):
            return NONE
        value = value * 10 + c - 48
        index = index + 1
    return value

def pending(s:readbuf, o:mutbuf, w:mutbuf, reason:u64) -> u32:
    at = text_pending_open(w, OUTPUT)
    end = 65536
    if reason == 0:
        end = text_unsupported(w, end)
    elif reason == 1:
        end = text_unsafe_receipt(w, end)
    else:
        end = text_missing_receipt(w, end)
    at = quoted(w, at, 65536, end - 65536)
    at = text_pending_end(w, at)
    return finish_status(s, o, w, at)

def owner_unknown(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = text_owner_unknown(w, OUTPUT)
    return finish_status(s, o, w, at)

def finish_status(s:readbuf, o:mutbuf, w:mutbuf, at:u64) -> u32:
    at = text_job_id(w, at)
    at = quoted_input(s, w, at, get(w, 56), uint(s, 48))
    at = text_reply_end(w, at)
    put(w, 176, at)
    put(w, 184, OUTPUT)
    return write_reply(o, w)

def witness_reply(s:readbuf, o:mutbuf, w:mutbuf, witness_protocol:u64) -> u32:
    at = text_terminal_open(w, OUTPUT)
    at = copy_json(w, 9437184, at, get(w, 248))
    at = text_witness_open(w, at)
    at = decimal(w, at, get(w, 200))
    at = text_comma(w, at)
    at = decimal(w, at, get(w, 256))
    at = text_comma(w, at)
    at = decimal(w, at, witness_protocol)
    at = text_request_nonce(w, at)
    at = quoted_metadata(w, at, 32768, get(w, 400))
    at = text_witness_job(w, at)
    at = limited_field(w, at, 1, witness_protocol != 3)
    at = text_nonce(w, at)
    at = limited_field(w, at, 7, witness_protocol != 3)
    at = text_digest(w, at)
    at = limited_field(w, at, 21, witness_protocol != 3)
    at = text_raw(w, at)
    index = 0
    while index < get(w, 240):
        c = byte(w, 12582912 + index)
        store(w, at, hex_digit(c >> 4))
        store(w, at + 1, hex_digit(c & 15))
        at = at + 2
        index = index + 1
    at = text_witness_end(w, at)
    return finish_status(s, o, w, at)

def limited_field(w:mutbuf, at:u64, field:u64, present:bool) -> u64:
    size = 0
    if present:
        size = field_string(w, lookup(w, field), 34816, 128)
    return quoted_metadata(w, at, 34816, size)

def legacy_terminal(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    at = text_terminal_open(w, OUTPUT)
    at = copy_json(w, 9437184, at, get(w, 248))
    at = text_facts(w, at)
    at = decimal(w, at, choose(field_is(w, lookup(w, 15), 39), 1, 0))
    at = text_comma(w, at)
    at = decimal(w, at, truth(w, lookup(w, 16)))
    at = text_comma(w, at)
    at = decimal(w, at, truth(w, lookup(w, 17)))
    at = text_comma(w, at)
    result = exit_fact(w, lookup(w, 18))
    if result == NONE:
        return 0
    at = decimal(w, at, result)
    at = text_comma(w, at)
    at = decimal(w, at, true_fact(w, lookup(w, 19)))
    at = text_comma(w, at)
    at = decimal(w, at, true_fact(w, lookup(w, 20)))
    at = text_facts_end(w, at)
    return finish_status(s, o, w, at)

def truth(w:mutbuf, record:u64) -> u64:
    if record == NONE:
        return 0
    kind = get(w, record)
    if kind == 0 or kind == 1:
        return 0
    if kind == 2:
        return 1
    if kind >= 4:
        return choose(get(w, record + 32) != 0, 1, 0)
    source = RAW_JSON + get(w, record + 24)
    size = get(w, record + 32)
    bits = numeric_value(w, source, size)
    return choose(bits & 9223372036854775807 != 0, 1, 0)

def true_fact(w:mutbuf, record:u64) -> u64:
    if record == NONE:
        return 0
    return choose(get(w, record) == 2, 1, 2)

def exit_fact(w:mutbuf, record:u64) -> u64:
    if record == NONE:
        return 2
    kind = get(w, record)
    if kind == 0 or kind >= 5:
        return 0
    if kind == 1:
        return 1
    if kind == 2:
        return 2
    size = get(w, record + 32)
    if kind == 4:
        return integer_text(w, ARENA + get(w, record + 24), size)
    source = RAW_JSON + get(w, record + 24)
    index = 0
    nonzero = False
    floating = False
    while index < size:
        c = byte(w, source + index)
        nonzero = nonzero or (c >= 49 and c <= 57)
        floating = floating or c == 46 or c == 69 or c == 101 or c == 78 or c == 73
        index = index + 1
    if floating:
        bits = numeric_value(w, source, size) & 9223372036854775807
        if bits >= 9218868437227405312:
            return 0
        return choose(bits < 4607182418800017408, 1, 2)
    return choose(nonzero, 2, 1)

def numeric_value(w:mutbuf, source:u64, size:u64) -> u64:
    index = 0
    if byte(w, source) == 45:
        index = 1
    if byte(w, source + index) == 78 or byte(w, source + index) == 73:
        return 9221120237041090560
    result = number_convert(w, source, size)
    if result == 4294967292:
        return 9218868437227405312
    if result != 8:
        return 9221120237041090560
    return number_get(w, 3200)

def integer_text(w:mutbuf, source:u64, size:u64) -> u64:
    index = 0
    stage = 0
    digits = 0
    previous = False
    nonzero = False
    while index < size:
        c = byte(w, source + index)
        index = index + 1
        cp = c
        need = 0
        if c >= 240:
            cp = c & 7
            need = 3
        elif c >= 224:
            cp = c & 15
            need = 2
        elif c >= 192:
            cp = c & 31
            need = 1
        while need != 0:
            cp = (cp << 6) | (byte(w, source + index) & 63)
            index = index + 1
            need = need - 1
        space = integer_space(cp)
        if stage == 0 and space:
            stage = 0
        elif stage == 0 and (cp == 43 or cp == 45):
            stage = 1
        elif space:
            if previous == False:
                return 0
            stage = 3
        elif stage == 3:
            return 0
        elif cp == 95:
            if previous == False:
                return 0
            previous = False
            stage = 2
        else:
            digit = integer_digit(cp)
            if digit > 9:
                return 0
            digits = digits + 1
            if digits > 4300:
                return 0
            nonzero = nonzero or digit != 0
            previous = True
            stage = 2
    if digits == 0 or previous == False:
        return 0
    return choose(nonzero, 2, 1)

def integer_space(cp:u64) -> bool:
    bits = choose(cp - 9 <= 4, 1, 0) | choose(cp == 32, 1, 0) | choose(cp == 133, 1, 0) | choose(cp == 160, 1, 0)
    bits = bits | choose(cp == 5760, 1, 0) | choose(cp - 8192 <= 10, 1, 0) | choose(cp - 8232 <= 1, 1, 0)
    bits = bits | choose(cp == 8239, 1, 0) | choose(cp == 8287, 1, 0) | choose(cp == 12288, 1, 0)
    return bits != 0
'''


def numeric_helpers():
    """Embed the existing exact HIA converter in private, nonoverlapping scratch."""
    tree = ast.parse(binary64_source())
    names = {node.name for node in tree.body}

    class Slice(ast.NodeTransformer):
        def visit_FunctionDef(self, node):
            if node.name == 'convert':
                node.args.args = [ast.arg(arg='w', annotation=ast.Name(id='mutbuf', ctx=ast.Load())),
                                  ast.arg(arg='start', annotation=ast.Name(id='u64', ctx=ast.Load())),
                                  ast.arg(arg='n', annotation=ast.Name(id='u64', ctx=ast.Load()))]
                node.returns = ast.Name(id='u64', ctx=ast.Load())
                node.body = [stmt for stmt in node.body
                             if not (isinstance(stmt, ast.If) and 'length(o)' in ast.unparse(stmt.test))
                             and not (isinstance(stmt, ast.Assign) and ast.unparse(stmt) == 'n = length(s)')]
            node.name = 'number_' + node.name
            return self.generic_visit(node)

        def visit_Call(self, node):
            node = self.generic_visit(node)
            if not isinstance(node.func, ast.Name):
                return node
            name = node.func.id
            if name == 'byte' and isinstance(node.args[0], ast.Name) and node.args[0].id == 's':
                node.args[0] = ast.Name(id='w', ctx=ast.Load())
                node.args[1] = ast.BinOp(ast.Name(id='start', ctx=ast.Load()), ast.Add(), node.args[1])
            elif name in ('byte', 'store', 'word_load', 'word_store') and isinstance(node.args[0], ast.Name) and node.args[0].id == 'w':
                node.args[1] = ast.BinOp(ast.Constant(192 << 20), ast.Add(), node.args[1])
            if name == 'put' and isinstance(node.args[0], ast.Name) and node.args[0].id == 'o':
                node.args[0] = ast.Name(id='w', ctx=ast.Load())
                node.args[1] = ast.Constant(3200)
            if name in names:
                node.func.id = 'number_' + name
            return node

    source = ast.unparse(ast.fix_missing_locations(Slice().visit(tree))) + '\n'
    source += r'''
def integer_digit(cp:u64) -> u64:
    if cp - 48 <= 9:
        return cp - 48
    low = 1
    high = 76
    while low < high:
        middle = (low + high) >> 1
        first = decimal_zero(middle)
        if cp < first:
            high = middle
        elif cp - first < 10:
            return cp - first
        else:
            low = middle + 1
    return 10

def decimal_zero(index:u64) -> u64:
    group = index // 3
    word = 0
'''
    for index in range(0, len(DECIMAL_ZEROES), 3):
        packed = sum(value << (21 * offset) for offset, value in enumerate(DECIMAL_ZEROES[index:index + 3]))
        source += f'    word = choose(group == {index // 3}, {packed}, word)\n'
    return source + '    return (word >> ((index % 3) * 21)) & 2097151\n'


def replace_once(source, before, after):
    if source.count(before) != 1:
        raise ValueError('job-observation status integration point changed: ' + before[:80])
    return source.replace(before, after)


def extend(source):
    source = replace_once(source,
        '    if phase == 90:\n',
        '    if phase >= 100 and phase < 300:\n        return status_advance(s, o, w, phase, result)\n    if phase == 90:\n')
    source = replace_once(source,
        '    if uint(s, 8) != 0 or uint(s, 72) != 0:\n        return 0',
        '    if (uint(s, 8) != 0 or uint(s, 72) != 0) and (uint(s, 8) != 1 or uint(s, 72) != 63):\n        return 0')
    source = replace_once(source,
        '    else:\n        at = text_exit_name(w, at)\n    store(w, at, 0)\n',
        '    elif which == 3:\n        at = text_started_name(w, at)\n    elif which == 4:\n        at = text_witness_name(w, at)\n    else:\n        at = text_exit_name(w, at)\n    put(w, 192, 0)\n    store(w, at, 0)\n')
    source = replace_once(source,
        '        if failed(result):\n            return 0\n        put(w, 96, result)\n        return call(o, w, 11,',
        '        if failed(result):\n            return metadata_failure(s, o, w, False)\n        put(w, 192, 1)\n        put(w, 96, result)\n        return call(o, w, 11,')
    source = replace_once(source,
        '        if failed(result) or safe_file(w, 4096) == 0 or get(w, 4144) > 4194304:\n            return 0',
        '        if failed(result) or safe_file(w, 4096) == 0 or get(w, 4144) > observation_limit(w):\n            return metadata_failure(s, o, w, False)\n        if get(w, 88) >= 3 and getn(w, 4120, 4) & 4095 != 384:\n            return metadata_failure(s, o, w, False)')
    source = source.replace('4194305 - get(w, 104)', 'observation_limit(w) + 1 - get(w, 104)')
    source = replace_once(source,
        '            if get(w, 104) > 4194304:\n                return 0',
        '            if get(w, 104) > observation_limit(w):\n                return metadata_failure(s, o, w, False)')
    source = replace_once(source,
        '        if failed(result) or result > observation_limit(w) + 1 - get(w, 104):\n            return 0',
        '        if failed(result) or result > observation_limit(w) + 1 - get(w, 104):\n            return metadata_failure(s, o, w, False)')
    source = replace_once(source,
        '        if failed(result) or same_stamp(w, 4096, 4352) == 0:\n            return 0',
        '        if failed(result) or same_stamp(w, 4096, 4352) == 0:\n            return metadata_failure(s, o, w, False)')
    source = replace_once(source,
        '        if failed(result) or same_stamp(w, 4096, 4608) == 0:\n            return 0',
        '        if failed(result) or same_stamp(w, 4096, 4608) == 0:\n            return metadata_failure(s, o, w, False)')
    source = replace_once(source,
        '        if result >= 4294967292 or get(w, ARENA + 64) != 6:\n            return 0',
        '        if result >= 4294967292 or get(w, ARENA + 64) != 6:\n            return metadata_failure(s, o, w, True)')
    source = replace_once(source,
        'def next_metadata(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    which = get(w, 88) + 1',
        'def next_metadata(s:readbuf, o:mutbuf, w:mutbuf) -> u32:\n    if uint(s, 8) == 1:\n        return status_metadata(s, o, w)\n    which = get(w, 88) + 1')
    return source + STATUS + LIFECYCLE + numeric_helpers()


LIFECYCLE = r'''
def lifecycle_start(s:readbuf, o:mutbuf, w:mutbuf, present:bool) -> u32:
    root = choose(present, ARENA + 64, NONE)
    identity = lookup_in(w, root, 11)
    uid_record = lookup_in(w, root, 9)
    pid_record = lookup_in(w, root, 10)
    uid = decimal_field(w, uid_record)
    pid = decimal_field(w, pid_record)
    put(w, 288, pid)
    put(w, 296, uid)
    put(w, 312, 0)
    put(w, 320, NONE)
    put(w, 328, 0)
    put(w, 360, choose(get(w, 216) == 0, 1, 0))
    if get(w, 216) == 0:
        if get(w, 208) == 0 or uid != get(w, 16) or pid < 2 or pid > 2147483647:
            return owner_unknown(s, o, w)
        if equal_input_field(s, w, lookup_in(w, root, 1), get(w, 56), uint(s, 48)) == 0:
            return owner_unknown(s, o, w)
        if equal_state_field(w, lookup_in(w, root, 7), 32768, 32) == 0 or field_is(w, lookup_in(w, identity, 12), 37) == False:
            return owner_unknown(s, o, w)
        size = field_string(w, lookup_in(w, identity, 13), 65536, 16384)
        if size == 0:
            return owner_unknown(s, o, w)
        put(w, 304, size)
        return process_start(o, w)
    at = text_lifecycle_open(w, OUTPUT)
    at = copy_field(w, uid_record, at)
    at = text_effective_uid(w, at)
    at = decimal(w, at, get(w, 16))
    at = text_starter_pid(w, at)
    at = copy_field(w, pid_record, at)
    at = text_request_job(w, at)
    at = quoted_input(s, w, at, get(w, 56), uint(s, 48))
    at = text_starter_job(w, at)
    at = copy_field(w, lookup_in(w, root, 1), at)
    at = text_starter_nonce(w, at)
    at = copy_field(w, lookup_in(w, root, 7), at)
    at = text_expected_kind(w, at)
    at = copy_field(w, lookup_in(w, identity, 12), at)
    at = text_starter_identity(w, at)
    at = copy_field(w, lookup_in(w, identity, 13), at)
    at = text_starter_invocation(w, at)
    at = copy_field(w, lookup_in(w, root, 14), at)
    at = text_request_witness(w, at)
    if get(w, 200) == 0:
        at = text_false(w, at)
    else:
        at = text_true(w, at)
    # All arena-backed starter fields are consumed before a large request
    # nonce can extend the response into the now-unused decoder arena.
    at = text_owner_request_nonce(w, at)
    at = copy_json(w, 226492416, at, get(w, 408))
    put(w, 176, at)
    if uid == get(w, 16) and pid > 1 and pid <= 2147483647 and (property_is(w, 23, 33) or property_is(w, 23, 34)) and property_is(w, 24, 35) == False and property_is(w, 24, 36) == False:
        return process_start(o, w)
    return process_reply(s, o, w)

def equal_state_field(w:mutbuf, record:u64, at:u64, size:u64) -> u64:
    if record == NONE or get(w, record) != 4 or get(w, record + 32) != size:
        return 0
    source = ARENA + get(w, record + 24)
    index = 0
    while index < size:
        if byte(w, source + index) != byte(w, at + index):
            return 0
        index = index + 1
    return 1

def systemctl_start(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 100, 102, 0, 0, 0, 0, 0, 0, 0)

def systemctl_arguments(s:readbuf, o:mutbuf, w:mutbuf, uid:u64) -> u32:
    at = 131072
    put(w, 81920, at)
    at = nul(w, text_systemctl(w, at))
    put(w, 81928, at)
    at = nul(w, text_user(w, at))
    put(w, 81936, at)
    at = nul(w, text_show(w, at))
    put(w, 81944, at)
    index = 0
    while index < uint(s, 56):
        store(w, at, byte(s, get(w, 64) + index))
        at = at + 1
        index = index + 1
    at = nul(w, at)
    put(w, 81952, at)
    at = nul(w, text_no_pager(w, at))
    put(w, 81960, at)
    at = nul(w, text_properties(w, at))
    put(w, 81968, NONE)
    count = 0
    index = 0
    xdg = False
    bus = False
    while index < get(w, 448):
        if count >= 4096:
            return 0
        start = index
        key_end = NONE
        while index < get(w, 448) and byte(w, 233832448 + index) != 0:
            if key_end == NONE and byte(w, 233832448 + index) == 61:
                key_end = index
            index = index + 1
        if index >= get(w, 448):
            return 0
        if key_end != NONE:
            key = key_id(w, 233832448 + start, key_end - start)
            xdg = xdg or key == 31
            bus = bus or key == 32
        put(w, 2097152 + count * 8, 233832448 + start)
        count = count + 1
        index = index + 1
    if xdg == False:
        put(w, 2097152 + count * 8, at)
        at = text_xdg_env(w, at)
        at = decimal(w, at, uid)
        at = nul(w, at)
        count = count + 1
    if bus == False:
        put(w, 2097152 + count * 8, at)
        at = text_bus_env(w, at)
        at = decimal(w, at, uid)
        at = text_bus_end(w, at)
        at = nul(w, at)
        count = count + 1
    put(w, 2097152 + count * 8, NONE)
    put(w, 464, count + 1)
    return relocate(o, w, 101, 81920, 7, 86016)

def status_advance(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 100:
        if failed(result):
            return 0
        return systemctl_arguments(s, o, w, result)
    if phase == 101:
        if failed(result):
            return 0
        return relocate(o, w, 102, 2097152, get(w, 464), 2162688)
    if phase == 102:
        return call(o, w, 103, 293, 90112, 524288, 0, 0, 0, 0, 3)
    if phase == 103:
        if failed(result):
            return 0
        put(w, 432, getn(w, 90112, 4))
        put(w, 440, getn(w, 90116, 4))
        return call(o, w, 109, 293, 90400, 524288, 0, 0, 0, 0, 3)
    if phase == 109:
        if failed(result):
            return 0
        put(w, 472, getn(w, 90400, 4))
        put(w, 480, getn(w, 90404, 4))
        return call(o, w, 104, 57, 0, 0, 0, 0, 0, 0, 0)
    if phase == 104:
        if failed(result):
            return 0
        if result == 0:
            return call(o, w, 110, 33, get(w, 440), 1, 0, 0, 0, 0, 0)
        put(w, 424, result)
        put(w, 416, 0)
        return call(o, w, 105, 3, get(w, 440), 0, 0, 0, 0, 0, 0)
    if phase == 105:
        if failed(result):
            return 0
        return call(o, w, 114, 3, get(w, 480), 0, 0, 0, 0, 0, 0)
    if phase == 114:
        if failed(result):
            return 0
        return systemctl_read(o, w)
    if phase == 106:
        if result == NEG4:
            return systemctl_read(o, w)
        if failed(result) or result > 65537 - get(w, 416):
            return 0
        if result != 0:
            put(w, 416, get(w, 416) + result)
            if get(w, 416) > 65536:
                return 0
            return systemctl_read(o, w)
        return call(o, w, 107, 3, get(w, 432), 0, 0, 0, 0, 0, 0)
    if phase == 107:
        if failed(result):
            return 0
        return call(o, w, 108, 61, get(w, 424), 90120, 0, 0, 0, 0, 12)
    if phase == 108:
        if result == NEG4:
            return call(o, w, 108, 61, get(w, 424), 90120, 0, 0, 0, 0, 12)
        if failed(result):
            return 0
        return call(o, w, 117, 0, get(w, 472), 90424, 8, 0, 0, 0, 12)
    if phase == 117:
        if result == NEG4:
            return call(o, w, 117, 0, get(w, 472), 90424, 8, 0, 0, 0, 12)
        if result != 0:
            return 0
        return call(o, w, 118, 3, get(w, 472), 0, 0, 0, 0, 0, 0)
    if phase == 118:
        if failed(result):
            return 0
        parse_properties(w)
        put(w, 88, 5)
        return open_metadata(o, w)
    if phase == 110:
        if failed(result):
            return child_failed(o, w)
        nul(w, text_devnull(w, 90128))
        return call(o, w, 111, 257, NEG100, 90128, 524289, 0, 0, 0, 12)
    if phase == 111:
        if failed(result):
            return child_failed(o, w)
        return call(o, w, 112, 33, result, 2, 0, 0, 0, 0, 0)
    if phase == 112:
        if failed(result):
            return child_failed(o, w)
        return call(o, w, 113, 59, 131072, 86016, 2162688, 0, 0, 0, 63)
    if phase == 113:
        return child_failed(o, w)
    if phase == 116:
        return call(o, w, 199, 60, 127, 0, 0, 0, 0, 0, 0)
    if phase >= 150 and phase <= 160:
        return process_advance(s, o, w, phase, result)
    return 0

def child_failed(o:mutbuf, w:mutbuf) -> u32:
    put(w, 90416, get(w, 8))
    return call(o, w, 116, 1, get(w, 480), 90416, 8, 0, 0, 0, 12)

def systemctl_read(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 106, 0, get(w, 432), 262144 + get(w, 416), 65537 - get(w, 416), 0, 0, 0, 12)

def nul(w:mutbuf, at:u64) -> u64:
    store(w, at, 0)
    return at + 1

def relocate(o:mutbuf, w:mutbuf, phase:u64, source:u64, count:u64, target:u64) -> u32:
    put(w, 0, phase)
    put(o, 0, source)
    put(o, 8, count)
    put(o, 16, target)
    return 2

def parse_properties(w:mutbuf) -> u64:
    slot = 512
    while slot < 656:
        put(w, slot, 0)
        slot = slot + 8
    index = 0
    while index < get(w, 416):
        start = index
        equal = NONE
        while index < get(w, 416) and byte(w, 262144 + index) != 10 and byte(w, 262144 + index) != 13:
            if equal == NONE and byte(w, 262144 + index) == 61:
                equal = index
            index = index + 1
        if equal != NONE:
            field = key_id(w, 262144 + start, equal - start)
            if field >= 22 and field <= 30:
                put(w, 512 + (field - 22) * 16, 262144 + equal + 1)
                put(w, 520 + (field - 22) * 16, index - equal - 1)
        while index < get(w, 416) and (byte(w, 262144 + index) == 10 or byte(w, 262144 + index) == 13):
            index = index + 1
    return 0

def property_is(w:mutbuf, property:u64, value:u64) -> bool:
    at = 512 + (property - 22) * 16
    return key_id(w, get(w, at), get(w, at + 8)) == value

def properties_json(w:mutbuf, at:u64) -> u64:
    at = text_object_open(w, at)
    index = 0
    count = 0
    while index < get(w, 416):
        start = index
        equal = NONE
        while index < get(w, 416) and byte(w, 262144 + index) != 10 and byte(w, 262144 + index) != 13:
            if equal == NONE and byte(w, 262144 + index) == 61:
                equal = index
            index = index + 1
        if equal != NONE:
            if count != 0:
                at = text_comma(w, at)
            at = quoted(w, at, 262144 + start, equal - start)
            at = text_colon(w, at)
            at = quoted(w, at, 262144 + equal + 1, index - equal - 1)
            count = count + 1
        while index < get(w, 416) and (byte(w, 262144 + index) == 10 or byte(w, 262144 + index) == 13):
            index = index + 1
    return text_object_close(w, at)

def process_start(o:mutbuf, w:mutbuf) -> u32:
    at = text_proc(w, 90128)
    at = decimal(w, at, get(w, 288))
    nul(w, at)
    return call(o, w, 150, 257, NEG100, 90128, 720896, 0, 0, 0, 12)

def process_advance(s:readbuf, o:mutbuf, w:mutbuf, phase:u64, result:u64) -> u32:
    if phase == 150:
        if failed(result):
            return observe_uid(o, w)
        put(w, 328, result)
        nul(w, text_proc_stat(w, 90304))
        return call(o, w, 152, 257, get(w, 328), 90304, 657408, 0, 0, 0, 12)
    if phase == 152:
        if failed(result):
            return observe_uid(o, w)
        put(w, 336, result)
        put(w, 344, 0)
        return process_stat_read(o, w)
    if phase == 153:
        if result == NEG4:
            return process_stat_read(o, w)
        if failed(result) or result > 4097 - get(w, 344):
            return observe_uid(o, w)
        if result != 0:
            put(w, 344, get(w, 344) + result)
            if get(w, 344) > 4096:
                return observe_uid(o, w)
            return process_stat_read(o, w)
        return call(o, w, 154, 3, get(w, 336), 0, 0, 0, 0, 0, 0)
    if phase == 154:
        if failed(result):
            return observe_uid(o, w)
        nul(w, text_boot(w, 90304))
        return call(o, w, 156, 257, NEG100, 90304, 657408, 0, 0, 0, 12)
    if phase == 156:
        if failed(result):
            return observe_uid(o, w)
        put(w, 376, result)
        put(w, 352, 0)
        return boot_read(o, w)
    if phase == 157:
        if result == NEG4:
            return boot_read(o, w)
        if failed(result) or result > 129 - get(w, 352):
            return observe_uid(o, w)
        if result != 0:
            put(w, 352, get(w, 352) + result)
            if get(w, 352) > 128:
                return observe_uid(o, w)
            return boot_read(o, w)
        return call(o, w, 158, 3, get(w, 376), 0, 0, 0, 0, 0, 0)
    if phase == 158:
        if failed(result) == False:
            observe_identity(w)
        return observe_uid(o, w)
    if phase == 159:
        if failed(result) == False:
            put(w, 320, getn(w, 4124, 4))
        if get(w, 328) >= 3:
            return call(o, w, 160, 3, get(w, 328), 0, 0, 0, 0, 0, 0)
        return process_reply(s, o, w)
    if phase == 160:
        return process_reply(s, o, w)
    return 0

def observe_uid(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 159, 262, NEG100, 90128, 4096, 0, 0, 0, 60)

def process_stat_read(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 153, 0, get(w, 336), 106496 + get(w, 344), 4097 - get(w, 344), 0, 0, 0, 12)

def boot_read(o:mutbuf, w:mutbuf) -> u32:
    return call(o, w, 157, 0, get(w, 376), 98304 + get(w, 352), 129 - get(w, 352), 0, 0, 0, 12)

def observe_identity(w:mutbuf) -> u64:
    if valid_utf8(w, 106496, get(w, 344)) == False:
        return 0
    boot_size = get(w, 352)
    while boot_size != 0 and (byte(w, 98304 + boot_size - 1) == 10 or byte(w, 98304 + boot_size - 1) == 13 or byte(w, 98304 + boot_size - 1) == 32 or byte(w, 98304 + boot_size - 1) == 9):
        boot_size = boot_size - 1
    if boot_size != 36:
        return 0
    index = 0
    while index < 36:
        c = byte(w, 98304 + index)
        if index == 8 or index == 13 or index == 18 or index == 23:
            if c != 45:
                return 0
        elif (c < 48 or c > 57) and (c < 97 or c > 102):
            return 0
        index = index + 1
    index = 0
    start = NONE
    while index + 1 < get(w, 344):
        if byte(w, 106496 + index) == 41 and byte(w, 106497 + index) == 32:
            start = index + 2
        index = index + 1
    if start == NONE:
        return 0
    index = start
    field = 0
    while field < 19:
        while index < get(w, 344) and white(byte(w, 106496 + index)):
            index = index + 1
        while index < get(w, 344) and white(byte(w, 106496 + index)) == False:
            index = index + 1
        field = field + 1
    while index < get(w, 344) and white(byte(w, 106496 + index)):
        index = index + 1
    start = index
    ticks = 0
    while index < get(w, 344) and white(byte(w, 106496 + index)) == False:
        c = byte(w, 106496 + index)
        if c < 48 or c > 57 or ticks > 1844674407370955161 or (ticks == 1844674407370955161 and c > 53):
            return 0
        ticks = ticks * 10 + c - 48
        index = index + 1
    if index == start:
        return 0
    at = copy_state(w, 98304, 122880, 36)
    store(w, at, 58)
    at = decimal(w, at + 1, ticks)
    put(w, 312, at - 122880)
    return 1

def white(c:u64) -> bool:
    return c == 32 or c == 9 or c == 10 or c == 13 or c == 11 or c == 12

def valid_utf8(w:mutbuf, at:u64, size:u64) -> bool:
    index = 0
    while index < size:
        c = byte(w, at + index)
        index = index + 1
        if c >= 128:
            need = 0
            low = 128
            high = 191
            if c >= 194 and c <= 223:
                need = 1
            elif c >= 224 and c <= 239:
                need = 2
                if c == 224:
                    low = 160
                elif c == 237:
                    high = 159
            elif c >= 240 and c <= 244:
                need = 3
                if c == 240:
                    low = 144
                elif c == 244:
                    high = 143
            else:
                return False
            if index + need > size:
                return False
            while need != 0:
                c = byte(w, at + index)
                if c < low or c > high:
                    return False
                low = 128
                high = 191
                index = index + 1
                need = need - 1
    return True

def process_reply(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if get(w, 360) != 0:
        matching = get(w, 312) != 0 and get(w, 304) == get(w, 312)
        index = 0
        while matching and index < get(w, 312):
            matching = byte(w, 65536 + index) == byte(w, 122880 + index)
            index = index + 1
        if matching == False and get(w, 200) != 0:
            return pending(s, o, w, 2)
        at = text_detached_open(w, OUTPUT)
        if matching:
            at = text_running(w, at)
        else:
            at = text_lost(w, at)
        at = text_backend(w, at)
        at = copy_json(w, 226492416, at, get(w, 224))
        at = text_pid(w, at)
        at = decimal(w, at, get(w, 288))
        at = text_identity(w, at)
        if get(w, 312) != 0:
            at = text_identity_open(w, at)
            at = quoted(w, at, 122880, get(w, 312))
            at = text_object_close(w, at)
        else:
            at = text_null(w, at)
        return finish_status(s, o, w, at)
    at = text_observed_uid(w, get(w, 176))
    if get(w, 320) == NONE:
        at = text_null(w, at)
    else:
        at = decimal(w, at, get(w, 320))
    at = text_observed_kind(w, at)
    if get(w, 312) == 0:
        at = text_null(w, at)
    else:
        at = text_proc_kind(w, at)
    at = text_observed_identity(w, at)
    if get(w, 312) == 0:
        at = text_null(w, at)
    else:
        at = quoted(w, at, 122880, get(w, 312))
    at = text_systemd(w, at)
    at = properties_json(w, at)
    at = text_object_close(w, at)
    return finish_status(s, o, w, at)
'''
