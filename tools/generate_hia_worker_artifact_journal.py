"""Author the checked Journal continuation for the immutable-input Worker."""
from pathlib import Path
import json
import re

from hepta.hia_agent_assembly import render_assembly
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_agent_journal import response_recipe
from tools.generate_hia_agent_journal_transport import transport_program
from tools.generate_hia_exec_release import POLICY_SOURCE as RELEASE_POLICY

SOURCE = 'examples/hia_bootstrap/worker_artifact_journal.hepta'

POLICY = r'''
def artifact_journal(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 24:
        return 0
    mode = input_word(s, 0)
    if mode == REQUEST:
        return artifact_request(s, o)
    if mode == REPLY:
        return artifact_reply(s, o)
    if mode == COST:
        return artifact_cost(s, o)
    if mode == REQUEST_KEYS:
        return artifact_keys(s, o)
    if mode == ERROR:
        return artifact_error(s, o)
    return 0

def artifact_request(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 40:
        return 0
    stage = input_word(s, 8)
    digits = input_word(s, 16)
    previous = input_word(s, 24)
    observed = input_word(s, 32)
    if digits > 2147483647 or observed > 8388608 or length(o) < 576 + observed:
        return 0
    if previous > 512 or length(s) != 40 + previous + observed:
        return 0
    if stage == 9:
        if previous != 0 or observed == 0:
            return 0
    elif previous != 512 or artifact_transition(s, stage, observed) == False:
        return 0
    put(o, 0, SINGLE)
    put(o, 8, observed)
    put(o, 16, read_workflow_scratch(stage, observed))
    put(o, 24, stage)
    put(o, 32, digits)
    put(o, 40, 0)
    put(o, 48, 0)
    put(o, 56, 0)
    index = 0
    while index < 512:
        value = 0
        if previous != 0:
            value = byte(s, 40 + index)
        store(o, 64 + index, value)
        index = index + 1
    copy_cost_bytes(s, o, 40 + previous, observed, 576)
    return 576 + observed

def artifact_transition(s:readbuf, stage:u64, observed:u64) -> bool:
    if input_word(s, 40) != STATE:
        return False
    phase = input_word(s, 48)
    action = input_word(s, 88)
    reason = input_word(s, 96)
    if stage == 0:
        return phase == 0 and input_word(s, 56) == 0 and action == 12 and reason == 0 and observed != 0
    if valid_state(s, 40) == False:
        return False
    if stage == 1:
        return phase == 1 and action == 2 and reason == 0 and observed >= 4
    if stage == 2:
        return phase == 2 and action == 3 and reason == 0 and observed == 0
    if stage == 3:
        return phase == 5 and action == 4 and reason == 0 and observed != 0
    if stage == 11 or stage == 12:
        if (phase != 3 and phase != 4) or action != 1 or reason != 0 or observed < 26:
            return False
        actual = input_word(s, 552)
        expected = input_word(s, 560)
        return input_word(s, 568) == 0 and actual != 0 and actual < observed - 24 and expected == observed - 24 - actual
    if stage == 5:
        return (phase == 3 or phase == 4) and action == 1 and reason == 0 and observed == 0
    if stage == 13:
        return phase == 10 and action == 1 and reason == 0 and input_word(s, 368) == 2 and observed == 0
    if stage == 14 or stage == 8:
        # Schema diagnostics run after the durable reservation, before catalog admission.
        valid = ((phase == 3 or phase == 4 or phase == 10) and action == 1 and reason == 0) or (action == 11 and reason != 0)
        return valid and ((stage == 14 and observed == 0) or (stage == 8 and observed != 0))
    return False

def valid_state(s:readbuf, at:u64) -> bool:
    if input_word(s, at) != STATE or input_word(s, at + 16) != 2 or input_word(s, at + 32) != 0:
        return False
    if input_word(s, at + 24) > 1 or input_word(s, at + 40) > input_word(s, at + 24):
        return False
    if admitted_read_identity(s, at) == False:
        return False
    if input_word(s, at + 24) == 0:
        return True
    end = at + 192
    pos = at + 128
    while pos < end:
        ch = byte(s, pos)
        if (ch < 48 or ch > 57) and (ch < 97 or ch > 102):
            return False
        pos = pos + 1
    return True

def artifact_reply(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 88 or length(o) < 64 or input_word(s, 32) != 0:
        return 0
    stage = input_word(s, 8)
    prior = input_word(s, 16)
    reply = input_word(s, 24)
    if prior > 512 or reply < 48 or length(s) != 40 + prior + reply:
        return 0
    at = 40 + prior
    if input_word(s, at) != JOURNAL_REPLY:
        return 0
    action = input_word(s, at + 8)
    response = input_word(s, at + 16)
    cost = input_word(s, at + 24)
    fixed = input_word(s, at + 32)
    arena = input_word(s, at + 40)
    if response > 8388608 or cost > 8388608 or fixed > 512 or arena > 23199808:
        return 0
    if reply != 48 + response + cost + fixed + arena:
        return 0
    state = at + 48 + response + cost
    status = 0
    next = 255
    if stage == 13 or stage == 14:
        if prior != 512 or fixed != 0 or arena != 0 or cost != 0 or action != response:
            return 0
        if artifact_transition(s, stage, 0) == False or response > 192 or response < RECIPE_OFFSET + 66:
            return 0
        if same_fields(s, 232, at + 48 + RECIPE_OFFSET, 66) == False:
            return 0
        next = 17
    else:
        if fixed != 512 or input_word(s, state + 48) != action:
            return 0
        if stage == 9:
            if prior != 0 or action != 12 or input_word(s, state) != STATE:
                return 0
            if input_word(s, state + 8) != 0 or input_word(s, state + 16) != 0:
                return 0
        else:
            if prior != 512 or valid_state(s, state) == False:
                return 0
            if stage != 0 and (valid_state(s, 40) == False or same_fields(s, 104, state + 64, 194) == False):
                return 0
        if stage == 8:
            status = artifact_terminal(s, state, response, cost)
            if status == 0 or arena != 0:
                return 0
            next = choose(input_word(s, state + 288) == 3, 20, 18)
        else:
            if response != 0 or cost != 0:
                return 0
            next = artifact_follow(s, stage, state, action, arena)
    if next == 255:
        return 0
    put(o, 0, VERIFIED)
    put(o, 8, stage)
    put(o, 16, next)
    put(o, 24, status)
    put(o, 32, 48)
    put(o, 40, response)
    put(o, 48, choose(fixed != 0, state - at, 0))
    put(o, 56, fixed)
    return 64

def artifact_follow(s:readbuf, stage:u64, state:u64, action:u64, arena:u64) -> u64:
    reason = input_word(s, state + 56)
    phase = input_word(s, state + 8)
    if stage == 3:
        if action == 5 and phase == 6 and reason == 0 and arena >= 64:
            return 19
        return 255
    if arena != 0:
        return 255
    if stage == 9:
        return 0
    if action == 11:
        if (stage == 1 and (reason == 2 or reason == 3)) or (stage == 11 and reason == 10) or (stage == 12 and reason == 11):
            return 14
        return 255
    if reason != 0:
        return 255
    if stage == 0:
        if action == 2 and phase == 1 and input_word(s, state + 24) == 1:
            return 1
        if action == 1 and phase == 4 and input_word(s, state + 24) == 0:
            return 11
    if stage == 1:
        if action == 3 and phase == 2:
            return 2
        if action == 4 and phase == 5:
            return 3
    if stage == 2 and action == 1 and phase == 3 and input_word(s, state + 40) == 1:
        return 11
    if stage == 11 and action == 1 and (phase == 3 or phase == 4):
        return 12
    if stage == 12 and action == 1 and (phase == 3 or phase == 4) and input_word(s, state + 320) == 0:
        return 5
    if stage == 5 and action == 1 and phase == 10 and input_word(s, state + 328) == 2:
        return 16
    return 255

def artifact_terminal(s:readbuf, at:u64, response:u64, cost:u64) -> u64:
    if valid_state(s, at) == False or response < 2 or cost < 31:
        return 0
    if input_word(s, at + 8) != 11 or input_word(s, at + 48) != 10:
        return 0
    if input_word(s, at + 272) != response or input_word(s, at + 280) != cost:
        return 0
    if input_word(s, at + 288) != 1 + 2 * input_word(s, at + 40):
        return 0
    status = input_word(s, at + 264)
    return choose(status >= 1 and status <= 2, status, 0)

def artifact_keys(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 552 or input_word(s, 32) != 0 or valid_state(s, 40) == False:
        return 0
    if input_word(s, 64) != 1:
        return 0
    mode = input_word(s, 8)
    time = input_word(s, 16)
    response = input_word(s, 24)
    phase = input_word(s, 48)
    action = input_word(s, 88)
    if response > 8388608 or length(s) != 552 + response:
        return 0
    if mode == 1 and phase == 1 and action == 2 and time == 0 and response == 0:
        put(o, 0, LOOKUP_REQUEST)
        return copy_cost_bytes(s, o, 168, 64, 8)
    if mode == 2 and phase == 2 and action == 3 and response == 0:
        if length(o) < 156:
            return 0
        put(o, 0, RESERVE_REQUEST)
        copy_cost_bytes(s, o, 168, 64, 8)
        copy_cost_bytes(s, o, 104, 64, 72)
        return decimal(o, 136, time)
    if mode == 3 and phase == 11 and action == 10 and time == 0 and input_word(s, 328) == 3:
        if response < 2 or input_word(s, 312) != response or length(o) < 72 + response:
            return 0
        put(o, 0, COMPLETE_REQUEST)
        copy_cost_bytes(s, o, 168, 64, 8)
        return copy_cost_bytes(s, o, 552, response, 72)
    return 0

def artifact_cost(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 584 or input_word(s, 16) != length(s) - 24:
        return 0
    if input_word(s, 24) != JOURNAL_REPLY or input_word(s, 32) != 10 or input_word(s, 56) != 512 or input_word(s, 64) != 0:
        return 0
    response = input_word(s, 40)
    cost = input_word(s, 48)
    if response > 8388608 or cost > 8388608:
        return 0
    state = 72 + response + cost
    if length(s) != state + 512 or length(o) < 134 + cost:
        return 0
    status = artifact_terminal(s, state, response, cost)
    if status == 0:
        return 0
    put(o, 0, COST_WIRE)
    put(o, 8, input_word(s, 8))
    put(o, 16, status)
    put(o, 24, 0)
    put(o, 32, 12)
    put(o, 40, 66)
    put(o, 48, cost)
    put(o, 56, TOOL_FIRST)
    put(o, 64, TOOL_LAST)
    copy_cost_bytes(s, o, state + 192, 66, 68)
    copy_cost_bytes(s, o, 72 + response, cost, 134)
    return 134 + cost
'''


ERROR_MESSAGES = (
    (1, 2, 'E_HIA_REQUEST_CONFLICT', 'request key is already bound to different arguments', 'correct_input'),
    (1, 3, 'E_HIA_REQUEST_UNKNOWN', 'original request has durable intent but no confirmed terminal result', 'observe_original'),
    (1, 10, 'E_HIA_CATALOG_STALE', 'tool catalog digest differs from installed catalog', 'correct_input'),
    (1, 11, 'E_HIA_IMPLEMENTATION_STALE', 'installed implementation changed during this service session', 'correct_input'),
    (2, 1, 'E_HIA_PROFILE_STALE', 'profile is unavailable or differs from the installed implementation', 'correct_input'),
    (2, 2, 'E_HIA_PROFILE_AUTHORITY', 'profile does not resolve to a retained server record', 'correct_input'),
    (2, 3, 'E_HIA_ARTIFACT_CHANGED', 'captured bytes differ from the expected digest', 'correct_input'),
    (3, 65, 'E_HIA_PATH', 'artifact paths must be absolute', 'correct_input'),
    (3, 66, 'E_HIA_PATH_AUTHORITY', 'artifact path is outside configured roots', 'correct_input'),
    (3, 67, 'E_HIA_ARTIFACT_FILE', 'artifact is not a bounded ordinary file', 'correct_input'),
    (3, 68, 'E_HIA_ARTIFACT_CHANGED', 'artifact changed while it was read', 'correct_input'),
    (3, 69, 'E_HIA_PATH', 'artifact traversal is not permitted', 'correct_input'),
    (3, 70, 'E_HIA_PATH', 'artifact path contains an unavailable or unsafe component', 'correct_input'),
    (3, 71, 'E_HIA_ARTIFACT_FILE', 'cannot read authorized ordinary artifact', 'correct_input'),
)


def errors():
    source = r'''
def artifact_error(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 40 or input_word(s, 24) != 0 or input_word(s, 32) != 0 or length(o) < 512:
        return 0
    group = input_word(s, 8)
    reason = input_word(s, 16)
'''
    for index, (group, reason, _, _, _) in enumerate(ERROR_MESSAGES):
        source += f'    if group == {group} and reason == {reason}:\n        return error_{index}(o)\n'
    source += '    return 0\n'
    for index, (_, _, code, message, retry) in enumerate(ERROR_MESSAGES):
        raw = json.dumps(dict(code=code, details_artifact=None, message=message, phase='admission', retry_action=retry),
                         sort_keys=True, separators=(',', ':')).encode('ascii')
        source += f'\ndef error_{index}(o:mutbuf) -> u64:\n'
        for at in range(0, len(raw), 8):
            field = raw[at:at + 8]
            if len(field) == 8:
                source += f'    put(o, {at}, {int.from_bytes(field, "little")})\n'
            else:
                source += ''.join(f'    store(o, {at + i}, {byte})\n' for i, byte in enumerate(field))
        source += f'    return {len(raw)}\n'
    return source


def source_program():
    tags = {'REQUEST': b'HIAJMP01', 'REPLY': b'HIAJMV01', 'VERIFIED': b'HIAJMO01', 'COST': b'HIAJMC01',
            'REQUEST_KEYS': b'HIAJMK01', 'LOOKUP_REQUEST': b'HIARJL01',
            'RESERVE_REQUEST': b'HIARJR01', 'COMPLETE_REQUEST': b'HIARJC01',
            'ERROR': b'HIAJME01', 'SINGLE': b'HIAJIN01', 'STATE': b'HIAJRN02', 'JOURNAL_REPLY': b'HIAJOU01',
            'COST_WIRE': b'HIAJCF01', 'TOOL_FIRST': b'hia_arti', 'TOOL_LAST': b'fact'}
    constants = {name: int.from_bytes(raw, 'little') for name, raw in tags.items()}
    constants['RECIPE_OFFSET'] = response_recipe()[0]
    source = POLICY + errors()
    for name, value in constants.items():
        source = re.sub(rf'\b{name}\b', str(value), source)
    source += RELEASE_POLICY[RELEASE_POLICY.index('\ndef decimal('):RELEASE_POLICY.index('\ndef hex(')]
    shared = transport_program()
    for name in ('admitted_read_identity', 'read_workflow_scratch', 'same_fields',
                 'copy_cost_bytes', 'input_word', 'put'):
        definition = '\ndef ' + name + '('
        start = shared.index(definition)
        end = shared.find('\ndef ', start + len(definition))
        source += shared[start:end if end != -1 else len(shared)] + '\n'
    return source


if __name__ == '__main__':
    Path(SOURCE).write_text(render_assembly(document(source_program(), 'artifact_journal')), encoding='utf-8')
