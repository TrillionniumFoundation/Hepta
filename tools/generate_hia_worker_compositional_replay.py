"""Connect independent scalar projections to the native compositional solver."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (
    CIRCUIT_CAPACITY, CIRCUIT_NODES, CIRCUIT_REQUEST, LEARNING_REQUEST,
    RESTART_REQUEST, SEARCH_PLAN_REQUEST, SPARSE_CLAUSES, SPARSE_REPLY, SPARSE_REQUEST,
    SPARSE_VARIABLES, STEP_LIMIT, UNSAT,
)
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_artifact_authority import source_program as authority
from tools.generate_hia_worker_compositional_skeleton import DECISION
from tools.generate_hia_worker_finite_reference import INVALID
from tools.generate_hia_worker_inspection_effect import function
from tools.hia_retained_proof_method import COMPOSITION_VERDICT

SOURCE = Path('examples/hia_bootstrap/worker_compositional_replay.hepta')
PHASES = ('HIACPL01', 'HIACPP01', 'HIACPS01', 'HIACPF01')

POLICY = r'''
# A physical Core projection, Boolean encoding, and solver result are
# separate observations. This role shapes their controls and completes
# only an exact UNSAT proof; SAT, exhaustion, and unsupported graphs
# cannot become a proved receipt here.
def compositional_replay(s:readbuf, o:mutbuf, w:mutbuf) -> u32:
    if length(s) < 16 or length(o) < 32:
        return BAD
    phase = input_word(s, 0)
    if phase == PLAN:
        return search_plan(s, o)
    if phase == PREPARE:
        return prepare_circuit(s, o)
    if phase == SEARCH:
        return prepare_search(s, o)
    if phase == FINISH:
        return check_result(s, o)
    return BAD

def search_plan(s:readbuf, o:mutbuf) -> u64:
    remaining = input_word(s, 8)
    if remaining == 0 or remaining > 5000 or circuit(s, 16) == False:
        return BAD
    nodes = input_word(s, 24)
    if length(o) < 32 + 16 * nodes:
        return BAD
    put(o, 0, PLAN_TAG)
    put(o, 8, remaining)
    put(o, 16, 0)
    put(o, 24, 0)
    index = 0
    while index < nodes:
        put(o, 32 + 16 * index, input_word(s, 48 + 40 * index))
        put(o, 40 + 16 * index, input_word(s, 56 + 40 * index))
        index = index + 1
    return 32 + 16 * nodes

def prepare_circuit(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 80 or length(o) < length(s) - 40 or valid_plan(s, 8) == False or circuit(s, 40) == False:
        return BAD
    copy(s, o, 40, length(s))
    put(o, 24, input_word(s, 16))
    return length(s) - 40

def prepare_search(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 72 or length(s) > 40 + CIRCUIT_BYTES or length(o) < length(s) - 40:
        return BAD
    if valid_plan(s, 8) == False or input_word(s, 40) != SPARSE_TAG:
        return BAD
    if sparse_header(s, 40) == False or input_word(s, 64) != input_word(s, 16):
        return BAD
    copy(s, o, 40, length(s))
    put(o, 0, solver_mode(s, 8))
    return length(s) - 40

def check_result(s:readbuf, o:mutbuf) -> u64:
    if length(s) != 128 or input_word(s, 8) != SKELETON_TAG or input_word(s, 16) != 0 or input_word(s, 24) > 4096:
        return BAD
    if valid_plan(s, 32) == False or sparse_header(s, 64) == False:
        return BAD
    if input_word(s, 64) != solver_mode(s, 32) or input_word(s, 88) != input_word(s, 40):
        return BAD
    if input_word(s, 96) != REPLY_TAG or input_word(s, 104) != UNSAT:
        return BAD
    if input_word(s, 112) != input_word(s, 72) or input_word(s, 120) > input_word(s, 40):
        return BAD
    put(o, 0, COMPLETE_TAG)
    put(o, 8, 0)
    put(o, 16, 1)
    return 24

def circuit(s:readbuf, at:u64) -> bool:
    if length(s) < at + 32 or input_word(s, at) != CIRCUIT_TAG or input_word(s, at + 24) != 0:
        return False
    nodes = input_word(s, at + 8)
    pairs = input_word(s, at + 16)
    return nodes > 0 and nodes <= NODE_MAX and pairs == 3 and length(s) == at + 32 + 40 * nodes + 16 * pairs

def valid_plan(s:readbuf, at:u64) -> bool:
    steps = input_word(s, at + 8)
    return input_word(s, at) == PLAN_TAG and steps > 0 and steps <= STEP_MAX and input_word(s, at + 16) <= 1 and input_word(s, at + 24) <= 1

def sparse_header(s:readbuf, at:u64) -> bool:
    return input_word(s, at + 8) <= VARIABLE_MAX and input_word(s, at + 16) <= CLAUSE_MAX

def solver_mode(s:readbuf, at:u64) -> u64:
    if input_word(s, at + 24) == 1:
        return RESTART_TAG
    if input_word(s, at + 16) == 1:
        return LEARN_TAG
    return SPARSE_TAG

def copy(s:readbuf, o:mutbuf, start:u64, stop:u64) -> u64:
    index = 0
    while start + index < stop:
        store(o, index, byte(s, start + index))
        index = index + 1
    return index
'''


def program():
    values = {name: int.from_bytes(tag.encode('ascii'), 'little')
              for name, tag in zip(('PLAN', 'PREPARE', 'SEARCH', 'FINISH'), PHASES, strict=True)}
    values.update(BAD=INVALID, PLAN_TAG=SEARCH_PLAN_REQUEST, CIRCUIT_TAG=CIRCUIT_REQUEST,
                  SPARSE_TAG=SPARSE_REQUEST, LEARN_TAG=LEARNING_REQUEST, RESTART_TAG=RESTART_REQUEST,
                  REPLY_TAG=SPARSE_REPLY, SKELETON_TAG=DECISION, COMPLETE_TAG=COMPOSITION_VERDICT,
                  CIRCUIT_BYTES=CIRCUIT_CAPACITY, NODE_MAX=CIRCUIT_NODES, STEP_MAX=STEP_LIMIT,
                  VARIABLE_MAX=SPARSE_VARIABLES, CLAUSE_MAX=SPARSE_CLAUSES, UNSAT=UNSAT)
    policy = re.sub(r'\b(' + '|'.join(values) + r')\b', lambda match: str(values[match[0]]), POLICY)
    return '\n'.join((policy, function(authority(), 'input_word'),
                      *(function(RELEASE_WRITER, name) for name in ('put', 'write'))))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
