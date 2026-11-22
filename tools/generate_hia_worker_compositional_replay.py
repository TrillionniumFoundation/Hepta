"""Connect independent scalar projections to the native compositional solver."""

from pathlib import Path
import re

from hepta.hia_agent_assembly import render_assembly
from hepta.hia_cnf_native import (
    CIRCUIT_CAPACITY, CIRCUIT_NODES, CIRCUIT_REQUEST, CIRCUIT_RETURNS, LEARNING_REQUEST,
    PROJECTION_INPUT_LIMIT,
    RESTART_REQUEST, SEARCH_PLAN_REQUEST, SPARSE_CLAUSES, SPARSE_REPLY, SPARSE_REQUEST,
    SPARSE_VARIABLES, STEP_LIMIT, UNSAT,
)
from tools.generate_hia_artifact_publication import document
from tools.generate_hia_release_install import POLICY_SOURCE as RELEASE_WRITER
from tools.generate_hia_worker_artifact_authority import source_program as authority
from hepta.hia_optimization import DEFAULT_POLICY
from tools.generate_hia_worker_compositional_barrier import OBLIGATION_BATCH
from tools.generate_hia_worker_compositional_skeleton import DECISION
from tools.generate_hia_worker_finite_reference import INVALID
from tools.generate_hia_worker_inspection_effect import function
from tools.hia_retained_proof_method import COMPOSITION_VERDICT

SOURCE = Path('examples/hia_bootstrap/worker_compositional_replay.hepta')
PHASES = ('HIACPL01', 'HIACPP01', 'HIACPS01', 'HIACPF01', 'HIACPB01')

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
    if phase == BATCH:
        return check_batch(s, o)
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
    if length(s) != 128 or structure_matched(s) == False or discharged(s, 32) == False:
        return BAD
    return proved(o)

# The caller supplies only physical execution results from the pinned roles.
# Accept one, and only one, result for every original projected obligation,
# in the original order, before granting a single retained proof verdict.
def check_batch(s:readbuf, o:mutbuf) -> u64:
    if length(s) < 176 or structure_matched(s) == False:
        return BAD
    if input_word(s, 32) != OBLIGATION_TAG or input_word(s, 40) != 0:
        return BAD
    count = input_word(s, 48)
    extent = input_word(s, 56)
    if count == 0 or count > OBLIGATION_MAX or length(s) != 64 + 112 * count:
        return BAD
    at = 64
    seen = 0
    ordinal = 0
    while ordinal < count:
        size = input_word(s, at + 8)
        if input_word(s, at) != ordinal or size < 208 or size > GRAPH_MAX:
            return BAD
        if discharged(s, at + 16) == False:
            return BAD
        seen = seen + 8 + size
        at = at + 112
        ordinal = ordinal + 1
    if seen != extent:
        return BAD
    return proved(o)

def structure_matched(s:readbuf) -> bool:
    return input_word(s, 8) == SKELETON_TAG and input_word(s, 16) == 0 and input_word(s, 24) <= SCALAR_MAX

def discharged(s:readbuf, plan:u64) -> bool:
    predicate = plan + 32
    reply = plan + 64
    if valid_plan(s, plan) == False or sparse_header(s, predicate) == False:
        return False
    steps = input_word(s, plan + 8)
    if input_word(s, predicate) != solver_mode(s, plan) or input_word(s, predicate + 24) != steps:
        return False
    if input_word(s, reply) != REPLY_TAG or input_word(s, reply + 8) != UNSAT:
        return False
    return input_word(s, reply + 16) == input_word(s, predicate + 8) and input_word(s, reply + 24) <= steps

def proved(o:mutbuf) -> u64:
    put(o, 0, COMPLETE_TAG)
    put(o, 8, 0)
    put(o, 16, 1)
    return 24

def circuit(s:readbuf, at:u64) -> bool:
    if length(s) < at + 32 or input_word(s, at) != CIRCUIT_TAG or input_word(s, at + 24) != 0:
        return False
    nodes = input_word(s, at + 8)
    pairs = input_word(s, at + 16)
    return nodes > 0 and nodes <= NODE_MAX and pairs >= 2 and pairs <= PAIR_MAX and length(s) == at + 32 + 40 * nodes + 16 * pairs

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
              for name, tag in zip(('PLAN', 'PREPARE', 'SEARCH', 'FINISH', 'BATCH'), PHASES, strict=True)}
    values.update(BAD=INVALID, PLAN_TAG=SEARCH_PLAN_REQUEST, CIRCUIT_TAG=CIRCUIT_REQUEST,
                  SPARSE_TAG=SPARSE_REQUEST, LEARN_TAG=LEARNING_REQUEST, RESTART_TAG=RESTART_REQUEST,
                  REPLY_TAG=SPARSE_REPLY, SKELETON_TAG=DECISION, COMPLETE_TAG=COMPOSITION_VERDICT,
                  CIRCUIT_BYTES=CIRCUIT_CAPACITY, NODE_MAX=CIRCUIT_NODES, PAIR_MAX=CIRCUIT_RETURNS,
                  STEP_MAX=STEP_LIMIT, GRAPH_MAX=PROJECTION_INPUT_LIMIT, OBLIGATION_TAG=OBLIGATION_BATCH,
                  OBLIGATION_MAX=DEFAULT_POLICY['max_obligations'], SCALAR_MAX=DEFAULT_POLICY['max_scalar_operations'],
                  VARIABLE_MAX=SPARSE_VARIABLES, CLAUSE_MAX=SPARSE_CLAUSES, UNSAT=UNSAT)
    policy = re.sub(r'\b(' + '|'.join(values) + r')\b', lambda match: str(values[match[0]]), POLICY)
    return '\n'.join((policy, function(authority(), 'input_word'),
                      *(function(RELEASE_WRITER, name) for name in ('put', 'write'))))


if __name__ == '__main__':
    SOURCE.write_text(render_assembly(document(program(), SOURCE.stem)), encoding='utf-8')
