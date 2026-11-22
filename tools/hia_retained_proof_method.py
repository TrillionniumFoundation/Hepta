"""Author preliminary native proof obligations, not solver or machine verdicts."""

FINITE_OBSERVATION = int.from_bytes(b'HIAFIR01', 'little')

EXTRA_KEYS = (
    'core_sha256', 'base_sha256', 'candidate_sha256', 'all_inputs', 'checked',
    'required', 'complete', 'all_inputs_in_declared_widths', 'transcript_sha256',
    'counterexample', 'reason', 'actual_sha256', 'bytes_equal', 'object_identity_equal',
    'sha256', 'outcome',
)

POLICY = r'''
# Result is a required independent evidence effect or zero for a local
# check. The enclosing Worker must still verify stored Core/subject custody.
def method_effect(s:readbuf, w:mutbuf, check:u64, evidence:u64, method:u64, claim:u64, status:u64) -> u64:
    scope = lookup(w, check, K_subject)
    core = lookup(w, scope, K_candidate_core_sha256)
    base = lookup(w, scope, K_base_core_sha256)
    if digest_text(w, core, False) == False:
        return BAD_METHOD
    if method == M_core_admission:
        if claim != 1 or status != 1 or admission_checker(w, lookup(w, evidence, K_checker)) == False:
            return BAD_METHOD
        return trust_if(same(s, w, core, lookup(w, evidence, K_core_sha256)))
    if method == M_complete_native_rederivation:
        if claim != 4:
            return BAD_METHOD
        return native_rederivation(s, w, scope, evidence, status)
    if claim == 2 and digest_text(w, base, False):
        return behavior_method(s, w, evidence, method, status, base, core)
    if claim == 3:
        return lowering_method(s, w, scope, evidence, method, status, core)
    return BAD_METHOD

def behavior_method(s:readbuf, w:mutbuf, evidence:u64, method:u64, status:u64, base:u64, core:u64) -> u64:
    if method == M_compositional_scalar_effect:
        if optimization_schema(w, lookup(w, evidence, K_schema)) == False:
            return BAD_METHOD
        if behavior_digests(s, w, evidence, base, core) == False:
            return BAD_METHOD
        code = optimization_status(w, lookup(w, evidence, K_status))
        if code == 0 or code != status:
            return BAD_METHOD
        return 1
    if method_id(w, lookup(w, evidence, K_method)) != method:
        return BAD_METHOD
    if method == M_canonical_core_identity:
        return trust_if(status == 1 and same(s, w, base, core) and behavior_digests(s, w, evidence, base, core)
                        and true_field(w, evidence, K_all_inputs))
    if method == M_context_budget_exhausted:
        return trust_if(status == 3)
    if method == M_finite_domain:
        return finite_evidence(s, w, evidence, status, base, core)
    return BAD_METHOD

def finite_evidence(s:readbuf, w:mutbuf, evidence:u64, status:u64, base:u64, core:u64) -> u64:
    checked = count4096(s, w, lookup(w, evidence, K_checked))
    required = count4096(s, w, lookup(w, evidence, K_required))
    if required == 0 or required > 4096 or checked > required:
        return BAD_METHOD
    if status == 1:
        return trust_if(checked == required and true_field(w, evidence, K_complete)
                        and true_field(w, evidence, K_all_inputs_in_declared_widths)
                        and behavior_digests(s, w, evidence, base, core)
                        and digest_text(w, lookup(w, evidence, K_transcript_sha256), False))
    counterexample = lookup(w, evidence, K_counterexample)
    if status == 2 and object(w, counterexample):
        return 3
    return trust_if(status == 3 and counterexample == NONE and false_field(w, evidence, K_complete))

def count4096(s:readbuf, w:mutbuf, node:u64) -> u64:
    if node == NONE or get(w, node) != 3:
        return 4097
    extent = get(w, node + 32)
    if extent < 1 or extent > 4:
        return 4097
    at = get(w, node + 24)
    total = 0
    index = 0
    while index < extent:
        digit = byte(s, at + index)
        if digit < 48 or digit > 57:
            return 4097
        total = total * 10 + digit - 48
        index = index + 1
    return total

def behavior_digests(s:readbuf, w:mutbuf, evidence:u64, base:u64, core:u64) -> bool:
    return same(s, w, base, lookup(w, evidence, K_base_sha256)) and same(s, w, core, lookup(w, evidence, K_candidate_sha256))

def lowering_method(s:readbuf, w:mutbuf, scope:u64, evidence:u64, method:u64, status:u64, core:u64) -> u64:
    kind = subject_id(w, lookup(w, scope, K_kind))
    if method == M_canonical_lowering_unsupported:
        reason = lookup(w, evidence, K_reason)
        return trust_if(status == 4 and kind == 2 and reason != NONE and get(w, reason) == 4)
    if method_id(w, lookup(w, evidence, K_method)) != method:
        return BAD_METHOD
    if method == M_checked_explicit_machine_choices:
        plan = lookup(w, evidence, K_plan)
        if status != 1 or kind != 3 or object(w, plan) == False:
            return BAD_METHOD
        return trust_if(same(s, w, core, lookup(w, evidence, K_core_sha256))
                        and same(s, w, core, lookup(w, plan, K_core_sha256)))
    if method == M_independent_safe_core_machine_validation and kind == 4:
        if status_id(w, lookup(w, evidence, K_outcome)) == status:
            return 2
    return BAD_METHOD

def native_rederivation(s:readbuf, w:mutbuf, scope:u64, evidence:u64, status:u64) -> u64:
    reference = lookup(w, scope, K_native_artifact)
    if object(w, reference) == False or method_id(w, lookup(w, evidence, K_method)) != M_complete_native_rederivation:
        return BAD_METHOD
    digest = lookup(w, reference, K_sha256)
    if digest_text(w, digest, False) == False or same(s, w, digest, lookup(w, evidence, K_actual_sha256)) == False:
        return BAD_METHOD
    bytes_equal = lookup(w, evidence, K_bytes_equal)
    object_equal = lookup(w, evidence, K_object_identity_equal)
    if bytes_equal == NONE or object_equal == NONE:
        return BAD_METHOD
    left = get(w, bytes_equal)
    right = get(w, object_equal)
    if left < 1 or left > 2 or right < 1 or right > 2:
        return BAD_METHOD
    return trust_if(status == choose(left == 2 and right == 2, 1, 2))

def true_field(w:mutbuf, record:u64, field:u64) -> bool:
    node = lookup(w, record, field)
    return node != NONE and get(w, node) == 2

def trust_if(value:bool) -> u64:
    return choose(value, 0, BAD_METHOD)

def optimization_status(w:mutbuf, node:u64) -> u64:
    if optimization_proved(w, node):
        return 1
    if optimization_refuted(w, node):
        return 2
    if optimization_unknown(w, node) or optimization_timeout(w, node):
        return 3
    return 0
'''
