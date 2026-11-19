"""Operator-selected HIA scalar identities and frozen-context budget rules.

The service binds inputs to Store authority before passing bounded scalar values
to this policy. It retains its existing public rejection codes and messages.
"""
from __future__ import annotations
import ctypes
import struct
from .hia_agent_store import MAX_INPUT_BYTES, _agent_resource_path, decode_data, reject, wire
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image
from .hia_opcodes import EFFECTS, OPCODES, WIDTHS
from .hia_program_tools import HIAEditRejected

SOURCE=_agent_resource_path('examples/hia_bootstrap/agent_identity.hepta')
SCHEMA='hepta.hia.agent-identity-native.v1'
MAGIC=int.from_bytes(b'HIAIDP01','little')
RESULT_MAGIC=int.from_bytes(b'HIAIDR01','little')
SELECTOR='HEPTA_HIA_AGENT_IDENTITY_MANIFEST'
CONTEXT_REFUSALS = {
    1: ('E_HIA_BUDGET', 'execution profile admits 64 MiB..4 GiB address-space budgets'),
    2: ('E_HIA_BUDGET', 'native wall budget exceeds total wall budget'),
    3: ('E_HIA_BUDGET', 'reported model tokens exceed the frozen budget'),
    4: ('E_HIA_COST', 'complete external cost report cannot contain unknown fields'),
    5: ('E_HIA_BUFFER_BUDGET', 'frozen workload exceeds 32 MiB of external byte snapshots'),
}
EVALUATION_OUTCOMES = ('budget_exceeded', 'incorrect', 'inconclusive', 'improved', 'regressed', 'unchanged')
WORD_MASK = (1 << 64) - 1
DECLARED_OBSERVATION, REFERENCE_OBSERVATION, NATIVE_OBSERVATION = range(3)
_CLAIMS = ('core_admission', 'behavior_equivalence', 'lowering_refinement', 'encoding_check')
_SUBJECT_KINDS = {'native_artifact': 1, 'agent_machine_plan': 2}
CLAIM_NOT_QUALIFIED, CLAIM_QUALIFIED, CLAIM_BUILD_RECHECK = range(3)
PROOF_OPCODE_IDS = {name: index for index, name in enumerate(sorted(OPCODES), 1)}
PROOF_EFFECT_IDS = {name: 1 << index for index, name in enumerate(sorted(EFFECTS))}
EXACT_COMPARISON_CHUNK = 256 * 1024
PROOF_EVIDENCE_METHODS = (
    '', 'core_admission', 'canonical_core_identity', 'finite_domain',
    'context_budget_exhausted', 'checked_explicit_machine_choices',
    'canonical_lowering_unsupported', 'complete_native_rederivation',
)
PROOF_FINITE_COUNTEREXAMPLE = 8
PROOF_COMPOSITIONAL = 9
PROOF_INDEPENDENT_MACHINE = 10
_EVIDENCE_METHOD_IDS = {
    'canonical_core_identity': 1, 'finite_domain': 2, 'context_budget_exhausted': 3,
    'checked_explicit_machine_choices': 4, 'complete_native_rederivation': 5,
}
_PROOF_STATUS_IDS = {'proved': 1, 'refuted': 2, 'unknown': 3, 'unsupported': 4}
_PROOF_SUBJECT_IDS = {'core': 1, 'canonical_lowering': 2, 'agent_machine_plan': 3, 'native_artifact': 4}
ABI_SCALAR_IDS = {name: role for role, name in enumerate((*WIDTHS, 'bool', 'unit'), 1)}


def _observation_fields(observation, *, reference):
    status = observation['status']
    # Preserve the public comparison in which JSON true/false and 1/0
    # compare equally when used as result values (not as typed arguments).
    returned = (wire([int(value) if type(value) is bool else value for value in observation['values']])
                if status == 'returned' else b'')
    buffers = wire(observation['buffers']) if 'buffers' in observation else b''
    trap = wire(observation.get('trap_code')) if reference else b''
    resources = wire(observation['ledger']['resources']) if reference else b''
    return status.encode('ascii'), returned, buffers, trap, resources


def _enum_id(table, value):
    return table.get(value, 0) if type(value) is str else 0


def _proof_text(value):
    return b'\x01' + value.encode('utf-8', 'surrogatepass') if type(value) is str else b'\x00'


def _proof_count(value):
    return value if type(value) is int and 0 <= value <= WORD_MASK else WORD_MASK


def _proof_boolean(value):
    return 2 if value is True else 1 if value is False else 0


def _paired_packet(header, left, right):
    packet = bytearray(header)
    for expected, observed in zip(left, right, strict=True):
        packet.extend(struct.pack('<2Q', len(expected), len(observed)))
        packet.extend(expected)
        packet.extend(observed)
    return bytes(packet)


def _record_fields(fields, kind):
    # Persisted namespace fields are strings. Any other supplied JSON type
    # cannot equal an issued string, regardless of its textual form.
    encoded = []
    for field in fields:
        encoded.append(b'\x01' + field.encode('utf-8', 'surrogatepass')
                       if isinstance(field, str) else b'\x02')
    encoded.append(b'' if kind is None else b'\x01' + kind.encode('utf-8', 'surrogatepass'))
    return encoded


class NativeAgentIdentity(NativeHiaJsonImage):
    def scalar(self, value, kind):
        if type(kind)is not int or kind not in (0,1):
            raise ValueError('unknown native Agent identity operation')
        # Value-kind and bounded transport, not a numeric/hex fallback.
        if type(value)is not str or len(value)>64:
            return None
        try: payload=value.encode('ascii')
        except UnicodeEncodeError:return None
        wire=struct.pack('<2Q',MAGIC,kind)+payload
        valid, number = self._request(wire)
        if valid not in (0, 1) or (not valid and number != 0) or (kind == 1 and number != 0):
            raise RuntimeError('invalid HIA Agent scalar result')
        return number if valid else None

    def abi_scalar(self, value, typ):
        if value is None:
            kind, word = 1, 0
        elif type(value) is bool:
            kind, word = 2, int(value)
        elif type(value) is int and value.bit_length() <= 64:
            kind, word = (4, -value) if value < 0 else (3, value)
        else:
            kind, word = 0, 0
        packet = struct.pack('<5Q', MAGIC, 14, ABI_SCALAR_IDS.get(typ, 0), kind, word)
        valid, result = self._request(packet)
        if valid != 1 or result not in (0, 1):
            raise RuntimeError('invalid HIA Agent call scalar result')
        return bool(result)

    def _request(self, wire):
        return self._response(wire, 24, '<3Q')

    def _response(self, wire, capacity, layout, *, workspace=0):
        source=ctypes.create_string_buffer(wire,len(wire))
        output=ctypes.create_string_buffer(capacity)
        scratch=ctypes.create_string_buffer(max(1, workspace))
        status=self._entry(source,len(wire),output,capacity,scratch,workspace)
        if status!=capacity:raise RuntimeError('HIA Agent identity rejected owned packet')
        magic, *result=struct.unpack(layout,output.raw)
        if magic != RESULT_MAGIC:
            raise RuntimeError('invalid HIA Agent identity result')
        return result

    def _context(self, kind, fields, allowed):
        wire = struct.pack(f'<{2 + len(fields)}Q', MAGIC, kind, *fields)
        valid, decision = self._request(wire)
        if valid != 1 or decision not in (0, *allowed):
            raise RuntimeError('invalid HIA Agent context budget result')
        if decision:
            code, message = CONTEXT_REFUSALS[decision]
            reject(code, message, 'context')

    def context_limits(self, memory, total_wall, native_wall):
        self._context(2, (memory, total_wall, native_wall), (1, 2))

    def context_cost(self, limit, external, complete):
        fields = ('model_tokens', 'model_wall_ns', 'discovery_wall_ns')
        missing = sum(1 << index for index, field in enumerate(fields) if external[field] is None)
        self._context(3, (limit, int(external['model_tokens'] or 0), missing, int(complete)), (3, 4))

    def context_snapshots(self, sizes):
        self._context(4, tuple(sizes), (5,))

    def evaluation_measurement(self, before, after, threshold, *,
                               budget_exceeded, correct, complete, latency, trapping):
        flags = (budget_exceeded | (correct << 1) | (complete << 2)
                 | (latency << 3) | (trapping << 4))
        packet = struct.pack('<4QdQ', MAGIC, 5, before, after, threshold, flags)
        decision, bits = self._request(packet)
        if not 1 <= decision <= len(EVALUATION_OUTCOMES):
            raise RuntimeError('invalid HIA Agent evaluation decision')
        if (bits >> 52) & 2047 == 2047:
            raise RuntimeError('nonfinite HIA Agent evaluation ratio')
        ratio = struct.unpack('<d', struct.pack('<Q', bits))[0]
        return ratio, EVALUATION_OUTCOMES[decision - 1]

    def observation_agreement(self, left, right, *, mode):
        reference = mode == REFERENCE_OBSERVATION
        packet = _paired_packet(struct.pack('<3Q', MAGIC, 7, mode), _observation_fields(left, reference=reference),
                                _observation_fields(right, reference=reference))
        valid, agreement = self._request(packet)
        if valid != 1 or agreement not in (0, 1):
            raise RuntimeError('invalid HIA Agent observation decision')
        return bool(agreement)

    def record_authority(self, expected, observed, *, required_kind=None, observed_kind=None):
        header = struct.pack('<3Q', MAGIC, 8, int(observed is not None))
        packet = _paired_packet(header, _record_fields(expected, required_kind),
                                (b'',) * 4 if observed is None else _record_fields(observed, observed_kind))
        valid, decision = self._request(packet)
        if valid != 1 or decision not in (0, 1, 2):
            raise RuntimeError('invalid HIA Agent record authority decision')
        return decision

    def wall_window(self, created_ns, now_ns, total_ms):
        packet = struct.pack('<5Q', MAGIC, 9, created_ns, now_ns, total_ms)
        expired, remaining, high = self._response(packet, 32, '<4Q')
        if expired not in (0, 1) or high not in (0, 1) or (expired and (remaining or high)):
            raise RuntimeError('invalid HIA Agent deadline decision')
        return bool(expired), (high << 64) | remaining

    def claim_eligibility(self, claim, receipt, candidate_artifact, native, baseline_core_sha):
        subject = receipt['subject']
        checks = bytes(_CLAIMS.index(check['claim']) + 4 * (check['status'] == 'proved')
                       for check in receipt['checks'])
        planned = native['machine_plan'] is not None
        header = struct.pack('<6Q', MAGIC, 10, _CLAIMS.index(claim),
                             _SUBJECT_KINDS.get(subject['kind'], 0), int(planned), len(checks))
        expected = (baseline_core_sha, candidate_artifact, native['codegen'].get('plan') if planned else None)
        observed = (receipt['base_core_sha256'], subject.get('native_artifact'), subject.get('plan'))
        packet = _paired_packet(header + checks, map(wire, expected), map(wire, observed))
        valid, decision = self._request(packet)
        if valid != 1 or decision not in (CLAIM_NOT_QUALIFIED, CLAIM_QUALIFIED, CLAIM_BUILD_RECHECK):
            raise RuntimeError('invalid HIA Agent claim eligibility decision')
        return decision

    def proof_evidence(self, claim, status, subject, evidence, *, admission_checker):
        claim_id = _CLAIMS.index(claim) + 1 if type(claim) is str and claim in _CLAIMS else 0
        core, base = subject['candidate_core_sha256'], subject['base_core_sha256']
        plan = evidence.get('plan')
        native = subject.get('native_artifact')
        flags = (
            (subject.get('base_program') is not None)
            | ((base is not None) << 1)
            | ((evidence.get('all_inputs') is True) << 2)
            | ((evidence.get('all_inputs_in_declared_widths') is True) << 3)
            | ((type(evidence.get('transcript_sha256')) is str) << 4)
            | (('counterexample' in evidence) << 5)
            | ((type(evidence.get('reason')) is str) << 6)
            | ((type(plan) is dict) << 7)
            | ((_enum_id({'hepta.hia.optimization-verification.v1': 1}, evidence.get('schema'))) << 8)
        )
        header = struct.pack('<12Q', MAGIC, 15, claim_id, _enum_id(_PROOF_STATUS_IDS, status),
            _enum_id(_PROOF_SUBJECT_IDS, subject.get('kind')), _enum_id(_EVIDENCE_METHOD_IDS, evidence.get('method')),
            flags, _proof_count(evidence.get('checked')), _proof_count(evidence.get('required')),
            _proof_boolean(evidence.get('complete')), _proof_boolean(evidence.get('bytes_equal')),
            _proof_boolean(evidence.get('object_identity_equal')))
        expected = (admission_checker, core, core, base, core, core,
                    native.get('sha256') if type(native) is dict else None)
        observed = (evidence.get('checker'), evidence.get('core_sha256'), base,
                    evidence.get('base_sha256'), evidence.get('candidate_sha256'),
                    plan.get('core_sha256') if type(plan) is dict else None, evidence.get('actual_sha256'))
        code, decision = self._request(_paired_packet(header, map(_proof_text, expected),
                                                     map(_proof_text, observed)))
        if code != 1 or not 0 <= decision <= PROOF_INDEPENDENT_MACHINE:
            raise RuntimeError('invalid HIA verification evidence decision')
        return decision

    def finite_function(self, function):
        blocks = function['blocks']
        count = sum(len(block['ops']) for block in blocks)
        if len(blocks) > 128 or count > 4096:
            packet = struct.pack('<6Q', MAGIC, 11, len(blocks), 0, count, 0)
        else:
            indexes = {block['id']: index for index, block in enumerate(blocks, 1)}
            effects = 0
            for effect in function['effects']:
                effects |= PROOF_EFFECT_IDS.get(effect, 1 << 63)
            packet = bytearray(struct.pack('<6Q', MAGIC, 11, len(blocks), indexes[function['entry']],
                                           count, effects))
            for block in blocks:
                term = block['term']
                if term['op'] == 'jump':
                    packet.extend((indexes[term['target']], 0))
                elif term['op'] == 'branch':
                    packet.extend((indexes[term['then']['target']], indexes[term['else']['target']]))
                else:
                    packet.extend((0, 0))
            packet.extend(PROOF_OPCODE_IDS.get(op['op'], 0) for block in blocks for op in block['ops'])
        valid, eligible = self._response(bytes(packet), 24, '<3Q', workspace=384)
        if valid != 1 or eligible not in (0, 1):
            raise RuntimeError('invalid HIA finite-function decision')
        return bool(eligible)

    def finite_domain(self, parameters, consumed):
        request = struct.pack('<4Q', MAGIC, 12, consumed, len(parameters))
        if len(parameters) <= 12:
            request += bytes(1 if name == 'bool' else WIDTHS.get(name, 255) for name in parameters)
        valid, needed, total = self._response(request, 32, '<4Q')
        if valid != 1 or needed > 4096 or total != consumed + needed or total > 4096:
            raise RuntimeError('invalid HIA finite-domain decision')
        return needed, total

    def exact_bytes_equal(self, left: bytes, right: bytes) -> bool:
        if type(left) is not bytes or type(right) is not bytes:
            raise TypeError('HIA Agent exact comparison requires bytes')
        for offset in range(0, max(1, len(left), len(right)), EXACT_COMPARISON_CHUNK):
            end = offset + EXACT_COMPARISON_CHUNK
            packet = _paired_packet(struct.pack('<2Q', MAGIC, 13), (left[offset:end],), (right[offset:end],))
            valid, equal = self._request(packet)
            if valid != 1 or equal not in (0, 1):
                raise RuntimeError('invalid HIA Agent exact comparison result')
            if not equal:
                return False
        return True

    def _cost_word_totals(self, rows):
        wire = struct.pack('<2Q', MAGIC, 6) + b''.join(
            struct.pack('<2Q', scope, value) for scope, value in rows)
        context_low, context_high, unscoped_low, unscoped_high = self._response(wire, 40, '<5Q')
        if context_high + unscoped_high > len(rows):
            raise RuntimeError('invalid HIA Agent cost totals')
        return (context_high << 64) | context_low, (unscoped_high << 64) | unscoped_low

    def cost_window(self, observed_count):
        valid, retained = self._request(struct.pack('<3Q', MAGIC, 17, observed_count))
        if valid != 1 or retained > observed_count:
            raise RuntimeError('invalid HIA Agent observed-cost window')
        return retained

    def cost_ledger_header(self, context_ref, observed_count, policy, totals, evaluation_ns, native_ns):
        """Transport the captured values; HIA owns the report policy and shape."""
        attributed, unscoped = totals
        external = policy['external_costs']
        fields = (context_ref, str(attributed), str(evaluation_ns), external['discovery_wall_ns'],
                  external['model_tokens'], external['model_wall_ns'], policy['expected_invocations'],
                  str(native_ns), str(unscoped))
        packet = bytearray(struct.pack('<4Q', MAGIC, 16, observed_count, int(policy['external_costs_complete'])))
        for value in fields:
            fragment = wire(value)
            packet.extend(struct.pack('<Q', len(fragment)))
            packet.extend(fragment)
        capacity = min(MAX_INPUT_BYTES, len(packet) + 2048)
        source = ctypes.create_string_buffer(bytes(packet))
        output = ctypes.create_string_buffer(capacity)
        size = self._entry(source, len(packet), output, capacity, None, 0)
        if size == 4294967294:
            raise HIAEditRejected('E_HIA_EDIT: JSON encoding exceeds byte budget')
        if not 0 < size <= capacity:
            raise RuntimeError('invalid HIA Agent cost receipt')
        return decode_data(output.raw[:size])

    def observed_cost_totals(self, rows, context_id):
        # Match the Store's historic integer text decoder. New elapsed times
        # fit a word; imported historical integers keep their exact value.
        values = [(int(row['context_id'] is None), int(row['wall_ns']))
                  for row in rows if row['context_id'] in (context_id, None)]
        if all(0 <= value <= WORD_MASK for _, value in values):
            return self._cost_word_totals(values)
        positive = self._cost_magnitude_totals([(scope, value) for scope, value in values if value > 0])
        negative = self._cost_magnitude_totals([(scope, -value) for scope, value in values if value < 0])
        return positive[0] - negative[0], positive[1] - negative[1]

    def _cost_magnitude_totals(self, values):
        context = unscoped = offset = 0
        while values:
            words = [(scope, value & WORD_MASK) for scope, value in values]
            context_word, unscoped_word = self._cost_word_totals(words)
            context += context_word << offset
            unscoped += unscoped_word << offset
            offset += 64
            values = [(scope, value >> 64) for scope, value in values if value > WORD_MASK]
        return context, unscoped

    def uint64(self,value):return self.scalar(value,0)
    def digest(self,value):return self.scalar(value,1)is not None


def installed_agent_identity(path):
    return _installed_json_image(path,SOURCE,SCHEMA,NativeAgentIdentity)
