"""Operator-selected HIA scalar identities and frozen-context budget rules.

The service binds inputs to Store authority before passing bounded scalar values
to this policy. It retains its existing public rejection codes and messages.
"""
from __future__ import annotations
import ctypes
import struct
from .hia_agent_store import _agent_resource_path, reject
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image

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

    def _request(self, wire):
        return self._response(wire, 24, '<3Q')

    def _response(self, wire, capacity, layout):
        source=ctypes.create_string_buffer(wire,len(wire))
        output=ctypes.create_string_buffer(capacity)
        unused=ctypes.create_string_buffer(1)
        status=self._entry(source,len(wire),output,capacity,unused,0)
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

    def _cost_word_totals(self, rows):
        wire = struct.pack('<2Q', MAGIC, 6) + b''.join(
            struct.pack('<2Q', scope, value) for scope, value in rows)
        context_low, context_high, unscoped_low, unscoped_high = self._response(wire, 40, '<5Q')
        if context_high + unscoped_high > len(rows):
            raise RuntimeError('invalid HIA Agent cost totals')
        return (context_high << 64) | context_low, (unscoped_high << 64) | unscoped_low

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
