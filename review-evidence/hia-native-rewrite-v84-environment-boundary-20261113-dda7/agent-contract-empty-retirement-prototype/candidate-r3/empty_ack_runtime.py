"""Fixed physical metadata port for an explicitly negotiated development ABI.

The original claim/foreign-effect/ACK order is retained.  The tag describes
only actual empty private operand slots; HIA owns whether that removes a
subsequent retirement request.  No policy result is cached or synthesized.
"""
from __future__ import annotations
import ctypes
import struct

from hepta import hia_machine_plan_control_native as protocol
from hepta.hia_agent_contract_native import NativeAgentContract, AgentContractFrame, AgentContractUnknown

CAPABILITY_MAGIC = int.from_bytes(b'HIAECAP1', 'little')
EMPTY_TAG = int.from_bytes(b'HIAEACK1', 'little')
_EMPTY = protocol._EMPTY
_UNPACK = struct.unpack_from
_PACK = struct.pack_into
_READ = protocol._read_word
_PARTS = protocol.PlanFrame._parts
_CLEAR = protocol.PlanFrame._clear
_SET = protocol.PlanFrame._set
_GET = protocol.PlanFrame._get
_BASE_EFFECT = protocol.PlanFrame._effect
_EFFECT = AgentContractFrame._effect
_CALL = AgentContractFrame._call
_MOVE = AgentContractFrame._move
_TYPE = type


class EmptyAckFrame(AgentContractFrame):
    def __init__(self, *args, **kwargs):
        self._ack_issued = self._ack_raw = None
        super().__init__(*args, **kwargs)

    def service(self, issued):
        self._ack_issued = issued
        self._ack_raw = issued.raw if _TYPE(issued) is protocol.Issued else None
        return super().service(issued)

    def _empty_call_operands(self):
        raw = self._ack_raw
        if _TYPE(raw) is not bytes or len(raw) < 128 or raw[32] != 9 or raw[72] != 1:
            return 0
        # Replaced mechanical providers retain all original calls. No cached
        # decoded request or object metadata crosses a foreign operation.
        if (not self.image.enable_empty_ack or _TYPE(self) is not EmptyAckFrame
                or _TYPE(self.image) is not NativeEmptyAckContract
                or self.image._entry is not self.image._empty_native_entry
                or struct.unpack_from is not _UNPACK or struct.pack_into is not _PACK
                or protocol._read_word is not _READ or protocol._EMPTY is not _EMPTY
                or protocol.PlanFrame._parts is not _PARTS
                or protocol.PlanFrame._clear is not _CLEAR
                or protocol.PlanFrame._set is not _SET
                or protocol.PlanFrame._get is not _GET
                or protocol.PlanFrame._effect is not _BASE_EFFECT
                or AgentContractFrame._effect is not _EFFECT
                or AgentContractFrame._call is not _CALL
                or AgentContractFrame._move is not _MOVE
                or _TYPE(self.values) is not list
                or not self.executed or not self.completed
                or self.pending is not self._ack_issued
                or _TYPE(self.pending) is not protocol.Issued
                or self.pending.raw is not self._ack_raw
                or self.frame_bytes is not self._ack_raw):
            return 0
        for name in ('_parts', '_clear', '_set', '_get', '_effect', '_call', '_move'):
            if name in self.__dict__ or name in EmptyAckFrame.__dict__:
                return 0
        if ('_parts' in AgentContractFrame.__dict__ or '_clear' in AgentContractFrame.__dict__
                or '_set' in AgentContractFrame.__dict__ or '_get' in AgentContractFrame.__dict__):
            return 0
        head = _UNPACK('<12Q', raw)
        if (head[0] != protocol.MAGIC or head[1] != self.nonce
                or head[2] != _READ(self.state, 144) or head[4] != 9 or head[9] != 1
                or _READ(self.state, 128) != protocol.MAGIC
                or _READ(self.state, 136) != self.nonce
                or _READ(self.state, 168) != 2 or _READ(self.state, 184) != 9):
            return 0
        at = _READ(self.state, 200)
        table = self.image.table
        if _TYPE(table) is not bytes or at + 14 > len(table):
            return 0
        count = table[at + 5]
        start = at + 14 + 2 * table[at + 2] + 2 * table[at + 3] + 4 * table[at + 4] + 2 * _UNPACK('<H', table, at + 6)[0]
        if (not count or head[10:12] != (count, start) or start + 2 * count > len(table)
                or table[at] != 1 or table[at + 1] != 9):
            return 0
        metadata = _READ(self.state, 256)
        for index in range(count):
            slot = _UNPACK('<H', table, start + 2 * index)[0]
            if (slot >= len(self.values) or metadata + slot >= len(table)
                    or table[metadata + slot] != 1 or self.values[slot] is not _EMPTY):
                return 0
        return EMPTY_TAG

    def _invoke(self, command, flag=0, error=0, op=0):
        # Original ordering through request packing and the entry counter.
        # Observe empty slots only after these original provider calls, at the
        # same ACK boundary. The following native call remains mandatory.
        if self.closed and not self._retiring:
            raise RuntimeError('native machine-plan frame is closed')
        sequence = 0 if not self._started else protocol._read_word(self.state, 144)
        value = self.mode if command == 0 else op if command == 2 else flag
        struct.pack_into('<6Q', self.state, 0, command, self.nonce, sequence, value, error,
                         self._runtime_profile)
        self.image.entries += 1
        if command == 1:
            tag = self._empty_call_operands()
            # The field is written freshly on every ACK, including a zero
            # fallback. No prior physical tag can authorize another request.
            _PACK('<Q', self.state, 48, tag)
        return self.image._entry(self.image._table_buffer, len(self.image.table),
                                 self.output, len(self.output), self.state, len(self.state))


class NativeEmptyAckContract(NativeAgentContract):
    """Explicit prototype, never registered as the R3 production image."""
    def __init__(self, image, expected_sha256, namespace=None, *, enable_empty_ack=True):
        super().__init__(image, expected_sha256, namespace)
        output = ctypes.create_string_buffer(2048)
        state = ctypes.create_string_buffer(self.workspace_bytes)
        _PACK('<Q', state, 0, 5)
        status = self._entry(self._table_buffer, len(self.table), output, len(output), state, len(state))
        if status != 16 or _UNPACK('<4Q', output) != (CAPABILITY_MAGIC, 1, EMPTY_TAG, 1):
            raise AgentContractUnknown('empty-ACK image did not emit its exact private capability')
        self._empty_native_entry = self._entry
        self.enable_empty_ack = enable_empty_ack

    def _frame(self, name, arguments, captures=(), *, witness=None):
        if _TYPE(name) is str:
            mode, arity = self.modes[name]
            if _TYPE(arguments) is not tuple or len(arguments) != arity:
                raise TypeError('contract argument arity differs')
        else:
            mode = name
        return EmptyAckFrame(self, mode, arguments, captures, witness=witness)
