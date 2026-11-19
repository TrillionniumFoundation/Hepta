"""HIA journal decisions with a mechanical, explicitly hosted service bridge.

Selected execution never calls the retained journal decision owner.
The selected store owns transactions and durability; business methods and
foreign Python object custody still use the service adapter.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
from functools import cached_property
from hashlib import sha256
from json import JSONDecodeError
import math
import os
import socket
import struct
import subprocess
import sys

from .hia_agent_data_json_native import materialize_data
from .hia_agent_store import AgentRejected, _agent_resource_path, wire
from .hia_json_decode_native import arena_sizes
from .hia_json_preflight_native import (
    MAX_IMAGE_BYTES, NativeHiaJsonImage, SYNTAX_REASONS, _installed_json_image, _source_resource_path,
)

SOURCE = _source_resource_path('examples/hia_bootstrap/agent_journal.hepta')
SCHEMA = 'hepta.hia.agent-journal-native.v2'
SELECTOR = 'HEPTA_HIA_AGENT_JOURNAL_MANIFEST'
MAX_BYTES = 8 << 20
HEADER_OFFSET = MAX_BYTES * 2
STATE_BYTES = 512
PRIVATE_BYTES = 32768
MAGIC = int.from_bytes(b'HIAJRN02', 'little')
COMPLETED_STAGE, REJECTED_STAGE, ENVELOPE_CAPACITY = 13, 14, 192
JOURNAL_FRAME = struct.Struct('<8s7Q')
JOURNAL_REPLY = struct.Struct('<8s5Q')
SESSION_EXECUTABLE_MARKER = b'hepta.hia.agent-journal.session.v1\0'
NONE, CONTINUE, LOOKUP, RESERVE, CACHE, REPLAY, VERIFY_REPLAY, ALIAS, ATOMIC, JOURNAL, FINAL, REFUSE, BOUND = range(13)
COST_WRITE, JOURNAL_WRITE = 1, 2
CONTEXT_NONE, CONTEXT_READ, CONTEXT_BUDGET, CONTEXT_CANDIDATE = range(4)
TOOLS = ('hia_describe', 'hia_artifact', 'hia_read', 'hia_context', 'hia_inspect',
         'hia_candidate', 'hia_verify', 'hia_emit', 'hia_evaluate',
         'hia_adopt', 'hia_rollback', 'hia_resource_read')


def buffer_sizes(size):
    arena, _keys = arena_sizes(size, 262144, 128)
    return HEADER_OFFSET + STATE_BYTES, max(arena, 4256 + _keys) + PRIVATE_BYTES


def _journal_scratch(stage, raw, tags):
    envelope = stage in (COMPLETED_STAGE, REJECTED_STAGE)
    return (8 + STATE_BYTES if envelope else
            buffer_sizes(0 if stage == 10 else len(raw))[1] + len(tags))


def _journal_reply(stage, scratch_size, header):
    if len(header) != JOURNAL_REPLY.size:
        raise RuntimeError('sealed HIA journal transport failed')
    envelope = stage in (COMPLETED_STAGE, REJECTED_STAGE)
    magic, code, response, cost, fixed, arena = JOURNAL_REPLY.unpack(header)
    if (magic != b'HIAJOU01' or code >= 1 << 32
            or response > (ENVELOPE_CAPACITY if envelope else MAX_BYTES)
            or cost > (0 if envelope else MAX_BYTES)
            or fixed != (0 if envelope else STATE_BYTES)
            or arena > (scratch_size - PRIVATE_BYTES if stage == 3 else 0)):
        raise RuntimeError('invalid sealed HIA journal frame')
    return code, response, cost, fixed, arena


def _journal_payload(reply, payload):
    code, response, cost, fixed, arena = reply
    if len(payload) != response + cost + fixed + arena:
        raise RuntimeError('invalid sealed HIA journal frame')
    response_end = response
    cost_end = response_end + cost
    state_end = cost_end + fixed
    return (code, payload[:response_end], payload[response_end:cost_end],
            payload[cost_end:state_end], payload[state_end:])


def _read_journal_bytes(stream, size):
    result = bytearray(size)
    view = memoryview(result)
    offset = 0
    while offset < size:
        count = stream.readinto(view[offset:])
        if not count:
            raise RuntimeError('sealed HIA journal session stopped before replying')
        offset += count
    return bytes(result)


def _standalone_journal(executable, stage, raw, state, tags=b'', *, data_profile=False):
    from .hia_scalar_reference_native import sealed_reference_bytes

    scratch_size = _journal_scratch(stage, raw, tags)
    header = JOURNAL_FRAME.pack(b'HIAJIN01', len(raw), scratch_size, stage,
                                sys.get_int_max_str_digits(), data_profile, len(tags), 0)
    try:
        with (sealed_reference_bytes(executable) as program,
              sealed_reference_bytes(header, state, tags, raw) as contents):
            child = subprocess.run(['/proc/self/fd/' + str(program)], stdin=contents,
                                   pass_fds=(program,), capture_output=True, env={'PATH': ''})
    except OSError as exc:
        raise RuntimeError('could not start the sealed HIA journal') from exc
    if child.returncode or child.stderr:
        raise RuntimeError('sealed HIA journal transport failed')
    header = child.stdout[:JOURNAL_REPLY.size]
    return _journal_payload(_journal_reply(stage, scratch_size, header), child.stdout[JOURNAL_REPLY.size:])


class _JournalProcess:
    """One exact executable owns a request's state; the bridge sends observations only."""
    def __init__(self, executable):
        from .hia_scalar_reference_native import sealed_reference_bytes

        control, child = socket.socketpair()
        try:
            with child, sealed_reference_bytes(executable) as program:
                self.process = subprocess.Popen(['/proc/self/fd/' + str(program), '--session'],
                    stdin=child, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                    pass_fds=(program,), env={'PATH': ''}, bufsize=0)
        except BaseException:
            control.close()
            raise
        self.control, self.sequence = control, 0

    def step(self, stage, raw, tags, *, data_profile):
        from .hia_scalar_reference_native import sealed_reference_bytes

        self.sequence += 1
        scratch_size = _journal_scratch(stage, raw, tags)
        header = JOURNAL_FRAME.pack(b'HIAJIN02', len(raw), scratch_size, stage,
                                    sys.get_int_max_str_digits(), data_profile, len(tags), self.sequence)
        try:
            with sealed_reference_bytes(header, tags, raw) as contents:
                ancillary = [(socket.SOL_SOCKET, socket.SCM_RIGHTS, struct.pack('@i', contents))]
                if self.control.sendmsg([b'J'], ancillary) != 1:
                    raise RuntimeError('incomplete HIA journal observation')
            reply = _journal_reply(stage, scratch_size,
                                   _read_journal_bytes(self.process.stdout, JOURNAL_REPLY.size))
            return _journal_payload(reply, _read_journal_bytes(self.process.stdout, sum(reply[1:])))
        except OSError as exc:
            raise RuntimeError('sealed HIA journal session transport failed') from exc

    def close(self, *, check):
        self.control.close()
        try:
            trailer, _ = self.process.communicate(timeout=5)
        except subprocess.TimeoutExpired as exc:
            self.process.kill()
            self.process.communicate()
            if check:
                raise RuntimeError('sealed HIA journal session did not exit') from exc
        else:
            if check and (trailer or self.process.returncode):
                raise RuntimeError('sealed HIA journal session did not close cleanly')


def _foreign_tool_types(tool):
    """Raw builtin type observations; no hash, membership or replay decision."""
    if type(tool) is not tuple:
        return b''
    pending, tags = [tool], bytearray()
    while pending:
        value = pending.pop()
        kind = type(value)
        tags.append({tuple: 1, list: 2, dict: 3}.get(kind, 0))
        if kind in (tuple, list):
            pending.extend(reversed(value))
        elif kind is dict:
            pending.extend(reversed(tuple(value.values())))
    return bytes(tags)


@dataclass(frozen=True)
class Instruction:
    action: int
    flags: int = 0
    response: bytes = b''
    cost_details: bytes = b''
    status: str | None = None
    arena: bytes = b''


class JournalSession:
    """Opaque state passed only between calls of one selected immutable image."""
    def __init__(self, image):
        from .hia_native_helpers import pinned_agent_journal_executable

        self.image = image
        self._state = bytes(STATE_BYTES)
        self._process = None
        self._executable = pinned_agent_journal_executable()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, *_):
        if self._process is not None:
            self._process.close(check=exc_type is None)

    def _exchange(self, stage, raw, tags=b'', *, data_profile=False):
        if self._process is None:
            if SESSION_EXECUTABLE_MARKER not in self._executable:
                return _standalone_journal(
                    self._executable, stage, raw, self._state, tags, data_profile=data_profile)
            try:
                self._process = _JournalProcess(self._executable)
            except OSError as exc:
                raise RuntimeError('could not start the sealed HIA journal session') from exc
        return self._process.step(stage, raw, tags, data_profile=data_profile)

    def _word(self, offset):
        return struct.unpack_from('<Q', self._state, offset)[0]

    @property
    def request_id(self):
        return self._state[192:258].decode('ascii') if self._state[192] else None

    @property
    def request_digest(self):
        return self._state[64:128].decode('ascii')

    @property
    def key(self):
        return self._state[128:192].decode('ascii') if self._word(24) else None

    @property
    def tool(self):
        value = self._word(16)
        return TOOLS[value - 1] if 1 <= value <= len(TOOLS) else None

    def _in_process_transition(self, stage, raw, foreign_types, data_profile):
        output_size, scratch_size = buffer_sizes(0 if stage == 10 else len(raw))
        scratch_size += len(foreign_types)
        canary = bytes(range(64))
        source = ctypes.create_string_buffer(raw + canary)
        output = ctypes.create_string_buffer(output_size + len(canary))
        scratch = ctypes.create_string_buffer(scratch_size + len(canary))
        ctypes.memmove(ctypes.addressof(output) + output_size, canary, len(canary))
        ctypes.memmove(ctypes.addressof(scratch) + scratch_size, canary, len(canary))
        ctypes.memmove(ctypes.addressof(scratch) + scratch_size - PRIVATE_BYTES,
                       self._state, STATE_BYTES)
        ctypes.memmove(ctypes.addressof(scratch) + scratch_size - PRIVATE_BYTES - len(foreign_types),
                       foreign_types, len(foreign_types))
        struct.pack_into('<Q', scratch, scratch_size - PRIVATE_BYTES + 336, len(foreign_types))
        struct.pack_into('<Q', scratch, scratch_size - PRIVATE_BYTES + 344,
                         data_profile)
        struct.pack_into('<2Q', scratch, 0, stage, sys.get_int_max_str_digits())
        code = self.image._entry(source, len(raw), output, output_size, scratch, scratch_size)
        if (ctypes.string_at(source, len(raw) + len(canary)) != raw + canary
                or ctypes.string_at(ctypes.addressof(output) + output_size, len(canary)) != canary
                or ctypes.string_at(ctypes.addressof(scratch) + scratch_size, len(canary)) != canary):
            raise RuntimeError('native journal violated buffer custody')
        state = ctypes.string_at(ctypes.addressof(output) + HEADER_OFFSET, STATE_BYTES)
        if code >= 1 << 31:
            return code, b'', b'', state, b''
        response_size, cost_size = struct.unpack_from('<2Q', state, 272)
        if max(response_size, cost_size) > MAX_BYTES:
            raise RuntimeError('invalid native journal write extent')
        arena = b''
        if stage == 3:
            extent = struct.unpack_from('<Q', scratch, 32)[0]
            if not 64 <= extent <= scratch_size - PRIVATE_BYTES:
                raise RuntimeError('invalid native journal arena extent')
            arena = ctypes.string_at(scratch, extent)
        return (code, ctypes.string_at(output, response_size),
                ctypes.string_at(ctypes.addressof(output) + MAX_BYTES, cost_size), state, arena)

    def _run(self, stage, raw=b'', foreign_types=b'', *, data_profile=False):
        if type(raw) is not bytes or stage != 10 and len(raw) > MAX_BYTES:
            raise ValueError('journal JSON must be bytes within 8 MiB')
        if type(foreign_types) is not bytes or len(foreign_types) > 262144 or stage != 0 and foreign_types:
            raise RuntimeError('invalid journal foreign-type observation')
        if self._executable is None:
            code, response, cost, state, arena = self._in_process_transition(stage, raw, foreign_types, data_profile)
        else:
            code, response, cost, state, arena = self._exchange(stage, raw, foreign_types, data_profile=data_profile)
        if code >= 1 << 31 and (response or cost or arena):
            raise RuntimeError('native journal diagnostic supplied write instructions')
        if code == 0xffffffe8:
            reason = struct.unpack_from('<Q', state)[0]
            if stage != 3 or reason not in SYNTAX_REASONS:
                raise RuntimeError('invalid native cached JSON syntax diagnostic')
            raise ValueError('HIA JSON preflight: ' + SYNTAX_REASONS[reason])
        if code == 0xffffffe7:
            start, end, reason = struct.unpack_from('<3Q', state)
            reasons = {1: 'invalid start byte', 2: 'invalid continuation byte', 3: 'unexpected end of data'}
            if stage != 10 or not 0 <= start < end <= len(raw) or reason not in reasons:
                raise RuntimeError('invalid native UTF-8 codec diagnostic')
            raise UnicodeDecodeError('utf-8', raw, start, end, reasons[reason])
        if code == 0xffffffe4:
            reason, position, line, column = struct.unpack_from('<4Q', state)
            reasons = {9: 'Expecting value', 10: 'Expecting value', 12: 'Extra data',
                       14: "Expecting ',' delimiter", 18: "Expecting ',' delimiter",
                       16: 'Expecting property name enclosed in double quotes',
                       17: "Expecting ':' delimiter"}
            if stage != 3 or data_profile or reason not in reasons or position > len(raw):
                raise RuntimeError('invalid native original JSON syntax diagnostic')
            # HIA owns grammar, the original character position and line/column.
            # This is only construction of the prior foreign exception object.
            error = JSONDecodeError(reasons[reason], raw.decode('utf-8'), position)
            if (error.lineno, error.colno) != (line, column):
                raise RuntimeError('native original JSON position disagrees with foreign text')
            raise error
        if code in (0xffffffe6, 0xffffffe5):
            if stage != 3:
                raise RuntimeError('invalid native cached JSON structural diagnostic')
            if code == 0xffffffe6:
                raise OverflowError('HIA JSON exceeds node/depth budget before decoding')
            raise ValueError('HIA JSON preflight: duplicate decoded object key')
        if code in (0xffffffff, 0xfffffffc, 0xfffffffe, 0xfffffff0, 0xffffffea):
            if stage == 3 and data_profile:
                # The existing explicit arena selector has a distinct public
                # diagnostic ABI. HIA still makes the parse/budget decision.
                if code == 0xfffffffe:
                    raise ValueError('HIA JSON preflight: node/depth budget exceeded')
                if code in (0xffffffff, 0xfffffffc):
                    raise ValueError('HIA JSON decoder: ' + {
                        0xffffffff: 'invalid JSON syntax or Unicode',
                        0xfffffffc: 'duplicate decoded object key'}[code])
            reasons = {0xffffffff: 'invalid JSON syntax or Unicode',
                       0xfffffffc: 'duplicate decoded object key',
                       0xfffffffe: 'JSON node/depth budget exceeded',
                       0xfffffff0: 'nonfinite number or integer conversion limit',
                       0xffffffea: 'E_HIA_EDIT: JSON encoding exceeds byte budget'}
            raise ValueError(reasons[code])
        if code == 0xfffffffd:
            raise RuntimeError('native journal rejected its protocol phase or scratch profile')
        word = lambda offset: struct.unpack_from('<Q', state, offset)[0]
        actions = {0: {CONTINUE, LOOKUP, ALIAS, REFUSE}, 1: {RESERVE, CACHE, REFUSE},
                   2: {CONTINUE}, 3: {REPLAY, VERIFY_REPLAY, REFUSE}, 4: {CONTINUE},
                   5: {CONTINUE, ATOMIC}, 6: {NONE, JOURNAL}, 7: {NONE},
                   8: {NONE, FINAL}, 9: {BOUND, REFUSE}, 10: {13},
                   11: {CONTINUE, REFUSE}, 12: {CONTINUE, REFUSE}}
        if (word(0) != MAGIC or code not in actions[stage] or word(48) != code
                or word(8) not in {0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11}
                or word(16) > 12 or word(24) > 1 or word(32) > 1 or word(40) > 1
                or word(264) > 2 or word(272) != len(response) or word(280) != len(cost)
                or word(288) > 3):
            raise RuntimeError('invalid native journal instruction')
        if self.request_id is not None and state[64:258] != self._state[64:258]:
            raise RuntimeError('native journal changed admitted request identity')
        if (code == FINAL and (word(288) not in {1, 3} or not word(272) or not word(280) or not word(264))
                or code == JOURNAL and (word(288) != 2 or not word(272) or word(280) or word(264) != 1)
                or code not in {FINAL, JOURNAL} and (word(288) or word(272) or word(280) or word(264))):
            raise RuntimeError('invalid native journal write instruction')
        if stage == 12 and (word(320) > CONTEXT_CANDIDATE
                            or code == REFUSE and word(320) != CONTEXT_NONE):
            raise RuntimeError('invalid native journal context instruction')
        if stage == 3 and len(arena) < 64:
            raise RuntimeError('invalid native journal arena extent')
        self._state = state
        return Instruction(code, word(288), response, cost,
                           {0: None, 1: 'completed', 2: 'rejected'}[word(264)], arena)

    def prepare(self, raw, foreign_types=b''):
        return self._run(0, raw, foreign_types)

    def bind_catalog(self, raw):
        if self._run(9, raw).action == REFUSE:
            self.raise_refusal()

    def lookup(self, row):
        # Actual observed columns, not a hosted comparison or decision.
        # Preserve non-TEXT SQLite storage classes without trying to JSON
        # encode BLOB or infinite REAL values. HIA rejects their type itself.
        def observed(value):
            return value if type(value) is str else {'sqlite_storage_class': type(value).__name__}
        return self._run(1, wire(None if row is None else
                               {'digest': observed(row['digest']), 'state': observed(row['state'])}))

    def reserved(self):
        return self._run(2)

    def cached(self, raw):
        if type(raw) not in (bytes, str):
            raise AgentRejected('E_HIA_JSON', 'JSON data must be UTF-8 bytes or text')
        selected = os.environ.get('HEPTA_HIA_AGENT_BINARY64_MANIFEST')
        selected_data = os.environ.get('HEPTA_HIA_AGENT_DATA_JSON_MANIFEST')
        payload = raw if type(raw) is bytes else raw.encode('utf-8')
        if type(raw) is bytes and not selected_data:
            # Python's previous byte codec precedes its JSON byte budget. HIA
            # scans the full observed BLOB and supplies the exact error span.
            self._run(10, payload)
        if len(payload) > MAX_BYTES:
            raise AgentRejected('E_HIA_JSON', 'JSON data exceeds 8 MiB')
        if selected_data:
            from .hia_agent_data_json_native import installed_agent_data_json
            installed_agent_data_json(selected_data)
        else:
            selected_preflight = os.environ.get('HEPTA_HIA_JSON_PREFLIGHT_MANIFEST')
            if selected_preflight:
                from .hia_json_preflight_native import installed_preflight
                installed_preflight(selected_preflight)
        result = self._run(3, payload, data_profile=bool(selected_data))
        # Preserve decode_data's lazy numeric-object conversion and diagnostic
        # precedence. This bridge does not parse syntax or decide replay.
        converter = None
        def floating(text):
            nonlocal converter
            if selected:
                from .hia_agent_binary64_native import installed_agent_binary64
                try:
                    if converter is None:
                        converter = installed_agent_binary64(selected)
                    return converter.convert(text)
                except ValueError as exc:
                    raise AgentRejected('E_HIA_JSON', str(exc)) from exc
            number = float(text)
            if not math.isfinite(number):
                raise AgentRejected('E_HIA_JSON', 'nonfinite JSON number')
            return number
        value = materialize_data(result.arena, payload, parse_float=floating)
        if result.action == REFUSE:
            kinds = {16: 'NoneType', 17: 'bool', 18: 'bool', 19: 'int',
                     20: 'str', 21: 'list', 23: 'float'}
            kind = kinds.get(self._word(56))
            if kind is None:
                raise RuntimeError('invalid native cached-object refusal')
            raise AttributeError("'" + kind + "' object has no attribute 'get'")
        return result, value

    def aliased(self):
        return self._run(4)

    def _admit(self, stage, actual, expected, has_context=False):
        actual, expected = wire(actual), wire(expected)
        packet = struct.pack('<3Q', len(actual), len(expected), has_context) + actual + expected
        if self._run(stage, packet).action == REFUSE:
            self.raise_refusal()

    def admit_catalog(self, supplied, installed):
        self._admit(11, supplied, installed)

    def plan_context(self, installed, pinned, has_context):
        self._admit(12, installed, pinned, has_context)
        return self._word(320)

    def effect(self):
        return self._run(5)

    def completed(self, result):
        return self._envelope(COMPLETED_STAGE, b'', result)

    def rejected(self, request_id, details):
        pending = request_id.encode('ascii') if self.request_id is None else b''
        return self._envelope(REJECTED_STAGE, pending, details)

    def _envelope(self, stage, observed, value):
        # Capture a small, read-only recipe. The result itself is not encoded,
        # copied, or inspected before the ordinary output-schema check.
        if self._executable is None:
            output = self._in_process_envelope(stage, observed)
        else:
            size, output, _, _, _ = self._exchange(stage, observed)
            if not 0 < size == len(output) <= ENVELOPE_CAPACITY:
                raise RuntimeError('invalid sealed HIA journal response envelope')
        size = len(output)
        response, cursor, bound = {}, 0, False
        while cursor < size:
            if size - cursor < 3:
                raise RuntimeError('truncated native journal response field')
            kind, key_size, text_size = struct.unpack_from('<3B', output, cursor)
            start = cursor + 3
            text = start + key_size
            cursor = text + text_size
            if not key_size or cursor > size:
                raise RuntimeError('invalid native journal response field extent')
            key = output[start:text].decode('ascii')
            if key in response:
                raise RuntimeError('duplicate native journal response field')
            if kind == 0:
                response[key] = output[text:cursor].decode('ascii')
            elif kind == 1 and not bound and not text_size:
                response[key] = value
                bound = True
            else:
                raise RuntimeError('invalid native journal response field kind')
        if not bound:
            raise RuntimeError('native journal response did not bind its payload')
        return response

    def _in_process_envelope(self, stage, observed):
        frame = struct.pack('<Q', stage) + self._state
        source = ctypes.create_string_buffer(observed, max(1, len(observed)))
        scratch = ctypes.create_string_buffer(frame, len(frame))
        canary = bytes(range(64))
        output = ctypes.create_string_buffer(ENVELOPE_CAPACITY + len(canary))
        output[ENVELOPE_CAPACITY:] = canary
        size = self.image._entry(source, len(observed), output, ENVELOPE_CAPACITY, scratch, len(frame))
        if not 0 < size <= ENVELOPE_CAPACITY or scratch.raw != frame or output[ENVELOPE_CAPACITY:] != canary:
            raise RuntimeError('invalid native journal response envelope')
        return output[:size]

    def inline(self, response):
        return self._run(6, wire(response))

    def committed_inline(self):
        return self._run(7)

    def finish(self, response):
        return self._run(8, b'' if response is None else wire(response))

    def raise_refusal(self):
        errors = {
            1: ('E_HIA_TOOL', 'unknown HIA tool'),
            2: ('E_HIA_REQUEST_CONFLICT', 'request key is already bound to different arguments'),
            3: ('E_HIA_REQUEST_UNKNOWN', 'original request has durable intent but no confirmed terminal result'),
            4: ('E_HIA_REJECTED', "unhashable type: 'list'"),
            5: ('E_HIA_REJECTED', "unhashable type: 'dict'"),
            7: ('E_HIA_JOURNAL_NATIVE', 'native journal catalog identity mismatch'),
            8: ('E_HIA_REJECTED', "unhashable type: 'list'"),
            9: ('E_HIA_REJECTED', "unhashable type: 'dict'"),
            10: ('E_HIA_CATALOG_STALE', 'tool catalog digest differs from installed catalog'),
            11: ('E_HIA_IMPLEMENTATION_STALE', 'installed implementation changed during this service session'),
        }
        code = self._word(56)
        if code not in errors:
            raise RuntimeError('invalid native journal refusal')
        name, message = errors[code]
        if code in (4, 5, 8, 9) and sys.version_info >= (3, 14):
            # HIA supplies both the top-level key kind and first unhashable
            # component. Only foreign interpreter exception wording varies.
            component = {4: 'list', 5: 'dict', 8: 'list', 9: 'dict'}[code]
            key_kind = 'tuple' if code in (8, 9) else component
            message = "cannot use '" + key_kind + "' as a dict key (" + message + ')'
        raise AgentRejected(name, message, retry_action='observe_original' if code == 3 else 'correct_input')


class NativeAgentJournal(NativeHiaJsonImage):
    def __init__(self, image, expected_sha256):
        if (type(image) is not bytes or not 0 < len(image) <= MAX_IMAGE_BYTES
                or sha256(image).hexdigest() != expected_sha256):
            raise ValueError('native HIA journal executable identity mismatch')
        self.image_sha256 = expected_sha256
        self._bytes = image

    def matches_standalone(self, executable):
        return executable.startswith(b'\x7fELF') and executable.count(self._bytes) == 1

    @cached_property
    def _in_process_image(self):
        return NativeHiaJsonImage(self._bytes, self.image_sha256)

    def _entry(self, *arguments):
        return self._in_process_image._entry(*arguments)

    def session(self):
        return JournalSession(self)

    def bind_catalog(self, raw):
        with self.session() as session:
            session.bind_catalog(raw)
        return self


def _catalog_bytes():
    return _agent_resource_path('docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes()


def installed_agent_journal(manifest):
    image = _installed_json_image(manifest, SOURCE, SCHEMA, NativeAgentJournal)
    return image.bind_catalog(_catalog_bytes())


def call_with_native_journal(service, tool, arguments, manifest):
    """Execute HIA instructions; tool effects retain their existing owners."""
    from . import hia_agent_service as hosted

    started = hosted.time.monotonic_ns()
    request_id = 'unadmitted-' + hosted.uuid.uuid4().hex
    try:
        session = _installed_json_image(manifest, SOURCE, SCHEMA, NativeAgentJournal).session()
    except (ValueError, OSError) as exc:
        return service._error(request_id, AgentRejected('E_HIA_JOURNAL_NATIVE', str(exc)))
    with session:
        try:
            session.bind_catalog(_catalog_bytes())
        except (ValueError, OSError) as exc:
            return service._error(request_id, AgentRejected('E_HIA_JOURNAL_NATIVE', str(exc)))
        return _run_native_journal(hosted, service, session, tool, arguments, started, request_id)


def _run_native_journal(hosted, service, session, tool, arguments, started, request_id):
    context_id, response = None, None
    native_failed = False
    domain_errors = (ValueError, TypeError, OSError, OverflowError, RecursionError, service.store.database_error)
    def native_step(operation, *arguments, acknowledgement=False):
        nonlocal native_failed
        try:
            return operation(*arguments)
        except BaseException as exc:
            # A newly introduced native protocol failure must not finalize a
            # completed response after its enclosing SQL transaction rolls back.
            # Do not invoke the failed image again or issue any terminal writes.
            # Payload refusal remains an ordinary domain rejection. Empty ACK
            # phases have no payload rejection domain; any failure is terminal
            # for this invocation, including asynchronous/process exceptions.
            if acknowledgement or not isinstance(exc, domain_errors):
                native_failed = True
            raise
    try:
        # Existing foreign snapshot and its error order remain explicit.
        arguments = hosted.decode_data(wire(arguments))
        original = wire({'tool': tool, 'arguments': arguments})
        step = native_step(session.prepare, original, _foreign_tool_types(tool))
        request_id = session.request_id
        if step.action == REFUSE:
            session.raise_refusal()
        if step.action == ALIAS:
            hosted.keys(arguments, ('uri',), ('max_bytes',), 'resource read')
            arguments = {'catalog_sha256': service.catalog_sha256,
                         'artifact': service.store.resolve_uri(arguments['uri']),
                         'max_bytes': arguments.get('max_bytes', 65536)}
            native_step(session.aliased)
            tool = session.tool
        if step.action == LOOKUP:
            with service.store.transaction():
                previous = service.store.journal_lookup(session.key)
                row = native_step(session.lookup, previous)
                if row.action == REFUSE:
                    session.raise_refusal()
                if row.action == RESERVE:
                    service.store.journal_reserve(session.key, session.request_digest, tool,
                                                  str(hosted.time.time_ns()))
                    # The write succeeded; acknowledgement precedes COMMIT, as before.
                    native_step(session.reserved, acknowledgement=True)
                elif row.action == CACHE:
                    replay, cached = native_step(session.cached, previous['response'])
                    if replay.action == VERIFY_REPLAY:
                        service._replay_verification(cached, arguments)
                    return cached
        service._validate_tool_arguments(tool, arguments)
        native_step(session.admit_catalog, arguments.get('catalog_sha256'), service.catalog_sha256)
        context_plan = native_step(session.plan_context, hosted.installation_manifest(),
                                   service.identities, 'context' in arguments)
        if context_plan != CONTEXT_NONE:
            context = service._context(arguments['context'])
            context_id = arguments['context']['id']
            if context_plan in {CONTEXT_BUDGET, CONTEXT_CANDIDATE}:
                service._budget(context, candidate=context_plan == CONTEXT_CANDIDATE)
        mode = native_step(session.effect)
        if mode.action == ATOMIC:
            try:
                with service.store.transaction():
                    result = getattr(service, '_' + tool)(arguments)
                    response = native_step(session.completed, result, acknowledgement=True)
                    service._validate_tool_response(tool, response)
                    instruction = native_step(session.inline, response)
                    if instruction.action == JOURNAL:
                        service.store.journal_complete(session.key, instruction.response.decode('utf-8'))
                        # The write succeeded; acknowledgement still precedes COMMIT.
                        native_step(session.committed_inline, acknowledgement=True)
            except BaseException as exc:
                # Also cover an asynchronous exception after SQL UPDATE returns
                # but before Python enters the ACK helper's own try boundary.
                if not isinstance(exc, domain_errors):
                    native_failed = True
                raise
        else:
            result = getattr(service, '_' + tool)(arguments)
            response = native_step(session.completed, result, acknowledgement=True)
            service._validate_tool_response(tool, response)
    except domain_errors as exc:
        if native_failed:
            raise
        try:
            response = native_step(session.rejected, request_id, service._error_details(exc), acknowledgement=True)
        except BaseException:
            native_failed = True
            raise
    except BaseException:
        # Include the whole SQL/hosted interval, not only calls into the image:
        # a signal or allocation failure can arrive after a successful INSERT
        # or UPDATE and before the following ACK helper is entered.
        native_failed = True
        raise
    finally:
        if not native_failed:
            instruction = session.finish(response)
            if instruction.flags & COST_WRITE:
                service.store.journal_cost(context_id, str(tool), request_id,
                                           str(hosted.time.monotonic_ns() - started), instruction.status,
                                           instruction.cost_details.decode('utf-8'))
            if instruction.flags & JOURNAL_WRITE:
                service.store.journal_complete(session.key, instruction.response.decode('utf-8'))
    return response
