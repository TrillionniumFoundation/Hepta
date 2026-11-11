"""HIA journal decisions with a mechanical, explicitly hosted SQLite bridge.

Selected execution never calls the retained journal decision owner. SQLite
transactions/durability, business methods, schemas, context/proof admission and
foreign Python object custody remain hosted. This is not a native AgentStore.
"""
from __future__ import annotations

import ctypes
from dataclasses import dataclass
import struct
import sys

from .hia_agent_data_json_native import materialize_data
from .hia_agent_store import AgentRejected, _agent_resource_path, wire
from .hia_json_decode_native import arena_sizes
from .hia_json_preflight_native import NativeHiaJsonImage, _installed_json_image, _source_resource_path

SOURCE = _source_resource_path('examples/hia_bootstrap/agent_journal.hiaasm')
SCHEMA = 'hepta.hia.agent-journal-native.v1'
SELECTOR = 'HEPTA_HIA_AGENT_JOURNAL_MANIFEST'
MAX_BYTES = 8 << 20
HEADER_OFFSET = MAX_BYTES * 2
STATE_BYTES = 512
PRIVATE_BYTES = 32768
MAGIC = int.from_bytes(b'HIAJRN01', 'little')
NONE, CONTINUE, LOOKUP, RESERVE, CACHE, REPLAY, VERIFY_REPLAY, ALIAS, ATOMIC, JOURNAL, FINAL, REFUSE, BOUND = range(13)
COST_WRITE, JOURNAL_WRITE = 1, 2
TOOLS = ('hia_describe', 'hia_artifact', 'hia_read', 'hia_context', 'hia_inspect',
         'hia_candidate', 'hia_verify', 'hia_emit', 'hia_evaluate',
         'hia_adopt', 'hia_rollback', 'hia_resource_read')


def buffer_sizes(size):
    arena, _keys = arena_sizes(size, 262144, 128)
    return HEADER_OFFSET + STATE_BYTES, arena + PRIVATE_BYTES


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
        self.image = image
        self._state = bytes(STATE_BYTES)

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

    def _run(self, stage, raw=b''):
        if type(raw) is not bytes or len(raw) > MAX_BYTES:
            raise ValueError('journal JSON must be bytes within 8 MiB')
        output_size, scratch_size = buffer_sizes(len(raw))
        canary = bytes(range(64))
        source = ctypes.create_string_buffer(raw + canary)
        output = ctypes.create_string_buffer(output_size + len(canary))
        scratch = ctypes.create_string_buffer(scratch_size + len(canary))
        ctypes.memmove(ctypes.addressof(output) + output_size, canary, len(canary))
        ctypes.memmove(ctypes.addressof(scratch) + scratch_size, canary, len(canary))
        ctypes.memmove(ctypes.addressof(scratch) + scratch_size - PRIVATE_BYTES,
                       self._state, STATE_BYTES)
        struct.pack_into('<2Q', scratch, 0, stage, sys.get_int_max_str_digits())
        code = self.image._entry(source, len(raw), output, output_size, scratch, scratch_size)
        if (ctypes.string_at(source, len(raw) + len(canary)) != raw + canary
                or ctypes.string_at(ctypes.addressof(output) + output_size, len(canary)) != canary
                or ctypes.string_at(ctypes.addressof(scratch) + scratch_size, len(canary)) != canary):
            raise RuntimeError('native journal violated buffer custody')
        if code in (0xffffffff, 0xfffffffc, 0xfffffffe, 0xfffffff0, 0xffffffea):
            reasons = {0xffffffff: 'invalid JSON syntax or Unicode',
                       0xfffffffc: 'duplicate decoded object key',
                       0xfffffffe: 'JSON node/depth budget exceeded',
                       0xfffffff0: 'nonfinite number or integer conversion limit',
                       0xffffffea: 'E_HIA_EDIT: JSON encoding exceeds byte budget'}
            raise ValueError(reasons[code])
        if code == 0xfffffffd:
            raise RuntimeError('native journal rejected its protocol phase or scratch profile')
        state = ctypes.string_at(ctypes.addressof(output) + HEADER_OFFSET, STATE_BYTES)
        word = lambda offset: struct.unpack_from('<Q', state, offset)[0]
        actions = {0: {CONTINUE, LOOKUP, ALIAS, REFUSE}, 1: {RESERVE, CACHE, REFUSE},
                   2: {CONTINUE}, 3: {REPLAY, VERIFY_REPLAY}, 4: {CONTINUE},
                   5: {CONTINUE, ATOMIC}, 6: {NONE, JOURNAL}, 7: {NONE},
                   8: {NONE, FINAL}, 9: {BOUND, REFUSE}}
        if (word(0) != MAGIC or code not in actions[stage] or word(48) != code
                or word(8) not in {0, 1, 2, 3, 4, 5, 6, 7, 8, 10, 11}
                or word(16) > 12 or word(24) > 1 or word(32) > 1 or word(40) > 1
                or word(264) > 2 or word(272) > MAX_BYTES or word(280) > MAX_BYTES
                or word(288) > 3):
            raise RuntimeError('invalid native journal instruction')
        if self.request_id is not None and state[64:258] != self._state[64:258]:
            raise RuntimeError('native journal changed admitted request identity')
        if (code == FINAL and (word(288) not in {1, 3} or not word(272) or not word(280) or not word(264))
                or code == JOURNAL and (word(288) != 2 or not word(272) or word(280) or word(264) != 1)
                or code not in {FINAL, JOURNAL} and (word(288) or word(272) or word(280) or word(264))):
            raise RuntimeError('invalid native journal write instruction')
        arena = b''
        if code in {REPLAY, VERIFY_REPLAY}:
            extent = struct.unpack_from('<Q', scratch, 32)[0]
            if not 64 <= extent <= scratch_size - PRIVATE_BYTES:
                raise RuntimeError('invalid native journal arena extent')
            arena = ctypes.string_at(scratch, extent)
        self._state = state
        return Instruction(code, word(288), ctypes.string_at(output, word(272)),
                           ctypes.string_at(ctypes.addressof(output) + MAX_BYTES, word(280)),
                           {0: None, 1: 'completed', 2: 'rejected'}[word(264)], arena)

    def prepare(self, raw):
        return self._run(0, raw)

    def lookup(self, row):
        # Actual observed columns, not a hosted comparison or decision.
        return self._run(1, wire(None if row is None else
                               {'digest': row['digest'], 'state': row['state']}))

    def reserved(self):
        return self._run(2)

    def cached(self, raw):
        if type(raw) is not str:
            raise AgentRejected('E_HIA_JSON', 'JSON data must be UTF-8 bytes or text')
        payload = raw.encode('utf-8')
        result = self._run(3, payload)
        return result, materialize_data(result.arena, payload)

    def aliased(self):
        return self._run(4)

    def effect(self):
        return self._run(5)

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
        }
        code = self._word(56)
        if code not in errors:
            raise RuntimeError('invalid native journal refusal')
        name, message = errors[code]
        raise AgentRejected(name, message, retry_action='observe_original' if code == 3 else 'correct_input')


class NativeAgentJournal(NativeHiaJsonImage):
    def session(self):
        return JournalSession(self)

    def bind_catalog(self, raw):
        session = self.session()
        result = session._run(9, raw)
        if result.action == REFUSE:
            session.raise_refusal()
        return self


def installed_agent_journal(manifest):
    image = _installed_json_image(manifest, SOURCE, SCHEMA, NativeAgentJournal)
    return image.bind_catalog(_agent_resource_path('docs/HIA_AGENT_NATIVE_TOOL_CATALOG.json').read_bytes())


def call_with_native_journal(service, tool, arguments, manifest):
    """Execute HIA instructions; hosted methods and SQL retain their own owners."""
    from . import hia_agent_service as hosted

    started = hosted.time.monotonic_ns()
    request_id = 'unadmitted-' + hosted.uuid.uuid4().hex
    context_id, response = None, None
    try:
        session = installed_agent_journal(manifest).session()
    except (ValueError, OSError) as exc:
        return service._error(request_id, AgentRejected('E_HIA_JOURNAL_NATIVE', str(exc)))
    try:
        # Existing foreign snapshot and its error order remain explicit.
        arguments = hosted.decode_data(wire(arguments))
        step = session.prepare(wire({'tool': tool, 'arguments': arguments}))
        request_id = session.request_id
        if step.action == REFUSE:
            session.raise_refusal()
        if step.action == ALIAS:
            hosted.keys(arguments, ('uri',), ('max_bytes',), 'resource read')
            arguments = {'catalog_sha256': service.catalog_sha256,
                         'artifact': service.store.resolve_uri(arguments['uri']),
                         'max_bytes': arguments.get('max_bytes', 65536)}
            session.aliased()
            tool = session.tool
        if step.action == LOOKUP:
            with service.store.transaction():
                previous = service.store.db.execute(
                    'SELECT * FROM requests WHERE key=?', (session.key,)).fetchone()
                row = session.lookup(previous)
                if row.action == REFUSE:
                    session.raise_refusal()
                if row.action == RESERVE:
                    service.store.db.execute('INSERT INTO requests VALUES (?,?,?,?,?,?)',
                        (session.key, session.request_digest, tool, 'running', None, str(hosted.time.time_ns())))
                    # SQL succeeded; acknowledgement precedes COMMIT, as before.
                    session.reserved()
                elif row.action == CACHE:
                    replay, cached = session.cached(previous['response'])
                    if replay.action == VERIFY_REPLAY:
                        service._replay_verification(cached, arguments)
                    return cached
        hosted.validate(arguments, service.tools[tool]['inputSchema'])
        if tool != 'hia_describe' and arguments['catalog_sha256'] != service.catalog_sha256:
            hosted.reject('E_HIA_CATALOG_STALE', 'tool catalog digest differs from installed catalog')
        if hosted.installation_manifest() != service.identities:
            hosted.reject('E_HIA_IMPLEMENTATION_STALE', 'installed implementation changed during this service session')
        if 'context' in arguments:
            context = service._context(arguments['context'])
            context_id = arguments['context']['id']
            if tool not in {'hia_inspect', 'hia_rollback'}:
                service._budget(context, candidate=tool == 'hia_candidate')
        mode = session.effect()
        if mode.action == ATOMIC:
            with service.store.transaction():
                result = getattr(service, '_' + tool)(arguments)
                response = {'contract_version': hosted.VERSION, 'request_id': request_id,
                            'status': 'completed', 'result': result}
                hosted.validate(response, service.tools[tool]['outputSchema'], 'result')
                instruction = session.inline(response)
                if instruction.action == JOURNAL:
                    service.store.db.execute("UPDATE requests SET state='completed',response=? WHERE key=?",
                                             (instruction.response.decode('utf-8'), session.key))
                    # UPDATE succeeded; acknowledgement still precedes COMMIT.
                    session.committed_inline()
        else:
            result = getattr(service, '_' + tool)(arguments)
            response = {'contract_version': hosted.VERSION, 'request_id': request_id,
                        'status': 'completed', 'result': result}
            hosted.validate(response, service.tools[tool]['outputSchema'], 'result')
    except (ValueError, TypeError, OSError, OverflowError, RecursionError, hosted.sqlite3.Error) as exc:
        response = service._error(request_id, exc)
    finally:
        instruction = session.finish(response)
        if instruction.flags & COST_WRITE:
            service.store.db.execute(
                'INSERT INTO costs (context_id,tool,request_id,wall_ns,status,details) VALUES (?,?,?,?,?,?)',
                (context_id, str(tool), request_id, str(hosted.time.monotonic_ns() - started),
                 instruction.status, instruction.cost_details.decode('utf-8')))
        if instruction.flags & JOURNAL_WRITE:
            service.store.db.execute("UPDATE requests SET state='completed',response=? WHERE key=?",
                                    (instruction.response.decode('utf-8'), session.key))
    return response
