"""Build only the isolated static delta; do not import/execute the product."""
from pathlib import Path
import ast
import difflib
import hashlib
import json

ROOT = Path(__file__).resolve().parent
BASE = Path('/workspace/scratch/e26ed3e2edcf/combined-native-v88-r1')
FILES = {
    'tools/generate_hia_json_wire.py': '5fb87da789bd5087eaeef09ea330c758f466e681f0f808eca987dbfb95576cd4',
    'hepta/hia_json_wire_native.py': 'b6034104addb305f30181632284c8eac18ff8871b13c22e18b3bf68ad3638216',
    'tests/test_hia_json_wire_cache.py': 'd1626bc66a90c5681016a94871418778035d402b758e2669876b52d4a1e45d35',
}

def replace(text, old, new, count=1):
    if text.count(old) != count:
        raise AssertionError((old, text.count(old), count))
    return text.replace(old, new)

def pin(path, data):
    header = b'blob ' + str(len(data)).encode() + b'\0'
    return {'path': path, 'bytes': len(data), 'sha256': hashlib.sha256(data).hexdigest(),
            'git_blob_sha1': hashlib.sha1(header + data).hexdigest()}

rows = []
patches = []
for name, expected in FILES.items():
    raw = (BASE / name).read_bytes()
    if hashlib.sha256(raw).hexdigest() != expected:
        raise AssertionError(('baseline hash', name))
    before = ROOT / 'baseline' / name
    before.parent.mkdir(parents=True, exist_ok=True)
    if before.exists():
        raise AssertionError(('baseline already exists', name))
    before.write_bytes(raw)
    text = raw.decode()
    if name == 'tools/generate_hia_json_wire.py':
        text = replace(text, "CACHED_MAGIC = int.from_bytes(b'HIAWIR03', 'little')\n",
            "CACHED_MAGIC = int.from_bytes(b'HIAWIR03', 'little')\n"
            "KEY_SUMMARY_MAGIC = int.from_bytes(b'HIAWIR04', 'little')\n")
        text = replace(text, "'MAGIC': MAGIC, 'CACHED_MAGIC': CACHED_MAGIC, 'AWAIT': 8,",
            "'MAGIC': MAGIC, 'CACHED_MAGIC': CACHED_MAGIC,\n"
            "    'KEY_SUMMARY_MAGIC': KEY_SUMMARY_MAGIC, 'AWAIT': 8,")
        text = replace(text, "'CACHE_STORES': 672, 'CACHE_BYTES': 163840,",
            "'CACHE_STORES': 672, 'CACHE_BYTES': 163840,\n"
            "    'KEY_SUMMARY_READY': 680, 'KEY_SUMMARY_SIZE': 688,\n"
            "    'KEY_SUMMARY_HITS': 696, 'KEY_SUMMARY_MISSES': 704,")
        text = replace(text, "elif read64(s, 0) == CACHED_MAGIC:",
            "elif read64(s, 0) == CACHED_MAGIC or read64(s, 0) == KEY_SUMMARY_MAGIC:")
        text = replace(text, "if read64(s, 0) == CACHED_MAGIC and read64(s, 96) != 0:",
            "if (read64(s, 0) == CACHED_MAGIC or read64(s, 0) == KEY_SUMMARY_MAGIC) and read64(s, 96) != 0:")
        text = replace(text, "choose(read64(s, 0) == CACHED_MAGIC, CACHE_BYTES, 0)",
            "choose(read64(s, 0) == CACHED_MAGIC or read64(s, 0) == KEY_SUMMARY_MAGIC, CACHE_BYTES, 0)")
        text = replace(text, "if read64(s, 0) == CACHED_MAGIC:\n            put(w, CACHE_BASE, required - 8192 - CACHE_BYTES)",
            "if read64(s, 0) == CACHED_MAGIC or read64(s, 0) == KEY_SUMMARY_MAGIC:\n"
            "            put(w, CACHE_BASE, required - 8192 - CACHE_BYTES)")
        text = replace(text, "(get(w, 0) != MAGIC and get(w, 0) != CACHED_MAGIC)",
            "(get(w, 0) != MAGIC and get(w, 0) != CACHED_MAGIC and get(w, 0) != KEY_SUMMARY_MAGIC)")
        helper = '''def key_summary(w:mutbuf, handle:u64, next:u64) -> u64:
    # Only protocol 04 may omit a SUMMARY, and only for the exact string
    # whose immutable-key preflight already completed in this workspace.
    # Legacy 02/03 retain even their unused header bytes and request order.
    if get(w, 0) == KEY_SUMMARY_MAGIC:
        put(w, KEY_SUMMARY_READY, 0)
        base = get(w, CACHE_BASE)
        if base != 0 and handle != 0:
            slot = base + (handle & 1023) * 160
            if get(w, slot) == handle:
                size = get(w, slot + 8)
                count = get(w, slot + 16)
                width = get(w, slot + 24)
                if size <= 32 and count <= 128 and width >= 2 and width <= get(w, MAX):
                    put(w, KEY_SUMMARY_SIZE, size)
                    put(w, KEY_SUMMARY_READY, 1)
                    put(w, KEY_SUMMARY_HITS, get(w, KEY_SUMMARY_HITS) + 1)
                    put(w, PHASE, next)
                    return 0
        put(w, KEY_SUMMARY_MISSES, get(w, KEY_SUMMARY_MISSES) + 1)
    return ask(w, 1, handle, 0, 0, 0, next)

def key_fact(s:readbuf, w:mutbuf, offset:u64) -> u64:
    if get(w, 0) == KEY_SUMMARY_MAGIC and get(w, KEY_SUMMARY_READY) != 0:
        if offset == 24:
            return 4
        if offset == 32:
            return get(w, KEY_SUMMARY_SIZE)
        return 0
    return read64(s, offset)

def key_norm_begin(s:readbuf, w:mutbuf, handle:u64, role:u64, target:u64, next:u64) -> u64:
    if get(w, 0) != KEY_SUMMARY_MAGIC or get(w, KEY_SUMMARY_READY) == 0:
        return norm_begin(s, w, handle, role, target, next)
    put(w, N_H, handle)
    put(w, N_KIND, 4)
    put(w, N_SIZE, get(w, KEY_SUMMARY_SIZE))
    put(w, N_A, 0)
    put(w, N_B, 0)
    put(w, N_ROLE, role)
    put(w, N_TARGET, target)
    put(w, N_RETURN, next)
    put(w, N_COUNT, 0)
    put(w, N_TEXT, 0)
    put(w, PHASE, 20)
    return 0

'''
        text = replace(text, 'def push(w:mutbuf, handle:u64, depth:u64, leaving:u64) -> u64:\n',
            helper + 'def push(w:mutbuf, handle:u64, depth:u64, leaving:u64) -> u64:\n')
        changes = (
            ('return ask(w, 1, read64(s, 24), 0, 0, 0, 12)', 'return key_summary(w, read64(s, 24), 12)'),
            ('put(w, KEY_KIND, read64(s, 24))', 'put(w, KEY_KIND, key_fact(s, w, 24))'),
            ('return norm_begin(s, w, get(w, KEY_H), 0, get(w, TEMP_A), 13)',
             'return key_norm_begin(s, w, get(w, KEY_H), 0, get(w, TEMP_A), 13)'),
            ('return ask(w, 1, handle, 0, 0, 0, 15)', 'return key_summary(w, handle, 15)'),
            ('return norm_begin(s, w, get(w, N_H), 1, get(w, TEMP_B), 16)',
             'return key_norm_begin(s, w, get(w, N_H), 1, get(w, TEMP_B), 16)'),
            ('return ask(w, 1, get(w, record), 0, 0, 0, 114)', 'return key_summary(w, get(w, record), 114)'),
            ('put(w, record + 16, read64(s, 24))', 'put(w, record + 16, key_fact(s, w, 24))'),
            ('put(w, record + 24, read64(s, 32))', 'put(w, record + 24, key_fact(s, w, 32))'),
            ('put(w, record + 32, read64(s, 40))', 'put(w, record + 32, key_fact(s, w, 40))'),
            ('put(w, record + 40, read64(s, 48))', 'put(w, record + 40, key_fact(s, w, 48))'),
            ('return ask(w, 1, get(w, record), 0, 0, 0, 143)', 'return key_summary(w, get(w, record), 143)'),
            ('return ask(w, 1, get(w, frame + 48), 0, 0, 0, 143)', 'return key_summary(w, get(w, frame + 48), 143)'),
            ('return norm_begin(s, w, get(w, frame + 48), 3, get(w, TEMP_A), 144)',
             'return key_norm_begin(s, w, get(w, frame + 48), 3, get(w, TEMP_A), 144)'),
        )
        for old, new in changes:
            text = replace(text, old, new)
    elif name == 'hepta/hia_json_wire_native.py':
        text = replace(text, "CACHED_MAGIC = int.from_bytes(b'HIAWIR03', 'little')\n",
            "CACHED_MAGIC = int.from_bytes(b'HIAWIR03', 'little')\n"
            "KEY_SUMMARY_MAGIC = int.from_bytes(b'HIAWIR04', 'little')\n")
        text = replace(text,
            "'immutable_key_cache': 'HIAWIR03_only_for_fresh_stable_builtin_observer_without_renderer',",
            "'immutable_key_cache': 'HIAWIR04_key_facts_and_text_only_for_fresh_stable_builtin_observer_without_renderer',\n"
            "    'legacy_key_cache_protocol': 'HIAWIR03_keeps_every_SUMMARY_observation',\n"
            "    'key_fact_cache_lifetime': 'one_fresh_zeroed_session_after_original_exact_string_key_preflight',")
        text = replace(text,
            'float_renderer=None, _renderer_profile=None, _builtin_keys=False):',
            'float_renderer=None, _renderer_profile=None, _builtin_keys=False,\n'
            '                 _builtin_key_summaries=False):')
        text = replace(text,
            'self._protocol_magic = CACHED_MAGIC if self.key_cache else MAGIC',
            'self.key_summary_cache = self.key_cache and _builtin_key_summaries is True\n'
            '        self._protocol_magic = (KEY_SUMMARY_MAGIC if self.key_summary_cache else\n'
            '                                CACHED_MAGIC if self.key_cache else MAGIC)')
        text = replace(text, '_builtin_keys=True).run()',
            '_builtin_keys=True, _builtin_key_summaries=True).run()')
    else:
        text = replace(text, 'self.assertEqual(seen, [(True, native.CACHED_MAGIC)])',
            'self.assertEqual(seen, [(True, native.KEY_SUMMARY_MAGIC)])')
    ast.parse(text, filename=name)
    after = ROOT / 'inputs' / name
    after.parent.mkdir(parents=True, exist_ok=True)
    if after.exists():
        raise AssertionError(('candidate already exists', name))
    newraw = text.encode()
    after.write_bytes(newraw)
    rows.append({'path': name, 'before': pin(name, raw), 'after': pin(name, newraw)})
    patches.extend(difflib.unified_diff(raw.decode().splitlines(True), text.splitlines(True),
        fromfile='baseline/' + name, tofile='inputs/' + name))
(ROOT / 'THREE-SOURCE-DELTA.json').write_text(json.dumps({
    'schema': 'hepta.hia.json-wire-key-summary.static-delta.v1',
    'status': 'STATIC_UNGENERATED_UNEXECUTED',
    'baseline_tree': 'd9e8407c70e44a3ea0152b8b4c5eb2ed3833d790',
    'files': rows,
    'original_89_ids_or_workload_or_5_second_assertion_modified': False,
    'observer_or_source_admission_bodies_modified': False,
    'native_or_core_vm_executed': False,
}, indent=2) + '\n')
(ROOT / 'THREE-SOURCE.diff').write_text(''.join(patches))
print(json.dumps({'status': 'STATIC_AST_PARSED_ONLY', 'files': rows}))
