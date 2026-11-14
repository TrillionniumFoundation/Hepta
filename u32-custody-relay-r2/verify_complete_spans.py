"""Read original custody bytes through one <=128 MiB decoded span.

No product imports, subprocesses, compilation, VM, network, extraction or retry.
All JSON outputs are new files; failures retain their intent and journal.
"""
from pathlib import Path, PurePosixPath
import ast
import base64
import collections
import copy
import gc
import hashlib
import io
import json
import os
import stat
import time
import traceback
import zipfile
import zlib

ROOT = Path(__file__).resolve().parent
BASE = Path('/workspace/scratch/dda74a4fae35')
SPAN = 128 << 20
BLOCK = 1 << 20
SIZE = 1270286664
ORIGINAL_SHA = 'f318593523cc6294e9507aae9ef351d64231a2ead829d325e2e563a96176fb02'
ORIGINAL_GIT = '756842fd978ecf0e5a346535ca251fd459c42bbe'
REPORTS_SHA = 'c7cc9ebf536332fb72b2f7f3f7fc62f879f4c40271f386717193f9da723a3594'
SCOPE = PurePosixPath('/home/runner/work/_temp/u32-frozen-r2')
PREFIX = 'scope/evidence/full-qualification-r2/'
SOURCE_PREFIX = 'scope/candidate/source/'
STAT_FIELDS = ('st_dev', 'st_ino', 'st_mode', 'st_size', 'st_mtime_ns', 'st_ctime_ns')
PIN_FIELDS = ('bytes', 'sha256', 'git_blob')
LOCAL_SCOPE = BASE / 'v121-selfhost-small-constant-r1'
LOCAL_ALLOW = BASE / 'v134-u32-full-hosted-plan-r1/JSON-POINTER-ALLOWLIST.json'
DOCS = {'generation': 'GENERATION-EXECUTION-PLAN.json', 'storage': 'C0-EXECUTION-PLAN-R2.json',
        'projection': 'authoring/full-qualification-r2/PROJECTION-PROOF.json',
        'full': 'FULL-QUALIFICATION-EXECUTION-PLAN-R2.json'}


def require(value, reason):
    if not value:
        raise AssertionError(reason)


def encode(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=False,
                       allow_nan=False) + '\n').encode('utf-8')


def pin(raw):
    return {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest(),
            'git_blob': hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()}


def stamp(path):
    value = path.lstat()
    require(stat.S_ISREG(value.st_mode), 'not a regular custody input: ' + str(path))
    return {key: getattr(value, key) for key in STAT_FIELDS}


def write_new(name, value):
    raw = encode(value)
    with (ROOT / name).open('xb') as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return dict(path=str(ROOT / name), **pin(raw))


def safe_name(name):
    require(type(name) is str and name and '\0' not in name and '\\' not in name,
            'invalid archive/logical name')
    value = name[:-1] if name.endswith('/') else name
    parts = value.split('/')
    require(not value.startswith('/') and all(x not in ('', '.', '..') for x in parts),
            'unsafe archive/logical name: ' + name)
    return value


def logical_path(absolute):
    value = PurePosixPath(absolute)
    require(value.is_absolute() and '..' not in value.parts, 'invalid captured absolute path')
    relative = value.relative_to(SCOPE).as_posix()
    safe_name(relative)
    return 'scope/' + relative


def same_pin(actual, expected, label):
    require(all(actual[key] == expected[key] for key in PIN_FIELDS), 'byte identity differs: ' + label)


def tree_id(files):
    nested = {}
    for path, row in files.items():
        parts = PurePosixPath(safe_name(path)).parts
        node = nested
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        require(parts[-1] not in node and row['git_mode'] in ('100644', '100755'), 'tree collision/mode')
        node[parts[-1]] = (row['git_mode'], row['git_blob'])
    def finish(node):
        rows = []
        for name, value in node.items():
            mode, sha = ('40000', finish(value)) if isinstance(value, dict) else value
            rows.append((name, mode, sha))
        raw = b''.join(mode.encode() + b' ' + name.encode() + b'\0' + bytes.fromhex(sha)
                       for name, mode, sha in sorted(rows, key=lambda x: (x[0] + ('/' if x[1] == '40000' else '')).encode()))
        return hashlib.sha1(b'tree ' + str(len(raw)).encode() + b'\0' + raw).hexdigest()
    return finish(nested)


class OriginalView(io.RawIOBase):
    """Seekable view; the only retained decoded original span is self.cache."""
    def __init__(self, rows, received):
        self.rows, self.received = rows, received
        self.pos, self.index, self.cache = 0, None, None
        self.loads = []
        self.maximum_decoded_cache_bytes = 0

    def readable(self):
        return True

    def seekable(self):
        return True

    def tell(self):
        return self.pos

    def seek(self, offset, whence=0):
        position = offset if whence == 0 else self.pos + offset if whence == 1 else SIZE + offset if whence == 2 else -1
        require(type(position) is int and 0 <= position <= SIZE, 'view seek outside complete original ZIP')
        self.pos = position
        return position

    def discard_cache(self):
        self.cache = None
        self.index = None

    def load(self, index):
        if self.index == index:
            return
        self.discard_cache()
        row = self.rows[index]
        expected = row['original_span']
        path = ROOT / 'spans' / ('span-%03d.zip' % index)
        require(stamp(path) == self.received[index]['closed_stat'], 'received span changed before decode')
        require(0 < expected['bytes'] <= SPAN, 'span exceeds frozen 128 MiB cache bound')
        cache = bytearray(expected['bytes'])
        sha, git, crc, count = hashlib.sha256(), hashlib.sha1(b'blob ' + str(len(cache)).encode() + b'\0'), 0, 0
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            require(len(members) == 1 and members[0].filename == expected['path']
                    and members[0].file_size == len(cache) and not members[0].is_dir(), 'outer span member differs')
            with archive.open(members[0]) as stream:
                while count < len(cache):
                    view = memoryview(cache)[count:min(count + BLOCK, len(cache))]
                    length = stream.readinto(view)
                    require(type(length) is int and 0 < length <= len(view), 'short decoded span')
                    sha.update(view[:length]); git.update(view[:length]); crc = zlib.crc32(view[:length], crc)
                    count += length
                    del view
                require(stream.read(1) == b'', 'span has unexpected decoded suffix')
        actual = {'bytes': count, 'sha256': sha.hexdigest(), 'git_blob': git.hexdigest(), 'crc32': '%08x' % (crc & 0xffffffff)}
        same_pin(actual, expected, 'raw span %d' % index)
        require(actual['crc32'] == expected['crc32'], 'raw span CRC differs')
        require(stamp(path) == self.received[index]['closed_stat'], 'received span changed during decode')
        self.cache, self.index = cache, index
        self.maximum_decoded_cache_bytes = max(self.maximum_decoded_cache_bytes, count)
        self.loads.append(dict(index=index, **actual))

    def read(self, length=-1):
        if length is None or length < 0:
            length = SIZE - self.pos
        require(type(length) is int and length <= SPAN, 'consumer requested more than one-span read')
        length = min(length, SIZE - self.pos)
        if length == 0:
            return b''
        chunks = []
        while length:
            index = self.pos // SPAN
            self.load(index)
            offset = self.pos - self.rows[index]['original_span']['original_ZIP_offset']
            count = min(length, len(self.cache) - offset)
            require(count > 0, 'nonprogressing span view')
            chunks.append(bytes(memoryview(self.cache)[offset:offset + count]))
            self.pos += count
            length -= count
        return chunks[0] if len(chunks) == 1 else b''.join(chunks)

    def readinto(self, target):
        raw = self.read(len(target))
        target[:len(raw)] = raw
        return len(raw)


def replace_pointer(value, parts, before, after):
    node = value
    for part in parts[:-1]:
        node = node[part]
    require(node[parts[-1]] == before, 'actual pointer preimage differs')
    node[parts[-1]] = copy.deepcopy(after)


def binding_readback(selected_raw, captures, actual_nodes, plan):
    bindings = json.loads(selected_raw('evidence/bind/JSON-BINDING-READBACK.json'))
    allow_raw = LOCAL_ALLOW.read_bytes()
    allow = json.loads(allow_raw)
    require(set(bindings) == set(allow['documents']) == set(DOCS), 'bound document set differs')
    allowed_nodes = [row for row in actual_nodes.values() if row['kind'] == 'file'
                     and row['path'].endswith('/JSON-POINTER-ALLOWLIST.json')]
    require(len(allowed_nodes) == 1, 'fixed pointer allowlist is not unique in actual retained inputs')
    same_pin(allowed_nodes[0], pin(allow_raw), 'frozen local pointer allowlist')
    proofs = {}
    for name in ('generation', 'storage', 'projection', 'full'):
        original_raw = selected_raw('evidence/bind/ORIGINAL-' + name + '.json')
        local_path = LOCAL_SCOPE / DOCS[name]
        local_raw = local_path.read_bytes()
        require(original_raw == local_raw, 'actual unbound original differs from frozen local R2: ' + name)
        expected, actual = allow['documents'][name], bindings[name]
        same_pin(pin(original_raw), actual['original'], 'original binder input')
        same_pin(actual['original'], expected['original_identity'], 'original allowed input')
        require(len(actual['changes']) == len(expected['pointers']) == {'full': 120, 'generation': 6, 'projection': 12, 'storage': 17}[name], 'pointer count differs')
        bound_raw = captures['scope/' + DOCS[name]]
        same_pin(pin(bound_raw), actual['bound'], 'actual bound input')
        bound, original = json.loads(bound_raw), json.loads(original_raw)
        require(encode(original) == original_raw and encode(bound) == bound_raw, 'original canonical JSON bytes differ')
        forward, inverse = copy.deepcopy(original), copy.deepcopy(bound)
        for frozen, row in zip(expected['pointers'], actual['changes']):
            require(all(row[key] == frozen[key] for key in ('parts', 'pointer', 'before')), 'pointer scope differs')
            replace_pointer(forward, row['parts'], row['before'], row['after'])
        for row in reversed(actual['changes']):
            replace_pointer(inverse, row['parts'], row['after'], row['before'])
        require(encode(forward) == bound_raw and encode(inverse) == original_raw, 'full byte forward/inverse differs')
        require(actual['inverse_full_bytes_exact'] is True, 'original binder did not record complete inverse')
        proofs[name] = {'actual_unbound': pin(original_raw), 'frozen_local_path': str(local_path),
                       'local_full_bytes_equal': True, 'actual_bound': pin(bound_raw),
                       'pointer_count': len(actual['changes']), 'full_byte_forward_and_inverse_equal': True}
    require(captures['scope/' + DOCS['full']] == selected_raw(PREFIX + 'PLAN.json'), 'executed plan differs from actual bound full plan')
    require(plan['source_files'] == 3180 and plan['storage']['required_free_bytes'] == 3 << 30
            and plan['budgets']['qualification_seconds'] == 180 and plan['budgets']['cleanup_seconds'] == 3, 'fixed gate boundary differs')
    return {'documents': proofs, 'total_pointer_count': 155, 'allowlist': pin(allow_raw),
            'unlisted_JSON_mutations': 0, 'actual_executed_plan_matches_bound_full_plan': True}


def observer_readback(captures, original_nodes, qualification_parts, plan):
    path = 'scope/authoring/full-qualification-r2/qualification_projection.py'
    raw = captures[path]
    local_raw = (LOCAL_SCOPE / 'authoring/full-qualification-r2/qualification_projection.py').read_bytes()
    require(raw == local_raw, 'actual serial observer control differs from frozen R2')
    same_pin(pin(raw), plan['controls']['r2:qualification_projection.py']['identity'], 'observer control pin')
    module = ast.parse(raw)
    functions = [n for n in module.body if isinstance(n, ast.FunctionDef) and n.name == 'qualify_explicit']
    require(len(functions) == 1, 'unique original qualification function required')
    body = functions[0].body
    def assignment(name):
        found = [(i, n) for i, n in enumerate(body) if isinstance(n, ast.Assign)
                 and any(isinstance(t, ast.Name) and t.id == name for t in n.targets)]
        require(len(found) == 1, 'unique original assignment required: ' + name)
        return found[0]
    ni, native = assignment('native_observer_reference')
    li, linked = assignment('linked_observer_reference')
    si, seed_time = assignment('seed_started_monotonic_ns')
    seed = [(i, n) for i, n in enumerate(body) if isinstance(n, ast.Assign)
            and isinstance(n.value, ast.Call) and isinstance(n.value.func, ast.Name)
            and n.value.func.id == 'build_seed']
    require(len(seed) == 1 and ni < li < si < seed[0][0], 'both observer references must precede seed call')
    require(isinstance(native.value, ast.Call) and isinstance(native.value.func, ast.Name)
            and native.value.func.id == 'observer_reference' and native.value.args == []
            and native.value.keywords == [], 'native observer reference call differs')
    require(isinstance(linked.value, ast.Call) and isinstance(linked.value.func, ast.Name)
            and linked.value.func.id == 'linked_observer_reference' and linked.value.args == []
            and len(linked.value.keywords) == 1 and linked.value.keywords[0].arg == 'before_B0'
            and isinstance(linked.value.keywords[0].value, ast.Constant)
            and linked.value.keywords[0].value.value is True, 'linked observer reference call differs')
    evidence = []
    for name, index in (('native', ni), ('linked', li)):
        filename = 'independent-' + name + '-observer-reference.json'
        statement = body[index + 1]
        require(isinstance(statement, ast.Expr) and isinstance(statement.value, ast.Call)
                and isinstance(statement.value.func, ast.Attribute) and statement.value.func.attr == 'write_text'
                and any(isinstance(x, ast.Constant) and x.value == filename for x in ast.walk(statement)), 'original observer write ordering differs')
        logical = PREFIX + 'qualification.evidence/' + filename
        actual = json.loads(captures[logical])
        require(actual == qualification_parts[name + '_observer_reference'], 'independent observer receipt differs from final full report')
        require(actual['before_B0'] is True and actual['every_output_byte_compared'] is True, 'observer reference incomplete')
        if name == 'linked':
            require(actual['before_native_compilation'] is True, 'linked observer was not before compilation')
        evidence.append({'kind': name, 'actual_reference': {key: original_nodes[logical][key] for key in PIN_FIELDS},
                         'full_original_report_same_reference': True, 'before_B0_flag': True,
                         'serial_call_and_complete_write_precede_seed_start': True,
                         'statement_ordinal': index, 'seed_start_statement_ordinal': si,
                         'separate_completion_monotonic_timestamp_present': 'completed_monotonic_ns' in actual})
    return {'observer_reference_count': 2, 'both_complete_before_B0_by_actual_serial_producer_order': True,
            'control_identity': pin(raw), 'references': evidence,
            'timing_limit': 'These two observer references do not carry separate completion timestamps; ordering follows their complete retained receipts, identical final report values, and the frozen serial producer that completed and wrote both before recording seed start. The 17 fresh workers separately carry completion timestamps.'}


def frame_readback(frame_index, captures, actual_nodes, prefixes, generation_rows):
    rows = frame_index['rows']
    require(frame_index['after_frames_synthesized'] is False, 'frame index admits synthesized after images')
    require(len({r['label'] for r in rows}) == len(rows), 'duplicate frame labels')
    proofs = []
    generations = {r['case']: r for r in generation_rows}
    require(set(generations) == {'B1', 'B2', 'B3', 'M1', 'M2', 'M3'}, 'generation observation inventory differs')
    for row in rows:
        label, directory = row['label'], logical_path(row['path'])
        files = row['files']
        for name, expected in files.items():
            actual = actual_nodes[directory + '/' + safe_name(name)]
            same_pin(actual, expected, label + '/' + name)
            require(actual['mode'] == expected['mode'], 'actual frame logical mode differs')
        names = {x + '.' + phase + '.bin' for x in ('source', 'output', 'workspace') for phase in ('before', 'after')}
        names.update(('before.json', 'after.json'))
        complete = names.issubset(files)
        require(row['complete_actual_six_frames'] is complete, 'frame index completeness differs from actual bytes')
        proof = {'label': label, 'directory': directory, 'file_count': len(files),
                 'all_actual_file_bytes_hashes_modes_match': True, 'complete_actual_six_frames': complete}
        if complete:
            before = json.loads(captures[directory + '/before.json'])
            after = json.loads(captures[directory + '/after.json'])
            parent = str(PurePosixPath(directory).parent)
            request = json.loads(captures[parent + '/' + label + '.request.json'])
            receipt = json.loads(captures[parent + '/' + label + '.receipt.json'])
            require(before['schema'] == after['schema'] == 'hepta.selfhost-seed-loader-actual-frames.v1', 'frame schema differs')
            require(before['phase'] == 'before' and after['phase'] == 'after', 'frame phase differs')
            require(type(before['child_pid']) is int and before['child_pid'] > 0
                    and before['child_pid'] == after['child_pid'], 'actual frame child identity differs')
            require(before['request'] == after['request'] == request, 'frame/request identity differs')
            require(before['result_u64'] is None and before['native_elapsed_ns'] is None, 'before frame contains a manufactured result')
            require(after['result_u64'] == receipt['result_u64']
                    and after['native_elapsed_ns'] == receipt['native_elapsed_ns'], 'actual after frame differs from native receipt')
            require(receipt['status'] == 'returned' and receipt['core_u32'] == receipt['result_u64'] & 0xffffffff
                    and receipt['abi_status'] == receipt['result_u64'] >> 32, 'actual result encoding differs')
            for phase, captured in (('before', before), ('after', after)):
                require(set(captured['frames']) == {'source', 'output', 'workspace'}, 'frame region inventory differs')
                for region, observed in captured['frames'].items():
                    actual = actual_nodes[directory + '/' + region + '.' + phase + '.bin']
                    require(observed == {key: actual[key] for key in ('bytes', 'sha256')}, 'actual complete region differs from frame observation')
            source_before = actual_nodes[directory + '/source.before.bin']
            source_after = actual_nodes[directory + '/source.after.bin']
            source_input = actual_nodes[logical_path(request['source'])]
            same_pin(source_before, source_input, label + ' source request')
            require(source_before['sha256'] == request['source_sha256'] == receipt['source_sha256'], 'actual source hash differs')
            require(receipt['source_unchanged'] is (source_before['sha256'] == source_after['sha256']), 'source unchanged observation differs')
            image = actual_nodes[logical_path(request['image'])]
            require(image['sha256'] == request['image_sha256'] == receipt['image_sha256'], 'actual called image differs')
            output_before = actual_nodes[directory + '/output.before.bin']
            output_after = actual_nodes[directory + '/output.after.bin']
            same_pin(output_after, actual_nodes[logical_path(request['output'])], label + ' captured output file')
            require(output_after['sha256'] == receipt['output_sha256'] and output_after['bytes'] == request['capacity'], 'actual output differs')
            require(output_before['bytes'] == request['capacity'], 'actual output before extent differs')
            require(receipt['output_unchanged'] is (output_before['sha256'] == output_after['sha256']), 'output unchanged observation differs')
            workspace_before = actual_nodes[directory + '/workspace.before.bin']
            workspace_after = actual_nodes[directory + '/workspace.after.bin']
            require(workspace_before['bytes'] == workspace_after['bytes'] == request['workspace_size'], 'workspace extent differs')
            require(0 <= request['workspace_size'] <= BLOCK and 0 <= request['capacity'] <= BLOCK, 'original buffer bound differs')
            initial_output = bytes.fromhex(request['output_initial_hex']) if 'output_initial_hex' in request else bytes([0xa5]) * request['capacity']
            require(hashlib.sha256(initial_output).hexdigest() == output_before['sha256'], 'actual original output initialization differs')
            initial_workspace = bytes([request.get('workspace_fill', 0)]) * request['workspace_size']
            require(hashlib.sha256(initial_workspace).hexdigest() == workspace_before['sha256'], 'actual original workspace initialization differs')
            header = prefixes[directory + '/workspace.after.bin']['raw_prefix']
            for at, value in receipt['workspace_header'].items():
                offset = int(at)
                require(str(offset) == at and 0 <= offset and offset + 8 <= len(header)
                        and int.from_bytes(header[offset:offset + 8], 'little') == value, 'actual workspace header differs')
            proof.update(child_pid=before['child_pid'], request_and_receipt_bound=True,
                         complete_before_after_regions_bound=True, workspace_header_bound=True,
                         original_initialization_bound=True, result_u64=after['result_u64'],
                         native_elapsed_ns=after['native_elapsed_ns'])
            if label in generations:
                generation = generations[label]
                require(receipt == generation, 'generation receipt differs from original final report')
                actual_image = actual_nodes[logical_path(generation['produced_image'])]
                require(actual_image['bytes'] == generation['produced_bytes']
                        and actual_image['sha256'] == generation['produced_sha256'], 'produced image differs')
                same_pin(prefixes[directory + '/output.after.bin']['image_prefix'], actual_image, label + ' actual output prefix/image')
                proof['complete_image_equals_actual_output_prefix'] = True
                proof['produced_image'] = {key: actual_image[key] for key in PIN_FIELDS}
        else:
            proof['interpretation'] = 'Exact original partial observation retained; no missing after frames synthesized.'
        proofs.append(proof)
    require(all(next(r for r in proofs if r['label'] == name)['complete_actual_six_frames'] for name in generations), 'one of the six generations has partial frames')
    return {'rows': proofs, 'observation_count': len(rows),
            'complete_actual_six_frame_observations': sum(r['complete_actual_six_frames'] for r in proofs),
            'partial_observations_preserved': sum(not r['complete_actual_six_frames'] for r in proofs),
            'all_six_B_and_M_generation_frames_and_images_verified': True,
            'no_VM_or_native_reexecution': True}


def main():
    started_ns = time.time_ns()
    receive_plan_raw = (ROOT / 'SPAN-RECEIVE-PLAN.json').read_bytes()
    receive_plan = json.loads(receive_plan_raw)
    require(receive_plan['original_artifact']['bytes'] == SIZE
            and receive_plan['original_artifact']['sha256'] == ORIGINAL_SHA
            and len(receive_plan['spans']) == 10, 'receive plan identity differs')
    rows = receive_plan['spans']
    received = [json.loads((ROOT / 'spans' / ('span-%03d.RESULT.json' % i)).read_bytes()) for i in range(10)]
    for index, (row, record) in enumerate(zip(rows, received)):
        require(row['index'] == index and record['index'] == index and record['artifact'] == row, 'received artifact binding differs')
        require(record['status'] == 'OUTER_ZIP_SHA_AND_COMPLETE_RAW_SPAN_SHA_GIT_CRC_PASS', 'span receipt is incomplete')
        require(record['received_bytes'] == row['outer_zip_bytes']
                and record['outer_zip_sha256'] == row['outer_zip_sha256'], 'outer span identity differs')
        require(stamp(ROOT / 'spans' / ('span-%03d.zip' % index)) == record['closed_stat'], 'closed received span changed')
        require(row['original_span']['original_ZIP_offset'] == index * SPAN
                and row['original_span']['bytes'] == min(SPAN, SIZE - index * SPAN), 'original span coverage differs')
    free = os.statvfs(ROOT).f_bavail * os.statvfs(ROOT).f_frsize
    require(free >= SPAN + (16 << 20), 'less than single cache plus frozen metadata reserve')
    write_new('COMPLETE-ORIGINAL-ZIP-INTENT.json', {
        'schema': 'hepta.u32.original-span-complete-readback-intent.v1', 'started_ns': started_ns,
        'original_artifact': receive_plan['original_artifact'], 'receive_plan': pin(receive_plan_raw),
        'received_spans': 10, 'remaining_network_bytes': 0, 'decoded_cache_limit': SPAN,
        'metadata_reserve_bytes': 16 << 20, 'actual_free_bytes': free,
        'product_executions': 0, 'network_requests': 0, 'automatic_retries': 0,
        'flat_original_ZIP_written': False, 'second_source_tree_written': False,
        'verifier': pin(Path(__file__).read_bytes())})
    reports_path = ROOT / 'reports.zip'
    reports_before = stamp(reports_path)
    require(reports_before['st_size'] == 6019201 and hashlib.sha256(reports_path.read_bytes()).hexdigest() == REPORTS_SHA, 'reports ZIP changed')
    existing_proof_raw = (ROOT / 'ORIGINAL-REPORTS-INDEPENDENT-READBACK.json').read_bytes()
    existing_proof = json.loads(existing_proof_raw)
    require(existing_proof['status'] == 'FULL_ORIGINAL_REPORTS_5052_38_17_OWNER_AND_SOURCE_MANIFESTS_VERIFIED', 'original report proof is not complete')
    reports_manifest = json.loads((ROOT / 'REPORTS-ZIP-MANIFEST.json').read_bytes())
    report_pins = {r['path']: r for r in reports_manifest['members']}
    with zipfile.ZipFile(reports_path) as reports:
        def report_raw(name):
            raw = reports.read(name)
            same_pin(pin(raw), report_pins[name], 'retained report ' + name)
            return raw
        selected = json.loads(report_raw('SELECTED-ORIGINALS.json'))
        selected_rows = {r['logical_path']: r for r in selected['reports']}
        require(len(selected_rows) == len(selected['reports']) == 98, 'selected originals differ')
        def selected_raw(logical):
            raw = report_raw(selected_rows[logical]['output'])
            same_pin(pin(raw), selected_rows[logical]['record'], logical)
            return raw
        node_raw = report_raw('original/NODE-MANIFEST.json')
        same_pin(pin(node_raw), selected['manifest_identity'], 'NODE manifest')
        node_list = json.loads(node_raw)
        nodes = {r['path']: r for r in node_list}
        require(len(nodes) == len(node_list) == 11421, 'logical NODE inventory differs')
        for name in nodes:
            safe_name(name)
        advertised_rows = json.loads(report_raw('ZIP-MEMBERS.json'))
        advertised = {r['path']: r for r in advertised_rows}
        require(len(advertised) == len(advertised_rows) == 4945, 'original ZIP inventory differs')
        transport = json.loads(report_raw('TRANSPORT.json'))
        require(transport['original_bytes'] == SIZE and transport['original_sha256'] == ORIGINAL_SHA
                and transport['original_git_blob'] == ORIGINAL_GIT, 'producer original ZIP identity differs')
        plan = json.loads(selected_raw(PREFIX + 'PLAN.json'))
        source_before = json.loads(selected_raw(PREFIX + 'SOURCE-BEFORE.json'))
        frame_index = json.loads(selected_raw(PREFIX + 'LOADER-FRAMES-AFTER.json'))
        qualification = json.loads(selected_raw(PREFIX + 'qualification.json'))
        qparts = {key: qualification[key] for key in ('generations', 'modified_generations',
            'native_observer_reference', 'linked_observer_reference', 'qualification_scheduling')}
        require(len(qualification['checks']) == 5052 and all(type(v) is bool and v for v in qualification['checks'].values()), 'full original check result differs')
        del qualification
        gc.collect()
        generation_rows = qparts['generations'] + qparts['modified_generations']
        generation_by_label = {r['case']: r for r in generation_rows}
        captures_needed = {'scope/' + path for path in DOCS.values()}
        captures_needed.add('scope/authoring/full-qualification-r2/qualification_projection.py')
        for kind in ('native', 'linked'):
            captures_needed.add(PREFIX + 'qualification.evidence/independent-' + kind + '-observer-reference.json')
        prefix_lengths = {}
        for row in frame_index['rows']:
            directory = logical_path(row['path'])
            label = row['label']
            require(PurePosixPath(directory).name == label + '.output.bin.full-frames', 'actual frame directory naming differs')
            parent = str(PurePosixPath(directory).parent)
            for name in ('before.json', 'after.json'):
                if name in row['files']:
                    captures_needed.add(directory + '/' + name)
            for suffix in ('.request.json', '.receipt.json'):
                if parent + '/' + label + suffix in nodes:
                    captures_needed.add(parent + '/' + label + suffix)
            if 'workspace.after.bin' in row['files']:
                prefix_lengths[directory + '/workspace.after.bin'] = (1032, False)
            if label in generation_by_label:
                prefix_lengths[directory + '/output.after.bin'] = (generation_by_label[label]['produced_bytes'], True)
        require(all(name in nodes and nodes[name]['kind'] == 'file' for name in captures_needed), 'required original observation file missing')
        require(sum(nodes[name]['bytes'] for name in captures_needed) <= 64 << 20, 'metadata capture bound exceeded')
        literal_comparisons = {r['ZIP_member']: r['output'] for r in selected['reports']}
        literal_comparisons[selected['manifest_member']] = 'original/NODE-MANIFEST.json'
        require(len(literal_comparisons) == 99, 'literal original report comparison set differs')
        original_view = OriginalView(rows, received)
        sha, git, crc, count = hashlib.sha256(), hashlib.sha1(b'blob ' + str(SIZE).encode() + b'\0'), 0, 0
        while count < SIZE:
            raw = original_view.read(min(BLOCK, SIZE - count))
            require(raw, 'short original concatenation')
            sha.update(raw); git.update(raw); crc = zlib.crc32(raw, crc); count += len(raw)
        require(count == SIZE and sha.hexdigest() == ORIGINAL_SHA and git.hexdigest() == ORIGINAL_GIT, 'complete concatenated original ZIP differs')
        concat = {'bytes': count, 'sha256': sha.hexdigest(), 'git_blob': git.hexdigest(), 'crc32': '%08x' % (crc & 0xffffffff)}
        concat_record = write_new('ORIGINAL-CONCATENATION-READBACK.json', dict(status='COMPLETE_ORIGINAL_ZIP_ALL_BYTES_PASS', **concat))
        print(json.dumps({'stage': 'original-concatenation', 'bytes': count, 'sha256': sha.hexdigest()}), flush=True)
        actual_members, captures, prefixes = {}, {}, {}
        storage_to_logical = {r['storage_path']: r['path'] for r in node_list if r['kind'] == 'file'}
        require(len(storage_to_logical) == 4941, 'ordinary logical file inventory differs')
        compared = []
        with (ROOT / 'ACTUAL-ORIGINAL-MEMBER-STREAM.jsonl').open('xb') as journal:
            with zipfile.ZipFile(original_view) as archive:
                infos = archive.infolist()
                require(len(infos) == len({i.filename for i in infos}) == 4945
                        and {i.filename for i in infos} == set(advertised), 'complete original ZIP member set differs')
                central_ordinals = {i.filename: n for n, i in enumerate(infos)}
                for sequence, info in enumerate(sorted(infos, key=lambda i: i.header_offset)):
                    safe_name(info.filename)
                    logical = storage_to_logical.get(info.filename.removeprefix('retained/')) if info.filename.startswith('retained/') else None
                    expected = advertised[info.filename]
                    require(info.file_size == expected['bytes'] and info.compress_size == expected['compressed_bytes']
                            and info.compress_type == expected['compression'] and info.external_attr == expected['external_attr']
                            and info.create_system == expected['create_system'] and list(info.date_time) == expected['date_time']
                            and info.flag_bits == expected['flag_bits'] and info.is_dir() is expected['is_directory']
                            and '%08x' % info.CRC == expected['crc32'], 'actual ZIP metadata differs: ' + info.filename)
                    sha, git, crc, count = hashlib.sha256(), hashlib.sha1(b'blob ' + str(info.file_size).encode() + b'\0'), 0, 0
                    capture = bytearray() if logical in captures_needed else None
                    prefix_spec = prefix_lengths.get(logical)
                    prefix_raw = bytearray() if prefix_spec and not prefix_spec[1] else None
                    image_sha = hashlib.sha256() if prefix_spec and prefix_spec[1] else None
                    image_git = hashlib.sha1(b'blob ' + str(prefix_spec[0]).encode() + b'\0') if image_sha is not None else None
                    comparison = reports.open(literal_comparisons[info.filename]) if info.filename in literal_comparisons else None
                    try:
                        with archive.open(info) as stream:
                            while True:
                                raw = stream.read(BLOCK)
                                if not raw:
                                    break
                                require(count + len(raw) <= info.file_size, 'member exceeded original extent')
                                sha.update(raw); git.update(raw); crc = zlib.crc32(raw, crc)
                                if capture is not None:
                                    require(len(capture) + len(raw) <= 16 << 20, 'single metadata capture exceeded bound')
                                    capture.extend(raw)
                                if prefix_spec and count < prefix_spec[0]:
                                    part = raw[:min(len(raw), prefix_spec[0] - count)]
                                    if image_sha is not None:
                                        image_sha.update(part); image_git.update(part)
                                    else:
                                        prefix_raw.extend(part)
                                if comparison is not None:
                                    require(comparison.read(len(raw)) == raw, 'literal original selected report bytes differ')
                                count += len(raw)
                        require(count == info.file_size and crc & 0xffffffff == info.CRC, 'complete member CRC/length differs')
                        if comparison is not None:
                            require(comparison.read(1) == b'', 'selected report has a suffix absent from original')
                            compared.append(info.filename)
                    finally:
                        if comparison is not None:
                            comparison.close()
                    item = dict(path=info.filename, bytes=count, sha256=sha.hexdigest(), git_blob=git.hexdigest(),
                                crc32='%08x' % (crc & 0xffffffff), compressed_bytes=info.compress_size,
                                compression=info.compress_type, external_attr=info.external_attr,
                                create_system=info.create_system, date_time=list(info.date_time),
                                flag_bits=info.flag_bits, is_directory=info.is_dir(),
                                ordinal=central_ordinals[info.filename], header_offset=info.header_offset,
                                stream_ordinal=sequence, ZIP_wrapper_mode=(info.external_attr >> 16) & 0xffff)
                    same_pin(item, expected, info.filename)
                    require(item['ordinal'] == expected['ordinal'], 'original central member order differs')
                    actual_members[info.filename] = item
                    if capture is not None:
                        captures[logical] = bytes(capture)
                    if prefix_spec:
                        if image_sha is not None:
                            require(info.file_size >= prefix_spec[0], 'produced image prefix exceeds captured output')
                            prefixes[logical] = {'image_prefix': {'bytes': prefix_spec[0], 'sha256': image_sha.hexdigest(), 'git_blob': image_git.hexdigest()}}
                        else:
                            prefixes[logical] = {'raw_prefix': bytes(prefix_raw)}
                    journal.write((json.dumps(item, sort_keys=True, separators=(',', ':')) + '\n').encode())
                    if sequence % 500 == 0:
                        journal.flush()
                        print(json.dumps({'stage': 'original-members', 'verified': sequence + 1, 'total': 4945}), flush=True)
            journal.flush(); os.fsync(journal.fileno())
        original_view.discard_cache()
        require(set(compared) == set(literal_comparisons) and len(compared) == 99, 'literal report comparison coverage differs')
        require(set(captures) == captures_needed, 'metadata capture inventory differs')
        actual_nodes = {}
        node_counts = collections.Counter()
        regular_modes = collections.Counter()
        for row in node_list:
            kind, logical = row['kind'], row['path']
            node_counts[kind] += 1
            if 'stat_before' in row:
                require(stat.S_IMODE(row['stat_before']['st_mode']) == row['mode'], 'original logical mode differs')
            if kind == 'file':
                member = 'retained/' + row['storage_path']
                actual = actual_members[member]
                same_pin(actual, row, logical)
                require(row['mode'] == stat.S_IMODE(row['stat_after']['st_mode'])
                        and stat.S_ISREG(row['stat_before']['st_mode']) and stat.S_ISREG(row['stat_after']['st_mode']), 'original file kind/mode differs')
                actual_nodes[logical] = dict(row)
                regular_modes[format(row['mode'], '04o')] += 1
            elif kind == 'directory':
                require(stat.S_ISDIR(row['stat_before']['st_mode']), 'original directory kind differs')
            elif kind == 'symlink':
                target = base64.b64decode(row['target_base64'], validate=True)
                require(stat.S_ISLNK(row['stat_before']['st_mode'])
                        and hashlib.sha256(target).hexdigest() == row['target_sha256'], 'original link metadata differs')
            else:
                require(kind in ('external-original-Actions-ZIP', 'excluded-checkout-metadata', 'absent', 'nonregular-node-metadata'), 'unknown original logical node kind')
        require(node_counts['file'] == 4941, 'logical ordinary file count differs')
        actual_sources = {}
        source_nodes = {name[len(SOURCE_PREFIX):]: row for name, row in actual_nodes.items() if name.startswith(SOURCE_PREFIX)}
        require(set(source_nodes) == set(source_before) and len(source_nodes) == 3180, 'complete actual source inventory differs')
        for name, node in source_nodes.items():
            expected = source_before[name]
            same_pin(node, expected, 'actual source ' + name)
            require(node['mode'] == expected['mode'], 'actual source mode differs')
            mode = '100755' if node['mode'] & 0o111 else '100644'
            require(mode == expected['git_mode'], 'source Git mode differs')
            actual_sources[name] = dict(expected)
        actual_tree = tree_id(actual_sources)
        require(actual_tree == plan['source_tree'] == '4c62be4ed66ff107fa6f88c6131313a354868bd9', 'actual source tree differs')
        source_record = write_new('ACTUAL-3180-SOURCE-MANIFEST.json', actual_sources)
        bindings = binding_readback(selected_raw, captures, actual_nodes, plan)
        binding_record = write_new('ACTUAL-PLAN-BINDING-READBACK.json', bindings)
        observers = observer_readback(captures, actual_nodes, qparts, plan)
        observer_record = write_new('ACTUAL-OBSERVER-REFERENCE-READBACK.json', observers)
        frames = frame_readback(frame_index, captures, actual_nodes, prefixes, generation_rows)
        frame_record = write_new('ACTUAL-FRAME-READBACK.json', frames)
        member_record = write_new('ACTUAL-ORIGINAL-ZIP-MANIFEST.json', [actual_members[r['path']] for r in advertised_rows])
        for index, record in enumerate(received):
            require(stamp(ROOT / 'spans' / ('span-%03d.zip' % index)) == record['closed_stat'], 'span changed before finalization')
        require(stamp(reports_path) == reports_before, 'reports input changed before finalization')
        result = {
            'schema': 'hepta.u32.complete-original-ZIP-span-readback.v1',
            'status': 'ALL_ORIGINAL_BYTES_4945_MEMBERS_3180_SOURCE_AND_ACTUAL_FRAMES_VERIFIED',
            'started_ns': started_ns, 'ended_ns': time.time_ns(),
            'original_run': 43579403463, 'original_job': 132400693130,
            'original_head': 'de4afa1f7f4cb1fc2d5284965f7f2a7c55632d2a',
            'original_artifact_id': 14108215158, 'custody_run': 43582958164,
            'original_zip': concat, 'reports_zip_sha256': REPORTS_SHA,
            'all_10_received_wrappers_full_SHA_previously_verified_and_stats_unchanged': True,
            'outer_zip_total_bytes': sum(r['outer_zip_bytes'] for r in rows),
            'single_decoded_cache_maximum_bytes': original_view.maximum_decoded_cache_bytes,
            'decoded_span_loads': original_view.loads,
            'complete_original_members': len(actual_members),
            'complete_member_logical_bytes': sum(r['bytes'] for r in actual_members.values()),
            'logical_node_counts': dict(node_counts), 'actual_regular_file_modes': dict(regular_modes),
            'mode_authority': 'Original NODE-MANIFEST mode/stat records; ZIP wrapper permissions are independently recorded and never substituted.',
            'all_98_selected_reports_plus_NODE_manifest_literal_bytes_equal': True,
            'source_files': 3180, 'actual_source_tree': actual_tree,
            'checks': 5052, 'phases': 38, 'fresh_reference_processes': 17,
            'additional_observer_references_before_B0': observers,
            'actual_plan_binding': bindings,
            'frame_observations': frames['observation_count'],
            'complete_actual_six_frame_observations': frames['complete_actual_six_frame_observations'],
            'partial_frame_observations_preserved': frames['partial_observations_preserved'],
            'all_six_generation_images_match_actual_complete_output_prefixes': True,
            'readback_records': [concat_record, source_record, binding_record, observer_record, frame_record, member_record],
            'prior_complete_original_report_proof': pin(existing_proof_raw),
            'network_requests': 0, 'product_executions': 0, 'automatic_retries': 0,
            'flat_original_ZIP_written': False, 'second_source_tree_written': False,
            'whole': False, 'matching_current_new_cold': False,
            'ordinary_encoding_and_entry_layout_gates': 'NOT_RUN',
            'nested_phase_archives': 'Complete original archive files were read and hash/CRC verified as original ZIP members; this reader does not reexecute phases or claim a second inner-archive restore.',
            'binary_durability': 'All 11 relay artifact ZIPs are retained locally and in the actual Actions relay run; no claim that their complete binary bytes have been republished as Git blobs.',
        }
        final_record = write_new('COMPLETE-ORIGINAL-ZIP-READBACK.json', result)
        print(json.dumps({'status': result['status'], 'record': final_record,
                          'source_tree': actual_tree, 'frames': frames['observation_count'],
                          'elapsed_seconds': (result['ended_ns'] - started_ns) / 1e9}), flush=True)


if __name__ == '__main__':
    try:
        main()
    except BaseException as exc:
        failure = {'status': 'CUSTODY_READBACK_FAILED_NO_PRODUCT_RETRY', 'ended_ns': time.time_ns(),
                   'exception_type': type(exc).__name__, 'error': str(exc),
                   'traceback': traceback.format_exc(), 'product_executions': 0,
                   'original_inputs_and_partial_records_retained': True}
        write_new('COMPLETE-ORIGINAL-ZIP-FAIL.json', failure)
        raise

