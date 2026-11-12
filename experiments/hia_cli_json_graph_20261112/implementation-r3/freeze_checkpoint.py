"""Freeze the new isolated source and source-only request, never execute it."""
from hashlib import sha1, sha256
import base64
import json
from pathlib import Path

HERE = Path(__file__).absolute().parent
ROOT = HERE.parent
PREFIX = 'experiments/hia_cli_json_graph_20261112/implementation-r3'


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2) + '\n').encode()


def record(path, relative):
    raw = path.read_bytes()
    return {'path': relative, 'local_path': str(path), 'mode': '100644',
            'type': 'blob', 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'sha': sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).hexdigest(),
            'content_base64': base64.b64encode(raw).decode()}


def main():
    status = {
        'schema': 'hia.cli-json.r3.concrete-source-checkpoint.v1',
        'status': 'STATIC_SOURCE_AND_SOURCE_ONLY_REQUEST_FROZEN_NOT_EXECUTED',
        'parent_checkpoint': '7ffea7cd6bb7334d6e5544a1ffbe7b1a15c46511',
        'previous_r2_qualification': 'STATIC_INCOMPLETE; no authoring, C or HIA native execution',
        'new_code': [
            '19 direct compare-error guards; merge_lo/hi copy the remaining temporary tail before failure',
            'actual list detach/restore raw-array owner retained; no PyList_Sort or Python sorted fallback',
            'entry result corrected to u32 in HIA and native callable declaration',
            'versioned note HIA follows _PyErr_FormatNote and BaseException_add_note directly',
            'raw context owns individual note/error cells; atomic transfers publish ownership before return',
            '3.14 C-graph HIA controls classification, markers, current-size loops, actual item sorting, layout and cleanup',
            '3.14.10 item references are owned across callbacks; 3.14.4 keeps its original borrowed policy',
            'output and frame growth retry continuations do not replay already emitted separators',
            'wrong-type string encoder result is released before its caller releases keystr',
        ],
        'new_source_request': {
            'local': str(ROOT / 'source-authoring-r1/PREEXEC.json'),
            'components': ['text', 'sort', 'note', 'cgraph'],
            'new_owner_seconds': 180, 'cleanup_seconds': 3,
            'scope': 'Syntax, actual HIA authoring, public Core assembly round trip, listed original structural compiler caps',
            'run_status': 'NOT_EXECUTED', 'C_compilation': False, 'native_product': False,
            'original_17_cli_methods_executed': False, '46_trace_plan_executed': False,
        },
        'unchanged': ['original 17 caller IDs', 'explicit 46 trace IDs',
                      'default CLI selection', 'root v88/v89 product source', 'all old UNKNOWN operations'],
        'remaining_product_obligations': [
            'No generated or compiled source is claimed by this checkpoint.',
            'Raw graph transport and nested HIA component transport are not yet complete.',
            'Public dumps/encoder/print binding and Python 3.12 traversal remain to be implemented; they are not excluded input domains.',
            'Original runtime integer early-limit checks/_pylong behavior and late diagnostic ordering remain open.',
            'CPython indentation-cache/writer allocation, GC and signal schedules still require precise restoration and actual trace controls.',
            'Original immortal constant-key string identity and public input-binding/refcount sequence require admission controls.',
            'Private note-session external-abort ownership and asynchronous failure traces remain unqualified.',
            'Full finite/foreign traces must execute on each actual supported runtime before any compatibility claim.',
        ],
        'retained_original_cp_source': 'Pinned errors.c/exceptions.c for 3.14.4 and 3.14.10; actual note call does not dynamically invoke exception.add_note',
        'old_078d_operation': 'UNKNOWN retained; never queried, reconciled, resumed or replayed',
    }
    status_path = HERE / 'STATUS.json'
    with status_path.open('xb') as stream:
        stream.write(wire(status))
    files = []
    for path in sorted((HERE / 'inputs').rglob('*')):
        if path.is_file():
            files.append(record(path, PREFIX + '/inputs/' + path.relative_to(HERE / 'inputs').as_posix()))
    for name in ('source_authoring_worker.py', 'prepare_source_request.py', 'freeze_checkpoint.py', 'SORT-COMPARE-ERROR-DELTA.json', 'STATUS.json'):
        files.append(record(HERE / name, PREFIX + '/' + name))
    request_root = ROOT / 'source-authoring-r1'
    for path in sorted(request_root.rglob('*')):
        if path.is_file():
            files.append(record(path, PREFIX + '/source-only-request-r1/' + path.relative_to(request_root).as_posix()))
    for version in ('3.14.4', '3.14.10'):
        for name in ('errors.c', 'exceptions.c'):
            path = ROOT / ('reference/cpython-v' + version) / name
            files.append(record(path, PREFIX + '/reference/cpython-v' + version + '/' + name))
    packet = {'schema': 'hia.cli-json.r3.publication-inputs.v1',
              'parent': status['parent_checkpoint'], 'files': files}
    destination = HERE / 'PUBLICATION-PACKET.json'
    with destination.open('xb') as stream:
        stream.write(wire(packet))
    print(json.dumps({'packet': str(destination), 'files': len(files),
                      'bytes': sum(row['bytes'] for row in files),
                      'packet_bytes': destination.stat().st_size,
                      'status': status['status']}, sort_keys=True))


if __name__ == '__main__':
    main()
