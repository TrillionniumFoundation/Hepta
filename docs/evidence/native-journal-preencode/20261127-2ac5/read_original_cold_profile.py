"""Read retained failed-cold journals; never execute or admit a cold product."""
from pathlib import Path
from hashlib import sha256
from collections import Counter, defaultdict
import json, mmap, struct, sys, time

ROOT = Path(sys.argv[1]).resolve()
OUT = ROOT / 'cold-journal-profile-v1.json'
SOURCE = ROOT / 'source'
QUAL = ROOT / 'cold-data-v1/cold/qualification'
NAMES = ('reference-signed', 'reference-capacity', 'reference-scalar-casts',
         'reference-keyword', 'base', 'original-signed', 'modified-signed',
         'original-scalar-casts', 'modified-scalar-casts')


def digest(raw):
    return sha256(raw).hexdigest()


def decode(raw):
    magic, size, payload, mode = struct.unpack_from('<8s3Q', raw)
    assert magic in (b'HIAQAZ01', b'HIAQAZ02')
    assert 0 < size <= 65504 and payload == len(raw) - 32
    assert mode <= (1 if magic == b'HIAQAZ01' else 2)
    if mode == 0:
        assert payload == size
        return raw[32:]
    pos = 32
    out = bytearray()
    while pos < len(raw):
        if mode == 1:
            assert len(raw) - pos >= 8
            token, = struct.unpack_from('<Q', raw, pos)
            pos += 8
            amount = token >> 1
            assert amount
            if token & 1:
                assert len(raw) - pos >= 8 and amount <= (size - len(out)) // 8
                out.extend(raw[pos:pos + 8] * amount)
                pos += 8
            else:
                assert amount <= len(raw) - pos and amount <= size - len(out)
                out.extend(raw[pos:pos + amount])
                pos += amount
        else:
            assert len(raw) - pos >= 3
            token, amount = struct.unpack_from('<BH', raw, pos)
            pos += 3
            assert amount
            if token == 0:
                assert amount <= len(raw) - pos and amount <= size - len(out)
                out.extend(raw[pos:pos + amount])
                pos += amount
            else:
                assert token == 1 and amount >= 8 and len(raw) - pos >= 2
                distance, = struct.unpack_from('<H', raw, pos)
                pos += 2
                assert 0 < distance <= len(out) and amount <= size - len(out)
                pattern = bytes(out[-distance:])
                out.extend((pattern * ((amount + distance - 1) // distance))[:amount])
    assert pos == len(raw) and len(out) == size
    return out


def plan_rows(raw):
    assert raw[:8] == b'HIAQPL01'
    count, zero1, zero2 = struct.unpack_from('<3Q', raw, 8)
    assert zero1 == zero2 == 0
    pos = 32
    rows = []
    for _ in range(count):
        op, ident, argc, size = struct.unpack_from('<4Q', raw, pos)
        pos += 32
        args = struct.unpack_from('<' + 'Q' * argc, raw, pos)
        pos += 8 * argc
        payload = raw[pos:pos + size]
        pos += size
        rows.append((op, ident, args, payload))
    assert pos == len(raw)
    return rows


def profile(name):
    path = QUAL / name / 'evidence.hiaqj'
    plan = SOURCE / 'examples/hia_bootstrap/cold_plans' / (name + '.hiacases')
    raw_plan = plan.read_bytes()
    expected = plan_rows(raw_plan)
    labels_path = plan.with_suffix('.json')
    labels = json.loads(labels_path.read_text()) if labels_path.exists() else []
    row = dict(phase=name, source_plan_sha256=digest(raw_plan), expected_nodes=len(expected),
               path=str(path.relative_to(ROOT)), complete=False, record_failures=[],
               decode_profile='independent bounded HIAQAZ01/02 plus exact physical backward references')
    handles = {}
    chunks = Counter()
    operations = Counter()
    tools = defaultdict(lambda: dict(calls=0, elapsed_ns=0, max_ns=0))
    slow = []
    record_bytes = Counter()
    logical = bytearray()
    node = 0
    boundary = {}
    with path.open('rb') as handle:
        with mmap.mmap(handle.fileno(), 0, access=mmap.ACCESS_READ) as raw:
            row.update(journal_bytes=len(raw), journal_sha256=digest(raw))
            cursor = 0
            while cursor < len(raw):
                if len(raw) - cursor < 32:
                    row['truncated_physical_tail_bytes'] = len(raw) - cursor
                    break
                magic, size, payload, mode = struct.unpack_from('<8s3Q', raw, cursor)
                assert magic in (b'HIAQAZ01', b'HIAQAZ02', b'HIAQAZ03'), (name, cursor, magic)
                assert 0 < size <= 65504 and payload <= 65504
                end = cursor + 32 + payload
                if end > len(raw):
                    row['truncated_physical_tail_bytes'] = len(raw) - cursor
                    break
                if magic == b'HIAQAZ03':
                    assert payload == 8 and mode == 3
                    previous, = struct.unpack_from('<Q', raw, cursor + 32)
                    assert previous in boundary and previous < cursor
                    previous_end, previous_size = boundary[previous]
                    assert previous_end <= cursor and previous_size == size
                    decoded = decode(raw[previous:previous_end])
                    chunks['backref'] += 1
                else:
                    decoded = decode(raw[cursor:end])
                    boundary[cursor] = (end, size)
                    chunks['mode-' + str(mode)] += 1
                assert len(decoded) == size
                logical.extend(decoded)
                cursor = end
                consumed = 0
                while len(logical) - consumed >= 64:
                    values = struct.unpack_from('<8Q', logical, consumed)
                    magic_word, index, op, ident, argc, payload_bytes, result_bytes, failure = values
                    assert magic_word == int.from_bytes(b'HIAQJL01', 'little') and index == node
                    assert argc <= 128 and payload_bytes <= 1048576 and result_bytes <= (64 << 20)
                    result_start = consumed + 64 + argc * 8 + payload_bytes
                    record_end = result_start + result_bytes
                    if record_end > len(logical):
                        break
                    args = struct.unpack_from('<' + 'Q' * argc, logical, consumed + 64)
                    payload_at = consumed + 64 + argc * 8
                    payload_raw = bytes(logical[payload_at:result_start])
                    assert (op, ident, args, payload_raw) == expected[node], (name, node)
                    result = bytes(logical[result_start:record_end])
                    label = labels[node]['label'] if labels else ''
                    operations[str(op)] += 1
                    record_bytes[str(op)] += record_end - consumed
                    if failure:
                        row['record_failures'].append(dict(node=node, failure=failure))
                    if op == 5:
                        assert result[:8] == b'HIAQRR01' and len(result) >= 64
                        stdout, stderr, receipt_n, shared, owned, request_n, zero = struct.unpack_from('<7Q', result, 8)
                        assert zero == 0 and len(result) == 64 + stdout + stderr + receipt_n + shared + request_n
                        receipt = result[64:64 + receipt_n]
                        executable = handles[args[0]]
                        input_data = handles[args[1]]
                        child = dict(node=node, label=label, executable=executable,
                                     input=input_data, stdout_bytes=stdout, stderr_bytes=stderr,
                                     receipt_sha256=digest(receipt), owned=owned)
                        if not owned:
                            assert receipt_n == 128 and receipt[:8] == b'HIASBR01'
                            words = struct.unpack('<16Q', receipt)
                            child.update(elapsed_ns=words[14], status=words[1], child_pid=words[4])
                            key = executable['sha256']
                            stat = tools[key]
                            stat['calls'] += 1
                            stat['elapsed_ns'] += words[14]
                            stat['max_ns'] = max(stat['max_ns'], words[14])
                            stat['origin'] = executable['origin']
                            stat['image_bytes'] = executable['bytes']
                            slow.append(child)
                        else:
                            child['receipt_magic'] = receipt[:8].hex()
                            row.setdefault('owned_children', []).append(child)
                    if op == 11:
                        for identifier in args:
                            del handles[identifier]
                    if ident:
                        origin = label or ('node-' + str(node) + '-op-' + str(op))
                        if op == 1:
                            origin = 'import:' + payload_raw.decode('ascii')
                        handles[ident] = dict(sha256=digest(result), bytes=len(result), origin=origin,
                                              producer_node=node, operation=op)
                    node += 1
                    consumed = record_end
                if consumed:
                    del logical[:consumed]
            row.update(physical_decoded_bytes=cursor, logical_tail_bytes=len(logical),
                       observed_nodes=node, chunks=dict(chunks), operations=dict(operations),
                       logical_bytes_by_operation=dict(record_bytes),
                       subprocess_calls=len(slow), subprocess_elapsed_ns=sum(c['elapsed_ns'] for c in slow),
                       subprocess_top=sorted(slow, key=lambda c: c['elapsed_ns'], reverse=True)[:20],
                       subprocess_images=sorted((dict(sha256=k, **v) for k, v in tools.items()),
                                                key=lambda v: v['elapsed_ns'], reverse=True))
            row['complete'] = cursor == len(raw) and not logical and node == len(expected) and not row['record_failures']
    return row


assert not OUT.exists(), 'separate report already exists; do not replace original evidence'
began = time.monotonic()
report = dict(schema='hepta.hia.failed-cold-journal-profile.v1',
              scope='read-only diagnosis of retained original failure; no full-cold qualification claim',
              source_head='2f4ff983a41212ba8bc6a89aa9dda001610a9d89',
              source_or_receipt_modified=False, full_cold_passed=False, phases=[])
for name in NAMES:
    item = profile(name)
    report['phases'].append(item)
    print(json.dumps(dict(phase=name, nodes=item['observed_nodes'], complete=item['complete'],
                          subprocess_seconds=item['subprocess_elapsed_ns'] / 1e9,
                          top=item['subprocess_top'][:3])), flush=True)
report['elapsed_seconds'] = time.monotonic() - began
body = json.dumps(report, indent=2, sort_keys=True).encode() + b'\n'
with OUT.open('xb') as handle:
    handle.write(body)
print(json.dumps(dict(report=str(OUT), bytes=len(body), sha256=digest(body),
                      elapsed_seconds=report['elapsed_seconds'])), flush=True)
