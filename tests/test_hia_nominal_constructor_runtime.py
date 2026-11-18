"""Compare the installed constructor with the existing bound callback route."""
from __future__ import annotations

import argparse
from contextlib import redirect_stdout
from copy import deepcopy
from hashlib import sha256
from io import StringIO
import json
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest.mock import patch

from hepta.hia_composite_functions_errors import ERRORS as FUNCTION_ERRORS
from hepta.hia_composite_constructor_errors import ERRORS as CONSTRUCTOR_ERRORS
from hepta.hia_composite_constructor_native import NativeConstructorInvocation
from hepta.hia_composite_function_tokens import ObjectTokenDecoder, detached_packet_index
from hepta.hia_composite_types_native import ERRORS as TYPE_ERRORS, NativeCompositeTypes
from hepta.hia_instruction_policy_native import transport
from hepta.hia_json_preflight_native import NativeHiaJsonImage
from hepta.hia_program import HIAProgramRejected, verify_core
from hepta.hia_program_composite import _Elaborator
from hepta.hia_program_tools import inspect_program, publish_program
from tests.test_hia_partial_record import roundtrip_program
from tests.test_hia_composite_returned_loans import pair_program, task_program as loan_task
from tests.test_hia_program_composite import enum_owner_program, i, stored_loan_program, task_program


FRAME = struct.Struct('<8s7Q')


def image(folder, role, cls=NativeHiaJsonImage):
    body = (folder / (role + '.image.bin')).read_bytes()
    return cls(body, sha256(body).hexdigest())


def reference(folder, document, legacy):
    images = {name: image(folder, name) for name in ('owner', 'render')}
    types = image(folder, 'types', NativeCompositeTypes)
    commands, terminal = [], None
    original = NativeConstructorInvocation._stream

    def observe(invocation, action, request):
        nonlocal terminal
        value = original(invocation, action, request)
        if action:
            commands.append(action)
        else:
            terminal = value
        return value

    owner = SimpleNamespace()
    with (patch('hepta.hia_composite_types_native.selected_composite_types', types.session),
          patch.object(NativeConstructorInvocation, '_stream', observe)):
        try:
            NativeConstructorInvocation(images, owner, document, legacy=legacy).initialize()
            code, message = None, None
        except HIAProgramRejected as exc:
            code, message = exc.code, str(exc)
        finally:
            if getattr(owner, 'native_types', None):
                owner.native_types.close()
    return commands, terminal, code, message


def cases():
    for profile in (1, 2, 3):
        doc = task_program()
        doc['schema'] = 'hepta.hia.composite.v' + str(profile)
        yield 'task-v' + str(profile), doc, False, (0, 0)
    yield 'legacy-v1', task_program(), True, (0, 0)
    yield 'returned-loan-v4', pair_program(), False, (0, 0)
    yield 'loan-and-task-v4', loan_task(), False, (0, 0)
    many = {'schema': 'hepta.hia.composite.v1', 'module': 'many',
            'types': [], 'functions': [
                {'name': f'f{i}', 'params': [{'name': f'p{j}', 'type': 'u8'} for j in range(6)],
                 'returns': [], 'effects': [], 'entry': 'b', 'blocks': []}
                for i in range(256)]}
    yield 'multi-chunk', many, False, (0, 0)
    wrong_origin = pair_program()
    wrong_origin['functions'][0]['return_loans'][0]['param'] = 'missing'
    yield 'delegated-refusal', wrong_origin, False, (999, 39)
    wrong_module = pair_program()
    wrong_module['module'] = '00'
    yield 'early-owner-refusal', wrong_module, False, (4, 0)
    wrong_effect = task_program()
    wrong_effect['functions'][0]['effects'].append('unknown')
    yield 'late-owner-refusal', wrong_effect, False, (14, 0)


def check(executable, oracle, ordinary=None):
    def run(raw, *, digits=4300, legacy=False, count=None, flags=0, trailer=b'', handoff=False):
        length = len(raw) if count is None else count
        magic = b'HIACBX01' if handoff else b'HIACSX01'
        request = FRAME.pack(magic, digits, int(legacy), length, flags, 0, 0, 0)
        result = subprocess.run([executable], input=request + raw + trailer, capture_output=True,
                                env={'PATH': ''}, timeout=20, check=False)
        assert not result.stderr
        return result.returncode, result.stdout

    requests, documents, kinds, seeds, admitted = 0, 0, set(), 0, 0
    for name, document, legacy, status in cases():
        commands, expected, old_code, old_message = reference(oracle, document, legacy)
        assert expected is not None, (name, old_message)
        raw = json.dumps(document, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
        code, data = run(raw, legacy=legacy)
        assert code == (65 if status[0] else 0), (name, code)
        assert FRAME.unpack_from(data) == (
            b'HIACSF01', *status, expected[0], expected[1], len(commands), len(raw), 1)
        diagnostic = TYPE_ERRORS[status[1]] if status[1] else CONSTRUCTOR_ERRORS.get(status[0])
        assert (diagnostic[0] if diagnostic else None) == old_code
        if diagnostic is not None:
            assert diagnostic[1] in old_message

        # Decoding is performed only by this independent test observer;
        # the actual installed process never imports a host object decoder.
        _, index = detached_packet_index(transport([document, legacy]))
        decoder = ObjectTokenDecoder(index)
        sequence, cursor = 0, 64
        while not decoder.complete:
            magic, action, seq, final, a, b, request, size = FRAME.unpack_from(data, cursor)
            assert (magic, action, seq, a, b, request) == (b'HIACTK01', 0, sequence, 0, 0, len(commands))
            assert final in (0, 1)
            cursor += FRAME.size
            assert size <= len(data) - cursor
            decoder.feed(data[cursor:cursor + size], final=bool(final))
            sequence += 1
            cursor += size
        assert cursor == len(data) and decoder.root == expected, name
        if name == 'multi-chunk':
            assert sequence > 1
        for role in (1, 2):
            seed_code, seed_data = run(raw, legacy=legacy, flags=role, handoff=True)
            if status[0]:
                assert (seed_code, seed_data) == (code, data)
                continue
            registry = [row[:3] for row in expected[4]]
            if role == 1:
                payload = transport([document, registry, expected[5], 0, 0, legacy, 0])
            else:
                payload = transport([document, registry, 0, 0, [], []])
            assert seed_code == 0
            assert FRAME.unpack_from(seed_data) == (
                b'HIACIP01', role, len(payload), expected[1], len(commands), 0, 0, 0)
            assert seed_data[64:] == payload
            seeds += 1
        first_code, first_data = run(raw, legacy=legacy, flags=3, handoff=True)
        if status[0]:
            assert (first_code, first_data) == (code, data)
        elif name == 'multi-chunk':
            assert (first_code, first_data) == (65, FRAME.pack(b'HIAFAF01', 1, 1, 0, 0, 0, 0, 0))
        else:
            serial, slots, count = {'returned-loan-v4': (8, 18, 6),
                                    'loan-and-task-v4': (9, 37, 19)}.get(name, (2, 38, 29))
            first = FRAME.pack(b'HIAFAF01', 10, 0, 100, serial, slots, count, 0)
            assert (first_code, first_data) == (0, first)
            admitted += count
        requests += len(commands)
        kinds.update(commands)
        documents += 1

    assert kinds == {1, 2, 3, 4, 5}
    malformed = [(b'{"x":0,"x":0}', 0xfffffffc), (b'{}\xff', 0xffffffff), (b'[] ', 0xfffffffd)]
    for raw, expected in malformed:
        digits = 639 if expected == 0xfffffffd else 4300
        assert run(raw, digits=digits) == (65, struct.pack('<8sQ', b'HIANJE01', expected))
    assert run(b'', count=(8 << 20) + 1) == (65, struct.pack('<8sQ', b'HIANJE01', 0xfffffffb))
    assert run(b'', count=1) == (64, b'')
    assert run(b'{}', flags=1) == (64, b'')
    assert run(b'{}', trailer=b' ') == (64, b'')
    assert run(b'{}', handoff=True, flags=0) == (64, b'')
    assert run(b'{}', handoff=True, flags=10) == (64, b'')
    bad_param = task_program()
    bad_param['functions'][0]['blocks'][0]['params'][0]['type'] = 'Missing'
    bad_raw = json.dumps(bad_param, separators=(',', ':')).encode()
    assert run(bad_raw, flags=3, handoff=True) == (
        65, FRAME.pack(b'HIAFAF01', 1, 999, 2, 0, 0, 1, 18))
    print(f'{documents} exact constructor completions and failure prefixes; '
          f'{requests} dependent requests across all five kinds; nine raw framing controls; '
          f'{seeds} exact function or outer seed packets; '
          f'{admitted} automatic first-function parameter requests and two refusal stages')
    check_bodies(run)
    check_modules(run)
    if ordinary is not None:
        check_ordinary(ordinary, run)


def check_bodies(run):
    def first(document, *, legacy=False):
        raw = json.dumps(document, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode()
        return run(raw, legacy=legacy, flags=4, handoff=True)

    with_helpers = task_program()
    with_helpers['functions'] = with_helpers['functions'][2:] + with_helpers['functions'][:2]
    samples = [(name, doc, legacy) for name, doc, legacy, status in cases()
               if not status[0] and name != 'multi-chunk']
    samples += [('partial-record', roundtrip_program(), False),
                ('five-task-helpers', with_helpers, False)]
    requests, helper_count = 0, 0
    for name, document, legacy in samples:
        owner = _Elaborator(deepcopy(document), legacy=legacy)
        expected = owner.function(owner.document['functions'][0])
        code, result = first(document, legacy=legacy)
        assert code == 0, (name, code)
        magic, action, error, phase, serial, slots, request, delegate = FRAME.unpack_from(result)
        assert (magic, action, error, phase, serial, slots, delegate) == (
            b'HIAFBL01', 2, 0, 2000, owner.serial, owner.value_slots, 0)
        payload, packet = transport(expected), FRAME.unpack_from(result, 64)
        assert packet == (b'HIAFPP01', 0, request, len(payload), serial, slots, 0, 0)
        assert result[128:128 + len(payload)] == payload, name
        cursor, handles, helpers = 128 + len(payload), [], []
        for helper in owner.helpers:
            marker, status, final, name_id, size, sequence, r0, r1 = FRAME.unpack_from(result, cursor)
            assert (marker, status, r0, r1) == (b'HIAFHR01', 0, 0, 0)
            assert name_id <= final <= serial and 0 < sequence < request
            start = cursor + 64
            end = start + size
            assert end <= len(result)
            value = json.loads(result[start:end])
            assert value == {'helper': helper}
            assert helper['name'] == 'h2internal_' + str(name_id)
            cursor = end
            handles.append(sequence)
            helpers.append(name_id)
        assert cursor == len(result) and handles == sorted(set(handles)), name
        assert helpers == sorted(set(helpers)), name
        if name == 'five-task-helpers':
            assert len(helpers) == 5
        requests += request
        helper_count += len(helpers)

    # An error after helper lowering must not publish any generated helper.
    broken = deepcopy(with_helpers)
    for block in broken['functions'][0]['blocks']:
        if any(ins['op'] == 'task.close' for ins in block['ops']):
            block['ops'].append({'op': 'call', 'args': [], 'out': [],
                                          'attrs': {'function': 'missing_function'}})
            break
    else:
        raise AssertionError('missing task.close fixture')
    owner = _Elaborator(deepcopy(broken))
    try:
        owner.function(owner.document['functions'][0])
    except HIAProgramRejected as exc:
        code, result = first(broken)
        assert code == 65 and len(result) == 64
        magic, action, error, phase, serial, slots, request, delegate = FRAME.unpack(result)
        assert (magic, action, delegate) == (b'HIAFBL01', 1, 0)
        assert request > 0 and phase < 2000
        assert (serial, slots) == (owner.serial, owner.value_slots)
        assert FUNCTION_ERRORS[error][0] == exc.code
        assert FUNCTION_ERRORS[error][1] in str(exc)
    else:
        raise AssertionError('hosted function did not reject the missing callee')
    assert owner.helpers, 'missing callee must be reached after real helper generation'

    wrong = task_program()
    wrong['functions'][0]['blocks'][0]['params'][0]['type'] = 'Missing'
    assert first(wrong) == (65, FRAME.pack(b'HIAFBL01', 1, 999, 2, 0, 0, 1, 18))
    print(f'{len(samples)} exact lowered Core function packets, {requests} automatic dependent requests, '
          f'{helper_count} generated helper functions, and two refusal stages with no partial output')


def check_modules(run):
    def module(raw, *, legacy=False):
        return run(raw, legacy=legacy, flags=5, handoff=True)

    root = Path(__file__).resolve().parents[1]
    checked = [(name, doc, legacy) for name, doc, legacy, status in cases()
               if not status[0] and name != 'multi-chunk']
    examples = (
        'examples/hia_program/cooperative_task.hepta',
        'examples/hia_program/generic_owned_enum.hepta',
        'examples/hia_program/partial_record.hepta',
        'examples/hia_program/stored_loan_record.hepta',
        'examples/hia_recursive_chain/composite_v2.hepta',
    )
    samples = [
        (name, json.dumps(doc, ensure_ascii=False, allow_nan=False, separators=(',', ':')).encode(), legacy)
        for name, doc, legacy in checked]
    samples += [(path, (root / path).read_bytes(), False) for path in examples]
    ordinary_count, helper_count = 0, 0
    profiles = set()
    for name, raw, legacy in samples:
        document = json.loads(raw)
        owner = _Elaborator(document, legacy=legacy)
        expected = owner.lower()
        payload = transport(expected)
        # The oracle still runs ordinary primitive verification; elaboration
        # alone neither grants execution authority nor mutates the source.
        checked = verify_core(expected)
        old = verify_core(raw)
        assert old.canonical_bytes == checked.canonical_bytes
        code, result = module(raw, legacy=legacy)
        count, helpers = len(document['functions']), len(owner.helpers)
        assert code == 0, (name, code)
        assert FRAME.unpack_from(result) == (b'HIAOMF01', 2, 0, 2000, count, 0, count, helpers), name
        assert FRAME.unpack_from(result, 64) == (
            b'HIAOTP01', count, len(payload), count, helpers, owner.serial, 0, 0), name
        assert result[128:] == payload, name
        ordinary_count += count
        helper_count += helpers
        profile = int(document['schema'][-1])
        profiles.add(profile)
        original, core = old.structured_bytes, old.canonical_bytes
        assert original is not None
        assert run(raw, legacy=legacy, flags=6, handoff=True) == (
            0, FRAME.pack(b'HIAVCF01', 0, 0, profile, len(original), len(core), 0, 0)
               + original + core), name
        if not legacy:
            for role, (_, formatted) in enumerate(reports(old), 7):
                assert run(raw, flags=role, handoff=True) == (0, formatted), (name, role)

    # A later function may reject after prior functions are already retained;
    # the outer status contains its delegate, not a partial Core program.
    broken = task_program()
    broken['functions'][-1]['blocks'] = []
    raw = json.dumps(broken, separators=(',', ':')).encode()
    code, result = module(raw)
    assert code == 65 and len(result) == 128
    assert FRAME.unpack_from(result) == (b'HIAOMF01', 1, 999, 2000, 3, 0, 2, 0)
    magic, action, error, phase, _serial, _slots, request, delegate = FRAME.unpack_from(result, 64)
    assert (magic, action, error, phase, delegate) == (b'HIAFBL01', 1, 1, 0, 0)
    assert request > 0

    for name, document, legacy, status in cases():
        if status[0]:
            raw = json.dumps(document, separators=(',', ':')).encode()
            assert module(raw, legacy=legacy) == run(raw, legacy=legacy), name
    assert profiles == {1, 2, 3, 4}
    # These documents are successfully elaborated, but must not pass the
    # independent primitive loan or effect checker.
    effect = enum_owner_program()
    effect['functions'][0]['effects'] = ['trap']
    loan = stored_loan_program()
    loan['functions'][0]['blocks'][1]['ops'].insert(
        3, i('buffer.store', ['parent', 'zero', 'before']))
    for document, error, diagnostic in ((effect, 0xfffffff7, 'E_HIA_EFFECT'),
                                        (loan, 0xfffffff8, 'E_HIA_LOAN')):
        raw = json.dumps(document, separators=(',', ':')).encode()
        assert module(raw)[0] == 0
        try:
            verify_core(raw)
        except HIAProgramRejected as exc:
            assert exc.code == diagnostic
        else:
            raise AssertionError('the independent Core oracle accepted invalid generated Core')
        assert run(raw, flags=6, handoff=True) == (
            65, FRAME.pack(b'HIAVCF01', 3, error, 1, 0, 0, 0, 0))
    too_deep = b'[' * 65 + b'0' + b']' * 65
    assert run(too_deep, flags=6, handoff=True) == (
        65, FRAME.pack(b'HIAVCF01', 1, 0xfffffffe, 0, 0, 0, 0, 0))
    assert run(b'{"x":0,"x":1}', flags=6, handoff=True) == (
        65, struct.pack('<8sQ', b'HIANJE01', 0xfffffffc))
    print(f'{len(samples)} native independent Core rechecks with original and Core canonical bytes; '
          'two genuine semantic and two ingress refusals')
    print(f'{len(samples)} exact complete nominal modules ({len(examples)} repository sources), '
          f'{ordinary_count} ordinary functions, {helper_count} helpers, '
          'and four failure prefixes without partial Core')


def reports(program):
    values = (
        ('verify', {**program.report(), 'status': 'standalone_core_checked',
                    'native_executed': False}),
        ('inspect', inspect_program(program)),
        ('normalize', program.as_dict()),
    )
    for action, value in values:
        yield action, pretty(value)


def pretty(value):
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + '\n').encode()


def check_ordinary(executable, run):
    root = Path(__file__).resolve().parents[1]
    sources = subprocess.check_output(
        ['git', 'ls-files', '-z', '--', '*.hepta'], cwd=root).split(b'\0')
    count = nominal = 0
    programs = []
    for encoded in filter(None, sources):
        path = root / encoded.decode()
        raw = path.read_bytes()
        if not raw.lstrip().startswith(b'{'):
            continue
        program = verify_core(raw)
        programs.append((path, program))
        count += 1
        nominal += program.structured_bytes is not None
        for action, expected in reports(program):
            result = subprocess.run([executable, action, path], capture_output=True,
                                    env={'PATH': ''}, timeout=20, check=False)
            assert (result.returncode, result.stdout, result.stderr) == (
                0, expected, b''), (path.relative_to(root), action, result.returncode)
    assert count >= 25 and nominal >= 5, (count, nominal)

    # Roles 7–9 must not accidentally expose successfully lowered but
    # semantically unverified payloads.
    broken = enum_owner_program()
    broken['functions'][0]['effects'] = ['trap']
    raw = json.dumps(broken, separators=(',', ':')).encode()
    for role in (7, 8, 9):
        assert run(raw, flags=role, handoff=True) == (
            65, FRAME.pack(b'HIAVCF01', 3, 0xfffffff7, 1, 0, 0, 0, 0))
    print(f'{count * 3} byte-exact ordinary reports on {count} structured sources '
          f'({nominal} nominal), and three no-payload post-lowering refusals')
    check_publication(executable, programs, raw)
    check_render_assembly(executable, programs, raw)


def check_render_assembly(executable, programs, rejected):
    from hepta.cli import _reference_hia_main

    def reference(source, *options):
        stdout = StringIO()
        with redirect_stdout(stdout):
            status = _reference_hia_main(['render-assembly', str(source), *map(str, options)])
        return status, stdout.getvalue().encode('utf-8'), b''

    def render(source, *options):
        result = subprocess.run([executable, 'render-assembly', source, *options],
                                env={'PATH': ''}, capture_output=True, timeout=20, check=False)
        return result.returncode, result.stdout, result.stderr

    profile_refusals = 0
    rendered = 0
    with TemporaryDirectory(prefix='hia-nominal-assembly-') as temporary:
        root = Path(temporary)
        for index, (source, _program) in enumerate(programs):
            expected = reference(source)
            assert render(source) == expected, source
            output = root / 'native' / str(index) / 'rendered.hepta'
            if expected[0] == 2:
                assert b'E_HIA_ASSEMBLY_PROFILE:' in expected[1]
                assert render(source, '-o', output) == expected
                assert not output.parent.exists()
                profile_refusals += 1
            else:
                reference_path = root / 'reference' / str(index) / 'rendered.hepta'
                status, stdout, stderr = reference(source, '-o', reference_path)
                report = json.loads(stdout)
                report['output'] = str(output)
                assert render(source, '-o', output) == (status, pretty(report), stderr), source
                assert output.read_bytes() == reference_path.read_bytes() == expected[1]
                rendered += 1
        broken = root / 'unverified.hepta'
        broken.write_bytes(rejected)
        forbidden = root / 'forbidden' / 'must-not-exist.hepta'
        refused = render(broken, '-o', forbidden)
        assert refused == (2, b'', b'') and not forbidden.parent.exists()
    assert profile_refusals >= 5 and rendered >= 5, (profile_refusals, rendered)
    print(f'{profile_refusals} byte-exact profile refusals and {rendered} rendered/published '
          'primitive assemblies; unverified nominal input has no profile report or publication')


def check_publication(executable, programs, rejected):
    def command(source, destination):
        return [executable, 'normalize', source, '-o', destination]

    def publish(source, destination):
        return subprocess.run(command(source, destination), env={'PATH': ''},
                              capture_output=True, timeout=20, check=False)

    with TemporaryDirectory(prefix='hia-nominal-publication-') as temporary:
        root = Path(temporary)
        for index, (source, program) in enumerate(programs):
            destination = root / 'actual' / str(index) / 'normalized.hepta'
            reference = publish_program(program, root / 'expected' / str(index) / 'normalized.hepta')
            reference['output'] = str(destination)
            result = publish(source, destination)
            assert (result.returncode, result.stdout, result.stderr) == (
                0, pretty(reference), b''), (source, result.returncode, result.stdout)
            assert destination.read_bytes() == program.canonical_bytes, source
        assert any(program.input_sha256 != program.sha256 for _, program in programs)

        source, program = next(pair for pair in programs if pair[1].structured_bytes is not None)
        broken = root / 'rejected.hepta'
        broken.write_bytes(rejected)
        untouched = root / 'not-created' / 'normalized.hepta'
        result = publish(broken, untouched)
        assert (result.returncode, result.stdout, result.stderr) == (2, b'', b'')
        assert not untouched.parent.exists()

        protected = root / 'protected'
        protected.mkdir()
        alias = root / 'alias'
        alias.symlink_to(protected, target_is_directory=True)
        result = publish(source, alias / 'normalized.hepta')
        assert (result.returncode, result.stdout, result.stderr) == (4, b'', b'')
        assert not tuple(protected.iterdir())

        shared = root / 'race' / 'normalized.hepta'
        shared.parent.mkdir()
        with (subprocess.Popen(command(source, shared), env={'PATH': ''},
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE) as first,
              subprocess.Popen(command(source, shared), env={'PATH': ''},
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE) as second):
            outputs = [child.communicate(timeout=20) for child in (first, second)]
            statuses = [child.returncode for child in (first, second)]
        assert sorted(statuses) == [0, 4]
        committed = shared.stat()
        assert shared.read_bytes() == program.canonical_bytes
        assert outputs[statuses.index(4)] == (b'', b'')
        result = publish(source, shared)
        assert (result.returncode, result.stdout, result.stderr) == (4, b'', b'')
        assert (shared.stat().st_ino, shared.read_bytes()) == (
            committed.st_ino, program.canonical_bytes)
    print(f'{len(programs)} exact canonical files and publication receipts; '
          'semantic refusal, symlink parent, competing writers and no overwrite')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('executable', type=Path)
    parser.add_argument('--oracle-images', type=Path, required=True)
    parser.add_argument('--ordinary', type=Path)
    args = parser.parse_args()
    check(args.executable, args.oracle_images, args.ordinary)
