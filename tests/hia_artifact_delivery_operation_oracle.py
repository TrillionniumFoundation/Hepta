"""Separate frozen original operation-object domain; the original 96 stay intact."""
from contextlib import ExitStack
import fcntl
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import subprocess
from types import SimpleNamespace
from unittest.mock import patch

from .hia_artifact_delivery_oracle import (
    Fixture, NONCE, canonical, fake_ack, original_namespace, public_observation)

ROOT = Path(__file__).resolve().parents[1]


def operation_value(case, comparisons):
    operation = case['operation']
    if case['custom_ne']:
        class OriginalOperation(str):
            def __ne__(self, other):
                comparisons.append(['__ne__', str(self), other])
                return True
        operation = OriginalOperation(operation)
    return operation


class OperationFixture(Fixture):
    def __init__(self, case):
        super().__init__(case)
        self.comparisons = []

    def arguments(self):
        args, keywords = super().arguments()
        return (args[0], operation_value(self.case, self.comparisons), *args[2:]), keywords

    def run(self, argv, **keywords):
        result = super().run(argv, **keywords)
        if self.candidate and self.case['operation'] == 'withdraw':
            # Actual original withdrawal consumes no stdin bytes. The separate
            # real-image control records this complete ACK, including when the
            # original Python operation object causes nonempty stdin to be sent.
            result.stderr = fake_ack('withdraw', result.returncode, result.stdout, 0)
        return result


def observe_case(case, owner=None):
    fixture = OperationFixture(case)
    result = fixture.observe(owner)
    result['operation_comparisons'] = fixture.comparisons
    return result


def actual_observations(root, manifest):
    from hepta import artifact_publication_native as api
    from hepta import hia_artifact_delivery as delivery
    from hepta.hia_artifact_delivery_protocol import acknowledgement, public_executable
    # The candidate uses fresh full actual admission. The independent original
    # body is given that same public image because its old source contract does
    # not assert custody for this successor source tree.
    private = api._admitted_code(manifest)
    public = public_executable(private)
    raw = (ROOT / 'tests/fixtures/hia_artifact_delivery_operation_cases.json').read_bytes()
    cases = json.loads(raw)['cases']
    real_run = subprocess.run

    def error_record(error):
        return {'type': type(error).__name__, 'message': str(error),
                'cause': None if error.__cause__ is None else error_record(error.__cause__)}

    def observe(case, selected, folder):
        folder.mkdir(mode=0o700)
        stage, destination = folder / 'stage', folder / 'destination'
        data = bytes.fromhex(case['data_hex'])
        stage.write_bytes(data or b'abc')
        if case['operation'] in ('withdraw', 'verify'):
            os.link(stage, destination)
        namespace = api.__dict__ if selected else original_namespace()
        calls, comparisons = [], []
        operation = operation_value(case, comparisons)

        def recorded(argv, **keywords):
            fd, = keywords['pass_fds']
            image = private if selected else public
            sealed = os.pread(fd, len(image) + 1, 0)
            assert sealed == image and os.fstat(fd).st_size == len(image)
            assert fcntl.fcntl(fd, getattr(fcntl, 'F_GET_SEALS', 1034)) & 15 == 15
            assert len(argv) == 4 and argv[0] == '/proc/self/fd/' + str(fd)
            assert keywords['env'] == {'PATH': ''} and keywords['capture_output'] is True
            row = {'argv': [str(value) for value in argv], 'env': keywords['env'],
                   'input_hex': keywords['input'].hex(), 'pass_fds': list(keywords['pass_fds']),
                   'sealed_sha256': sha256(sealed).hexdigest(),
                   'entry': struct.unpack_from('<Q', sealed, 24)[0]}
            calls.append(row)
            result = real_run(argv, **keywords)
            row.update(exit=result.returncode, stdout_hex=result.stdout.hex(), stderr_hex=result.stderr.hex())
            if selected:
                row['ack'] = vars(acknowledgement(result.stderr, NONCE, result.returncode, result.stdout))
            else:
                assert result.stderr == b''
            return result

        with ExitStack() as stack:
            providers = {'subprocess': SimpleNamespace(run=recorded)}
            if not selected:
                providers['_validated_code'] = lambda value: public
            stack.enter_context(patch.dict(namespace, providers))
            stack.enter_context(patch.object(delivery.os, 'urandom', return_value=NONCE))
            try:
                value = namespace['invoke_native'](manifest, operation, stage, destination, data)
            except BaseException as error:
                outcome = {'error': error_record(error)}
            else:
                outcome = {'returned': value}
        return {'name': case['name'], 'outcome': outcome, 'operation_comparisons': comparisons,
                'stage_exists': stage.exists(), 'destination_exists': destination.exists(), 'calls': calls}

    original, selected = [], []
    for index, case in enumerate(cases):
        original.append(observe(case, False, root / ('original-operation-' + str(index))))
        selected.append(observe(case, True, root / ('selected-operation-' + str(index))))
    record = {'cases_sha256': sha256(raw).hexdigest(), 'original': original, 'selected': selected,
              'public_image_sha256': sha256(public).hexdigest(), 'private_image_sha256': sha256(private).hexdigest(),
              'candidate_full_current_admission': True, 'original_code_admission_explicit': True}
    (root / 'operation-observations.json').write_bytes(canonical(record) + b'\n')
    for old, new in zip(original, selected, strict=True):
        assert canonical({k: v for k, v in old.items() if k != 'calls'}) == canonical(
            {k: v for k, v in new.items() if k != 'calls'}), old['name']
    assert original[1]['outcome'] == {'returned': True}
    assert original[1]['operation_comparisons'] == [['__ne__', 'withdraw', 'withdraw']] * 2
    assert selected[1]['calls'][0]['ack']['operation'] == 3
    assert selected[1]['calls'][0]['ack']['input_bytes'] == 0
    assert selected[1]['calls'][0]['input_hex'] == (NONCE + b'abc').hex()
    return record
