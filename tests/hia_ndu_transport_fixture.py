"""Explicit test-only admission for process ownership fixtures.

The script images exercise pipes, immutable sealing, deadlines and reaping.
They are never native NDU implementations or acceptable production receipts.
"""
from hashlib import sha256
from pathlib import Path
from unittest.mock import patch

from hepta.hia_ndu_native import UPSTREAM
from hepta.hia_ndu_optimizer import _VerifiedBridgeImage, _bytes, _json, _read_file, _reject

SCHEMA = 'hepta.test.ndu-transport-fixture.v1'


def fixture_receipt(raw):
    return {'schema': SCHEMA, 'binary_sha256': sha256(raw).hexdigest(),
            'provenance': 'UNQUALIFIED_TEST_PROCESS_FIXTURE'}


def admit_fixture(bridge):
    if type(bridge) is not dict or set(bridge) != {'binary', 'build_receipt'}:
        _reject('invalid test fixture paths')
    binary = Path(bridge['binary']).resolve()
    receipt_raw = _read_file(Path(bridge['build_receipt']).resolve(), 4096)
    receipt = _json(receipt_raw)
    raw = _read_file(binary, 8 << 20)
    if receipt != fixture_receipt(raw):
        _reject('test fixture executable differs from its recorded build')
    return _VerifiedBridgeImage(binary, raw), {
        'upstream_commit': UPSTREAM, 'binary_sha256': sha256(raw).hexdigest(),
        'build_receipt_sha256': sha256(receipt_raw).hexdigest(),
        'build_inputs_sha256': sha256(_bytes({'fixture': True})).hexdigest(),
        'source_attestation': 'UNQUALIFIED_TEST_PROCESS_FIXTURE',
    }


def patch_fixture_admission(test):
    # Only these tests replace admission. Real process/sealing/transport remains
    # untouched, and test_hia_ndu_scalar_native covers genuine HIA admission.
    for module in ('hia_ndu_optimizer', 'hia_ndu_prepared_ranker'):
        patcher = patch('hepta.' + module + '._bridge_identity', side_effect=admit_fixture)
        patcher.start()
        test.addCleanup(patcher.stop)
