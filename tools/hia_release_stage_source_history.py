"""Bind complete original Stage-plan inputs to the unchanged original methods.

The current physical release catalog is always captured under its real identity.
A named historical take selects a separate immutable whole table; it never
rewrites the production catalog or the test methods.
"""
from __future__ import annotations

from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
import stat

TABLE = 'examples/hia_bootstrap/release_stage_sources.tsv'
TEST = 'tests/test_hia_release_stage_plan.py'
FIXTURE_ROOT = 'tests/fixtures/hia_release_stage_original_d1a62d1/'
FIXTURE_TABLE = FIXTURE_ROOT + 'release_stage_sources.tsv.txt'
FIXTURE_TEST = FIXTURE_ROOT + 'test_hia_release_stage_plan.py.txt'
ORIGINAL_COMMIT = 'd1a62d1311cfb1213974a90481f0d8b57d0901a4'
PRIOR_TAKE = 'original-stage-plan-d1a62d1-10-66'
TABLE_SHA = '0b63fe4c2f1171d75a5807e4bbeeb54425e86ef4092a1a34caca2909412696cb'
TEST_SHA = 'aa4f35fe190a48602afac058313bee2bb2a0a7d6798ded9b21c8af86180b3a65'


def capture(path):
    path = Path(path)
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError('original stage input must be an ordinary single-link file')
    raw = path.read_bytes()
    after = path.lstat()
    identity = lambda info: (info.st_dev, info.st_ino, info.st_mode, info.st_uid,
                             info.st_gid, info.st_nlink, info.st_size,
                             info.st_mtime_ns, info.st_ctime_ns)
    if identity(before) != identity(after) or len(raw) != before.st_size:
        raise ValueError('original stage input changed during capture')
    return {'path': str(path), 'bytes': len(raw), 'sha256': sha256(raw).hexdigest(),
            'identity': list(identity(after))}


@contextmanager
def original_stage_inputs(root, module, *, prior_take):
    root = Path(root).resolve(strict=True)
    if prior_take != PRIOR_TAKE:
        raise ValueError('explicit original stage prior_take required')
    if (module.__name__ != 'tests.test_hia_release_stage_plan'
            or Path(module.__file__).resolve(strict=True) != root / TEST
            or module.ROOT != root or module.TABLE != root / TABLE):
        raise ValueError('original stage module or input binding differs')
    paths = (TABLE, TEST, FIXTURE_TABLE, FIXTURE_TEST)
    before = {name: capture(root / name) for name in paths}
    if (before[FIXTURE_TABLE]['sha256'] != TABLE_SHA
            or before[TEST]['sha256'] != TEST_SHA
            or before[FIXTURE_TEST]['sha256'] != TEST_SHA):
        raise ValueError('whole original stage input or method file changed')
    current = module.TABLE
    fixture = root / FIXTURE_TABLE
    record = {'schema': 'hepta.hia.original-stage-input-take.v1',
              'prior_take': prior_take, 'original_commit': ORIGINAL_COMMIT,
              'physical_initial': before, 'historical_table': before[FIXTURE_TABLE],
              'original_method_file': before[TEST], 'status': 'BOUND'}
    module.TABLE = fixture
    try:
        yield record
    finally:
        binding_ok = module.TABLE == fixture
        module.TABLE = current
        after = {name: capture(root / name) for name in paths}
        record.update(physical_terminal=after,
                      source_initial_terminal_identical=before == after,
                      original_binding_restored=module.TABLE == root / TABLE)
        record['status'] = 'UNCHANGED_AND_RESTORED' if before == after and binding_ok else 'HOLD'
        if before != after or not binding_ok:
            raise ValueError('original stage take or physical source changed')
