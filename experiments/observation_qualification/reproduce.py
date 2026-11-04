"""Real temporary-file counterexamples, using existing supported checkpoints.

Run with python -B -m experiments.observation_qualification.reproduce.
Stack inspection only schedules adversarial writes; it does not replace reads,
validation, authority, admission, or counters. Nothing imports this in runtime.
"""
import argparse
import hashlib
import inspect
import json
from pathlib import Path
import tempfile

from hepta import packages
from hepta.ast import HeptaError
from experiments.frontend_lock_revalidation.adapter import FrontendRequest
from experiments.frontend_lock_revalidation.owner import Owner
from experiments.loader_budget.prototype import Reader, Limits

TEXT = b'fn main()->Unit effects {} {}'
BAD_SOURCE = TEXT + b'\n// changed graph\n'
BAD_LOCK = b'broken between lock observations'


def fixture(root):
    entry = root / 'main.hepta'
    entry.write_bytes(TEXT)
    (root / 'hepta.toml').write_text('[package]\nname="app"\nversion="1.0.0"\nsource_root="."\nentry="main.hepta"\n')
    packages.write_lock(root)
    lock = root / 'Hepta.lock'
    return entry, lock, lock.read_bytes()


def in_graph():
    frame = inspect.currentframe()
    try:
        while frame:
            if (frame.f_code.co_name == '_unchanged'
                    and frame.f_globals.get('__name__') == 'hepta.modules'):
                return True
            frame = frame.f_back
        return False
    finally:
        del frame


def current_route():
    with tempfile.TemporaryDirectory() as tmp:
        entry, lock, _ = fixture(Path(tmp))
        mutations = []
        def checkpoint():
            if request.phase == 'revalidation' and in_graph():
                lock.write_bytes(BAD_LOCK)
                mutations.append(True)
        request = FrontendRequest(config={'locked': True}, checkpoint=checkpoint)
        analysis = request.check(entry)
        fresh_code = None
        try:
            Owner().load(entry, locked=True)
        except HeptaError as error:
            fresh_code = error.diagnostic.code
        return dict(ok=analysis.report['ok'], qualification=request.lock_revalidation,
                    mutated=bool(mutations), fresh_code=fresh_code,
                    lock_bad=lock.read_bytes() == BAD_LOCK)


def alternating(rounds=8, *, final_lock=False):
    if type(rounds) is not int or not 1 <= rounds <= 8:
        raise ValueError('test harness supports 1..8 rounds')
    with tempfile.TemporaryDirectory() as tmp:
        entry, lock, good_lock = fixture(Path(tmp))
        armed, mode = False, None
        states, transitions = [], []
        def state():
            current = (lock.read_bytes() == good_lock, entry.read_bytes() == TEXT)
            states.append(current)
            assert current != (True, True)
        def checkpoint():
            nonlocal mode
            if not armed:
                return
            desired = 'graph' if in_graph() else 'lock'
            if desired == mode:
                return
            # The other input remains bad during each write, including partial
            # writes. Record BOTH BAD between the two writes, not just endpoints.
            if desired == 'graph':
                lock.write_bytes(BAD_LOCK)
                state()
                entry.write_bytes(TEXT)
            else:
                entry.write_bytes(BAD_SOURCE)
                state()
                lock.write_bytes(good_lock)
            state()
            mode = desired
            transitions.append(desired)
        owner = Owner(checkpoint=checkpoint)
        handle = owner.load(entry, locked=True)
        authority = next(graph for known, graph in owner._handles if known is handle)
        # Initial load is deliberately OUTSIDE the claimed observation window.
        entry.write_bytes(BAD_SOURCE)
        state()
        armed = True
        outcomes = [owner.revalidate(handle) for _ in range(rounds)]
        bracket_equal = None
        if final_lock:
            # Hypothetical test-only tail, using original operations/authority.
            # Not a production lifecycle or implemented extra-pass profile.
            assert owner._ops.path(lock, 'is_file')
            actual = owner._ops.json(json.loads, owner._ops.read(lock, 'lock'), lock)
            bracket_equal = actual == authority.package_state
        return dict(outcomes=outcomes, states=states, transitions=transitions,
                    bracket_equal=bracket_equal, source_good=entry.read_bytes() == TEXT,
                    lock_good=lock.read_bytes() == good_lock,
                    reads=owner.context.reader.reads,
                    metadata_parses=owner.context.counts['metadata_parses'],
                    failure=owner.context.failure)


def torn_stream(*, digest=False):
    """Actual inherited Reader, real fd/os.read, supported four-byte chunks.

    AAAAXXXX -> ZZZZXXXX -> ZZZZBBBB, but observed stream is AAAABBBB.
    Each write leaves a disjoint wrong half, so even partial writes cannot
    produce the accepted full stream. No monkeypatch or replacement reader.
    """
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / 'stream'
        path.write_bytes(b'AAAAXXXX')
        states = [path.read_bytes()]
        mutated = False
        def checkpoint():
            nonlocal mutated
            if reader.bytes_read == 4 and not mutated:
                mutated = True
                with path.open('r+b', buffering=0) as stream:
                    stream.write(b'ZZZZ')
                    states.append(path.read_bytes())
                    stream.seek(4)
                    stream.write(b'BBBB')
                    states.append(path.read_bytes())
        reader = Reader(Limits(chunk_bytes=4), checkpoint=checkpoint)
        observed = reader.digest(path) if digest else reader.read(path)
        expected = hashlib.sha256(b'AAAABBBB').hexdigest() if digest else b'AAAABBBB'
        return dict(matches=observed == expected, states=states, mutated=mutated,
                    reads=reader.reads, bytes_read=reader.bytes_read)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--rounds', type=int, choices=range(1, 9), default=8)
    args = parser.parse_args()
    print('Current route:', current_route())
    print('Alternating observations and hypothetical final L:', alternating(args.rounds, final_lock=True))
    print('Torn observed stream:', torn_stream())


if __name__ == '__main__':
    main()
