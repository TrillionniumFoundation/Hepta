"""Data-only whole observer predecessor for the explicit retained source test."""
from contextlib import contextmanager
from hashlib import sha256
import json
from pathlib import Path
import stat
from tempfile import TemporaryDirectory

SELF = "tests/hia_runtime_dispatch_source_history.py"
OBSERVER = "tests/hia_service_bootstrap_observer.py"
FIXTURE = "tests/fixtures/hia_runtime_dispatch_observer_successor_v1.json"
FIXTURE_PIN = {'bytes': 957, 'sha256': '58ec792c5147a85082000a8c5f7337210a3d2fa2926d3d697acf06f74b9f7883'}
PRIOR_PIN = {'bytes': 40879, 'sha256': 'c3e774b6507a2c78cb81c5b64bb2b173850d17ed45d120a8659ff0c5bfc5e8e7'}
CURRENT_PIN = {'bytes': 41108, 'sha256': '61e98ae538188289d87d2168000af4ab51949606a3ddf8976f20d67cb05c4c62'}
_SELF_PATH = Path(__file__).resolve()
_SELF_BYTES = _SELF_PATH.read_bytes()


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def _stamp(value):
    return tuple(getattr(value, name) for name in (
        "st_dev", "st_ino", "st_mode", "st_uid", "st_gid", "st_nlink",
        "st_size", "st_mtime_ns", "st_ctime_ns"))


def _capture(path):
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or path.resolve() != path or before.st_nlink != 1:
        raise ValueError("observer history requires a physical regular source")
    raw = path.read_bytes()
    after = path.lstat()
    if _stamp(before) != _stamp(after):
        raise ValueError("observer history input changed during capture")
    return raw, _stamp(after)


def _unchanged(captures):
    if _SELF_PATH.read_bytes() != _SELF_BYTES:
        raise ValueError("executed observer history module changed")
    for path, expected in captures.items():
        if _capture(path) != expected:
            raise ValueError("physical observer history input changed")


def _prior(raw, fixture):
    if pin(raw) != CURRENT_PIN or pin(fixture) != FIXTURE_PIN:
        raise ValueError("unreviewed observer successor")
    record = json.loads(fixture)
    if (type(record) is not dict or set(record) != {"schema", "path", "prior", "current", "splices"}
            or record["schema"] != "hepta.hia.runtime-dispatch-observer-successor.v1"
            or record["path"] != OBSERVER or record["prior"] != PRIOR_PIN
            or record["current"] != CURRENT_PIN
            or type(record["splices"]) is not list or len(record["splices"]) != 2):
        raise ValueError("wrong complete observer history")
    prior = raw
    for splice in reversed(record["splices"]):
        if type(splice) is not dict or set(splice) != {"prior", "current"}:
            raise ValueError("wrong observer splice")
        before, after = splice["prior"].encode(), splice["current"].encode()
        if prior.count(after) != 1:
            raise ValueError("observer inverse is not exact")
        prior = prior.replace(after, before)
    if pin(prior) != PRIOR_PIN:
        raise ValueError("whole observer predecessor differs")
    replay = prior
    for splice in record["splices"]:
        before, after = splice["prior"].encode(), splice["current"].encode()
        if replay.count(before) != 1:
            raise ValueError("observer replay is not exact")
        replay = replay.replace(before, after)
    if replay != raw:
        raise ValueError("whole observer replay differs")
    return prior


@contextmanager
def observer_source_view(root):
    root = Path(root).resolve(strict=True)
    captures = {}
    def take(name):
        path = root / name
        value = _capture(path)
        if path in captures and captures[path] != value:
            raise ValueError("observer input changed between reads")
        captures[path] = value
        return value[0]
    physical = take(OBSERVER)
    if pin(physical) == PRIOR_PIN:
        try:
            yield root
        finally:
            for path, expected in captures.items():
                if _capture(path) != expected:
                    raise ValueError("retained observer source changed")
        return
    if pin(physical) != CURRENT_PIN:
        raise ValueError("unknown observer whole-file version")
    if take(SELF) != _SELF_BYTES:
        raise ValueError("selected history does not match executed source")
    prior = _prior(physical, take(FIXTURE))
    _unchanged(captures)
    with TemporaryDirectory(prefix="hia-runtime-dispatch-prior-") as directory:
        stage = Path(directory).resolve()
        destination = stage / OBSERVER
        destination.parent.mkdir(parents=True)
        destination.write_bytes(prior)
        try:
            yield stage
        finally:
            if destination.read_bytes() != prior:
                raise ValueError("explicit retained observer view changed")
            _unchanged(captures)
