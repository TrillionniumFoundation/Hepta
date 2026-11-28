"""Physical-source custody for the exact retained installed worker workload.

The recovered bytes are a historical comparison input, never an executable
replacement or a native release authority. Current source requires the complete
fixed installed-distribution relation from the caller's explicit root.
"""
from hashlib import sha256
from pathlib import Path
import stat

SOURCE = "tools/hia_worker_installed_workload_source.py"
WORKLOAD = "tests/hia_service_verification_installed.py"
ORIGINAL = {"bytes": 12075, "sha256": "0f95cc59fe2a66bcc2fbcfa8dc253266e763bbc8ca7c873d5bdf956fd04bdda6"}
CURRENT = {"bytes": 12217, "sha256": "3b2f50f9605d0da0a74029337bcf86ed64daa8df7b7d77712f33ec1b8359d1a9"}
READERS = {
    "tests/hia_installed_distribution_history.py": {"bytes": 5636, "sha256": "797655698610c5f074b71a3f6056bad3c85f757a749bd56c60db0711c12dcb2f"},
    "tests/hia_component_authoring_history.py": {"bytes": 3029, "sha256": "72c7261a11a85016e64abd82362202efb90db24fc249d5ace12989562f596db8"},
    "tests/hia_component_native_cold_history.py": {"bytes": 4509, "sha256": "e1f16b56047c355a962d8999e09a9a03e1b9fe1ccd2f61926edf5a7e90073060"},
}


def pin(raw):
    return {"bytes": len(raw), "sha256": sha256(raw).hexdigest()}


def _physical(path):
    path = Path(path).absolute()
    try:
        if path.resolve(strict=True) != path:
            raise ValueError("workload source must not traverse a symbolic link")
        before = path.lstat()
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ValueError("workload source must be one regular file")
        raw = path.read_bytes()
        after = path.lstat()
    except OSError as error:
        raise ValueError("workload source or required history is absent: " + str(path)) from error
    fields = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_nlink", "st_mode")
    if len(raw) != before.st_size or any(getattr(before, k) != getattr(after, k) for k in fields):
        raise ValueError("workload physical source changed during capture")
    return raw


def verify_workload_source(admission):
    root = admission["root"]
    for name, raw in admission["captured"].items():
        if _physical(root / name) != raw:
            raise ValueError("workload source history changed at terminal readback: " + name)
    for name, path in admission["loaded"].items():
        if _physical(path) != admission["captured"][name]:
            raise ValueError("loaded workload history reader changed")


def capture_workload_source(root, *, take=Path.read_bytes):
    root = Path(root).absolute()
    if root.resolve(strict=True) != root:
        raise ValueError("workload root must not traverse a symbolic link")
    captured, loaded = {}, {}

    def capture(path):
        path = Path(path).absolute()
        try:
            name = path.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError("workload history escaped its explicit root") from error
        physical = _physical(path)
        raw = take(path)
        if type(raw) is not bytes or raw != physical or name in captured and captured[name] != raw:
            raise ValueError("workload captured bytes differ from physical source")
        captured[name] = raw
        return raw

    physical = capture(root / WORKLOAD)
    identity = pin(physical)
    if identity == ORIGINAL:
        original = physical
        mode = "EXACT_ORIGINAL_WITHOUT_MIGRATION"
    elif identity == CURRENT:
        from tests import hia_installed_distribution_history as installed
        from tests import hia_component_authoring_history as component
        from tests import hia_component_native_cold_history as native_cold
        modules = (installed, component, native_cold)
        for name, module in zip(READERS, modules):
            raw = capture(root / name)
            loaded[name] = Path(module.__file__).absolute()
            if pin(raw) != READERS[name] or _physical(loaded[name]) != raw:
                raise ValueError("fixed workload history reader differs from captured root")
        loaded[SOURCE] = Path(__file__).absolute()
        if capture(root / SOURCE) != _physical(loaded[SOURCE]):
            raise ValueError("workload custody reader differs from captured root")
        original = installed.predecessor(WORKLOAD, physical, root=root, take=capture)
        mode = "EXACT_INSTALLED_DISTRIBUTION_PREDECESSOR"
    else:
        raise ValueError("unrecognized physical installed workload source")
    if pin(original) != ORIGINAL:
        raise ValueError("complete original installed workload differs")
    admission = {"root": root, "physical": physical, "original": original,
                 "captured": captured, "loaded": loaded}
    verify_workload_source(admission)
    admission["proof"] = {
        "schema": "hepta.hia.worker-installed-workload-source.v1",
        "source_root": str(root), "path": WORKLOAD, "mode": mode,
        "physical": pin(physical), "original": ORIGINAL,
        "inputs": {name: pin(raw) for name, raw in sorted(captured.items())},
        "historical_bytes_executed": False, "native_distribution_qualified": False,
    }
    return admission
