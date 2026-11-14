"""STATIC_DRAFT: metadata copy/freeze only; no product imports or execution.
Root must first supply an exact, complete CONFIG and all referenced file pins.
The four runtime controls are reused byte for byte; their schema is a format tag.
"""
from __future__ import annotations
import argparse, gzip, hashlib, importlib.util, os, stat, sys
from pathlib import Path, PurePosixPath
P = Path("/home/qq/hia-rewrite-20261113-e26e-r1")
DONOR_CONTROL = P / "wire05-leaf-width-reads-derive8-r1/control"
PYTHON = Path("/usr/bin/python3.14")
N = P / "core-balanced-dispatch-derive8-r1"
DOCS = ["docs/HIA_SELFHOST_CORE_SUPPORT.json",
        "docs/HIA_SELFHOST_LANGUAGE_COVERAGE.json"]
BASE_ROOT = P / "core-balanced-dispatch-r1/source"
BASE_TREE = "9ea63eabcd01c80396d4b48c89923f47dcc389c7"
INITIAL_TREE = "e3ff4d436520c3ed52fde6874e3d133def6b57f1"
OVERLAY_PINS = {
    "tests/hia_core_pc_expected.py": (
        17850, "3baaed3f3fca210f625e27491108473407e357252abcd30961a056839f473ad3",
        "8c5a47d497f7d74d0ce1b44c09dd3c384a2bca69"),
    "tools/hia_selfhost_contract.py": (
        138885, "5fb1ea912e0655e6fc3e585e5c1aacdb0b64fba00fc9c26627562780c52b8a5d",
        "4aa7b47e31418066492abc80a7764d2dbfa40a4c"),
    "tests/fixtures/hia_core_balanced_dispatch_v1.json": (
        27441, "575c3a408a6130a54eff4667ef699a361977fa358b616960f4c94d6b98df5772",
        "c5c68af52cc6cca39677c1aacbcc65726133e495"),
}
CONTROL_PINS = {
    "source_common.py": (9351, "4d0678bab4028e1c23761f37fb3d59debcfb1c95c5a7d8a40930a23ddd0df54c", "8490fade47cf8513091b1e1adba597279705fc6d"),
    "derive_child.py": (3013, "cc7c0d64427cd4eb3f435044eb3b307345501c05be3905cce2561f26ee843716", "8ef44e9738b556f9d30c75911e5985a52520ed75"),
    "derive_worker.py": (4072, "4030d2beae3e8f177894864cb28e6dbae7e615022d19083b92996d7b543a47b7", "e46375155b81063f2bcea84137c545f489c7d420"),
    "derive_launch.py": (5444, "0ff6811ca6f095a95703e48f236c06742abc10061a57029cbc925dc3484cbe27", "b76deb801f8af9593d722474a6a07f2e8cfb1690"),
}
COMMANDS = [
    {"args":[],"ordinal":0,"path":"tools/generate_hia_selfhost_contract.py","phase":"derive"},
    {"args":["--generate-inventory"],"ordinal":1,"path":"tests/test_hia_selfhost_language_coverage.py","phase":"derive"},
    {"args":[],"ordinal":2,"path":"tools/generate_hia_selfhost_contract.py","phase":"derive"},
    {"args":["--check"],"ordinal":3,"path":"tools/generate_hia_selfhost_contract.py","phase":"derive"},
    {"args":[],"ordinal":0,"path":"tools/generate_hia_selfhost_contract.py","phase":"idempotence"},
    {"args":["--generate-inventory"],"ordinal":1,"path":"tests/test_hia_selfhost_language_coverage.py","phase":"idempotence"},
    {"args":[],"ordinal":2,"path":"tools/generate_hia_selfhost_contract.py","phase":"idempotence"},
    {"args":["--check"],"ordinal":3,"path":"tools/generate_hia_selfhost_contract.py","phase":"idempotence"},
]
def _bootstrap_identity(s):
    return {"dev": s.st_dev, "ino": s.st_ino, "mode": stat.S_IMODE(s.st_mode),
            "uid": s.st_uid, "gid": s.st_gid, "nlink": s.st_nlink,
            "size": s.st_size, "mtime_ns": s.st_mtime_ns, "ctime_ns": s.st_ctime_ns}

def _bootstrap_read(path, expected_size, expected_sha):
    if not path.is_absolute() or path.resolve(strict=True) != path:
        raise RuntimeError("bootstrap input alias")
    for parent in path.parents:
        info = parent.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise RuntimeError("bootstrap ancestor")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or before.st_uid not in (0, os.geteuid())
                or stat.S_IMODE(before.st_mode) & 0o022):
            raise RuntimeError("bootstrap regular input")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read(expected_size + 1)
        observed = _bootstrap_identity(before)
        if (observed != _bootstrap_identity(os.fstat(fd))
                or observed != _bootstrap_identity(path.lstat())
                or len(raw) != expected_size
                or hashlib.sha256(raw).hexdigest() != expected_sha):
            raise RuntimeError("bootstrap whole bytes/identity")
    finally:
        os.close(fd)
    return raw, {"path": str(path), "bytes": len(raw),
                 "sha256": expected_sha, "identity": observed}

if (tuple(sys.version_info[:3]) != (3, 14, 4)
        or sys.flags.isolated != 1 or sys.flags.no_site != 1
        or sys.flags.dont_write_bytecode != 1
        or Path(sys.executable) != PYTHON
        or sys.orig_argv[:4] != [str(PYTHON), "-I", "-S", "-B"]):
    raise RuntimeError("fixed Python3.14.4 -I -S -B invocation required")
_runtime_raw, _runtime_pin = _bootstrap_read(
    PYTHON, 7477160,
    "52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41")
del _runtime_raw
_common_path = DONOR_CONTROL / "source_common.py"
_common_raw, _common_pin = _bootstrap_read(
    _common_path, CONTROL_PINS["source_common.py"][0],
    CONTROL_PINS["source_common.py"][1])
# importlib creates the module; execute only the already verified source bytes.
_spec = importlib.util.spec_from_loader(
    "balanced_derive8_pinned_common", loader=None, origin=str(_common_path))
C = importlib.util.module_from_spec(_spec)
C.__file__ = str(_common_path)
exec(compile(_common_raw, str(_common_path), "exec", dont_inherit=True), C.__dict__)
C.require(C.read_regular(_common_path, _common_pin)[0] == _common_raw,
          "common changed during verified-byte module loading")
C.read_regular(PYTHON, _runtime_pin)

def git_object(kind,raw):
    return hashlib.sha1(kind.encode()+b" "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def tree(rows):
    root={}
    for row in rows:
        path=PurePosixPath(row["path"])
        C.require(not path.is_absolute() and path.as_posix()==row["path"]
            and all(x not in ("",".","..") for x in path.parts),"canonical Git path")
        node=root
        for part in path.parts[:-1]:
            node=node.setdefault(part,{})
            C.require(type(node) is dict,"tree prefix conflict")
        C.require(path.name not in node,"duplicate leaf")
        node[path.name]=(row["mode"],row["sha"])
    def render(node):
        raw=bytearray()
        for name,value in sorted(node.items(),key=lambda item:
                (item[0]+("/" if type(item[1]) is dict else "")).encode()):
            directory=type(value) is dict
            mode,digest=("40000",render(value)) if directory else value
            raw.extend((mode+" "+name).encode()+b"\0"+bytes.fromhex(digest))
        return git_object("tree",bytes(raw))
    return render(root)
def leaves(root):
    result=[]
    for path in root.rglob("*"):
        s=path.lstat()
        C.require(not stat.S_ISLNK(s.st_mode),"source symlink")
        if stat.S_ISDIR(s.st_mode):continue
        C.require(stat.S_ISREG(s.st_mode),"source special file")
        result.append(path.relative_to(root).as_posix())
    return sorted(result)

def load_manifest(pin, expected_tree, expected_count, expected_bytes):
    raw, observed = C.read_regular(pin["path"], pin)
    rows = C.decode(raw)
    C.require(type(rows) is list and type(expected_count) is int
              and type(expected_bytes) is int and len(rows) == expected_count,
              "manifest population")
    for row in rows:
        C.require(set(row) == {"path", "mode", "type", "sha", "size"}
            and row["type"] == "blob" and row["mode"] in ("100644", "100755")
            and type(row["size"]) is int and row["size"] >= 0,
            "manifest leaf fields")
    rows = sorted(rows, key=lambda row: row["path"])
    C.require(sum(row["size"] for row in rows) == expected_bytes
              and tree(rows) == expected_tree, "manifest Merkle/size binding")
    return rows

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    config_raw, config_pin = C.read_regular(args.config)
    C.require(config_pin["sha256"] == args.sha256, "config SHA")
    q = C.decode(config_raw)
    C.require(q["schema"] == "hia.core-balanced-dispatch.derive8-copy-inputs.v1"
              and q["frozen"] is True, "final frozen config required")
    C.require(tuple(sys.version_info[:3]) == (3, 14, 4), "runtime version")
    C.require(q["runtime"] == _runtime_pin, "fresh fixed runtime config binding")
    C.read_regular(PYTHON, q["runtime"])
    base = Path(q["source_root"])
    C.require(base == BASE_ROOT and base.resolve(strict=True) == base,
              "fixed post-generation donor source root")
    C.require(q["base_tree"] == BASE_TREE and q["base_file_count"] == 4134
              and q["base_bytes"] == 412660165
              and q["candidate_tree"] == INITIAL_TREE
              and q["candidate_file_count"] == 4135
              and q["candidate_bytes"] == 412691868, "fixed input trees/counts/bytes")
    C.require(not N.exists() and N.parent.resolve(strict=True) == N.parent,
              "fresh namespace")
    base_rows = load_manifest(q["base_manifest"], q["base_tree"],
                             q["base_file_count"], q["base_bytes"])
    final_rows = load_manifest(q["candidate_manifest"], q["candidate_tree"],
                              q["candidate_file_count"], q["candidate_bytes"])
    base_by = {row["path"]: row for row in base_rows}
    final_by = {row["path"]: row for row in final_rows}
    C.require(leaves(base) == [row["path"] for row in base_rows],
              "complete donor path population")
    C.require(set(base_by) <= set(final_by), "no source deletion")
    C.require(all(name in final_by for name in DOCS), "two derived documents exist")
    overlays = {}
    external = [config_pin, q["runtime"], q["base_manifest"], q["candidate_manifest"]]
    for item in q["overlays"]:
        name = item["path"]
        C.require(name not in overlays and name in final_by and name in OVERLAY_PINS,
                  "unique exact overlay")
        raw, pin = C.read_regular(item["input"]["path"], item["input"])
        size, digest, blob = OVERLAY_PINS[name]
        C.require(len(raw) == size and C.digest(raw) == digest
                  and git_object("blob", raw) == blob, "frozen overlay body: " + name)
        row = final_by[name]
        C.require(len(raw) == row["size"] and git_object("blob", raw) == row["sha"],
                  "overlay whole body: " + name)
        overlays[name] = (raw, pin)
        external.append(pin)
    changed = {name for name, row in final_by.items() if base_by.get(name) != row}
    C.require(changed == set(overlays) == set(OVERLAY_PINS),
              "exact three-overlay delta")
    C.require(type(q["generation_prerequisites"]) is list
              and len(q["generation_prerequisites"]) > 0,
              "current generation custody inputs required")
    for pin in q["generation_prerequisites"]:
        C.read_regular(pin["path"], pin)
        external.append(pin)
    # No prerequisite is treated as a Source4, fixture6 or cold qualification.
    controls = {}
    for name, (size, digest, blob) in CONTROL_PINS.items():
        raw, pin = C.read_regular(DONOR_CONTROL / name)
        C.require(len(raw) == size and C.digest(raw) == digest
                  and git_object("blob", raw) == blob, "original control: " + name)
        if name == "source_common.py":
            C.require(pin == _common_pin, "same verified imported common identity")
        controls[name] = (raw, pin)
        external.append(pin)
    stage_pin = C.read_regular(Path(__file__).resolve())[1]
    external.append(stage_pin)
    space = os.statvfs(N.parent)
    C.require(space.f_bavail * space.f_frsize >= 1073741824
              and space.f_favail >= 4096, "original free-space admission")
    N.mkdir(mode=0o700)
    (N / "source").mkdir(mode=0o700)
    (N / "control").mkdir(mode=0o700)
    for name, (raw, pin) in controls.items():
        C.save(N / "control" / name, raw)
    materialized = []
    donor_pins = []
    actual_rows = []
    for row in final_rows:
        name = row["path"]
        donor = None
        if name in base_by:
            original, donor = C.read_regular(base / name)
            old = base_by[name]
            C.require(len(original) == old["size"]
                      and git_object("blob", original) == old["sha"],
                      "donor whole body: " + name)
            donor_pins.append(donor)
        else:
            C.require(name in overlays, "new leaf requires explicit overlay")
            original = None
        raw = overlays[name][0] if name in overlays else original
        C.require(len(raw) == row["size"] and git_object("blob", raw) == row["sha"],
                  "candidate whole body: " + name)
        target = N / "source" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        C.save(target, raw)
        if row["mode"] == "100755":
            target.chmod(0o700)
        copied, pin = C.read_regular(target)
        C.require(copied == raw, "copied whole body: " + name)
        materialized.append({"path": name, "baseline": base_by.get(name),
            "donor": donor,
            "candidate": {"bytes": len(raw), "sha256": C.digest(raw),
                          "git_blob": row["sha"], "git_mode": row["mode"]},
            "physical": pin["identity"]})
        actual_rows.append({**row, "size": len(copied),
                            "sha": git_object("blob", copied)})
    C.require(leaves(base) == [row["path"] for row in base_rows],
              "donor population after")
    for pin in donor_pins:
        C.read_regular(pin["path"], pin)
    for pin in external:
        C.read_regular(pin["path"], pin)
    C.require(actual_rows == final_rows
              and leaves(N / "source") == [row["path"] for row in final_rows]
              and tree(actual_rows) == q["candidate_tree"], "complete clone")
    root = N / "source"
    out = N / "derive8-actual-r1"
    materialization = C.save_json(N / "MATERIALIZATION.json", {
        "schema": "hia.core-balanced-dispatch.derive8-materialization.v1",
        "status": "PREPARED_ONLY_NO_DERIVATION_OR_SOURCE_METHOD",
        "file_count": len(final_rows), "source_root": str(root),
        "donor_root": str(base), "base_tree": q["base_tree"],
        "initial_tree": q["candidate_tree"], "files": materialized})
    # Passive transport of the same full materialization; no source extraction or execution.
    materialization_raw = C.read_regular(materialization["path"], materialization)[0]
    materialization_packed = gzip.compress(materialization_raw, compresslevel=6, mtime=0)
    C.require(len(materialization_packed) <= 16 << 20, "metadata transport bound")
    materialization_gzip = C.save(N / "MATERIALIZATION.json.gz", materialization_packed)
    C.read_regular(materialization["path"], materialization)
    owner = C.read_regular(root / "tools/hia_selfhost_process_owner.py")[1]
    C.require(owner["bytes"] == 17601 and owner["sha256"] ==
              "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2",
              "original owner implementation")
    environment = {"PATH": "", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                   "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0",
                   "PYTHONNOUSERSITE": "1", "TMPDIR": str(out / "scratch")}
    request_path = N / "control" / "REQUEST.json"
    inputs = {}
    for pin in [*external, materialization, owner,
                *(C.read_regular(N / "control" / name)[1] for name in CONTROL_PINS)]:
        C.require(pin["path"] not in inputs or inputs[pin["path"]] == pin,
                  "conflicting input role")
        inputs[pin["path"]] = pin
    request = {
        "schema": C.SCHEMA,
        "scope": "balanced Core fixture document derivation only",
        "schema_note": "unchanged donor wire-leaf05 schema is a format label",
        "source_root": str(root), "source_file_count": len(final_rows),
        "output_root": str(out), "runtime": q["runtime"],
        "owner_implementation": owner, "materialization": materialization,
        "inputs": [inputs[path] for path in sorted(inputs)],
        "boot_id": Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "qualification_seconds": 180, "cleanup_seconds": 3,
        "minimum_free_bytes": 1073741824, "minimum_free_inodes": 4096,
        "environment": environment, "commands": COMMANDS,
        "generated_write_paths": DOCS, "allowed_changed_documents": DOCS,
        "unchanged_generated_paths": [],
        "provenance": {"config_sha256": config_pin["sha256"],
            "base_tree": q["base_tree"], "initial_tree": q["candidate_tree"],
            "generation_prerequisites": q["generation_prerequisites"],
            "prior_source_method_pass_inherited": False},
        "worker_command_template": [
            q["runtime"]["path"], "-I", "-S", "-B", str(N / "control/derive_worker.py"),
            "--request", str(request_path), "--sha256", "<REQUEST-SHA256>"]}
    req = C.save_json(request_path, request)
    launch = C.save_json(N / "LAUNCH.json", {
        "command": [q["runtime"]["path"], "-I", "-S", "-B",
                    str(N / "control/derive_launch.py"), "--request",
                    str(request_path), "--sha256", req["sha256"]],
        "cwd": str(root), "env": environment, "request": req,
        "qualification_seconds": 180, "cleanup_seconds": 3,
        "execution": "NOT_EXECUTED_ROOT_ONLY"})
    C.save_json(N / "MATERIALIZE-REPORT.json", {
        "status": "PREPARED_ONLY", "source_file_count": len(final_rows),
        "source_bytes": sum(row["size"] for row in final_rows),
        "initial_tree": q["candidate_tree"], "request": req, "launch": launch,
        "materialization": materialization, "materialization_gzip": materialization_gzip,
        "materialization_transport_only": True,
        "donor_whole_bytes_and_nine_identities_stable": True,
        "core_author_write_calls": 0, "derive_commands": 0,
        "source_methods": 0, "VM": 0, "native": 0, "network": 0})
    print("PREPARED_ONLY")

if __name__ == "__main__":
    main()
