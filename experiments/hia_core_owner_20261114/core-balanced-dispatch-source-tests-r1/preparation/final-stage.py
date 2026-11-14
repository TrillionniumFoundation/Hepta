"""Metadata only: freeze two original source groups against the closed N2 tree."""
from __future__ import annotations
import argparse
import ast
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import time
import traceback
import types

CONFIG_SCHEMA = "hia.core-balanced-dispatch.source-tests-preparation-inputs.v1"
CONFIG_SHA256 = "d947170d1560e8b0709e68f9176db18263db22da1c7bfc11240ae1564395e84a"
CONFIG_BYTES = 7132
CONFIG_GIT = "0b38a2d906b492c4b6bc47de7bbedf6c510356fe"
SOURCE_SCHEMA = "hia.core-balanced-dispatch.original-source-tests.v1"
FIELDS = ("dev", "ino", "mode", "uid", "gid", "nlink", "size", "mtime_ns", "ctime_ns")
CONFIG_KEYS = {
    "schema", "runtime", "boot_id", "source_root", "stage_root",
    "old_materialization", "final_snapshot", "owner_implementation", "controls",
    "derive8_prerequisites", "final_file_count", "final_total_bytes", "final_tree",
    "source_map_count", "source_map_sha256", "support_document", "coverage_document",
    "minimum_free_bytes", "minimum_free_inodes", "derive8_HJOB",
}
BASE_ENV = {
    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "PATH": "",
    "PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0", "PYTHONNOUSERSITE": "1",
}
CONTROL_NAMES = {
    "common": "source_common.py", "child": "source_tests_child.py", "launch": "launch.py",
}
CONTROL_BODIES = {
    "common": (9376, "a03e29a99c29c3b88343c1db4334be8680b41faf54874175e2c68235d4e34537",
               "cc72ac269fb8cd1619c8e3e0290b87aa9baee4a1"),
    "child": (19322, "aa9f537cf0cce13d1e6703ed3e86aa82aec2fc8507a71e010fb4120a20a63757",
              "97c3bf031c54735e1ff68d79aa5be959c2b21411"),
    "launch": (11124, "e88c38da56b297edbcab31c2aa59735af26a52826671ffb3d8c04ca6b80e99cb",
               "2b272ee4395b1103e89368cdec4351e1b6c1a504"),
}
SUPPORT = "docs/HIA_SELFHOST_CORE_SUPPORT.json"

def require(value, message):
    if not value:
        raise RuntimeError(message)

def object_sha(kind, raw):
    return hashlib.sha1(kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

def identity(info):
    return {
        "dev": info.st_dev, "ino": info.st_ino, "mode": stat.S_IMODE(info.st_mode),
        "uid": info.st_uid, "gid": info.st_gid, "nlink": info.st_nlink,
        "size": info.st_size, "mtime_ns": info.st_mtime_ns, "ctime_ns": info.st_ctime_ns,
    }

def pin_shape(pin):
    require(type(pin) is dict and set(pin) == {"path", "bytes", "sha256", "identity"}, "pin fields")
    require(type(pin["path"]) is str and Path(pin["path"]).is_absolute(), "absolute pin path")
    require(type(pin["bytes"]) is int and pin["bytes"] >= 0, "pin size")
    require(type(pin["sha256"]) is str and len(pin["sha256"]) == 64
            and all(c in "0123456789abcdef" for c in pin["sha256"]), "pin SHA256")
    ids = pin["identity"]
    require(type(ids) is dict and set(ids) == set(FIELDS)
            and all(type(ids[k]) is int for k in FIELDS)
            and ids["size"] == pin["bytes"], "exact integer nine-field identity")

def bootstrap_read(path, expected=None):
    path = Path(path).absolute()
    require(path.resolve(strict=True) == path, "bootstrap file alias")
    for parent in path.parents:
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                "bootstrap ancestor")
    fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    try:
        initial = os.fstat(fd)
        require(stat.S_ISREG(initial.st_mode) and initial.st_nlink == 1
                and initial.st_uid in (0, os.geteuid())
                and not stat.S_IMODE(initial.st_mode) & 0o022, "unsafe bootstrap file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            raw = stream.read()
        require(identity(initial) == identity(os.fstat(fd)) == identity(path.lstat()),
                "bootstrap identity changed")
    finally:
        os.close(fd)
    pin = {"path": str(path), "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
           "identity": identity(initial)}
    pin_shape(pin)
    if expected is not None:
        pin_shape(expected)
        require(pin == expected, "bootstrap fixed pin mismatch: " + str(path))
    return raw, pin

def no_duplicate_pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result

def relative_name(name):
    require(type(name) is str and name and "\0" not in name, "relative source name")
    parts = PurePosixPath(name).parts
    require(not name.startswith("/") and all(x not in ("", ".", "..") for x in parts)
            and "/".join(parts) == name, "noncanonical relative source name")
    return parts

def namespace(root):
    require(root.resolve(strict=True) == root, "source root alias")
    result = {}
    def fail(error):
        raise error
    for directory, dirs, files in os.walk(root, topdown=True, followlinks=False, onerror=fail):
        dirs.sort()
        files.sort()
        for name in dirs:
            path = Path(directory) / name
            info = path.lstat()
            require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                    "source directory link/special")
        for name in files:
            path = Path(directory) / name
            info = path.lstat()
            require(stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode),
                    "source nonregular leaf")
            rel = path.relative_to(root).as_posix()
            relative_name(rel)
            require(rel not in result, "duplicate source path")
            result[rel] = identity(info)
    return dict(sorted(result.items()))

def git_tree(records):
    tree = {}
    for name, record in records.items():
        parts = relative_name(name)
        current = tree
        for part in parts[:-1]:
            current = current.setdefault(part, {})
            require(type(current) is dict, "Git file/directory conflict")
        require(parts[-1] not in current, "duplicate Git path")
        require(record["mode"] in ("100644", "100755"), "unsupported Git source mode")
        current[parts[-1]] = (record["mode"], record["sha"])
    def one(node):
        entries = []
        for name, value in node.items():
            directory = type(value) is dict
            encoded = name.encode("utf-8")
            mode, digest = ("40000", one(value)) if directory else value
            entries.append((encoded + (b"/" if directory else b""),
                            mode.encode() + b" " + encoded + b"\0" + bytes.fromhex(digest)))
        payload = b"".join(value for _, value in sorted(entries))
        return object_sha("tree", payload)
    return one(tree)

def constants_from_child(raw):
    tree = ast.parse(raw, filename=CONTROL_NAMES["child"])
    values = {}
    for name in ("GROUPS", "ORIGINAL_TEST_FILES"):
        matches = [node for node in tree.body if isinstance(node, ast.Assign)
                   and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name)
                   and node.targets[0].id == name]
        require(len(matches) == 1, "one frozen child constant: " + name)
        values[name] = ast.literal_eval(matches[0].value)
    groups, originals = values["GROUPS"], values["ORIGINAL_TEST_FILES"]
    require(type(groups) is dict and set(groups) == {"source4", "fixture6"}, "two groups")
    for group, count in (("source4", 4), ("fixture6", 6)):
        ids = groups[group]
        require(type(ids) is list and len(ids) == len(set(ids)) == count
                and all(type(x) is str and x.startswith("tests.") for x in ids), "exact group IDs")
    require(type(originals) is list and len(originals) == 6
            and len({row["path"] for row in originals}) == 6, "six original test files")
    return groups, originals

def unique_pins(items):
    result = {}
    for pin in items:
        pin_shape(pin)
        old = result.setdefault(pin["path"], pin)
        require(old == pin, "conflicting input pin")
    return [result[name] for name in sorted(result)]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--sha256", required=True)
    args = parser.parse_args()
    os.umask(0o077)
    require(args.config.is_absolute(), "absolute config argv")
    config_raw, config_pin = bootstrap_read(args.config)
    require(args.sha256 == CONFIG_SHA256 == config_pin["sha256"]
            and len(config_raw) == CONFIG_BYTES and object_sha("blob", config_raw) == CONFIG_GIT,
            "exact frozen CONFIG")
    config = json.loads(config_raw, object_pairs_hook=no_duplicate_pairs)
    require(type(config) is dict and set(config) == CONFIG_KEYS
            and config["schema"] == CONFIG_SCHEMA, "exact actual CONFIG keys/schema")
    author_path = Path(__file__).absolute()
    author_raw, author_pin = bootstrap_read(author_path)
    runtime_raw, runtime_pin = bootstrap_read(config["runtime"]["path"], config["runtime"])
    del runtime_raw
    require(Path(sys.executable).resolve(strict=True) == Path(config["runtime"]["path"])
            and tuple(sys.version_info[:3]) == (3, 14, 4), "fixed runtime")
    require(sys.flags.isolated == 1 and sys.flags.no_site == 1
            and sys.dont_write_bytecode is True, "metadata -I -S -B")
    expected_argv = [config["runtime"]["path"], "-I", "-S", "-B", str(author_path),
                     "--config", str(args.config), "--sha256", args.sha256]
    require(sys.orig_argv == expected_argv, "literal metadata argv")
    require(Path.cwd() == Path("/") and dict(os.environ) == BASE_ENV, "literal metadata cwd/env")
    require(Path("/proc/sys/kernel/random/boot_id").read_text().strip() == config["boot_id"],
            "host incarnation")
    require(not any(x.split(".", 1)[0] in {"hepta", "tools", "tests"} for x in sys.modules),
            "project already imported")
    require(set(config["controls"]) == set(CONTROL_NAMES), "three frozen controls")
    common_raw, common_source_pin = bootstrap_read(
        config["controls"]["common"]["path"], config["controls"]["common"])
    require((len(common_raw), hashlib.sha256(common_raw).hexdigest(), object_sha("blob", common_raw))
            == CONTROL_BODIES["common"], "selected common body")
    root, stage = Path(config["source_root"]), Path(config["stage_root"])
    control = stage / "control"
    require(root.is_absolute() and stage.is_absolute() and root.resolve(strict=True) == root
            and stage.parent.resolve(strict=True) == stage.parent and not stage.exists(),
            "fixed source and fresh stage roots")
    require(not root.is_relative_to(stage) and not stage.is_relative_to(root), "disjoint stage/source")
    require(config["final_file_count"] == 4135 and config["final_total_bytes"] == 412691995
            and config["final_tree"] == "cd7d49368f9621ea9379ba32c3f1f969a28c65b4"
            and config["source_map_count"] == 900
            and config["source_map_sha256"] ==
                "8f8c3f07735391ec0d095dcaca9bd10c8d7f12bf8c32aa763195bee365885179"
            and config["minimum_free_bytes"] == 1073741824
            and config["minimum_free_inodes"] == 4096, "fixed finite source/capacity")
    output_roots = {group: stage / (group + "-actual-r1") for group in ("source4", "fixture6")}
    allowed_names = set(CONTROL_NAMES.values()) | {
        "MATERIALIZATION.json", "SOURCE-MAP.json",
        "REQUEST-source4.json", "REQUEST-fixture6.json",
        "LAUNCH-source4.json", "LAUNCH-fixture6.json",
        "STATIC-FREEZE.json", "PREPARATION-HOLD.json",
    }
    allowed_writes = {control / name for name in allowed_names}
    forbidden = []
    def deny(label):
        forbidden.append(label)
        raise RuntimeError("metadata-only forbidden action: " + label)
    def audit(event, values):
        if event == "import" and values[0].split(".", 1)[0] in {"hepta", "tools", "tests"}:
            deny("project import:" + values[0])
        if event in {"subprocess.Popen", "os.system", "os.posix_spawn", "os.fork", "os.forkpty",
                     "os.exec", "ctypes.dlopen", "ctypes.dlsym", "mmap.__new__"} or event.startswith("socket."):
            deny(event)
        if event == "open":
            path, mode, flags = values
            writing = ((isinstance(mode, str) and any(x in mode for x in "wax+"))
                or (isinstance(flags, int) and
                    flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC | os.O_APPEND)))
            if writing:
                name = (os.readlink("/proc/self/fd/" + str(path))
                        if isinstance(path, int) else os.fsdecode(os.fspath(path)))
                if Path(os.path.abspath(name)).resolve(strict=False) not in allowed_writes:
                    deny("write:" + name)
        if event == "os.mkdir" and Path(os.path.abspath(os.fspath(values[0]))) not in {stage, control}:
            deny("mkdir")
        if event in {"os.remove", "os.rmdir", "os.rename", "os.link", "os.symlink",
                     "os.chmod", "os.chown", "os.utime", "os.truncate"}:
            deny(event)
    sys.addaudithook(audit)
    C = types.ModuleType("_frozen_source_tests_metadata_common")
    C.__file__ = config["controls"]["common"]["path"]
    # Load only the exact bytes admitted above; never let a loader reread unbound code.
    exec(compile(common_raw, C.__file__, "exec", dont_inherit=True), C.__dict__)
    require(C.SCHEMA == SOURCE_SCHEMA and C.FIELDS == FIELDS, "frozen common interface")
    report = {
        "schema": "hia.core-balanced-dispatch.source-tests-static-freeze.v1",
        "status": "HOLD", "config": config_pin, "author": author_pin,
        "bootstrap": {"argv": expected_argv, "cwd": "/", "environment": dict(os.environ),
                      "runtime": runtime_pin, "boot_id": config["boot_id"]},
        "metadata_has_product_owner": False, "metadata_outer_timeout_claimed": False,
        "source_tests_executed": False, "generation_executed": False,
        "VM_native_or_machine_compiler_executed": False,
        "source_files_copied": 0, "project_imports": [], "errors": [],
        "forbidden_attempts": forbidden, "derive8_HJOB_git_provenance_only": config["derive8_HJOB"],
    }
    created = False
    started = time.monotonic_ns()
    try:
        raw_controls, source_controls = {"common": common_raw}, {"common": common_source_pin}
        for name in ("child", "launch"):
            raw, pin = C.read_regular(config["controls"][name]["path"], config["controls"][name])
            require((len(raw), C.digest(raw), object_sha("blob", raw)) == CONTROL_BODIES[name],
                    "frozen control body: " + name)
            raw_controls[name], source_controls[name] = raw, pin
        for name, raw in raw_controls.items():
            ast.parse(raw, filename=CONTROL_NAMES[name])
        groups, originals = constants_from_child(raw_controls["child"])
        prerequisite_pins = config["derive8_prerequisites"]
        require(type(prerequisite_pins) is list and len(prerequisite_pins) == 5,
                "five exact derive8 prerequisites")
        by_name = {}
        for pin in prerequisite_pins:
            pin_shape(pin)
            name = Path(pin["path"]).name
            require(name not in by_name, "duplicate prerequisite basename")
            by_name[name] = pin
        require(set(by_name) == {"REQUEST.json", "process-owner.json",
            "process-owner.json.request.json", "owner-wrapper.json", "derive8-report.json"},
            "fixed derive8 prerequisite roles")
        dq_pin = by_name["REQUEST.json"]
        dq = C.decode(C.read_regular(dq_pin["path"], dq_pin)[0])
        owner_pin = by_name["process-owner.json"]
        child_pin = by_name["process-owner.json.request.json"]
        wrapper_pin = by_name["owner-wrapper.json"]
        owner_before = C.decode(C.read_regular(owner_pin["path"], owner_pin)[0])
        child_before = C.decode(C.read_regular(child_pin["path"], child_pin)[0])
        wrapper = C.decode(C.read_regular(wrapper_pin["path"], wrapper_pin)[0])
        template = dq["worker_command_template"]
        require(dq.get("worker_command") is None and type(template) is list and len(template) == 9
                and template[:4] == [config["runtime"]["path"], "-I", "-S", "-B"]
                and Path(template[4]).parent == Path(dq_pin["path"]).parent
                and template[5:] == ["--request", dq_pin["path"], "--sha256", "<REQUEST-SHA256>"],
                "prior literal worker template")
        dq["worker_command"] = [*template[:-1], dq_pin["sha256"]]
        prior_implementation = dq["owner_implementation"]
        pin_shape(prior_implementation)
        require(dq["runtime"] == config["runtime"] and dq["source_root"] == str(root)
                and dq["materialization"] == config["old_materialization"]
                and dq["source_file_count"] == config["final_file_count"]
                and prior_implementation["bytes"] == config["owner_implementation"]["bytes"] == 17601
                and prior_implementation["sha256"] == config["owner_implementation"]["sha256"] ==
                    "36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2",
                "prior source/runtime/materialization and exact original owner body")
        if not Path(prior_implementation["path"]).is_relative_to(root):
            C.read_regular(prior_implementation["path"], prior_implementation)
        old_output = Path(dq["output_root"])
        require(Path(owner_pin["path"]) == old_output / "process-owner.json"
                and Path(child_pin["path"]) == old_output / "process-owner.json.request.json"
                and Path(wrapper_pin["path"]) == old_output / "owner-wrapper.json"
                and Path(by_name["derive8-report.json"]["path"]) == old_output / "derive8-report.json"
                and Path(config["final_snapshot"]["path"]) == old_output / "source-after.json",
                "prior exact output paths")
        life, child_request, natural = C.bind_closed(dq, wrapper, Path(owner_pin["path"]))
        require(life == owner_before and child_request == child_before and natural is True,
                "prior natural original180/3 and ECHILD")
        report["prior_owner_admission"] = {
            "request": dq_pin, "lifecycle": owner_pin, "child_request": child_pin,
            "wrapper": wrapper_pin, "implementation": prior_implementation,
            "natural_zero": True, "ECHILD": True,
            "qualification_seconds": 180, "cleanup_seconds": 3,
        }
        # Child bodies are first opened only after the preceding admission.
        old_report_pin = by_name["derive8-report.json"]
        old_report = C.decode(C.read_regular(old_report_pin["path"], old_report_pin)[0])
        final_raw, final_pin = C.read_regular(config["final_snapshot"]["path"], config["final_snapshot"])
        after = C.decode(final_raw)
        old_raw, old_pin = C.read_regular(config["old_materialization"]["path"], config["old_materialization"])
        old = C.decode(old_raw)
        report["prior_child_report"] = {"pin": old_report_pin,
            "status_observed": old_report.get("status"), "semantic_requalification_performed": False}
        require(type(old) is dict and old["source_root"] == str(root)
                and old["file_count"] == config["final_file_count"], "old MAT source/count")
        rows = old["files"]
        require(type(rows) is list and len(rows) == config["final_file_count"], "old MAT rows")
        names = [row["path"] for row in rows]
        require(names == sorted(names) and len(set(names)) == len(names)
                and type(after) is dict and sorted(after) == names, "same complete4135 population")
        allowed = dq["generated_write_paths"]
        require(type(allowed) is list and len(allowed) == len(set(allowed)) == 2
                and SUPPORT in allowed and set(dq["allowed_changed_documents"]) == set(allowed),
                "two original derived documents")
        coverage = next(name for name in allowed if name != SUPPORT)
        require(coverage in after, "coverage document is in final source")
        first_namespace = namespace(root)
        require(list(first_namespace) == names, "actual4135 namespace")
        observed, git_records, new_rows = {}, {}, []
        documents = {}
        body_changes, identity_changes = [], []
        total = 0
        for row in rows:
            rel = row["path"]
            relative_name(rel)
            expected = after[rel]
            pin_shape(expected)
            require(expected["path"] == str(root / rel)
                    and expected["identity"] == first_namespace[rel], "snapshot/namespace identity: " + rel)
            before = row["candidate"]
            physical = row["physical"]
            require(type(physical) is dict and set(physical) == set(FIELDS)
                    and all(type(physical[k]) is int for k in FIELDS), "old exact identity")
            changed = (before["bytes"], before["sha256"]) != (expected["bytes"], expected["sha256"])
            changed_identity = physical != expected["identity"]
            if changed:
                body_changes.append(rel)
            if changed_identity:
                identity_changes.append(rel)
            if rel not in allowed:
                require(not changed and not changed_identity, "non-document source changed: " + rel)
            else:
                require(all(physical[k] == expected["identity"][k]
                    for k in ("dev", "ino", "mode", "uid", "gid", "nlink")), "document stable identity")
            mode = before["git_mode"]
            require(mode in ("100644", "100755")
                    and mode == ("100755" if expected["identity"]["mode"] & stat.S_IXUSR else "100644"),
                    "original Git mode: " + rel)
            raw, pin = C.read_regular(root / rel, expected)
            observed[rel] = pin
            git_records[rel] = {"mode": mode, "sha": object_sha("blob", raw)}
            total += len(raw)
            new_rows.append({"path": rel, "candidate": {"bytes": len(raw), "sha256": pin["sha256"]},
                             "physical": pin["identity"]})
            if rel in allowed:
                documents[rel] = raw
            del raw
        require(len(observed) == config["final_file_count"] and total == config["final_total_bytes"],
                "actual source count/bytes")
        require(set(body_changes) == {SUPPORT} and set(identity_changes) <= set(allowed),
                "only support bytes changed; only two original documents may change identity")
        for rel, wanted in ((SUPPORT, config["support_document"]), (coverage, config["coverage_document"])):
            require(len(documents[rel]) == wanted["bytes"]
                    and C.digest(documents[rel]) == wanted["sha256"]
                    and git_records[rel]["sha"] == wanted["git"], "fixed complete document pin")
        require(config["owner_implementation"] == observed["tools/hia_selfhost_process_owner.py"],
                "actual original owner identity")
        if Path(prior_implementation["path"]).is_relative_to(root):
            rel = Path(prior_implementation["path"]).relative_to(root).as_posix()
            require(prior_implementation == observed[rel], "prior owner physical identity")
        for wanted in originals:
            require(set(wanted) == {"path", "bytes", "sha256", "git_blob"}, "old test pin fields")
            actual = observed[wanted["path"]]
            require((actual["bytes"], actual["sha256"], git_records[wanted["path"]]["sha"]) ==
                    (wanted["bytes"], wanted["sha256"], wanted["git_blob"]),
                    "complete original test file: " + wanted["path"])
        actual_tree = git_tree(git_records)
        require(actual_tree == config["final_tree"], "complete final Git tree")
        support = C.decode(documents[SUPPORT])
        declared = support["source_identity"]["files"]
        require(type(declared) is dict and len(declared) == 899 and SUPPORT not in declared,
                "exact899 source declarations")
        source_map = dict(declared)
        source_map[SUPPORT] = observed[SUPPORT]["sha256"]
        require(len(source_map) == config["source_map_count"]
                and all(type(name) is str and name in observed and type(value) is str
                    and value == observed[name]["sha256"] for name, value in source_map.items()),
                "all900 source hashes join actual full tree")
        map_raw = json.dumps(source_map, sort_keys=True, separators=(",", ":")).encode("utf-8")
        require(C.digest(map_raw) == config["source_map_sha256"], "exact compact/noLF900 map")
        require(namespace(root) == {name: observed[name]["identity"] for name in sorted(observed)},
                "source identities changed during metadata read")
        resource = os.statvfs(stage.parent)
        require(resource.f_bavail * resource.f_frsize >= config["minimum_free_bytes"]
                and resource.f_favail >= config["minimum_free_inodes"], "fixed metadata/source capacity")
        require(all(not value.exists() for value in output_roots.values()), "no actual output exists")
        stage.mkdir(mode=0o700)
        control.mkdir(mode=0o700)
        created = True
        selected_controls = {}
        for name, raw in raw_controls.items():
            selected_controls[name] = C.save(control / CONTROL_NAMES[name], raw)
            require((selected_controls[name]["bytes"], selected_controls[name]["sha256"])
                    == (source_controls[name]["bytes"], source_controls[name]["sha256"]),
                    "safe copy bytes unchanged")
        materialization = {
            "schema": "hia.core-balanced-dispatch.source-tests-materialization.v1",
            "source_root": str(root), "file_count": config["final_file_count"],
            "total_bytes": total, "tree": actual_tree,
            "source_map_count": len(source_map), "source_map_sha256": C.digest(map_raw),
            "provenance": {"old_materialization": old_pin, "closed_source_after": final_pin,
                          "derive8_HJOB_git_reference_only": config["derive8_HJOB"]},
            "files": new_rows,
        }
        materialization_pin = C.save_json(control / "MATERIALIZATION.json", materialization)
        map_pin = C.save(control / "SOURCE-MAP.json", map_raw)
        input_pins = unique_pins([
            config_pin, author_pin, runtime_pin, config["owner_implementation"], prior_implementation,
            old_pin, final_pin, *prerequisite_pins, *source_controls.values(),
            *selected_controls.values(), materialization_pin, map_pin,
        ])
        requests, launches = {}, {}
        for group in ("source4", "fixture6"):
            request_path = control / ("REQUEST-" + group + ".json")
            output = output_roots[group]
            environment = dict(BASE_ENV)
            environment.update({
                "TMPDIR": str(output / "scratch"),
                "HEPTA_COMPARE_BASE_ROOT": str(root),
                "HEPTA_COMPARE_CONTROL_EVIDENCE": str(output / "scratch/comparison-evidence"),
            })
            request = {
                "schema": SOURCE_SCHEMA, "runtime": runtime_pin, "boot_id": config["boot_id"],
                "owner_implementation": config["owner_implementation"],
                "source_root": str(root), "source_file_count": config["final_file_count"],
                "source_total_bytes": total, "source_tree": actual_tree,
                "materialization": materialization_pin, "source_map": map_pin,
                "source_map_count": len(source_map), "source_map_sha256": C.digest(map_raw),
                "inputs": input_pins, "group": group, "requested_ids": groups[group],
                "expected_tests": len(groups[group]), "output_root": str(output),
                "generated_write_paths": [], "allowed_changed_documents": [],
                "unchanged_generated_paths": [], "qualification_seconds": 180, "cleanup_seconds": 3,
                "minimum_free_bytes": config["minimum_free_bytes"],
                "minimum_free_inodes": config["minimum_free_inodes"], "environment": environment,
                "worker_command": None,
                "worker_command_template": [runtime_pin["path"], "-I", "-S", "-B",
                    str(control / "source_tests_child.py"), "--request", str(request_path),
                    "--sha256", "<REQUEST-SHA256>"],
                "preparation_config": config_pin, "preparation_author": author_pin,
                "derive8_HJOB_git_provenance_only": config["derive8_HJOB"],
            }
            request_pin = C.save_json(request_path, request)
            launch = {
                "schema": "hia.core-balanced-dispatch.original-source-tests-launch.v1",
                "group": group, "request": request_pin, "cwd": "/", "environment": dict(BASE_ENV),
                "command": [runtime_pin["path"], "-I", "-S", "-B", str(control / "launch.py"),
                            "--request", str(request_path), "--sha256", request_pin["sha256"]],
                "qualification_seconds": 180, "cleanup_seconds": 3,
                "output_root": str(output), "execution_authority": "ROOT_ONLY_NOT_EXECUTED",
                "outer_watchdog_not_assigned_by_this_metadata_stage": True,
            }
            requests[group] = request_pin
            launches[group] = C.save_json(control / ("LAUNCH-" + group + ".json"), launch)
        # No second source-content pass: close all actual4135 path/identity records.
        require(namespace(root) == {name: observed[name]["identity"] for name in sorted(observed)},
                "source changed before freeze completion")
        for pin in input_pins:
            path = Path(pin["path"])
            if path.is_relative_to(root):
                require(pin == observed[path.relative_to(root).as_posix()]
                        and identity(path.lstat()) == pin["identity"], "source input changed at close")
            else:
                C.read_regular(path, pin)
        require(all(not value.exists() for value in output_roots.values()), "actual roots remain absent")
        require(not any(x.split(".", 1)[0] in {"hepta", "tools", "tests"} for x in sys.modules)
                and not forbidden, "no project import or forbidden action")
        expected_names = set(CONTROL_NAMES.values()) | {
            "MATERIALIZATION.json", "SOURCE-MAP.json",
            "REQUEST-source4.json", "REQUEST-fixture6.json",
            "LAUNCH-source4.json", "LAUNCH-fixture6.json",
        }
        require({path.name for path in control.iterdir()} == expected_names, "exact prepared namespace")
        report.update({
            "status": "PREPARED_ONLY", "selected_controls": selected_controls,
            "supplied_controls": source_controls, "materialization": materialization_pin,
            "source_map": map_pin, "requests": requests, "launches": launches,
            "source": {"root": str(root), "file_count": len(observed), "bytes": total,
                "git_tree": actual_tree, "source_map_count": len(source_map),
                "source_map_sha256": C.digest(map_raw), "full_content_reads": len(observed),
                "final_identity_namespace_equal": True, "body_changes_from_old_MAT": body_changes,
                "identity_changes_from_old_MAT": identity_changes},
            "original_test_files": originals, "groups": groups,
            "actual_output_roots_absent": [str(value) for value in output_roots.values()],
            "elapsed_ns": time.monotonic_ns() - started,
        })
        report_pin = C.save_json(control / "STATIC-FREEZE.json", report)
        print(json.dumps({"status": "PREPARED_ONLY", "report": report_pin,
                          "requests": requests, "launches": launches}, sort_keys=True))
        return 0
    except BaseException as error:
        report["status"] = "HOLD"
        report["errors"].append({"type": type(error).__name__, "message": str(error),
                                "traceback": traceback.format_exc()})
        report["elapsed_ns"] = time.monotonic_ns() - started
        traceback.print_exc()
        if created:
            try:
                pin = C.save_json(control / "PREPARATION-HOLD.json", report)
                print(json.dumps({"status": "HOLD", "report": pin}, sort_keys=True))
            except BaseException as saving_error:
                print(json.dumps({"status": "HOLD", "original_error": str(error),
                                  "hold_save_error": str(saving_error)}, sort_keys=True), file=sys.stderr)
        return 1

if __name__ == "__main__":
    raise SystemExit(main())
