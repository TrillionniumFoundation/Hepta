"""Create S2 after preserving S1; change only the source83 launcher closure guard."""
from pathlib import Path
from hashlib import sha256, sha1
import ast
import difflib
import importlib.util
import json
import sys

BASE = Path("/workspace/scratch/e26ed3e2edcf/core-numeric-source83-on-v89-r1")
HERE = Path(__file__).resolve().parent

def save(name, value):
    with (HERE / name).open("x") as output:
        json.dump(value, output, sort_keys=True, indent=2)
        output.write("\n")

def digest(raw):
    return {"size": len(raw), "sha256": sha256(raw).hexdigest(),
            "git_blob_sha1": sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}

def replace_once(raw, old, new):
    assert raw.count(old) == 1, old
    return raw.replace(old, new, 1)

def main():
    for name in ("BASE-GIT-TREE.json", "BASE-MATERIALIZATION.json", "EXPECTED-SOURCE-IDS.json",
                 "SOURCE-DELTA.diff", "SOURCE-DELTA.json", "SOURCE-PHYSICAL-PINS.json"):
        with (HERE / name).open("xb") as output:
            output.write((BASE / name).read_bytes())
    for prefix in ("control", "inputs"):
        for source in sorted((BASE / prefix).rglob("*")):
            if source.is_file():
                target = HERE / source.relative_to(BASE)
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("xb") as output:
                    output.write(source.read_bytes())
    old = (BASE / "control/launch.py").read_text()
    raw = replace_once(old, "    try:\n        returned = owner.run_owned", """    closed = False
    parent_pins = [pin(folder / 'RESOURCE-OBSERVATION.json')]
    try:
        returned = owner.run_owned""")
    before = """        save(folder / 'wrapper.json', returned)
        life_raw = (folder / 'lifecycle.json').read_bytes()
        life = json.loads(life_raw)
        require(returned['receipt_sha256'] == sha256(life_raw).hexdigest()
                and all(returned.get(key) == value for key, value in life.items())
                and returned['supervisor_returncode'] == 0,
                'original lifecycle/wrapper binding differs')
        cleanup = life['cleanup']
"""
    after = """        save(folder / 'wrapper.json', returned)
        parent_pins.append(pin(folder / 'wrapper.json'))
        provisional = returned.get('cleanup', {})
        require(type(returned.get('supervisor_returncode')) is int
                and type(returned.get('receipt_sha256')) is str
                and provisional.get('complete') is True
                and provisional.get('observed_echild') is True
                and provisional.get('leader_reaped') is True
                and provisional.get('deadline_exceeded') is False
                and provisional.get('errors') == []
                and provisional.get('remaining_direct_children') == [],
                'owner closure is unconfirmed; child originals must not be read')
        life_path = folder / 'lifecycle.json'
        life_pin = pin(life_path)
        life_raw = life_path.read_bytes()
        require(sha256(life_raw).hexdigest() == life_pin['sha256']
                and pin(life_path) == life_pin, 'owner receipt changed while binding')
        life = json.loads(life_raw)
        request_path = folder / 'lifecycle.json.request.json'
        request_pin = pin(request_path)
        owner_request_raw = request_path.read_bytes()
        require(sha256(owner_request_raw).hexdigest() == request_pin['sha256']
                and pin(request_path) == request_pin, 'owner request changed while binding')
        owner_request = json.loads(owner_request_raw)
        require(returned['receipt_sha256'] == sha256(life_raw).hexdigest()
                and {key: value for key, value in returned.items()
                     if key not in {'receipt_sha256', 'supervisor_returncode'}} == life,
                'original lifecycle/wrapper binding differs')
        require(owner_request['schema'] == life['schema'] == 'hepta.hia.selfhost-process-owner.v1'
                and life['request_sha256'] == sha256(owner_request_raw).hexdigest()
                and owner_request['command'] == command and owner_request['cwd'] == str(HERE)
                and owner_request['env'] == environment
                and owner_request['stdout_path'] == str(folder / 'child.stdout.log')
                and owner_request['stderr_path'] == str(folder / 'child.stderr.log')
                and owner_request['receipt_path'] == str(life_path)
                and owner_request['qualification_seconds'] == life['qualification_seconds'] == 180
                and owner_request['cleanup_seconds'] == life['cleanup_seconds'] == 3
                and owner_request['implementation_sha256'] == life['implementation_sha256'] == expected['sha256']
                and type(owner_request['started_ns']) is int
                and type(owner_request['deadline_ns']) is int
                and owner_request['deadline_ns'] - owner_request['started_ns'] == 180_000_000_000,
                'original owner command/request/deadline binding differs')
        cleanup = life['cleanup']
        require(life['subreaper_enabled'] is True
                and cleanup.get('attempted') is True and cleanup.get('complete') is True
                and cleanup.get('observed_echild') is True and cleanup.get('leader_reaped') is True
                and cleanup.get('deadline_exceeded') is False
                and cleanup.get('remaining_direct_children') == [] and cleanup.get('errors') == [],
                'bound original owner does not confirm ECHILD closure')
        closed = True
        final['bound_owner_observation'] = {
            'lifecycle': life_pin, 'request': request_pin,
            'status': life['status'], 'returncode': life['returncode'],
            'supervisor_returncode': returned['supervisor_returncode']}
"""
    raw = replace_once(raw, before, after)
    raw = replace_once(raw, "        require(life['schema'] == 'hepta.hia.selfhost-process-owner.v1'\n",
                      "        require(returned['supervisor_returncode'] == 0\n"
                      "                and life['schema'] == 'hepta.hia.selfhost-process-owner.v1'\n")
    raw = replace_once(raw, """    finally:
        final['actual_originals'] = [pin(path) for path in sorted(folder.rglob('*')) if path.is_file()]
        save(folder / 'FINAL.json', final)
""", """    finally:
        final['closed_owner_confirmed'] = closed
        final['child_originals_read'] = closed
        if closed:
            final['actual_originals'] = [pin(path) for path in sorted(folder.rglob('*')) if path.is_file()]
        else:
            final['actual_originals'] = []
            save(folder / 'PARENT-OBSERVATIONS.json', {
                'files': parent_pins, 'closed_owner_confirmed': False,
                'child_originals_read': False,
                'scope': 'Only files written by this parent; no traversal or child-body read.'})
        save(folder / 'FINAL.json', final)
""")
    ast.parse(raw, filename="control/launch.py")
    (HERE / "control/launch.py").write_text(raw)
    spec = importlib.util.spec_from_file_location("source83_s2_freezer_metadata", HERE / "control/common.py")
    common = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(common)
    request = json.loads((BASE / "REQUEST.json").read_bytes())
    old_request = dict(request)
    request.update(revision="r4-on-v89-fixed-transports-bound-closure-actions-template",
                   evidence_root=str(HERE / "unexecuted-local-template-only"),
                   control_inputs=[common.pin(p) for p in sorted((HERE / "control").glob("*.py"))])
    assert all(request[k] == old_request[k] for k in old_request
               if k not in {"revision", "evidence_root", "control_inputs"})
    assert request["expected_methods"] == 83 and len(request["generator_names"]) == 62
    assert request["qualification_seconds"] == 180 and request["cleanup_seconds"] == 3
    for name in ("child.py", "common.py", "worker.py"):
        assert (HERE / "control" / name).read_bytes() == (BASE / "control" / name).read_bytes()
    save("REQUEST.json", request)
    save("LAUNCH.json", {"schema": "hepta.hia.core-compare-integration-source-launch.v1",
        "operation": "UNEXECUTED_TEMPLATE_ONLY_ADAPT_TO_NEW_ACTIONS_RUN",
        "request": common.pin(HERE / "REQUEST.json"),
        "command": [request["runtime"]["path"], "-I", "-S", "-B", str(HERE / "control/launch.py")],
        "cwd": str(HERE), "qualification_seconds": 180, "cleanup_seconds": 3,
        "local_execution_authorized": False, "new_Actions_runtime_binding_required": True})
    checks = json.loads((BASE / "STATIC-CHECKS.json").read_bytes())
    checks.pop("original4_controls_byte_equal")
    checks.update(original_three_controls_byte_equal=True,
        one_launcher_delta="Bind closure independently from success before any child traversal.",
        request_protected_fields_unchanged_from_S1=True,
        source_physical_copy_reused_only_as_unexecuted_template=True,
        source_root=request["source_root"], original_S1_remains_unexecuted=True,
        controller_synthetic_tests_executed=0)
    save("STATIC-CHECKS.json", checks)
    with (HERE / "LAUNCH-CLOSURE.diff").open("x") as output:
        output.writelines(difflib.unified_diff(old.splitlines(keepends=True), raw.splitlines(keepends=True),
            fromfile="S1/control/launch.py", tofile="S2/control/launch.py"))
    save("CLOSURE-CORRECTION.json", {
        "schema": "hepta.hia.numeric-source83-launcher-closure-correction.v1",
        "status": "FROZEN_UNEXECUTED_SOURCE_CONTROL_ONLY",
        "preserved_S1_commit": "1dff558270cccfe29ad9207f39e37cea62da16d4",
        "old_launch": digest(old.encode()), "new_launch": digest(raw.encode()),
        "only_source_control_changed": "control/launch.py",
        "other_three_controls_exact": True, "source83_and_generators62_exact": True,
        "poison_and_180_plus_3_exact": True,
        "closed_nonzero_preserves_all_actual_child_originals": True,
        "unknown_closure_never_traverses_or_reads_child_bodies": True,
        "raw_owner_binding_required": ["wrapper receipt SHA and full projection", "raw request SHA",
            "exact command/cwd/environment/output paths", "180-second deadline and 3-second cleanup",
            "original implementation SHA", "subreaper/ECHILD/reaped/empty remainder"],
        "qualification_success_still_requires_original_natural_zero_and_complete83": True,
        "no_execution": True})
    print(json.dumps({"status": "FROZEN_UNEXECUTED", "request": digest((HERE / "REQUEST.json").read_bytes()),
        "launch_control": digest(raw.encode()), "source_methods":83, "generators":62}, sort_keys=True))

if __name__ == "__main__":
    main()
