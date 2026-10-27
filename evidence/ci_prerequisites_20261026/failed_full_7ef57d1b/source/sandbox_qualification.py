"""Real namespace and native-compiler qualification using trusted probes only.

This is a release prerequisite, not an AI run or a sandbox escape proof.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import tempfile

import hepta
from hepta.backend import find_rustc, sha256, toolchain_info
from hepta.pipeline import compiler_hash

from .sandbox import clean_environment, kill_process, probe_sandbox, run_bounded, wrap_command


REQUIRED_NAMESPACES = ("user", "pid", "ipc", "mnt", "net")
CHECKS = ("startup", "namespace_identity", "capabilities_dropped", "empty_proc", "parent_paths_unreadable",
          "credentials_not_inherited", "host_network_unreachable", "system_files_read_only",
          "hepta_rust_native", "workspace_native_profile")
CREDENTIAL_CANARY = "HEPTA_SANDBOX_CREDENTIAL_CANARY"
HEPTA_SOURCE = """fn plus_one(x: i32) -> i32 effects {panic} { return x + 1; }
fn main() -> i32 effects {panic} { assert(plus_one(41) == 42); return 0; }
"""

BOUNDARY_SCRIPT = """import ctypes,json,os,socket,sys
config=json.loads(sys.argv[1])
class CapHeader(ctypes.Structure):
    _fields_=[('version',ctypes.c_uint32),('pid',ctypes.c_int)]
class CapData(ctypes.Structure):
    _fields_=[('effective',ctypes.c_uint32),('permitted',ctypes.c_uint32),('inheritable',ctypes.c_uint32)]
libc=ctypes.CDLL(None,use_errno=True)
header=CapHeader(0x20080522,0)
data=(CapData*2)()
if libc.capget(ctypes.byref(header),ctypes.byref(data))!=0:
    raise OSError(ctypes.get_errno(),'capget failed')
capabilities={name:getattr(data[0],name)|(getattr(data[1],name)<<32)
              for name in ('effective','permitted','inheritable')}
capabilities['no_new_privileges']=libc.prctl(39,0,0,0,0)
checks={}
for name,path in config['paths'].items():
    try:
        descriptor=os.open(path,os.O_RDONLY)
    except OSError as exc:
        checks[name]={'unreadable':True,'errno':exc.errno}
    else:
        os.close(descriptor)
        checks[name]={'unreadable':False}
connection=socket.socket()
connection.settimeout(1)
try:
    connection.connect(('127.0.0.1',config['port']))
except OSError as exc:
    network={'blocked':True,'errno':exc.errno}
else:
    network={'blocked':False}
finally:
    connection.close()
print(json.dumps({'pid':os.getpid(),'ppid':os.getppid(),
    'proc_entries':os.listdir('/proc'),'path_checks':checks,'host_loopback':network,
    'capabilities':capabilities,
    'credential_in_environment':config['credential_name'] in os.environ,
    'toolchain_visible':os.path.isfile(config['rustc']),
    'toolchain_read_only':bool(os.statvfs(config['sysroot']).f_flag & os.ST_RDONLY),
    'usr_read_only':bool(os.statvfs('/usr').f_flag & os.ST_RDONLY)}),flush=True)
sys.stdin.readline()
"""

NATIVE_SCRIPT = """import json,subprocess,sys
from pathlib import Path
sys.path.insert(0,str(Path(__file__).parent))
from hepta.backend import compile_rust
from hepta.pipeline import analyze
from hepta.workspace import initialize,pin
root=Path(__file__).parent
source=(root/'main.hepta').read_text()
selected=sys.argv[1]
checked=analyze(source,str(root/'main.hepta'),rustc=selected,crate_type='bin')
result={'analysis_ok':checked.report['ok'],'analysis':checked.report}
if checked.report['ok']:
    built=compile_rust(checked.rust,rustc=selected,crate_type='bin',output=root/'candidate')
    result['build']=built
    if built['ok']:
        executed=subprocess.run([built['artifact']],capture_output=True,text=True,timeout=3)
        result['execution']={'returncode':executed.returncode,'stdout':executed.stdout,'stderr':executed.stderr}
    bundle=root/'public_bundle'
    bundle.mkdir()
    (bundle/'main.hepta').write_text(source)
    initialized=initialize(root/'store',bundle,'main.hepta',rustc=selected)
    result['workspace_ok']=initialized['ok']
    if initialized['ok']:
        snapshot=pin(root/'store')
        result['workspace_version']=snapshot['version']
        result['workspace_profile']=snapshot['manifest']['profile']
        result['workspace_backend']=snapshot['manifest']['validation']['backend']
    else:
        result['workspace_failure']=initialized
print(json.dumps(result))
sys.exit(0 if result.get('execution',{}).get('returncode')==0 and result.get('workspace_ok') else 1)
"""


def _boundary_observation(parent: Path, capsule: Path, selected: Path):
    oracle = parent / "parent_oracle_canary"
    credentials = parent / "parent_credentials_canary"
    oracle.write_text("qualification-only parent oracle marker\n")
    credentials.write_text("qualification-only credential marker\n")
    escape = capsule / "parent_symlink"
    escape.symlink_to(oracle)
    paths = {"parent_oracle_canary": str(oracle), "parent_credentials_canary": str(credentials),
             "capsule_symlink_to_parent": str(escape),
             "proc_parent_root_escape": f"/proc/{os.getpid()}/root{oracle}",
             "proc_init_root_escape": "/proc/1/root" + str(oracle),
             "proc_environment": "/proc/self/environ",
             "parent_private_oracle_module": str(Path(__file__).parent / "_private" / "oracles.py"),
             "host_credentials_path": "/root/.aws/credentials"}
    # The canaries and real private module must exist outside the capsule;
    # absence inside then demonstrates a boundary, not an absent host input.
    for name in ("parent_oracle_canary", "parent_credentials_canary", "parent_private_oracle_module"):
        if not Path(paths[name]).is_file():
            raise ValueError("qualification host input missing: " + name)
    listener = socket.socket()
    read_fd, write_fd = os.pipe()
    process = None
    prior = os.environ.get(CREDENTIAL_CANARY)
    try:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        config = {"paths": paths, "port": listener.getsockname()[1], "credential_name": CREDENTIAL_CANARY,
                  "rustc": str(selected), "sysroot": str(selected.parent.parent)}
        os.environ[CREDENTIAL_CANARY] = "qualification-only-not-a-secret"
        command = ["/usr/bin/python3", "-I", "-S", "-c", BOUNDARY_SCRIPT, json.dumps(config)]
        argv = wrap_command(command, capsule, read_only=[selected.parent.parent])
        argv[1:1] = ["--info-fd", str(write_fd)]
        process = subprocess.Popen(argv, env=clean_environment(), stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                   start_new_session=True, pass_fds=(write_fd,))
        os.close(write_fd)
        write_fd = None
        if not select.select([read_fd], [], [], 3)[0]:
            raise TimeoutError("bubblewrap namespace identity was not reported")
        info = json.loads(os.read(read_fd, 8192))
        namespaces = {}
        for name in (*REQUIRED_NAMESPACES, "uts", "cgroup"):
            host = os.readlink("/proc/self/ns/" + name)
            child = os.readlink(f"/proc/{info['child-pid']}/ns/" + name)
            namespaces[name] = {"parent": host, "child": child, "different": host != child}
        if not select.select([process.stdout], [], [], 3)[0]:
            raise TimeoutError("trusted boundary probe did not respond")
        inside = json.loads(process.stdout.readline())
        stdout, stderr = process.communicate(input="continue\n", timeout=3)
        listener.setblocking(False)
        try:
            connection, _ = listener.accept()
        except BlockingIOError:
            accepted = False
        else:
            connection.close()
            accepted = True
        return {"returncode": process.returncode, "stderr": stderr, "remaining_stdout": stdout,
                "namespaces": namespaces, "required_namespaces": list(REQUIRED_NAMESPACES),
                "inside": inside, "parent_listener_received_connection": accepted,
                "paths": {name: {"path": path, "host_exists": Path(path).exists()}
                          for name, path in paths.items()}}
    finally:
        if process is not None:
            kill_process(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream and not stream.closed:
                    stream.close()
        os.close(read_fd)
        if write_fd is not None:
            os.close(write_fd)
        listener.close()
        if prior is None:
            os.environ.pop(CREDENTIAL_CANARY, None)
        else:
            os.environ[CREDENTIAL_CANARY] = prior


def qualify_sandbox(rustc=None):
    report = {"schema": "hepta.sandbox_qualification.v1", "status": "not_qualified",
              "qualified": False, "ai_comparison_eligible": False,
              "scope": "trusted namespace, boundary, and native compiler qualification",
              "compiler_sha256": compiler_hash(),
              "implementation_sha256": {name: sha256((Path(__file__).parent / name).read_bytes())
                                        for name in ("sandbox.py", "sandbox_qualification.py")},
              "checks": {name: {"status": "not_run"} for name in CHECKS}}

    def record(name, passed):
        report["checks"][name] = {"status": "passed" if passed else "failed"}

    probe_sandbox.cache_clear()
    report["startup"] = probe_sandbox()
    record("startup", report["startup"]["available"])
    if not report["startup"]["available"]:
        report["status"] = "environment_blocked"
        return report
    try:
        bubblewrap = Path(shutil.which("bwrap")).resolve()
        version = subprocess.run([str(bubblewrap), "--version"], env=clean_environment(),
                                 capture_output=True, text=True, timeout=3, check=True)
        report["sandbox_executable"] = {"path": str(bubblewrap), "version": version.stdout.strip(),
                                        "executable_sha256": sha256(bubblewrap.read_bytes())}
        selected = Path(find_rustc(rustc)).resolve()
        identity = toolchain_info(str(selected))
        report["toolchain"] = identity
        if identity["sysroot_discovery"] != "verified_compiler_prefix":
            raise ValueError("E_SANDBOX_TOOLCHAIN: qualification requires an explicitly mountable compiler prefix")
        with tempfile.TemporaryDirectory(prefix="hepta-sandbox-qualification-") as temporary:
            parent = Path(temporary)
            capsule = parent / "capsule"
            capsule.mkdir()
            boundary = _boundary_observation(parent, capsule, selected)
            report["boundary"] = boundary
            executed = boundary["returncode"] == 0
            inside = boundary["inside"]
            record("namespace_identity", executed and all(boundary["namespaces"][name]["different"]
                                                           for name in REQUIRED_NAMESPACES))
            record("capabilities_dropped", executed and all(inside["capabilities"][name] == 0
                     for name in ("effective", "permitted", "inheritable"))
                   and inside["capabilities"]["no_new_privileges"] == 1)
            record("empty_proc", executed and inside["proc_entries"] == [])
            record("parent_paths_unreadable", executed and all(item["unreadable"]
                                                               for item in inside["path_checks"].values()))
            record("credentials_not_inherited", executed and not inside["credential_in_environment"])
            record("host_network_unreachable", executed and inside["host_loopback"]["blocked"]
                                                  and not boundary["parent_listener_received_connection"])
            record("system_files_read_only", executed and inside["usr_read_only"]
                   and inside["toolchain_visible"] and inside["toolchain_read_only"])
            if any(item["status"] == "failed" for item in report["checks"].values()):
                return report
            shutil.copytree(Path(hepta.__file__).parent, capsule / "hepta",
                            ignore=shutil.ignore_patterns("__pycache__", "*.pyc"))
            (capsule / "main.hepta").write_text(HEPTA_SOURCE)
            (capsule / "native_probe.py").write_text(NATIVE_SCRIPT)
            native = run_bounded(["/usr/bin/python3", "-I", str(capsule / "native_probe.py"), str(selected)],
                                 cwd=capsule, read_only=[selected.parent.parent], timeout=30, max_output=1024**2)
            report["native_process"] = native
            report["hepta_source_sha256"] = sha256(HEPTA_SOURCE.encode())
            if native["status"] != "exited" or native["returncode"] != 0:
                record("hepta_rust_native", False)
                return report
            result = json.loads(native["stdout"])
            report["native"] = result
            record("hepta_rust_native", result["analysis_ok"] and result["build"]["ok"]
                                        and result["execution"]["returncode"] == 0
                                        and bool(result["build"].get("artifact_sha256")))
            flags = result["workspace_backend"]["flags"]
            record("workspace_native_profile", result["workspace_ok"]
                   and result["workspace_profile"]["native_flags"] == flags
                   and "sysroot=" + identity["sysroot"] in flags)
    except Exception as exc:
        report["error"] = {"type": type(exc).__name__, "message": str(exc)}
        return report
    report["qualified"] = all(item["status"] == "passed" for item in report["checks"].values())
    report["status"] = "qualified" if report["qualified"] else "not_qualified"
    return report
