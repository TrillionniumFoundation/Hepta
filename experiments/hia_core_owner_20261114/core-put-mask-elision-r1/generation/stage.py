"""Metadata only: clone the exact4135 leaves, overlay one author, freeze one future request."""
from __future__ import annotations
import argparse, hashlib, importlib.util, os, stat, sys
from pathlib import Path, PurePosixPath
P=Path("/home/qq/hia-rewrite-20261113-e26e-r1")
DONOR_CONTROL=P/"core-balanced-dispatch-r1/control"
PYTHON=Path("/usr/bin/python3.14")
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
    _common_path, 9364,
    "7e7db5f65243be9791f8755c08af8e9811ad6554f1de8054eafb20ff0a65971c")
# importlib creates the module; execute only the already verified source bytes.
_spec = importlib.util.spec_from_loader(
    "put_mask_generation_pinned_common", loader=None, origin=str(_common_path))
C = importlib.util.module_from_spec(_spec)
C.__file__ = str(_common_path)
exec(compile(_common_raw, str(_common_path), "exec", dont_inherit=True), C.__dict__)
C.require(C.read_regular(_common_path, _common_pin)[0] == _common_raw,
          "common changed during verified-byte module loading")
C.read_regular(PYTHON, _runtime_pin)

BASE=P/"core-balanced-dispatch-derive8-r1/source"
N=P/"core-put-mask-elision-r1"
MANIFEST=P/"core-put-mask-elision-r1-base4135.json"
AUTHOR=P/"core-put-mask-elision-r1-author.py"
BASE_TREE="cd7d49368f9621ea9379ba32c3f1f969a28c65b4"
INITIAL_TREE="6ec441e7829b908a26c9936f616871792e30528e"
TARGET="tools/generate_hia_core_lowering.py"
CONTROL_PINS={
 "source_common.py":(9364,"7e7db5f65243be9791f8755c08af8e9811ad6554f1de8054eafb20ff0a65971c"),
 "generation_child.py":(9372,"a84b8cab172a053347082567f286895389afb30de54ee7b216883b429584e68d"),
 "generation_launch.py":(8045,"e1c2c2645cf5ab5bff332e23bfe06bc35d2c8fba777238ed3f9a2567b9964575"),
}
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
def main():
    parser=argparse.ArgumentParser()
    # Bind these to the existing donor request values in Root's metadata INTENT.
    parser.add_argument("--minimum-free-bytes",type=int,required=True)
    parser.add_argument("--minimum-free-inodes",type=int,required=True)
    args=parser.parse_args()
    os.umask(0o077)
    C.require(tuple(sys.version_info[:3])==(3,14,4),"runtime version")
    C.require(args.minimum_free_bytes>=0 and args.minimum_free_inodes>=0,"space fields")
    C.require(not N.exists() and N.parent.resolve(strict=True)==N.parent,"fresh namespace")
    mr,mp=C.read_regular(MANIFEST);ar,ap=C.read_regular(AUTHOR)
    C.require(len(mr)==832965 and C.digest(mr)=="1838cf54d6522f4307357c7659f0147a0884a5abd5bc7f138297c5d9737937e7"
        and git_object("blob",mr)=="3d62e5f875f116e177d61ecab22b6c8a7c6b11e7","base manifest")
    C.require(len(ar)==17703 and C.digest(ar)=="bbd03622a355917aba369375a226aab3b7003ed0bca8d53d9fdc5a0b7906d548"
        and git_object("blob",ar)=="99cd0840528faac59ae3a2a10baa6466baa905aa","candidate author")
    rows=C.decode(mr)
    C.require(type(rows) is list and len(rows)==4135
        and all(set(r)=={"path","mode","type","sha","size"} and r["type"]=="blob"
            and r["mode"] in ("100644","100755") and type(r["size"]) is int
            and 0<=r["size"]<=11429219 for r in rows)
        and sum(r["size"] for r in rows)==412691995 and tree(rows)==BASE_TREE,"full baseline")
    rows=sorted(rows,key=lambda r:r["path"])
    C.require(leaves(BASE)==[r["path"] for r in rows],"baseline path population")
    controls={}
    for name,(size,digest) in CONTROL_PINS.items():
        raw,pin=C.read_regular(DONOR_CONTROL/name)
        C.require(len(raw)==size and C.digest(raw)==digest,"control pin:"+name)
        controls[name]=(raw,pin)
    runtime=C.read_regular(Path(sys.executable).resolve())[1]
    C.require(runtime["path"]=="/usr/bin/python3.14" and runtime["bytes"]==7477160
        and runtime["sha256"]=="52e0a13e60a981d8c4b6478be2ba5176f69da07948a056bf49cf6f077e30cb41",
        "fixed Python runtime")
    C.require(sys.flags.isolated==1 and sys.flags.no_site==1 and sys.dont_write_bytecode,
        "isolated no-site no-bytecode metadata entry")
    stage_pin=C.read_regular(Path(__file__).resolve())[1]
    space=os.statvfs(N.parent)
    C.require(space.f_bavail*space.f_frsize>=args.minimum_free_bytes
              and space.f_favail>=args.minimum_free_inodes,"existing space admission")
    N.mkdir(mode=0o700);(N/"source").mkdir(mode=0o700);(N/"control").mkdir(mode=0o700)
    for name,(raw,pin) in controls.items():C.save(N/"control"/name,raw)
    C.save(N/"BASE4135.json",mr)
    materialized=[];new_rows=[]
    for row in rows:
        original,donor=C.read_regular(BASE/row["path"])
        C.require(len(original)==row["size"] and git_object("blob",original)==row["sha"],"base body:"+row["path"])
        raw=ar if row["path"]==TARGET else original
        destination=N/"source"/row["path"];destination.parent.mkdir(parents=True,exist_ok=True)
        C.save(destination,raw)
        if row["mode"]=="100755":destination.chmod(0o700)
        observed=C.read_regular(destination)[1]
        blob=git_object("blob",raw)
        materialized.append({"path":row["path"],"baseline":row,"donor":donor,
            "candidate":{"bytes":len(raw),"sha256":C.digest(raw),"git_blob":blob,"git_mode":row["mode"]},
            "physical":observed["identity"]})
        new_rows.append({**row,"size":len(raw),"sha":blob})
    C.require(len(new_rows)==4135 and sum(r["size"] for r in new_rows)==412692160
              and tree(new_rows)==INITIAL_TREE,"one-overlay input tree")
    C.require(leaves(BASE)==[r["path"] for r in rows],"donor population after")
    for row in materialized:C.read_regular(BASE/row["path"],row["donor"])
    C.read_regular(MANIFEST,mp);C.read_regular(AUTHOR,ap)
    for raw,pin in controls.values():C.read_regular(pin["path"],pin)
    C.read_regular(runtime["path"],runtime)
    root=N/"source";out=N/"generation1-actual-r1"
    materialization={"schema":"hia.core-balanced-dispatch.materialization.v1",
        "status":"PREPARED_ONLY_NOT_MATCHING_SOURCE_QUALIFIED","file_count":4135,
        "source_root":str(root),"donor_root":str(BASE),"baseline_tree":BASE_TREE,
        "initial_tree":INITIAL_TREE,"files":materialized}
    mat=C.save_json(N/"MATERIALIZATION.json",materialization)
    numbered=["examples/hia_bootstrap/core_lowering_%03d.hiaasm"%i for i in range(38)]
    pool="examples/hia_bootstrap/core_lowering_pool.hiaasm";abi="hepta/hia_core_lowering_abi.json"
    assembly=[pool,*numbered];allowed=sorted([*assembly,abi])
    owner=C.read_regular(root/"tools/hia_selfhost_process_owner.py")[1]
    C.require(owner["bytes"]==17601 and owner["sha256"]=="36946082b3345f45ee2b28f1f810a22936d182a586cd0404154dfb01b3bd53a2","original owner")
    environment={"PATH":"","LANG":"C.UTF-8","LC_ALL":"C.UTF-8",
        "PYTHONDONTWRITEBYTECODE":"1","PYTHONHASHSEED":"0","PYTHONNOUSERSITE":"1",
        "TMPDIR":str(out/"scratch")}
    request_path=N/"control/REQUEST.json"
    inputs=[runtime,owner,mat,mp,ap,stage_pin]
    inputs.extend(C.read_regular(N/"control"/name)[1] for name in CONTROL_PINS)
    inputs.append(C.read_regular(root/TARGET)[1])
    request={"schema":C.SCHEMA,"scope":"one put-mask-elision author.write and original finite9cap acceptance only",
        "baseline_tree":BASE_TREE,"initial_tree":INITIAL_TREE,"source_root":str(root),
        "source_file_count":4135,"output_root":str(out),"runtime":runtime,
        "owner_implementation":owner,"materialization":mat,"inputs":inputs,
        "boot_id":Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        "qualification_seconds":180,"cleanup_seconds":3,"environment":environment,
        "minimum_free_bytes":args.minimum_free_bytes,"minimum_free_inodes":args.minimum_free_inodes,
        "assembly_paths":assembly,"generated_write_paths":allowed,
        "allowed_changed_documents":allowed,"unchanged_generated_paths":[pool,abi],
        "worker_command_template":[runtime["path"],"-I","-S","-B",str(N/"control/generation_child.py"),
            "--request",str(request_path),"--sha256","<REQUEST-SHA256>"]}
    req=C.save_json(request_path,request)
    command=[runtime["path"],"-I","-S","-B",str(N/"control/generation_launch.py"),
             "--request",str(request_path),"--sha256",req["sha256"]]
    launch=C.save_json(N/"LAUNCH.json",{"command":command,"cwd":str(root),"env":environment,
        "request":req,"qualification_seconds":180,"cleanup_seconds":3,
        "execution":"NOT_EXECUTED_ROOT_ONLY"})
    C.save_json(N/"MATERIALIZE-REPORT.json",{"status":"PREPARED_ONLY","source_file_count":4135,
        "baseline_tree":BASE_TREE,"initial_tree":INITIAL_TREE,"source_bytes":412692160,
        "request":req,"launch":launch,"original_donor_bytes_and_nine_identities_stable":True,
        "generation_count":0,"tests":0,"VM":0,"native":0,"network":0})
    print("PREPARED_ONLY")
if __name__=="__main__":main()
