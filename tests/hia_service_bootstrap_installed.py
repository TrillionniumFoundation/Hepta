"""Real installed wheel, worker identity and all five bootstrap public methods."""
from __future__ import annotations
import argparse,base64,configparser,csv,io,json,os,shutil,sqlite3,sys,zipfile
from hashlib import sha256
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
if __package__ in (None,""):sys.path.insert(0,str(ROOT))
from tests import hia_service_bootstrap_support as support
from tests.hia_service_bootstrap_controls import bundle,clean_environment,manifest_pins
from tests.hia_slot_operations_qualification_support import run_owned

WORKER=r"""import importlib.abc,sys
from pathlib import Path
installed=sys.argv.pop(1);sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name in ('tools','tests') or name.startswith(('tools.','tests.')):
            raise AssertionError('installed worker imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta.hia_service_bootstrap_native import SOURCE
assert SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta/_data')
from hepta.hia_agent_worker import main
raise SystemExit(main(sys.argv[1:]))
"""
CONSUMER=r"""import ctypes,importlib.abc,json,os,struct,sys
from pathlib import Path
installed,mode,bundle,bundle_sha,state_root,files_root,payload_path=sys.argv[1:]
sys.path.insert(0,installed)
class NoAuthoring(importlib.abc.MetaPathFinder):
    def find_spec(self,name,path=None,target=None):
        if name in ('tools','tests') or name.startswith(('tools.','tests.')):
            raise AssertionError('installed consumer imported authoring code')
sys.meta_path.insert(0,NoAuthoring())
from hepta import hia_agent_service as api,hia_agent_store as store_api
from hepta import hia_service_bootstrap_native as native,hia_native_delivery as delivery
from hepta.hia_native_helpers import native_helpers_scope,native_helpers_identity
assert native.SOURCE.resolve().is_relative_to(Path(installed).resolve()/'hepta/_data')
counts={'mode':{},'event':{},'close_body':0}
original_initialize=native.NativeServiceBootstrap.__init__
def initialize(image,*args,**kwargs):
    original_initialize(image,*args,**kwargs)
    actual=image._entry
    def entry(source,size,output,capacity,state,extent):
        words=struct.unpack('<16Q',ctypes.string_at(source,size))
        code=actual(source,size,output,capacity,state,extent)
        assert code==native.OUTPUT_BYTES
        for category,value in (('mode',words[5]),('event',words[1])):
            key=str(value);counts[category][key]=counts[category].get(key,0)+1
        if mode=='lost_program_FINALIZE' and words[5]==native.PROGRAM and words[1]==native.FINALIZE:
            raise ValueError('installed original Store read succeeded; parent FINALIZE return lost')
        return code
    image._entry=entry
native.NativeServiceBootstrap.__init__=initialize
def forbidden(*args,**kwargs):
    raise AssertionError('selected installed bootstrap entered a retained whole method')
api._SERVICE_BOOTSTRAP_REFERENCES={key:forbidden for key in api._SERVICE_BOOTSTRAP_REFERENCES}
original_close=store_api._NATIVE_STORE_CLOSE_REFERENCE
def close(store):
    counts['close_body']+=1
    return original_close(store)
store_api._NATIVE_STORE_CLOSE_REFERENCE=close
payload=json.loads(Path(payload_path).read_bytes())
report={'mode':mode,'counts':counts,'qualified_whole_native':False,
        'independent_budget_B_selected':False}
with native_helpers_scope(bundle,bundle_sha):
    service=api.HIAAgentService(Path(state_root),artifact_roots=(Path(files_root),))
    assert service._candidate_budget is None
    assert native_helpers_identity()['native_helpers_sha256']==bundle_sha
    service._profiles()
    profile=service._profile(service.profiles['compiler'],'compiler')
    assert profile['schema']=='hepta.hia.agent.compiler-profile.v1'
    ref=service.store.json(payload,'program')
    try:
        verified=service._program(ref)
        assert mode=='normal','installed actual loss did not occur'
        report['program_type']=type(verified).__name__
    except (native.ServiceBootstrapUnknown,delivery.NativeDeliveryUnknown) as error:
        assert mode=='lost_program_FINALIZE'
        report['unknown_type']=type(error).__name__
        try:service.close()
        except (native.ServiceBootstrapUnknown,delivery.NativeDeliveryUnknown):
            report['close_refused']=True
        else:raise AssertionError('unknown installed Store was retired')
    else:
        service.close()
    report['lost_records']=sum(row['lost'] for row in delivery.custody_snapshot())
    report['resources']=len(delivery._RESOURCE_OBSERVATIONS)
if mode=='normal':
    assert {'1','2','3','4','5'}<=set(counts['mode'])
    assert counts['close_body']==1 and report['lost_records']==0 and report['resources']==0
else:
    assert counts['close_body']==0 and report['lost_records']>0 and report['resources']>0
print(json.dumps(report,sort_keys=True,separators=(',',':')))
"""

def wheel_records(wheel,installed):
    installed=Path(installed);files={}
    with zipfile.ZipFile(wheel) as archive:
        names=archive.namelist()
        if len(names)!=len(set(names)):raise ValueError("wheel repeats a member")
        record_name,=[name for name in names if name.endswith(".dist-info/RECORD")]
        raw_record=archive.read(record_name)
        old={}
        for row in csv.reader(io.StringIO(raw_record.decode())):
            if len(row)!=3 or row[0] in old:raise ValueError("wheel RECORD row differs")
            name,digest,size=row;old[name]=(digest,size)
            if Path(name).is_absolute() or ".." in Path(name).parts:
                raise ValueError("wheel member leaves installation root")
            raw=archive.read(name)
            if digest:
                value="sha256="+base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode()
                if digest!=value or size!=str(len(raw)):raise ValueError("wheel RECORD member bytes differ")
            elif name!=record_name or size:raise ValueError("only RECORD has an empty self digest")
            if name!=record_name:
                if (installed/name).read_bytes()!=raw:raise ValueError("installed wheel bytes differ: "+name)
                files[name]=support.bytes_pin(raw)
        installed_raw=(installed/record_name).read_bytes()
        now={}
        for row in csv.reader(io.StringIO(installed_raw.decode())):
            if len(row)!=3 or row[0] in now:raise ValueError("installed RECORD duplicates a path")
            now[row[0]]=tuple(row[1:])
        if any(now.get(name)!=value for name,value in old.items()):
            raise ValueError("pip changed a preexisting RECORD path/hash/size")
        directory=str(Path(record_name).parent)
        additions={"../../bin/hia",directory+"/INSTALLER",directory+"/REQUESTED",directory+"/direct_url.json"}
        if set(now)-set(old)!=additions:raise ValueError("undeclared pip metadata delta")
        extra={}
        for name in sorted(additions):
            target=installed/"bin/hia" if name=="../../bin/hia" else installed/name
            raw=target.read_bytes();digest,size=now[name]
            actual="sha256="+base64.urlsafe_b64encode(sha256(raw).digest()).rstrip(b"=").decode()
            if digest!=actual or size!=str(len(raw)):raise ValueError("actual installed metadata differs")
            extra[name]={"actual_relative":str(target.relative_to(installed)),**support.bytes_pin(raw)}
        if (installed/directory/"INSTALLER").read_bytes()!=b"pip\n" or (installed/directory/"REQUESTED").read_bytes()!=b"":
            raise ValueError("unexpected installer/request marker")
        direct_raw=(installed/directory/"direct_url.json").read_bytes();direct=support.parse(direct_raw)
        if (direct["url"]!=Path(wheel).resolve().as_uri()
                or direct["archive_info"]["hashes"]!={"sha256":support.file_pin(wheel)["sha256"]}):
            raise ValueError("direct_url does not bind the actual wheel")
        config=configparser.ConfigParser()
        config.read_string(archive.read(directory+"/entry_points.txt").decode())
        module,function=map(str.strip,config["console_scripts"]["hia"].split(":"))
        script=(installed/"bin/hia").read_text()
        if "from "+module+" import "+function not in script or "sys.exit("+function+"())" not in script:
            raise ValueError("actual console entry differs from wheel entry_points")
    return {"wheel":support.file_pin(wheel),"wheel_record":support.bytes_pin(raw_record),
        "installed_record":{"path":record_name,**support.bytes_pin(installed_raw)},
        "common_rows":len(old),"installed_rows":len(now),"installed_additions":extra,
        "wheel_member_files":files,"direct_url":support.bytes_pin(direct_raw),
        "RECORD_file_bytes_expected_identical":False}

def database_rows(path):
    connection=sqlite3.connect(Path(path)/"state.sqlite3")
    try:
        connection.row_factory=sqlite3.Row
        return {table:[dict(row) for row in connection.execute("SELECT * FROM "+table)]
                for table in ("requests","artifacts","profiles","costs")}
    finally:connection.close()


def describe_worker_controls(output,command,worker,installed,bundle_path,bundle_sha,
                             identity,files_root,flags,observations,report,api):
    """Keep the old malformed request and add a distinct valid manifest pair."""
    state_root=output/"worker-state"
    labels=("worker-first","worker-replay","worker-manifest-first","worker-manifest-replay")
    record={"schema":"hepta.hia.installed-describe-controls.v2","status":"HOLD",
            "ordered_labels":list(labels),"cases":{},"new_worker_commands":2,
            "durable_request_key_supplied":False,"cached_journal_replay_claimed":False}
    report["worker_requests"]=record
    events=[];previous=None
    def event(row):
        raw=support.canonical(row)+b"\n"
        with (output/"worker-request-events.jsonl").open("ab") as stream:stream.write(raw)
        events.append(row)
    try:
        for kind,arguments,pair,filename in (
                ("malformed",{},labels[:2],"worker-request.json"),
                ("manifest",{"section":"manifest"},labels[2:],"worker-manifest-request.json")):
            request={"schema":"hia-agent-worker-request-v1","tool":"hia_describe","arguments":arguments,
                     "profile_sha256":"a"*64,"catalog_sha256":identity["catalog_sha256"]}
            request["request_sha256"]=api.digest(request)
            body=support.canonical(request);request_raw=body+b"\n"
            with (output/filename).open("xb") as stream:stream.write(request_raw)
            saved={"file":filename,"pin":support.bytes_pin(request_raw),
                   "stdin":support.bytes_pin(body),"value":request,"labels":list(pair)}
            record["cases"][kind]=saved
            pair_first=None
            for label in pair:
                event({"event":"start","id":label,"kind":kind,"stdin":saved["stdin"]})
                raw=command(label,[worker,installed,"--state-root",state_root,
                    "--artifact-root",files_root,"--request-json-stdin",
                    "--native-helpers-manifest",bundle_path,
                    "--expected-native-helpers-sha256",bundle_sha,*flags],body=body)
                value=support.parse(raw)
                data=database_rows(state_root)
                database_raw=support.canonical(data)+b"\n"
                with (output/label/"database.json").open("xb") as stream:stream.write(database_raw)
                observations[label].update(response=value,database=data,
                    database_pin=support.bytes_pin(database_raw),
                    request_kind=kind,request=saved["pin"],stdin=saved["stdin"])
                if (value["schema"]!="hia-agent-worker-report-v1" or value["complete"] is not True
                        or value["tool"]!="hia_describe"
                        or value["request_sha256"]!=request["request_sha256"]
                        or value["profile_sha256"]!=request["profile_sha256"]
                        or value["native_helpers_sha256"]!=bundle_sha):
                    raise AssertionError("installed worker request correlation differs: "+label)
                for key in ("worker_sha256","backend_sha256","catalog_sha256"):
                    if value[key]!=identity[key]:
                        raise AssertionError("installed worker actual identity differs: "+label)
                response=value["response"]
                expected_id="r-"+api.digest({"tool":"hia_describe","arguments":arguments})
                if response["request_id"]!=expected_id:
                    raise AssertionError("installed describe request ID changed")
                if kind=="malformed":
                    expected_error={"code":"E_HIA_SCHEMA","phase":"admission",
                        "message":"arguments: missing fields section",
                        "retry_action":"correct_input","details_artifact":None}
                    if response["status"]!="rejected" or not support.same(response["error"],expected_error):
                        raise AssertionError("old malformed describe no longer has its schema refusal")
                elif (response["status"]!="completed"
                        or response["result"]["catalog_sha256"]!=identity["catalog_sha256"]
                        or response["result"]["resources"]!=[response["result"]["manifest"]]
                        or response["result"]["next_cursor"] is not None):
                    raise AssertionError("valid installed manifest request did not complete")
                # No request_key is legal for hia_describe. A repeated call is
                # another original request attempt, not a durable journal hit.
                if data["requests"]!=[]:
                    raise AssertionError("describe invented a durable request key")
                costs=data["costs"]
                before=[] if previous is None else previous["costs"]
                if len(costs)!=len(before)+1 or not support.same(costs[:-1],before):
                    raise AssertionError("describe cost rows were rewritten or omitted")
                last=costs[-1]
                if (last["context_id"] is not None or last["tool"]!="hia_describe"
                        or last["request_id"]!=expected_id or last["status"]!=response["status"]
                        or type(last["wall_ns"]) is not str or not last["wall_ns"].isdecimal()
                        or not support.same(support.parse(last["details"].encode()),
                            {"error":response.get("error"),"replayed":False})):
                    raise AssertionError("actual describe cost event differs")
                if pair_first is None:
                    pair_first=(raw,data)
                elif (raw!=pair_first[0]
                        or any(not support.same(data[key],pair_first[1][key])
                               for key in ("requests","artifacts","profiles"))):
                    raise AssertionError("repeated describe response or non-cost database changed")
                previous=data
                event({"event":"stop","id":label,"kind":kind,"status":response["status"],
                       "stdout":observations[label]["stdout"],
                       "database":observations[label]["database_pin"]})
        record["state_file"]=support.file_pin(state_root/"state.sqlite3")
        record["malformed_repeated_rejection_checked"]=True
        record["valid_manifest_completed_repeat_checked"]=True
        record["status"]="PASS_REQUEST_CONTROLS_ONLY"
    finally:
        raw=(output/"worker-request-events.jsonl").read_bytes() if (output/"worker-request-events.jsonl").exists() else b""
        if raw!=b"".join(support.canonical(row)+b"\n" for row in events):
            raise AssertionError("installed request event bytes changed")
        record["events"]=support.bytes_pin(raw)


def run(args):
    from tests.test_hia_agent_installed_resources import RESOURCES,SDIST_SUPPORT_FILES
    from tests.test_hia_native_byte_abi import byte_program
    from hepta import hia_agent_service as api
    args.output.mkdir(mode=0o700,parents=True,exist_ok=False)
    report={"schema":"hepta.hia.service-bootstrap-installed.v2",**support.child_identity(),
            "status":"HOLD","source_before":support.source_snapshot(),
            "whole_native_stack_qualified":False}
    commands={};observations={};environment=clean_environment()
    source_raw,manifests,manifest_pin=support.capture_json(args.manifest_list)
    images_before=manifest_pins(manifests)
    # B has a separate real blocking retirement gate. This installed Store A
    # exercise neither enables B nor claims its missing retirement boundary.
    selected={name:path for name,path in manifests.items() if name!="candidate"}
    bundle_path=args.output/"bundle.json";bundle_sha=bundle(bundle_path,selected)
    report.update({"manifest_list":manifest_pin,"images_before":images_before,
                   "bundle":support.file_pin(bundle_path),"selected_helpers":list(selected),
                   "independent_budget_B_selected":False})
    def command(label,arguments,*,body=None,expected=0,cwd=ROOT):
        target=args.output/label
        result=run_owned([sys.executable,"-I","-B",*map(str,arguments)],cwd=cwd,directory=target,
            timeout_seconds=60,environment=environment,stdin=body)
        commands[label]=result
        raw=(target/"stdout.log").read_bytes();stderr=(target/"stderr.log").read_bytes()
        observations[label]={"stdout":support.bytes_pin(raw),"stderr":support.bytes_pin(stderr)}
        if (type(result["exit_code"]) is not int or result["exit_code"]!=expected
                or result["timed_out"] or result["interruption"]
                or not result["owned_cleanup"]["reaped"] or result["owned_cleanup"]["after"]
                or result["owned_cleanup"]["signals"]):
            raise AssertionError("installed owned command failed: "+label)
        return raw
    try:
        staging=args.output/"source";staging.mkdir()
        shutil.copytree(ROOT/"hepta",staging/"hepta",ignore=shutil.ignore_patterns("__pycache__"))
        for name in (*RESOURCES,*SDIST_SUPPORT_FILES,"setup.py","pyproject.toml","MANIFEST.in"):
            target=staging/name;target.parent.mkdir(parents=True,exist_ok=True)
            shutil.copyfile(ROOT/name,target)
        command("wheel",["-m","pip","wheel","--no-deps","--no-build-isolation","--no-index",
                         "--wheel-dir",args.output/"wheels",staging])
        wheel,=(args.output/"wheels").glob("*.whl")
        installed=args.output/"installed"
        command("install",["-m","pip","install","--no-deps","--no-index","--no-compile",
                           "--target",installed,wheel])
        installation=wheel_records(wheel,installed);report["installation"]=installation
        packaged=installed/"hepta/_data/examples/hia_bootstrap/service_bootstrap.hepta"
        if packaged.read_bytes()!=(ROOT/"examples/hia_bootstrap/service_bootstrap.hepta").read_bytes():
            raise AssertionError("bootstrap HIA source is not packaged exactly")
        worker=args.output/"worker.py";worker.write_text(WORKER)
        consumer=args.output/"consumer.py";consumer.write_text(CONSUMER)
        payload=args.output/"program.json";support.write_json(payload,byte_program())
        identity_raw=command("identity",[worker,installed,"--installation-manifest",
            "--native-helpers-manifest",bundle_path,"--expected-native-helpers-sha256",bundle_sha])
        identity=support.parse(identity_raw)
        if identity["native_helpers_sha256"]!=bundle_sha:
            raise AssertionError("actual installed worker identity does not bind bundle")
        report["worker_identity"]={"raw":support.bytes_pin(identity_raw),"value":identity}
        def expected_flags():
            return ["--expected-worker-sha256",identity["worker_sha256"],
                    "--expected-backend-sha256",identity["backend_sha256"],
                    "--expected-catalog-sha256",identity["catalog_sha256"]]
        files_root=args.output/"files";files_root.mkdir()
        describe_worker_controls(args.output,command,worker,installed,bundle_path,bundle_sha,
            identity,files_root,expected_flags(),observations,report,api)
        for mode in ("normal","lost_program_FINALIZE"):
            raw=command("consumer-"+mode,[consumer,installed,mode,bundle_path,bundle_sha,
                args.output/("consumer-state-"+mode),files_root,payload])
            value=support.parse(raw);observations["consumer-"+mode]["response"]=value
            if mode=="normal":
                if not {"1","2","3","4","5"}<=set(value["counts"]["mode"]):
                    raise AssertionError("installed consumer missed an actual public owner")
            elif value.get("close_refused") is not True:
                raise AssertionError("installed resource loss did not fence public close")
        original_source=packaged.read_bytes()
        try:
            packaged.write_bytes(original_source+b"\n")
            command("worker-source-LF",[worker,installed,"--installation-manifest",
                "--native-helpers-manifest",bundle_path,"--expected-native-helpers-sha256",bundle_sha,
                *expected_flags()],expected=2)
        finally:packaged.write_bytes(original_source)
        extra=installed/"hepta/_bootstrap_control_extra.py"
        try:
            with extra.open("xb") as stream:stream.write(b"MARKER = True\n")
            command("worker-extra-module",[worker,installed,"--installation-manifest",
                "--native-helpers-manifest",bundle_path,"--expected-native-helpers-sha256",bundle_sha,
                *expected_flags()],expected=2)
        finally:
            if extra.exists():extra.unlink()
        for kind in ("manifest-source","image-byte"):
            drift=args.output/kind;drift.mkdir()
            actual_manifest=Path(selected["bootstrap"])
            manifest_raw,manifest_value,_=support.capture_json(actual_manifest)
            image_name=manifest_value["image_path"]
            image_raw=(actual_manifest.parent/image_name).read_bytes()
            if kind=="manifest-source":manifest_value["source_sha256"]="0"*64
            else:image_raw=bytes([image_raw[0]^1])+image_raw[1:]
            (drift/image_name).write_bytes(image_raw)
            changed=drift/"manifest.json";support.write_json(changed,manifest_value)
            drift_paths={**selected,"bootstrap":str(changed)}
            bad_bundle=drift/"bundle.json";bad_digest=bundle(bad_bundle,drift_paths)
            command("worker-"+kind,[worker,installed,"--installation-manifest",
                "--native-helpers-manifest",bad_bundle,"--expected-native-helpers-sha256",bad_digest,
                *expected_flags()],expected=2)
            support.exact_reread(actual_manifest,manifest_raw)
        if not support.same(installation,wheel_records(wheel,installed)):
            raise AssertionError("installed files/RECORD did not return to exact identities")
        report["images_after"]=manifest_pins(manifests);report["source_after"]=support.source_snapshot()
        if (not support.same(report["source_before"],report["source_after"])
                or not support.same(images_before,report["images_after"])):
            raise AssertionError("installed original source/image changed")
        support.exact_reread(args.manifest_list,source_raw)
        report["all_repeated_worker_expected_flags"]=True
        report["all_five_public_methods_selected"]=True
        report["status"]="PASS_INSTALLED_ONLY"
        return 0
    finally:
        support.write_json(args.output/"commands.json",commands)
        support.write_json(args.output/"observations.json",observations)
        report["commands"]=support.file_pin(args.output/"commands.json")
        report["observations"]=support.file_pin(args.output/"observations.json")
        support.write_json(args.output/"report.json",report)

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-list",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    return run(parser.parse_args())
if __name__=="__main__":raise SystemExit(main())
