"""Read complete immutable timing traces; no HIA, VM, B3 or target execution."""
from __future__ import annotations
import argparse,heapq,json,resource,stat,struct,sys,time,traceback
from decimal import Decimal
from hashlib import sha256
from pathlib import Path
sys.dont_write_bytecode=True
p=argparse.ArgumentParser()
p.add_argument("--capture",type=Path,required=True)
p.add_argument("--build",type=Path,required=True)
p.add_argument("--original-readback",type=Path,required=True)
p.add_argument("--out",type=Path,required=True)
a=p.parse_args()
CAPTURE=a.capture.resolve();BUILD=a.build.resolve();ORIGINAL=a.original_readback.resolve();OUT=a.out.resolve()
assert all(OUT!=root and not OUT.is_relative_to(root) for root in (CAPTURE,BUILD,ORIGINAL))
OUT.mkdir(parents=True,exist_ok=False)
resource.setrlimit(resource.RLIMIT_CPU,(90,90))
resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
START=time.monotonic_ns();PINS={};results=[];status="FAIL";details={}
MAGIC=int.from_bytes(b"HIAIPT01","little")
def save(name,value):
    path=OUT/name;path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def identity(path):
    path=Path(path).resolve();before=path.lstat()
    assert stat.S_ISREG(before.st_mode) and before.st_nlink==1 and not path.is_symlink()
    h=sha256()
    with path.open("rb") as f:
        while True:
            raw=f.read(1<<20)
            if not raw:break
            h.update(raw)
    after=path.lstat()
    assert (before.st_dev,before.st_ino,before.st_size,before.st_mode,before.st_mtime_ns,before.st_ctime_ns)==(
        after.st_dev,after.st_ino,after.st_size,after.st_mode,after.st_mtime_ns,after.st_ctime_ns)
    return dict(path=str(path),bytes=before.st_size,sha256=h.hexdigest(),mode=stat.S_IMODE(before.st_mode))
def pin(path):
    path=Path(path).resolve();row=identity(path)
    if path in PINS:assert row==PINS[path]
    PINS[path]=row
    return row
def read(path):
    row=pin(path);raw=Path(path).read_bytes()
    assert len(raw)==row["bytes"] and sha256(raw).hexdigest()==row["sha256"]
    return raw
def ns(frame,word):
    assert frame[word+1]<1000000000
    return frame[word]*1000000000+frame[word+1]
def frame_view(frame,offset):
    return dict(byte_offset=str(offset),u64_decimal=[str(x) for x in frame],
        stage=str(frame[1]),controller_role=str(frame[6]),kind=str(frame[7]),
        lease=str(frame[8]),sequence=str(frame[9]),event_operation=str(frame[10]),
        event_role=str(frame[11]),input_bytes=str(frame[12]),
        second_capacity=str(frame[13]),workspace_capacity=str(frame[14]),
        original_or_returned_RAX=str(frame[15]),
        thread_CPU_ns=str(ns(frame,2)),monotonic_ns=str(ns(frame,4)))
def analyze(record):
    label=record["label"];path=Path(record["streams"]["trace"]["path"]).resolve()
    assert path.is_relative_to(CAPTURE)
    before=pin(path);assert before==record["streams"]["trace"]
    pending=None;previous_CPU=previous_wall=None;first_CPU=last_CPU=0
    count=complete=0;total_CPU=total_wall=0;by_role={};top=[];trailing=b""
    with path.open("rb") as stream:
        while True:
            offset=stream.tell();raw=stream.read(128)
            if not raw:break
            if len(raw)!=128:trailing=raw;break
            words=struct.unpack("<16Q",raw)
            assert words[0]==MAGIC and words[1] in (1,2,3,4),(label,offset,"frame header")
            cpu=ns(words,2);wall=ns(words,4)
            assert previous_CPU is None or cpu>=previous_CPU,(label,offset,"CPU order")
            assert previous_wall is None or wall>=previous_wall,(label,offset,"wall order")
            if count==0:first_CPU=cpu
            previous_CPU=last_CPU=cpu;previous_wall=wall;count+=1
            if words[1] in (1,3):
                assert pending is None,(label,offset,"interleaved before frame")
                pending=(offset,words)
                continue
            assert pending is not None,(label,offset,"after without before")
            at,old=pending
            assert words[1]==old[1]+1 and words[6:10]==old[6:10],(label,offset,"pair context")
            if old[1]==3:assert words[10:15]==old[10:15],(label,offset,"component event mutated")
            family="controller" if old[1]==1 else "component"
            role=old[6] if family=="controller" else old[11]
            assert 1<=role<=63,(label,role)
            delta_CPU=cpu-ns(old,2);delta_wall=wall-ns(old,4)
            complete+=1;total_CPU+=delta_CPU;total_wall+=delta_wall
            key=(family,role)
            row=by_role.setdefault(key,dict(family=family,role=role,calls=0,CPU_ns=0,wall_ns=0,
                max_CPU_ns=0,max_wall_ns=0,minimum_input_bytes=None,maximum_input_bytes=0,
                controller_roles=set(),first_before_offset=at,last_after_offset=offset))
            row["calls"]+=1;row["CPU_ns"]+=delta_CPU;row["wall_ns"]+=delta_wall
            row["max_CPU_ns"]=max(row["max_CPU_ns"],delta_CPU);row["max_wall_ns"]=max(row["max_wall_ns"],delta_wall)
            row["first_before_offset"]=min(row["first_before_offset"],at);row["last_after_offset"]=offset
            row["controller_roles"].add(old[6])
            if family=="component":
                row["minimum_input_bytes"]=old[12] if row["minimum_input_bytes"] is None else min(row["minimum_input_bytes"],old[12])
                row["maximum_input_bytes"]=max(row["maximum_input_bytes"],old[12])
            segment=dict(family=family,role=str(role),CPU_ns=str(delta_CPU),wall_ns=str(delta_wall),
                before=frame_view(old,at),after=frame_view(words,offset))
            heapq.heappush(top,(delta_CPU,complete,segment))
            if len(top)>32:heapq.heappop(top)
            pending=None
    assert count*128+len(trailing)==before["bytes"]
    assert complete*2+(1 if pending is not None else 0)==count
    if record["calibration"] or record["returncode"]==0:
        assert pending is None and not trailing,(label,"successful process lacks full trace pairs")
    values=[]
    for key,row in by_role.items():
        output=dict(row)
        output["role"]=str(output["role"]);output["controller_roles"]=[str(x) for x in sorted(output["controller_roles"])]
        for name in ("CPU_ns","wall_ns","max_CPU_ns","max_wall_ns","first_before_offset","last_after_offset","minimum_input_bytes","maximum_input_bytes"):
            output[name]=None if output[name] is None else str(output[name])
        binding=bindings[str(row["role"])]
        output["original_image_binding"]={k:binding[k] for k in ("source_path","source_bytes","source_sha256","image_path","image_bytes","image_sha256")}
        values.append(output)
    values.sort(key=lambda row:(-int(row["CPU_ns"]),row["family"],int(row["role"])))
    approximate_child_CPU=int((Decimal(str(record["child_user_CPU_seconds"]))+Decimal(str(record["child_system_CPU_seconds"])))*Decimal(1000000000))
    value=dict(label=label,status="COMPLETE_READ_ONLY_TRACE_ANALYSIS",
        original_process_returncode=record["returncode"],original_process_timed_out=record["timed_out"],
        complete_trace=before,full_frames=count,complete_entry_pairs=complete,
        trailing_raw_bytes=len(trailing),trailing_raw_hex=trailing.hex(),
        first_frame_thread_CPU_ns=str(first_CPU),last_frame_thread_CPU_ns=str(last_CPU),
        summed_complete_pair_CPU_ns=str(total_CPU),summed_complete_pair_wall_ns=str(total_wall),
        approximate_child_rusage_CPU_ns=str(approximate_child_CPU),
        approximate_CPU_after_last_frame_ns=str(approximate_child_CPU-last_CPU),
        unmatched_before_frame=None if pending is None else frame_view(pending[1],pending[0]),
        unmatched_before_is_not_proof_of_exact_in_flight_HIA_call=True,
        note="A missing after frame may mean HIA is still running or it returned before its after frame was fully written. Before-to-after includes the before hook sampling and write overhead. Rusage tail is approximate and includes code outside the measured pair.",
        all_complete_pair_totals_include_before_hook_overhead=True,
        top_complete_pairs=[x[2] for x in sorted(top,reverse=True)],
        by_role=values,new_HIA=0,new_B3=0,new_VM=0,new_native=0,
        original_qualification_unchanged=True,semantic_qualification=False,whole_stack_closed=False)
    save(label+"/timing-analysis.json",value)
    assert identity(path)==before
    return value
try:
    read(__file__)
    original_index=read(ORIGINAL/"impact-original-member-index.json")
    assert len(original_index)==1376145 and sha256(original_index).hexdigest()=="9e63275d5f9541d69aa8bf75a0c2e2fa8f736af0fdc62374fdcfdd2ef97b4b48"
    indexed={r["name"]:r for r in json.loads(original_index)};assert len(indexed)==3090
    manifest_name="ordinary-impact-coordinator/development/build-r1/manifest.json"
    manifest_path=ORIGINAL/"archive-originals"/manifest_name
    manifest_raw=read(manifest_path);expected=indexed[manifest_name]
    assert (len(manifest_raw),sha256(manifest_raw).hexdigest(),stat.S_IMODE(manifest_path.stat().st_mode))==(expected["bytes"],expected["sha256"],expected["mode"])
    bindings=json.loads(manifest_raw)["role_bindings"]
    assert set(bindings)=={str(i) for i in range(1,64)}
    build=json.loads(read(BUILD/"manifest.json"))
    assert build["retained_HIA_images"]==63 and build["all_retained_source_image_bytes_bound"]
    for row in build["role_bindings"]:
        original=bindings[str(row["role"])]
        for key in ("source_bytes","source_sha256","image_bytes","image_sha256"):assert original[key]==row[key]
    capture=json.loads(read(CAPTURE/"summary.json"))
    assert capture["semantic_images_changed"]==0 and not capture["semantic_qualification"]
    for record in capture["processes"]:
        for stream in record["streams"].values():
            path=Path(stream["path"]).resolve();assert path.is_relative_to(CAPTURE)
            assert pin(path)==stream
        if record["streams"]["trace"]["bytes"]>0:results.append(analyze(record))
    assert capture["status"]=="PASS_DIAGNOSTIC_CAPTURE_ONLY"
    assert capture["actual_ELF_processes_started"]==capture["actual_processes_with_returned_record"]==3
    assert [x["label"] for x in results]==["calibration-timed","large-valid-timed"]
    assert capture["source_and_image_before_after_equal"] and capture["parent_plus_children_CPU_seconds"]<90
    status="PASS_TIMING_ANALYSIS_ONLY"
except BaseException as exc:
    details.update(error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
    traceback.print_exc()
finally:
    after_errors=[]
    for path,before in PINS.items():
        try:assert identity(path)==before
        except BaseException as exc:after_errors.append(dict(path=str(path),error=repr(exc)))
    usage=resource.getrusage(resource.RUSAGE_SELF)
    CPU=usage.ru_utime+usage.ru_stime;elapsed=time.monotonic_ns()-START
    if after_errors or CPU>=90 or elapsed>=180000000000:status="FAIL"
    details.update(schema="hia-impact-mechanical-timing-analysis-v1",status=status,
        actual_new_HIA=0,actual_new_B3=0,actual_new_VM=0,actual_new_native=0,
        original_impact_failure_unchanged=True,semantic_qualification=False,whole_stack_closed=False,
        complete_inputs_before_after_equal=not after_errors,after_check_errors=after_errors,
        parent_CPU_seconds=CPU,elapsed_ns=str(elapsed),
        actual_limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
            address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE)),
            wall_seconds=180),
        results=results,complete_original_raw_traces_preserved=True)
    save("input-pins.json",list(PINS.values()));save("summary.json",details)
    projection=dict(status=status,new_native=0,semantic_qualification=False,
        input_before_after_equal=not after_errors,CPU_seconds=CPU,elapsed_ns=str(elapsed),
        error_class=details.get("error_class"),error=details.get("error"),traceback=details.get("traceback"),
        results=[{k:r[k] for k in ("label","original_process_returncode","full_frames","complete_entry_pairs",
            "trailing_raw_bytes","summed_complete_pair_CPU_ns","approximate_CPU_after_last_frame_ns",
            "unmatched_before_frame","unmatched_before_is_not_proof_of_exact_in_flight_HIA_call","by_role")} for r in results])
    print("HIA_IMPACT_TIMING_ANALYSIS "+json.dumps(projection,sort_keys=True),flush=True)
if status!="PASS_TIMING_ANALYSIS_ONLY":raise SystemExit(1)
