"""Refusal controls for independent native NDU persistent readback.

Only owned copies of complete actual observations are mutated. No native process
is executed here. The original campaign, its registration and the legacy Rust
reader remain intact; positive and negative readbacks are reported separately.
"""
from pathlib import Path
from hashlib import sha256
import argparse, importlib.util, json, shutil, stat, time

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source",type=Path,required=True)
    parser.add_argument("--directory",type=Path,required=True)
    parser.add_argument("--output",type=Path,required=True)
    args=parser.parse_args()
    source=args.source.resolve();original=args.directory.resolve();out=args.output.resolve()
    out.mkdir(mode=0o700)
    reader_source=source/"tools/replay_hia_ndu_persistent_native.py"
    reader_raw=reader_source.read_bytes();self_raw=Path(__file__).read_bytes()
    reader_path=out/"executed-reader.py";reader_path.write_bytes(reader_raw)
    spec=importlib.util.spec_from_file_location("_ndu_native_independent_control",reader_path)
    reader=importlib.util.module_from_spec(spec);spec.loader.exec_module(reader)
    def snapshot(root):
        return {str(p.relative_to(root)):{"bytes":p.stat().st_size,"sha256":sha256(p.read_bytes()).hexdigest(),
                "mode":stat.S_IMODE(p.stat().st_mode)}for p in sorted(root.rglob("*"))if p.is_file()}
    before=snapshot(original)
    working=out/"captured";shutil.copytree(original,working)
    base_reg=(working/"registration.json").read_bytes()
    base_report=(working/"result.json").read_bytes()
    reg=json.loads(base_reg);report=json.loads(base_report)
    digest=sha256(base_reg).hexdigest()
    positive=reader.replay(working,digest)
    assert positive["cells_replayed"]==72 and positive["original_native_responses_checked"]==1020
    (out/"positive.json").write_text(json.dumps(positive,indent=2)+"\n")
    saved={};controls=[]
    def remember(path):
        if path not in saved:saved[path]=(path.read_bytes(),stat.S_IMODE(path.stat().st_mode))
    def write(path,raw):
        remember(path);path.chmod(0o600);path.write_bytes(raw)
    def remove(path):
        remember(path);path.unlink()
    def restore():
        for path,(raw,mode)in reversed(tuple(saved.items())):
            if path.exists():path.chmod(0o600)
            path.write_bytes(raw);path.chmod(mode)
            assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
        saved.clear()
    def rebound(modify):
        current=json.loads(base_reg);result=json.loads(base_report)
        modify(current,result)
        raw=(json.dumps(current,sort_keys=True,indent=2)+"\n").encode()
        new_digest=sha256(raw).hexdigest();result["registration_sha256"]=new_digest
        write(working/"registration.json",raw)
        write(working/"result.json",(json.dumps(result,sort_keys=True,indent=2)+"\n").encode())
        return new_digest
    def refused(name,action,phrase,*,missing=False):
        try:
            action()
        except ValueError as error:
            assert phrase in str(error),(name,str(error))
            controls.append({"case":name,"refused":True,"error":str(error)})
        except FileNotFoundError as error:
            assert missing,(name,str(error))
            controls.append({"case":name,"refused":True,"error":"FileNotFoundError"})
        else:raise AssertionError("readback falsely accepted: "+name)
        finally:restore()
    started=time.monotonic()
    # Each required source is physically absent, and both digest declarations
    # are rebound. The fixed full inventory must still reject all 418 cases.
    for name in sorted(reader.FIXED_SOURCE):
        def action(name=name):
            remove(working/"frozen-source"/name)
            def alter(r,p):
                del r["source_files"][name];del p["source_files"][name]
            return reader.replay(working,rebound(alter))
        refused("missing-required:"+name,action,"closed native source inventory")
    assert len(controls)==418
    for name,key,value in (("bool-cell-count","planned_cells",True),
                           ("float-process-count","native_processes_started",534.0)):
        def action(key=key,value=value):
            result=json.loads(base_report);result[key]=value
            write(working/"result.json",(json.dumps(result,sort_keys=True,indent=2)+"\n").encode())
            return reader.replay(working,digest)
        refused(name,action,"invalid observed integer")
    def binary_bool():
        return reader.replay(working,rebound(lambda r,p:r.update(native_binary_bytes=True)))
    refused("bool-native-byte-count",binary_bool,"invalid observed integer")
    for name,phrase in (
        ("tools/qualify_hia_ndu_persistent_native.py","exact native producer source"),
        ("hepta/hia_ndu_optimizer.py","exact native execution source"),
        ("examples/hia_bootstrap/ndu_evaluator.hepta","native leaf source identity"),
        ("examples/hia_bootstrap/ndu_rank_binding.hepta","native rank source identity")):
        def action(name=name):
            path=working/"frozen-source"/name;raw=path.read_bytes()+b"\n# changed\n";write(path,raw)
            def alter(r,p):
                r["source_files"][name]=sha256(raw).hexdigest();p["source_files"][name]=sha256(raw).hexdigest()
            return reader.replay(working,rebound(alter))
        refused("rebound-source:"+name,action,phrase)
    def build_receipt():
        raw=(working/"original-build-receipt.json").read_bytes()+b" "
        write(working/"original-build-receipt.json",raw)
        def alter(r,p):
            r["original_build_receipt_sha256"]=sha256(raw).hexdigest()
            r["native_identity"]["build_receipt_sha256"]=sha256(raw).hexdigest()
            p["native_identity"]["build_receipt_sha256"]=sha256(raw).hexdigest()
        return reader.replay(working,rebound(alter))
    refused("rebound-whole-build-receipt",build_receipt,"fixed whole native construction receipt")
    def rank_contract():
        raw=(working/"original-rank-contract.json").read_bytes()+b" "
        write(working/"original-rank-contract.json",raw)
        def alter(r,p):
            r["rank_contract_sha256"]=sha256(raw).hexdigest();p["rank_contract_sha256"]=sha256(raw).hexdigest()
        return reader.replay(working,rebound(alter))
    refused("rebound-whole-rank-contract",rank_contract,"exact current rank policy contract")
    product=working/"recorded-products/_hia_ndu_rank_engine.bin"
    def image_mutation():
        raw=product.read_bytes();write(product,raw[:-1]+bytes([raw[-1]^1]))
        return reader.replay(working,digest)
    refused("physical-native-product",image_mutation,"native rank product complete bytes")
    def import_window():
        write(reader_path,reader_raw+b"\n# changed after import\n")
        return reader.replay(working,digest)
    refused("executed-reader-after-import",import_window,"executed reader changed since import")
    old_check=reader.check_cost_intervals
    for name,path in (
        ("late-native-source",working/"frozen-source/examples/hia_bootstrap/ndu_rank_binding.hepta"),
        ("late-product",product),
        ("late-originals",working/"h01-p01-prepared_ndu-originals.jsonl"),
        ("late-reader-self",reader_path)):
        def action(path=path):
            def late(cells,result):
                old_check(cells,result)
                write(path,path.read_bytes()+b"\nlate\n")
            reader.check_cost_intervals=late
            try:return reader.replay(working,digest)
            finally:reader.check_cost_intervals=old_check
        refused(name,action,"physical input changed at terminal")
    empty=out/"missing-root";empty.mkdir()
    refused("missing-captured-root",lambda:reader.replay(empty,digest),"",missing=True)
    legacy_path=source/"tools/replay_hia_ndu_persistent_ranker.py"
    legacy_raw=legacy_path.read_bytes()
    assert sha256(legacy_raw).hexdigest()=="0bfe5bfe6b5b78d4afeb9ca34e4d90a464bb98aff1d7b6beac02e6bc17d3f805"
    legacy_spec=importlib.util.spec_from_file_location("_ndu_preserved_rust_profile",legacy_path)
    legacy=importlib.util.module_from_spec(legacy_spec);legacy_spec.loader.exec_module(legacy)
    refused("legacy-profile-still-rejects-native",lambda:legacy.replay(working,digest),"closed frozen-source inventory")
    terminal_positive=reader.replay(working,digest)
    assert terminal_positive==positive and before==snapshot(original)
    assert reader_source.read_bytes()==reader_raw and legacy_path.read_bytes()==legacy_raw
    assert Path(__file__).read_bytes()==self_raw and reader_path.read_bytes()==reader_raw
    result={"schema":"hepta.hia.ndu-native-persistent-readback-controls.v1","passed":True,
        "count":len(controls),"required_path_refusals":418,"controls":controls,"original_campaign_unchanged":True,
        "positive":positive,"positive_after_all_mutations":terminal_positive,"reader_sha256":sha256(reader_raw).hexdigest(),
        "executed_control_sha256":sha256(self_raw).hexdigest(),"seconds":time.monotonic()-started,
        "native_execution_repeated":False}
    (out/"report.json").write_text(json.dumps(result,indent=2)+"\n")
    print(json.dumps({k:v for k,v in result.items()if k!="controls"}),flush=True)
    return 0
if __name__=="__main__":raise SystemExit(main())
