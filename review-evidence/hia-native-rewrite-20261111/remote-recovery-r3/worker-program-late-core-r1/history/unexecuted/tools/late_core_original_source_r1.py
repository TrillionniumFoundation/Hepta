"""Read the complete original role23 archive and reproduce its exact HIA.

No original test is rerun.  All 2981 members are hashed before selected
authoring is imported.  The unused IR authoring module is parsed only for its
literal SOURCE; its original Builder/other runtime imports are not executed.
The old visitor image remains a source-bound dependency, not a new test PASS.
"""
from __future__ import annotations
import ast,importlib.util,json,stat,sys,tarfile,types
from hashlib import sha256
from pathlib import Path,PurePosixPath

ARCHIVE_BYTES=722432
ARCHIVE_SHA="0f6d044b158c647592418784022a4b0450cb65cc0ec54dcc71884ee97a51e407"
CUSTODY_SHA="e94c07106d219a73c52e7836d5906e085844e7c97f608ce78cd75de340521c2e"
SELECTED={
 "checkpoints/source-dev-r1/tools/generate_hia_composite_core_final.py":
    (5461,"2289db846e25e4ed658eba00ba8c51531255ef45b5859a4a3ecf0b78bef41428"),
 "checkpoints/source-dev-r1/tools/generate_hia_composite_core_final_common.py":
    (10325,"4aa9548da4efe72ac1fd9b75b1a725a81b04a28d1d43648be0b69a57f3eb8c27"),
 "checkpoints/source-dev-r1/tools/generate_hia_composite_core_final_stream.py":
    (10919,"f57a429ebbeb6adb5fe0331ec25100f82cc9a69df452f812603e8ffe7648d78a"),
 "dependencies/driver/tools/generate_hia_composite_object_ir.py":
    (18333,"32995ab727a01acd424f75aa336fd46264d6644586ed8471e90dcd60d299be48"),
 "checkpoints/source-dev-r1/examples/hia_bootstrap/composite_core_final.hiaasm":
    (140616,"34f0d66c4ffe19b286dab5ad5c07d3b11e69bf8cd6c9e27d4bd3ddb53cf87e66"),
 "development/compile-visitor-r1/composite-core-final.image.bin":
    (212690,"b210b6e1f8347c783273baf860e76a1e2462a7be4d38529c122dc722252e508e"),
 "development/compile-visitor-r1/composite-core-final.manifest.json":
    (647,"fc5820dc5533743b75df1d4ddb5f60b69ebdfe9d1fbd625639f25f6140cf1f08"),
 "development/compile-visitor-r1/composite-core-final.receipt.json":
    (1749,"a16b9bb03eaba26f7d404dcc92f759e8ae35c817ae0f74f8c060147de6e6990f"),
}
def digest(raw):return sha256(raw).hexdigest()
def dump(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def restore_and_generate(project,reference,out,role_map,read,render_assembly):
    project=Path(project);reference=Path(reference);out=Path(out)
    out.mkdir(parents=True,exist_ok=False)
    archive=project/"resources/core-final-stage1.tar.xz"
    custody=project/"resources/core-final-stage1-custody.json"
    raw=read(archive);metadata=read(custody)
    assert (len(raw),digest(raw))==(ARCHIVE_BYTES,ARCHIVE_SHA)
    assert len(metadata)==658863 and digest(metadata)==CUSTODY_SHA
    original=json.loads(metadata)
    assert (original["archive_bytes"],original["archive_sha256"],
            original["members"],original["raw_bytes"])==(ARCHIVE_BYTES,ARCHIVE_SHA,2981,218379198)
    rows=original["files"]
    assert type(rows) is list and len(rows)==2981
    expected={row["path"]:row for row in rows};assert len(expected)==len(rows)
    seen=set();found={};total=0;ledger=[]
    with tarfile.open(archive,"r|xz") as tf:
        for member in tf:
            path=PurePosixPath(member.name)
            assert member.name and not path.is_absolute() and ".." not in path.parts
            assert member.name not in seen and member.name in expected
            row=expected[member.name];seen.add(member.name)
            assert member.isfile() and member.mode==row["mode"]==0o644
            assert member.size==row["bytes"]
            stream=tf.extractfile(member);assert stream is not None
            value=[] if member.name in SELECTED else None;size=0;h=sha256()
            with stream:
                for chunk in iter(lambda:stream.read(1<<20),b""):
                    size+=len(chunk);h.update(chunk)
                    if value is not None:value.append(chunk)
            assert (size,h.hexdigest())==(row["bytes"],row["sha256"]),member.name
            total+=size;ledger.append(dict(row))
            if value is not None:found[member.name]=b"".join(value)
    assert seen==set(expected) and total==218379198
    assert set(found)==set(SELECTED)
    dump(out/"complete-original-member-readback.json",ledger)
    selected={}
    for member,raw in found.items():
        assert (len(raw),digest(raw))==SELECTED[member],member
        destination=out/"originals"/member
        destination.parent.mkdir(parents=True,exist_ok=True)
        with destination.open("xb") as f:f.write(raw)
        destination.chmod(0o644)
        assert read(destination)==raw
        selected[Path(member).name]=destination
    role=role_map["components"]["23"]
    old_hia=read(Path(role["source_path"]));old_image=read(Path(role["image_path"]))
    assert old_hia==found["checkpoints/source-dev-r1/examples/hia_bootstrap/composite_core_final.hiaasm"]
    assert old_image==found["development/compile-visitor-r1/composite-core-final.image.bin"]
    receipt=json.loads(found["development/compile-visitor-r1/composite-core-final.receipt.json"])
    assert receipt["status"]=="returned" and receipt["abi_status"]==0
    assert receipt["input_sha256"]==digest(old_hia)
    assert receipt["produced_sha256"]==digest(old_image)
    assert receipt["artifact_sha256"]=="0e09ccca227d8f8ed7e7fa37111d2c44e1329517b19763bd9f280d00135591c8"
    ir_path=selected["generate_hia_composite_object_ir.py"]
    ir_raw=read(ir_path);ir_nodes=ast.parse(ir_raw,filename=str(ir_path)).body
    assignments=[node for node in ir_nodes if isinstance(node,ast.Assign)
        and any(isinstance(target,ast.Name) and target.id=="SOURCE" for target in node.targets)]
    assert len(assignments)==1
    ir_source=ast.literal_eval(assignments[0].value)
    assert type(ir_source) is str
    assert not any(isinstance(node,ast.AugAssign) and isinstance(node.target,ast.Name)
                   and node.target.id=="SOURCE" for node in ir_nodes)
    names=("tools.generate_hia_composite_object_ir",
           "tools.generate_hia_composite_core_final_common",
           "tools.generate_hia_composite_core_final_stream",
           "worker_exact_original_Core_visitor_r1")
    saved={name:sys.modules.get(name) for name in names}
    def load(name,path):
        source=read(path);ast.parse(source,filename=str(path))
        spec=importlib.util.spec_from_file_location(name,path)
        module=importlib.util.module_from_spec(spec);sys.modules[name]=module
        spec.loader.exec_module(module);return module
    try:
        ir=types.ModuleType(names[0]);ir.SOURCE=ir_source;ir.__file__=str(ir_path)
        sys.modules[names[0]]=ir
        load(names[1],selected["generate_hia_composite_core_final_common.py"])
        load(names[2],selected["generate_hia_composite_core_final_stream.py"])
        generator=load(names[3],selected["generate_hia_composite_core_final.py"])
        body=generator.source_program();document=generator.document()
        generated=render_assembly(document).encode("utf-8")
        assert generated==old_hia,(len(generated),digest(generated),digest(old_hia))
        (out/"reproduced-source.hiaasm").write_bytes(generated)
        (out/"reproduced-authoring.py").write_text(body)
        dump(out/"reproduced-document.json",document)
    finally:
        for name,previous in saved.items():
            if previous is None:sys.modules.pop(name,None)
            else:sys.modules[name]=previous
    # The caller's read() pins the complete originals and every emitted copy.
    # Its unconditional final before/after gate owns the whole build lifetime.
    assert (len(read(archive)),digest(read(archive)))==(ARCHIVE_BYTES,ARCHIVE_SHA)
    assert digest(read(custody))==CUSTODY_SHA
    proof=dict(schema="hia-worker-late-Core-original-source-reproduction-r1",
        original_archive_bytes=ARCHIVE_BYTES,original_archive_sha256=ARCHIVE_SHA,
        complete_original_members=len(ledger),complete_original_raw_bytes=total,
        original_bytes_SHA256_modes_all_checked=True,
        exact_role23_HIA_reproduced=True,source_bytes=len(old_hia),source_sha256=digest(old_hia),
        image_bytes=len(old_image),image_sha256=digest(old_image),
        original_compile_receipt_copied_only=True,original_tests_reexecuted=0,
        IR_SOURCE_literal_only=True,original_IR_module_executed=False,
        selected_source_members=SELECTED,new_native_entries=0,
        new_compiler_entries=0,no_old_qualification_inherited=True)
    dump(out/"proof.json",proof)
    return body,document,proof
