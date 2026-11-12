"""Build the new assembly publication CLI from exact component snapshots.
Development authoring and packaging only; Python never handles a native request.
The complete inactive E table remains independently pinned and is not qualified.
"""
from pathlib import Path
from hashlib import sha256,sha1
import ast,ctypes,importlib,json,os,struct,sys,zlib
sys.dont_write_bytecode=True
def digest(raw):return sha256(raw).hexdigest()
def save(path,value):
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(json.dumps(value,sort_keys=True,indent=2)+"\n")
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def protected(raw,size=None):
    size=len(raw) if size is None else size
    assert len(raw)<=size
    guard=b"HIA-FINITE-CARRIER-CANARY-32BYTE";assert len(guard)==32
    backing=ctypes.create_string_buffer(64+max(1,size));at=ctypes.addressof(backing)+32
    ctypes.memmove(at-32,guard,32);ctypes.memmove(at,raw,len(raw))
    ctypes.memmove(at+max(1,size),guard,32)
    return backing,at,size,guard
def checked(row):
    _,at,size,guard=row
    assert ctypes.string_at(at-32,32)==guard and ctypes.string_at(at+max(1,size),32)==guard

class Custody:
    def __init__(self,out):
        self.out=Path(out);self.pins={}
    def read(self,path):
        path=Path(path).resolve();raw=path.read_bytes()
        if path in self.pins:assert self.pins[path]==(len(raw),digest(raw)),path
        self.pins[path]=(len(raw),digest(raw))
        return raw
    def row(self,row):
        raw=self.read(row["path"])
        assert (len(raw),digest(raw))==(row["bytes"],row["sha256"]),row
        return raw
    def cas(self,raw):
        raw=bytes(raw);h=digest(raw);p=self.out/"cas"/(h+".zlib");p.parent.mkdir(exist_ok=True)
        if not p.exists():p.write_bytes(zlib.compress(raw,6))
        assert zlib.decompress(p.read_bytes())==raw
        return dict(bytes=len(raw),sha256=h,path="cas/"+p.name,compression="zlib")
    def finish(self):
        changed=[]
        for path,pin in self.pins.items():
            try:raw=path.read_bytes()
            except OSError:changed.append(str(path));continue
            if (len(raw),digest(raw))!=pin:changed.append(str(path))
        save(self.out/"source-pins.json",[dict(path=str(p),bytes=v[0],sha256=v[1]) for p,v in self.pins.items()])
        total=0;objects=0
        for path in sorted((self.out/"cas").glob("*.zlib")):
            raw=zlib.decompress(path.read_bytes());assert digest(raw)==path.stem
            total+=len(raw);objects+=1
        result=dict(status="PASS" if not changed else "FAIL",source_pins_unchanged=not changed,
            changed_paths=changed,cas_objects=objects,cas_logical_bytes=total)
        save(self.out/"custody.json",result);assert not changed,changed
        return result

def build(root,reference,assets_path,inactive_map,inactive_dir,sha_source,sha_image,out,custody):
    root=Path(root);reference=Path(reference);out=Path(out);out.mkdir(parents=True,exist_ok=False)
    c=custody;c.read(__file__)
    for path in sorted((root/"tools").glob("*.py")):c.read(path)
    sys.path[:0]=[str(root/"tools"),str(root.parent/"Hepta-agent-edit-native"),str(reference)]
    assets=json.loads(c.read(assets_path))
    assert assets["status"]=="PASS_READBACK_ONLY" and not assets["old_case_counts_inherited"]
    assert assets["source_image_bindings"] and assets["preserved_original_inputs_unchanged"]
    compiler=assets["compiler"];compiler_raw=c.row(compiler)
    assert (len(compiler_raw),digest(compiler_raw))==(669556,"35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b")
    parent={};first={};second={};original_first={};source_rows={}
    for role,row in assets["cli_roles"].items():
        c.row(row["source"]);parent[int(role)]=c.row(row["image"])
        if "manifest" in row:c.row(row["manifest"])
    for role,row in assets["service_roles"].items():
        c.row(row["source"]);first[int(role)]=c.row(row["image"])
    original_first=dict(first)
    map_raw=c.read(inactive_map)
    assert git_blob(map_raw)=="35202c1c5961923b60f6100e07fa696e2c8f84a0"
    inactive=json.loads(map_raw)
    assert set(inactive["components"])=={str(i) for i in range(1,64)}
    for role in range(1,64):
        pin=inactive["components"][str(role)]
        source=c.read(Path(inactive_dir)/str(role)/"source.hiaasm")
        image=c.read(Path(inactive_dir)/str(role)/"image.bin")
        assert (len(source),digest(source))==(pin["source_bytes"],pin["source_sha256"]),(role,"source")
        assert (len(image),digest(image))==(pin["image_bytes"],pin["image_sha256"]),(role,"image")
        second[role]=image
        source_rows["2:"+str(role)]=dict(source_bytes=len(source),source_sha256=digest(source),
            image_bytes=len(image),image_sha256=digest(image),scope="INACTIVE_EXACT_DEPENDENCY")
    base=c.row(assets["packer"]["assembly"])
    assert digest(base)=="f06b915cdfb415894e05c8c4a3e7bbdba9fe9c0bc5b8791878516f91cdfa66de"
    sr=c.read(sha_source);ir=c.read(sha_image)
    assert (len(sr),digest(sr))==(33683,"a30377e1f08a3426cfffe609ddbe35de67e87791cb0e9645c79e063f5d3d205a")
    assert (len(ir),digest(ir))==(38349,"7bca81777197af059b1b5c48e340c0215214370fec007bb82ae5cadca81ef274")
    parent[10]=ir
    import cli_authoring
    from hepta.hia_agent_assembly import assemble_program,render_assembly
    from tools.qualify_hia_selfhost import compile_stage
    assert digest(c.read(reference/"tools/qualify_hia_selfhost.py"))=="2674bbc29a67214c16595a226a0dfb28d3dcf56e238058d45e618dd42925cb76"
    compiled=[]
    def compile_document(label,doc,authoring):
        profile=cli_authoring.profile(doc)
        where=out/"compiled"/label;where.mkdir(parents=True)
        (where/"authoring.py").write_text(authoring);save(where/"profile.json",profile)
        raw=render_assembly(doc).encode();(where/"source.hiaasm").write_bytes(raw)
        assert profile["functions"]<=128 and profile["blocks"]<=1536 and profile["ops"]<=8192
        assert profile["max_params"]<=16 and max(len(f["blocks"]) for f in doc["functions"])<=256 and len(raw)<=1<<20
        assemble_program(raw)
        c.read(where/"source.hiaasm")
        assert c.read(compiler["path"])==compiler_raw
        image,receipt=compile_stage(where,label,Path(compiler["path"]),raw)
        binary=c.read(image)
        assert receipt["artifact_sha256"]==digest(compiler_raw)
        assert receipt["input_sha256"]==digest(raw) and receipt["produced_sha256"]==digest(binary)
        assert receipt["status"]=="returned" and receipt["abi_status"]==0
        assert receipt["limits"]["cpu_seconds"]==10 and receipt["limits"]["address_bytes"]==256<<20
        assert c.read(compiler["path"])==compiler_raw and c.read(where/"source.hiaasm")==raw
        row=dict(label=label,source_path=str(where/"source.hiaasm"),source_bytes=len(raw),source_sha256=digest(raw),
            image_path=str(image),image_bytes=len(binary),image_sha256=digest(binary),profile=profile,receipt=receipt)
        compiled.append(row);save(where/"manifest.json",row);c.read(where/"manifest.json")
        print("HIA_ASSEMBLY_CLI_COMPILE "+json.dumps(row,sort_keys=True),flush=True)
        return binary
    def compile_body(label,body,constants):
        text=cli_authoring.expanded(body,constants)
        return compile_document(label,cli_authoring.document(text,label.replace("-","_")),text)

    import cli_publication_presentation_owner as presentation
    body,constants,meta=presentation.source();save(out/"presentation-tables.json",meta)
    parent[14]=compile_body("assembly-publication-presentation",body,constants)
    for role,name in {8:"cli_publication_verified_owner",9:"cli_publication_path_owner",
                     11:"cli_publication_stage_writer",12:"cli_publication_tempdir_owner",
                     13:"cli_publication_cleanup_owner"}.items():
        owner=importlib.import_module(name)
        body=owner.BODY+(owner.message_body() if role==8 else "")
        parent[role]=compile_body(name,body,owner.CONSTANTS)
    import cli_publication_parent_owner as owner
    parent[7]=compile_body("assembly-public-parent",owner.BODY+owner.literals()+owner.COMMON,owner.CONSTANTS)

    import assembly_syntax_owner,assembly_render_owner,assembly_object_prefix
    body,constants,meta=assembly_syntax_owner.source();save(out/"syntax-metadata.json",meta)
    first[61]=compile_body("assembly-syntax",body,constants)
    body,constants,meta=assembly_render_owner.source();save(out/"render-metadata.json",meta)
    first[62]=compile_body("assembly-render",body,constants)
    first[63]=compile_document("assembly-object-prefix",assembly_object_prefix.document(),
                              assembly_object_prefix.source_program())
    import generate_hia_assembly_service as service
    proof=service.generate(out/"service-generation")
    for label,role in (("assembly_A_root",56),("assembly_control",59)):
        row=proof["records"][label];text=c.read(row["authoring"]).decode()
        doc=service.base.document(text);doc["module"]=label
        assert render_assembly(doc).encode()==c.read(row["source"])
        first[role]=compile_document(label,doc,text)
    for path,raw in {**service.base.RAW,**service.INPUTS}.items():
        assert c.read(path)==raw
    assert set(parent)==set(range(1,15))
    assert set(first)==set(range(1,57))|{58,59,60,61,62,63}
    assert all(first[n]==raw for n,raw in original_first.items() if n!=56)
    assert first[60]==original_first[60]
    assert set(second)==set(range(1,64))

    import compose_cli_publication_filesystem_r3 as filesystem
    import compose_cli_assembly_carrier as assembly_carrier
    assembled=filesystem.compose(base,root/"tools/compose_cli_publication_filesystem_r2.py")
    assembled,scope=assembly_carrier.compose(assembled,base)
    native=out/"carrier";native.mkdir();source=native/"cli_assembly_executor.S";source.write_bytes(assembled)
    save(native/"scope.json",scope);c.read(source)
    import generate_hia_cli_publication_packer_r3 as packer
    prefix,tables,actual=packer.template(source,native);assert actual==assembled
    (native/"prefix.bin").write_bytes(prefix)
    save(native/"layout.json",dict(tables=tables,rows=140,header=1184,prefix_bytes=len(prefix),
        prefix_sha256=digest(prefix),source_sha256=digest(assembled)))
    packer_image=compile_body("assembly-CLI-packer",packer.source(prefix,tables),{})
    parts=[b""]*140
    for table,roles,offset in ((0,parent,0),(1,first,14),(2,second,77)):
        for role,raw in roles.items():
            assert 0<len(raw)<=1048576
            parts[offset+role-1]=raw
            source_rows.setdefault(str(table)+":"+str(role),dict(image_bytes=len(raw),image_sha256=digest(raw)))
    assert all(parts[77+i-1]==second[i] for i in range(1,64))
    assert sum(bool(x) for x in parts)==139
    packet=struct.pack("<8Q",int.from_bytes(b"HIACBP03","little"),3,3,140,
        1184+sum(map(len,parts)),1184,64,0)+struct.pack("<140Q",*map(len,parts))+b"".join(parts)
    expected=bytearray(prefix)
    for index,raw in enumerate(parts):
        if not raw:continue
        expected+=bytes((-len(expected))&15)
        table=0 if index<14 else 1 if index<77 else 2
        role=index+1 if table==0 else index-13 if table==1 else index-76
        struct.pack_into("<Q",expected,tables[table]+role*8,0x400000+len(expected));expected+=raw
    struct.pack_into("<Q",expected,96,len(expected));struct.pack_into("<Q",expected,104,len(expected))
    from hepta.hia_json_preflight_native import NativeHiaJsonImage
    native_packer=NativeHiaJsonImage(packer_image,expected_sha256=digest(packer_image))
    src=protected(packet);dst=protected(b"",len(expected));work=protected(b"",64)
    before=dict(source=c.cas(packet),output=c.cas(bytes(len(expected))),workspace=c.cas(bytes(64)))
    save(out/"pack-pending.json",before)
    returned=int(native_packer._entry(src[1],src[2],dst[1],dst[2],work[1],work[2]))
    for row in(src,dst,work):checked(row)
    after=ctypes.string_at(dst[1],dst[2]);scratch=ctypes.string_at(work[1],64)
    save(out/"pack.json",dict(before=before,returned=returned,after=c.cas(after),expected=c.cas(expected),
        source_after=c.cas(ctypes.string_at(src[1],src[2])),workspace_after=c.cas(scratch)))
    assert returned==len(expected) and after==bytes(expected)
    assert ctypes.string_at(src[1],src[2])==packet and scratch==bytes(64)
    elf=out/"hia-assembly-development";elf.write_bytes(after);elf.chmod(0o700);c.read(elf)
    assert after[:4]==b"\x7fELF"
    report=dict(status="ACTUAL_BUILD_ONLY",compiled=compiled,new_B3_compilations=len(compiled),
        actual_packer_entries=1,executable_path=str(elf),executable_bytes=len(after),
        executable_sha256=digest(after),image_slots=140,nonzero_images=139,
        role_tables=source_rows,table1_60_original_projector_unchanged=True,
        inactive_table2_all_63_images_byte_equal=True,inactive_E_qualified=False,
        table1_new_roles=[56,59,61,62,63],carrier_scope=scope,
        public_assembly_semantics_executed=False,source_graph_not_core_authority=True,
        installed_activated=False,cold_qualified=False)
    save(out/"bundle.json",report)
    return elf,report
