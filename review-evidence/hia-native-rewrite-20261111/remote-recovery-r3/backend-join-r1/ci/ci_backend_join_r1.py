"""Fresh twenty-one-image post-Core backend join qualification.
No previous Emitter, checked-plan or inspector cases are rerun or inherited.
Every target decision is native HIA; Python/C are explicit authoring, oracle,
fixture and mechanical evidence TCB. Public admission and file custody stay open.
"""
from pathlib import Path
from hashlib import sha1,sha256
import ast,base64,json,lzma,os,re,stat,struct,sys,traceback,types
sys.dont_write_bytecode=True
R3="review-evidence/hia-native-rewrite-20261111/remote-recovery-r3/"
SOURCE_PREFIX=R3+"backend-join-r1/"
COMMON_GIT="61373d6c6dfe9bf3f6b3ef3813da612d15abdb2e"
SEAL_GIT="7c970e9de4e4e860639d31e4721c3c86dba84275"
COMPILER_SHA="35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"
CHILD_SHA="1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
LIMITS=dict(cpu=[90,90],address=[1<<30,1<<30],core=[0,0])
FILES=[
  {
    "path": "ci/backend_streamed_finish.py",
    "mode": "100644",
    "bytes": 6141,
    "sha256": "e7b23177bd86f2e8855c6a6f65e5539d0997e786b12ec56f5fee54a9d39a7143",
    "gitsha": "7c970e9de4e4e860639d31e4721c3c86dba84275"
  },
  {
    "path": "docs/HIA_BACKEND_JOIN_NATIVE.md",
    "mode": "100644",
    "bytes": 13648,
    "sha256": "bb53e81e126f857bb622c4e004e750af09433cbe1d31ec212374c4a54310eee1",
    "gitsha": "1b42c3df2a2f6bc23e74f62392c681dd65f2252d"
  },
  {
    "path": "reference/generate_hia_graph_wire_common.py",
    "mode": "100644",
    "gitsha": "0711ccf18b3838e53b47821c464c3492b802eff6",
    "bytes": 13815,
    "sha256": "32ceeceb285f9d3d3250a920c40ebd7bac8e1a44460c5321d714f6f5a0da2b3c"
  },
  {
    "path": "reference/hia_checked_plan_controller.py",
    "mode": "100644",
    "gitsha": "a21bf7ae8f3cc4f3d551fe0ab827f3229c716dda",
    "bytes": 18316,
    "sha256": "d15c8141db699d1f6df0e6753f6220905903911cf6bd1a01accc41fbbf5103f6"
  },
  {
    "path": "reference/hia_emitter_controller.py",
    "mode": "100644",
    "gitsha": "fdbbeed9d5cf5798f3a7b42aa4299f0c57e37402",
    "bytes": 45316,
    "sha256": "7b706ef28c91d57a36d567ce701501dfa9ed025f4e27278cf629ace6bf011398"
  },
  {
    "path": "reference/hia_machine_elf.py",
    "mode": "100644",
    "gitsha": "cad2e6d21dccc95ad3cfd368da42964ec52d4bb7",
    "bytes": 7026,
    "sha256": "c77cc453d33058ccbeea9e056191001982892a3e59386958090122ccf487c101"
  },
  {
    "path": "reference/hia_machine_plan.py",
    "mode": "100644",
    "gitsha": "61833e8bf8497089461bad9eb2347c82a233e8b2",
    "bytes": 13270,
    "sha256": "ae3e54c4dc3299ba9b6d0a9b4caec55e26f3233e5699d3a0cab7deb1337efb8a"
  },
  {
    "path": "reference/hia_machine_x64.py",
    "mode": "100644",
    "gitsha": "8e87bd317c5f61e00993bb0bf8d803c5385d6556",
    "bytes": 11057,
    "sha256": "8795fb4e5034673401f5f6a5a60e57872c48a3982dbdcb4d3b8198ee7b3f41a9"
  },
  {
    "path": "reference/hia_native_byte_abi.py",
    "mode": "100644",
    "gitsha": "4412810e9e6dfba82879dbb9ae19c19ce2de178c",
    "bytes": 5825,
    "sha256": "0bb40a17f76c27146a48a6d3d229228c9a89bfd96d4b9d65b3b9c70215a3edd6"
  },
  {
    "path": "reference/hia_program.py",
    "mode": "100644",
    "gitsha": "5d0027f4453759e4156a3496e64215c441a727e4",
    "bytes": 45247,
    "sha256": "76a222745e13fe29825a661be206243f137ada7b57292b07ab7513a40146fb92"
  },
  {
    "path": "reference/hia_program_native.py",
    "mode": "100644",
    "gitsha": "1d0e0344f8300b11b5dd505cbea655170aba5be1",
    "bytes": 46917,
    "sha256": "bf953a8b85d1ebc6b9d7a90fbbcaa4137e40ed214c2ede2af1a13cfc01b1c07c"
  },
  {
    "path": "reference/hia_selfhost_child.py",
    "mode": "100644",
    "gitsha": "2ecbf3a04680eceee0537cb3d621073bac9c52f4",
    "bytes": 6791,
    "sha256": "1d298396e97b6d362bcd51121eff1d2f411305133fadb1c974477b2dd9052c29"
  },
  {
    "path": "reference/object_structure.py",
    "mode": "100644",
    "gitsha": "5231ee37ef4ca65a3175a1162178ea21b9503082",
    "bytes": 6155,
    "sha256": "4fb0b3d962e4b7f6ba508257bf605f4403d402e4f3d7e05cffa084b91651f5a8"
  },
  {
    "path": "reference/object_symbols.py",
    "mode": "100644",
    "gitsha": "9476bc3346cdc5e778a145f50c46c30190112780",
    "bytes": 14652,
    "sha256": "aff81d724d08ed4a8c3189e3370f75e234daa010ec9e9855aedc1019d55a693f"
  },
  {
    "path": "tests/backend_mechanical_harness.py",
    "mode": "100644",
    "bytes": 8829,
    "sha256": "68e884ce901c2c5611ca72309513ba3b6e605c5338246fd3a4123e12e0a351eb",
    "gitsha": "f4f8b88d9b77e19ea53d81527d1a6fc0fe9d758c"
  },
  {
    "path": "tests/backend_native_adapter.py",
    "mode": "100644",
    "bytes": 14782,
    "sha256": "d5c2732735410dd02be8754ce16db0473bb51febf6b2dc8f11ffd897a42dc4b7",
    "gitsha": "a43445f3153653582e3453e87dcc2b58ab88570e"
  },
  {
    "path": "tests/function_frame_test_reference.py",
    "mode": "100644",
    "gitsha": "a7d64f7804753398df08e69158bcebb7afc54747",
    "bytes": 42184,
    "sha256": "b3d590336e647df0804ef51c62b73ca2236abdfe8774161d4fd155cf0a5fbee6"
  },
  {
    "path": "tests/function_lowering_test_reference.py",
    "mode": "100644",
    "gitsha": "cb42b8e725bc16471c1cd9fd965c0bdd7f704405",
    "bytes": 48120,
    "sha256": "e08023ddab7501313a45825e5e2cdbba40d3524fee3e4a0f9ad33ba65335bc17"
  },
  {
    "path": "tests/test_hia_backend_join.py",
    "mode": "100644",
    "bytes": 34032,
    "sha256": "7f3062a520bc546258f3bf4d715025a63a657d14232d3fc9cbed0c62f8a17095",
    "gitsha": "cdf5a6c0c43963d4f5e1f636443092c12d62877e"
  },
  {
    "path": "tests/wrapper_test_reference.py",
    "mode": "100644",
    "gitsha": "b92c5ab3053e6661d564d13cb053c4d403a872c5",
    "bytes": 28437,
    "sha256": "30950bd89da646f64061fc55bd0b855178c7e20fd214485b58b20ad86b4bd470"
  },
  {
    "path": "tools/backend_native_mechanics.c",
    "mode": "100644",
    "bytes": 10431,
    "sha256": "dae66f88b96826384c6c278e4f391754acdd43c51c989f963bd90e6bc83d764c",
    "gitsha": "9a0770eb18dd1a9b0a1777db1645d47aef5c3794"
  },
  {
    "path": "tools/build_backend_native_mechanics.py",
    "mode": "100644",
    "bytes": 4319,
    "sha256": "93bfbb6a17c24ffd42b0a8b9a3a484142f6559ac87a842b36f9127786a6461a4",
    "gitsha": "e8e9bc0a9fb66dfdccf236a0b9a447c2bd822d25"
  },
  {
    "path": "tools/build_hia_backend_join.py",
    "mode": "100644",
    "bytes": 12976,
    "sha256": "290a22eaaf8d19345c21ac0c6e483cd6387b7462cb32547a186d6dcbc364d078",
    "gitsha": "8af91893431486bed1b92b019c3ceb4a754ce46b"
  },
  {
    "path": "tools/build_hia_checked_plan.py",
    "mode": "100644",
    "gitsha": "a50b1741eef85ba8416dbc307e345f40bb739f5d",
    "bytes": 11868,
    "sha256": "e834443162d08ef5e29e47bbc9c04f0410b289ffce13fff20f08e35279028fe1"
  },
  {
    "path": "tools/build_hia_complete_emitter.py",
    "mode": "100644",
    "gitsha": "41d4a135744468845b6bc0fe79a3bf9ab3e5a227",
    "bytes": 15496,
    "sha256": "7b6664186a423173487aa8a562cd043768e7fec3b71a4f1948005ec39915530a"
  },
  {
    "path": "tools/build_hia_elf_object_inventory.py",
    "mode": "100644",
    "gitsha": "ad73ef119a6e642e23cd1facda668d84f85351e3",
    "bytes": 9660,
    "sha256": "9de076f55dfc086e6cb5e25b90cff032ca2c54a97f654bf7ebc9bf7bd1f50388"
  },
  {
    "path": "tools/function_authoring_reference.py",
    "mode": "100644",
    "gitsha": "6f1bffe8bd815a068f9834489960006cbaad6fac",
    "bytes": 2112,
    "sha256": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b"
  },
  {
    "path": "tools/generate_hia_sha256.py",
    "mode": "100644",
    "bytes": 5474,
    "sha256": "4114a26ff0ea47229bccbedadcb40efdd9715a8dd0739d2fcb55c98f8ddbdf97",
    "gitsha": "b59c2259f038eab830c16bf498b14a5d15556ee4"
  },
  {
    "path": "tools/generate_hia_sha256_stream.py",
    "mode": "100644",
    "bytes": 4420,
    "sha256": "247816be2a50d384a6dd86a1d8cad909a48fbcdef54444f2394a7789fb137238",
    "gitsha": "80167acbcc4c4f162deaf436aab95fffefb9947a"
  },
  {
    "path": "tools/hia_agent_edit_source_views.py",
    "mode": "100644",
    "gitsha": "f7d123bdb2bf65b25182b571f024299cb0342828",
    "bytes": 23950,
    "sha256": "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"
  },
  {
    "path": "tools/hia_backend_child_forwarder.py",
    "mode": "100644",
    "bytes": 10574,
    "sha256": "d089e80fc78c8c3e2d2234aea587c38bbd5caa757178bf1f93845b15c2fe474c",
    "gitsha": "c7566ec8de704b13a078300c20f40aecabc8961d"
  },
  {
    "path": "tools/hia_backend_command_issuer.py",
    "mode": "100644",
    "bytes": 7716,
    "sha256": "97fb41eb1d4215b081a341b91b26502182ed4592871ccc79ec70b8137af1d17a",
    "gitsha": "b74f6207064efbf45ce64f56caedb2909fa027c7"
  },
  {
    "path": "tools/hia_backend_controller.py",
    "mode": "100644",
    "bytes": 35648,
    "sha256": "35ce9e9fccfb0601d3d000834c241ae9140eb70449fabc2747ae19e84c1d2a05",
    "gitsha": "7041aff7dd3111c996da0fac870a213667e6f693"
  },
  {
    "path": "tools/hia_backend_post.py",
    "mode": "100644",
    "bytes": 19344,
    "sha256": "955ede388d85f85e4651637ad9b3051e607d2eeef55548ea5b7dc2d721f01e45",
    "gitsha": "1bffd7eef205f04f803255b347edc4b7dcfd4a6d"
  },
  {
    "path": "tools/hia_checked_machine_plan.py",
    "mode": "100644",
    "gitsha": "f7eac3d992da5855174845e6861f19fa5d115631",
    "bytes": 40924,
    "sha256": "8fd64a521afb771255d112e40fe7586b1c46c69f343fe5bdd6d42e643d205336"
  },
  {
    "path": "tools/hia_checked_plan_controller.py",
    "mode": "100644",
    "gitsha": "a21bf7ae8f3cc4f3d551fe0ab827f3229c716dda",
    "bytes": 18316,
    "sha256": "d15c8141db699d1f6df0e6753f6220905903911cf6bd1a01accc41fbbf5103f6"
  },
  {
    "path": "tools/hia_composite_lowering_driver_common.py",
    "mode": "100644",
    "gitsha": "e56539a9cb76f95010ea6ca995737f40ab6e1850",
    "bytes": 17781,
    "sha256": "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"
  },
  {
    "path": "tools/hia_elf_object_inventory.py",
    "mode": "100644",
    "gitsha": "e1088c710fdfc5645b5789e888a63a820c0bf5a0",
    "bytes": 19368,
    "sha256": "5b8807b7eaee30a04c12fe2d96a5c457abb0a6f2517804e6b001fbbfc32d16ce"
  },
  {
    "path": "tools/hia_emitter_controller.py",
    "mode": "100644",
    "gitsha": "fdbbeed9d5cf5798f3a7b42aa4299f0c57e37402",
    "bytes": 45316,
    "sha256": "7b706ef28c91d57a36d567ce701501dfa9ed025f4e27278cf629ace6bf011398"
  },
  {
    "path": "tools/hia_emitter_finish.py",
    "mode": "100644",
    "gitsha": "c3deb8a4c86c382b58e0897617770b8e2ac5ae45",
    "bytes": 25093,
    "sha256": "66b6480a3f6f37985fc4d97c4d54de848bb7fcd247591f04542df7e94570337c"
  },
  {
    "path": "tools/hia_emitter_prepare.py",
    "mode": "100644",
    "gitsha": "16e1786ece4aa71c0dac6d5a431288893c2829ad",
    "bytes": 26939,
    "sha256": "da2a957ed48c1fce78c7b931b6b6e3833522271d0fe0578b248e367820ebfb3f"
  },
  {
    "path": "tools/hia_emitter_wrapper_issuer.py",
    "mode": "100644",
    "gitsha": "fad97e3489b06f128270ccc662a9f001ef2aa3b7",
    "bytes": 5548,
    "sha256": "5eb9752617afea5af7ceddfedb9c309fcf7d88fa3da5f3895e7e1a1aae1d7ff8"
  },
  {
    "path": "tools/hia_emitter_wrapper_tape.py",
    "mode": "100644",
    "gitsha": "2f4253bd3c56bda55a5e7d36928c6b8f53ca355a",
    "bytes": 20087,
    "sha256": "332a8633a13f09fcc6021ebdf1f916e97b65b93f4b875b57264abf7eb93b0287"
  },
  {
    "path": "tools/hia_frozen_ssa_rename.py",
    "mode": "100644",
    "gitsha": "13174e28113ed390ba0522e4d39096764fe6cce1",
    "bytes": 2791,
    "sha256": "ceafde9ccf11f5d58de8519821e8b29061de9c967c636a63901735c93f3f419b"
  },
  {
    "path": "tools/hia_function_code_issuer.py",
    "mode": "100644",
    "gitsha": "0309b3f34843287552778eefda7962a7f95f4f02",
    "bytes": 21712,
    "sha256": "f126ef9f45988e4eb699e22cd965f3e6057fdcc969e590ebd8e266b520287219"
  },
  {
    "path": "tools/hia_function_frame_plan.py",
    "mode": "100644",
    "gitsha": "bb475cb50848f09dc4fda62ab1aa869bc0b9891d",
    "bytes": 32438,
    "sha256": "27a817d4cb0d3c8131efa4c8474779f55d74d618124a987a551cb26b3e18ddbd"
  },
  {
    "path": "tools/hia_function_lowering_tape.py",
    "mode": "100644",
    "gitsha": "d5b590bb7c67c34e9f994ff550da99358371a281",
    "bytes": 54950,
    "sha256": "e61fcb540bbe51a0e85dc09cd9afa3813b6ba24d6739da2912269c10ce1522eb"
  },
  {
    "path": "tools/hia_machine_elf_writer.py",
    "mode": "100644",
    "gitsha": "3f92d9e185f17f6df8b45d91a4201ce968723073",
    "bytes": 28963,
    "sha256": "84bbd81168ca645807ce0095755bb6e74efb1ffd9419cec3473a439e34dca985"
  },
  {
    "path": "tools/hia_machine_x64_encoder.py",
    "mode": "100644",
    "gitsha": "817443cde4a81402e850086b80ac5de985b62183",
    "bytes": 51420,
    "sha256": "92070ffcb9e12bce1825c3f3361a97aadc8279f1041c4d2ed16dfadf350ec55a"
  }
]
SCHEDULE=[["cross",0,2,0],["scalar",0,12,0],["plan",0,6,0],["borrowed",0,10,0],["order",0,8,0],["planerror",0,12,0],["late",0,5,0],["scale",0,1,0],["scale",1,1,0],["scale",2,1,0],["scale",3,1,0],["inspect",0,2,0],["initial",0,32,32],["ack",0,8,8],["peer",0,4,4],["peer",1,4,4],["peer",2,4,4],["peer",3,4,4],["peer",4,4,4],["peer",5,4,4],["peer",6,4,4],["grow",0,4,4]]
EMITTER=("prepare","frame","tape","issuer","wrap_tape","wrap_issuer","encoder","finalizer","finish","elf","controller")
EMITTER_OWNERS=("hia_emitter_prepare.py","hia_function_frame_plan.py","hia_function_lowering_tape.py",
 "hia_function_code_issuer.py","hia_emitter_wrapper_tape.py","hia_emitter_wrapper_issuer.py",
 "hia_machine_x64_encoder.py","hia_machine_x64_encoder.py","hia_emitter_finish.py",
 "hia_machine_elf_writer.py","hia_emitter_controller.py")
PLAN=("snapshot","wire_scan","wire_emit","semantics","controller")
POST=("post","hash","controller","command")
POST_OWNERS=("hia_backend_post.py","generate_hia_sha256_stream.py","hia_backend_controller.py","hia_backend_command_issuer.py")
WIRE={
 "wire_scan":dict(path="native-edit-candidate-next/development/build-r1/source/59/graph_json_wire_scan.hiaasm",
  bytes=147822,sha256="c1cb49c1df3c4c653dfd37beebba12b3baf57a28a7d77c257157d2cc7e58cde3"),
 "wire_emit":dict(path="native-edit-candidate-next/development/build-r1/source/61/graph_json_wire_emit.hiaasm",
  bytes=173680,sha256="9ad72bddb7eaa3d9118155a056e4c5faa7ff3e015e45fbc2d09dae14e2cfb7a2")}
RRW=frozenset((1,2,3,4,5,6,8,9,10,12,13,14,15,17,18,21))
def digest(raw):return sha256(raw).hexdigest()
def git_blob(raw):return sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def save(path,value):
 path.parent.mkdir(parents=True,exist_ok=True)
 path.write_text(json.dumps(value,sort_keys=True,indent=2,ensure_ascii=True)+"\n")
def hash_stream(stream):
 h=sha256();n=0
 while True:
  raw=stream.read(1<<18)
  if not raw:break
  h.update(raw);n+=len(raw)
 return dict(bytes=n,sha256=h.hexdigest())
def identity(path):
 with Path(path).open("rb") as stream:return hash_stream(stream)
file_hash=identity
def loaded(name,path,expected):
 raw=Path(path).read_bytes()
 assert git_blob(raw)==expected,(str(path),git_blob(raw),expected)
 module=types.ModuleType(name);module.__file__=str(path);sys.modules[name]=module
 exec(compile(raw,str(path),"exec"),module.__dict__)
 return module,raw
def original(path,label):
 raw=path.read_bytes()
 for at in range(0,len(raw),18000):
  part=raw[at:at+18000]
  print(label+" "+json.dumps(dict(path=str(path),bytes=len(raw),sha256=digest(raw),
   offset=at,part_bytes=len(part),base64=base64.b64encode(part).decode()),sort_keys=True),flush=True)
def summary(directory,label):
 path=directory/"summary.json"
 if not path.exists():return None
 raw=path.read_bytes();value=json.loads(raw)
 print(label+" "+raw.decode().strip(),flush=True)
 return value
def file_closure(project):
 for row in FILES:
  path=project/row["path"];info=path.lstat()
  assert stat.S_ISREG(info.st_mode) and info.st_nlink==1 and not path.is_symlink()
  raw=path.read_bytes()
  assert (len(raw),digest(raw),git_blob(raw))==(row["bytes"],row["sha256"],row["gitsha"])
  assert stat.S_IMODE(info.st_mode)==int(row["mode"],8)&0o777
 return dict(files=len(FILES),all_complete_source_bytes_modes_equal=True)
def named_pin(name):
 rows=[r for r in FILES if r["path"]==name];assert len(rows)==1
 return rows[0]["sha256"]
def gates(build,manifest,document_dir):
 before=json.loads((build/"source-before.json").read_bytes())
 after=json.loads((build/"source-after.json").read_bytes())
 assert before and len(before)==len(after)
 for a,b in zip(before,after):
  assert a["path"]==b["path"] and a["bytes"]==b["bytes"] and a["sha256"]==b["sha256"] and b["same"]
  source=Path(a["path"]);snapshot=build/a["snapshot"]
  assert source.read_bytes()==snapshot.read_bytes()
  assert identity(source)=={k:a[k] for k in("bytes","sha256")}
  assert stat.S_IMODE(source.stat().st_mode)==stat.S_IMODE(snapshot.stat().st_mode)==a["mode"]
 p=manifest["profile"];r=manifest["compile_receipt"]
 document=json.loads((document_dir/"document.json").read_bytes());functions=document["functions"]
 blocks=[b for f in functions for b in f["blocks"]]
 names=[v["name"] for b in blocks for v in b["params"]+[v for op in b["ops"] for v in op["out"]]]
 assert names and all(re.fullmatch(r"v[0-9]+",name) for name in names)
 observed=dict(functions=len(functions),blocks=len(blocks),ops=sum(len(b["ops"]) for b in blocks),
  max_blocks=max(len(f["blocks"]) for f in functions),
  max_params=max(len(b["params"]) for b in blocks),max_block_ops=max(len(b["ops"]) for b in blocks),
  max_ssa_index=max(int(name[1:]) for name in names))
 assert all(p[k]==v for k,v in observed.items()),(p,observed)
 if "max_function_values" in p:assert p["max_function_values"]==p["max_ssa_index"]+1
 assert p["functions"]<=128 and p["blocks"]<=1536 and p["ops"]<=8192
 assert p["max_blocks"]<=256 and p["max_params"]<=16 and p["max_ssa_index"]<2048
 assert r["limits"]["cpu_seconds"]==10 and r["limits"]["address_bytes"]==256<<20
 assert r["runner_sha256"]==CHILD_SHA
 assert r["source_sha256"]==r["input_sha256"]==manifest["source_sha256"]
 assert r["artifact_sha256"]==r["image_sha256"]==COMPILER_SHA
 assert r["produced_sha256"]==manifest["image_sha256"] and r["produced_bytes"]==manifest["image_bytes"]
 assert r["source_unchanged"] and not r["forbidden_compiler_modules_loaded"]
 for kind in("source","image"):
  assert identity(manifest[kind+"_path"])==dict(bytes=manifest[kind+"_bytes"],sha256=manifest[kind+"_sha256"])
  assert 0<manifest[kind+"_bytes"]<=1<<20
 assert manifest["status"]=="BUILT_ONLY" and manifest["compiler_sha256"]==COMPILER_SHA
 return dict(complete_source_mode_snapshots_equal=True,snapshots=len(before),
  complete_document_profile_independently_recomputed=True,original_B3_limits=True,
  original_profile_gates=True,max_block_ops_recorded_not_gated=True)
def alpha_readback(build,manifest):
 proof=json.loads((build/"full-SSA-alpha-proof.json").read_bytes())
 original=json.loads((build/"original-frozen.document.json").read_bytes())
 revised=json.loads((build/"document.json").read_bytes())
 restored=json.loads(json.dumps(revised))
 assert proof["schema"]=="hia-frozen-HIA-bijective-SSA-rename-v1"
 assert all(proof[k] for k in("original_entire_document_restored_by_inverse","input_document_unmodified",
     "only_SSA_definition_and_use_spellings_changed","operations_types_literals_attributes_labels_and_order_unchanged",
     "original_limits_unchanged","actual_B3_compilation_required","actual_semantic_validation_required"))
 assert identity(build/"original-frozen.hiaasm")==dict(bytes=proof["original_source_bytes"],sha256=proof["original_source_sha256"])
 assert identity(manifest["source_path"])==dict(bytes=proof["revised_source_bytes"],sha256=proof["revised_source_sha256"])
 assert identity(build/"original-frozen.hiaasm")=={k:WIRE[manifest["component"]][k] for k in("bytes","sha256")}
 assert len(proof["functions"])==len(original["functions"])==len(revised["functions"])
 for old,new,restore,row in zip(original["functions"],revised["functions"],restored["functions"],proof["functions"]):
  def defs(fn):
   return [v for b in fn["blocks"] for v in b["params"]+[v for op in b["ops"] for v in op["out"]]]
  old_names=[v["name"] for v in defs(old)];new_names=[v["name"] for v in defs(new)]
  pairs=row["old_to_new"]
  assert [p[0] for p in pairs]==old_names and [p[1] for p in pairs]==new_names
  assert new_names==["v"+str(i) for i in range(len(new_names))]
  assert len(set(old_names))==len(old_names)==row["distinct_definitions"]
  assert row["function"]==old["name"]==new["name"]
  assert row["original_max_numeric_suffix"]==max(int(n[1:]) for n in old_names)
  assert row["revised_max_numeric_suffix"]==len(new_names)-1<2048
  reverse={b:a for a,b in pairs}
  for param in restore["params"]:param["name"]=reverse[param["name"]]
  for block in restore["blocks"]:
   for param in block["params"]:param["name"]=reverse[param["name"]]
   for op in block["ops"]:
    op["args"]=[reverse[n] for n in op["args"]]
    for output in op["out"]:output["name"]=reverse[output["name"]]
   term=block["term"];kind=term["op"]
   if kind=="ret":term["values"]=[reverse[n] for n in term["values"]]
   elif kind=="jump":term["args"]=[reverse[n] for n in term["args"]]
   elif kind=="branch":
    term["cond"]=reverse[term["cond"]]
    for side in("then","else"):term[side]["args"]=[reverse[n] for n in term[side]["args"]]
   else:assert kind=="trap"
 assert restored==original
 return dict(complete_inverse_original_document_equal=True,functions=len(proof["functions"]),
   changed_fields_only_SSA_spelling=True,original_and_revised_sources_retained=True,
   original_profile_limit_retained=True,proof=identity(build/"full-SSA-alpha-proof.json"))

def read_exact(stream,n):
 parts=[];remaining=n
 while remaining:
  raw=stream.read(min(remaining,1<<18));assert raw,"truncated retained evidence"
  parts.append(raw);remaining-=len(raw)
 return b"".join(parts)
def encoded_trace_records(path):
 directory=Path(path).parent
 encoded=json.loads((directory/"exact-raw-encoding.json").read_bytes())
 row=next(r for r in encoded["rows"] if Path(r["encoded_path"])==Path(path))
 total=row["raw"]["bytes"];used=0
 with lzma.open(path,"rb") as stream:
  while used<total:
   assert total-used>=16
   kind,n=struct.unpack("<2Q",read_exact(stream,16));used+=16
   assert kind in range(1,9) and n<=total-used
   raw=read_exact(stream,n);used+=n
   yield kind,raw
  assert used==total and stream.read(1)==b""
def audit_trace(path,assets,initial):
 counts={i:0 for i in range(1,22)};image_seen=set();limits=None;input_seen=False
 current=None;last_return=None;pending=None;last_ack=True;commands=0;terminal=None
 for kind,raw in encoded_trace_records(path):
  if kind==8:
   assert limits is None and len(raw)==64 and not image_seen
   limits=struct.unpack("<8Q",raw);assert limits==(90,90,1<<30,1<<30,0,0,180,4096)
  elif kind==1:
   assert limits and not input_seen and len(raw)>=16
   role,n=struct.unpack_from("<2Q",raw);assert role not in image_seen and role in counts and n==len(raw)-16
   m=assets["roles"][str(role)]["manifest"];assert n==m["image_bytes"] and digest(raw[16:])==m["image_sha256"]
   assert raw[16:]==Path(m["image_path"]).read_bytes()
   image_seen.add(role)
  elif kind==2:
   assert image_seen==set(counts) and not input_seen and raw==initial
   input_seen=True
  elif kind==3:
   assert input_seen and terminal is None and current is None and len(raw)==128
   v=struct.unpack("<16Q",raw);serial,role=v[:2]
   assert role in counts and serial==sum(counts.values())+1 and v[9]==1 and v[11]==0 and v[12:]==(0,)*4
   if role==20:
    assert pending is None and last_ack and v[5:9]==(3,128,2,1<<20) and v[10]==0
   else:
    assert pending is not None and pending[1]==1 and role==pending[4]
    assert v[2:9]==(pending[5],pending[6],pending[7],pending[8],pending[9],pending[10],pending[11])
    assert v[10]==(0 if role in(7,11,16,19) else 1)
   current=v;counts[role]+=1
  elif kind==4:
   assert current is not None and len(raw)>=32
   serial,role,returned,n=struct.unpack_from("<4Q",raw)
   assert (serial,role)==current[:2] and n==len(raw)-32 and n<=128
   last_return=(role,returned,raw[32:]);current=None
  elif kind==5:
   assert current is None and pending is None and last_return is not None and last_return[0]==20 and last_return[1]==128
   assert raw==last_return[2] and len(raw)==128
   pending=struct.unpack("<16Q",raw)
   assert pending[0]==int.from_bytes(b"HIACDE01","little") and pending[1] in(1,2,3,4,5,6,14)
   assert pending[3]==commands+1
   commands+=1;last_ack=False
  elif kind==6:
   assert pending is not None and len(raw)>=64
   a=struct.unpack_from("<8Q",raw)
   assert a[:5]==(int.from_bytes(b"HIACDA01","little"),pending[2],pending[3],pending[1],0)
   assert a[6]==len(raw)-64 and a[7]==0
   if pending[1]==1:
    assert last_return is not None and last_return[0]==pending[4] and a[5]==last_return[1]
    if pending[12]==pending[10] and pending[13]==0 and pending[14]<=len(last_return[2]):
     assert raw[64:]==last_return[2][:pending[14]]
   else:assert a[5]==0
   pending=None;last_ack=True
  else:
   assert kind==7 and current is None and pending is None and last_return is not None and last_return[0]==20
   assert terminal is None and raw==last_return[2] and len(raw)==128
   terminal=(last_return[1],raw)
 assert limits is not None and image_seen==set(counts) and input_seen and terminal is not None and current is None and pending is None
 return dict(native_entries=sum(counts.values()),by_role=counts,commands=commands,returned=terminal[0],
             terminal_hex=terminal[1].hex(),full_images_input_events_ACKs=True,all_intermediate_workspaces=False)

def full_cas(directory,expected,expected_roles):
 value=json.loads((directory/"source-after.json").read_bytes())
 assert value["status"]=="PASS" and value["source_pins_unchanged"] and not value["changed"]
 for key in("all_new_pages_decompressed_equal","all_final_pages_rehashed",
    "full_memory_read_before_after_each_entry","delta_pages_reconstruct_identically"):
  assert value[key]
 assert value["complete_snapshot_descriptors"]==expected*6
 descriptors={}
 with (directory/"snapshots.jsonl").open() as stream:
  for i,line in enumerate(stream):
   d=json.loads(line)
   assert d["id"]==i and d["page_size"]==4096 and d["page_count"]==(d["bytes"]+4095)//4096
   assert d["base"] is None or 0<=d["base"]<i
   descriptors[i]={k:d[k] for k in("id","key","bytes","sha256")}
 assert len(descriptors)==expected*6
 entered=returned=0;pending=None;counts={str(i):0 for i in range(1,22)}
 with (directory/"entries.jsonl").open() as stream:
  for line in stream:
   rec=json.loads(line)
   if rec["status"]=="MECHANICAL_ACK":
    assert pending is None and len(bytes.fromhex(rec["event_hex"]))==128 and rec["ack"]["bytes"]>=64
    continue
   assert rec["status"] in("ENTERING","RETURNED")
   if rec["status"]=="ENTERING":
    assert pending is None and rec["number"]==entered and str(rec["role"]) in counts
    assert len(rec["before"])==len(rec["capacities"])==len(rec["readonly"])==3
    for view,cap in zip(rec["before"],rec["capacities"]):
     assert view==descriptors[view["id"]] and view["bytes"]==cap
    entered+=1;pending=rec
   else:
    assert pending is not None
    for key in("number","role","before","capacities","readonly"):assert rec[key]==pending[key]
    assert rec["canaries_intact"] and len(rec["after"])==3
    for i,(view,cap) in enumerate(zip(rec["after"],rec["capacities"])):
     assert view==descriptors[view["id"]] and view["bytes"]==cap
     if rec["readonly"][i]:assert view["sha256"]==rec["before"][i]["sha256"]
    assert len(bytes.fromhex(rec["event_hex"]))==128
    counts[str(rec["role"])]+=1;returned+=1;pending=None
 want={str(i):expected_roles.get(str(i),expected_roles.get(i,0)) for i in range(1,22)}
 assert pending is None and entered==returned==expected and counts==want
 return dict(entries=expected,descriptors=len(descriptors),logical_buffer_bytes=value["logical_buffer_bytes"],
  all_trace_records_correlated=True,all_three_operands_before_after_retained=True)
def encoded_final(directory,case,trace):
 result=(case/"actual.result.bin").read_bytes()
 event=(case/"actual.terminal.bin").read_bytes();ev=struct.unpack("<16Q",event)
 refs={ev[6]:[(ev[7],len(result),case/"actual.result.bin")]}
 if ev[4]==0:
  h=struct.unpack("<64Q",result)
  for start,file in((8,"actual.object.bin"),(11,"actual.text.bin"),(14,"actual.metadata.json")):
   refs.setdefault(h[start],[]).append((h[start+1],h[start+2],case/file))
  if h[23]:refs.setdefault(h[20],[]).append((h[21],h[22],case/"actual.plan.json"))
 total=0;last=-1;seen=set();slot_hashes={}
 with lzma.open(directory/"final-slots.bin.xz","rb") as stream:
  h=struct.unpack("<8Q",read_exact(stream,64));total+=64
  assert h[:2]==(int.from_bytes(b"HIAEMXS1","little"),1) and h[2:4]==(trace["native_entries"],trace["commands"])
  assert h[4]==trace["returned"] and h[6:]==(128,0)
  assert read_exact(stream,128)==event==bytes.fromhex(trace["terminal_hex"]);total+=128
  for _ in range(h[5]):
   slot,n,ro,owned,*reserved=struct.unpack("<8Q",read_exact(stream,64));total+=64
   assert last<slot<64 and ro in(0,1) and owned==1 and reserved==[0]*4
   wanted=refs.get(slot,[])
   for at,count,path in wanted:
    assert 0<=at<=n and 0<=count<=n-at and path.stat().st_size==count
   if wanted:assert ro==1
   at=0;digest_state=sha256()
   while at<n:
    raw=read_exact(stream,min(n-at,1<<18));digest_state.update(raw)
    for begin,count,path in wanted:
     low=max(at,begin);high=min(at+len(raw),begin+count)
     if low<high:
      with path.open("rb") as original:
       original.seek(low-begin);assert original.read(high-low)==raw[low-at:high-at]
    at+=len(raw);total+=len(raw)
   slot_hashes[str(slot)]=dict(bytes=n,readonly=bool(ro),sha256=digest_state.hexdigest())
   seen.add(slot);last=slot
  assert stream.read(1)==b"" and set(refs)<=seen
 return dict(all_slot_bytes_streamed=True,slots=slot_hashes,bytes=total,
  actual_terminal_and_complete_selected_views_equal=True)
def encoded_case(directory,case,assets,expected_entries,expected_roles):
 receipt=json.loads((directory/"exact-raw-encoding.json").read_bytes())
 assert receipt["schema"]=="hia-complete-raw-lossless-encoding-v1"
 assert receipt["full_effective_extents_retained"] and receipt["no_target_entry_during_encoding"] and len(receipt["rows"])==2
 for name,row in zip(("trace.bin","final-slots.bin"),receipt["rows"]):
  raw=Path(row["raw_path"]);encoded=Path(row["encoded_path"])
  assert raw==directory/name and encoded==directory/(name+".xz") and not raw.exists()
  assert row["compression"]=="xz-crc64-preset3" and row["all_decoded_bytes_compared_to_actual_raw"]
  assert row["raw"]==row["decoded"] and row["raw_mode"]==row["encoded_mode"]
  assert stat.S_IMODE(encoded.stat().st_mode)==row["raw_mode"] and identity(encoded)==row["encoded"]
  with lzma.open(encoded,"rb") as stream:assert hash_stream(stream)==row["raw"]
 closed=json.loads((directory/"closed-evidence.json").read_bytes())
 assert closed["source_image_before_after_exact"] and closed["complete_event_ACK_trace"]
 assert not closed["all_intermediate_workspaces"]
 assert closed["trace"]==receipt["rows"][0]["raw"] and closed["all_final_slots"]==receipt["rows"][1]["raw"]
 process=json.loads((directory/"process.json").read_bytes())
 assert process["exit_code"]==0 and not process["timeout"] and process["child_reaped"]
 assert process["limits"]==dict(**LIMITS,wall=180)
 assert (directory/"stdout.bin").read_bytes()==(directory/"stderr.bin").read_bytes()==b""
 initial=(case/"initial.bin").read_bytes()
 assert (directory/"initial.bin").read_bytes()==initial
 trace=audit_trace(directory/"trace.bin.xz",assets,initial)
 normalized=json.loads(json.dumps(trace,sort_keys=True))
 assert normalized==json.loads((directory/"trace-summary.json").read_bytes())
 assert trace["native_entries"]==expected_entries
 assert trace["by_role"]=={i:expected_roles.get(str(i),expected_roles.get(i,0)) for i in range(1,22)}
 final=encoded_final(directory,case,trace)
 assert final["bytes"]==receipt["rows"][1]["raw"]["bytes"]
 return dict(entries=expected_entries,files=2,trace=normalized,final=final)
def case_rows(directory,value,assets):
 paths=sorted((directory/"cases").glob("*/result.json"))
 rows=[json.loads(p.read_bytes()) for p in paths]
 assert len(rows)==value["cases"] and all(r["status"]=="PASS" for r in rows)
 assert len({r["label"] for r in rows})==len(rows)
 entries=private=full_count=encoded_count=cross_count=0
 by_role={str(i):0 for i in range(1,22)};scopes={};details=[]
 for path,row in zip(paths,rows):
  case=path.parent;one=dict(label=row["label"])
  entries+=row["native_entries"]+row.get("crosscheck_native_entries",0)
  for field in("by_role","crosscheck_by_role"):
   for role,n in row.get(field,{}).items():by_role[str(role)]+=n
  scopes[row["evidence_scope"]]=scopes.get(row["evidence_scope"],0)+1
  if row["kind"]=="PRIVATE_BACKEND_PERMANENT_BAD":
   private+=1;assert row["interceptions"] in(0,1) and row["permanent_poison_on_original_ACK"]
  else:
   assert row["kind"]=="POST_CORE_COMPLETE_BACKEND_ORACLE"
   oracle=json.loads((case/"oracle.json").read_bytes())
   assert oracle["actual_reference_admitted_Core"] and oracle["raw_plan_supplied_to_native"] and not oracle["canonical_plan_supplied_to_native"]
   assert oracle["error"]==row["error"]
   if row["error"] is None:
    assert row["complete_object_text_metadata_equal"] and not row["original_error_full_text_equal"]
    for name in("object.bin","text.bin","metadata.json"):
     assert (case/("actual."+name)).read_bytes()==(case/("reference."+name)).read_bytes()
    if row["canonical_plan_equal"]:assert (case/"actual.plan.json").read_bytes()==(case/"reference.plan.json").read_bytes()
   else:
    assert row["original_error_full_text_equal"] and not row["complete_object_text_metadata_equal"]
    error=(case/"reference.error.bin").read_bytes()
    assert (case/"actual.result.bin").read_bytes()==error==row["error"]["text"].encode("utf-8")
    terminal=struct.unpack("<16Q",(case/"actual.terminal.bin").read_bytes())
    assert terminal[4]==row["error"]["domain"]
   assert not row["public_native_Core_admission"] and not row["public_native_file_hash_custody"]
  full=case/"python-full-CAS"
  if full.exists():
   one["full_CAS"]=full_cas(full,row["native_entries"],row["by_role"]);full_count+=1
  native=case/"native-trace"
  if native.exists():
   count=row["crosscheck_native_entries"] if row.get("crosscheck") is not None else row["native_entries"]
   roles=row["crosscheck_by_role"] if row.get("crosscheck") is not None else row["by_role"]
   one["encoded"]=encoded_case(native,case,assets,count,roles);encoded_count+=2
  if row.get("crosscheck") is not None:
   cross=row["crosscheck"]
   assert all(cross[k] for k in("all_native_header_returns_equal","all_command_ACK_bytes_equal",
      "all_final_slot_bytes_permissions_equal","python_full_intermediate_workspace_CAS_retained"))
   assert not cross["native_runner_intermediate_workspaces_recorded"]
   assert row["crosscheck_native_entries"]==row["native_entries"] and full.exists() and native.exists()
   cross_count+=1
  if row["evidence_scope"]=="per-entry-full-workspace-CAS":assert full.exists()
  else:assert row["evidence_scope"]=="full-events-ACKs-and-final-all-slots" and native.exists()
  details.append(one)
 assert entries==value["native_entries"] and by_role==value["by_role"]
 assert private==value["private_protocol_controls"] and scopes==value["evidence_scope_counts"]
 save(directory/"independent-evidence-readback.json",details)
 return dict(cases=len(rows),native_entries=entries,by_role=by_role,private_controls=private,
  full_CAS_cases=full_count,encoded_raw_files=encoded_count,crosscheck_cases=cross_count,scope_counts=scopes,
  all_full_originals_readback=True)

def readback_main():
 import argparse,resource,signal,time
 parser=argparse.ArgumentParser()
 parser.add_argument("--readback-group",type=Path,required=True)
 parser.add_argument("--assets",type=Path,required=True)
 parser.add_argument("--out",type=Path,required=True)
 args=parser.parse_args()
 resource.setrlimit(resource.RLIMIT_CPU,(90,90));resource.setrlimit(resource.RLIMIT_AS,(1<<30,1<<30))
 resource.setrlimit(resource.RLIMIT_CORE,(0,0))
 def expired(*a):raise TimeoutError("backend full-originals readback original 180 wall")
 signal.signal(signal.SIGALRM,expired);signal.alarm(180);start=time.monotonic()
 out=args.out.resolve();out.mkdir(parents=True,exist_ok=False)
 report=dict(status="INCOMPLETE",native_entries_executed=0,VM_entries_executed=0,product_imports=0,
  original_group_limits_not_changed=True,read_only_originals=True)
 pins={}
 def pin(path):
  path=Path(path).resolve();info=path.stat();row=dict(identity(path),mode=stat.S_IMODE(info.st_mode))
  if path in pins:assert pins[path]==row
  pins[path]=row
  return path.read_bytes()
 try:
  pin(__file__);assets=json.loads(pin(args.assets))
  for row in assets["roles"].values():
   for kind in("source","image"):
    m=row["manifest"];raw=pin(m[kind+"_path"])
    assert (len(raw),digest(raw))==(m[kind+"_bytes"],m[kind+"_sha256"])
  value=json.loads(pin(args.readback_group/"summary.json"));assert value["status"]=="PASS"
  report["group"]=value["group"];report["variant"]=value["variant"]
  report["readback"]=case_rows(args.readback_group,value,assets)
  report["status"]="PASS"
 except BaseException as exc:
  report.update(status="FAIL",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  errors=[]
  for path,row in pins.items():
   try:assert dict(identity(path),mode=stat.S_IMODE(path.stat().st_mode))==row,str(path)
   except BaseException as exc:errors.append(dict(path=str(path),error=repr(exc)))
  usage=resource.getrusage(resource.RUSAGE_SELF);cpu=usage.ru_utime+usage.ru_stime
  elapsed=time.monotonic()-start
  if errors or cpu>90 or elapsed>=180:report["status"]="FAIL"
  report.update(source_image_summary_before_after_equal=not errors,after_errors=errors,
    CPU_seconds=cpu,elapsed_seconds=elapsed,limits=dict(cpu=list(resource.getrlimit(resource.RLIMIT_CPU)),
    address=list(resource.getrlimit(resource.RLIMIT_AS)),core=list(resource.getrlimit(resource.RLIMIT_CORE)),wall=180))
  save(out/"summary.json",report);print(json.dumps(report,sort_keys=True),flush=True);signal.alarm(0)
 if report["status"]!="PASS":raise SystemExit(1)
def main():
 common_path=Path(os.environ["HIA_CI_COMMON"]).resolve()
 common,common_raw=loaded("backend_join_ci_common",common_path,COMMON_GIT)
 seal_path=Path(__file__).resolve().with_name("backend_streamed_finish.py")
 seal,seal_raw=loaded("backend_join_stream_seal",seal_path,SEAL_GIT)
 common.PINS[common_path]=common_raw;common.PINS[seal_path]=seal_raw
 common.PINS[Path(__file__).resolve()]=Path(__file__).read_bytes()
 project=None;status="FAIL";roles={};pairs={}
 report=dict(scope="FRESH_POST_CORE_BACKEND_TWENTY_ONE_IMAGE_JOIN",status="INCOMPLETE",
   expected_fresh_B3=21,expected_groups=22,expected_cases=133,expected_private_controls=72,
   builds={},groups={},readbacks={},actual_compilations=0,actual_cases=0,actual_native_entries=0,
   actual_private_controls=0,old_results_inherited=False,old_Emitter_55_groups_rerun=False,
   old_Function_39_groups_rerun=False,old_wrapper_26_groups_rerun=False,
   old_checked_plan_55_groups_rerun=False,old_inventory_20_groups_rerun=False,
   actual_native_Core_admission=False,public_foreign_capture=False,
   actual_native_implementation_file_hash_custody=False,full_public_backend=False,
   compile_program_machine=False,installed=False,cold=False,
   host_instruction_or_ELF_or_plan_generation_during_native=False,
   development_C_mechanics_and_Python_authoring_TCB=True)
 try:
  context=common.prepare()
  mine=Path(context["base"])/"backend-join-recovery-r1";mine.mkdir()
  project=mine/"native-backend-join-next";project.mkdir()
  for row in FILES:
   source=common.materialize(SOURCE_PREFIX+row["path"],row["gitsha"],project/row["path"])
   raw=source.read_bytes()
   assert (len(raw),digest(raw),git_blob(raw))==(row["bytes"],row["sha256"],row["gitsha"])
   source.chmod(int(row["mode"],8)&0o777)
  driver_copy=project/"ci-driver-original.py";driver_copy.write_bytes(Path(__file__).read_bytes())
  file_closure(project)
  tree=ast.parse((project/"tests/test_hia_backend_join.py").read_bytes())
  schedules=[n for n in tree.body if isinstance(n,ast.Assign) and any(isinstance(t,ast.Name) and t.id=="SCHEDULE" for t in n.targets)]
  assert len(schedules)==1 and ast.literal_eval(schedules[0].value)==SCHEDULE
  assert len(SCHEDULE)==22 and sum(r[2] for r in SCHEDULE)==133 and sum(r[3] for r in SCHEDULE)==72
  env=dict(PYTHONDONTWRITEBYTECODE="1",PYTHONPATH=context["reference"],LC_ALL="C.UTF-8",LANG="C.UTF-8")
  tasks=[]
  for i,component in enumerate(EMITTER,1):
   tasks.append((i,"emitter",component,"build_hia_complete_emitter.py",EMITTER_OWNERS[i-1]))
  for i,component in enumerate(PLAN,12):
   owner="hia_checked_plan_controller.py" if component=="controller" else "hia_checked_machine_plan.py"
   tasks.append((i,"plan",component,"build_hia_checked_plan.py",owner))
  tasks.append((17,"inventory","inventory","build_hia_elf_object_inventory.py","hia_elf_object_inventory.py"))
  for i,component in enumerate(POST,18):
   tasks.append((i,"backend",component,"build_hia_backend_join.py",POST_OWNERS[i-18]))
  assert [t[0] for t in tasks]==list(range(1,22))
  for role,family,component,builder,owner in tasks:
   label=family+"-"+component;build=project/"development"/("build-"+label+"-r1")
   command=[context["python"],"-B",project/"tools"/builder,"--reference",context["reference"],
    "--compiler",context["compiler"],"--out",build,"--component",component]
   if family=="plan" and component in WIRE:
    wire=Path(context["workspace"])/WIRE[component]["path"]
    assert identity(wire)=={k:WIRE[component][k] for k in("bytes","sha256")}
    command.extend(["--wire-source",wire])
   step="backend-build-"+label
   try:
    common.run(step,command,cwd=project,timeout=180,env=env)
   finally:
    value=summary(build,"HIA_BACKEND_BUILD_ORIGINAL")
    if value is not None:
     report["builds"][label]=value
     report["actual_compilations"]=sum(v.get("compilations",0) for v in report["builds"].values())
    if build.exists():
     for path in sorted(set(build.rglob("*.stderr"))|set(build.rglob("*.stderr.log"))):
      original(path,"HIA_BACKEND_NESTED_STDERR")
     for path in sorted(build.rglob("profile-before-gates.json")):original(path,"HIA_BACKEND_PROFILE_ORIGINAL")
     for path in sorted(build.rglob("profile-functions-before-gates.json")):original(path,"HIA_BACKEND_FUNCTION_PROFILE_ORIGINAL")
   value=report["builds"][label]
   assert value["status"]=="PASS_BUILD_ONLY" and value["compilations"]==1 and value["native_semantic_entries"]==0
   assert value.get("actual_limits",value.get("limits"))==LIMITS and value["source_pins_unchanged"]
   process=json.loads((common.OUTPUT/"steps"/step/"process.json").read_bytes())
   assert process["status"]=="PASS" and not process["timed_out"] and process["timeout_seconds"]==180
   assert process["child_cpu_seconds"]<=90
   if family=="emitter":
    assert set(value["components"])=={component};m=value["components"][component];docdir=build/component
    assert m["schema"]=="hepta.hia.complete-emitter-development.v1" and m["role"]==role
   else:
    m=value["manifest"];docdir=build
    if family=="plan":
     assert m["schema"]=="hia-checked-machine-plan-development-component-v1" and m["role"]==role-11
     assert m["abi_second_readonly"]==(role!=16) and value["original_limits_unchanged"]
    elif family=="inventory":assert m["schema"]=="hepta.hia.elf-object-inventory-development.v1"
    else:
     assert m["schema"]=="hia-backend-join-development-component-v1" and m["role"]==role
     assert m["abi_second_readonly"]==(role in(18,21))
   expected_author=WIRE[component]["sha256"] if family=="plan" and component in WIRE else named_pin("tools/"+owner)
   assert m["component"]==component and m["author_sha256"]==expected_author
   report["builds"][label]["independent_gate_readback"]=gates(build,m,docdir)
   if family=="plan" and component in WIRE:
    report["builds"][label]["complete_inverse_readback"]=alpha_readback(build,m)
   roles[str(role)]=dict(name=label,manifest=m,actual_role=role,second_readonly=role in RRW)
   pairs[str(role)]={kind:dict(path=m[kind+"_path"],bytes=m[kind+"_bytes"],sha256=m[kind+"_sha256"],
    mode=stat.S_IMODE(Path(m[kind+"_path"]).stat().st_mode)) for kind in("source","image")}
  assert report["actual_compilations"]==21 and set(roles)=={str(i) for i in range(1,22)}
  assets=project/"development/runtime-assets.json"
  assets_value=dict(schema="hia-backend-join-runtime-assets-v1",roles=roles,
    root_role=20,actual_fresh_B3_compilations=21,old_results_inherited=False,
    private_actual_Core_and_hash_issuers_required=True,header_is_authentication=False)
  save(assets,assets_value);save(project/"development/source-image-pairs.json",pairs)
  nativebuild=project/"development/native-mechanics-build-r1";c_label="backend-development-C-mechanics-build"
  try:
   common.run(c_label,[context["python"],"-B",project/"tools/build_backend_native_mechanics.py",
      "--stage","build","--source",project/"tools/backend_native_mechanics.c","--out",nativebuild],
      cwd=project,timeout=180,env=env)
   common.run("backend-development-C-mechanics-seal",[context["python"],"-B",project/"tools/build_backend_native_mechanics.py",
      "--stage","seal","--source",project/"tools/backend_native_mechanics.c","--out",nativebuild,
      "--receipt",common.OUTPUT/"steps"/c_label/"process.json"],cwd=project,timeout=180,env=env)
  finally:
   report["C_mechanics_build"]=summary(nativebuild,"HIA_BACKEND_C_BUILD_ORIGINAL")
  c=report["C_mechanics_build"];assert c["status"]=="PASS_BUILD_ONLY"
  assert c["source_sha256"]==named_pin("tools/backend_native_mechanics.c")
  carrier=nativebuild/"backend-native-mechanics";carrier_before=identity(carrier)
  assert carrier_before==c["executable"] and c["source_before_after_exact"] and not c["installed"]
  for group,variant,count,private in SCHEDULE:
   label=group+"-"+str(variant);out=project/"development"/("native-"+label+"-r1")
   step="backend-native-"+label
   try:
    common.run(step,[context["python"],"-B",project/"tests/test_hia_backend_join.py",
      "--assets",assets,"--carrier",carrier,"--reference",context["reference"],"--out",out,
      "--group",group,"--variant",str(variant)],cwd=project,timeout=180,env=env)
   finally:
    value=summary(out,"HIA_BACKEND_GROUP_ORIGINAL")
    if value is not None:
     report["groups"][label]=value
     for target,field in(("actual_cases","cases"),("actual_native_entries","native_entries"),("actual_private_controls","private_protocol_controls")):
      report[target]=sum(v.get(field,0) for v in report["groups"].values())
    else:report.setdefault("missing_group_summaries",[]).append(label)
   value=report["groups"][label]
   assert value["status"]=="PASS" and (value["group"],value["variant"])==(group,variant)
   assert (value["cases"],value["private_protocol_controls"])==(count,private)
   assert value["limits"]==dict(**LIMITS,wall=180) and value["source_custody"]["all_bytes_and_modes_equal"]
   assert value["parent_plus_children_CPU_seconds"]<=90 and value["elapsed_seconds"]<180
   assert value["native_entries"]==sum(value["by_role"].values())
   assert value["original_group_limits_include_evidence_encoding"] and value["native_control_and_all_command_issuance_HIA"]
   assert not any(value[k] for k in("host_instruction_or_ELF_or_plan_generation_during_native",
     "actual_native_Core_admission","public_foreign_capture","actual_native_implementation_file_hash_custody",
     "full_public_backend","compile_program_machine","installed","cold","all_prior_results_inherited"))
   process=json.loads((common.OUTPUT/"steps"/step/"process.json").read_bytes())
   assert process["status"]=="PASS" and process["returncode"]==0 and not process["timed_out"]
   assert process["timeout_seconds"]==180 and process["child_cpu_seconds"]<=90
   readback=project/"development"/("readback-"+label+"-r1")
   try:
    common.run("backend-originals-"+label,[context["python"],"-B",driver_copy,
       "--readback-group",out,"--assets",assets,"--out",readback],cwd=project,timeout=180,env=env)
   finally:
    observation=summary(readback,"HIA_BACKEND_ORIGINAL_READBACK")
    if observation is not None:report["readbacks"][label]=observation
   observation=report["readbacks"][label]
   assert observation["status"]=="PASS" and observation["limits"]==dict(**LIMITS,wall=180)
   assert observation["native_entries_executed"]==observation["VM_entries_executed"]==observation["product_imports"]==0
   assert observation["source_image_summary_before_after_equal"] and not observation["after_errors"]
   assert (observation["group"],observation["variant"])==(group,variant)
   assert observation["readback"]["cases"]==count and observation["readback"]["private_controls"]==private
   file_closure(project);assert identity(carrier)==carrier_before
  assert len(report["groups"])==len(report["readbacks"])==22
  assert (report["actual_cases"],report["actual_private_controls"])==(133,72)
  readings=[v["readback"] for v in report["readbacks"].values()]
  assert sum(v["crosscheck_cases"] for v in readings)==2
  assert sum(v["full_CAS_cases"] for v in readings)==76
  assert sum(v["encoded_raw_files"] for v in readings)==118
  assert sum(v["native_entries"] for v in readings)==report["actual_native_entries"]
  report.update(status="PASS",actual_by_role={str(i):sum(v["by_role"][str(i)] for v in readings) for i in range(1,22)},
    complete_original_public_outer_oracle_after_private_admission=True,
    all_actual_HIA_sources_documents_images_receipts_retained=True,
    complete_object_text_metadata_plan_or_error_bytes_compared=True,
    actual_all_seventy_two_private_controls_permanent_BAD=True,
    two_small_cases_complete_fixed_mechanics_crosschecked=True,
    new_large_cases_complete_trace_and_final_slots_not_intermediate_CAS=True)
  status="PASS"
 except BaseException as exc:
  report.update(status="FAIL",error_class=type(exc).__name__,error=str(exc),traceback=traceback.format_exc())
  traceback.print_exc()
 finally:
  errors=[]
  if project is not None:
   try:report["submitted_source_after"]=file_closure(project)
   except BaseException as exc:errors.append(dict(scope="source",error=repr(exc)))
  for role,pair in pairs.items():
   for kind,row in pair.items():
    try:
     assert identity(row["path"])=={k:row[k] for k in("bytes","sha256")}
     assert stat.S_IMODE(Path(row["path"]).stat().st_mode)==row["mode"]
    except BaseException as exc:errors.append(dict(role=role,kind=kind,error=repr(exc)))
  if errors:status="FAIL";report["status"]="FAIL"
  report["final_source_image_after_check_errors"]=errors
  report["actual_source_image_pairs"]=pairs
  report["all_completed_source_image_pairs_before_after_equal"]=not errors
  roots={} if project is None else {"backend-join":project}
  seal.finish(common,"backend-join-r1",status,report,roots=roots)
 if status!="PASS":raise SystemExit(1)
if __name__=="__main__":
 if "--readback-group" in sys.argv[1:]:readback_main()
 else:main()
