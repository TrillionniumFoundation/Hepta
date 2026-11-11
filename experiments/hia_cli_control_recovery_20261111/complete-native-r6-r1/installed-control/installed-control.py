
import argparse,importlib.abc,importlib.metadata,io,json,os,sys
from contextlib import redirect_stdout,redirect_stderr
from hashlib import sha256
from pathlib import Path
installed=Path(sys.argv[1]).resolve(strict=True)
manifest=Path(sys.argv[2]).resolve(strict=True)
input_path=Path(sys.argv[3]).resolve(strict=True)
sys.path.insert(0,str(installed))
forbidden_entries={"tools":[],"retained_cli":[],"retained_parser":[]}
class NoTools(importlib.abc.MetaPathFinder):
 def find_spec(self,fullname,path=None,target=None):
  if fullname=="tools" or fullname.startswith("tools."):
   forbidden_entries["tools"].append(fullname)
   raise AssertionError("installed native CLI imported authoring tools")
sys.meta_path.insert(0,NoTools())
from hepta import cli
from hepta.hia_cli_native import SOURCES,SELECTOR,installed_cli
def forbidden_cli(*args,**kwargs):
 forbidden_entries["retained_cli"].append(True)
 raise AssertionError("retained CLI body entered")
def forbidden_parser(*args,**kwargs):
 forbidden_entries["retained_parser"].append(True)
 raise AssertionError("retained argparse entered")
cli._reference_hia_main=forbidden_cli
argparse.ArgumentParser=forbidden_parser
entries=[e for e in importlib.metadata.distribution("hia-core").entry_points
         if e.group=="console_scripts" and e.name=="hia"]
assert len(entries)==1 and entries[0].value=="hepta.cli:hia_main"
entry=entries[0].load()
assert entry is cli.hia_main
os.environ[SELECTOR]=str(manifest)
source_bytes={}
for name,path in SOURCES.items():
 assert path.resolve(strict=True)==installed/"hepta/_data/examples/hia_bootstrap"/("cli_"+name+".hiaasm")
 source_bytes[name]=path.read_bytes()
owner=installed_cli(str(manifest))
native_returns={"control":[],"format":[]}
for name,image in (("control",owner.control),("format",owner.formatter)):
 original=image._entry
 def record(*args,_name=name,_original=original):
  result=_original(*args)
  native_returns[_name].append(int(result))
  return result
 image._entry=record
calls=[]
def call(argv):
 output,errors=io.StringIO(),io.StringIO()
 with redirect_stdout(output),redirect_stderr(errors):
  try:kind,code="return",entry(argv)
  except SystemExit as error:kind,code="exit",error.code
 value={"argv":argv,"kind":kind,"code":code,"stdout":output.getvalue(),"stderr":errors.getvalue()}
 calls.append(value)
 return value
version=call(["--version"])
assert version["kind"]=="exit" and version["code"]==0 and version["stdout"]=="hia "+cli.__version__+"\n" and version["stderr"]==""
help_result=call(["--help"])
assert help_result["code"]==0 and help_result["stderr"]=="" and all(name in help_result["stdout"] for name in cli.HIA_AGENT_ACTIONS)
verified=call(["verify",str(input_path)])
assert verified["kind"]=="return" and verified["code"]==0 and json.loads(verified["stdout"])["status"]=="standalone_core_checked"
capabilities=call(["capabilities"])
assert capabilities["kind"]=="return" and capabilities["code"]==0 and json.loads(capabilities["stdout"])["schema"]=="hepta.hia.agent-entry.v1"
bad=call(["verify"])
assert bad["kind"]=="exit" and bad["code"]==2 and "required: input" in bad["stderr"] and bad["stdout"]==""
missing=call(["verify",str(input_path.with_suffix(".missing"))])
assert missing["kind"]=="return" and missing["code"]==2 and json.loads(missing["stdout"])["diagnostics"][0]["code"]=="E_DRIVER"
refusals=[]
def refuse(label,expected):
 before={name:len(values) for name,values in native_returns.items()}
 output,errors=io.StringIO(),io.StringIO()
 with redirect_stdout(output),redirect_stderr(errors):
  try:entry(["--version"])
  except expected as error:refusals.append({"case":label,"type":type(error).__name__,"message":str(error)})
  else:raise AssertionError("selected invalid installation or bundle was accepted: "+label)
 assert output.getvalue()==errors.getvalue()==""
 assert before=={name:len(values) for name,values in native_returns.items()}
for name,path in SOURCES.items():
 original=source_bytes[name]
 path.write_bytes(original+b"\n")
 try:refuse("changed-installed-"+name,ValueError)
 finally:path.write_bytes(original)
 held=path.with_suffix(path.suffix+".held")
 path.rename(held)
 try:refuse("missing-installed-"+name,FileNotFoundError)
 finally:held.rename(path)
 restored=call(["--version"])
 assert restored["code"]==0
bundle_original=manifest.read_bytes()
metadata=json.loads(bundle_original)
for label,change in (("bundle-schema",{"schema":"unrecognized"}),
                     ("bundle-child-traversal",{"control_manifest":"../outside.json"}),
                     ("bundle-child-hash",{"control_manifest_sha256":"0"*64})):
 manifest.write_text(json.dumps({**metadata,**change}))
 try:refuse(label,ValueError)
 finally:manifest.write_bytes(bundle_original)
os.environ[SELECTOR]=str(manifest.with_suffix(".missing"))
try:refuse("missing-selected-bundle",FileNotFoundError)
finally:os.environ[SELECTOR]=str(manifest)
os.environ[SELECTOR]=""
try:refuse("empty-selected-bundle",OSError)
finally:os.environ[SELECTOR]=str(manifest)
assert all(path.read_bytes()==source_bytes[name] for name,path in SOURCES.items())
assert manifest.read_bytes()==bundle_original
assert all(native_returns.values()) and not any(forbidden_entries.values())
assert not any(name=="tools" or name.startswith("tools.") for name in sys.modules)
assert sys.flags.isolated and sys.flags.no_site and os.environ["PATH"]==""
print(json.dumps({"schema":"hepta.hia.cli-installed-execution.v1",
 "status":"PASS_INSTALLED_NATIVE_CLI_CONTROL","python":sys.version,
 "installed_source_paths":{name:str(path) for name,path in SOURCES.items()},
 "source_sha256":{name:sha256(raw).hexdigest() for name,raw in source_bytes.items()},
 "bundle_sha256":sha256(bundle_original).hexdigest(),"native_returns":native_returns,
 "console_entry_point":entries[0].value,"isolated_without_site":True,"empty_PATH":True,
 "forbidden_entries":forbidden_entries,"calls":calls,"refusals":refusals,
 "sources_and_bundle_restored":True,"whole_native_delivery_qualified":False},sort_keys=True))
