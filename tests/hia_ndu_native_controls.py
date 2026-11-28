"""Real installed-resource refusal controls for the native NDU default.

These controls mutate an isolated installed fixture, restore every byte, and
accept only the product's OptimizationRejected exception. They do not substitute
an evaluator, loosen a deadline, or treat a skipped test as qualified.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import shutil
import subprocess
import sys

CHILD = r'''
from pathlib import Path
from hashlib import sha256
import json,os,sys,stat
from unittest.mock import patch
package=Path(sys.argv[1]);case=sys.argv[2]
sys.path.insert(0,str(package))
from hepta.hia_ndu_optimizer import _bridge_identity,OptimizationRejected
from hepta import hia_ndu_evaluator_native as native
from hepta import hia_ndu_optimizer as optimizer
base=package/'hepta'
image=base/native.BINARY_RESOURCE;receipt=base/native.RECEIPT_RESOURCE
template=base/'_data'/native.TEMPLATE
contract=json.loads(template.read_bytes())
initial,identity=_bridge_identity(None)
assert identity['implementation']=='HIA' and initial.data==image.read_bytes()
restored={};observed=[]
def remember(path):
 if path not in restored:
  restored[path]=(path.read_bytes(),stat.S_IMODE(path.stat().st_mode))
def change(path,raw=None,missing=False,fifo=False):
 remember(path)
 if missing or fifo:
  path.unlink()
  if fifo:os.mkfifo(path)
 else:
  path.chmod(restored[path][1] | 0o200)
  path.write_bytes(raw)
def reject():
 try:_bridge_identity(None)
 except OptimizationRejected as error:
  observed.append(str(error))
 else:raise AssertionError('native default admitted '+case)
try:
 if case.startswith('source:'):
  name=case.split(':',1)[1];path=base/'_data'/name
  change(path,path.read_bytes()+b'\n');reject()
 elif case=='receipt-json-type':
  data=json.loads(receipt.read_bytes());data['binary_bytes']=True
  change(receipt,json.dumps(data).encode());reject()
 elif case=='receipt-reformat':
  change(receipt,json.dumps(json.loads(receipt.read_bytes()),separators=(',',':')).encode());reject()
 elif case=='old-rust-receipt':
  change(receipt,b'{"schema":"hepta.hia.ndu-build.v1","production_activation":false}')
  reject()
 elif case=='binary-byte':
  raw=bytearray(image.read_bytes());raw[-1]^=1;change(image,bytes(raw));reject()
 elif case=='binary-fifo':
  change(image,fifo=True);reject()
 elif case=='receipt-fifo':
  change(receipt,fifo=True);reject()
 elif case=='missing-binary':
  change(image,missing=True);reject()
 elif case=='missing-receipt':
  change(receipt,missing=True);reject()
 elif case=='no-environment-fallback':
  saved=package/'outside-evaluator';saved.write_bytes(image.read_bytes())
  try:
   os.environ['HEPTA_NDU_BRIDGE']=str(saved)
   change(image,missing=True);change(receipt,missing=True);reject()
  finally:saved.unlink()
 elif case=='missing-installed-resource':
  path=base/'_data'/next(iter(contract['source_files']))
  change(path,missing=True);reject()
 elif case=='module-after-import':
  path=Path(native.__file__);change(path,path.read_bytes()+b'\n');reject()
 elif case=='source-after-image-capture':
  real=optimizer._read_file;path=base/'_data'/next(iter(contract['source_files']))
  triggered=False
  def read(target,limit):
   global triggered
   raw=real(target,limit)
   if Path(target)==image and not triggered:
    triggered=True;change(path,path.read_bytes()+b'\n')
   return raw
  with patch.object(optimizer,'_read_file',side_effect=read):reject()
  assert triggered
 elif case=='receipt-after-admission':
  real=native.admit_ndu_bridge
  def late(*args):
   answer=real(*args);change(receipt,receipt.read_bytes()+b'\n');return answer
  with patch.object(native,'admit_ndu_bridge',side_effect=late):reject()
 else:raise AssertionError('unknown control '+case)
 assert len(observed)==1
finally:
 for path,(raw,mode)in restored.items():
  if path.exists() and not path.is_file():path.unlink()
  if path.exists():path.chmod(mode | 0o200)
  path.write_bytes(raw);path.chmod(mode)
 for path,(raw,mode)in restored.items():
  assert path.read_bytes()==raw and stat.S_IMODE(path.stat().st_mode)==mode
print(json.dumps({'case':case,'refused':True,'error':observed[0],'all_mutations_restored':True}))
'''


def pins(root):
    return {str(path.relative_to(root)): sha256(path.read_bytes()).hexdigest()
            for path in sorted(root.rglob("*")) if path.is_file()}


def run_controls(installed_fixture, output):
    output = Path(output)
    output.mkdir(mode=0o700)
    package = output / "installed"
    shutil.copytree(installed_fixture, package)
    before = pins(package)
    child = output / "control.py"
    child.write_text(CHILD)
    contract = json.loads((package / "hepta/_hia_ndu_evaluator_build.json").read_bytes())
    cases = ["source:" + name for name in contract["source_files"]]
    cases += ["receipt-json-type", "receipt-reformat", "old-rust-receipt", "binary-byte",
              "binary-fifo", "receipt-fifo", "missing-binary", "missing-receipt",
              "no-environment-fallback", "missing-installed-resource", "module-after-import",
              "source-after-image-capture", "receipt-after-admission"]
    rows = []
    for index, case in enumerate(cases):
        result = subprocess.run([sys.executable, "-I", "-B", str(child), str(package), case],
                                capture_output=True, timeout=10, check=False)
        directory = output / str(index)
        directory.mkdir()
        (directory / "stdout").write_bytes(result.stdout)
        (directory / "stderr").write_bytes(result.stderr)
        if result.returncode != 0 or result.stderr:
            raise ValueError("native NDU control failed: " + case)
        row = json.loads(result.stdout)
        if (row["case"] != case or row["refused"] is not True
                or row["all_mutations_restored"] is not True):
            raise ValueError("native NDU control returned an incomplete observation")
        rows.append(row)
    after = pins(package)
    if after != before:
        raise ValueError("native NDU control fixture was not fully restored")
    report = {"passed": True, "controls": len(rows), "source_before": before,
              "source_after": after, "all_mutations_restored": True, "rows": rows}
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
