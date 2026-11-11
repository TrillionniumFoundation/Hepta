import hashlib,json,sys,time,unicodedata
from pathlib import Path
started=time.monotonic_ns()
executable=Path(sys.executable).resolve()
with executable.open("rb") as stream: before=hashlib.file_digest(stream,"sha256").hexdigest()
assert before=="b2d6bc2ad950753c5ea407a30788165d8f59c110ca4e90fbad14c8c75376a493"
intervals={"decimal":[],"printable":[]}
starts={"decimal":None,"printable":None}
counts={"decimal":0,"printable":0}
for point in range(0x110000):
 char=chr(point)
 for kind,accepted in (("decimal",str.isdecimal(char)),("printable",str.isprintable(char))):
  if accepted:
   counts[kind]+=1
   if starts[kind] is None: starts[kind]=point
  elif starts[kind] is not None:
   intervals[kind].append([starts[kind],point-1]);starts[kind]=None
for kind in intervals:
 if starts[kind] is not None:intervals[kind].append([starts[kind],0x10ffff])
with executable.open("rb") as stream: after=hashlib.file_digest(stream,"sha256").hexdigest()
assert before==after
report={"schema":"hia.cpython-unicode-observation.v1","scope":"READ_ONLY_RUNTIME_FACTS_NOT_PRODUCT_QUALIFICATION","executable":str(executable),"requested_executable":sys.executable,"executable_sha256":before,"source_program_sha256":hashlib.sha256(Path("/proc/self/cmdline").read_bytes().split(bytes([0]))[3]).hexdigest() if False else None,"python":sys.version,"unicode_database_version":unicodedata.unidata_version,"range_convention":"inclusive endpoints","points_examined":0x110000,"predicate_true_counts":counts,"true_intervals":intervals,"binary_preserved":before==after,"elapsed_ns":time.monotonic_ns()-started,"whole_native_delivery_qualified":False}
print(json.dumps(report,ensure_ascii=True,separators=(",",":"),sort_keys=True),flush=True)
