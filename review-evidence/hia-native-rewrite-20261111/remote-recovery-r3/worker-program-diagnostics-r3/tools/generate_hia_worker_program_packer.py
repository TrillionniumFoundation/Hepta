"""63-slot HIA ELF packer with explicitly vacant, unreachable service rows.

Exact retained packing algorithm; remove only the per-row nonzero requirement.
All lengths, image copies, padding, ELF extents and addresses remain native.
A zero row must be declared inactive by the immutable service build manifest.
"""
from pathlib import Path
from hashlib import sha256
import importlib.util
REFERENCE_SHA="7b15d7f5c48f7079b6f3c6f1b71fc4b7264f003611e79efd0aee2bc14770db71"
path=Path(__file__).with_name("worker_program_packer_reference.py")
raw=path.read_bytes();assert sha256(raw).hexdigest()==REFERENCE_SHA
spec=importlib.util.spec_from_file_location("worker_program_exact_packer_r1",path)
reference=importlib.util.module_from_spec(spec);spec.loader.exec_module(reference)
ROWS=reference.ROWS;HEADER=reference.HEADER;MAGIC=reference.MAGIC
assert ROWS==63 and HEADER==568
template=reference.template
def source(prefix,tables):
    body=reference.source(prefix,tables)
    old="        if size == 0:\n            return 4294967293\n"
    assert body.count(old)==1
    result=body.replace(old,"",1)
    assert path.read_bytes()==raw
    return result
