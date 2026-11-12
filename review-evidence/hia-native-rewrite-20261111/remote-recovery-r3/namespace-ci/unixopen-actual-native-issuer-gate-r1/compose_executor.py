"""Compose the new fixed nine-role UnixOpen issuance carrier.
Pure text authoring only; exact inherited FS9 body is recovered by inversion.
This source has not run Python AST, GNU as, B3, CoreVM, or native execution.
"""
from __future__ import annotations
import argparse,hashlib,json,re
from pathlib import Path
BASE_GIT="ceb21c40b4287b1eff4e998d61fdfcfa59fb3110"
BASE_SHA="dd33f23d901ecd8ecb85b65b71d672d9865855f5eb3308b7cb9735d52cd66d3a"
CAPSULE_GIT="3df087271e4a7bb3258be5e87580f8cb3d56e728"
CAPSULE_SHA="a8e08c861ae6ece09b296c0696e642bf2ae63a4047ffefdbd50c5cf650c181f2"
DISPATCH_GIT="c4b564a0105abec863abc02f4d7536fc2aa49834"
DISPATCH_SHA="9ec4b8a61e81d2e576c4c61662c729c42d495abde4440aebac87893927bdae3e"
OUTPUT_SHA="b7dfd47c4887ecb4ba423b75b1d1432f0a28f293cb0ed925aae729f1c54e5ef2"
OUTPUT_BYTES=95632
EDITS=json.loads(r'''[["    mov esi,4096\n    call initialize_context\n\nouter_next_request:","    mov esi,4096\n    call initialize_context\n    jmp .Luij_boot\n\nouter_next_request:"],["    lea rdi,[r15+OUTPUT]\n    mov esi,3\n    call protect_descriptor\n    lea rdi,[r15+WORK]\n    mov esi,3\n    call protect_descriptor\n    call trace_before\n","    lea rdi,[r15+OUTPUT]\n    mov esi,3\n    cmp qword ptr [r15+ROLE],8\n    jne .Luij_invoke_second_permission\n    mov esi,1\n.Luij_invoke_second_permission:\n    call protect_descriptor\n    lea rdi,[r15+WORK]\n    mov esi,3\n    call protect_descriptor\n    call trace_before\n"],["    cmp r10,6\n    ja protocol_failure\n    lea rax,[rip+.Limage_table]","    cmp r10,9\n    ja protocol_failure\n    lea rax,[rip+.Limage_table]"],["outer_terminal:\n    mov rax,[r15+OUTPUT+16]","outer_terminal:\n    cmp qword ptr [r15+UI_MASTER],0\n    jne .Luij_fs_terminal\n    mov rax,[r15+OUTPUT+16]"],["    .zero 56\nexecutor_end:","    .zero 80\nexecutor_end:"]]''')
ANCHOR="\n.balign 16\nimage_table:\n.Limage_table:\n"
def sha(raw):return hashlib.sha256(raw).hexdigest()
def git(raw):return hashlib.sha1(b"blob "+str(len(raw)).encode()+b"\0"+raw).hexdigest()
def exact(raw,expected_sha,expected_git):
 assert sha(raw)==expected_sha
 assert git(raw)==expected_git
 return raw.decode("utf-8")
def compose(base,capsule,dispatch):
 before=exact(base,BASE_SHA,BASE_GIT)
 cap=exact(capsule,CAPSULE_SHA,CAPSULE_GIT)
 ext=exact(dispatch,DISPATCH_SHA,DISPATCH_GIT)
 current=before
 for old,new in EDITS:
  assert current.count(old)==1
  current=current.replace(old,new,1)
 assert current.count(ANCHOR)==1
 insertion="\n"+cap+ext+ANCHOR
 current=current.replace(ANCHOR,insertion,1)
 restored=current
 assert restored.count(insertion)==1
 restored=restored.replace(insertion,ANCHOR,1)
 for old,new in reversed(EDITS):
  assert restored.count(new)==1
  restored=restored.replace(new,old,1)
 assert restored==before
 labels=re.findall(r"^([A-Za-z_.$][\w.$]*):",current,re.M)
 assert len(labels)==len(set(labels))
 targets=re.findall(r"^\s*(?:j[a-z]+|call)\s+([A-Za-z_.$][\w.$]*)\s*$",current,re.M)
 assert not (set(targets)-set(labels))
 # Actual fixed context is4096B. Existing base scratch and named metadata are
 # kept below1200 or at2304..2487. New descriptors and scalar records are disjoint.
 old_slots=[(0,200),(256,496),(512,608),(640,672),(2304,2384),(2400,2488)]
 new_slots=[(1200,1240),(1240,1280),(1280,1320),(1320,1360),
            (2496,2632),(2632,2688)]
 for lo,hi in new_slots:
  assert 0<=lo<hi<=4096
  assert all(hi<=a or b<=lo for a,b in old_slots)
 for i,(lo,hi) in enumerate(new_slots):
  assert all(hi<=a or b<=lo for a,b in new_slots[i+1:])
 output=current.encode("utf-8")
 assert len(output)==OUTPUT_BYTES and sha(output)==OUTPUT_SHA
 return output,dict(scope="Pure source composition; no assembler/compiler/native execution",
  original_source=dict(bytes=len(base),sha256=sha(base),git_blob_sha1=git(base)),
  capsule_source=dict(bytes=len(capsule),sha256=sha(capsule),git_blob_sha1=git(capsule)),
  dispatcher_source=dict(bytes=len(dispatch),sha256=sha(dispatch),git_blob_sha1=git(dispatch)),
  output=dict(bytes=len(output),sha256=sha(output),git_blob_sha1=git(output)),
  exact_old_source_inverse=True,unique_edits=len(EDITS),labels=len(labels),
  fixed_image_table_slots=10,fixed_runtime_roles=list(range(1,10)),
  new_context_metadata_disjoint=True,AST=0,assembler=0,B3=0,VM=0,native=0)
def main():
 p=argparse.ArgumentParser()
 for name in ("base","capsule","dispatch","output","manifest"):p.add_argument("--"+name,type=Path,required=True)
 a=p.parse_args()
 sources=[a.base.read_bytes(),a.capsule.read_bytes(),a.dispatch.read_bytes()]
 output,report=compose(*sources)
 assert not a.output.exists() and not a.manifest.exists()
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_bytes(output)
 assert a.output.read_bytes()==output
 a.manifest.parent.mkdir(parents=True,exist_ok=True)
 raw=(json.dumps(report,sort_keys=True,indent=2)+"\n").encode()
 a.manifest.write_bytes(raw);assert a.manifest.read_bytes()==raw
 assert [a.base.read_bytes(),a.capsule.read_bytes(),a.dispatch.read_bytes()]==sources
 print(json.dumps(report,sort_keys=True),flush=True)
if __name__=="__main__":main()
