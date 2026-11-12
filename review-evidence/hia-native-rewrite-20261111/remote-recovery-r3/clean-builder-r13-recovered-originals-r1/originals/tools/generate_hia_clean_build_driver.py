"""Emit the complete native clean-build controller, including original kit gate."""
from pathlib import Path
import sys,json,ast
ROOT=Path(__file__).resolve().parents[1];BASE=ROOT.parent
sys.path[:0]=[str(ROOT/'tools'),str(BASE/'Hepta-agent-edit-native')]
from build_authoring import document,expanded,profile
from clean_build_gate import BODY as GATE
from clean_build_gate_common import BODY as COMMON,CONSTANTS as GC,literals,hashing
from clean_build_driver import BODY as DRIVER,CONSTANTS as BC
from clean_build_package import BODY as PACKAGE,texts
from hepta.hia_agent_assembly import render_assembly

def source():
 h=hashing();tree=ast.parse(h);fn=next(n for n in tree.body if n.name=='hash_range');pad=next(n for n in tree.body if n.name=='hpadded')
 wh=ast.get_source_segment(h,fn).replace('hash_range(s:readbuf, start:u64, size:u64, w:mutbuf, target:u64)','hash_work(w:mutbuf, start:u64, size:u64, target:u64)').replace('hpadded(s,','wpadded(w,')
 wp=ast.get_source_segment(h,pad).replace('hpadded(s:readbuf,','wpadded(w:mutbuf,').replace('byte(s,','byte(w,')
 common=COMMON.replace('return event(w, 1, source, size, 0, 0)','return decoder_event(w, source, size)')
 return expanded(DRIVER+GATE+common+literals()+literals(True)+'\n'+h+'\n'+wh+'\n'+wp+'\n'+PACKAGE+texts(),{**GC,**BC})

def main():
 body=source();doc=document(body,'clean_build_driver');target=ROOT/'examples/hia_bootstrap/clean_build_driver.hiaasm';target.write_text(render_assembly(doc))
 (ROOT/'development/driver-profile-r1.json').write_text(json.dumps(profile(doc),indent=2)+'\n');print(target.stat().st_size,profile(doc))
if __name__=='__main__':main()
