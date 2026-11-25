"""Author-only same-state header comparison; actual native gates remain open."""
from pathlib import Path
import ast,hashlib,importlib,json,sys
ROOT=Path(__file__).resolve().parents[1]
REPO=ROOT.parents[1]/'root_native_recovery'
VALUE=ROOT.parent/'native_value_extension/tree'
sys.path[:0]=[str(ROOT),str(VALUE),str(REPO)]
import tools
tools.__path__=[str(ROOT/'tools'),str(VALUE/'tools'),str(REPO/'tools')]
from tools.qualify_hia_result_value_dict_iterator import AuthorEngine,Values,wire,word
from tools import generate_hia_result_value_owner as current_owner
from tools import generate_hia_result_value_common as current_common
OLD_FINISH='def finish(s:readbuf,o:mutbuf,status:u64) -> u64:\n    zero(o,0,128)\n    put(o,0,REPLY)\n    put(o,8,status)\n    if status==0:\n        op=readword(s,8)\n        if op==0 or op==6 or op==20 or op==22:\n            return 0\n        put(o,16,get(o,G_KIND))\n        put(o,24,get(o,G_CAP))\n        put(o,32,get(o,G_TAG0))\n        put(o,40,get(o,G_TAG1))\n        put(o,48,get(o,G_N))\n        put(o,72,get(o,G_BYTES))\n        if readword(s,8)==19:\n            put(o,56,get(o,G_INDEX))\n            put(o,64,get(o,G_PLAN))\n        if readword(s,8)==23:\n            put(o,64,get(o,G_PLAN))\n            put(o,72,get(o,G_REQUIRED))\n        put(o,104,get(o,G_ID0))\n        put(o,112,get(o,G_ID1))\n    elif status==13:\n        put(o,72,get(o,G_REQUIRED))\n    return 0'

def main():
    engine=AuthorEngine();v=Values(engine)
    old=dict(engine.ns);exec("from __future__ import annotations\n"+OLD_FINISH,old)
    values=[v.scalar(x)for x in(None,True,123,1.25,'raw',b'bytes')]
    values += [v.keep(v.raw(3)),v.keep(v.raw(4))]
    env,name=v.scalar(None),v.scalar('OriginalMetadata')
    values.append(v.keep(v.raw(25,a=env,c=name)))
    rows=[]
    for cap in values:
        raw=wire(7,a=cap);rc,out=engine.call(raw);assert rc==0 and word(out,8)==0
        compare=bytearray(out);old['finish'](raw,compare,0)
        assert compare[:128]==out[:128]
        rows.append(dict(kind=word(out,16),original_header_equal=True))
    d=v.dictionary([('a',1)])
    for mode in range(3):
        it=v.iterator(d,mode);out=v.raw(7,a=it)
        assert (word(out,16),word(out,48),word(out,56),word(out,72))==(9,0,mode,0)
        retained=v.keep(v.raw(5,a=it));out=v.raw(5,a=it);second=v.keep(out);assert word(out,56)==0
        assert v.next(it,mode)==('value','a'if mode==0 else('a',1)if mode==1 else 1)
        v.drop(it);v.drop(retained);v.drop(second)
        rows.append(dict(kind=9,mode=mode,old_other_operation_fields_unchanged=True,metadata_did_not_advance_iterator=True))
    v.finish()
    report=dict(scope='development-author-only',native_qualified=False,groups=rows,
       sources={'tools/'+Path(m.__file__).name:hashlib.sha256(Path(m.__file__).read_bytes()).hexdigest()for m in(current_owner,current_common)})
    out=Path(sys.argv[1]);out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(report,indent=2)+'\n');print('AUTHOR_METADATA',len(rows))
if __name__=='__main__':main()
