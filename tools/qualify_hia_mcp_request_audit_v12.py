"""Run actual native audit v12 cases against a supplied executable.

Usage: python -m tools.qualify_hia_mcp_request_audit_v12 IMAGE FRESH_OUTPUT
No runtime mock, host policy fallback or original-test assertion edits.
"""
from pathlib import Path
from hashlib import sha256
import json,sys,os,time,signal
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from tests.hia_request_audit_native_support import Audit,good,identity,write_json
image=Path(sys.argv[1]);out=Path(sys.argv[2]).resolve();out.mkdir(mode=0o700);rows=[]

def initialized_root(label):
 base=out/label;base.mkdir();root=base/'state'
 with Audit(root,image,base/'initial') as a:good(a.prepare())
 return base,root

def pending(root,count=None,created=False,extra=False,anchor=False):
 shard=root/'request-archive-v12';ids=[]
 if count is not None or created:shard.mkdir(mode=0o700)
 if count is not None:
  for i in range(count):
   p=shard/f'{i:02x}';p.mkdir(mode=0o700);ids.append(identity(p))
  if extra and count<256:(shard/f'{count:02x}').mkdir(mode=0o700)
 value={'format':12,'root':identity(root),'legacy':identity(root/'request-archive-v11'),'archive':identity(shard) if count is not None else None,'shards':ids}
 write_json(root/'.request-archive-v12-init.json',value)
 if anchor:write_json(root/'.request-archive-v12-anchor.json',value)
 return value

def verify_complete(root):
 p=root/'request-archive-v12';anchor=json.loads((root/'.request-archive-v12-anchor.json').read_bytes());assert not (root/'.request-archive-v12-init.json').exists();assert sorted(x.name for x in p.iterdir())==[f'{i:02x}' for i in range(256)];assert anchor=={'format':12,'root':identity(root),'legacy':identity(root/'request-archive-v11'),'archive':identity(p),'shards':[identity(p/f'{i:02x}') for i in range(256)]}
 return anchor

cases=[('intent-only',None,False,False,False),('created-unbound-root',None,True,False,False),('bound-root',0,False,False,False),('prefix-one',1,False,False,False),('prefix-seven-next-unbound',7,False,True,False),('prefix-128',128,False,False,False),('prefix-255-next-unbound',255,False,True,False),('prefix-256',256,False,False,False),('complete-anchor-pending-intent',256,False,False,True)]
for label,count,created,extra,anchor in cases:
 base,root=initialized_root(label);pending(root,count,created,extra,anchor);start=time.monotonic()
 with Audit(root,image,base/'resume') as a:
  prep=good(a.prepare());value=verify_complete(root);a.lease(0);beg=good(a.begin());rid=beg['id'];arch=root/'request-archive-v12'/rid[:2]/(rid+'.json');hot=root/'request-audit'/(rid+'.json');assert json.loads(arch.read_bytes())['state']=='unknown' and arch.read_bytes()==hot.read_bytes();fin=good(a.finish(beg));assert json.loads(arch.read_bytes())['state']=='completed' and arch.read_bytes()==hot.read_bytes();a.release(0)
 row={'case':label,'status':'PASS','elapsed_seconds':time.monotonic()-start,'shards':len(value['shards']),'begin':beg,'finish':fin};rows.append(row);print('V12_PASS',label,row['elapsed_seconds'],flush=True)

for label,anchor,alias in [('intent-known-hardlink',False,True),('anchor-known-hardlink',True,True),('intent-unknown-hardlink',False,False),('anchor-unknown-hardlink',True,False)]:
 base,root=initialized_root(label);pending(root,256,anchor=anchor);target=root/('.request-archive-v12-anchor.json' if anchor else '.request-archive-v12-init.json');prefix='.archive-v12-anchor-' if anchor else '.archive-v12-init-';name=(prefix+'b'*64+'.tmp') if alias else 'unrecognized-link';link=root/name;os.link(target,link)
 with Audit(root,image,base/'resume') as a:
  prep=a.prepare()
  if alias:good(prep);verify_complete(root);assert not link.exists()
  else:assert prep['status']!=0 and link.exists() and target.exists(),prep
 rows.append({'case':label,'status':'PASS','response':prep});print('V12_PASS',label,flush=True)

for label in ['root-binding','legacy-binding','missing-recorded-shard','substituted-recorded-shard','unexpected-next-shard','nonempty-shard','nonempty-unbound-root','symlink-shard','unknown-entry']:
 base,root=initialized_root(label);value=pending(root,4 if label!='nonempty-unbound-root' else None,created=label=='nonempty-unbound-root');shard=root/'request-archive-v12';intent=root/'.request-archive-v12-init.json'
 if label in ('root-binding','legacy-binding'):
  value['root' if label=='root-binding' else 'legacy'][1]+=1000;intent.unlink();write_json(intent,value)
 elif label=='missing-recorded-shard':(shard/'01').rmdir()
 elif label=='substituted-recorded-shard':(shard/'01').rename(root/'held-old-shard');(shard/'01').mkdir(mode=0o700)
 elif label=='unexpected-next-shard':(shard/'05').mkdir(mode=0o700)
 elif label in ('nonempty-shard','nonempty-unbound-root'):write_json((shard/'00' if label=='nonempty-shard' else shard)/'payload',{})
 elif label=='symlink-shard':(shard/'01').rmdir();(shard/'01').symlink_to('00',target_is_directory=True)
 elif label=='unknown-entry':(shard/'zz').mkdir(mode=0o700)
 before=intent.read_bytes()
 with Audit(root,image,base/'refusal') as a:prep=a.prepare();assert prep['status']!=0,prep
 assert intent.read_bytes()==before and not (root/'.request-archive-v12-anchor.json').exists()
 rows.append({'case':label,'status':'PASS','response':prep});print('V12_REFUSAL_PASS',label,flush=True)

for adopt in (False,True):
 label='live-old-ticket-'+('adopt-complete-set' if adopt else 'refuse-unvalidated-set');base,root=initialized_root(label)
 with Audit(root,image,base/'live') as a:
  good(a.prepare());a.lease(0);old=good(a.begin());pending(root)
  if adopt:a.lease(1);new=good(a.begin(1,2));verify_complete(root)
  end=a.finish(old)
  if adopt:good(end);good(a.finish(new));a.release(1)
  else:assert end['status']!=0,end
  oldrow=json.loads((root/'request-archive-v11'/(old['id']+'.json')).read_bytes());assert oldrow['state']==('completed' if adopt else 'unknown')
  a.release(0)
 rows.append({'case':label,'status':'PASS','response':end});print('V12_EPOCH_PASS',label,flush=True)

report={'status':'PASS','image':str(image),'image_sha256':sha256(image.read_bytes()).hexdigest(),'case_count':len(rows),'cases':rows,'scope':'Actual native daemon prefix recovery, metadata custody, namespace refusal and shared active-ticket adoption; not whole request-audit qualification'}
(out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print('V12_CAMPAIGN_PASS',len(rows),flush=True)
