"""Observe actual native session callback lifecycles without changing implementation."""
import argparse
from hashlib import sha256
import json
import os
from pathlib import Path
import struct
import sys
import time

parser=argparse.ArgumentParser()
parser.add_argument('--source-root',required=True,type=Path)
parser.add_argument('--manifest',required=True,type=Path)
parser.add_argument('--output',required=True,type=Path)
args=parser.parse_args()
if args.output.exists():raise FileExistsError(args.output)
for name in list(os.environ):
 if name.startswith('HEPTA_HIA_'):del os.environ[name]
sys.path.insert(0,str(args.source_root))
from hepta.hia_json_wire_native import SOURCE,WireSession,ForeignGraphObserver,installed_json_wire
assert SOURCE.resolve()==(args.source_root/'examples/hia_bootstrap/json_wire.hiaasm').resolve()
manifest=json.loads(args.manifest.read_bytes())
paths={'source':SOURCE,'adapter':args.source_root/'hepta/hia_json_wire_native.py','manifest':args.manifest,'image':args.manifest.parent/manifest['image_path']}
pins={key:sha256(path.read_bytes()).hexdigest() for key,path in paths.items()}
image=installed_json_wire(str(args.manifest))
assert image.image_sha256==manifest['image_sha256']==pins['image']
class Observer(ForeignGraphObserver):
 def __init__(self,fail_once=False):super().__init__();self.events=[];self.fail_once=fail_once
 def summary(self,handle):
  self.events.append({'operation':'summary','handle':handle})
  if self.fail_once and len(self.events)==1:raise RuntimeError('intentional foreign summary failure')
  return super().summary(handle)
def new(fail_once=False):
 observer=Observer(fail_once)
 return WireSession(image,observer,observer.register(None),32,ensure_ascii=False,sort_keys=True),observer
def attempt(session):
 try:
  result=session.observe();return {'kind':'returned','packet_hex':result.hex()}
 except BaseException as exc:return {'kind':'raised','type':type(exc).__name__,'message':str(exc)}
rows=[];started=time.monotonic()
s,o=new();before=len(o.events);result=attempt(s)
rows.append({'case':'before-first-native-request','before':before,'after':len(o.events),'observation':result,'unexpected_callback_replay':len(o.events)!=before,'events':o.events})
s,o=new();assert s.step()==1;first=attempt(s);assert first['kind']=='returned';before=len(o.events);second=attempt(s)
rows.append({'case':'repeat-observe-before-reply-consumption','before':before,'after':len(o.events),'first':first,'observation':second,'unexpected_callback_replay':len(o.events)!=before,'events':o.events})
s,o=new();assert s.step()==1;packet=bytearray(s.observe());struct.pack_into('<Q',packet,8,0);status=s.step(bytes(packet));assert status==199 and s.finished
before=len(o.events);result=attempt(s)
rows.append({'case':'observe-after-terminal-bad-sequence','terminal_status':status,'finished':s.finished,'before':before,'after':len(o.events),'observation':result,'unexpected_callback_replay':len(o.events)!=before,'events':o.events})
s,o=new(True);assert s.step()==1;first=attempt(s);assert first['kind']=='raised' and first['message']=='intentional foreign summary failure';before=len(o.events);second=attempt(s)
rows.append({'case':'repeat-observe-after-foreign-exception','before':before,'after':len(o.events),'first':first,'observation':second,'unexpected_callback_replay':len(o.events)!=before,'events':o.events})
s,o=new();wire=s.run();assert wire==b'null' and s.finished;before=len(o.events);result=attempt(s)
rows.append({'case':'observe-after-successful-completion','wire_hex':wire.hex(),'finished':s.finished,'before':before,'after':len(o.events),'observation':result,'unexpected_callback_replay':len(o.events)!=before,'events':o.events})
stable=all(sha256(path.read_bytes()).hexdigest()==pins[key] for key,path in paths.items())
report={'schema':'hepta.hia.wire-native-observe-lifecycle.v1','scope':'NEW_ACTUAL_R5_PUBLIC_SESSION_CONTROLS_NOT_R7_NOT_COLD_QUALIFICATION','python':sys.version,'executable':sys.executable,'manifest':manifest,'pins_before':pins,'all_pins_unchanged':stable,'cases':rows,'case_count':len(rows),'replayed_cases':[row['case'] for row in rows if row['unexpected_callback_replay']],'status':'REPLAY_OBSERVED' if any(row['unexpected_callback_replay'] for row in rows) else 'NO_REPLAY_IN_FIVE_CONTROLS','wall_seconds':time.monotonic()-started,'old_local_r7_session_96283':'UNKNOWN'}
args.output.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report))
if not stable:raise SystemExit(1)
