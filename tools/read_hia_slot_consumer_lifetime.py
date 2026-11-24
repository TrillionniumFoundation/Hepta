"""Independently read the separate Slot consumer/terminal lifetime gate.

This reader imports no production implementation. The original strict comparison,
including every seal-time discrepancy, remains separately visible in the output.
"""
from __future__ import annotations
import argparse
from pathlib import Path
import hashlib
import itertools
import json

HERE=Path(__file__).resolve().parents[1]
DEFAULT_PROFILE=HERE/'tests/fixtures/hia_slot_external_lifetime_cpython3144.json'
DEFAULT_PROBE=HERE/'tests/hia_slot_external_lifetime_probe.py'

def read(p):return json.loads(p.read_text())
def digest(p):
 h=hashlib.sha256()
 with p.open('rb') as f:
  while data:=f.read(1<<20):h.update(data)
 return {'path':str(p),'bytes':p.stat().st_size,'sha256':h.hexdigest()}
def rows(p):
 with p.open() as f:
  for line in f:yield json.loads(line)
def differences(a,b,path=()):
 if type(a)!=type(b):yield path,a,b
 elif isinstance(a,dict):
  for k in sorted(a.keys()|b.keys()):
   if k not in a or k not in b:yield path+(k,),a.get(k),b.get(k)
   else:yield from differences(a[k],b[k],path+(k,))
 elif isinstance(a,list):
  if len(a)!=len(b):yield path+('length',),len(a),len(b)
  for i,(x,y) in enumerate(zip(a,b)):yield from differences(x,y,path+(i,))
 elif a!=b:yield path,a,b

def readback(root, baseline, evidence, profile, labels, probe):
 root=Path(root).resolve(strict=True);B=Path(baseline).resolve(strict=True);Q=Path(evidence).resolve(strict=True)
 profile=Path(profile).resolve(strict=True);probe=Path(probe).resolve(strict=True)
 LANES=labels;layout=read(profile)
 if set(LANES)!={'original248','derived7574'} or any(set(x)!={'original','native'} for x in LANES.values()):
  raise ValueError('both complete original/native groups are required')
 for names in LANES.values():
  for name in names.values():
   if not isinstance(name,str) or Path(name).name!=name or name in ('','.','..'):
    raise ValueError('capture labels must be simple directory names')
 python=Path(read(B/'original248-original-1/command.json')['argv'][0]).resolve(strict=True)
 gdb=Path(read(Q/LANES['original248']['original']/'process.json')['command']['argv'][0]).resolve(strict=True)
 if (layout['schema']!='hepta.slot.external-lifetime-layout.v1'
     or digest(python)['sha256']!=layout['python']['sha256']
     or digest(gdb)['sha256']!=layout['gdb']['sha256']):
  raise ValueError('runtime or debugger does not match the independently verified layout profile')
 if digest(Q/'probe.py')['sha256']!=digest(probe)['sha256']:
  raise ValueError('executed probe differs from the requested committed probe')
 out={'schema':'hepta.slot-consumer-terminal-lifetime-readback.v1',
  'contract':{
   'consumer':'Exact events/outcome/weakref labels/provider type+refcount at original consumer_release.end after append completes and before original copy_json.',
   'seal_diagnostic':'Compare entire event digest/count and weakref/provider type+refcount at original case-sealed phase assignment. This phase follows the allocating original consumer copy_json; its differences remain separate failed measurement evidence.',
   'terminal':'Original separately declared post-seal gc.collect completes with no live provider weakrefs and no unraisable exceptions.',
   'measurement':'Object data is read through /proc/PID/mem in the debugger process. GDB installs breakpoints/watchpoints and enables selected GC probes. No target Python evaluation/allocation, source edits, GC threshold changes or additional collection are performed.',
   'noninterference':'Each traced full observations.jsonl must byte-match the previously untraced same lane.',
   'retained_original_strict_gate':'Original strict comparison is retained separately; this gate does not overwrite or relax it.',
   'limits':['External lifetime component gate uses CPython 3.14.4 Linux x86-64 and source-bound development V5 component; no whole-installed-worker or release-completion claim.',
             'Matching refcounts/weakrefs are not proof of arbitrary unenumerated C-stack references; selected-case ownership graph diagnostic is retained separately.']},
  'probe':digest(Q/'probe.py'),'committed_probe':digest(probe),'layout_profile':digest(profile),
  'runtime_binary':digest(python),'debugger_binary':digest(gdb),'source_root':str(root),
  'groups':{},'original_strict_report':digest(B/'independent-readback/report.json')}
 strict=read(B/'independent-readback/report.json')
 out['original_strict_status']=strict['status'];out['original_strict_comparisons']=strict['comparisons']
 complete=True;consumer_same=True;seal_same=True;terminal_good=True;noninterference=True;decoder_good=True
 for group,labels in LANES.items():
  count=248 if group=='original248' else 7574
  g={'cases':count,'lanes':{},'consumer_differences':[],'seal_differences':[]}
  for backend,label in labels.items():
   p=Q/label;r=read(p/'external-report.json');pr=read(p/'process.json');ob=p/'observation'
   source_label=group+('-original-1' if backend=='original' else '-native')
   base=B/source_label/'observation';bc=read(B/source_label/'command.json');cfg=read(p/'config.json')
   baseline_raw=digest(base/'observations.jsonl');traced_raw=digest(ob/'observations.jsonl')
   rb={'raw_matches_untraced_same_lane':baseline_raw['sha256']==traced_raw['sha256'] and baseline_raw['bytes']==traced_raw['bytes'],'traced_raw_sha256':traced_raw['sha256']}
   ids=read(base/'planned.json')['ordered_ids']
   expected_argv=list(bc['argv']);expected_argv[expected_argv.index('--output')+1]=str(ob)
   actual_argv=pr['command']['argv']
   expected_progress=[{'ordinal':i,'event':event,'id':case_id} for i,case_id in enumerate(ids,1) for event in ('started','stopped')]
   layout_ok=(read(Path(cfg['frame_layout']))==layout['layouts']['frame-layout.json']
       and all(read(Path(cfg['layout_base'])/name)==value for name,value in layout['layouts'].items() if name!='frame-layout.json'))
   custody_ok=(Path(bc['cwd']).resolve()==root and Path(actual_argv[0]).resolve()==gdb
       and '--args' in actual_argv and actual_argv[actual_argv.index('--args')+1:]==expected_argv
       and cfg['expected_environment']==bc['environment']==pr['command']['environment']==r['initial_environment']
       and cfg['ordered_ids']==ids and read(ob/'planned.json')['ordered_ids']==ids
       and r['progress']==expected_progress and not r['stopped_early'] and layout_ok
       and read(ob/'source-before.json')==read(ob/'source-after.json')==read(base/'source-before.json')
       and read(ob/'product-before.json')==read(ob/'product-after.json')==read(base/'product-before.json'))
   assert len(ids)==count and len(set(ids))==count, 'baseline case coverage differs'
   report=read(ob/'report.json');post=read(ob/'post-seal-gc.json')
   bad_alive=[x['id'] for x in post['cases'] if x['alive']]
   bad_unraisable=[x['id'] for x in post['cases'] if x['unraisable']]
   ok=(r['status']=='RECORDED' and r['cases']==count and r['completed'] and r['natural_inferior_exit_code']==0
       and not r['failures'] and pr['exit_code']==0 and not pr['timed_out'] and pr['interruption'] is None
       and report['status']=='RECORDED' and report['source_stable'] and report['product_stable'] and custody_ok
       and pr['owned_cleanup']['reaped'] and not pr['owned_cleanup']['after'])
   complete=complete and ok;noninterference=noninterference and rb['raw_matches_untraced_same_lane']
   good_post=(len(post['cases'])==count and not bad_alive and not bad_unraisable)
   terminal_good=terminal_good and good_post
   checks=[];decoded=0
   for ext,raw in itertools.zip_longest(rows(p/'external-records.jsonl'),rows(ob/'observations.jsonl')):
    if ext is None or raw is None:checks.append({'error':'row count differs'});break
    c=ext['consumer'];decoded+=1
    if c['case_id']!=ids[decoded-1] or c['ordinal']!=decoded or raw['id']!=ids[decoded-1]:checks.append({'error':'ordered case identity differs','ordinal':decoded})
    checkfields=['consumer_snapshot','fake_sql_effects','sql_prefix_length','complete_request_packets','fault_hits','unraisable']
    bad=[k for k in checkfields if c[k]!=raw[k]]
    if c['handler']!={k:raw[k] for k in c['handler']}:bad.append('handler')
    if bad:checks.append({'id':raw['id'],'fields':bad})
   # Consumer copy may itself trigger GC; any discrepancy is retained, never suppressed.
   decoder_good=decoder_good and decoded==count and not checks
   gc_start=[x for x in r['gc_events_selected_cases'] if x['boundary']=='start']
   lane={'external_report':digest(p/'external-report.json'),'external_records':digest(p/'external-records.jsonl'),
    'natural_exit_complete':ok,'source_command_environment_and_layout_custody':custody_ok,'cases':r['cases'],'raw_same_lane_match':rb['raw_matches_untraced_same_lane'],
    'traced_raw_sha256':rb['traced_raw_sha256'],'external_consumer_vs_original_copy_differences':checks,
    'external_consumer_records':decoded,'post_seal':{'collected':post['collected'],'cases':len(post['cases']),
       'nonempty_alive':bad_alive,'unraisable_cases':bad_unraisable,'actual_original_declared_collection_completed':good_post,
       'raw':digest(ob/'post-seal-gc.json')},
    'selected_case_gc_starts':gc_start}
   if backend=='native':
    controller=read(ob/'controller.json');lane['actual_native_controller']=controller
    c=controller['counts']
    ok_native=(c['attempted_entries']==c['returned_entries'] and c['returned_entries']>0 and not c['retained_calls'])
    complete=complete and ok_native;lane['native_entries_all_returned_without_retained_fallback']=ok_native
   g['lanes'][backend]=lane
  for a,b in itertools.zip_longest(rows(Q/labels['original']/'external-records.jsonl'),rows(Q/labels['native']/'external-records.jsonl')):
   if a is None or b is None:complete=False;break
   cd=list(differences(a['consumer'],b['consumer']))
   if cd:
    consumer_same=False;g['consumer_differences'].append({'id':a['consumer']['case_id'],'leaves':[{'path':list(p),'original':x,'native':y} for p,x,y in cd]})
   sd=list(differences(a['seal_diagnostic'],b['seal_diagnostic']))
   if sd:
    seal_same=False;g['seal_differences'].append({'id':a['consumer']['case_id'],'leaves':[{'path':list(p),'original':x,'native':y} for p,x,y in sd]})
  out['groups'][group]=g
 out['verdicts']={'full_natural_execution':complete,'same_lane_full_raw_noninterference':noninterference,
  'exact_consumer_boundary_match':consumer_same,'exact_case_seal_boundary_match':seal_same,
  'external_consumer_matches_original_copy':decoder_good,'declared_terminal_provider_release':terminal_good}
 out['semantic_gate']={'scope':'consumer-release boundary plus original declared terminal collection only',
  'status':'PASS' if complete and noninterference and consumer_same and decoder_good and terminal_good else 'HOLD',
  'required_facts':['full_natural_execution','same_lane_full_raw_noninterference','exact_consumer_boundary_match','external_consumer_matches_original_copy','declared_terminal_provider_release']}
 out['seal_comparison_status']='MATCH' if seal_same else 'HOLD'
 out['status']='PASS_CONSUMER_TERMINAL_COMPONENT' if out['semantic_gate']['status']=='PASS' else 'HOLD'
 out['does_not_close_original_strict_gate']=out['original_strict_status']!='PASS'
 return out


def main():
 parser=argparse.ArgumentParser(description=__doc__)
 parser.add_argument('--root',type=Path,required=True)
 parser.add_argument('--baseline',type=Path,required=True)
 parser.add_argument('--evidence',type=Path,required=True)
 parser.add_argument('--profile',type=Path,default=DEFAULT_PROFILE)
 parser.add_argument('--probe',type=Path,default=DEFAULT_PROBE)
 parser.add_argument('--labels',type=Path)
 args=parser.parse_args()
 labels=read(args.labels or args.evidence/'labels.json')
 result=readback(args.root,args.baseline,args.evidence,args.profile,labels,args.probe)
 path=args.evidence/'independent-lifetime-readback.json'
 path.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'status':result['status'],'semantic_gate':result['semantic_gate'],
   'original_strict_status':result['original_strict_status'],'seal_comparison_status':result['seal_comparison_status'],
   'verdicts':result['verdicts'],'groups':{g:{'cases':v['cases'],'consumer_difference_cases':len(v['consumer_differences']),
   'seal_difference_cases':len(v['seal_differences'])} for g,v in result['groups'].items()},'report':str(path)},sort_keys=True))
 return 0 if result['semantic_gate']['status']=='PASS' else 1

if __name__=='__main__':
 raise SystemExit(main())
