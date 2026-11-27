"""Root complete original ZIP, all restored members and actual observation readback."""
import hashlib,json,os,stat,time,zipfile,zlib
from pathlib import Path
D=Path('/tmp/hia-namespace-fresh-publication-r1-dda7/actual')
RAW=D/'raw';H=RAW/'Hepta/Hepta/harness';E=RAW/'Hepta/Hepta/evidence';C=E/'case-0/observations'
def pin(b):return dict(bytes=len(b),git_blob=hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest(),sha256=hashlib.sha256(b).hexdigest())
def obj(p):return json.loads(Path(p).read_bytes())
def stable(p):
 p=Path(p);a=p.lstat();assert stat.S_ISREG(a.st_mode)
 b=p.read_bytes();z=p.lstat()
 keys=('st_dev','st_ino','st_mode','st_size','st_mtime_ns','st_ctime_ns','st_nlink')
 assert all(getattr(a,k)==getattr(z,k) for k in keys)
 return b,stat.S_IMODE(a.st_mode)
start=time.monotonic_ns()
manifest=obj(D/'ZIP-MANIFEST.json');report=obj(D/'ACTUAL-READBACK.json')
zipraw,_=stable(D/'namespace-single-fresh.zip')
assert pin(zipraw)==manifest['archive']==report['original_zip']
assert len(zipraw)==2127371 and pin(zipraw)['sha256']=='fd5d85e2ebd6a3ffe2814b249530af54be48e1cca5f527f55b4a76f56ab4a731'
rows={r['member']:r for r in manifest['members']}
assert len(rows)==manifest['files']==report['original_zip_files']==27
with zipfile.ZipFile(D/'namespace-single-fresh.zip') as z:
 assert z.testzip() is None and {i.filename for i in z.infolist()}==set(rows)
 for i in z.infolist():
  assert not i.is_dir() and i.filename in rows and not i.filename.startswith('/') and '..' not in Path(i.filename).parts
  row=rows[i.filename];data=z.read(i)
  assert pin(data)=={k:row[k] for k in ('bytes','git_blob','sha256')}
  assert format(zlib.crc32(data)&0xffffffff,'08x')==row['crc32']
  assert i.external_attr>>16==row['zip_unix_mode'] and stat.S_IMODE(i.external_attr>>16)==row['mode']
  current,mode=stable(RAW/i.filename);assert current==data and mode==row['mode']
assert {p.relative_to(RAW).as_posix() for p in RAW.rglob('*') if p.is_file()}==set(rows)
assert sum(r['bytes'] for r in rows.values())==11917163
for n,r in report['reports'].items():assert pin((E/n).read_bytes())==r
author=Path('/tmp/hia-namespace-fresh-execution-r1-dda7/harness')
hfiles={p.relative_to(H).as_posix() for p in H.rglob('*') if p.is_file()}
assert len(hfiles)==11 and hfiles=={p.relative_to(author).as_posix() for p in author.rglob('*') if p.is_file()}
for n in hfiles:assert stable(H/n)==stable(author/n)
sources=[(E/'SOURCE-BEFORE.json').read_bytes(),(E/'SOURCE-AFTER.json').read_bytes(),(C/'SOURCE-BEFORE.json').read_bytes(),(C/'SOURCE-AFTER.json').read_bytes()]
assert all(v==sources[0] for v in sources)
source=json.loads(sources[0]);assert len(source['files'])==3177 and source['tree']=='84df4b42f1e20fd7d0c7229e658cf3b458984ffb' and source['head']=='26fd6c4c1a71dc970ae11b00c8a9ff74c5c8508d'
fresh=obj(H/'inputs/EXPECTED-FRESH-MAP.json');current=obj(C/'ACTUAL-CURRENT-SOURCES.json')
assert len(fresh)==1551 and len(current)==1552 and all(current[n]==sha for n,sha in fresh.items())
assert all(current[n]==source['files'][n]['sha256'] for n in current)
assert sum(source['files'][n]['bytes'] for n in fresh)==58637295
events=obj(C/'ORDERED-EVENTS.json');components=obj(C/'COMPONENTS.json')
assert events['incomplete_stack']==events['observer_errors']==[]
items=events['intervals'];ev=events['events'];assert len(items)==11410 and len(ev)==22820
assert [r['sequence'] for r in items]==list(range(11410))
stack=[];begun=set();ended=set()
for index,row in enumerate(ev):
 i,kind,seq,wall,cpu=row;assert i==index;r=items[seq]
 if kind=='begin':
  assert seq not in begun and r['parent']==(stack[-1] if stack else None)
  assert wall==r['wall_start_ns'] and cpu==r['cpu_start_ns']
  begun.add(seq);stack.append(seq)
 else:
  assert kind=='end' and stack.pop()==seq and seq not in ended
  assert wall==r['wall_end_ns'] and cpu==r['cpu_end_ns']
  assert wall>=r['wall_start_ns'] and cpu>=r['cpu_start_ns']
  ended.add(seq)
assert not stack and begun==ended==set(range(11410))
totals={};fresh_totals={}
for r in items:
 k=r['kind']+':'+r['name'];t=totals.setdefault(k,dict(calls=0,inclusive_wall_ns=0,inclusive_cpu_ns=0));t['calls']+=1;t['inclusive_wall_ns']+=r['wall_end_ns']-r['wall_start_ns'];t['inclusive_cpu_ns']+=r['cpu_end_ns']-r['cpu_start_ns']
 if r['kind']=='c' and r['fresh']:
  t=fresh_totals.setdefault(r['name'],dict(calls=0,inclusive_wall_ns=0,inclusive_cpu_ns=0));t['calls']+=1;t['inclusive_wall_ns']+=r['wall_end_ns']-r['wall_start_ns'];t['inclusive_cpu_ns']+=r['cpu_end_ns']-r['cpu_start_ns']
assert totals==components['inclusive_totals']==report['inclusive_totals']
assert fresh_totals==report['fresh_c_totals'] and all(t['calls']==1551 for t in fresh_totals.values())
assert set(fresh_totals)=={'open','read','context_exit','sha256','hexdigest'}
assert totals['python:current_sources']['calls']==1 and totals['python:_source_protocol_current']['calls']==1823
lex=[r for r in items if r['kind']=='python' and r['name']=='_source_lexical_read']
assert len(lex)==1551 and [r['ordinal'] for r in lex]==list(range(1,1552))
for i,(r,n,assoc) in enumerate(zip(lex,sorted(fresh),components['inferred_path_associations']),1):
 assert r['return_type']=='bytes' and r['return_length']==source['files'][n]['bytes']
 assert assoc==dict(actual_path_argument_observed=False,inferred_from_pinned_source_path=n,observed_bytes_length=r['return_length'],ordinal=i)
children={}
for v in items:
 children[v['parent']]=children.get(v['parent'],0)+v['wall_end_ns']-v['wall_start_ns']
for r in components['residuals']:
 item=items[r['sequence']]
 direct=children.get(r['sequence'],0)
 assert r['unlabelled_wall_residual_ns']==item['wall_end_ns']-item['wall_start_ns']-direct
assert components['actual_path_arguments_observed'] is False and components['observer_overhead_included'] is True and components['uninstrumented_deadline_result'] is None
child=obj(C/'REPORT.json');outer=obj(E/'REPORT.json');process=obj(E/'case-0/PROCESS.json')
assert child['status']==outer['status']=='ONE_ORIGINAL_FRESH_OBSERVATION_COMPLETE'
assert child['product_calls_attempted']==outer['process_launch_attempts']==1
assert child['source_unchanged'] and child['bindings_and_function_definitions_unchanged'] and child['monitor_tool_released'] and child['profile_is_original_none']
assert child['observer_cleanup_errors']==child['terminal_evidence_errors']==outer['terminal_evidence_errors']==[]
assert all(child[k]==0 for k in ['Native','VM','compilers','product_tests'])
assert process['returncode']==0 and process['same_process_group_absent'] is True and process['timed_out'] is False
assert process['original_group_seconds']==1800 and process['cleanup_seconds']==3
m=obj(H/'inputs/SOURCE-MANIFEST.json')
assert source['files']=={n:dict(bytes=r['bytes'],git_blob=r['git_blob'],sha256=r['sha256'],mode=r['git_mode']) for n,r in m.items()}
lines=events['line_events'];assert len(lines)==554
first=next(v for v in lines if v[0]==1795);last=next(v for v in lines if v[0]==1800)
assert components['inventory_statement_interval']==dict(wall_start_ns=first[1],wall_end_ns=last[1],cpu_start_ns=first[2],cpu_end_ns=last[2])
proof=dict(schema='hepta.root-namespace-fresh-actual-full-readback.v1',status='PASS_ORIGINAL_ZIP_ALL_MEMBERS_FULL_PAIRED_EVENTS_AND_SOURCE_CLOSURE',
 original_zip=pin(zipraw),original_zip_files=27,original_zip_logical_bytes=11917163,
 original_zip_CRC_and_all_members_bytes_modes_current_seven_stats=True,complete_restored_pathset=True,
 harness_files=11,harness_tree='b0b8c1f37e4c3ba0f3a4ed603f70be225ee843c4',
 harness_actual_files_exact_to_root_reviewed_author=True,
 head='ce4a685248b49dab31b9740ced57b0c84a8363e8',run=43595690951,job=132449559860,attempt=1,
 four_source_reports_whole_bytes_equal_and_actual_manifest_exact=True,source_files=3177,source_commit=source['head'],source_tree=source['tree'],
 actual_fresh_paths=1551,actual_fresh_bytes=58637295,actual_current_sources_paths=1552,actual_current_sources_calls=1,
 event_rows=22820,complete_intervals=11410,complete_nesting_and_parentage_and_both_clocks=True,
 lexical_returns_type_and_lengths_exact=1551,inferred_names_not_directly_observed=True,guards=1823,
 recomputed_inclusive_totals=totals,recomputed_fresh_C_totals=fresh_totals,recomputed_inventory_statement_wall_ns=last[1]-first[1],
 observer_overhead_included=True,inclusive_and_LINE_intervals_overlap_not_additive=True,
 filesystem_guards_warm_cache=True,uninstrumented_deadline_result=None,previous_deadline_failure_fixed=False,
 process_returncode=0,same_process_group_absent=True,ECHILD_observed=False,original_owner_seconds=1800,original_cleanup_seconds=3,
 observed_product_calls=1,reader_product_calls=0,compilers=0,VM=0,Native=0,business_tests=0,
 qualification=False,whole_native=False,production_legacy_retired=False,reader_elapsed_ns=time.monotonic_ns()-start)
out=Path('/tmp/hia-root-v141-dda7/ROOT-NAMESPACE-FRESH-ACTUAL-TERMINAL.json')
with out.open('x') as f:f.write(json.dumps(proof,indent=2,sort_keys=True)+'\n')
print(json.dumps(proof,sort_keys=True))
