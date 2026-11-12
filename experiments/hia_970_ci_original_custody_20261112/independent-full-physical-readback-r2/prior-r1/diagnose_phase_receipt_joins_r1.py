"""Describe actual report additions to unchanged archived receipts; read-only."""
import hashlib, io, json, pathlib, zipfile
ROOT=pathlib.Path(__file__).resolve().parent
ARCHIVE=ROOT/'full-zip-two-parts-r1/actual-local-readback-r1/artifact-13911977275.original.zip'
SEMANTIC=ROOT/'semantic-readback-r2/SEMANTIC-READBACK.json'
def embedded(x):
    if isinstance(x,dict):
        if all(k in x for k in ('case','input_sha256','artifact_sha256','wall_elapsed_ns')):
            yield x
        for y in x.values():yield from embedded(y)
    elif isinstance(x,list):
        for y in x:yield from embedded(y)
def key(x):return hashlib.sha256(json.dumps(x,sort_keys=True,separators=(',',':')).encode()).hexdigest()
result={'schema':'hia.970-original-phase-receipt-difference-observation.v1','product_execution':False,'phases':[]}
with zipfile.ZipFile(ARCHIVE) as outer:
    for phase in json.loads(SEMANTIC.read_bytes())['cold']['phases']:
        name=phase['archive']['archive'].removeprefix('/home/runner/work/_temp/')
        raw=outer.read(name)
        assert len(raw)==phase['archive']['packed_bytes'] and hashlib.sha256(raw).hexdigest()==phase['archive']['archive_sha256']
        obs=json.loads(outer.read(phase['report']['name']))
        cases={};full=set()
        with zipfile.ZipFile(io.BytesIO(raw)) as z:
            manifest=json.loads(z.read('HIA_ARCHIVE_MANIFEST.json'))
            for n in z.namelist():
                if not n.endswith('.receipt.json'):continue
                b=z.read(n);assert hashlib.sha256(b).hexdigest()==manifest['files'][n]['sha256']
                d=json.loads(b)
                if 'case' in d:cases.setdefault(d['case'],[]).append((n,d));full.add(key(d))
        unmatched=[];count=0
        for d in embedded(obs):
            count+=1
            if key(d) in full:continue
            matches=cases.get(d['case'],[])
            diff=[]
            for n,r in matches:
                diff.append({'receipt':n,'extra_report_keys':sorted(set(d)-set(r)),
                    'missing_report_keys':sorted(set(r)-set(d)),
                    'changed_shared_keys':sorted(k for k in set(r)&set(d) if r[k]!=d[k]),
                    'extra_report_values':{k:d[k] for k in set(d)-set(r)}})
            unmatched.append({'case':d['case'],'candidate_receipts':diff})
        result['phases'].append({'family':phase['family'],'label':phase['compiler_label'],
            'embedded_receipts':count,'physical_cases':len(cases),'unmatched':unmatched})
out=ROOT/'phase-receipt-difference-r1.original.json'
out.write_bytes((json.dumps(result,indent=2,sort_keys=True)+'\n').encode())
sets={}
for p in result['phases']:
    for d in p['unmatched']:
        for r in d['candidate_receipts']:
            k=json.dumps([r['extra_report_keys'],r['missing_report_keys'],r['changed_shared_keys']])
            sets[k]=sets.get(k,0)+1
print(json.dumps({'phases':len(result['phases']),'difference_groups':sets,'unmatched_counts':[(p['family'],p['label'],len(p['unmatched'])) for p in result['phases'] if p['unmatched']],'report_bytes':out.stat().st_size,'report_sha256':hashlib.sha256(out.read_bytes()).hexdigest()}))
