#!/usr/bin/env python3
"""Independent bounded assignment and transition oracle for resolver + lock-diff.
No production helpers are used to construct expected graphs, hashes, or deltas.
"""
import hashlib, itertools, json, os, sys, tempfile
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from hepta.packages import write_lock
from hepta.lock_diff import compare_locks
from hepta.ast import HeptaError

def sha(b): return hashlib.sha256(b).hexdigest()
def cand(name, roots, allowed): return ('candidate', name, roots, allowed)
def fixed(p): return ('fixed',p)
def resolve_model(nodes):
    # Exhaust all assignments independently, then choose lexicographically by
    # root's ordered A/B decision priority and numeric versions.
    solutions=[]
    for a,b in itertools.product(('a1','a2'),('b1','b2')):
        assignment={'A':a,'B':b}; todo=['.']; seen=set(); edges={}; valid=True
        while todo and valid:
            p=todo.pop()
            if p in seen: continue
            seen.add(p); edges[p]={}
            for alias,spec in nodes[p]['deps'].items():
                if spec[0]=='fixed': q=spec[1]
                else:
                    _,name,roots,allowed=spec; q=assignment[name]
                    if q not in roots or nodes[q]['version'] not in allowed:
                        valid=False; break
                edges[p][alias]=q; todo.append(q)
        if valid:
            key=tuple(tuple(map(int,nodes[q]['version'].split('.'))) for q in (a,b))
            solutions.append((key,seen,edges))
    if not solutions: return None
    _,seen,edges=max(solutions,key=lambda v:v[0]); return seen,edges

def materialize(base,nodes):
    data={}
    for p,n in nodes.items():
        d=base if p=='.' else base/p; (d/'src').mkdir(parents=True,exist_ok=True)
        lines=['[package]',f'name = "{n["name"]}"',f'version = "{n["version"]}"',f'kind = "{n["kind"]}"','entry = "src/main.hepta"','[dependencies]']
        for alias,s in sorted(n['deps'].items()):
            if s[0]=='fixed':
                target=os.path.relpath(base/s[1],d); rhs='{ path = '+json.dumps(target)+' }'
            else:
                _,name,roots,allowed=s
                # Allowed sets in this finite model are singleton or all versions.
                req='>=1.0.0' if len(allowed)>1 else '='+next(iter(allowed))
                paths=[os.path.relpath(base/r,d) for r in reversed(roots)]
                rhs='{ package = '+json.dumps(name)+', version = '+json.dumps(req)+', candidates = '+json.dumps(paths)+' }'
            lines.append(alias+' = '+rhs)
        manifest=('\n'.join(lines)+'\n').encode(); source=('// '+n['source']+'\nfn main() -> Int { 0 }\n').encode()
        for tail,content in [('hepta.toml',manifest),('src/main.hepta',source)]:
            (d/tail).write_bytes(content); data[(p+'/'+tail if p!='.' else tail)]=sha(content)
    return data

def expected_snapshot(nodes,solution,files):
    seen,edges=solution; packages={}; selected_files={}
    for p in seen:
        n=nodes[p]; packages[p]={k:n[k] for k in ('name','version','kind')}
        packages[p].update(entry='src/main.hepta',dependencies=edges[p])
        for suffix in ('hepta.toml','src/main.hepta'):
            key=p+'/'+suffix if p!='.' else suffix; selected_files[key]=files[key]
    content={'packages':packages,'files':selected_files}
    return {'schema':'hepta.lock.v1',**content,'sha256':sha(json.dumps(content,sort_keys=True,separators=(',',':')).encode())}

def expected_delta(old,new):
    # Generate one event per key by a union walk, rather than production's
    # difference/intersection comprehensions.
    result={'schema':'hepta.lock-diff.v1','ok':True,'changed':old!=new,'compatibility':'not_assessed','before_sha256':old['sha256'],'after_sha256':new['sha256'],'packages':{'added':[],'removed':[],'changed':[]},'dependencies':{'added':[],'removed':[],'retargeted':[]},'files':{'added':[],'removed':[],'changed':[]}}
    for p in sorted(set(old['packages'])|set(new['packages'])):
        l=old['packages'].get(p); r=new['packages'].get(p)
        if l is None: result['packages']['added'].append({'path':p,'package':r})
        elif r is None: result['packages']['removed'].append({'path':p,'package':l})
        else:
            changes={}
            for k in ['name','version','kind','entry']:
                if l[k]!=r[k]: changes[k]={'before':l[k],'after':r[k]}
            if changes: result['packages']['changed'].append({'path':p,'changes':changes})
        ld=l['dependencies'] if l else {}; rd=r['dependencies'] if r else {}
        for a in sorted(set(ld)|set(rd)):
            if a not in ld: result['dependencies']['added'].append({'package':p,'alias':a,'target':rd[a]})
            elif a not in rd: result['dependencies']['removed'].append({'package':p,'alias':a,'target':ld[a]})
            elif ld[a]!=rd[a]: result['dependencies']['retargeted'].append({'package':p,'alias':a,'before':ld[a],'after':rd[a]})
    for p in sorted(set(old['files'])|set(new['files'])):
        if p not in old['files']: event='added'; item={'path':p,'sha256':new['files'][p]}
        elif p not in new['files']: event='removed'; item={'path':p,'sha256':old['files'][p]}
        elif old['files'][p]!=new['files'][p]: event='changed'; item={'path':p,'before':old['files'][p],'after':new['files'][p]}
        else: continue
        result['files'][event].append(item)
    return result

def graphs():
    reqs=[{'1.0.0'},{'2.0.0'},{'1.0.0','2.0.0'}]
    for index,(ar,br,r1,r2,fixed_a,edge) in enumerate(itertools.product(range(3),range(3),range(3),range(3),range(2),range(2))):
        nodes={p:{'name':name,'version':v,'kind':'bin' if p=='.' else 'lib','source':f'{p}:{index%2}','deps':{}} for p,name,v in [('.','Root','1.0.0'),('a1','A','1.0.0'),('a2','A','2.0.0'),('b1','B','1.0.0'),('b2','B','2.0.0'),('c','C','1.0.0')]}
        nodes['.']['deps']={'a':cand('A',('a1','a2'),reqs[ar]),'b':cand('B',('b1','b2'),reqs[br])}
        nodes['a1']['deps']={'b':cand('B',('b1','b2'),reqs[r1])}
        nodes['a2']['deps']={'b':cand('B',('b1','b2'),reqs[r2])}
        if fixed_a: nodes['.']['deps']['z']=fixed('a1')
        if edge: nodes['.']['deps']['extra']=fixed('c')
        yield nodes
    # Same-path metadata change on a fixed package; then source-only change.
    nodes['c']['version']='3.1.4'; yield nodes
    nodes['c']['source']='source-only'; yield nodes

def main():
    counts={'states':0,'satisfiable':0,'unsatisfiable':0,'transition_pairs':0,'delta_checks':0,'backtracking_states':0,'fixed_distinct_identity_states':0}
    with tempfile.TemporaryDirectory(prefix='hepta-composition-independent-') as tmp:
        base=Path(tmp)/'project'; base.mkdir(); last=None; before=Path(tmp)/'before.lock'; after=Path(tmp)/'after.lock'
        for nodes in graphs():
            counts['states']+=1; files=materialize(base,nodes); model=resolve_model(nodes)
            prior=(base/'Hepta.lock').read_bytes() if (base/'Hepta.lock').exists() else None
            if model is None:
                try: write_lock(base)
                except HeptaError as e: assert e.diagnostic.code=='E_PACKAGE_RESOLUTION',e
                else: raise AssertionError('unsatisfiable assignment unexpectedly locked')
                assert ((base/'Hepta.lock').read_bytes() if prior is not None else None)==prior
                counts['unsatisfiable']+=1; continue
            counts['satisfiable']+=1
            if model[1]['.']['a']=='a1' and '2.0.0' in nodes['.']['deps']['a'][3]: counts['backtracking_states']+=1
            if model[1]['.'].get('z')=='a1' and model[1]['.']['a']=='a2': counts['fixed_distinct_identity_states']+=1
            expected=expected_snapshot(nodes,model,files); actual=write_lock(base)['snapshot']; assert actual==expected,(counts,nodes,actual,expected)
            after.write_bytes((base/'Hepta.lock').read_bytes())
            assert compare_locks(after,after)==expected_delta(expected,expected); counts['delta_checks']+=1
            if last is not None:
                assert compare_locks(before,after)==expected_delta(last,expected)
                assert compare_locks(after,before)==expected_delta(expected,last)
                counts['delta_checks']+=2; counts['transition_pairs']+=1
            before.write_bytes(after.read_bytes()); last=expected
    print(json.dumps({'python':sys.version.split()[0],'result':'PASS',**counts},sort_keys=True))
if __name__=='__main__': main()
