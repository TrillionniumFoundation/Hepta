"""Real original/native Future interleavings, no fabricated completion facts."""
from pathlib import Path
import argparse,ctypes,json,threading
from concurrent.futures import InvalidStateError
from tools.qualify_hia_multiversion_future import Native,Reference
from tools.qualify_hia_multiversion_components import sha

def main():
    p=argparse.ArgumentParser();p.add_argument('--directory',type=Path,required=True);a=p.parse_args();D=a.directory
    lib=ctypes.CDLL(str(D/'future-component.so'));rows=[]
    for native in (False,True):
      for family in ('commit-cancel','register-complete','competing-complete'):
        seen={}
        for ordinal in range(40):
            q=Native(lib,assert_global_unlocked=False) if native else Reference();errors=[];answers=[];called=[]
            width=8 if family=='competing-complete' else 2;barrier=threading.Barrier(width+1)
            def execute(fn):
                barrier.wait()
                try:answers.append(fn())
                except InvalidStateError:answers.append('concurrent-invalid-state')
                except BaseException as e:errors.append(repr(e))
            if family=='commit-cancel':
                functions=[lambda:('cancel',q.cancel()),lambda:('commit',q.token_commit())]
            elif family=='register-complete':
                functions=[lambda:q.add(lambda f:called.append(f.result(0))),lambda:q.complete(73)]
            else:
                q.add(lambda f:called.append(f.result(0)))
                functions=[lambda i=i:q.complete(i) for i in range(width)]
            threads=[threading.Thread(target=execute,args=(fn,)) for fn in functions]
            for t in threads:t.start()
            barrier.wait()
            for t in threads:t.join(3);assert not t.is_alive()
            assert not errors,errors
            if family=='commit-cancel':
                result=dict(answers);assert result in ({'cancel':True,'commit':False},{'cancel':False,'commit':True})
                if result['commit']:assert q.state()=='pending' and q.token_state()==2;q.complete(73)
                else:assert q.state()=='cancelled' and q.token_state()==1
                outcome=str(sorted(result.items()))
            elif family=='register-complete':
                assert called==[73] and q.result(0)==73 and q.state()=='finished';outcome='exactly-once'
            else:
                assert len(called)==1 and q.result(0)==called[0] and called[0] in range(width)
                invalid=answers.count('concurrent-invalid-state');assert invalid<width
                assert all(x is None or x=='concurrent-invalid-state' for x in answers)
                outcome='invalid-state-count-'+str(invalid)
            q.destroy();seen[outcome]=seen.get(outcome,0)+1
        rows.append({'implementation':'native' if native else 'original','family':family,'real_thread_rounds':40,'outcomes':seen})
        print('FUTURE_REAL_CONCURRENCY_PASS',native,family,seen,flush=True)
    report={'schema':'hepta.hia.native-future-concurrency.v1','passed':240,'failed':0,'whole_native_runtime':False,'image_sha256':sha((D/'future-component.so').read_bytes()),'cases':rows}
    (D/'concurrency-qualification.json').write_text(json.dumps(report,indent=2)+'\n')
if __name__=='__main__':main()
