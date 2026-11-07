from dataclasses import replace
from pathlib import Path
import os
import tempfile
import unittest
from unittest.mock import patch
from hia_candidate import verify,run,Refused
from hia_candidate.core import Verified
from hia_candidate.builders import op,scalar
from hia_candidate.native import emit_c
from hia_candidate.optimizer import eliminate_wrapping_add_zero
from hia_candidate.migrate_c import migrate
from hia_candidate.activation import AdmissionStore

ROOT=Path(__file__).resolve().parent.parent

class AdversarialTests(unittest.TestCase):
    def test_forged_receipt_does_not_admit_execution_or_native(self):
        base=verify(scalar())
        fake=replace(base,core_digest="0"*64)
        for func in (lambda:run(fake,[1]),lambda:emit_c(fake),lambda:eliminate_wrapping_add_zero(fake)):
            with self.assertRaisesRegex(Refused,"E_RECEIPT"):
                func()
        phantom=Verified(b'{}',"0"*64,"0"*64,())
        with self.assertRaises(Refused): run(phantom,[2])

    def test_c_source_symlink_must_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            link=Path(tmp)/'link.c'
            link.symlink_to(ROOT/'fixtures'/'c'/'add_zero.c')
            with self.assertRaises(Refused): migrate(link)

    def test_c_source_freshness_race_must_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'snapshot.c'
            path.write_bytes((ROOT/'fixtures'/'c'/'add_zero.c').read_bytes())
            from hia_candidate import migrate_c
            real=migrate_c._bounded_ast
            def mutate(source,compiler):
                value=real(source,compiler)
                path.write_bytes(path.read_bytes()+b'\n ')
                return value
            with patch('hia_candidate.migrate_c._bounded_ast',side_effect=mutate):
                with self.assertRaisesRegex(Refused,"E_C_SOURCE_RACE"):
                    migrate(path)

    def test_c_macro_not_silently_migrated(self):
        with tempfile.TemporaryDirectory() as tmp:
            path=Path(tmp)/'macro.c'
            path.write_text('#define FOO 1u\nunsigned int test(unsigned int x){return x + FOO;}\n')
            with self.assertRaisesRegex(Refused,"E_C_PREPROCESSOR"):
                migrate(path)

    def test_activation_cas_failure_restart_and_rollback(self):
        src=verify(scalar(ops=[op("const",results=[("z","u32")],value=0),
                               op("int.add.wrap",["x","z"],[("r","u32")])],returns=["r"]))
        candidate=eliminate_wrapping_add_zero(src).candidate
        with tempfile.TemporaryDirectory() as tmp:
            store=AdmissionStore(tmp)
            start=store.initialize(src)
            self.assertEqual(start['generation'],0)
            self.assertEqual(store.execute([77])['result']['results'],(77,))
            with self.assertRaisesRegex(Refused,"E_INJECTED_CRASH"):
                store.activate(candidate,0,failure_hook='after_store')
            self.assertEqual(AdmissionStore(tmp).read_state()['generation'],0)
            applied=store.activate(candidate,0)
            self.assertEqual(applied['generation'],1)
            self.assertEqual(store.execute([77])['result']['results'],(77,))
            with self.assertRaisesRegex(Refused,"E_STALE_GENERATION"):
                store.activate(candidate,0)
            restarted=AdmissionStore(tmp)
            self.assertEqual(restarted.read_state()['active_digest'],candidate.core_digest)
            reverted=restarted.rollback(1)
            self.assertEqual(reverted['generation'],2)
            self.assertEqual(reverted['active_digest'],src.core_digest)
            self.assertEqual(restarted.execute([99])['result']['results'],(99,))

    def test_tampered_active_artifact_denied_before_execution(self):
        src=verify(scalar())
        with tempfile.TemporaryDirectory() as tmp:
            store=AdmissionStore(tmp)
            store.initialize(src)
            art=Path(tmp)/'versions'/(src.core_digest+'.json')
            art.write_text('{}')
            with self.assertRaisesRegex(Refused,'E_ARTIFACT'):
                store.execute([42])

if __name__=='__main__':unittest.main()

class MutatedInputTests(unittest.TestCase):
    def test_1000_deterministic_mutations_fail_closed(self):
        import random,json,copy
        from hia_candidate.builders import op,scalar
        rnd=random.Random(20261031)
        base=scalar(ops=[op('const',results=[('z','u32')],value=0),
            op('int.add.wrap',['x','z'],[('out','u32')])],returns=['out'])
        samples=[None,0,1,True,False,'','x','u32','buffer',[],{},[1],{'op':'const'},3.1,-1,2**80]
        failures=[]
        for i in range(1000):
            x=copy.deepcopy(base)
            node=x
            for j in range(rnd.randrange(1,7)):
                if isinstance(node,dict) and node:
                    key=rnd.choice(list(node))
                    if j==5 or rnd.random()<.3:
                        node[key]=copy.deepcopy(rnd.choice(samples));break
                    node=node[key]
                elif isinstance(node,list) and node:
                    key=rnd.randrange(len(node))
                    if j==5 or rnd.random()<.3:
                        node[key]=copy.deepcopy(rnd.choice(samples));break
                    node=node[key]
                else:break
            try:verify(json.dumps(x))
            except Refused:pass
            except Exception as e:failures.append((i,type(e).__name__))
        self.assertEqual(failures,[])
