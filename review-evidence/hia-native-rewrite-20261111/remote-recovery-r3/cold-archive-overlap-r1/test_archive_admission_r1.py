"""Meaningful archive admission controls for the isolated cold candidate."""
from pathlib import Path
from hashlib import sha1,sha256
from concurrent.futures import Future,ThreadPoolExecutor
from threading import Event,Lock
from unittest.mock import patch
import argparse,json,sys,tempfile,unittest
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--source",type=Path,required=True)
    ap.add_argument("--out",type=Path,required=True);a=ap.parse_args()
    a.out.mkdir(parents=True,exist_ok=False)
    sys.path.insert(0,str(a.source.resolve()))
    from tools import qualify_hia_selfhost as q
    assert Path(q.__file__).resolve()==(a.source/"tools/qualify_hia_selfhost.py").resolve()
    before=Path(q.__file__).read_bytes()
    assert sha1(b"blob "+str(len(before)).encode()+b"\0"+before).hexdigest()=="0bc5eb3dc49ee79faa67d3ff0d2e504689bab1f8"
    real_wait=q.wait
    class ArchiveAdmissionTests(unittest.TestCase):
        def root(self,label):
            p=a.out/label;p.mkdir();return p
        def test_native_return_stays_pending_until_archive_finishes(self):
            root=self.root("delayed-seal")
            native,seal=Future(),Future();native.set_result(q._PendingPhaseArchive(seal))
            waiting=Event()
            def watch(futures,**kwargs):
                if seal in futures:waiting.set()
                return real_wait(futures,**kwargs)
            with patch.object(q,"wait",side_effect=watch),ThreadPoolExecutor(max_workers=1) as pool:
                result=pool.submit(q._collect_qualification_phases,root,[("case","original",native)])
                try:
                    self.assertTrue(waiting.wait(3))
                    index=json.loads((root/"phase-index.json").read_bytes())
                    self.assertEqual((index["completed"],index["exceptions"]),(0,0))
                    self.assertEqual(index["phases"][0]["state"],"pending")
                    self.assertFalse(result.done())
                finally:
                    if not seal.done():seal.set_result(({"status":"PASS"},{"sealed":True}))
                value=result.result(timeout=3)
            self.assertEqual(value,[({"status":"PASS"},{"sealed":True})])
            self.assertEqual(json.loads((root/"phase-index.json").read_bytes())["phases"][0]["state"],"completed")
        def test_native_and_archive_failures_are_both_observed(self):
            root=self.root("both-failures")
            first,second,seal=Future(),Future(),Future()
            first.set_exception(ValueError("native-original-failure"))
            second.set_result(q._PendingPhaseArchive(seal))
            waiting=Event()
            def watch(futures,**kwargs):
                if seal in futures:waiting.set()
                return real_wait(futures,**kwargs)
            with patch.object(q,"wait",side_effect=watch),ThreadPoolExecutor(max_workers=1) as pool:
                result=pool.submit(q._collect_qualification_phases,root,
                    [("first","original",first),("second","modified",second)])
                try:self.assertTrue(waiting.wait(3))
                finally:
                    if not seal.done():seal.set_exception(OSError("archive-original-failure"))
                with self.assertRaises(AssertionError):result.result(timeout=3)
            index=json.loads((root/"phase-index.json").read_bytes())
            self.assertEqual((index["completed"],index["exceptions"]),(2,2))
            self.assertEqual({r["exception_message"] for r in index["phases"]},
                {"native-original-failure","archive-original-failure"})
        def test_reused_archive_future_cannot_qualify_two_phases(self):
            root=self.root("future-alias")
            first,second,seal=Future(),Future(),Future()
            first.set_result(q._PendingPhaseArchive(seal));second.set_result(q._PendingPhaseArchive(seal))
            seal.set_result(({"status":"PASS"},{"sealed":True}))
            with self.assertRaises(AssertionError):
                q._collect_qualification_phases(root,[("first","original",first),("second","modified",second)])
            index=json.loads((root/"phase-index.json").read_bytes())
            self.assertEqual((index["completed"],index["exceptions"]),(2,1))
            self.assertEqual(sum(r["state"]=="completed" for r in index["phases"]),1)
            self.assertEqual([r["exception_message"] for r in index["phases"] if r["state"]=="exception"],
                ["qualification archive future reused"])
        def test_backpressure_and_single_archiver_with_real_full_seal(self):
            root=self.root("bounded-real-seal")
            from tools.hia_evidence_archive import OWNER,read_retained_evidence
            started,release,third_started,third_admitted=Event(),Event(),Event(),Event()
            lock=Lock();active=maximum=0;seals=[]
            for i in range(3):
                stage=root/("stage-"+str(i));stage.mkdir();(stage/OWNER).write_text("owner-"+str(i))
                payload=bytes(range(256))*(i+1);(stage/"payload.bin").write_bytes(payload)
                seals.append((stage,"owner-"+str(i),root/("receipt-"+str(i)+".json"),
                    {"status":"PASS"},{"label":i},payload))
            def archive(index):
                nonlocal active,maximum
                with lock:active+=1;maximum=max(maximum,active)
                try:
                    if index==0:
                        started.set()
                        if not release.wait(3):raise RuntimeError("test release timeout")
                    args=seals[index]
                    return q._seal_qualification_phase(*args[:5])
                finally:
                    with lock:active-=1
            with q._PhaseArchivePool() as archives,ThreadPoolExecutor(max_workers=1) as submitters:
                first=archives.submit(archive,0)
                self.assertTrue(started.wait(3))
                second=archives.submit(archive,1)
                def third():
                    third_started.set();value=archives.submit(archive,2);third_admitted.set();return value
                third_result=submitters.submit(third)
                try:
                    self.assertTrue(third_started.wait(3))
                    self.assertFalse(third_admitted.is_set())
                    self.assertFalse(first.future.done());self.assertFalse(second.future.done())
                finally:release.set()
                values=[first,second,third_result.result(timeout=3)]
                for value in values:self.assertEqual(value.future.result(timeout=3)[0]["status"],"PASS")
            self.assertEqual(maximum,1)
            for stage,owner,receipt,report,prior,payload in seals:
                saved=json.loads(receipt.read_bytes())
                self.assertTrue(saved["raw_artifacts"]["every_original_byte_verified_before_retirement"])
                self.assertIn("archive_completed_monotonic_ns",saved)
                self.assertEqual(read_retained_evidence(stage/"payload.bin"),payload)
    suite=unittest.defaultTestLoader.loadTestsFromTestCase(ArchiveAdmissionTests)
    retained=unittest.defaultTestLoader.loadTestsFromName("tests.test_hia_evidence_archive")
    expected=suite.countTestCases()+retained.countTestCases()
    suite.addTests(retained)
    result=unittest.TextTestRunner(verbosity=2).run(suite)
    unchanged=Path(q.__file__).read_bytes()==before
    report=dict(status="PASS" if result.wasSuccessful() and not result.skipped and not result.expectedFailures
                and not result.unexpectedSuccesses and unchanged else "FAIL",
        cases=result.testsRun,expected_cases=expected,new_archive_lane_controls=4,
        retained_archive_controls=expected-4,failures=len(result.failures),errors=len(result.errors),
        skipped=len(result.skipped),expected_failures=len(result.expectedFailures),
        unexpected_successes=len(result.unexpectedSuccesses),source_unchanged=unchanged,
        qualifier_sha256=sha256(before).hexdigest(),actual_native_entries=0,
        cold_qualification=False,whole_stack_closed=False)
    (a.out/"summary.json").write_text(json.dumps(report,indent=2,sort_keys=True)+"\n")
    print("HIA_COLD_ARCHIVE_CONTROLS "+json.dumps(report,sort_keys=True),flush=True)
    if report["status"]!="PASS" or report["cases"]!=expected:raise SystemExit(1)
if __name__=="__main__":main()
