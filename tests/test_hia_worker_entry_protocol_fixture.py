"""Physical-source controls for the complete protocol-specific CLI fixture."""
from pathlib import Path
import tempfile
import unittest
from tools import hia_worker_entry_protocol_fixture as fixture


class WorkerEntryProtocolFixtureTests(unittest.TestCase):
    def stage(self, root):
        for name in (fixture.SELF, fixture.FIXTURE, fixture.ORIGINAL):
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True)
            p.write_bytes((fixture.ROOT/name).read_bytes())

    def test_complete_original_and_both_explicit_domains(self):
        original=(fixture.ROOT/fixture.ORIGINAL).read_bytes()
        for number in ("01","02","03"):
            view=fixture.prepare(fixture.ROOT,number)
            self.assertEqual(len(view.source),len(original))
            expected=original.replace(b"options==b'HIAWOP01'",
                                      ("options==b'HIAWOP"+number+"'").encode())
            self.assertEqual(view.source,expected)
            self.assertEqual(view.source.replace(("HIAWOP"+number).encode(),b"HIAWOP01"),
                             original)
            view.verify()
            self.assertEqual(set(view.captured),(set((fixture.SELF,fixture.FIXTURE,fixture.ORIGINAL))))

    def test_unknown_domain_and_missing_or_changed_physical_authority_refuse(self):
        for number in (None,True,1,"3","../03",b"03"):
            with self.subTest(number=number),self.assertRaises(ValueError):
                fixture.prepare(fixture.ROOT,number)
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(strict=True);self.stage(root)
            for name in (fixture.SELF,fixture.FIXTURE,fixture.ORIGINAL):
                p=root/name;old=p.read_bytes();p.unlink()
                with self.subTest(name=name,kind="missing"),self.assertRaises(FileNotFoundError):
                    fixture.prepare(root,"03")
                p.write_bytes(old+b"\n")
                with self.subTest(name=name,kind="changed"),self.assertRaises(ValueError):
                    fixture.prepare(root,"03")
                p.write_bytes(old)

    def test_every_physical_input_is_checked_again_at_completion(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(strict=True);self.stage(root)
            for name in (fixture.SELF,fixture.FIXTURE,fixture.ORIGINAL):
                view=fixture.prepare(root,"02")
                p=root/name;old=p.read_bytes();p.write_bytes(old+b"\n")
                with self.subTest(name=name),self.assertRaisesRegex(ValueError,"input changed"):
                    view.verify()
                p.write_bytes(old);view.verify()

    def test_late_read_change_during_prepare_is_not_admitted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory).resolve(strict=True);self.stage(root)
            for target in (fixture.SELF,fixture.FIXTURE,fixture.ORIGINAL):
                changed=False;p=root/target;original=p.read_bytes()
                def take(path):
                    nonlocal changed
                    raw=path.read_bytes()
                    if path==root/fixture.ORIGINAL and not changed:
                        changed=True;p.write_bytes(original+b"\n")
                    return raw
                with self.subTest(target=target),self.assertRaises(ValueError):
                    fixture.prepare(root,"03",take=take)
                p.write_bytes(original)


if __name__=="__main__":
    unittest.main()
