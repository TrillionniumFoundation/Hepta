"""Wheel data controls and opt-in actual installed HIA carrier controls.

Data-only tests run without an installed product. The explicit script command
also requires an actual installer PASS result and runs fresh installed processes.
Neither scope substitutes for the complete native Worker/public campaign.
"""
from pathlib import Path
from hashlib import sha256
import argparse
import base64
import csv
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import unittest
import zipfile

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
from tools import install_hia_carrier_compat as subject


def example_wheel(*, bad_mode=None, duplicate=False, bad_record=False):
    dist = "hia_core-0.3.0.dist-info"
    members = {"hepta/__init__.py": b"__version__='0.3.0'\n",
               dist + "/WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
               dist + "/METADATA": b"Metadata-Version: 2.1\nName: hia-core\nVersion: 0.3.0\n"}
    record = dist + "/RECORD"
    out = io.StringIO()
    writer = csv.writer(out, lineterminator="\n")
    for name, raw in sorted(members.items()):
        writer.writerow((name, subject.record_digest(raw), str(len(raw))))
    writer.writerow((record, "", ""))
    members[record] = out.getvalue().encode()
    if bad_record:
        members["hepta/__init__.py"] += b"# late\n"
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        for name, raw in members.items():
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            mode = 0o664 if name == record else 0o600
            if name == "hepta/__init__.py" and bad_mode is not None:
                mode = bad_mode
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, raw)
        if duplicate:
            archive.writestr("hepta/__init__.py", members["hepta/__init__.py"])
    return output.getvalue()


class WheelDataControls(unittest.TestCase):
    def test_real_standard_record_metadata_is_extracted_without_write_grant(self):
        members, modes, dist = subject.wheel_members(example_wheel())
        self.assertEqual(modes[dist + "/RECORD"] & 0o022, 0)
        self.assertEqual(members["hepta/__init__.py"], b"__version__='0.3.0'\n")

    def test_other_unsafe_modes_and_special_bits_refuse(self):
        for mode in (0o664, 0o666, 0o777, 0o4600, 0o2600):
            with self.subTest(mode=oct(mode)), self.assertRaises(ValueError):
                subject.wheel_members(example_wheel(bad_mode=mode))

    def test_complete_record_bytes_and_member_uniqueness(self):
        with self.assertRaises(ValueError):
            subject.wheel_members(example_wheel(bad_record=True))
        with self.assertRaises(ValueError):
            subject.wheel_members(example_wheel(duplicate=True))

    def test_member_escape_and_empty_aliases_refuse(self):
        for name in ("", "../outside", "/root/x", "hepta/../outside", "hepta//x",
                     "hepta/./x", "hepta\\x", "hepta/x\n", "hepta/"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                subject.member_name(name)

    def test_only_known_package_paths_relocate(self):
        old, new = Path("/owned/stage/hepta"), Path("/owned/installed/hepta")
        value = {"base_bundle": "/native/base.json", "policy_release": "/native/release",
                 "bridges": [{"package_path": str(old),
                              "build_receipt": {"path": str(old / "receipt.json")},
                              "binary": {"path": str(old / "image.so")},
                              "sources": {"hepta/reader.py": {"path": str(old / "reader.py")}}}]}
        moved = subject.rewrite_package_paths(value, old, new)
        self.assertEqual(moved["base_bundle"], value["base_bundle"])
        self.assertEqual(moved["policy_release"], value["policy_release"])
        self.assertEqual(moved["bridges"][0]["sources"]["hepta/reader.py"]["path"],
                         str(new / "reader.py"))
        self.assertEqual(value["bridges"][0]["package_path"], str(old))
        value["bridges"][0]["binary"]["path"] = "/foreign/image.so"
        with self.assertRaises(ValueError):
            subject.rewrite_package_paths(value, old, new)

    def test_profile_bool_is_not_a_python_version(self):
        members, modes, dist = subject.wheel_members(example_wheel())
        with self.assertRaises(ValueError):
            subject.make_wheel(members, modes, dist, Path("/owned/target"), {}, {},
                               {"python": [3, True, 0]})


_ACTUAL = r"""
import json,sys,types,struct
from pathlib import Path
from hashlib import sha256
root=Path(sys.argv[1]);sys.path.insert(0,str(root)); mode=sys.argv[2]
from hepta import hia_native_helpers as h
from hepta import hia_carrier_default as default
from hepta.hia_current_carrier_worker_bundle import NativeCurrentCarrierWorkerBinding
if mode=='refuse':
 try:
  with h.native_helpers_scope():
   raise AssertionError('invalid installed default was admitted')
 except (ValueError,OSError) as error:
  loaded=[name for name in ('hepta._hia_native_image','hepta._hia_cell_frame') if name in sys.modules]
  if loaded: raise AssertionError('invalid default reached extension load: '+repr(loaded))
  print(json.dumps({'refused':True,'type':type(error).__name__,'message':str(error),'loaded':loaded}))
elif mode in ('late-pin','late-record','late-default-reader'):
 from hepta import hia_current_carrier_worker_bundle as current
 file={'late-pin':root/'hepta'/default.PIN_RESOURCE,
       'late-record':root/'hia_core-0.3.0.dist-info/RECORD',
       'late-default-reader':root/'hepta/hia_carrier_default.py'}[mode]
 raw=file.read_bytes(); prior=current._ordinary_binding
 def mutate(*a,**k):
  result=prior(*a,**k); file.write_bytes(raw+b' ');return result
 current._ordinary_binding=mutate
 try:
  try:
   with h.native_helpers_scope(): raise AssertionError('late default mutation admitted')
  except (ValueError,OSError) as error:
   loaded=[name for name in ('hepta._hia_native_image','hepta._hia_cell_frame') if name in sys.modules]
   if loaded: raise AssertionError('late default mutation reached extension load: '+repr(loaded))
   print(json.dumps({'refused':True,'type':type(error).__name__,'loaded':loaded}))
 finally:file.write_bytes(raw)
elif mode=='explicit':
 observed=default.capture_default_bundle()
 def forbidden():raise AssertionError('explicit selection unexpectedly read package default')
 default.capture_default_bundle=forbidden
 with h.native_helpers_scope(str(observed[0]),observed[1]) as binding:
  assert type(binding) is NativeCurrentCarrierWorkerBinding;binding.check()
  print(json.dumps({'explicit':True,'sha256':binding.sha256}))
elif mode=='valid':
 from hepta import hia_native_image as image
 from hepta import hia_cell_frame as cell
 from hepta import hia_service_artifact_native as artifact
 from hepta import hia_service_verification_native as verification
 with h.native_helpers_scope() as binding:
  assert type(binding) is NativeCurrentCarrierWorkerBinding
  im,cm=image.selected_extension(),cell.selected_extension()
  selected=artifact.installed_service_artifact(binding.selections[artifact.SELECTOR])
  assert type(selected._mapping) is im.Image
  request=im.Buffer(struct.pack('<10Q',artifact.REQUEST_MAGIC,0,0,0,0,1,11,17,0,0),80)
  answer,state=im.Buffer(96),im.Buffer(128)
  result=selected._entry(request,80,answer,96,state,128)
  assert type(result) is int
  cells=cm.CellBindings(('value',),(types.CellType(7),),verification._read_empty_free_cell)
  assert cells['value']==7
  binding.check()
  print(json.dumps({'status':'PASS','default':True,'result':result,
                    'sha256':binding.sha256,'selections':sorted(binding.selections),
                    'image_policy':im._policy_observation(),
                    'cell_policy':cm._policy_observation()}))
else:raise ValueError('unknown installed control')
"""


def actual_controls(installation, output):
    installation = installation.resolve(strict=True)
    result = subject.decode((installation / "result.json").read_bytes())
    if result.get("status") != "PASS" or result.get("scope") != "TARGET_BOUND_CPYTHON_COMPATIBILITY":
        raise ValueError("actual installer PASS and explicit compatibility scope are required")
    target = Path(result["target"])
    output.mkdir(mode=0o700)
    original = {p: p.read_bytes() for p in target.rglob("*") if p.is_file()}
    controls = []

    def invoke(label, mode, selected=target):
        command = [sys.executable, "-I", "-B", "-c", _ACTUAL, str(selected), mode]
        (output / (label + ".intent.json")).write_bytes(subject.canonical(
            {"argv": command, "timeout_seconds": 60}))
        env = {k: v for k, v in os.environ.items() if not k.startswith("HEPTA_HIA_")}
        env.update(PYTHONDONTWRITEBYTECODE="1", TMPDIR=str(output))
        begin = time.monotonic()
        run = subprocess.run(command, capture_output=True, timeout=60, env=env, cwd=output)
        (output / (label + ".stdout")).write_bytes(run.stdout)
        (output / (label + ".stderr")).write_bytes(run.stderr)
        row = {"id": label, "returncode": run.returncode, "seconds": time.monotonic() - begin}
        controls.append(row)
        if run.returncode:
            raise AssertionError(label + ": " + run.stderr.decode(errors="replace"))
        return subject.decode(run.stdout)

    def mutate(path, transform, label):
        raw = path.read_bytes()
        try:
            path.write_bytes(transform(raw))
            observed = invoke(label, "refuse")
            if observed["refused"] is not True:
                raise AssertionError(label)
        finally:
            path.write_bytes(raw)

    class InstalledControls(unittest.TestCase):
        def test_actual_default_runs_both_native_policies(self):
            observed = invoke("actual-default", "valid")
            self.assertIs(observed["default"], True)
            self.assertGreater(observed["image_policy"]["native_calls"], 0)
            self.assertGreater(observed["cell_policy"]["native_calls"], 0)
            self.assertEqual(observed["image_policy"]["protocol_failures"], 0)
            self.assertEqual(observed["cell_policy"]["protocol_failures"], 0)

        def test_explicit_selection_is_not_supplemented(self):
            self.assertIs(invoke("explicit-selection", "explicit")["explicit"], True)

        def test_current_slot_receipt_keeps_old_v6_domain_closed(self):
            from tools.capture_hia_native_carrier_bundle import capture_bridge_records, read
            package = target / "hepta"
            receipt = package / "_slot_mechanical_build.json"
            expected = {"slot-mechanical": sha256(receipt.read_bytes()).hexdigest()}
            captures = []
            rows = capture_bridge_records(package, expected, ("slot-mechanical",),
                                          captures, current_slot=True)
            self.assertEqual(len(rows), 1)
            self.assertIn("hepta/hia_native_host_support.py", rows[0]["sources"])
            for path, raw, maximum in captures:
                self.assertEqual(read(path, maximum), raw)
            with self.assertRaises(ValueError):
                capture_bridge_records(package, expected, ("slot-mechanical",), [])
            with self.assertRaises(ValueError):
                capture_bridge_records(package, expected, ("slot-mechanical",), [], current_slot=1)
            helper = package / "hia_native_host_support.py"
            raw = helper.read_bytes()
            try:
                helper.write_bytes(raw + b"\n# actual captured source mutation\n")
                with self.assertRaises(ValueError):
                    capture_bridge_records(package, expected, ("slot-mechanical",), [],
                                           current_slot=True)
            finally:
                helper.write_bytes(raw)

        def test_missing_pin_with_existing_record_refuses(self):
            path = target / subject.PIN_RESOURCE
            raw = path.read_bytes()
            path.unlink()
            try:
                self.assertIs(invoke("missing-pin", "refuse")["refused"], True)
            finally:
                path.write_bytes(raw)

        def test_pin_and_bundle_record_changes_refuse(self):
            for name in (subject.PIN_RESOURCE, subject.BUNDLE_RESOURCE):
                mutate(target / name, lambda raw: raw + b" ", "mutated-" + Path(name).stem)

        def test_record_and_current_reader_changes_refuse(self):
            for name in ("hia_core-0.3.0.dist-info/RECORD", "hepta/hia_carrier_default.py"):
                mutate(target / name, lambda raw: raw + b" ", "mutated-" + Path(name).stem)

        def test_receipts_and_both_embedded_policies_refuse(self):
            for name in ("_native_image_build.json", "_cell_frame_build.json",
                         "native/carrier_image_policy.flat", "native/carrier_cell_policy.flat"):
                mutate(target / "hepta" / name, lambda raw: raw + b"\0",
                       "mutated-" + Path(name).name)

        def test_late_package_pins_refuse_before_extension_load(self):
            for mode in ("late-pin", "late-record", "late-default-reader"):
                self.assertIs(invoke(mode, mode)["refused"], True)

        def test_target_relocation_does_not_rebind_default(self):
            moved = output / "relocated"
            shutil.copytree(target, moved)
            self.assertIs(invoke("relocated-target", "refuse", moved)["refused"], True)

        def test_invalid_target_pin_type_refuses_even_with_updated_record(self):
            path = target / subject.PIN_RESOURCE
            record_path = target / "hia_core-0.3.0.dist-info/RECORD"
            raw, record = path.read_bytes(), record_path.read_bytes()
            try:
                value = subject.decode(raw)
                value["bundle_sha256"] = True
                changed = subject.canonical(value)
                path.write_bytes(changed)
                rows = list(csv.reader(io.StringIO(record.decode())))
                for row in rows:
                    if row[0] == subject.PIN_RESOURCE:
                        row[1:] = [subject.record_digest(changed), str(len(changed))]
                out = io.StringIO()
                csv.writer(out, lineterminator="\n").writerows(rows)
                record_path.write_bytes(out.getvalue().encode())
                self.assertIs(invoke("pin-bool-rebound-record", "refuse")["refused"], True)
            finally:
                path.write_bytes(raw)
                record_path.write_bytes(record)

    suite = unittest.TestSuite((unittest.defaultTestLoader.loadTestsFromTestCase(WheelDataControls),
                               unittest.defaultTestLoader.loadTestsFromTestCase(InstalledControls)))
    observed = unittest.TextTestRunner(verbosity=2).run(suite)
    stable = set(original) == {p for p in target.rglob("*") if p.is_file()} and all(
        p.read_bytes() == raw for p, raw in original.items())
    report = {"status": "PASS" if observed.wasSuccessful() and stable else "HOLD",
              "methods": observed.testsRun, "controls": controls,
              "original_installed_bytes_unchanged": stable,
              "scope": "ACTUAL_TARGET_BOUND_HOST_COMPATIBILITY_CONTROLS",
              "full_native_release_or_public_worker_claimed": False}
    (output / "result.json").write_bytes(subject.canonical(report))
    if not observed.wasSuccessful() or not stable:
        raise ValueError("actual installed carrier controls did not close")
    return report


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--installation", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.installation is None:
        unittest.main(argv=[sys.argv[0]])
    else:
        if args.output is None:
            parser.error("--output is required for actual installed controls")
        print(json.dumps(actual_controls(args.installation, args.output), sort_keys=True))
