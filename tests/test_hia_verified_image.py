"""Final-image capture is bounded and remains bound to each producer's identity."""
from __future__ import annotations

from hashlib import sha256
import importlib.util
import os
from pathlib import Path
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_verified_image as reader
from hepta.hia_verified_image import (
    MAX_VERIFIED_IMAGE_BYTES, VerifiedImageRejected, read_bounded_elf_image,
)


ROOT = Path(__file__).resolve().parents[1]
LINUX = platform.system() == "Linux"
NATIVE = (LINUX and platform.machine().lower() in {"x86_64", "amd64"}
          and shutil.which("ld") is not None and importlib.util.find_spec("z3") is not None)


class _ReadMutation:
    """Mutate a real candidate at the read boundary, preserving real file I/O."""
    def __init__(self, stream, action, *, before=False, observations=None):
        self.stream, self.action = stream, action
        self.before, self.observations = before, observations

    def __enter__(self):
        self.stream.__enter__()
        return self

    def __exit__(self, *args):
        return self.stream.__exit__(*args)

    def read(self, size):
        if self.before:
            self.action()
        data = self.stream.read(size)
        if self.observations is not None:
            self.observations.append((size, len(data)))
        if not self.before:
            self.action()
        return data


@unittest.skipUnless(LINUX, "no-follow nonblocking Linux file descriptors are required")
class VerifiedImageReadTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-image-read-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)

    def test_exact_regular_bytes_include_both_size_boundaries(self):
        path = self.root / "image.so"
        for size in (64, MAX_VERIFIED_IMAGE_BYTES):
            with self.subTest(size=size):
                data = b"\x7fELF" + bytes(size - 4)
                path.write_bytes(data)
                captured = read_bounded_elf_image(str(path))
                self.assertIs(type(captured), bytes)
                self.assertEqual(captured, data)

    def test_short_and_oversized_sparse_files_never_enter_stream_read(self):
        path = self.root / "image.so"
        for size in (0, 63, MAX_VERIFIED_IMAGE_BYTES + 1):
            with self.subTest(size=size):
                with path.open("wb") as stream:
                    stream.truncate(size)
                with patch.object(reader.os, "fdopen", side_effect=AssertionError("rejected size reached read")):
                    with self.assertRaisesRegex(VerifiedImageRejected, "bounded regular ELF"):
                        read_bounded_elf_image(path)

    def test_fifo_refusal_has_an_external_deadline(self):
        path = self.root / "image.so"
        os.mkfifo(path)
        script = ("import sys\n"
                  "from hepta.hia_verified_image import read_bounded_elf_image, VerifiedImageRejected\n"
                  "try:\n"
                  "    read_bounded_elf_image(sys.argv[1])\n"
                  "except VerifiedImageRejected:\n"
                  "    raise SystemExit(0)\n"
                  "raise SystemExit(1)\n")
        result = subprocess.run([sys.executable, "-B", "-c", script, str(path)],
                                cwd=ROOT, timeout=5, capture_output=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))

    def test_symlink_directory_and_missing_file_are_typed_refusals(self):
        target = self.root / "original"
        original = b"caller-owned bytes" * 4
        target.write_bytes(original)
        link = self.root / "link.so"
        link.symlink_to(target)
        for path in (link, self.root, self.root / "missing.so"):
            with self.subTest(path=path.name), self.assertRaises(VerifiedImageRejected):
                read_bounded_elf_image(path)
        self.assertEqual(target.read_bytes(), original)

    def test_same_size_write_replacement_and_symlink_swap_are_refused(self):
        real_fdopen = reader.os.fdopen
        for change in ("write", "replace", "symlink"):
            with self.subTest(change=change):
                path = self.root / (change + ".so")
                path.write_bytes(b"A" * 64)
                before = path.stat()
                replacement = self.root / (change + "-replacement")
                replacement.write_bytes(path.read_bytes())
                os.utime(replacement, ns=(before.st_atime_ns, before.st_mtime_ns))

                def mutate():
                    if change == "write":
                        path.write_bytes(b"B" * 64)
                        os.utime(path, ns=(before.st_atime_ns, before.st_mtime_ns + 1000000000))
                    elif change == "replace":
                        os.replace(replacement, path)
                    else:
                        path.unlink()
                        path.symlink_to(replacement)

                def open_mutating(*args, **kwargs):
                    return _ReadMutation(real_fdopen(*args, **kwargs), mutate)

                with patch.object(reader.os, "fdopen", side_effect=open_mutating):
                    with self.assertRaisesRegex(VerifiedImageRejected, "changed during bounded read"):
                        read_bounded_elf_image(path)

    def test_growth_after_initial_stat_cannot_exceed_capture_budget(self):
        path = self.root / "growing.so"
        path.write_bytes(b"A" * 64)
        observations = []
        real_fdopen = reader.os.fdopen

        def grow():
            with path.open("ab") as stream:
                stream.truncate(MAX_VERIFIED_IMAGE_BYTES + 1024 * 1024)

        def open_growing(*args, **kwargs):
            return _ReadMutation(real_fdopen(*args, **kwargs), grow,
                                 before=True, observations=observations)

        with patch.object(reader.os, "fdopen", side_effect=open_growing):
            with self.assertRaisesRegex(VerifiedImageRejected, "changed during bounded read"):
                read_bounded_elf_image(path)
        self.assertEqual(observations, [(MAX_VERIFIED_IMAGE_BYTES + 1, MAX_VERIFIED_IMAGE_BYTES + 1)])

    def test_descriptor_is_closed_when_stream_creation_fails(self):
        path = self.root / "image.so"
        path.write_bytes(b"A" * 64)
        opened = []
        real_open = reader.os.open

        def record_open(*args, **kwargs):
            descriptor = real_open(*args, **kwargs)
            opened.append(descriptor)
            return descriptor

        with patch.object(reader.os, "open", side_effect=record_open), \
                patch.object(reader.os, "fdopen", side_effect=OSError("injected stream failure")):
            with self.assertRaises(VerifiedImageRejected):
                read_bounded_elf_image(path)
        self.assertEqual(len(opened), 1)
        with self.assertRaises(OSError):
            os.fstat(opened[0])


@unittest.skipUnless(NATIVE, "Linux x86-64, GNU ld and pinned Z3 are required")
class VerifiedImageBuilderTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="hia-image-builder-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        from tests.test_hia_program import arithmetic
        self.core = arithmetic("int.add.wrap", "u32")

    def test_safe_core_success_binds_reader_and_never_uses_unbounded_candidate_read(self):
        from hepta.hia_safe_core import build_safe_core
        original = Path.read_bytes

        def reject_candidate_read(path):
            if path.name == "candidate.so":
                raise AssertionError("unbounded candidate read")
            return original(path)

        output = self.root / "safe.so"
        with patch.object(Path, "read_bytes", reject_candidate_read):
            report = build_safe_core(self.core, output)
        self.assertEqual(report["artifact_sha256"], sha256(output.read_bytes()).hexdigest())
        self.assertEqual(report["validation"]["source_identity"]["hia_verified_image.py"],
                         sha256((ROOT / "hepta/hia_verified_image.py").read_bytes()).hexdigest())
        self.assertNotIn("hia_verified_image.py", report["validation"]["checker"]["source_identity"])

    def test_safe_core_rejects_special_or_oversized_post_link_candidate_before_proof(self):
        from hepta.hia_program_native import compile_program_machine
        from hepta.hia_safe_core import build_safe_core, SafeCoreRejected
        target = self.root / "untouched-input"
        target.write_bytes(b"caller-owned bytes" * 4)
        original_target = target.read_bytes()
        for kind in ("fifo", "symlink", "sparse"):
            with self.subTest(kind=kind):
                output = self.root / (kind + ".so")

                def compile_and_replace(*args, **kwargs):
                    result = compile_program_machine(*args, **kwargs)
                    candidate = Path(kwargs["output"])
                    candidate.unlink()
                    if kind == "fifo":
                        os.mkfifo(candidate)
                    elif kind == "symlink":
                        candidate.symlink_to(target)
                    else:
                        with candidate.open("wb") as stream:
                            stream.truncate(MAX_VERIFIED_IMAGE_BYTES + 1)
                    return result

                with patch("hepta.hia_program_native.compile_program_machine", side_effect=compile_and_replace), \
                        patch("hepta.hia_safe_core.validate_safe_core_image",
                              side_effect=AssertionError("inadmissible file reached proof")):
                    with self.assertRaises(SafeCoreRejected) as caught:
                        build_safe_core(self.core, output)
                self.assertIsInstance(caught.exception.__cause__, VerifiedImageRejected)
                self.assertFalse(output.exists())
        self.assertEqual(target.read_bytes(), original_target)

    def test_safe_core_reader_identity_drift_never_reaches_proof(self):
        from hepta import hia_safe_core as safe
        identity = safe._source_identity()
        original_read = safe.read_bounded_elf_image

        def read_then_drift(path):
            data = original_read(path)
            identity["hia_verified_image.py"] = "0" * 64
            return data

        output = self.root / "drift.so"
        with patch.object(safe, "_source_identity", side_effect=lambda: dict(identity)), \
                patch.object(safe, "read_bounded_elf_image", side_effect=read_then_drift), \
                patch.object(safe, "validate_safe_core_image", side_effect=AssertionError("identity drift reached proof")):
            with self.assertRaisesRegex(safe.SafeCoreRejected, "producer source changed"):
                safe.build_safe_core(self.core, output)
        self.assertFalse(output.exists())

    def test_safe_core_incomplete_or_failed_consumer_report_never_publishes(self):
        from hepta import hia_safe_core as safe
        for number, flags in enumerate(({}, {"ok": True, "complete": False},
                                        {"ok": False, "complete": True},
                                        {"ok": 1, "complete": True})):
            with self.subTest(report=flags):
                output = self.root / ("incomplete-" + str(number) + ".so")
                report = {"source_identity": safe._source_identity(), "status": "unknown", **flags}
                with patch.object(safe, "validate_safe_core_image", return_value=report), \
                        patch("hepta.artifact_publication.publish_verified",
                              side_effect=AssertionError("incomplete consumer reached publication")):
                    with self.assertRaisesRegex(safe.SafeCoreRejected, "validation did not complete"):
                        safe.build_safe_core(self.core, output)
                self.assertFalse(output.exists())

    def test_safe_core_reader_identity_drift_after_publication_withdraws_own_output(self):
        from hepta import artifact_publication, hia_safe_core as safe
        identity = safe._source_identity()
        original_publish = artifact_publication.publish_verified
        output = self.root / "withdrawn.so"
        unrelated = self.root / "unrelated.so"
        unrelated.write_bytes(b"preserve unrelated file")

        def publish_then_drift(*args):
            result = original_publish(*args)
            if Path(args[1]) == output:
                identity["hia_verified_image.py"] = "0" * 64
            return result

        with patch.object(safe, "_source_identity", side_effect=lambda: dict(identity)), \
                patch.object(artifact_publication, "publish_verified", side_effect=publish_then_drift):
            with self.assertRaisesRegex(safe.SafeCoreRejected, "checker changed before final publication"):
                safe.build_safe_core(self.core, output)
        self.assertFalse(output.exists())
        self.assertEqual(unrelated.read_bytes(), b"preserve unrelated file")

    def test_simd_reader_identity_drift_never_publishes(self):
        from hepta import hia_verified_kernel as kernel
        from hepta.hia_verified_simd import simd_kernel_program
        identity = kernel._simd_producer_identity()
        self.assertEqual(identity["hia_verified_image.py"],
                         sha256((ROOT / "hepta/hia_verified_image.py").read_bytes()).hexdigest())
        original_read = kernel.read_bounded_elf_image

        def read_then_drift(path):
            data = original_read(path)
            identity["hia_verified_image.py"] = "0" * 64
            return data

        output = self.root / "simd-drift.so"
        with patch.object(kernel, "_simd_producer_identity", side_effect=lambda: dict(identity)), \
                patch.object(kernel, "read_bounded_elf_image", side_effect=read_then_drift), \
                patch.object(kernel, "publish_verified", side_effect=AssertionError("identity drift reached publication")):
            with self.assertRaisesRegex(kernel.VerifiedKernelRejected, "producer or linker changed"):
                kernel.build_verified_kernel(simd_kernel_program("sum_u8"), output,
                                             strategy="simd", simd_unroll=1)
        self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
