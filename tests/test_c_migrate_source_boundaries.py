"""Port the source-boundary fixes without replacing the newer strict lowerer."""
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from hepta import c_migrate
from hepta.checker import check as real_check


class CMigrationSourceBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.clang = shutil.which("clang")
        self.assertIsNotNone(self.clang, "real Clang is required")
        self.temp = tempfile.TemporaryDirectory(prefix="hepta-c-source-boundary-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.source = self.root / "input.c"
        self.output = self.root / "output.hepta"
        self.source.write_text("int f(int x){return x+1;}\n")

    def run_migration(self):
        return c_migrate.migrate_c(self.source, self.output, clang=self.clang)

    def reject_without_output(self, result, code):
        self.assertFalse(result["ok"], result)
        self.assertIn(code, [x["code"] for x in result["rejected"]])
        self.assertFalse(self.output.exists())
        self.assertEqual(list(self.root.glob(".hepta-migrate-*")), [])

    def test_initial_oversize_rejects_before_clang_and_without_read_bytes(self):
        self.source.write_bytes(b" " * (c_migrate.MAX_SOURCE_BYTES + 1000))
        with patch.object(Path, "read_bytes", side_effect=AssertionError("unbounded read")), \
                patch.object(c_migrate, "_run") as clang:
            result = self.run_migration()
        clang.assert_not_called()
        self.reject_without_output(result, "E_C_SIZE")

    def test_initial_and_freshness_reads_have_exact_limits(self):
        original_open, reads = Path.open, []
        source = self.source
        class Bounded:
            def __init__(self, stream): self.stream = stream
            def __enter__(self): self.stream.__enter__(); return self
            def __exit__(self, *args): return self.stream.__exit__(*args)
            def read(self, size=-1):
                reads.append(size)
                if size != c_migrate.MAX_SOURCE_BYTES + 1:
                    raise AssertionError("unbounded source read")
                return self.stream.read(size)
        def observe(path, *args, **kwargs):
            stream = original_open(path, *args, **kwargs)
            return Bounded(stream) if path == source and args and args[0] == "rb" else stream
        with patch.object(Path, "open", observe):
            result = self.run_migration()
        self.assertTrue(result["ok"], result)
        self.assertEqual(reads, [c_migrate.MAX_SOURCE_BYTES + 1] * 4)

    def test_growth_after_real_clang_is_a_controlled_source_race(self):
        real_run = c_migrate._run
        def growing(argv, **kwargs):
            answer = real_run(argv, **kwargs)
            if "-ast-dump=json" in argv:
                self.source.write_bytes(b" " * (c_migrate.MAX_SOURCE_BYTES + 1000))
            return answer
        with patch.object(c_migrate, "_run", side_effect=growing):
            result = self.run_migration()
        self.reject_without_output(result, "E_C_SOURCE_RACE")

    def test_equal_size_frontend_mutation_is_rejected_before_publication(self):
        def mutate(program):
            checked = real_check(program)
            self.source.write_text("int f(int x){return x+2;}\n")
            return checked
        with patch("hepta.checker.check", side_effect=mutate):
            result = self.run_migration()
        self.reject_without_output(result, "E_C_SOURCE_RACE")

    def test_comment_mutation_during_final_preprocess_does_not_keep_old_source_identity(self):
        real_run, preprocessing = c_migrate._run, []
        def mutate_after_preprocessing(argv, **kwargs):
            answer = real_run(argv, **kwargs)
            if "-P" in argv:
                preprocessing.append(True)
                if len(preprocessing) == 2:
                    self.source.write_text("int f(int x){return x+1;} /*changed*/\n")
            return answer
        with patch.object(c_migrate, "_run", side_effect=mutate_after_preprocessing):
            result = self.run_migration()
        self.reject_without_output(result, "E_C_SOURCE_RACE")

    def test_read_error_is_controlled_and_global_status_matches_body_rejection(self):
        original_open = Path.open
        def unavailable(path, *args, **kwargs):
            if path == self.source and args and args[0] == "rb":
                raise OSError("simulated disappearing source")
            return original_open(path, *args, **kwargs)
        with patch.object(Path, "open", unavailable):
            result = self.run_migration()
        self.reject_without_output(result, "E_C_SOURCE_RACE")
        self.source.write_text("int hidden=1; int f(int x){return x;}\n")
        result = self.run_migration()
        self.reject_without_output(result, "E_C_TOPLEVEL")
        self.assertEqual(result["status"], "unsupported_source")


if __name__ == "__main__":
    unittest.main()
