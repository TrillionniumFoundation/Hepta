"""Failed real Git observations must not become clean qualification evidence."""
import tempfile
import unittest

from tools.qualify_hia_returned_loans import command, git_observation


class ReturnedLoanQualificationIdentityTests(unittest.TestCase):
    def test_non_repository_command_failure_cannot_claim_clean_or_stable(self):
        with tempfile.TemporaryDirectory() as folder:
            head = command(["git", "-C", folder, "rev-parse", "HEAD"])
            status = command(["git", "-C", folder, "status", "--porcelain"])
        self.assertNotEqual(head["returncode"], 0)
        self.assertNotEqual(status["returncode"], 0)
        self.assertEqual(git_observation(head, status, head, status),
                         {"observed": False, "same_head": False, "clean": False})

    def test_dirty_source_is_observed_without_becoming_clean(self):
        head = {"returncode": 0, "stdout": "a" * 40 + "\n"}
        status = {"returncode": 0, "stdout": " M hepta/hia_program.py\n"}
        self.assertEqual(git_observation(head, status, head, status),
                         {"observed": True, "same_head": True, "clean": False})
        clean = {"returncode": 0, "stdout": ""}
        self.assertEqual(git_observation(head, clean, head, clean),
                         {"observed": True, "same_head": True, "clean": True})
        for unobserved in ({"error": "unavailable"},
                           {"returncode": False, "stdout": head["stdout"]},
                           {"returncode": 0, "stdout": "not a commit\n"}):
            with self.subTest(unobserved=unobserved):
                self.assertFalse(git_observation(unobserved, clean, unobserved, clean)["observed"])


if __name__ == "__main__":
    unittest.main()
