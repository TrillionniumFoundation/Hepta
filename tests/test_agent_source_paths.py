"""Source path identity must be invariant under v4 version relocation."""
import unittest

from hepta.agent_source_paths import relative_validated_source


class AgentSourcePathTests(unittest.TestCase):
    def test_new_version_same_logical_source(self):
        first = "/store/versions/" + "a" * 64 + "/tree"
        second = "/store/versions/" + "b" * 64 + "/tree"
        inventory = ["src/api.hepta", "src/main.hepta"]
        self.assertEqual(relative_validated_source(first + "/src/api.hepta", first, inventory),
                         relative_validated_source(second + "/src/api.hepta", second, inventory))

    def test_escape_and_unrecorded_source_rejected(self):
        root = "/store/versions/" + "a" * 64 + "/tree"
        for path in (root + "/src/missing.hepta", root + "/../outside.hepta",
                     "/outside/src/api.hepta", "src/api.hepta"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                relative_validated_source(path, root, ["src/api.hepta"])

    def test_malformed_manifest_rejected(self):
        root = "/store/versions/" + "a" * 64 + "/tree"
        for inventory in (["../api.hepta"], ["/src/api.hepta"],
                          ["src/api.hepta", "src/api.hepta"], ["src\\\\api.hepta"],
                          [], [None], ["src/api.py"]):
            with self.subTest(inventory=inventory), self.assertRaises(ValueError):
                relative_validated_source(root + "/src/api.hepta", root, inventory)


if __name__ == "__main__":
    unittest.main()
