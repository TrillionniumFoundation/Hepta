"""The Store profile exposes its release API without loading the Store adapter at discovery."""
from pathlib import Path
import subprocess
import sys
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WorkerStoreProfileImportTests(unittest.TestCase):
    def fresh_python(self, source):
        body = "import sys\nsys.path.insert(0, sys.argv[1])\n" + textwrap.dedent(source)
        result = subprocess.run(
            [sys.executable, "-I", "-B", "-c", body, str(ROOT)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_schema_discovery_and_explicit_store_selection(self):
        self.fresh_python("""
            from hepta import hia_worker_store_profile as profile
            exports = ("RELEASE_IMAGES", "capture_release_image", "release_identity")
            assert all(name in dir(profile) for name in exports)
            assert "hepta.hia_agent_store_native" not in sys.modules
            images = profile.profile_images(profile.SCHEMA)
            from hepta import hia_agent_store_native as store
            assert tuple(images.values()) == store.RELEASE_IMAGES
            assert all(getattr(profile, name) is getattr(store, name) for name in exports)
        """)

    def test_wildcard_import_preserves_release_api_objects(self):
        self.fresh_python("""
            from hepta.hia_worker_store_profile import *
            from hepta import hia_agent_store_native as store
            assert RELEASE_IMAGES is store.RELEASE_IMAGES
            assert capture_release_image is store.capture_release_image
            assert release_identity is store.release_identity
        """)
