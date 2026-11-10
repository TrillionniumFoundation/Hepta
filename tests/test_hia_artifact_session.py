"""Actual native and adversarial lifetime checks for prepared artifact reuse."""
from copy import copy, deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from hepta import hia_artifact_session as session_module
from hepta import hia_guarded_optimization as guarded_module
from hepta.hia_artifact_session import PreparedArtifactSession, ArtifactSessionRejected
from hepta.hia_guarded_optimization import propose_guarded_reduction
from hepta.hia_multiversion import PublicationCancellation
from hepta.native_tool_identity import MAX_EXECUTABLE_BYTES, ToolIdentityRejected




if __name__ == "__main__":
    unittest.main()
