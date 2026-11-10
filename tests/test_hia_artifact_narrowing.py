"""Real native controls for the prepared guarded+narrowed artifact route."""
from copy import deepcopy
from hashlib import sha256
import json
import os
from pathlib import Path
import platform
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from hepta import hia_artifact_session as session_module
from hepta import hia_narrowing as narrowing_module
from hepta.hia_artifact_session import ArtifactSessionRejected, PreparedArtifactSession
from hepta.hia_multiversion import PublicationCancellation
from hepta.hia_narrowing import propose_guarded_narrowing
from hepta.hia_optimization import DEFAULT_POLICY, OptimizationRejected




if __name__ == "__main__":
    unittest.main()
