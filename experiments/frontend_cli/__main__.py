"""Explicit process boundary: main flushes output; avoid shutdown pipe retries."""
import os
from .cli import main

# No atexit output retry after a partial/failed transport. Owner cleanup has already
# finished inside the adapter. Import/interpreter failures are outside this boundary.
os._exit(main())
