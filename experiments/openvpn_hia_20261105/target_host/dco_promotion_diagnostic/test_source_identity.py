#!/usr/bin/env python3
"""Check canonical source identity and rejection before any C compiler starts."""
import argparse
import hashlib
from pathlib import Path
import subprocess
import sys
import tempfile

import reproduce_dco_promotion_schedule as diagnostic


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("ssl_source", type=Path)
    args = parser.parse_args()
    raw = args.ssl_source.read_bytes()
    blob = hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    if blob != "a2eee6a72c59b658aaa0308ebc8f2983efac1ffe":
        parser.error("test input is not the canonical official Git blob")
    if hashlib.sha256(raw).hexdigest() != diagnostic.SSL_SHA256:
        raise RuntimeError("the diagnostic hash pin does not match official source bytes")
    checked = 0
    with tempfile.TemporaryDirectory(prefix="promotion-source-identity-") as temp:
        temp = Path(temp)
        for name, data in (("extra-newline", raw + b"\n"), ("truncated", raw[:-1]),
                           ("changed-byte", b"x" + raw[1:])):
            source = temp / (name + ".c")
            source.write_bytes(data)
            for script in ("reproduce_dco_promotion_schedule.py", "review_dco_promotion_states.py"):
                result = subprocess.run(
                    [sys.executable, "-B", str(Path(__file__).with_name(script)), str(source),
                     "--cc", str(temp / "compiler-must-not-start")],
                    capture_output=True, text=True, timeout=5)
                if result.returncode != 2 or "source differs" not in result.stderr:
                    raise RuntimeError(f"{script} did not reject {name} before compilation: {result}")
                checked += 1
    print(f"PASS canonical Git-blob identity and {checked} altered-input refusals before compiler execution.")


if __name__ == "__main__":
    main()
