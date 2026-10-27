"""Read retained native stderr records without executing any target/toolchain."""
from __future__ import annotations
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys

root = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2]).resolve()
pattern = re.compile(r"implicit declaration|conflicting types|incompatible pointer|implicit-int|pointer from integer|integer from pointer", re.I)
reports = []
findings = []


def sha(data):
    return hashlib.sha256(data).hexdigest()


def visit(value, pointer, report):
    if isinstance(value, dict):
        for key, item in value.items():
            escaped = key.replace("~", "~0").replace("/", "~1")
            current = pointer + "/" + escaped
            if key == "stderr":
                text = item if isinstance(item, str) else item.get("text", "") if isinstance(item, dict) else ""
                lines = [line for line in text.splitlines() if pattern.search(line)]
                if lines:
                    findings.append({"report": report, "json_pointer": current,
                                     "matching_lines": lines, "stderr_utf8_sha256": sha(text.encode())})
            if isinstance(item, (dict, list)):
                visit(item, current, report)
    elif isinstance(value, list):
        for number, item in enumerate(value):
            if isinstance(item, (dict, list)):
                visit(item, pointer + "/" + str(number), report)


for path in sorted(root.glob("*.json")):
    data = path.read_bytes()
    parsed = json.loads(data)
    reports.append({"name": path.name, "bytes": len(data), "sha256": sha(data)})
    visit(parsed, "", path.name)
commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=root).decode().strip()
document = {"schema": "hepta.retained-caller-warning-audit.v1", "commit": commit,
            "report_root": str(root), "reports": reports, "findings": findings,
            "matching_stderr_records": len(findings),
            "scope": "Top-level retained source-qualification JSON stderr fields only; no compiler or native program executed."}
with output.open("x") as stream:
    json.dump(document, stream, indent=2, sort_keys=True)
    stream.write("\n")
print(json.dumps({"reports": len(reports), "matching_stderr_records": len(findings), "output": str(output)}))
