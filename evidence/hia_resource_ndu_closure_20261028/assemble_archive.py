"""Verify the two published parts and restore the exact audited xz container."""
from hashlib import sha256
import json
from pathlib import Path


def main():
    root = Path(__file__).resolve().parent
    manifest = json.loads((root / "raw-evidence-manifest.json").read_text())
    spec = manifest["publication_parts"]
    archive = manifest["archive"]
    destination = root / archive["name"]
    parts = []
    for part in spec["ordered"]:
        data = (root / part["name"]).read_bytes()
        if len(data) != part["bytes"] or sha256(data).hexdigest() != part["sha256"]:
            raise ValueError("Published part differs: " + part["name"])
        parts.append(data)
    content = b"".join(parts)
    digest = sha256(content).hexdigest()
    if (len(content) != archive["bytes"] or digest != archive["sha256"]
            or digest != spec["concatenation_sha256"]):
        raise ValueError("Reassembled archive differs from audited container")
    # Exclusive creation: preserve any archive already present for inspection.
    with destination.open("xb") as output:
        output.write(content)
    print(f"Verified {len(parts)} parts; restored {destination.name}")
    print(f"{digest}  {destination.name}")


if __name__ == "__main__":
    main()
