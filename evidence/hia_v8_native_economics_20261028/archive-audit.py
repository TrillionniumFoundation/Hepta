"""Read-only final archive audit; no extraction, target execution, or network.

Prepare once, invoke only after the final package exists.  An explicit mapping
can rename workspace-relative required paths.  Otherwise an optional archive
root prefix is accepted only when the suffix identifies exactly one member.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile
import zipfile

WORK = Path(__file__).resolve().parent.parent
REQUIREMENTS = WORK / "hia-round3-final-audit/ndu-evidence-package-requirements.json"
REQUIREMENTS_SHA = "19c30f199b817accb2fe16dcd4b57595f031c7d2fa2a7900fc5fb333a184a0cc"
COMPANION = WORK / "hia-round3-final-audit/ndu-package-requirements-manifest.json"
COMPANION_SHA = "aed865bcbd3d6c2d027758883325e596e233041871783801f9c833af1d185ff3"
PATTERNS = {
    "signed_url": re.compile(rb"https://[^\s\"'<>]+[?&](?:sig|se|sv|X-Amz-Signature|X-Goog-Signature)=", re.I),
    "github_token": re.compile(rb"\bgh[pousr]_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    "authorization_token": re.compile(rb"Authorization:\s*(?:Bearer|token)\s+[A-Za-z0-9_.-]{20,}", re.I),
}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def file_hash(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def safe_name(name):
    path = PurePosixPath(name)
    return bool(name) and not path.is_absolute() and ".." not in path.parts and "\\" not in name


def pointer(value, name):
    for piece in name.split("/")[1:]:
        value = value[piece.replace("~1", "/").replace("~0", "~")]
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archive", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--mapping", type=Path, help="JSON workspace-relative path -> exact archive member")
    parser.add_argument("--extra-freeze-manifest", type=Path, action="append", default=[])
    args = parser.parse_args()
    if args.output.exists():
        raise SystemExit("Refusing to overwrite an existing audit result")
    if file_hash(REQUIREMENTS) != REQUIREMENTS_SHA or file_hash(COMPANION) != COMPANION_SHA:
        raise SystemExit("Frozen package requirements or companion changed")
    requirements = json.loads(REQUIREMENTS.read_text())
    required = {name: {"bytes": row["bytes"], "sha256": row["sha256"], "role": "ndu_frozen_payload"} for name, row in requirements["required_files"].items()}
    for path in (REQUIREMENTS, COMPANION):
        required[str(path.relative_to(WORK))] = {"bytes": path.stat().st_size, "sha256": file_hash(path), "role": "ndu_frozen_metadata"}
    for path in args.extra_freeze_manifest:
        path = path.resolve()
        obj = json.loads(path.read_text())
        base = path.parent.relative_to(WORK)
        for row in obj["files"]:
            name = str(base / row["path"])
            expected = {"bytes": row["bytes"], "sha256": row["sha256"], "role": "extra_frozen_evidence"}
            if name in required and any(required[name][key] != expected[key] for key in ("bytes", "sha256")):
                raise SystemExit("Conflicting required identities: " + name)
            required[name] = expected
        required[str(path.relative_to(WORK))] = {"bytes": path.stat().st_size, "sha256": file_hash(path), "role": "extra_freeze_manifest"}
    mapping = json.loads(args.mapping.read_text()) if args.mapping else {}
    if not isinstance(mapping, dict) or any(not isinstance(k, str) or not isinstance(v, str) for k, v in mapping.items()):
        raise SystemExit("Mapping must be a string-to-string object")
    records, captured, unsafe, duplicates, secret_findings, forbidden = {}, {}, [], [], [], []
    formal_key = str(Path(requirements["key_artifacts"]["formal_result"]["source_path"]).relative_to(WORK))

    def consume(name, size, stream, kind="regular"):
        if not safe_name(name) or kind != "regular":
            unsafe.append({"member": name, "kind": kind})
        if name in records:
            duplicates.append(name)
        if size > 256 * 1024 * 1024:
            raise ValueError("Individual member exceeds declared audit read limit: " + name)
        if any(part in {".aws", ".git-credentials", ".netrc"} for part in PurePosixPath(name).parts) or re.search(r"(?:^|/)(?:hia-round3-ci-download-\d+|hia-round3-range-config|hia-range-[^/]+)\.json$", name):
            forbidden.append(name)
        digest, count, previous = hashlib.sha256(), 0, b""
        wants_result = name == mapping.get(formal_key) or name == formal_key or name.endswith("/" + formal_key)
        result = bytearray() if wants_result else None
        if stream is not None:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                count += len(chunk)
                if count > size:
                    raise ValueError("Member larger than its declared size")
                digest.update(chunk)
                window = previous + chunk
                for label, pattern in PATTERNS.items():
                    if pattern.search(window) and {"member": name, "pattern": label} not in secret_findings:
                        # Do not copy a possible credential to the audit output.
                        secret_findings.append({"member": name, "pattern": label})
                previous = window[-8192:]
                if result is not None:
                    if count > 16 * 1024 * 1024:
                        raise ValueError("Formal result exceeds JSON capture bound")
                    result.extend(chunk)
        if count != size:
            unsafe.append({"member": name, "kind": "byte_count_mismatch", "expected": size, "observed": count})
        records[name] = {"bytes": count, "sha256": digest.hexdigest(), "kind": kind}
        if result is not None:
            captured[name] = bytes(result)

    if zipfile.is_zipfile(args.archive):
        archive_format = "zip"
        with zipfile.ZipFile(args.archive) as archive:
            for info in archive.infolist():
                if info.is_dir():
                    continue
                mode = (info.external_attr >> 16) & 0o170000
                kind = "symlink" if mode == 0o120000 else "regular"
                with archive.open(info) as stream:
                    consume(info.filename, info.file_size, stream, kind)
    else:
        archive_format = "tar"
        with tarfile.open(args.archive, "r:*") as archive:
            for info in archive:
                if info.isdir():
                    continue
                if info.isfile():
                    with archive.extractfile(info) as stream:
                        consume(info.name, info.size, stream)
                else:
                    consume(info.name, info.size, None, "link_or_special")

    bindings, errors = {}, []
    for name, expected in required.items():
        found = [mapping[name]] if name in mapping else [key for key in records if key == name or key.endswith("/" + name)]
        if len(found) != 1 or found[0] not in records:
            errors.append({"required": name, "reason": "missing_or_ambiguous_member", "matches": found})
            continue
        member = found[0]
        observed = records[member]
        ok = observed["kind"] == "regular" and all(observed[key] == expected[key] for key in ("bytes", "sha256"))
        bindings[name] = {"member": member, "matches": ok, "expected": expected, "observed": observed}
        if not ok:
            errors.append({"required": name, "reason": "byte_identity_mismatch", "member": member})
    assertions = []
    if formal_key in bindings and bindings[formal_key]["matches"]:
        original = json.loads(captured[bindings[formal_key]["member"]])
        special = {"episodes_count": len(original["episodes"]), "completed_episode_count": sum(row["status"] == "completed" for row in original["episodes"]), "published_episode_count": sum(bool((row.get("publication") or {}).get("published")) for row in original["episodes"])}
        for name, expected in requirements["mandatory_result_assertions"].items():
            observed = pointer(original, name) if name.startswith("/") else special[name]
            assertions.append({"path": name, "expected": expected, "observed": observed, "passed": type(expected) is type(observed) and expected == observed})
    else:
        errors.append({"reason": "exact_formal_result_unavailable_for_negative_assertions"})
    cache_presence = []
    for row in requirements["reproducible_cache_excluded"]["files"]:
        name = str(Path(row["source_path"]).relative_to(WORK))
        if any(member == name or member.endswith("/" + name) for member in records):
            cache_presence.append(name)
    passed = not (errors or unsafe or duplicates or secret_findings or forbidden or cache_presence) and len(assertions) == len(requirements["mandatory_result_assertions"]) and all(x["passed"] for x in assertions)
    report = {
        "schema": "hepta.final-evidence-archive-readonly-audit.v1",
        "status": "PASS_WITH_SCOPE_LIMITS" if passed else "FAIL_OR_REQUIRES_REVIEW",
        "archive": {"path": str(args.archive.resolve()), "bytes": args.archive.stat().st_size, "sha256": file_hash(args.archive), "format": archive_format},
        "requirements_sha256": REQUIREMENTS_SHA,
        "source_scope": {"ndu_formal_source": "8b0fd11dde9f13ac784b3579ec9930ae4832784d", "release_source_expected": "5fead4df11e6157626773ea74c42a59b342f91a6", "historical_requirements_candidate_6b_is_not_a_final_source_assertion": True, "campaign_relabel_allowed": False},
        "required_payload_count": len(requirements["required_files"]), "required_total_with_metadata_and_extra_freezes": len(required), "matched_required_count": sum(x["matches"] for x in bindings.values()),
        "bindings": bindings, "negative_result_assertions": assertions, "cache_exclusion_count": len(requirements["reproducible_cache_excluded"]["files"]), "excluded_cache_members_present": cache_presence,
        "archive_member_hashes": records, "unsafe_members": unsafe, "duplicate_members": duplicates, "missing_or_mismatched": errors, "forbidden_cache_paths": forbidden, "high_confidence_credential_findings": secret_findings,
        "scan_limitations": ["Only named high-confidence byte patterns are scanned; absence is not a proof that arbitrary secrets are absent.", "No nested archive is executed or recursively unpacked; nested archives receive a byte hash and outer byte scan.", "Final-release source qualification is established separately by its source-bound CI and local reports; this audit preserves their included bytes when supplied as extra frozen manifests.", "This is a final package integrity audit, not a new execution or performance measurement."],
        "audit_script_sha256": file_hash(Path(__file__)),
    }
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": report["status"], "required": len(required), "matched": report["matched_required_count"], "errors": len(errors), "output_sha256": file_hash(args.output)}))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
