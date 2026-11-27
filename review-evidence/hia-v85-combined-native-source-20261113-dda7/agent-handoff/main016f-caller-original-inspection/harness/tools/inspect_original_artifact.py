"""Inspect one immutable original Actions artifact, without product execution."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = Path(os.environ["RUNNER_TEMP"]) / "original-artifact-inspection"
FILES = (".github/workflows/original-artifact-inspection.yml",
         "inputs/ORIGINAL.json", "tools/inspect_original_artifact.py", "README.md")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, new_url):
        return None


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def save(name, value):
    raw = (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False) + "\n").encode()
    (OUT / name).write_bytes(raw)


def require(value, message):
    if not value:
        raise ValueError(message)


def get_api(path, token):
    url = "https://api.github.com" + path
    request = urllib.request.Request(url, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            return json.load(response)
    except urllib.error.HTTPError as error:
        raise RuntimeError("GitHub API read returned status " + str(error.code)) from None


def download_original(path, token, target, expected_size):
    # GitHub authentication is never forwarded to the signed storage URL.
    request = urllib.request.Request("https://api.github.com" + path, headers={
        "Authorization": "Bearer " + token,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })
    try:
        urllib.request.build_opener(NoRedirect()).open(request, timeout=60)
    except urllib.error.HTTPError as response:
        require(response.code in (301, 302, 303, 307, 308),
                "original artifact download did not return its storage redirect")
        location = response.headers.get("Location")
    else:
        raise ValueError("original artifact endpoint unexpectedly returned direct content")
    require(type(location) is str and urllib.parse.urlparse(location).scheme == "https",
            "original artifact redirect is not HTTPS")
    digest, size = hashlib.sha256(), 0
    # Fresh unauthenticated request; neither the URL nor headers are logged.
    with urllib.request.urlopen(urllib.request.Request(location), timeout=60) as response:
        with target.open("xb") as output:
            while True:
                chunk = response.read(1 << 20)
                if not chunk:
                    break
                size += len(chunk)
                require(size <= expected_size, "original ZIP exceeds recorded size")
                output.write(chunk)
                digest.update(chunk)
    require(size == expected_size, "original ZIP size differs")
    return {"bytes": size, "sha256": digest.hexdigest()}


def snapshot():
    return {name: {"bytes": (ROOT / name).stat().st_size,
                   "sha256": sha((ROOT / name).read_bytes())} for name in FILES}


def main():
    OUT.mkdir(mode=0o700, parents=False, exist_ok=False)
    fixed = json.loads((ROOT / "inputs/ORIGINAL.json").read_bytes())
    before = snapshot()
    started = time.monotonic()
    result = {
        "schema": fixed["schema"], "status": "STARTED", "input": fixed,
        "harness_commit": os.environ.get("GITHUB_SHA"),
        "source_before": before, "product_executions": 0, "test_reruns": 0,
        "qualification_claimed": False, "ref_mutations": 0,
        "outer_raw_reuploaded": False,
        "original_outer_custody": "Original Actions artifact; this job retains member observations and exact matched targets only.",
    }
    try:
        token = os.environ["GITHUB_TOKEN"]
        base = "/repos/" + fixed["repository"]
        run = get_api(base + "/actions/runs/" + str(fixed["original_run"]), token)
        job = get_api(base + "/actions/jobs/" + str(fixed["original_job"]), token)
        artifact = get_api(base + "/actions/artifacts/" + str(fixed["artifact"]["id"]), token)
        save("ORIGINAL-RUN.json", run)
        save("ORIGINAL-JOB.json", job)
        save("ORIGINAL-ARTIFACT.json", artifact)
        require(type(run["id"]) is int and run["id"] == fixed["original_run"],
                "original run ID differs")
        require(run["head_sha"] == fixed["original_head"]
                and run["run_attempt"] == fixed["original_attempt"]
                and run["status"] == "completed"
                and run["conclusion"] == fixed["original_conclusion"],
                "original run head/attempt/terminal state differs")
        require(job["id"] == fixed["original_job"] and job["run_id"] == run["id"]
                and job["status"] == "completed"
                and job["conclusion"] == fixed["original_conclusion"],
                "original job binding or terminal differs")
        for name in ("id", "name", "size_in_bytes", "digest"):
            require(artifact[name] == fixed["artifact"][name],
                    "original artifact identity differs: " + name)
        require(artifact["expired"] is False and type(artifact["size_in_bytes"]) is int,
                "original artifact is unavailable or size is malformed")
        require(artifact["workflow_run"]["id"] == run["id"]
                and artifact["workflow_run"]["head_sha"] == run["head_sha"],
                "original artifact run/head differs")
        zip_path = Path(os.environ["RUNNER_TEMP"]) / "original-016f-artifact.zip"
        outer = download_original(base + "/actions/artifacts/" + str(artifact["id"]) + "/zip",
                                  token, zip_path, artifact["size_in_bytes"])
        require("sha256:" + outer["sha256"] == artifact["digest"],
                "original ZIP full digest differs")
        result["outer"] = outer
        rows, matches, targets, seen = [], [], [], set()
        with zipfile.ZipFile(zip_path) as archive:
            for info in archive.infolist():
                require(info.filename not in seen, "original ZIP has duplicate member names")
                seen.add(info.filename)
                digest, size = hashlib.sha256(), 0
                target = next((name for name in fixed["target_files"]
                               if info.filename == name or info.filename.endswith("/" + name)), None)
                chunks = [] if target is not None else None
                with archive.open(info) as stream:
                    while True:
                        chunk = stream.read(1 << 20)
                        if not chunk:
                            break
                        size += len(chunk)
                        digest.update(chunk)
                        if chunks is not None:
                            chunks.append(chunk)
                require(size == info.file_size, "original member size differs")
                row = {"name": info.filename, "bytes": size,
                       "compressed_bytes": info.compress_size, "crc32": info.CRC,
                       "sha256": digest.hexdigest(), "external_attr": info.external_attr,
                       "mode": (info.external_attr >> 16) & 0xffff,
                       "compression_type": info.compress_type, "directory": info.is_dir()}
                rows.append(row)
                parts = info.filename.rstrip("/").split("/")
                if fixed["target_directory"] in parts:
                    matches.append(row)
                if target is not None:
                    raw = b"".join(chunks)
                    name = "matched-" + str(len(targets)) + "-" + target.rsplit("/", 1)[1]
                    (OUT / name).write_bytes(raw)
                    targets.append({**row, "exact_target": target, "retained_as": name})
        save("COMPLETE-OUTER-MEMBERS.json", rows)
        save("TARGET-DIRECTORY-MEMBERS.json", matches)
        save("EXACT-TARGETS.json", targets)
        result.update(
            status="ORIGINAL_ARTIFACT_INSPECTION_COMPLETE",
            outer_crc_all_members_pass=True, outer_member_count=len(rows),
            target_directory_member_count=len(matches), exact_targets=targets,
            target_report_available=any(row["exact_target"].endswith("/report.json")
                                        for row in targets),
            target_log_available=any(row["exact_target"].endswith("/tests.log")
                                     for row in targets),
            target_directory_observation=("PRESENT" if matches else
                                          "ABSENT_FROM_ORIGINAL_ARTIFACT"),
            nested_archives_validated=False,
            original_caller_outcome_unchanged="FAIL; 130 executed; original summary only unless exact targets are present",
        )
    except BaseException as error:
        # Never stringify an HTTP/URL exception: it can include a signed URL.
        result["status"] = "INSPECTION_FAILED"
        result["failure_type"] = type(error).__name__
        result["failure_message"] = (str(error) if isinstance(error, ValueError) else
                                     "read-only inspection did not complete; inspect preserved stage metadata")
    finally:
        after = snapshot()
        result["source_after"] = after
        result["harness_source_unchanged"] = before == after
        result["seconds"] = time.monotonic() - started
        if before != after:
            result["status"] = "INSPECTION_FAILED"
            result["source_failure"] = "harness sources changed"
        save("REPORT.json", result)
    print(json.dumps({name: result.get(name) for name in (
        "status", "outer_member_count", "target_directory_observation",
        "target_report_available", "target_log_available", "harness_source_unchanged")}))
    return 0 if result["status"] == "ORIGINAL_ARTIFACT_INSPECTION_COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
