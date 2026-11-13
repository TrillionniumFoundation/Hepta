"""Preserve two completed Normal Core originals; never import project modules."""
from __future__ import annotations
import base64, gzip, hashlib, io, json, os, pathlib, stat, sys, tarfile, time, urllib.error, urllib.parse, urllib.request, zipfile, zlib
REPOSITORY = "TrillionniumFoundation/Hepta"
API = "https://api.github.com/repos/" + REPOSITORY
TOKEN = os.environ["GH_TOKEN"]
OUT = pathlib.Path(os.environ["RUNNER_TEMP"]) / ("hia-v85-normalcore-custody-" + os.environ["GITHUB_RUN_ID"])
OUT.mkdir(mode=0o700, exist_ok=False)
INPUTS = json.loads(pathlib.Path("inputs/ORIGINALS.json").read_bytes())
ACKS, INTENTS, ENTRIES, RESULTS, CACHE, TREES = [], [], [], [], {}, {}
STAGE = "start"
PREFIX = INPUTS["mount_prefix"]

def require(ok, message):
    if not ok:
        raise ValueError(message)


def wire(value):
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode()


def identity(raw):
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
            "blob": hashlib.sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()}


def save(path, raw):
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as f:
        f.write(raw)
        f.flush()
        os.fsync(f.fileno())


def record(name, value):
    save(OUT / name, wire(value))


def api(path, value=None):
    require(path.startswith(("/git/commits/", "/git/trees/", "/git/blobs/", "/actions/artifacts/", "/actions/runs/"))
            or path == "/git/blobs", "unreviewed API route")
    require(value is None or path == "/git/blobs", "only immutable blob creation is writable")
    request = urllib.request.Request(API + path, data=None if value is None else wire(value),
        method="GET" if value is None else "POST",
        headers={"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json",
                 "X-GitHub-Api-Version": "2022-11-28", "Content-Type": "application/json",
                 "User-Agent": "hia-v84-original-custody"})
    with urllib.request.urlopen(request, timeout=90) as response:
        return json.load(response)


def blob_bytes(sha):
    value = api("/git/blobs/" + sha)
    require(value["sha"] == sha and value["encoding"] == "base64", "blob response differs")
    raw = base64.b64decode("".join(value["content"].split()), validate=True)
    require(identity(raw)["blob"] == sha and len(raw) == value["size"], "blob bytes differ")
    return raw


def publish_text(raw, path):
    """One POST at most. Ambiguous POST failures stop; never replay mutations."""
    raw.decode("utf-8", errors="strict")
    meta = identity(raw)
    ordinal = len(INTENTS)
    intention = {"ordinal": ordinal, "path": path, **meta, "post_replayed": False}
    INTENTS.append(intention)
    record("intent-" + str(ordinal).zfill(4) + ".json", intention)
    existing = False
    try:
        before = blob_bytes(meta["blob"])
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise
    else:
        require(before == raw, "existing immutable blob differs")
        existing = True
    if not existing:
        answer = api("/git/blobs", {"content": raw.decode("utf-8"), "encoding": "utf-8"})
        require(answer["sha"] == meta["blob"], "create ACK differs from local Git hash")
    require(blob_bytes(meta["blob"]) == raw, "complete blob readback differs")
    row = {"ordinal": ordinal, "path": path, **meta, "full_readback": True, "already_existed": existing}
    ACKS.append(row)
    ENTRIES.append({"path": PREFIX + "/" + path, "mode": "100644", "type": "blob", "sha": meta["blob"]})
    record("ack-" + str(ordinal).zfill(4) + ".json", row)
    print(json.dumps({"saved": path, "blob": meta["blob"], "bytes": len(raw), "full_readback": True}), flush=True)
    return meta


def canonical_tree(rows):
    root = {}
    for path, row in rows.items():
        cursor = root
        parts = path.split("/")
        for part in parts[:-1]:
            cursor = cursor.setdefault(part, {})
        require(parts[-1] not in cursor, "tree collision")
        cursor[parts[-1]] = row
    def visit(node):
        records = []
        for name, child in node.items():
            if "blob" in child:
                mode, sha, order = child["mode"], child["blob"], name.encode()
            else:
                mode, sha, order = "40000", visit(child), (name + "/").encode()
            records.append((order, mode.encode() + b" " + name.encode() + b"\0" + bytes.fromhex(sha)))
        raw = b"".join(value for _, value in sorted(records))
        return hashlib.sha1(b"tree " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
    return visit(root)


def git_tree(commit, expected_tree, expected_count):
    if commit in TREES:
        return TREES[commit]
    value = api("/git/commits/" + commit)
    require(value["sha"] == commit and value["tree"]["sha"] == expected_tree, "commit identity differs")
    tree = api("/git/trees/" + expected_tree + "?recursive=1")
    require(tree["sha"] == expected_tree and tree["truncated"] is False, "tree response incomplete")
    rows = {}
    for row in tree["tree"]:
        if row["type"] == "tree":
            continue
        require(row["type"] == "blob" and row["mode"] in ("100644", "100755"), "unreviewed tree entry")
        rows[row["path"]] = {"blob": row["sha"], "mode": row["mode"], "bytes": row["size"]}
    require(len(rows) == expected_count and canonical_tree(rows) == expected_tree, "complete Git tree differs")
    TREES[commit] = rows
    return rows

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def download(item, target):
    authority = api("/actions/artifacts/" + str(item["artifact"]["id"]))
    original = item["artifact"]
    for key in ("id", "name", "size_in_bytes", "digest", "created_at", "expires_at"):
        require(authority[key] == original[key], "artifact authority changed")
    require(authority["expired"] is False, "original artifact expired")
    require(authority["workflow_run"]["id"] == item["run_id"]
            and authority["workflow_run"]["head_sha"] == item["harness_commit"], "artifact run/head differs")
    run = api("/actions/runs/" + str(item["run_id"]))
    require(run["status"] == "completed" and run["head_sha"] == item["harness_commit"], "original run is not terminal at the pinned head")
    req = urllib.request.Request(API + "/actions/artifacts/" + str(original["id"]) + "/zip",
        headers={"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json",
                 "User-Agent": "hia-v84-original-custody"})
    try:
        urllib.request.build_opener(NoRedirect).open(req, timeout=90)
    except urllib.error.HTTPError as redirect:
        require(redirect.code in (301, 302, 303, 307, 308), "artifact did not give its expected download redirect")
        location = redirect.headers["Location"]
    else:
        raise ValueError("unexpected nonredirect artifact response")
    parsed = urllib.parse.urlparse(location)
    require(parsed.scheme == "https" and not parsed.username and not parsed.password, "invalid artifact redirect")
    require(parsed.hostname is not None and
            (parsed.hostname.endswith(".blob.core.windows.net") or
             parsed.hostname.endswith(".githubusercontent.com") or
             parsed.hostname.endswith(".actions.githubusercontent.com") or
             parsed.hostname == "productionresultssa0.blob.core.windows.net"),
            "unreviewed artifact storage host")
    # Authorization is deliberately absent from the storage-host request.
    digest = hashlib.sha256()
    count = 0
    with urllib.request.urlopen(location, timeout=90) as response, target.open("xb") as f:
        while chunk := response.read(1024 * 1024):
            count += len(chunk)
            require(count <= original["size_in_bytes"], "artifact exceeds authority size")
            f.write(chunk)
            digest.update(chunk)
    require(count == original["size_in_bytes"] and "sha256:" + digest.hexdigest() == original["digest"],
            "original outer ZIP identity differs")
    return authority, run, digest.hexdigest()


def zip_inventory(archive):
    rows = {}
    for info in archive.infolist():
        path = pathlib.PurePosixPath(info.filename)
        require(not path.is_absolute() and ".." not in path.parts and info.filename not in rows,
                "unsafe or duplicate ZIP path")
        row = {"crc32": f"{info.CRC:08x}", "zip_mode": oct(info.external_attr >> 16),
               "compressed_bytes": info.compress_size, "compression": info.compress_type,
               "directory": info.is_dir()}
        if not info.is_dir():
            digest, blob = hashlib.sha256(), hashlib.sha1(b"blob " + str(info.file_size).encode() + b"\0")
            size = 0
            with archive.open(info) as f:
                while chunk := f.read(1024 * 1024):
                    digest.update(chunk); blob.update(chunk); size += len(chunk)
            require(size == info.file_size, "ZIP file length differs")
            row.update(bytes=size, sha256=digest.hexdigest(), blob=blob.hexdigest())
        rows[info.filename] = row
    return rows



def file_identity(path):
    size = path.stat().st_size
    sha = hashlib.sha256()
    blob = hashlib.sha1(b"blob " + str(size).encode() + b"\0")
    count = 0
    with path.open("rb") as stream:
        while part := stream.read(1024 * 1024):
            count += len(part); sha.update(part); blob.update(part)
    require(count == size and path.stat().st_size == size, "owned file extent changed")
    return {"bytes": size, "sha256": sha.hexdigest(), "blob": blob.hexdigest()}

def publish_record(value, path):
    raw = wire(value)
    if len(raw) > 350000:
        original = path
        raw = wire({"schema": "hia.lossless-zlib-text-capsule.v1",
                    "original_name": original, **identity(raw),
                    "encoding": "base64(zlib(UTF-8))",
                    "data": base64.b64encode(zlib.compress(raw, 9)).decode("ascii")})
        path += ".zlib.json"
    require(len(raw) <= 900000, "receipt requires an additional explicit chunk index")
    return {"path": path, **publish_text(raw, path)}

def verify_nested(archive, rows, prefix, nested, depth=0):
    require(depth <= 6, "nested ZIP depth exceeds evidence limit")
    for name in sorted(rows):
        if rows[name]["directory"] or not name.lower().endswith(".zip"):
            continue
        raw = archive.read(name)
        require(identity(raw) == {k: rows[name][k] for k in ("bytes", "sha256", "blob")},
                "nested container readback differs")
        key = prefix + name
        if not zipfile.is_zipfile(io.BytesIO(raw)):
            nested[key] = {"container": rows[name], "recognized_zip": False,
                           "opaque_original_bytes_preserved": True}
            continue
        with zipfile.ZipFile(io.BytesIO(raw)) as child:
            members = zip_inventory(child)
            value = {"container": rows[name], "recognized_zip": True, "members": members}
            if "HIA_ARCHIVE_MANIFEST.json" in members:
                manifest_raw = child.read("HIA_ARCHIVE_MANIFEST.json")
                manifest = json.loads(manifest_raw)
                expected = manifest["files"]
                require(set(members) == set(expected) | {"HIA_ARCHIVE_MANIFEST.json"},
                        "nested original member set differs")
                for path, wanted in expected.items():
                    row = members[path]
                    require(row["bytes"] == wanted["bytes"] and row["sha256"] == wanted["sha256"]
                            and stat.S_IMODE(int(row["zip_mode"], 8)) == wanted["mode"],
                            "nested original member bytes or mode differ")
                require(sum(x["bytes"] for x in expected.values()) == manifest["unpacked_bytes"],
                        "nested original total differs")
                value.update(original_manifest=manifest,
                             original_manifest_identity=identity(manifest_raw))
            nested[key] = value
            verify_nested(child, members, key + "::", nested, depth + 1)

def cold_source_bindings(item, archive, rows, git_rows):
    cold_raw = archive.read("hia-cold.json")
    cold = json.loads(cold_raw)
    require(cold["schema"] == "hepta.hia.selfhost-cold-replay.v1", "unexpected cold report schema")
    require(cold["qualification_wall_limit_seconds"] == 180 and cold["cleanup_wall_limit_seconds"] == 3,
            "original 180+3 limits differ")
    require(type(cold["checks"]) is dict and len(cold["checks"]) == 11 and all(type(x) is bool for x in cold["checks"].values()),
            "cold checks are not strict booleans")
    request = json.loads(archive.read("hia-cold.cold/request.json"))
    require(request["source_manifest"] == cold["source_manifest"], "cold request/report source mismatch")
    source_prefix = "hia-cold.cold/source/"
    source_rows = {p[len(source_prefix):]: r for p, r in rows.items()
                   if p.startswith(source_prefix) and not r["directory"]}
    require(set(source_rows) == set(cold["source_manifest"]), "actual cold export set differs")
    contract_path = "docs/HIA_SELFHOST_CORE_SUPPORT.json"
    contract = json.loads(archive.read(source_prefix + contract_path))
    expected = dict(contract["source_identity"]["files"])
    expected[contract_path] = rows[source_prefix + contract_path]["sha256"]
    require(expected == cold["source_manifest"], "frozen support contract/source export mismatch")
    bindings = {}
    for name, row in source_rows.items():
        wanted = git_rows[name]
        require(row["bytes"] == wanted["bytes"] and row["blob"] == wanted["blob"]
                and row["sha256"] == cold["source_manifest"][name],
                "actual cold export differs from pinned Git source")
        bindings[source_prefix + name] = {
            "repository": REPOSITORY, "commit": item["source_commit"],
            "tree": item["source_tree"], "path": name,
            "blob": row["blob"], "bytes": row["bytes"], "sha256": row["sha256"],
            "git_mode": wanted["mode"], "zip_mode": row["zip_mode"],
            "mode_boundary": "ZIP transport mode is retained separately from original Git source mode"}
    return cold, bindings

def read_cold_authority(item, archive, rows, nested, cold, bindings):
    owner_raw = archive.read("hia-cold.cold/process-owner.json")
    owner = json.loads(owner_raw)
    embedded = cold["process_owner"]
    require(embedded.get("receipt_sha256") == hashlib.sha256(owner_raw).hexdigest()
            and all(embedded.get(k) == v for k, v in owner.items()),
            "cold process-owner receipt mismatch")
    prefix = "hia-cold.cold/qualification.evidence/"
    phases, pending, references, unconsumed = [], {}, {}, None
    process_names = sorted(n for n in rows if n.startswith(prefix + "phase-")
                           and n.count("/") == 2 and n.endswith(".process.json"))
    for name in process_names:
        process = json.loads(archive.read(name))
        stem = name[len(prefix + "phase-"):-len(".process.json")]
        report_name = prefix + "phase-" + stem + ".json"
        phase = None
        if report_name in rows:
            raw = archive.read(report_name)
            if process.get("report_sha256") is not None:
                require(hashlib.sha256(raw).hexdigest() == process["report_sha256"],
                        "phase report hash differs")
            phase = json.loads(raw)
        packed_name = prefix + "phase-runs/" + stem + ".zip"
        if "raw_artifacts" in process:
            packed, custody = nested[packed_name], process["raw_artifacts"]
            require(packed.get("recognized_zip") is True and "original_manifest" in packed,
                    "receipted phase ZIP lacks its full original manifest")
            require(custody["archive_sha256"] == rows[packed_name]["sha256"]
                    and custody["packed_bytes"] == rows[packed_name]["bytes"]
                    and custody["manifest_sha256"] == packed["original_manifest_identity"]["sha256"]
                    and custody["files"] == len(packed["original_manifest"]["files"])
                    and custody["unpacked_bytes"] == packed["original_manifest"]["unpacked_bytes"],
                    "phase original archive custody differs")
        phases.append({"key": stem, "process": process,
                       "process_identity": rows[name],
                       "phase_report_identity": rows.get(report_name),
                       "phase_report_status": None if phase is None else phase.get("status"),
                       "archive_identity": rows.get(packed_name),
                       "direct_originals": {n: r for n, r in rows.items()
                                            if n.startswith(prefix + "phase-runs/" + stem + "/")}})
    completed = {p["key"] for p in phases if p["process"].get("returncode") == 0
                 and p["phase_report_identity"] is not None}
    for name in sorted(rows):
        if name.startswith(prefix + "phase-") and name.count("/") == 2 and name.endswith(".request.json"):
            stem = name[len(prefix + "phase-"):-len(".request.json")]
            if stem not in completed:
                pending[stem] = {"request": json.loads(archive.read(name)),
                                 "partial_originals": {n: r for n, r in rows.items()
                                                      if n.startswith(prefix + "phase-runs/" + stem + "/")}}
        if name.startswith(prefix + "reference-") and name.count("/") == 2 and name.endswith(".worker.json"):
            envelope = json.loads(archive.read(name))
            reference_raw = json.dumps(envelope["reference"], sort_keys=True, separators=(",", ":")).encode()
            manifest_raw = json.dumps(cold["source_manifest"], sort_keys=True, separators=(",", ":")).encode()
            require(envelope["schema"] == "hepta.hia.selfhost-independent-reference-process.v1"
                    and envelope["before_B0"] is True
                    and type(envelope["worker_pid"]) is int and envelope["worker_pid"] > 0
                    and type(envelope["reference"]) is dict
                    and hashlib.sha256(reference_raw).hexdigest() == envelope["reference_sha256"]
                    and hashlib.sha256(manifest_raw).hexdigest() == envelope["source_manifest_sha256"]
                    and envelope["family"] not in references,
                    "original independent reference complete payload/source mismatch")
            references[envelope["family"]] = {"member": name, "identity": rows[name], "envelope": envelope}
    qualification = None
    qname = "hia-cold.cold/qualification.json"
    if qname in rows:
        raw = archive.read(qname)
        if cold.get("nested_report_sha256") is not None:
            require(hashlib.sha256(raw).hexdigest() == cold["nested_report_sha256"],
                    "admitted final qualification report identity differs")
            qualification = json.loads(raw)
        else:
            unconsumed = {"identity": rows[qname],
                          "reason": "Original cold owner did not admit this report; raw bytes preserved, not promoted."}
    images = {label: rows.get(prefix + label + ".image.bin")
              for label in ("B0", "B1", "B2", "B3", "M1", "M2", "M3")}
    if cold["status"] == "COLD_SELFHOST_REPLAY_PASS":
        require(type(cold["returncode"]) is int and cold["returncode"] == 0 and all(v is True for v in cold["checks"].values())
                and qualification is not None and not pending
                and owner["timed_out"] is False and owner["cleanup"]["complete"] is True
                and owner["exit_observed_before_deadline"] is True
                and owner["status"] == "OWNED_PROCESS_COMPLETED",
                "cold success lacks complete original deadline/cleanup authority")
        require(qualification["status"] == "SELF_HOSTED_FIXED_CORE_PASS"
                and qualification["checks"] and all(type(v) is bool and v for v in qualification["checks"].values())
                and qualification["source_manifest"] == cold["source_manifest"],
                "nested qualification checks/source mismatch")
        scheduling = qualification["qualification_scheduling"]
        require(set(scheduling["phase_inventory"]) == completed
                and len(scheduling["phase_inventory"]) == len(phases)
                and {r["family"] + "-" + r["compiler_label"]: r for r in scheduling["phases"]}
                    == {r["key"]: r["process"] for r in phases}
                and all(type(p["process"]["returncode"]) is int and p["process"]["returncode"] == 0
                        and p["phase_report_status"] == "PASS" and p["archive_identity"] is not None for p in phases),
                "nested complete phase inventory/receipts mismatch")
        require([images[k]["sha256"] for k in ("B1", "B2", "B3")] == cold["generation_sha256"]
                and [images[k]["sha256"] for k in ("M1", "M2", "M3")] == cold["modified_generation_sha256"]
                and [g["produced_sha256"] for g in qualification["generations"]] == cold["generation_sha256"]
                and [g["produced_sha256"] for g in qualification["modified_generations"]] == cold["modified_generation_sha256"],
                "retained B/M images do not match admitted generation records")
    summary = {
        "schema": "hia.normal-core-original-byte-verification.v1",
        "verification_status": "ORIGINAL_BYTES_AND_AVAILABLE_AUTHORITY_VERIFIED",
        "source_commit": item["source_commit"], "source_tree": item["source_tree"],
        "full_git_source_files": item["source_files"], "actual_cold_export_files": len(bindings),
        "full_git_tree_present_in_artifact": len(bindings) == item["source_files"],
        "cold_status": cold["status"], "checks": cold["checks"],
        "cold_checks_passed": sum(cold["checks"].values()), "cold_checks_total": len(cold["checks"]),
        "cold_wall_elapsed_ns": cold["wall_elapsed_ns"], "cold_limits": {"qualification": 180, "cleanup": 3},
        "owner": owner, "phase_processes": len(phases),
        "phase_archives": sum(p["archive_identity"] is not None for p in phases),
        "completed_phases": sorted(completed), "pending_phases": sorted(pending),
        "reference_workers": len(references), "actual_generation_images": images,
        "admitted_final_qualification_present": qualification is not None,
        "unconsumed_final_report": unconsumed,
        "final_qualification_status": None if qualification is None else qualification["status"],
        "final_qualification_checks": None if qualification is None else len(qualification["checks"]),
        "original_business_result_reclassified": False, "business_reexecuted": False,
        "new_qualification": False, "whole_native_inferred": False}
    return summary, {"cold": cold, "owner": owner, "phases": phases, "pending": pending,
                     "references": references, "qualification": qualification}

def verify_original_business_reports(archive, rows):
    # Preserve both full reports and exact text originals in the content pool.
    # This projection is descriptive; all nested failure reports remain raw.
    result = {}
    for name in sorted(rows):
        if rows[name]["directory"] or not name.endswith((".json", ".log", ".txt")):
            continue
        if name.endswith(".json") and rows[name]["bytes"] <= 16 * 1024 * 1024:
            try:
                value = json.loads(archive.read(name))
            except (UnicodeError, json.JSONDecodeError):
                continue
            if isinstance(value, dict) and any(k in value for k in ("tests_run", "testsRun", "status", "checks", "returncode")):
                result[name] = {"identity": rows[name],
                                "observation": {k: value[k] for k in
                                ("schema", "status", "tests_run", "testsRun", "returncode",
                                 "elapsed_ns", "seconds", "timed_out", "failures", "errors",
                                 "skips", "skipped", "expected_failures", "unexpected_successes",
                                 "source_and_inputs_unchanged", "actual_machine_returns")
                                if k in value}}
    return result

def make_pool(item, archive, rows, nested, bindings, git_rows, observations, authority):
    # Source references are allowed only after complete actual Git-byte binding.
    objects, logical = {}, {}
    for name, row in rows.items():
        if row["directory"]:
            logical[name] = {"original": row, "storage": "directory-metadata"}
        elif name in bindings:
            logical[name] = {"original": row, "storage": "external-exact-git-source",
                             "external": bindings[name]}
        else:
            key = row["sha256"]
            if key in objects:
                require(all(objects[key]["identity"][k] == row[k] for k in ("bytes", "sha256", "blob")),
                        "content key collision")
            else:
                objects[key] = {"representative": name, "identity": row}
            logical[name] = {"original": row, "storage": "pool-object", "object": "objects/" + key + ".bin"}
    recovery = {
        "schema": "hia.normal-core-original-content-pool.v1", "key": item["key"],
        "original_artifact": item["artifact"], "run_id": item["run_id"],
        "source_commit": item["source_commit"], "source_tree": item["source_tree"],
        "original_outer_zip_reconstructed": False,
        "original_outer_bytes_retained_in": "Actions original artifact, exact ID/digest/retention above",
        "all_original_logical_members_recoverable": True,
        "all_original_nested_zip_bytes_unchanged": True,
        "logical_members": logical, "nested_archives": nested,
        "exact_git_tree": git_rows, "verification": observations, "authority": authority,
        "external_source_references": len(bindings),
        "unique_pool_objects": len(objects),
        "qualification_transferred": False
    }
    recovery_raw = wire(recovery)
    target = OUT / (item["key"] + "-CONTENT-POOL.tar.gz")
    expected_objects = {name: {"bytes": len(recovery_raw), "sha256": hashlib.sha256(recovery_raw).hexdigest()}
                        for name in ("RECOVERY.json",)}
    with target.open("xb") as file:
        with gzip.GzipFile(filename="", mode="wb", fileobj=file, compresslevel=6, mtime=0) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as packed:
                header = tarfile.TarInfo("RECOVERY.json"); header.size=len(recovery_raw); header.mode=0o644; header.mtime=0
                packed.addfile(header, io.BytesIO(recovery_raw))
                for key, value in sorted(objects.items()):
                    raw = archive.read(value["representative"])
                    require(identity(raw) == {k: value["identity"][k] for k in ("bytes", "sha256", "blob")},
                            "original changed while pooling")
                    name = "objects/" + key + ".bin"
                    header = tarfile.TarInfo(name); header.size=len(raw); header.mode=0o644; header.mtime=0
                    packed.addfile(header, io.BytesIO(raw))
                    expected_objects[name] = {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
    tar_sha = hashlib.sha256(); tar_bytes = 0
    with gzip.open(target, "rb") as stream:
        while part := stream.read(1024 * 1024):
            tar_sha.update(part); tar_bytes += len(part)
    seen = {}
    with tarfile.open(target, "r:gz") as packed:
        for member in packed:
            require(member.isfile() and member.name not in seen and member.mode == 0o644,
                    "derived pool path/type/mode differs")
            reader = packed.extractfile(member)
            sha = hashlib.sha256(); size = 0
            while part := reader.read(1024 * 1024):
                sha.update(part); size += len(part)
            seen[member.name] = {"bytes": size, "sha256": sha.hexdigest()}
    require(seen == expected_objects, "complete derived pool readback differs")
    return target, {"logical_members": len(logical), "external_source_references": len(bindings),
                    "unique_pool_objects": len(objects), "pool_members": len(seen),
                    "complete_decompression_and_member_hashes_verified": True,
                    "complete_gzip_crc_verified": True,
                    "tar_stream_bytes": tar_bytes, "tar_stream_sha256": tar_sha.hexdigest(),
                    "recovery_manifest": identity(recovery_raw)}

def publish_pool(path, item, pool_report):
    meta = file_identity(path)
    chunks = []
    name = item["key"] + "/CONTENT-POOL.tar.gz"
    offset = 0
    with path.open("rb") as stream:
        while part := stream.read(512 * 1024):
            number = len(chunks)
            value = {"schema": "hia.lossless-archive-chunk.v1", "archive_name": name,
                     "archive_bytes": meta["bytes"], "archive_sha256": meta["sha256"],
                     "index": number, "offset": offset, "bytes": len(part),
                     "sha256": hashlib.sha256(part).hexdigest(),
                     "encoding": "base64", "data": base64.b64encode(part).decode("ascii")}
            ref = publish_text(wire(value), item["key"] + "/chunk-" + str(number).zfill(3) + ".json")
            chunks.append({"index": number, "offset": offset, "bytes": len(part),
                           "sha256": value["sha256"], "wrapper": ref})
            offset += len(part)
    require(offset == meta["bytes"] and file_identity(path) == meta, "pooled archive changed during publication")
    index = {"schema": "hia.lossless-original-content-pool-index.v1", "archive": meta,
             "archive_name": name, "chunks": chunks, "original": item,
             "pool_verification": pool_report, "all_published": True,
             "all_wrappers_full_readback": True, "ordered_offsets_complete": True,
             "archive_blob_is_computed_identity_only": True,
             "raw_binary_git_blob_separately_uploaded": False,
             "original_outer_zip_reconstructed": False,
             "original_nested_zip_bytes_repacked": False,
             "qualification_transferred": False}
    ref = publish_record(index, item["key"] + "/INDEX.json")
    return meta, ref

def collect(item):
    global STAGE
    STAGE = item["key"] + ":download"
    target = OUT / (item["key"] + "-original-artifact.zip")
    artifact, run, outer_sha = download(item, target)
    jobs = api("/actions/runs/" + str(item["run_id"]) + "/jobs?filter=latest&per_page=100&page=1")
    require(jobs["total_count"] == len(jobs["jobs"]), "original jobs response truncated")
    actual_jobs = {j["id"]: j for j in jobs["jobs"]}
    require(actual_jobs[item["native_job_id"]]["status"] == "completed"
            and actual_jobs[item["native_job_id"]]["conclusion"] == item["expected_original_native_conclusion"]
            and actual_jobs[item["source_job_id"]]["status"] == "completed"
            and actual_jobs[item["source_job_id"]]["conclusion"] == item["expected_original_source_conclusion"],
            "pinned original job conclusion changed")
    STAGE = item["key"] + ":git-and-crc"
    git_rows = git_tree(item["source_commit"], item["source_tree"], item["source_files"])
    authority = {"artifact": artifact, "run": run, "jobs": jobs,
                 "original_outer": {"bytes": target.stat().st_size, "sha256": outer_sha}}
    direct = {}
    for label, blob in item.get("log_anchors", {}).items():
        raw = blob_bytes(blob)
        direct["original-" + label + "-job.log"] = publish_text(raw, item["key"] + "/original-" + label + "-job.log")
    with zipfile.ZipFile(target) as archive:
        rows = zip_inventory(archive)
        nested = {}
        verify_nested(archive, rows, "", nested)
        print(json.dumps({"original": item["key"], "outer_crc_members": len(rows),
                          "nested_archives": len(nested),
                          "nested_crc_members": sum(len(v.get("members", {})) for v in nested.values())}), flush=True)
        STAGE = item["key"] + ":source-binding"
        cold, bindings = cold_source_bindings(item, archive, rows, git_rows)
        STAGE = item["key"] + ":original-cold-authority"
        summary, detailed = read_cold_authority(item, archive, rows, nested, cold, bindings)
        summary.update(outer_members=len(rows), nested_archives=len(nested),
                       nested_members=sum(len(v.get("members", {})) for v in nested.values()),
                       all_original_outer_and_recognized_nested_crc_sha_git_checked=True,
                       recognized_nested_zip_count=sum(v.get("recognized_zip") is True for v in nested.values()),
                       original_native_job_conclusion=actual_jobs[item["native_job_id"]]["conclusion"],
                       original_source_job_conclusion=actual_jobs[item["source_job_id"]]["conclusion"])
        observations = {"summary": summary, "cold_authority": detailed,
                        "original_report_observations": verify_original_business_reports(archive, rows)}
        direct["VERIFICATION.json"] = publish_record(summary, item["key"] + "/VERIFICATION.json")
        direct["ORIGINAL-COLD.json"] = publish_record(cold, item["key"] + "/ORIGINAL-COLD.json")
        direct["ORIGINAL-OWNER.json"] = publish_record(detailed["owner"], item["key"] + "/ORIGINAL-OWNER.json")
        if detailed["qualification"] is not None:
            direct["ORIGINAL-QUALIFICATION.json"] = publish_record(detailed["qualification"], item["key"] + "/ORIGINAL-QUALIFICATION.json")
        direct["PHASES-AND-REFERENCES.json"] = publish_record(
            {"phases": detailed["phases"], "pending": detailed["pending"],
             "reference_worker_identities": {k: {"member": v["member"], "identity": v["identity"]}
                                            for k, v in detailed["references"].items()}},
            item["key"] + "/PHASES-AND-REFERENCES.json")
        direct["SOURCE-BINDINGS.json"] = publish_record(bindings, item["key"] + "/SOURCE-BINDINGS.json")
        direct["AUTHORITY.json"] = publish_record(authority, item["key"] + "/AUTHORITY.json")
        print(json.dumps({"original": item["key"], "cold_status": summary["cold_status"],
                          "cold_checks": [summary["cold_checks_passed"], summary["cold_checks_total"]],
                          "cold_elapsed_ns": summary["cold_wall_elapsed_ns"],
                          "cold_export_files": len(bindings), "pending_phases": summary["pending_phases"],
                          "business_result_unchanged": True}), flush=True)
        STAGE = item["key"] + ":lossless-content-pool"
        path, pool_report = make_pool(item, archive, rows, nested, bindings, git_rows, observations, authority)
    require(file_identity(target)["sha256"] == outer_sha, "original outer changed after inspection")
    STAGE = item["key"] + ":immutable-publication"
    meta, index = publish_pool(path, item, pool_report)
    RESULTS.append({"key": item["key"], "original_run_id": item["run_id"],
                    "original_native_conclusion": actual_jobs[item["native_job_id"]]["conclusion"],
                    "original_cold_status": cold["status"], "original_artifact": artifact,
                    "archive": meta, "index": index, "receipts": direct,
                    "source_commit": item["source_commit"], "source_tree": item["source_tree"],
                    "all_logical_original_members_recoverable": True,
                    "outer_zip_bytes_in_git": False, "nested_zip_original_bytes_preserved": True})
    record(item["key"] + "-COMPLETE.json", RESULTS[-1])
    STAGE = item["key"] + ":complete"

def main():
    global STAGE
    before = {str(p): identity(p.read_bytes()) for p in sorted(pathlib.Path(".").rglob("*"))
              if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts}
    require(os.environ["GITHUB_REPOSITORY"] == REPOSITORY, "repository differs")
    record("CUSTODIAN-SOURCE-BEFORE.json", before)
    success = False
    try:
        for item in INPUTS["originals"]:
            collect(item)
        success = True
    except BaseException as error:
        record("FAILURE.json", {"stage": STAGE, "error_type": type(error).__name__,
                               "http_code": getattr(error, "code", None),
                               "detail": str(error) if isinstance(error, (ValueError, KeyError, AssertionError)) else "Transport or runtime failure; no credential or signed URL is logged.",
                               "original_results_reclassified": False})
    finally:
        after = {str(p): identity(p.read_bytes()) for p in sorted(pathlib.Path(".").rglob("*"))
                 if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts}
        unchanged = before == after
        final = {"schema": "hia.normal-core-evidence-custody-complete-or-partial.v1",
                 "status": "CUSTODY_COMPLETE" if success and unchanged else "CUSTODY_INCOMPLETE",
                 "expected_originals": len(INPUTS["originals"]), "completed_originals": RESULTS,
                 "last_stage": STAGE, "intents": INTENTS, "acks": ACKS, "entries": ENTRIES,
                 "custodian_source_unchanged": unchanged,
                 "unpreserved_originals": [x["key"] for x in INPUTS["originals"] if x["key"] not in {r["key"] for r in RESULTS}],
                 "actual_custodian_commit": os.environ["GITHUB_SHA"], "actual_custodian_run": os.environ["GITHUB_RUN_ID"],
                 "product_execution": False, "compiler_execution": False, "tests_execution": False,
                 "old_results_reclassified": False, "product_or_audit_refs_changed": False,
                 "whole_native": False}
        record("FINAL.json", final)
        try:
            ref = publish_text(wire(final), "FINAL.json")
            print(json.dumps({"custody_status": final["status"], "manifest_blob": ref["blob"],
                              "bytes": ref["bytes"], "sha256": ref["sha256"]}), flush=True)
        except BaseException as error:
            record("FINAL-PUBLISH-FAILURE.json", {"stage": STAGE, "error_type": type(error).__name__})
            success = False
        return 0 if success and unchanged else 1

if __name__ == "__main__":
    raise SystemExit(main())
