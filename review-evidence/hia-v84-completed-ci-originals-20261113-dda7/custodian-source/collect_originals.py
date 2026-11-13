"""Read and retain completed originals only; never imports the product."""
from __future__ import annotations
import base64, hashlib, io, json, os, pathlib, stat, sys, time, urllib.error, urllib.parse, urllib.request, zipfile, zlib

REPOSITORY = "TrillionniumFoundation/Hepta"
API = "https://api.github.com/repos/" + REPOSITORY
TOKEN = os.environ["GH_TOKEN"]
OUT = pathlib.Path(os.environ["RUNNER_TEMP"]) / ("hia-v84-terminal-custody-" + os.environ["GITHUB_RUN_ID"])
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

def expected_harness(item):
    key = item["harness_commit"]
    if key in CACHE:
        return CACHE[key]
    expected = INPUTS["harnesses"][key]
    rows = git_tree(key, expected["tree"], len(expected["files"]))
    result = {}
    require(set(rows) == set(expected["files"]), "harness path inventory differs")
    for name, row in expected["files"].items():
        require({k: row[k] for k in ("blob", "mode", "bytes")} == rows[name], "harness tree row differs")
        raw = blob_bytes(row["blob"])
        require(identity(raw) == {k: row[k] for k in ("blob", "bytes", "sha256")}, "harness file bytes differ")
        result[name] = {k: row[k] for k in ("blob", "bytes", "sha256")}
    CACHE[key] = result
    return result

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

def normalized(rows):
    return {name: {"bytes": row["bytes"], "sha256": row["sha256"],
                   "blob": row.get("blob", row.get("git_blob_sha")),
                   "mode": row.get("mode", row.get("git_mode"))} for name, row in rows.items()}

def source_from_archive(item, outer, inner_name, original_report, inner):
    commit, tree, count = item["source_commit"], item["source_tree"], item["source_files"]
    expected = git_tree(commit, tree, count)
    if item["kind"] == "four-profile":
        prefix = inner_name.removesuffix("COMPLETE-RAW.zip") + "source/"
        actual = {}
        for name, row in outer.items():
            if name.startswith(prefix) and not row["directory"]:
                actual[name[len(prefix):]] = {k: row[k] for k in ("bytes", "sha256", "blob")}
                actual[name[len(prefix):]]["mode"] = "100755" if int(row["zip_mode"], 8) & 0o111 else "100644"
        require({p: {k:r[k] for k in ("bytes", "blob", "mode")} for p,r in actual.items()} == expected,
                "outer source differs from actual immutable Git tree")
        require(canonical_tree(actual) == tree, "outer source tree recomputation differs")
        require(normalized(original_report["source_manifest"]) == actual,
                "original authored source record differs from outer bytes")
        if original_report["profile"] in ("native314", "evaluation314"):
            require(normalized(original_report["generated_source_manifest"]) == actual,
                    "original generated source record differs from outer bytes")
        else:
            require(original_report["profile"] in ("default311", "source314")
                    and "generated_source_manifest" not in original_report,
                    "unexpected original source-report schema")
        require(normalized(json.loads(inner.read("FINAL-SOURCE.json"))) == actual, "original source-after differs")
        require(original_report["harness_inputs_unchanged"] is True
                and original_report["final_inputs_and_source_unchanged"] is True,
                "original harness/source integrity report failed")
        require(original_report["original_compiler_limit_seconds"] == 20
                and original_report["original_work_limit_seconds"] == 1800, "original limits differ")
        CACHE["source:" + commit] = actual
    else:
        reference = CACHE["source:" + INPUTS["a733_source_commit"]]
        actual = {}
        for path, row in expected.items():
            cached = reference.get(path)
            if cached is not None and all(cached[k] == row[k] for k in ("bytes", "blob", "mode")):
                actual[path] = cached
            else:
                actual[path] = {**identity(blob_bytes(row["blob"])), "mode": row["mode"]}
        require(normalized(json.loads(inner.read("GENERATED-SOURCE.json"))) == actual
                and normalized(json.loads(inner.read("SOURCE-AFTER.json"))) == actual,
                "diagnostic source before/after differs from immutable Git")
        require(original_report["source_unchanged"] is True
                and original_report["harness_inputs_unchanged"] is True
                and original_report["authentic_head_unchanged"] is True
                and original_report["retained_compiler_unchanged"] is True, "diagnostic input preservation failed")
        require(json.loads(inner.read("HARNESS-INPUTS.json")) == expected_harness(item),
                "diagnostic retained harness bytes differ")
    return actual

def publish_archive(raw, item):
    name = item["key"] + "/original-inner.zip"
    archive_meta = identity(raw)
    if item.get("inner_sha256") is not None:
        require(archive_meta["sha256"] == item["inner_sha256"] and len(raw) == item["inner_bytes"],
                "previously observed inner identity differs")
    chunks = []
    for index, offset in enumerate(range(0, len(raw), 512 * 1024)):
        part = raw[offset:offset + 512 * 1024]
        data = {"schema": "hia.lossless-archive-chunk.v1", "archive_name": name,
                "archive_bytes": len(raw), "archive_sha256": archive_meta["sha256"],
                "index": index, "offset": offset, "bytes": len(part),
                "sha256": hashlib.sha256(part).hexdigest(), "encoding": "base64",
                "data": base64.b64encode(part).decode("ascii")}
        wrapper = wire(data)
        ref = publish_text(wrapper, item["key"] + "/chunk-" + str(index).zfill(3) + ".json")
        chunks.append({"index": index, "offset": offset, "bytes": len(part),
                       "sha256": data["sha256"], "wrapper": ref})
    require(sum(row["bytes"] for row in chunks) == len(raw), "archive chunk extent incomplete")
    index = {"schema": "hia.lossless-archive-chunks.complete.v1", "archive": archive_meta,
             "archive_name": name, "chunks": chunks, "original_run_id": item["run_id"],
             "original_artifact": item["artifact"], "ordered_offsets_complete": True,
             "all_wrappers_full_readback": True, "all_published": True,
             "outer_zip_reconstructed": False, "original_outer_retention": "original Actions artifact identity and retention are retained separately",
             "old_result_changed": False, "current_cold": False, "whole_native": False}
    ref = publish_text(wire(index), item["key"] + "/INDEX.json")
    return archive_meta, ref

def compact_original_report(inner):
    output = {}
    for name in inner.namelist():
        if (name == "REPORT.json" or name.endswith("/original-agent-48.json")
                or name.endswith("/original-suite.json") or name.endswith("observations/REPORT.json")
                or name.endswith("default-front-64/REPORT.json") or name.endswith("actual-combinations/REPORT.json")
                or name.endswith("COST-REPORT.json")):
            value = json.loads(inner.read(name))
            fields = ("schema", "status", "tests_run", "elapsed_ns", "actual_machine_returns",
                      "actual_machine_mode_returns", "source_and_inputs_unchanged", "source_unchanged",
                      "failures", "errors", "skips", "skipped", "expected_failures", "unexpected_successes",
                      "loaded_ids", "executed_ids", "all_executed_ids", "loaded", "executed",
                      "comparisons", "actual_returns", "original_method_outcomes", "outcome")
            output[name] = {k:value[k] for k in fields if k in value}
            output[name]["original_identity"] = identity(inner.read(name))
    return output

def collect(item):
    global STAGE
    STAGE = item["key"] + ": authority"
    require(item["artifact"]["workflow_run"]["id"] == item["run_id"]
            and item["artifact"]["workflow_run"]["head_sha"] == item["harness_commit"], "frozen authority inconsistent")
    expected_harness(item)
    folder = OUT / item["key"]
    folder.mkdir(parents=True)
    archive = folder / "original-artifact.zip"
    authority, run, outer_sha = download(item, archive)
    STAGE = item["key"] + ": complete CRC and source"
    with zipfile.ZipFile(archive) as outer_zip:
        outer = zip_inventory(outer_zip)
        suffix = "COMPLETE-RAW.zip" if item["kind"] == "four-profile" else "RAW-EVIDENCE.zip"
        candidates = [n for n,r in outer.items() if not r["directory"] and pathlib.PurePosixPath(n).name == suffix]
        require(len(candidates) == 1, "original inner ZIP is not unique")
        name = candidates[0]
        raw = outer_zip.read(name)
    with zipfile.ZipFile(io.BytesIO(raw)) as inner:
        members = zip_inventory(inner)
        report = json.loads(inner.read("REPORT.json"))
        actual_source = source_from_archive(item, outer, name, report, inner)
        if item["kind"] == "diagnostic":
            manifest = json.loads(inner.read("EVIDENCE-MANIFEST.json"))
            require(set(manifest) | {"EVIDENCE-MANIFEST.json"} == set(members), "diagnostic complete member inventory differs")
            for path, row in manifest.items():
                require(all(members[path][key] == row[key] for key in ("bytes","sha256","blob")), "diagnostic manifest bytes differ")
                require(int(members[path]["zip_mode"],8)&0o7777 == int(row["local_mode"],8), "diagnostic original member mode differs")
        observations = compact_original_report(inner)
        # This wrapper keeps the exact complete original root report, even when it is large.
        root_raw = inner.read("REPORT.json")
        root_wrapper = {"schema":"hia.lossless-zlib-text-capsule.v1", **identity(root_raw),
                        "encoding":"base64(zlib(UTF-8))", "data":base64.b64encode(zlib.compress(root_raw,6)).decode("ascii")}
    verification = {"schema":"hia.original-artifact-custody.v1", "key":item["key"],
        "original_run_id":item["run_id"], "original_run_conclusion":run["conclusion"],
        "original_artifact":authority, "outer_bytes":archive.stat().st_size, "outer_sha256":outer_sha,
        "outer_members":len(outer), "inner_original_member":name, "inner":identity(raw),
        "inner_members":len(members), "all_outer_inner_crc_sha_git_verified":True,
        "source_commit":item["source_commit"], "source_tree":item["source_tree"], "source_files":len(actual_source),
        "source_matches_actual_git":True, "source_before_after_matches":True,
        "harness_commit":item["harness_commit"], "harness_git_bytes_full_readback":True,
        "original_harness_unchanged_report":report.get("harness_inputs_unchanged"),
        "original_status":report["status"], "product_tests_executed_by_custodian":0,
        "current_cold":False,"whole_native":False,"observation_is_not_qualification":True}
    record(item["key"]+"/VERIFICATION.json",verification)
    record(item["key"]+"/ORIGINAL-OBSERVATIONS.json",observations)
    STAGE=item["key"]+": immutable custody"
    archive_meta,index=publish_archive(raw,item)
    refs={}
    for leaf,value in (("VERIFICATION.json",verification),("ORIGINAL-OBSERVATIONS.json",observations),
                       ("OUTER-MEMBERS.json",outer),("INNER-MEMBERS.json",members),
                       ("ROOT-REPORT.zlib.json",root_wrapper)):
        payload=wire(value)
        if len(payload)>400000:
            original_leaf=leaf
            leaf=leaf.removesuffix(".json")+".zlib.json"
            payload=wire({"schema":"hia.lossless-zlib-text-capsule.v1",**identity(payload),
                          "original_name":original_leaf,"encoding":"base64(zlib(UTF-8))",
                          "data":base64.b64encode(zlib.compress(payload,6)).decode("ascii")})
        refs[leaf]=publish_text(payload,item["key"]+"/"+leaf)
    RESULTS.append({"key":item["key"],"original_status":report["status"],
                    "archive":archive_meta,"index":index,"receipts":refs})
    # Do not delete or rewrite original ZIP bytes in this job.
    require(hashlib.sha256(archive.read_bytes()).hexdigest()==outer_sha,"outer original changed after custody")
    print(json.dumps({"completed_original":item["key"],"original_status":report["status"],
                      "index_blob":index["blob"],"no_product_execution":True}),flush=True)

def main():
    global STAGE
    before={str(p):identity(p.read_bytes()) for p in sorted(pathlib.Path(".").rglob("*"))
            if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts}
    require(os.environ["GITHUB_REPOSITORY"]==REPOSITORY, "repository differs")
    record("CUSTODIAN-SOURCE-BEFORE.json",before)
    success=False
    try:
        for item in INPUTS["originals"]:
            collect(item)
        success=True
    except BaseException as error:
        record("FAILURE.json",{"stage":STAGE,"error_type":type(error).__name__,
                               "http_code":getattr(error,"code",None),"message":"See pinned source and stage; credentials and storage URLs are never logged",
                               "original_results_reclassified":False})
    finally:
        after={str(p):identity(p.read_bytes()) for p in sorted(pathlib.Path(".").rglob("*"))
               if p.is_file() and ".git" not in p.parts and "__pycache__" not in p.parts}
        unchanged=before==after
        final={"schema":"hia.evidence-only-complete-or-partial.v1",
               "status":"CUSTODY_COMPLETE" if success and unchanged else "CUSTODY_INCOMPLETE",
               "expected_originals":len(INPUTS["originals"]),"completed_originals":RESULTS,
               "last_stage":STAGE,"intents":INTENTS,"acks":ACKS,"entries":ENTRIES,"custodian_source_unchanged":unchanged,
               "unpreserved_originals":[x["key"] for x in INPUTS["originals"] if x["key"] not in {r["key"] for r in RESULTS}],
               "actual_custodian_commit":os.environ["GITHUB_SHA"],"actual_custodian_run":os.environ["GITHUB_RUN_ID"],
               "product_execution":False,"compiler_execution":False,"tests_execution":False,
               "old_results_reclassified":False,"product_or_audit_refs_changed":False,
               "current_cold":False,"whole_native":False}
        record("FINAL.json",final)
        try:
            ref=publish_text(wire(final),"FINAL.json")
            print(json.dumps({"custody_status":final["status"],"manifest_blob":ref["blob"],
                              "bytes":ref["bytes"],"sha256":ref["sha256"]}),flush=True)
        except BaseException as error:
            record("FINAL-PUBLISH-FAILURE.json",{"stage":STAGE,"error_type":type(error).__name__})
            success=False
        return 0 if success and unchanged else 1

if __name__ == "__main__":
    raise SystemExit(main())
