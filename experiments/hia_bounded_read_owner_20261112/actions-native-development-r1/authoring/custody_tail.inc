
def capture_terminal(root, source):
    names = ["report.json", "build/report.json", "build/bounded-read.hiaasm", "build/bounded-read.hia.json",
             "build/manifest.json", "build/entry-abi.json", "build/B0.receipt.json", "build/B0.so",
             "build/linker-version.stdout.log", "build/linker-version.stderr.log",
             "reject/report.json", "lifetime/report.json", "permission/report.json", "filesystem/report.json",
             "original-eight/report.json", "original-eight/unittest.log"]
    for label in ("B1", "B2", "bounded-read"):
        names += ["build/" + label + end for end in (".input.bin", ".output.bin", ".request.json",
                    ".receipt.json", ".image.bin", ".stdout.log", ".stderr.log")]
    for label in ("prepare-native", "reject", "lifetime", "permission", "filesystem", "original-eight"):
        names += ["processes/" + label + end for end in (".stdout.log", ".stderr.log", ".process-owner.json",
                    ".process-owner.json.request.json", ".process-owner.json.stdout.log", ".process-owner.json.stderr.log")]
    records, errors = [], []
    for name in names:
        try:
            records.append({"name": name, "record": read(root / "evidence" / name, 16 << 20)[1]})
        except FileNotFoundError:
            records.append({"name": name, "missing": True})
        except BaseException as error:
            records.append({"name": name, "error": type(error).__name__})
            errors.append({"name": name, "traceback": traceback.format_exc()})
    generated = None
    try:
        raw, record = read(source / GENERATED, 1 << 20)
        generated = {"source": record, "copy": create(root / "GENERATED-SOURCE-AT-TERMINAL.hiaasm", raw)}
    except FileNotFoundError:
        generated = {"missing": True}
    except BaseException as error:
        errors.append({"phase": "generated_source_original", "type": type(error).__name__,
                       "traceback": traceback.format_exc()})
    inventory = None
    try:
        inventory = create(root / "EVIDENCE-INVENTORY.json", wire(evidence_inventory(root / "evidence")))
    except BaseException as error:
        errors.append({"phase": "typed_inventory", "type": type(error).__name__,
                       "traceback": traceback.format_exc()})
    result = {"schema": "hepta.hia.bounded-read-fixed-terminal-originals.v1", "originals": records,
              "errors": errors, "typed_evidence_inventory": inventory, "generated_source_original": generated,
              "closed_current_outer_ECHILD_before_all_reads": True}
    return result, create(root / "TERMINAL-ORIGINALS.json", wire(result))

def retain_typed_owned_output(root):
    """No live child reads, no FIFO opens, no symlink traversal or extraction."""
    inventory = evidence_inventory(root)
    rows = [r for r in inventory["members"] if r["path"] != "public" and not r["path"].startswith("public/")]
    require(all(r["path"] != ".BOUND-CUSTODY-MANIFEST.json" for r in rows), "reserved archive name collides")
    manifest = wire({"schema": "hepta.hia.bounded-read-typed-owned-custody.v1", "originals": rows,
        "all_regular_bytes_preserved": True, "symlinks_and_FIFO_are_typed_metadata": True,
        "nanosecond_original_identities_preserved_in_manifest": True,
        "tar_mtime_uses_whole_seconds": True, "direct_extraction_authorized": False})
    archive_path = root / "public/owned-originals.tar"
    expected = {}
    with _checked_parent(archive_path) as (parent, name, stable):
        fd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                     0o600, dir_fd=parent)
        with os.fdopen(fd, "w+b", buffering=0) as output:
            with tarfile.open(fileobj=output, mode="w", format=tarfile.PAX_FORMAT) as archive:
                for row in rows:
                    relative = row["path"]
                    if relative == ".":
                        continue
                    path = root / relative
                    info = path.lstat()
                    require(list(identity(info)) == row["identity"], "typed original changed")
                    member = tarfile.TarInfo(relative)
                    member.uid, member.gid, member.mode = info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)
                    member.mtime, member.uname, member.gname = info.st_mtime_ns // 1000000000, "", ""
                    kind = row["kind"]
                    if kind == "regular":
                        raw, actual = read(path, 128 << 20)
                        require(actual["identity"] == row["identity"]
                                and pin(raw) == {k: row[k] for k in ("bytes", "sha256", "git_blob_sha1")},
                                "typed original bytes changed")
                        member.type, member.size = tarfile.REGTYPE, len(raw)
                        archive.addfile(member, io.BytesIO(raw))
                    elif kind == "directory":
                        member.type = tarfile.DIRTYPE
                        archive.addfile(member)
                    elif kind == "symlink":
                        require(os.readlink(path) == row["target"], "link metadata changed")
                        member.type, member.linkname = tarfile.SYMTYPE, row["target"]
                        archive.addfile(member)
                    elif stat.S_ISFIFO(info.st_mode):
                        member.type = tarfile.FIFOTYPE
                        archive.addfile(member)
                    else:
                        # Other specials retain identity/type in the manifest;
                        # no body is read and no device/socket node is created.
                        continue
                    expected[relative] = row
                member = tarfile.TarInfo(".BOUND-CUSTODY-MANIFEST.json")
                member.mode, member.size = 0o400, len(manifest)
                archive.addfile(member, io.BytesIO(manifest))
            os.fchmod(output.fileno(), 0o400)
            os.fsync(output.fileno())
            stable()
    raw, archive_pin = read(archive_path, 160 << 20)
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        members = archive.getmembers()
        require(len({m.name for m in members}) == len(members)
                and {m.name for m in members} == set(expected) | {".BOUND-CUSTODY-MANIFEST.json"},
                "complete archive member set differs")
        for member in members:
            if member.name == ".BOUND-CUSTODY-MANIFEST.json":
                require(member.isfile() and archive.extractfile(member).read() == manifest, "manifest bytes differ")
                continue
            original = expected[member.name]
            values = original["identity"]
            require(member.mode == stat.S_IMODE(values[2]) and member.uid == values[3]
                    and member.gid == values[4] and member.mtime == values[7] // 1000000000,
                    "archive metadata differs")
            kind = original["kind"]
            if kind == "regular":
                data = archive.extractfile(member).read() if member.isfile() else None
                require(data is not None and pin(data) == {k: original[k] for k in ("bytes", "sha256", "git_blob_sha1")},
                        "archived original bytes differ")
            elif kind == "directory":
                require(member.isdir(), "directory metadata differs")
            elif kind == "symlink":
                require(member.issym() and member.linkname == original["target"], "link metadata differs")
            else:
                require(member.isfifo(), "FIFO metadata differs")
    for row in rows:
        path = root if row["path"] == "." else root / row["path"]
        require(list(identity(path.lstat())) == row["identity"], "original changed during archive verification")
    require(read(archive_path, 160 << 20)[1] == archive_pin, "sealed typed archive changed")
    result = {"schema": "hepta.hia.bounded-read-typed-custody-receipt.v1",
              "status": "EXACT_TYPED_ORIGINALS_RETAINED_NOT_PRODUCT_PASS", "archive": archive_pin,
              "manifest": pin(manifest), "members": len(members), "original_members": len(rows),
              "regular_original_bytes": sum(r.get("bytes", 0) for r in rows),
              "closed_current_outer_ECHILD": True, "no_product_execution": True,
              "no_special_member_open_or_follow": True}
    result["receipt"] = create(root / "public/CUSTODY.json", wire(result))
    return result
