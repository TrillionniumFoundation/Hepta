"""Independent CI reconstruction and actual native CLI component validation.

This driver consumes exact published R6/R14 inputs plus new source-delivery
files. Original ROG observations are never inherited as CI test results.
It does not activate an installed entry or qualify whole-stack native closure.
"""
from pathlib import Path, PurePosixPath
from hashlib import sha1, sha256
import importlib.util, io, json, lzma, os, shutil, stat, sys, tarfile, traceback, zlib
sys.dont_write_bytecode = True
DELIVERY = Path(__file__).resolve().parents[1]
EXPECTED = {
  "tools/cli_capture_owner.py": "28af4a67d6bcf8596b008c5c7e37fca14d95f4317477c076c8bed33d5c61e2c0",
  "tools/generate_hia_cli_capture.py": "f0514ef20d0bd3847c02538d3ab456d7ad9c651afbd47f5a1019e5052f111706",
  "development/test_capture_reconstructed_r1.py": "f40464841d73c3b0175a71d8caa9fea764791a3bdbf37304145436d973845ffc",
  "tools/cli_graph_wire_common.py": "6edd1ad961c0db0d19cc27fcd96ae762abc60788e10ee7e0fc0bf02029a1d6fe",
  "tools/cli_graph_wire_emit.py": "a9a8b5d3de5176781784381101c5f85f7c16b58198b145fc1a5a8a3ab3354e40",
  "tools/generate_hia_cli_graph_wire.py": "c1ee7b519b0b684f0c6ec9d6d7dc9f6a50ce874755bc1496c1844024a2d2d545",
  "tools/cli_pretty_owner.py": "6acd5426863aba7f93acef7b8ff0ba9df8edfddaa67dd4c464c361c78b964e5c",
  "tools/generate_hia_cli_pretty.py": "e76c785895c4ebfc4f9b72f0cf50c2d39f6d9c1c2f7db5bd316d709bcce86c2c",
  "development/test_wire_pretty_reconstructed_r1.py": "9e142b2341cf0afcb15c32af2a1ac25509a82695dd26134704827fece1f0e406",
  "docs/RECONSTRUCTED_COMPONENTS_R1_HANDOFF.md": "e23bdd15175c846ef5cc3fb99bf3fc1df5164e10920c8e8715ffff73d6d217e0",
  "tools/generate_hia_cli_entry.py": "d3c0be75cfb3ef160adcc5a1c8e606ee61d204048318a23cfc7167c12a0d83e9",
  "tools/cli_native_executor.S": "717f23a65686cabc8a2599e28079fa37645393eaa31e5e30cdc0cad6aef86c26",
  "development/original-rogrun-capture-compile-r1.py": "db0b3bb1e62e8911c5002d0871fa5272f51e57f3093ee63b27513fc2c1bfbc46",
  "development/original-rogrun-wire-compile-r1.py": "4c2582f362068775c225c7a71cb7df30d47f3a64f051de17b1fc9778bcfcb7e3",
  "development/original-rogrun-pretty-compile-r1.py": "1432f0af6ff1bfe9fc92dc5d1dc1dc1f6804c470b6d2788b3d5097bb26848a7a",
  "development/original-rogrun-file-compile-r2.py": "3b1769e53747a9d21208c6164126872a7e21d3a1e7d2c16da2850d166bfa2ae1",
  "tools/cli_authoring.py": "717d3bbd4bfc22bcca68aea7375787bfe9b0a355d74279c7258437dda2a4851b",
  "tools/cli_file_owner.py": "92bc344da299cd98c50867d17a6d8609003f14980c8bec024c20eee1b15578d0",
  "tools/generate_hia_cli_file.py": "ebfac56dc0fe4cf225665efe4658743569f53de63df7999bd871391286203bdf",
  "development/test_file_reconstructed_r2.py": "b2cdc98a446ff52be32fbca0198d17dd20706bea00b7459655901c885f3b7186",
  "tools/cli_entry_owner.py": "1f55d6005054f9a56f282559480b36f51cec950858c639db1ec773980a988693",
  "tools/generate_hia_cli_native_packer.py": "ff9304fd88c4244b7b93647bedaebed03d94f969180c0b159fcb21766a246ade",
  "development/build_cli_entry_reconstructed_r3.py": "b13c89745a0e3bf32ad7fe8774f927da9ee083c805c5ec2354be1c29303604b3",
  "docs/HIA_CLI_BUSINESS_HANDOFF_FIELDS.json": "4a67da8afe6d25b7765d67ea88fcf446dd5ea0fe82016ef2ab6695320c99d46b"
}
BASE = Path("/var/tmp/hia9acdfa-native-resume-a3c61136-20261111")
COMPILER_SHA = "35ee92b7258134b0bdf517448b51cfdef4c191a510af26ae581b81ad2924ee5b"

def digest(raw):
    return sha256(raw).hexdigest()

def git_sha(raw):
    return sha1(b"blob " + str(len(raw)).encode() + b"\0" + raw).hexdigest()

def save(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")

def exact_copy(source, target, expected=None):
    source, target = Path(source), Path(target)
    assert source.is_file() and not source.is_symlink()
    raw = source.read_bytes()
    if expected is not None:
        assert digest(raw) == expected, (str(source), digest(raw), expected)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        assert target.is_file() and not target.is_symlink() and target.read_bytes() == raw
    else:
        target.write_bytes(raw)
        target.chmod(stat.S_IMODE(source.stat().st_mode))
    assert target.read_bytes() == raw
    return dict(source=str(source), target=str(target), bytes=len(raw),
                sha256=digest(raw), mode=stat.S_IMODE(target.stat().st_mode))

def unpack_verified(archive, rows, target, expected_files, expected_bytes, cas_expected=None):
    assert not target.exists()
    target.mkdir(parents=True)
    wanted = {row.get("name", row.get("path")): row for row in rows}
    assert None not in wanted and len(wanted) == expected_files
    seen, total, cas_count, expanded = set(), 0, 0, 0
    with tarfile.open(archive, "r:xz") as tf:
        for item in tf:
            path = PurePosixPath(item.name)
            assert item.isfile() and not path.is_absolute() and ".." not in path.parts
            assert item.name not in seen and item.name in wanted
            row = wanted[item.name]
            raw = tf.extractfile(item).read()
            expected_size = row.get("bytes", row.get("size"))
            assert (len(raw), digest(raw), stat.S_IMODE(item.mode)) == (expected_size, row["sha256"], row["mode"])
            assert item.size == expected_size
            destination = target / path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(raw)
            destination.chmod(row["mode"])
            assert destination.read_bytes() == raw and stat.S_IMODE(destination.stat().st_mode) == row["mode"]
            if destination.suffix == ".zlib" and len(destination.stem) == 64:
                expanded_raw = zlib.decompress(raw)
                assert digest(expanded_raw) == destination.stem
                cas_count += 1
                expanded += len(expanded_raw)
            total += len(raw)
            seen.add(item.name)
    assert seen == set(wanted) and len(seen) == expected_files and total == expected_bytes
    if cas_expected is not None:
        assert (cas_count, expanded) == cas_expected, (cas_count, expanded)
    return dict(status="PASS_EXACT_ORIGINAL_RECOVERY_NOT_NEW_NATIVE_TEST",
                target=str(target), files=len(seen), raw_bytes=total,
                zlib_cas=cas_count, zlib_expanded_bytes=expanded)

def recover_inputs(context, mine):
    source = Path(context["source"])
    r14 = source / "review-evidence/hia-native-rewrite-20261111/reconstructed-components-r14"
    manifest_raw = (r14 / "transport-objects.json").read_bytes()
    assert digest(manifest_raw) == "1e4596cde24ebdd9e5b7042ea67db5bc3f9548b778d57b78d9142afd6dd02577"
    manifest = json.loads(manifest_raw)
    row = next(row for row in manifest["objects"] if row["name"] == "cli-argv-formatter/development.tar.xz")
    chunks = []
    for part in row["ordered_parts"]:
        raw = (source / part["path"]).read_bytes()
        assert (len(raw), digest(raw), git_sha(raw)) == (part["bytes"], part["sha256"], part["git_sha"])
        chunks.append(raw)
    raw = b"".join(chunks)
    assert len(raw) == row["original_bytes"] == 13539564
    assert digest(raw) == row["original_sha256"] == "37ed85a727a2c18f08e0a5b3c473556db14a51e376cb62ce4c62169c7f311d9e"
    archive = mine / "r14-cli-argv-formatter-exact.tar.xz"
    archive.write_bytes(raw)
    custody_row = next(row for row in manifest["objects"] if row["name"] == "cli-argv-formatter/custody.json")
    transport = (r14 / custody_row["transport_object_name"]).read_bytes()
    assert (len(transport), digest(transport)) == (custody_row["bytes"], custody_row["sha256"])
    custody_raw = lzma.decompress(transport)
    assert (len(custody_raw), digest(custody_raw)) == (custody_row["original_bytes"], custody_row["original_sha256"])
    assert digest(custody_raw) == "7988b5d2b91759cbaa854ba6c89e8946b8efe9708ea69115c7ad16ff22083641"
    custody = json.loads(custody_raw)
    result14 = unpack_verified(archive, custody["rows"], mine / "r14-exact-original",
                              27046, 85599523, (26842, 750459170))
    result14.update(archive_sha256=digest(raw), original_transport_sha256=digest(manifest_raw))
    save(mine / "r14-ci-restoration.json", result14)
    r6 = source / "review-evidence/hia-native-rewrite-20261111/reconstructed-components-r6"
    archive6 = r6 / "graph-wire-r3.tar.xz"
    raw = archive6.read_bytes()
    assert (len(raw), digest(raw)) == (537224, "31b4b7ce104d0ff611891abe43a4131d7fd94d342aba9686c4c789d6d485f25b")
    custody6 = json.loads((r6 / "graph-wire-r3-custody.json").read_bytes())
    rows = custody6["members"]
    if isinstance(rows, dict):
        rows = [dict(value, name=name) for name, value in rows.items()]
    result6 = unpack_verified(archive6, rows, mine / "r6-exact-original", 823, 70930366)
    result6["archive_sha256"] = digest(raw)
    save(mine / "r6-ci-restoration.json", result6)
    return result14, result6

def populate(context, mine, project, common):
    old = mine / "r14-exact-original/checkpoints/argv-formatter-source-r1"
    copies = []
    for folder in ("tools", "examples", "docs"):
        for path in sorted((old / folder).rglob("*")):
            if path.is_file():
                copies.append(exact_copy(path, project / path.relative_to(old)))
    for relative, expected in EXPECTED.items():
        source = DELIVERY / relative
        raw = source.read_bytes()
        assert digest(raw) == expected, (relative, digest(raw), expected)
        common.PINS[source.resolve()] = raw
        target = project / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if target.exists():
            prior = mine / "ci-preoverlay-originals" / relative
            exact_copy(target, prior)
        target.write_bytes(raw)
        target.chmod(stat.S_IMODE(source.stat().st_mode))
        assert target.read_bytes() == raw
        copies.append(dict(source=str(source), target=str(target), bytes=len(raw), sha256=expected))
    for relative in ("development/test_cli_entry_ci_r1.py",):
        source = DELIVERY / relative
        raw = source.read_bytes()
        common.PINS[source.resolve()] = raw
        copies.append(exact_copy(source, project / relative))
    workspace = Path(context["workspace"])
    deps = [
        (workspace / "native-edit-json-next/development/main-compile-r3/source/6/hia_agent_edit_source_views.py",
         mine / "workspace/Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py",
         "555472263213f15deb239fcf3bf8e5b273a28caf3a67bb29ffd037f171d7ae5c"),
        (workspace / "native-edit-json-next/development/main-compile-r3/source/8/hia_composite_lowering_driver_common.py",
         mine / "workspace/native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py",
         "fe63327671ea51ca950b955512a0f574d706176a4a8d050e3f8f12c83ef5e3a1"),
    ]
    for source, target, expected in deps:
        copies.append(exact_copy(source, target, expected))
    for old_name, new_name in {
        "checkpoints/source-r3/tools/generate_hia_graph_wire_scan.py": "cli_graph_wire_scan.py",
        "dependencies/base/tools/generate_hia_agent_binary64_format.py": "generate_hia_agent_binary64_format.py",
        "dependencies/base/tools/generate_hia_agent_binary64.py": "generate_hia_agent_binary64.py",
    }.items():
        copies.append(exact_copy(mine / "r6-exact-original" / old_name, project / "tools" / new_name))
    (project / "development").mkdir(exist_ok=True)
    (project / "checkpoints").mkdir(exist_ok=True)
    save(mine / "ci-source-materialization.json", copies)
    return copies

def build_components(context, mine, project, common):
    source_root = Path(context["source"])
    compiler = Path(context["compiler"])
    compiler_raw = compiler.read_bytes()
    assert len(compiler_raw) == 669556 and digest(compiler_raw) == COMPILER_SHA
    compiler_snapshot = mine / "ci-compiler/B3.image.bin"
    exact_copy(compiler, compiler_snapshot, COMPILER_SHA)
    sys.path.insert(0, str(source_root))
    from tools.qualify_hia_selfhost import compile_stage
    from hepta.hia_agent_assembly import assemble_program
    helper = mine / "workspace/Hepta-agent-edit-native"
    ordinary_env = dict(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(helper) + ":" + str(source_root))
    wire_env = dict(PYTHONDONTWRITEBYTECODE="1", PYTHONPATH=str(project) + ":" + str(source_root))
    original_sources = {}
    for root in (project / "tools", helper / "tools",
                 mine / "workspace/native-composite-driver-reconstructed/tools"):
        for path in sorted(root.rglob("*.py")):
            original_sources[str(path)] = path.read_bytes()
    save(mine / "ci-generation-source-before.json",
         {name:dict(bytes=len(raw), sha256=digest(raw)) for name,raw in original_sources.items()})
    specifications = [
        ("capture", "generate_hia_cli_capture.py", "capture-reconstructed-compile-r1",
         [("cli-capture", "cli_capture.hiaasm", "cli-capture.manifest.json",
           "3c9c3f558e25ea29fc726bbba1e22eb10c2b9edac5f7c18e23fe9b908af1f87c",
           "960aef38158d4fda7ee171ec61d8496bf1cd5130508cb5b4dca3fc10d4b4abf7")]),
        ("wire", "generate_hia_cli_graph_wire.py", "cli-wire-reconstructed-compile-r1",
         [("cli-graph-wire-scan", "cli_graph_json_wire_scan.hiaasm", "scan.manifest.json",
           "7ac81329c5bcaea0bfd4a2a31f9efdfb1d24590307ec90fa72250371b16f3d2e",
           "bbd4d6c19b3159c3a64c5be4e2f77a943eb057696fe00ded55e8b4bd70a5e4c4"),
          ("cli-graph-wire-emit", "cli_graph_json_wire_emit.hiaasm", "emit.manifest.json",
           "1eb4e4236a7caf222254f3d10d510bf650074ce666ddf68f7423a374245e05ea",
           "9498c83fab2af063bfa15ebee750b60bae9aa1ad21e03443f788891b69d054fd")]),
        ("pretty", "generate_hia_cli_pretty.py", "pretty-reconstructed-compile-r1",
         [("cli-pretty", "cli_pretty.hiaasm", "cli-pretty.manifest.json",
           "15e1c050b52b29948c7cde357684cc71c3837f93216756f2c5c2201133e62ac6",
           "fdf6b79b307cbe9169edccf50ad81871511f9193e411420ed9e56d0d6697cdf2")]),
        ("file", "generate_hia_cli_file.py", "file-reconstructed-compile-r2",
         [("cli-file", "cli_file.hiaasm", "cli-file.manifest.json",
           "9db9331891c177da57621f69922214226886d74bf126b6362d5c223e6578dc16",
           "e6ba028f4f9e8565c80d792e2721bf2032706942aa7ec5d6b8cf03ee44b4cfa3")]),
    ]
    compiled = []
    for kind, generator, directory, parts in specifications:
        stage = project / "development" / directory
        stage.mkdir(parents=True, exist_ok=False)
        common.run("cli-generate-" + kind, [sys.executable, "-B", project / "tools" / generator],
                   cwd=project, env=wire_env if kind == "wire" else ordinary_env, timeout=90 if kind == "wire" else 60)
        components = {}
        for label, filename, manifest_name, source_sha, image_sha in parts:
            source = project / "examples/hia_bootstrap" / filename
            raw = source.read_bytes()
            assert digest(raw) == source_sha, (kind, filename, digest(raw), source_sha)
            (stage / filename).write_bytes(raw)
            assemble_program(raw)
            image, receipt = compile_stage(stage, label, compiler_snapshot, raw)
            image = Path(image)
            image_raw = image.read_bytes()
            assert receipt["source_sha256"] == receipt["input_sha256"] == source_sha
            assert receipt["image_sha256"] == receipt["artifact_sha256"] == COMPILER_SHA
            assert receipt["produced_sha256"] == digest(image_raw) == image_sha
            assert receipt["produced_bytes"] == len(image_raw)
            assert source.read_bytes() == raw and compiler.read_bytes() == compiler_raw
            manifest = dict(schema="hepta.hia.cli-" + kind + ".development.v1",
                            scope="NEW_INDEPENDENT_CI_DEVELOPMENT_NOT_ROG_RUN_OR_COLD",
                            qualification="DEVELOPMENT_ONLY_NEW_CI_REBUILD",
                            source=str(source), source_path=str(source), source_sha256=source_sha,
                            source_bytes=len(raw), image=str(image), image_path=str(image),
                            image_sha256=image_sha, image_bytes=len(image_raw),
                            compiler=str(compiler_snapshot), compiler_sha256=COMPILER_SHA,
                            receipt=receipt, python=sys.version)
            save(stage / manifest_name, manifest)
            compiled.append(manifest)
            if kind == "wire":
                components["scan" if "scan" in label else "emit"] = manifest
        if kind == "wire":
            save(stage / "bundle.json", dict(status="PASS_COMPILE_ONLY",
                 scope="NEW_INDEPENDENT_CI_GRAPH_WIRE_DEVELOPMENT_NOT_COLD", components=components))
    after = {name:dict(bytes=Path(name).stat().st_size, sha256=digest(Path(name).read_bytes()))
             for name in original_sources}
    save(mine / "ci-generation-source-after.json", after)
    assert all(Path(name).read_bytes() == raw for name,raw in original_sources.items())
    return compiled, ordinary_env

def portable_raw_export(mine, project):
    """Keep complete portable bytes; represent test filesystem objects explicitly.

    Actual symlinks, hardlinks, FIFOs and sockets are test fixtures, never
    followed by archival code. Their types/modes/targets and all regular-file
    content are retained with lossless CAS. No native buffer is omitted.
    """
    export = mine / "ci-portable-evidence-r1"
    export.mkdir(exist_ok=False)
    fixture_rows = []
    cas_dir = export / "fixture-cas"
    cas_dir.mkdir()
    if project.exists():
        for path in sorted(project.rglob("*")):
            info = path.lstat()
            relative = path.relative_to(project)
            if stat.S_ISDIR(info.st_mode):
                continue
            in_fixtures = relative.parts[:3] == ("development", "file-reconstructed-native-r2", "fixtures")
            if in_fixtures:
                row = dict(path=relative.as_posix(), type=stat.S_IFMT(info.st_mode),
                           mode=stat.S_IMODE(info.st_mode), links=info.st_nlink,
                           device=info.st_dev, inode=info.st_ino)
                if stat.S_ISLNK(info.st_mode):
                    row["target"] = os.readlink(path)
                elif stat.S_ISREG(info.st_mode):
                    raw = path.read_bytes()
                    h = digest(raw)
                    destination = cas_dir / (h + ".zlib")
                    if not destination.exists():
                        destination.write_bytes(zlib.compress(raw, 6))
                    assert zlib.decompress(destination.read_bytes()) == raw
                    row["data"] = dict(bytes=len(raw), sha256=h, compression="zlib",
                                       path="fixture-cas/" + destination.name)
                fixture_rows.append(row)
                continue
            assert stat.S_ISREG(info.st_mode) and info.st_nlink == 1, (str(path), "nonportable nonfixture")
            exact_copy(path, export / "project" / relative)
    save(export / "fixture-object-inventory.json", fixture_rows)
    for name in ("r14-ci-restoration.json", "r6-ci-restoration.json", "ci-source-materialization.json",
                 "ci-generation-source-before.json", "ci-generation-source-after.json"):
        path = mine / name
        if path.exists():
            exact_copy(path, export / name)
    for relative in (
        "workspace/Hepta-agent-edit-native/tools/hia_agent_edit_source_views.py",
        "workspace/native-composite-driver-reconstructed/tools/hia_composite_lowering_driver_common.py",
        "r6-exact-original/development/graph_harness_r3.py",
        "r6-exact-original/development/compile-r3/scan.manifest.json",
        "r6-exact-original/development/compile-r3/emit.manifest.json",
        "r6-exact-original/examples/hia_bootstrap/graph_json_wire_scan.hiaasm",
        "r6-exact-original/examples/hia_bootstrap/graph_json_wire_emit.hiaasm",
    ):
        path = mine / relative
        if path.exists():
            exact_copy(path, export / "dependencies" / relative)
    old_images = mine / "r6-exact-original/development/compile-r3"
    if old_images.exists():
        for path in old_images.glob("*.image.bin"):
            exact_copy(path, export / "dependencies/r6-images" / path.name)
    return export

def main():
    common_path = Path(os.environ["HIA_CI_COMMON"]).resolve()
    common_raw = common_path.read_bytes()
    specification = importlib.util.spec_from_file_location("cli_ci_common", common_path)
    common = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(common)
    common.PINS[common_path] = common_raw
    common.PINS[Path(__file__).resolve()] = Path(__file__).read_bytes()
    context = None
    mine = BASE / "cli-recovery"
    project = mine / "workspace/native-hia-cli-next"
    caught = None
    status = "FAIL"
    details = dict(new_execution=True, old_ROG_launch_status="UNKNOWN_NOT_RESOLVED_BY_CI",
                   whole_stack_closed=False, installed_entry_activated=False,
                   common_module_git_blob=git_sha(common_raw))
    roots = {}
    try:
        context = common.prepare()
        assert Path(context["base"]) == BASE
        mine.mkdir(exist_ok=False)
        recovered14, recovered6 = recover_inputs(context, mine)
        details["original_restoration"] = dict(r14=recovered14, r6=recovered6)
        details["source_files"] = populate(context, mine, project, common)
        compiled, env = build_components(context, mine, project, common)
        details["actual_new_compiles"] = [
            {k:row[k] for k in ("source_path", "source_sha256", "image_path", "image_sha256")}
            for row in compiled]
        tests = [
            ("cli-capture-native", "test_capture_reconstructed_r1.py", 120,
             "capture-reconstructed-native-r1/summary.json", 358, "actual_entries", 1061),
            ("cli-wire-pretty-native", "test_wire_pretty_reconstructed_r1.py", 180,
             "wire-pretty-reconstructed-native-r1/result.json", 397, "entries", 2395),
            ("cli-file-native", "test_file_reconstructed_r2.py", 180,
             "file-reconstructed-native-r2/result.json", 212, "entries", 1340),
        ]
        results = []
        for label, filename, timeout, summary, cases, entry_key, entries in tests:
            common.run(label, [sys.executable, "-B", project / "development" / filename],
                       cwd=project, timeout=timeout, env=env)
            result = json.loads((project / "development" / summary).read_bytes())
            actual_entries = result[entry_key]
            if isinstance(actual_entries, dict):
                actual_entries = sum(actual_entries.values())
            assert result["status"] == "PASS" and result["cases"] == cases and actual_entries == entries
            results.append(result)
            details["new_native_results"] = results
        build_out = project / "development/entry-independent-ci-build-r1"
        common.run("cli-seven-image-build", [
            sys.executable, "-B", project / "development/build_cli_entry_reconstructed_r3.py",
            "--output", build_out, "--compiler", context["compiler"]],
            cwd=project, timeout=180, env=env)
        built = json.loads((build_out / "summary.json").read_bytes())
        assert built["status"] == "PASS" and built["mapping_entries"] == 1 and built["source_pins_unchanged"]
        details["entry_build"] = built
        actual_out = project / "development/entry-independent-ci-native-r1"
        common.run("cli-seven-image-actual-entry", [
            sys.executable, "-B", project / "development/test_cli_entry_ci_r1.py",
            "--bundle", build_out / "bundle.json", "--source", context["source"], "--out", actual_out],
            cwd=project, timeout=300, env=env)
        entry = json.loads((actual_out / "result.json").read_bytes())
        assert entry["status"] == "PASS" and entry["source_pins_unchanged"]
        assert (entry["cases"], entry["exact_equivalence_cases"], entry["explicit_open_handoff_cases"],
                entry["native_processes"], entry["reference_processes"]) == (193, 176, 17, 193, 176)
        details["new_actual_entry"] = entry
        status = "PASS"
    except BaseException as error:
        caught = error
        details["failure"] = traceback.format_exc()
        print(details["failure"], file=sys.stderr, flush=True)
    finally:
        try:
            if mine.exists():
                export = portable_raw_export(mine, project)
                roots["cli"] = export
        except BaseException as error:
            status = "FAIL"
            details["portable_export_failure"] = traceback.format_exc()
            if caught is None:
                caught = error
            else:
                caught.add_note("CLI portable raw export failed: " + repr(error))
        try:
            common.finish("cli-independent-reconstruction-r1", status, details, roots=roots)
        except BaseException as error:
            if caught is None:
                raise
            caught.add_note("Final CI evidence export failed: " + repr(error))
    if caught is not None:
        raise caught

if __name__ == "__main__":
    main()
