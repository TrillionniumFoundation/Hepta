"""Core-only HIA Agent CLI. This hosted bridge still requires Python."""
from __future__ import annotations
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from . import __version__
HIA_AGENT_ACTIONS = ("capabilities", "catalog", "import-assembly", "render-assembly", "check-assembly", "verify", "inspect", "normalize", "build", "patch", "impact", "edit-query", "edit-apply", "edit-batch-query", "edit-batch-apply")

def agent_capabilities():
    """Describe the Core-only hosted entry, not whole native closure."""
    return {
        "schema": "hepta.hia.agent-entry.v1",
        "entry": "hia", "audience": "ai-agent", "language_core": "HIA",
        "actions": list(HIA_AGENT_ACTIONS),
        "high_level_hepta": "removed",
        "high_level_source_required": False,
        "inputs": ["standalone-hia-json", "explicit-hia-assembly"],
        "build": {"backend": "native", "kind": "object",
                  "target": "x86_64-unknown-linux-gnu", "fallback": False},
        "edits": {"snapshot_bound": True, "entire_module_reverified": True,
                  "publication": "new_path_only"},
        "implementation": "python_host_bridge",
        "native_only_delivery_qualified": False,
        "production_activated": False,
    }

def output_json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))

def publish_json_view(value, destination):
    """No-replace publication of a checked, non-executable agent JSON view."""
    from .artifact_publication import publish_verified
    target = Path(destination).absolute()
    if target.exists() or target.is_symlink():
        raise ValueError("JSON output must be a new file")
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.resolve() != target.parent:
        raise ValueError("JSON output parent must not traverse a symlink")
    payload = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + "\n").encode()
    with tempfile.TemporaryDirectory(prefix=".hepta-json-view-", dir=target.parent) as temporary:
        stage = Path(temporary) / "view.json"
        with stage.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        receipt = publish_verified(stage, target, payload)
    return {"schema": "hepta.hia.json-view-output.v1", "ok": True,
            "output": str(target), "view_schema": value["schema"], "publication": receipt}

def _reference_hia_main(argv=None):
    parser = argparse.ArgumentParser(prog="hia", description="HIA Core Agent interface")
    parser.add_argument("--version", action="version", version="hia " + __version__)
    actions = parser.add_subparsers(dest="hia_action", required=True)
    actions.add_parser("capabilities")
    from .hia_schema import LATEST_CORE_SCHEMA, PRIMITIVE_PROFILES
    catalog = actions.add_parser("catalog")
    catalog.add_argument("--schema", choices=tuple(PRIMITIVE_PROFILES), default=LATEST_CORE_SCHEMA)
    for action in HIA_AGENT_ACTIONS:
        if action in {"capabilities", "catalog"}: continue
        command = actions.add_parser(action)
        command.add_argument("input", help="Explicit HIA assembly or standalone Core JSON")
        if action in {"import-assembly", "render-assembly", "normalize", "build", "patch", "edit-query", "edit-apply", "edit-batch-query", "edit-batch-apply"}:
            command.add_argument("--output", "-o", required=action=="build")
        if action=="build":
            command.add_argument("--backend", choices=["native"], default="native")
            command.add_argument("--kind", choices=["object"], default="object")
            command.add_argument("--target", choices=["x86_64-unknown-linux-gnu"], default="x86_64-unknown-linux-gnu")
        if action in {"patch", "impact"}: command.add_argument("--request", required=True)
        if action=="edit-query":
            command.add_argument("--function", required=True)
            command.add_argument("--block", required=True)
            command.add_argument("--value", required=True)
            command.add_argument("--fields", required=True)
        if action=="edit-batch-query": command.add_argument("--selections", required=True)
        if action in {"edit-apply", "edit-batch-apply"}:
            command.add_argument("--query", required=True)
            command.add_argument("--response", required=True)
    args = parser.parse_args(argv)
    try:
        if args.hia_action=="capabilities":
            output_json(agent_capabilities())
            return 0
        from .hia_program import verify_program
        from .hia_program_tools import read_bounded, decode_json, inspect_program, apply_program_patch, publish_program
        if args.hia_action == 'catalog':
            from .hia_opcodes import opcode_catalog
            output_json(opcode_catalog(args.schema))
            return 0
        if args.hia_action in {'import-assembly', 'render-assembly', 'check-assembly'}:
            from .hia_agent_assembly import assemble_program, render_assembly, diagnose_assembly
            raw = read_bounded(args.input)
            if args.hia_action == 'check-assembly':
                result = diagnose_assembly(raw)
                output_json(result)
                return 0 if result['accepted'] else 1
            if args.hia_action == 'import-assembly':
                program = assemble_program(raw)
                output_json(publish_program(program, args.output) if args.output else program.as_dict())
                return 0
            program = verify_program(raw)
            text = render_assembly(program)
            if args.output:
                from .artifact_publication import publish_verified
                target = Path(args.output).absolute()
                if target.exists() or target.is_symlink():
                    raise ValueError('Assembly output must be a new file')
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.parent.resolve() != target.parent:
                    raise ValueError('Assembly output parent must not traverse a symlink')
                with tempfile.TemporaryDirectory(prefix='.hepta-assembly-', dir=target.parent) as temporary:
                    stage = Path(temporary) / 'program.hiaasm'
                    payload = text.encode('utf-8')
                    with stage.open('xb') as stream:
                        stream.write(payload)
                        stream.flush()
                        os.fsync(stream.fileno())
                    receipt = publish_verified(stage, target, payload)
                output_json({'schema': 'hepta.hia.assembly-output.v1', 'ok': True, 'output': str(target), 'core_sha256': program.sha256, 'publication': receipt, 'deployment_authority': False})
            else:
                print(text, end='')
            return 0
        program = verify_program(read_bounded(args.input))
        if args.hia_action == 'edit-batch-query':
            from .hia_edit_batch import prepare_batch
            query = prepare_batch(program, decode_json(read_bounded(args.selections)))
            output_json(publish_json_view(query, args.output) if args.output else query)
            return 0
        if args.hia_action == 'edit-batch-apply':
            from .hia_edit_batch import apply_batch, MAX_QUERY_BYTES, MAX_RESPONSE_BYTES
            revised, receipt = apply_batch(program, read_bounded(args.query, limit=MAX_QUERY_BYTES), read_bounded(args.response, limit=MAX_RESPONSE_BYTES))
            if args.output:
                receipt['publication'] = publish_program(revised, args.output)
                receipt['status'] = 'verified_new_snapshot_published'
            else:
                receipt['program'] = revised.as_dict()
            output_json(receipt)
            return 0
        if args.hia_action == 'edit-query':
            from .hia_edit_query import prepare_edit
            query = prepare_edit(program, function=args.function, block=args.block, output=args.value, fields=args.fields.split(','))
            output_json(publish_json_view(query, args.output) if args.output else query)
            return 0
        if args.hia_action == 'edit-apply':
            from .hia_edit_query import apply_edit, MAX_RESPONSE_BYTES
            revised, receipt = apply_edit(program, decode_json(read_bounded(args.query)), read_bounded(args.response, limit=MAX_RESPONSE_BYTES))
            if args.output:
                receipt['publication'] = publish_program(revised, args.output)
                receipt['status'] = 'verified_new_snapshot_published'
            else:
                receipt['program'] = revised.as_dict()
            output_json(receipt)
            return 0
        if args.hia_action == 'normalize':
            output_json(publish_program(program, args.output) if args.output else program.as_dict())
            return 0
        if args.hia_action == 'verify':
            output_json({**program.report(), 'status': 'standalone_core_checked', 'native_executed': False})
            return 0
        if args.hia_action == 'inspect':
            output_json(inspect_program(program))
            return 0
        if args.hia_action == 'build':
            from .hia_program_native import build_program_machine
            result = build_program_machine(program, args.output, kind='object', linker='cc')
            output_json(result)
            return 0 if result.get('ok') is True else 1
        if args.hia_action == 'impact':
            from .hia_patch_impact import analyze_patch_impact
            _revised, receipt, impact = analyze_patch_impact(program, read_bounded(args.request))
            output_json({'schema': 'hepta.hia.impact-query.v1', 'ok': True, 'status': 'verified_unpublished', 'patch': receipt, 'impact': impact})
            return 0
        if args.hia_action == 'patch':
            revised, receipt = apply_program_patch(program, read_bounded(args.request))
            if args.output:
                receipt['publication'] = publish_program(revised, args.output)
                receipt['status'] = 'verified_new_snapshot_published'
            else:
                receipt['program'] = revised.as_dict()
            output_json(receipt)
            return 0

        raise ValueError("unsupported HIA action")
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
        output_json({"ok":False,"status":"error","diagnostics":[{"code":"E_DRIVER","message":str(error),"phase":"driver"}]})
        return 2

def hia_main(argv=None):
    selected = os.environ.get("HEPTA_HIA_CLI_MANIFEST")
    if selected is not None:
        from .hia_cli_native import installed_cli
        return installed_cli(selected).run(argv, sys.modules[__name__])
    return _reference_hia_main(argv)

main = hia_main
