"""Explicit Python reference/research CLI for standalone HIA Core only.

Not installed as the Agent entry and never selected as a native fallback.
"""
from __future__ import annotations
import argparse, json, os, subprocess, sys, tempfile
from pathlib import Path
from hepta import __version__

def output_json(value):
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))

def publish_json_view(value, destination):
    """No-replace publication of a checked, non-executable agent JSON view."""
    from hepta.artifact_publication import publish_verified
    target = Path(destination).absolute()
    if target.exists() or target.is_symlink():
        raise ValueError('JSON output must be a new file')
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.parent.resolve() != target.parent:
        raise ValueError('JSON output parent must not traverse a symlink')
    payload = (json.dumps(value, sort_keys=True, indent=2, allow_nan=False) + '\n').encode()
    with tempfile.TemporaryDirectory(prefix='.hepta-json-view-', dir=target.parent) as temporary:
        stage = Path(temporary) / 'view.json'
        with stage.open('xb') as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        receipt = publish_verified(stage, target, payload)
    return {'schema': 'hepta.hia.json-view-output.v1', 'ok': True, 'output': str(target), 'view_schema': value['schema'], 'publication': receipt}

def main(argv=None):
    parser = argparse.ArgumentParser(prog='hia-reference', description=__doc__)
    parser.add_argument('--version', action='version', version='hia-reference ' + __version__)
    hia = parser
    hia_actions = parser.add_subparsers(dest='hia_action', required=True)
    hia_actions.add_parser('routes')
    from hepta.hia_schema import LATEST_CORE_SCHEMA, PRIMITIVE_PROFILES
    catalog_parser = hia_actions.add_parser('catalog', help='Complete generated instruction and resource contract for an exact Core version')
    catalog_parser.add_argument('--schema', choices=tuple(PRIMITIVE_PROFILES), default=LATEST_CORE_SCHEMA)
    for action in ('import-assembly', 'render-assembly', 'check-assembly'):
        h = hia_actions.add_parser(action, help='Explicit typed HIA assembly over the same checked Core')
        h.add_argument('input', help='HIA assembly text; render-assembly accepts checked Core JSON')
        if action != 'check-assembly':
            h.add_argument('--output', '-o', help='New output file; existing files are never replaced')
    for action in ('verify', 'inspect', 'run', 'emit', 'build', 'patch', 'normalize', 'impact', 'import-composite-v2', 'upgrade-v7', 'edit-query', 'edit-apply', 'edit-batch-query', 'edit-batch-apply', 'verify-translation', 'optimize', 'verify-optimization', 'fold-constants', 'build-optimized', 'optimize-guarded', 'verify-guarded', 'build-guarded', 'optimize-narrowed', 'verify-narrowed', 'build-narrowed', 'optimize-guarded-narrowed', 'verify-guarded-narrowed', 'build-guarded-narrowed'):
        h = hia_actions.add_parser(action)
        h.add_argument('input', help='Standalone HIA Core JSON program')
        if action in {'verify-translation', 'optimize'}:
            h.add_argument('--function', required=True, help='Exact public scalar function')
            h.add_argument('--timeout-ms', type=int, default=2000, help='Independent translation proof timeout in milliseconds')
            h.add_argument('--json', action='store_true', help='Return the versioned JSON report (also the default for HIA)')
        if action == 'verify-translation':
            h.add_argument('after', help='Candidate standalone HIA JSON program')
        if action == 'optimize':
            h.add_argument('--bridge', required=True, help='Actual pinned native NDU bridge executable')
            h.add_argument('--bridge-build-receipt', required=True, help='Trusted local build receipt binding the bridge and upstream source')
            h.add_argument('--observations', required=True, help='Exact program-bound host observations for abstain and generated proposals')
            h.add_argument('--objective', required=True, help='Fixed objective JSON file')
            h.add_argument('--max-candidates', type=int, default=8, help='Maximum finite proposals, from one through eight')
        if action in {'emit', 'build', 'patch', 'normalize', 'import-composite-v2', 'upgrade-v7', 'edit-query', 'edit-apply', 'edit-batch-query', 'edit-batch-apply', 'fold-constants', 'build-optimized', 'optimize-guarded', 'build-guarded', 'optimize-narrowed', 'build-narrowed', 'optimize-guarded-narrowed', 'build-guarded-narrowed'}:
            h.add_argument('--output', '-o', required=action in {'build', 'build-optimized', 'build-guarded', 'build-narrowed', 'build-guarded-narrowed'})
        if action in {'verify-optimization', 'fold-constants', 'build-optimized', 'optimize-guarded', 'verify-guarded', 'build-guarded', 'optimize-narrowed', 'verify-narrowed', 'build-narrowed', 'optimize-guarded-narrowed', 'verify-guarded-narrowed', 'build-guarded-narrowed'}:
            h.add_argument('--policy', help='Exact versioned optimization policy JSON')
        if action in {'verify-optimization', 'build-optimized', 'verify-guarded', 'build-guarded', 'verify-narrowed', 'build-narrowed', 'verify-guarded-narrowed', 'build-guarded-narrowed'}:
            h.add_argument('--candidate', required=True, help='Actual proposed HIA bytes, never a verification receipt')
        if action in {'optimize-guarded', 'optimize-guarded-narrowed'}:
            h.add_argument('--maximum', type=int, help='Runtime byte-count guard; the complete original fallback remains')
        if action == 'optimize-guarded':
            h.add_argument('--include-induction', action='store_true', help='Also propose same-bound loop increments; each removed check requires proof')
        if action == 'import-composite-v2':
            h.add_argument('--report', help='New file for explicit legacy import and reverification provenance')
        if action == 'upgrade-v7':
            from hepta.hia_schema import PROFILE_V2
            h.add_argument('--legacy-profile', choices=[PROFILE_V2])
            h.add_argument('--report', help='New file for the explicit Core version transition')
        if action == 'edit-batch-query':
            h.add_argument('--selections', required=True, help='JSON list of function/block/output/fields selections')
        if action == 'edit-query':
            h.add_argument('--function', required=True)
            h.add_argument('--block', required=True)
            h.add_argument('--value', required=True, help='SSA output selecting one value-producing instruction')
            h.add_argument('--fields', required=True, help='Comma-separated subset of op,args,attrs')
        if action in {'edit-apply', 'edit-batch-apply'}:
            h.add_argument('--query', required=True)
            h.add_argument('--response', required=True)
        if action == 'run':
            h.add_argument('--function', required=True)
            h.add_argument('--arguments', default='[]')
            h.add_argument('--max-steps', type=int, default=1000000)
            h.add_argument('--max-heap-bytes', type=int, default=1048576)
            h.add_argument('--allocation-fail-at', type=int)
        if action in {'build', 'build-optimized', 'build-guarded', 'build-narrowed', 'build-guarded-narrowed'}:
            h.add_argument('--clang', default='clang')
            h.add_argument('--kind', choices=['shared', 'object'], default='shared')
        if action == 'build':
            h.add_argument('--backend', choices=['llvm', 'native'], default='llvm', help='native writes x86-64 instructions and ELF directly; llvm preserves the existing backend')
            h.add_argument('--linker', default='cc', help='System linker (ld) or C driver for native shared libraries; unused for native objects')
        if action in {'emit', 'build'}:
            h.add_argument('--target', choices=['x86_64-unknown-linux-gnu', 'aarch64-unknown-linux-gnu', 'riscv64-unknown-linux-gnu'], default='x86_64-unknown-linux-gnu')
        if action in {'patch', 'impact'}:
            h.add_argument('--request', required=True)
        if action == 'verify':
            h.add_argument('--rust-shadow-bin', help='opt-in exact-byte Rust shadow executable (not native admission)')
            h.add_argument('--rust-shadow-sha256', help='required exact lowercase SHA-256 when Rust shadow is selected')
            h.add_argument('--rust-shadow-profile', choices=('scalar', 'owned'), help='scalar or Owner/Loan Rust shadow; requires both executable flags')
    args = parser.parse_args(argv)
    try:
        from hepta.hia_program import verify_program
        from hepta.hia_routes import admit_route, route_inventory
        from hepta.hia_program_tools import read_bounded, decode_json, inspect_program, apply_program_patch, publish_program
        if args.hia_action == 'routes':
            output_json(route_inventory())
            return 0
        if args.hia_action == 'catalog':
            from hepta.hia_opcodes import opcode_catalog
            output_json(opcode_catalog(args.schema))
            return 0
        if args.hia_action in {'import-assembly', 'render-assembly', 'check-assembly'}:
            from hepta.hia_agent_assembly import render_assembly, diagnose_assembly
            raw = read_bounded(args.input)
            if args.hia_action == 'check-assembly':
                result = diagnose_assembly(raw)
                output_json(result)
                return 0 if result['accepted'] else 1
            if args.hia_action == 'import-assembly':
                program = admit_route('agent-assembly', raw)
                output_json(publish_program(program, args.output) if args.output else program.as_dict())
                return 0
            program = admit_route('standalone-hia', raw)
            text = render_assembly(program)
            if args.output:
                from hepta.artifact_publication import publish_verified
                target = Path(args.output).absolute()
                if target.exists() or target.is_symlink():
                    raise ValueError('Assembly output must be a new file')
                target.parent.mkdir(parents=True, exist_ok=True)
                if target.parent.resolve() != target.parent:
                    raise ValueError('Assembly output parent must not traverse a symlink')
                with tempfile.TemporaryDirectory(prefix='.hepta-assembly-', dir=target.parent) as temporary:
                    stage = Path(temporary) / 'program.hepta'
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
        if args.hia_action == 'import-composite-v2':
            from hepta.hia_core_upgrade import import_legacy_composite_v2
            program, report = import_legacy_composite_v2(read_bounded(args.input))
            if args.report:
                with Path(args.report).open('x', encoding='utf-8') as stream:
                    json.dump(report, stream, sort_keys=True, indent=2)
                    stream.write('\n')
            output_json(publish_program(program, args.output) if args.output else program.as_dict())
            return 0
        program = admit_route('standalone-hia', read_bounded(args.input))
        if args.hia_action == 'verify-translation':
            from hepta.hia_translation_validation import validate_translation
            report = validate_translation(program, read_bounded(args.after), function=args.function, timeout_ms=args.timeout_ms)
            output_json(report)
            return 0 if report.get('status') == 'proved' else 1
        if args.hia_action == 'optimize':
            import time
            started = time.perf_counter_ns()
            from hepta.hia_finite_actions import propose_candidates
            from hepta.hia_ndu_optimizer import rank_candidates
            proposals = propose_candidates(program, function=args.function, max_candidates=args.max_candidates)
            objective = decode_json(read_bounded(args.objective, limit=65536))
            observations = decode_json(read_bounded(args.observations, limit=1024 * 1024))
            if type(observations) is not dict or type(observations.get('abstain')) is not dict or type(observations['abstain'].get('search_ns')) is not int or (observations['abstain']['search_ns'] < 0):
                raise ValueError('abstain observation requires a nonnegative exact search_ns')
            supplied = observations['abstain']['search_ns']
            preparation_ns = time.perf_counter_ns() - started
            observations['abstain']['search_ns'] = supplied + preparation_ns
            report = rank_candidates(program, proposals, observations, function=args.function, bridge={'binary': args.bridge, 'build_receipt': args.bridge_build_receipt}, objective=objective, timeout_ms=args.timeout_ms)
            report['cli_preparation_cost'] = {'measured_ns': preparation_ns, 'charged_once_to': 'abstain.search_ns', 'supplied_abstain_search_ns': supplied, 'charged_abstain_search_ns': observations['abstain']['search_ns'], 'includes': ['finite_proposal_regeneration', 'bounded_input_decoding', 'lazy_module_imports']}
            output_json(report)
            return 0
        if args.hia_action in {'optimize-narrowed', 'verify-narrowed', 'build-narrowed', 'optimize-guarded-narrowed', 'verify-guarded-narrowed', 'build-guarded-narrowed'}:
            from hepta.hia_narrowing import propose_modular_narrowing, verify_modular_narrowing, build_narrowed_native, propose_guarded_narrowing, verify_guarded_narrowing, build_guarded_narrowed_native
            guarded = 'guarded' in args.hia_action
            propose = propose_guarded_narrowing if guarded else propose_modular_narrowing
            verify = verify_guarded_narrowing if guarded else verify_modular_narrowing
            build = build_guarded_narrowed_native if guarded else build_narrowed_native
            policy = decode_json(read_bounded(args.policy)) if args.policy else None
            if args.hia_action.startswith('optimize-'):
                proposal = propose(program, maximum=args.maximum) if guarded else propose(program)
            else:
                proposal = decode_json(read_bounded(args.candidate))
            if args.hia_action.startswith('build-'):
                output_json(build(program, proposal, args.output, policy=policy, clang=args.clang, kind=args.kind))
                return 0
            result = verify(program, proposal, policy)
            if args.hia_action.startswith('optimize-'):
                wrapper = {'schema': 'hepta.hia.narrowing-cli-proposal.v1', 'verification': result}
                if result['status'] == 'verified':
                    if args.output:
                        wrapper['publication'] = publish_json_view(proposal, args.output)
                    else:
                        wrapper['proposal'] = proposal
                output_json(wrapper)
            else:
                output_json(result)
            return 0 if result['status'] == 'verified' else 1
        if args.hia_action in {'optimize-guarded', 'verify-guarded', 'build-guarded'}:
            from hepta.hia_guarded_optimization import propose_guarded_reduction, verify_guarded_optimization, build_guarded_native
            policy = decode_json(read_bounded(args.policy)) if args.policy else None
            proposal = propose_guarded_reduction(program, maximum=args.maximum, include_induction=args.include_induction) if args.hia_action == 'optimize-guarded' else decode_json(read_bounded(args.candidate))
            if args.hia_action == 'build-guarded':
                result = build_guarded_native(program, proposal, args.output, policy=policy, clang=args.clang, kind=args.kind)
                output_json(result)
                return 0
            result = verify_guarded_optimization(program, proposal, policy)
            if args.hia_action == 'optimize-guarded':
                wrapper = {'schema': 'hepta.hia.guarded-optimization-proposal.v1', 'verification': result}
                if result['status'] == 'verified':
                    if args.output:
                        wrapper['publication'] = publish_json_view(proposal, args.output)
                    else:
                        wrapper['proposal'] = proposal
                output_json(wrapper)
            else:
                output_json(result)
            return 0 if result['status'] == 'verified' else 1
        if args.hia_action in {'verify-optimization', 'fold-constants', 'build-optimized'}:
            from hepta.hia_optimization import verify_optimization, fold_constants, build_optimized_native
            policy = decode_json(read_bounded(args.policy)) if args.policy else None
            generation = None
            if args.hia_action == 'fold-constants':
                candidate, generation = fold_constants(program)
            else:
                candidate = admit_route('standalone-hia', read_bounded(args.candidate))
            if args.hia_action == 'build-optimized':
                result = build_optimized_native(program, candidate, args.output, policy=policy, clang=args.clang, kind=args.kind)
                output_json(result)
                return 0
            result = verify_optimization(program, candidate, policy)
            if generation is not None:
                wrapper = {'schema': 'hepta.hia.optimization-proposal.v1', 'generation': generation, 'verification': result}
                if result['status'] == 'verified':
                    if args.output:
                        wrapper['publication'] = publish_program(candidate, args.output)
                    else:
                        wrapper['program'] = candidate.as_dict()
                output_json(wrapper)
            else:
                output_json(result)
            return 0 if result['status'] == 'verified' else 1
        if args.hia_action == 'upgrade-v7':
            from hepta.hia_core_upgrade import upgrade_core_to_v7
            revised, receipt = upgrade_core_to_v7(program, legacy_profile=args.legacy_profile)
            if args.report:
                publish_json_view(receipt, args.report)
            output_json(publish_program(revised, args.output) if args.output else revised.as_dict())
            return 0
        if args.hia_action == 'edit-batch-query':
            from hepta.hia_edit_batch import prepare_batch
            query = prepare_batch(program, decode_json(read_bounded(args.selections)))
            output_json(publish_json_view(query, args.output) if args.output else query)
            return 0
        if args.hia_action == 'edit-batch-apply':
            from hepta.hia_edit_batch import apply_batch, MAX_QUERY_BYTES, MAX_RESPONSE_BYTES
            revised, receipt = apply_batch(program, read_bounded(args.query, limit=MAX_QUERY_BYTES), read_bounded(args.response, limit=MAX_RESPONSE_BYTES))
            if args.output:
                receipt['publication'] = publish_program(revised, args.output)
                receipt['status'] = 'verified_new_snapshot_published'
            else:
                receipt['program'] = revised.as_dict()
            output_json(receipt)
            return 0
        if args.hia_action == 'edit-query':
            from hepta.hia_edit_query import prepare_edit
            query = prepare_edit(program, function=args.function, block=args.block, output=args.value, fields=args.fields.split(','))
            output_json(publish_json_view(query, args.output) if args.output else query)
            return 0
        if args.hia_action == 'edit-apply':
            from hepta.hia_edit_query import apply_edit, MAX_RESPONSE_BYTES
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
            report = {**program.report(), 'status': 'standalone_core_checked', 'native_executed': False}
            selected_shadow = any((getattr(args, name, None) is not None for name in ('rust_shadow_bin', 'rust_shadow_sha256', 'rust_shadow_profile')))
            if selected_shadow:
                if not args.rust_shadow_bin or not args.rust_shadow_sha256:
                    raise ValueError('Rust shadow requires both --rust-shadow-bin and --rust-shadow-sha256')
                from hepta.hia_rust_crosscheck import crosscheck_rust_shadow
                report['rust_crosscheck'] = crosscheck_rust_shadow(program, args.rust_shadow_bin, executable_sha256=args.rust_shadow_sha256, profile=args.rust_shadow_profile or 'owned')
            output_json(report)
            return 0
        if args.hia_action == 'inspect':
            output_json(inspect_program(program))
            return 0
        if args.hia_action == 'run':
            from hepta.hia_program_runtime import execute_program, HIAProgramTrap, HIAProgramBudgetExceeded
            if len(args.arguments.encode('utf-8')) > 65536:
                raise ValueError('HIA entry arguments exceed their byte limit')
            try:
                result = execute_program(program, args.function, decode_json(args.arguments), max_steps=args.max_steps, max_heap_bytes=args.max_heap_bytes, allocation_fail_at=args.allocation_fail_at)
            except (HIAProgramTrap, HIAProgramBudgetExceeded) as exc:
                output_json(exc.report)
                return 1
            output_json(result)
            return 0 if result.get('status') == 'returned' else 1
        if args.hia_action in {'emit', 'build'}:
            if args.hia_action == 'build' and args.backend == 'native':
                if args.target != 'x86_64-unknown-linux-gnu':
                    raise ValueError('E_HIA_PROGRAM_NATIVE: direct machine backend supports x86_64-unknown-linux-gnu')
                from hepta.hia_program_native import build_program_machine
                result = build_program_machine(program, args.output, kind=args.kind, linker=args.linker)
                output_json(result)
                return 0 if result.get('ok') is True else 1
            from hepta.hia_program_llvm import emit_program_llvm, build_program_native
            if args.hia_action == 'build':
                result = build_program_native(program, args.output, clang=args.clang, kind=args.kind, target=args.target)
                output_json(result)
                return 0 if result.get('ok') is True else 1
            ir = emit_program_llvm(program, target=args.target)
            if args.output:
                destination = Path(args.output).absolute()
                destination.parent.mkdir(parents=True, exist_ok=True)
                with destination.open('x', encoding='utf-8') as stream:
                    stream.write(ir.text)
                output_json({'schema': 'hepta.hia.llvm-output.v1', 'ok': True, 'program_sha256': program.sha256, 'output': str(destination), 'status': 'emitted_not_compiled'})
            else:
                print(ir.text, end='')
            return 0
        if args.hia_action == 'impact':
            from hepta.hia_patch_impact import analyze_patch_impact
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
        raise ValueError('unsupported HIA action')
    except (OSError, ValueError, UnicodeError, subprocess.SubprocessError) as error:
        output_json({'ok': False, 'status': 'error', 'diagnostics': [{'code': 'E_DRIVER', 'message': str(error), 'phase': 'driver'}]})
        return 2
    return 0
if __name__ == '__main__':
    raise SystemExit(main())
