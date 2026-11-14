"""One frozen R8 compilation, then at most one capacity-admitted HIA pack."""
from pathlib import Path
import json
import shutil
import sys
import time
import traceback

sys.path.insert(0, str(Path(__file__).resolve().parent))
import size_support as S
from retained_pack_contract import _frame, _elf_structure


def initial_result():
    return {'schema': 'hepta.u32-r8-size-pack-observation.v1', 'status': 'FAIL',
        'compile_calls_attempted': 0, 'pack_calls_attempted': 0, 'semantic_native_cases': 0,
        'semantic_vm_cases': 0, 'aggregate_cases': 0, 'ELF_exec_calls': 0,
        'matching_current_new_cold': False, 'ordinary_compiler_admission': False,
        'production_profile_changed': False, 'ordinary_SOURCE_rebound': False,
        'qualification': False, 'whole_native': False, 'automatic_retry': False,
        'finalization_errors': []}


def child():
    result = initial_result()
    before = None
    try:
        S.dump(S.OUT / 'CHILD-RUNTIME.json', S.runtime())
        S.dump(S.OUT / 'CHILD-CONTROLS.json', S.controls())
        S.dump(S.OUT / 'CHILD-INPUTS.json', S.input_guard())
        S.dump(S.OUT / 'CHILD-PROJECTION.json', S.projection_guard())
        before = S.source_snapshot(S.OUT / 'SOURCE-CHILD-BEFORE.json')
        source = S.input_bytes('R8.hepta')
        compiler = S.ROOT / 'inputs/u32/B3.image.bin'
        result['compile_calls_attempted'] = 1
        image, observed = S.observe('compile-r8', compiler, source)
        S.write(S.OUT / 'R8.u32.image.bin', image)
        result['compile'] = observed
        result['image'] = S.pin(image)
        controller = S.input_bytes('retained/controller.image.bin')
        representation = S.input_bytes('retained/representation.image.bin')
        images = (controller, representation, image)
        offsets = []
        cursor = 1024
        for value in images:
            offsets.append(cursor)
            cursor = (cursor + len(value) + 15) & -16
        elf_size = (offsets[-1] + len(image) + 4095) & -4096
        frame_size = 48 + sum(map(len, images))
        S.require(offsets == [1024, 60928, 491200], 'fixed retained image layout differs')
        size = {'actual_image_bytes': len(image), 'old_ordinary_R8_image_bytes': 562746,
            'actual_reduction_bytes': 562746-len(image), 'actual_frame_bytes': frame_size,
            'required_aligned_ELF_bytes': elf_size, 'physical_image_offsets': offsets,
            'original_capacity': S.CAPACITY, 'max_image_by_frame': 558378,
            'max_image_by_ELF': 557376, 'exact_minimum_reduction_from_old': 5370,
            'historical_conservative_growth_shortfall': 6600,
            'frame_admitted': len(image) <= 558378 and frame_size <= S.CAPACITY,
            'ELF_admitted': len(image) <= 557376 and elf_size <= S.CAPACITY}
        # This original function only frames bytes. It does not execute HIA or
        # bypass the public builder's independently retained R5 source admission.
        try:
            package = _frame(images)
        except BaseException as error:
            size['original_frame_exception'] = {'type': type(error).__name__, 'message': str(error)}
            S.dump(S.OUT / 'SIZE-ADMISSION.json', size)
            result['status'] = 'SIZE_REJECTED_NO_PACK'
            result['size'] = size
            raise
        S.dump(S.OUT / 'SIZE-ADMISSION.json', size)
        result['size'] = size
        if not (size['frame_admitted'] and size['ELF_admitted']):
            result['status'] = 'SIZE_REJECTED_NO_PACK'
            raise ValueError('real R8 image exceeds unchanged frame or stricter ELF capacity')
        S.require(len(package) == frame_size, 'actual original frame size differs')
        S.write(S.OUT / 'packer-input.bin', package)
        result['pack_calls_attempted'] = 1
        elf, packed = S.observe('pack-r8', S.ROOT / 'inputs/retained/packer.image.bin', package)
        inspection = _elf_structure(elf, images)
        S.require(len(elf) == elf_size and inspection['file_bytes'] == elf_size,
                  'actual HIA ELF size differs from original layout')
        # No executable permission, execution, profile registration or publication.
        S.write(S.OUT / 'R8.private-nonexecuted.elf.bin', elf)
        result.update(pack=packed, ELF=S.pin(elf), elf_inspection=inspection,
                      status='PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY')
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        for name, operation in (
            ('SOURCE', lambda: S.same_source(before, S.OUT / 'SOURCE-CHILD-AFTER.json')),
            ('INPUTS', S.input_guard), ('CONTROLS', S.controls),
            ('RUNTIME', S.runtime), ('PROJECTION', S.projection_guard)):
            try:
                value = operation()
                if name != 'SOURCE':
                    S.dump(S.OUT / (name+'-CHILD-AFTER.json'), value)
            except BaseException as error:
                result['status'] = 'FAIL'
                result['finalization_errors'].append({'name': name, 'type': type(error).__name__,
                    'error': str(error), 'traceback': traceback.format_exc()})
        try:
            result['actual_frames'] = S.frame_inventory(result['compile_calls_attempted'], result['pack_calls_attempted'],
                require_complete=result['status'] == 'PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY')
        except BaseException as error:
            result['status'] = 'FAIL'
            result['finalization_errors'].append({'name': 'FRAME-INVENTORY', 'type': type(error).__name__, 'error': str(error)})
        S.dump(S.OUT / 'RESULT.json', result)
        print(json.dumps(result, sort_keys=True), flush=True)
    return 0 if result['status'] == 'PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY' else 1


def driver():
    S.require(not S.OUT.exists() and not S.OUT.is_symlink(), 'unique output already exists; do not retry or overwrite')
    S.OUT.mkdir(parents=True, mode=0o700)
    S.write(S.OUT / 'PLAN.json', S.PLAN_RAW)
    S.write(S.OUT / 'RUNNER.py', Path(__file__).read_bytes())
    result = initial_result()
    before = None
    result['owner_launch_intents'] = 0
    started = time.monotonic_ns()
    try:
        S.dump(S.OUT / 'RUNTIME-PREFLIGHT.json', S.runtime())
        S.dump(S.OUT / 'CONTROLS-PREFLIGHT.json', S.controls())
        S.dump(S.OUT / 'INPUTS-PREFLIGHT.json', S.input_guard())
        S.dump(S.OUT / 'PROJECTION-PREFLIGHT.json', S.projection_guard())
        free = shutil.disk_usage(S.OUT).free
        S.dump(S.OUT / 'STORAGE-PREFLIGHT.json', {'free_bytes': free,
            'required_free_bytes': S.PLAN['storage']['required_free_bytes'],
            'source_tree_copy': False, 'original_ZIP_copy': False})
        S.require(free >= S.PLAN['storage']['required_free_bytes'], 'raw evidence reserve unavailable')
        before = S.source_snapshot(S.OUT / 'SOURCE-OUTER-BEFORE.json')
        sys.path.insert(0, str(S.SOURCE))
        from tools.hia_selfhost_process_owner import run_owned
        command = [sys.executable, '-I', '-S', '-B', str(Path(__file__).resolve()),
                   '--plan-sha256', S.pin(S.PLAN_RAW)['sha256'], '--child']
        env = S.PLAN['environment']
        S.dump(S.OUT / 'LAUNCH-INTENT.json', {'command': command, 'cwd': str(S.SOURCE),
            'env': env, 'supervisor_env': env, 'qualification_seconds': 180, 'cleanup_seconds': 3,
            'compile_and_conditional_pack_share_one_budget': True, 'product_retries': 0})
        result['owner_launch_intents'] = 1
        returned = run_owned(command, cwd=S.SOURCE, env=env, supervisor_env=env,
            stdout_path=S.OUT / 'child.stdout.bin', stderr_path=S.OUT / 'child.stderr.bin',
            receipt_path=S.OUT / 'OWNER.json', qualification_seconds=180, cleanup_seconds=3)
        S.dump(S.OUT / 'OWNER-RETURNED.json', returned)
        result['owner'] = returned
        S.owner_return(S.OUT / 'OWNER.json', returned)
        S.complete_owner(returned, 180)
        observed = json.loads((S.OUT / 'RESULT.json').read_bytes())
        result['child'] = observed
        S.require(observed['status'] == 'PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY'
            and observed['compile_calls_attempted'] == observed['pack_calls_attempted'] == 1
            and observed['finalization_errors'] == [], 'private size/pack observation did not pass')
        result['status'] = 'PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY'
    except BaseException as error:
        result.update(error_type=type(error).__name__, error=str(error), traceback=traceback.format_exc())
        traceback.print_exc()
    finally:
        for name, operation in (
            ('SOURCE', lambda: S.same_source(before, S.OUT / 'SOURCE-OUTER-AFTER.json')),
            ('INPUTS', S.input_guard), ('CONTROLS', S.controls), ('RUNTIME', S.runtime),
            ('PROJECTION', S.projection_guard)):
            try:
                value = operation()
                if name != 'SOURCE':
                    S.dump(S.OUT / (name+'-OUTER-AFTER.json'), value)
            except BaseException as error:
                result['status'] = 'FAIL'
                result['finalization_errors'].append({'name': name, 'type': type(error).__name__,
                    'error': str(error), 'traceback': traceback.format_exc()})
        if (S.OUT / 'RESULT.json').is_file():
            try:
                result['actual_child_result'] = json.loads((S.OUT / 'RESULT.json').read_bytes())
                for key in ('compile_calls_attempted', 'pack_calls_attempted'):
                    result[key] = result['actual_child_result'][key]
            except BaseException as error:
                result['status'] = 'FAIL'
                result['compile_calls_attempted'] = None
                result['pack_calls_attempted'] = None
                result['finalization_errors'].append({'name':'CHILD-TERMINAL',
                    'type':type(error).__name__,'error':str(error),
                    'traceback':traceback.format_exc()})
        elif result['owner_launch_intents']:
            result['compile_calls_attempted'] = None
            result['pack_calls_attempted'] = None
            result['missing_child_terminal_not_zero_calls'] = True
        result['elapsed_ns'] = time.monotonic_ns()-started
        S.dump(S.OUT / 'OUTER.json', result)
        try:
            raw = S.raw_inventory()
        except BaseException as error:
            S.dump(S.OUT / 'RAW-INVENTORY-ERROR.json', {'type':type(error).__name__,
                'error':str(error),'traceback':traceback.format_exc()})
            return 1
        print(json.dumps({'status':result['status'], 'raw':raw, 'qualification':False,
            'whole_native':False, 'matching_current_new_cold':False}, sort_keys=True),flush=True)
    return 0 if result['status'] == 'PASS_EXPLICIT_U32_SIZE_AND_PRIVATE_PACK_ONLY' else 1


if __name__ == '__main__':
    args=sys.argv[1:]
    S.require(len(args) in (2,3) and args[0]=='--plan-sha256' and args[1]==S.pin(S.PLAN_RAW)['sha256']
        and (len(args)==2 or args[2]=='--child'), 'exact reviewed plan SHA and arguments required')
    raise SystemExit(child() if len(args)==3 else driver())
