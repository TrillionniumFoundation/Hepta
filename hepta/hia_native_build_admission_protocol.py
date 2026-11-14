"""Fixed opaque-object ports for native artifact and build admission.

These identifiers name foreign operations. Routing, loop termination, ordered
short circuit and the four complete original acceptance policies live in HIA.
"""

PORTS = (
    'args_signatures', 'signature_imports', 'signature_document',
    'signature_scalar_init', 'signature_fn_next', 'signature_fn_entry',
    'signature_param_init', 'signature_param_next', 'signature_param_allowed',
    'signature_return_length', 'signature_returns_init',
    'signature_returns_next', 'signature_return_allowed',
    'signature_capture_name', 'signature_params_init',
    'signature_params_next', 'signature_params_append', 'signature_scalar_publish',
    'signature_normalize', 'signature_exports_iter',
    'signature_export_fn_next', 'signature_export_contains',
    'signature_export_params_init', 'signature_export_params_next',
    'signature_export_params_append', 'signature_export_publish',
    'signature_result',
    'args_native', 'native_get', 'native_installation_differs',
    'native_context_present', 'native_context_differs', 'native_program',
    'native_context', 'native_exports_init', 'native_exports_next',
    'native_exports_append', 'native_exports_finish', 'native_core_differs',
    'native_signatures_differs', 'native_exports_list_init',
    'native_exports_list_next', 'native_exports_list_append',
    'native_exports_differs', 'native_result',
    'args_build', 'build_get', 'build_context_differs', 'build_artifact_differs',
    'build_installation_differs', 'build_target_differs', 'build_backend_differs',
    'build_metadata_init', 'build_metadata_next', 'build_metadata_unpack',
    'build_metadata_compare', 'build_metadata_truth', 'build_built',
    'build_built_not_dict', 'build_object_ref_not_dict',
    'build_object_ref_differs', 'build_object_sha_differs',
    'build_core_sha_differs', 'build_input_sha_differs',
    'build_implementation_differs', 'build_kind_differs',
    'build_exports_differs', 'build_final_sha_differs', 'build_object_get',
    'build_expected_metadata', 'build_object_metadata_differs',
    'build_object_bytes_sha_differs', 'build_ref_object_sha_differs',
    'build_output_is_object', 'build_object_bytes_differs',
    'build_result', 'receipt_result',
    'reject_native_subject', 'reject_native_identity', 'reject_build_subject',
    'reject_metadata', 'reject_build_bytes', 'reject_object',
)
PORT = {name: index + 1 for index, name in enumerate(PORTS)}
MODES = {'signatures': 1, 'native': 2, 'build_inputs': 3, 'build_receipt': 4}
