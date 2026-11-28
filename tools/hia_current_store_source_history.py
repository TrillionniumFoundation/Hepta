"""Compose current physical Store inputs with the retained frozen source reader.

The original reader and both prior fixtures remain immutable. Its predecessor
view is explicit data; captures and complete_current always describe actual
files from the selected repository.
"""
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from tools import hia_frozen_component_sources as frozen

ROOT = Path(__file__).resolve().parents[1]
SELF = 'tools/hia_current_store_source_history.py'
_EXECUTED_SELF_PATH = Path(__file__).resolve(strict=True)
_EXECUTED_SELF_BYTES = _EXECUTED_SELF_PATH.read_bytes()
WINDOW_HELPER = 'tools/hia_evaluation_window_history.py'
WINDOW_HELPER_PIN = {
    'bytes': 8876, 'sha256': '08054cf59af6e93453fc370d08c64d1b14e9072012f69652cfae747083346cfa',
}
ENGINE = 'tools/hia_frozen_component_sources.py'
ENGINE_PIN = {
    'bytes': 15561, 'sha256': '60a30ab07d6c58ef0523531636a3250cc9e75402bffe75a07115012efa5d0774',
}
WINDOW_CURRENT = {
    'hepta/hia_agent_service.py': {
        'bytes': 268730, 'sha256': '353bd2673cc4f269c9c2d6cbf226d8956703d434ca960214864f56689d8f82c1'},
    'hepta/hia_evaluation_native.py': {
        'bytes': 47978, 'sha256': 'f9b25023b393f7b621b515b9b7f481a992715f15a386bf8c2457e2eb3136a73d'},
    'tests/test_hia_evaluation_native.py': {
        'bytes': 50437, 'sha256': '333abf8107aec87e42002c0a2f0218aeacdf9837642e443563f64272d6dc5083'},
}
UNCHANGED = {
    name: dict(identity) for name, identity in frozen.CURRENT.items()
    if name not in WINDOW_CURRENT
}
COLD_HELPER = 'tools/hia_evaluation_cold_source_history.py'
COLD_HELPER_PIN = {
    'bytes': 8539, 'sha256': 'd3d1375b2fcd4ab670cb7a2611d36077c9a31acd9b0d2290c8bc482d6077d91c',
}
COLD_FIXTURE = 'tests/fixtures/hia_evaluation_native_cold_history_v1.json'
COLD_CURRENT = {**deepcopy(WINDOW_CURRENT), 'tests/test_hia_evaluation_native.py': {
    'bytes': 50368, 'sha256': '8e55e6c0adda8629c5c484173262b63f726c727b2eeefbaf4926622e59a6cec0'}}
WINDOW_PHYSICAL_CURRENT = {**deepcopy(frozen.CURRENT), **deepcopy(WINDOW_CURRENT)}
PHYSICAL_CURRENT = {**deepcopy(frozen.CURRENT), **deepcopy(COLD_CURRENT)}
NATIVE_TOOLS = 'tests/test_hia_agent_native_tools.py'
NATIVE_TOOLS_CURRENT = {
    'bytes': 47052, 'sha256': '9af14ac9dc15cafcd60be2c4e8690fafa778b41bc66c73379e9490ac67376fc2',
}
CALLER_HELPER = 'tools/hia_current_caller_source_history.py'
CALLER_HELPER_PIN = {
    'bytes': 3838, 'sha256': '9f773647bacc0a59f8ddff7b45e27f9d5474bb96a7f2368fa7e18a2a98141558',
}
SCHEMA = 'hepta.hia.current-store-source-composition-review.v1'

BROAD_HELPER = 'tools/hia_native_cold_caller_history.py'
BROAD_HELPER_PIN = {
    'bytes': 44659, 'sha256': '0beac4d7b6f9ca0f87aa7b8f6b63cf2ec0a234228e7358d8ff0f33f8e78ee6e1',
}
# Exact current identities are independent of optional selected-root authority.
# All five production members are excluded from the generic prior view.
BROAD_CURRENT = {
    "hepta/hia_agent_service.py": {'bytes': 268278, 'sha256': 'afc92b555bd0dfa23f25c4f9c2661af30853474342f4e32a036d37c1ce663a57'},
    "tests/hia_composite_function_fixture.py": {'bytes': 22025, 'sha256': 'c1e14fcee5e77563319e6ec96e536852b63e9813b46640b124858c049a5487b9'},
    "tests/hia_service_bootstrap_controls.py": {'bytes': 26208, 'sha256': 'cafbfb896879f7679aefe5787b9684c00e364ce01d4acb8586da9b5d67c258ab'},
    "tests/hia_service_lease_controls.py": {'bytes': 35680, 'sha256': '1f65b1db4aa29fe0653fd6bc5214ba13ab80dec5e5d38e3f6a1f3a24083cf587'},
    "tests/hia_slot_operations_component_fixture.py": {'bytes': 8904, 'sha256': '257c95b3d48ce31f261c075f9ef9b9b704311e20451d476150edece4c748b34d'},
    "tests/test_hia_agent_installed_resources.py": {'bytes': 74769, 'sha256': '03ef282856ab2f587a120a4b7e38e55c78c5f74d29dcd3a37716cdf54f8b09da'},
    "tests/test_hia_agent_journal_extensions.py": {'bytes': 16086, 'sha256': '41ab738562230155fd7314042e5647c6caf01baf655c92d4d97805e9838564f1'},
    "tests/test_hia_agent_journal_native.py": {'bytes': 48895, 'sha256': 'ca519da2e7dd577e30a9465544376c0bc5637d21b5a9a3eea5882127121d1933'},
    "tests/test_hia_agent_stdio.py": {'bytes': 44700, 'sha256': 'fa3c4279373efdb47bfaf71b179014e44f84ef1d4b9e931a5c09a3467a873531'},
    "tests/test_hia_artifact_delivery.py": {'bytes': 13064, 'sha256': '11865a8a64addd4a4bbc71674572945f7150ea6d9274209489f30f5fc65d4cba'},
    "tests/test_hia_artifact_publication_native.py": {'bytes': 19607, 'sha256': 'de92f2dc85c187fb0834de801899801c6cb1c36ab03909dab07554bcf15ee0dc'},
    "tests/test_hia_artifact_publication_route.py": {'bytes': 14826, 'sha256': 'ed4b466b20e6c7b96c671d56263b0501b1a3d20ff314cf47e5c75e52158af740'},
    "tests/test_hia_byte_wrapper_native.py": {'bytes': 21198, 'sha256': 'ab6b26012e6c8b669f1ef05c8454f8e39c90a13e024241c767dfffdf41154a29'},
    "tests/test_hia_candidate_budget_native.py": {'bytes': 47663, 'sha256': 'c57d05e69b9e646bf07f77161f16943d0ea6b3d400216439940e5902bfe994d1'},
    "tests/test_hia_capability_renaming_native.py": {'bytes': 12366, 'sha256': '1d29ba34ca01a52230be92250b2e6f10a0fb3e08553e44f185d6f2cd11108004'},
    "tests/test_hia_cli_native.py": {'bytes': 62446, 'sha256': '81c45847a2c5f44cbdfee0632dc576954602067587cc8fe0eb35f740206601d6'},
    "tests/test_hia_composite_native_composition.py": {'bytes': 10163, 'sha256': '3765cde070080da3b1b89e660d08269f8db9f0a54b47a64860958ad3c5dd99aa'},
    "tests/test_hia_composite_types_native.py": {'bytes': 45857, 'sha256': '58c9b06ec4a49f2faed2c7878e451d47f6565e057aef9e382b48efd6ddc4779d'},
    "tests/test_hia_continuation_native.py": {'bytes': 47325, 'sha256': 'c7de9ccf59c488826350513c7e4197cbf35864817f249d2d6c779ac041f843f6'},
    "tests/test_hia_core_admission_cli.py": {'bytes': 31112, 'sha256': '5f5f7f1e40d32353b0503eeb796a0fc35af7a550d532cd2134916ebd95ccf892'},
    "tests/test_hia_core_admission_native.py": {'bytes': 28747, 'sha256': '26bdf9a5223ce3e06e9a2d76bbda73213c31efbe166ce784c8e8e69ee4506757'},
    "tests/test_hia_core_emitter_native.py": {'bytes': 24733, 'sha256': 'e6403926b548e782db6c09ab7b8edd922b58f5b9c8e74050dc1814cff63d3713'},
    "tests/test_hia_core_json_bytes_native.py": {'bytes': 23358, 'sha256': '5b5482edee36e46b517a398f852dbc2b00c0616f48a971d36c7ffdbf3f413a8e'},
    "tests/test_hia_core_lowering_native.py": {'bytes': 34348, 'sha256': '796e08806a0d633a07b8d509df3d29100042376a26db57a3599eaf10e402bc4d'},
    "tests/test_hia_core_module_graph_native.py": {'bytes': 33305, 'sha256': 'ae438a098da1b0dc82a5e35271dd198a7e4d7b2f187bd47b85f131655611d640'},
    "tests/test_hia_core_patch_cli.py": {'bytes': 17630, 'sha256': '02ef8c624cfcf901e281c3169fb2e2223d495affaf1ff5107ee97aa2c8a294a2'},
    "tests/test_hia_core_patch_native.py": {'bytes': 26329, 'sha256': 'e28bd4cc0adef96b8c6173cfd51a49cf7e44c151147868e844dd160e8aff5477'},
    "tests/test_hia_core_patch_result_cli.py": {'bytes': 28818, 'sha256': '794fdeacc7004dbefc0a6f62544cc98bd9b3896d2d28e5c69b82f5cb3f49b04d'},
    "tests/test_hia_core_workspace_json_native.py": {'bytes': 24628, 'sha256': '2b31a3df83f84b86f805cb21549441457766f71a27fda0b15c658ba5e855e608'},
    "tests/test_hia_core_workspace_pipeline.py": {'bytes': 23407, 'sha256': '056cc080e82bc10949e119a4922b92748871313df1ed803f9377a855e51c9ab2'},
    "tests/test_hia_cost_ledger_native.py": {'bytes': 26137, 'sha256': '13b677939273323814166ae31aa154caa47fa8dccf83dfbf1076296ef54ed7c0'},
    "tests/test_hia_default_native_release.py": {'bytes': 58380, 'sha256': 'f9552d7acf5ad24a733b8b3a66724aee4a4e591b83377545287f745b79dd6c15'},
    "tests/test_hia_emission_native.py": {'bytes': 59098, 'sha256': '1cf70583e3e663b9106e814fc2ba60f63ae7e7d8b94311dd28cb32a3f8a0818c'},
    "tests/test_hia_evaluation_capture.py": {'bytes': 18026, 'sha256': '4e129ebb1190425823462d2046a08d79850c1f6c2fb981b473066711ec6e7214'},
    "tests/test_hia_evaluation_native.py": {'bytes': 50228, 'sha256': '091164ad78e1d3fab04e9410176b259b4a80f1e3b4b0c92c0da14743f2a43ab2'},
    "tests/test_hia_execution_budget_native.py": {'bytes': 56700, 'sha256': '0e78c223a6b905a13497db0090405e81b42d99f75ec321f92c491e4e362b6d36'},
    "tests/test_hia_execution_observation_native.py": {'bytes': 22950, 'sha256': '84f775dfe79c3c8a714910a52295e6d7c2521b913c65bea2bbb14cf755613336'},
    "tests/test_hia_full_cost_native.py": {'bytes': 27361, 'sha256': '93aa86e3ca9c372cf5dd9b258b631194cbce89ce45d34165ea371031a2f2ea57'},
    "tests/test_hia_function_shape_native.py": {'bytes': 14677, 'sha256': '5a09d5d258c4a101c05ad4e6fc20df2da434c1ee9219dbaeef485d58ad5987f0'},
    "tests/test_hia_generation_retention_native.py": {'bytes': 51570, 'sha256': 'edb25b1a045a27493bea17f0290e60e48af2e019c693cc0aa632f0b61460e85a'},
    "tests/test_hia_instruction_policy_native.py": {'bytes': 12703, 'sha256': '22eebadc6d7df2bda771a71ca073d0b6d90e9dca90d2341c1e57d34830954deb'},
    "tests/test_hia_json_wire_native.py": {'bytes': 34001, 'sha256': 'ee0d0bc9bf0db4104320b6ad89303d8df399b0a7df0cd717e993aa20c6a1fc65'},
    "tests/test_hia_machine_encoding_native.py": {'bytes': 21159, 'sha256': 'ed314306ce02885c077f5bc0f71277fa00f4e9428bb3d4ae81b4592b9a8fac33'},
    "tests/test_hia_machine_instructions_native.py": {'bytes': 28015, 'sha256': '7dbf47f0851b1e145e926763961a17c1cf7b2d62a077d0f47e7b349ba320dff1'},
    "tests/test_hia_machine_object_native.py": {'bytes': 24116, 'sha256': 'ccd7731d438185b7889c788912c9b0514ca3e07fb6238736cbe49f2172be1b8b'},
    "tests/test_hia_machine_plan_native.py": {'bytes': 22439, 'sha256': 'cd92bfd7774710d65f75bf1f632bcf361d35a0f74946f6595d618d16c416e40f'},
    "tests/test_hia_machine_state_native.py": {'bytes': 32718, 'sha256': '593217dab6ebe1d28b75b6cd4d168e9648c19bfde2896d6e283136f3289e6932'},
    "tests/test_hia_native_admission_io.py": {'bytes': 8421, 'sha256': '250898e812fb9de68556a5663c1a05f32fc8e3eea521a40347f59c8a237b1988'},
    "tests/test_hia_native_build_admission_native.py": {'bytes': 47949, 'sha256': '397d3466a30bbe4cfab9c9ce66f1554348b04f631feae1ffd9f78d44c9ae818a'},
    "tests/test_hia_native_build_dispatch.py": {'bytes': 18657, 'sha256': '84ac9d461b11dd29111c50fdca6d9ed6dd05a76c1e5d5d41c7c055976a3369c9'},
    "tests/test_hia_native_delivery.py": {'bytes': 13403, 'sha256': 'f3ce861a16923a264becff4002c73c0c198c0579d75eeea8a5b7e92dabf369a8'},
    "tests/test_hia_native_mapping_native.py": {'bytes': 37641, 'sha256': 'e0dd2b6dbc6ab7131bc7c8e427c715d9d3e8392d5b05455c7060eadfe062c3d9'},
    "tests/test_hia_native_transport_failures.py": {'bytes': 39809, 'sha256': '5573ffa450ff517a9193913c9b26dfb95dd7d9c46fd42b81758b4c93f7807ba9'},
    "tests/test_hia_nominal_json_native.py": {'bytes': 23922, 'sha256': '91b86e99c69ec41397e4cf7fe0d0daeda9094cc7b7f48f4d547da5272a5182bd'},
    "tests/test_hia_nominal_tokens_native.py": {'bytes': 38422, 'sha256': '5615afaeac4458d19177e5124442f310f44758953e9213e170d61e38d02909d8'},
    "tests/test_hia_patch_impact_native.py": {'bytes': 16679, 'sha256': 'e81b445300f8de9e04f706c995610d22e5bba1209aa41fbbd6a4c38665b8f1c5'},
    "tests/test_hia_program_selfhost.py": {'bytes': 52005, 'sha256': '779b1829875aeba75a24d27e6d17414a56b5b0ecc5bc72f94c70d53a4192ed6c'},
    "tests/test_hia_program_shape_native.py": {'bytes': 13271, 'sha256': '2518580fd47c6121a3ea4d6bd989132f58a47def044067c7d4af94806e3a9aae'},
    "tests/test_hia_publication_measurement_native.py": {'bytes': 29665, 'sha256': '8c1470d60feebda26ce89c153055e1ce731daf9580d1eee8dcb9c89283162af7'},
    "tests/test_hia_release_install.py": {'bytes': 35511, 'sha256': 'e9066cee6b34ebdf59e68f12a1493c45c57a611860b09c7d18a507b78811a240'},
    "tests/test_hia_release_selection.py": {'bytes': 33303, 'sha256': '43c73c9d44afba887f5a60aacb2830b34025c87a27a027e8be88f5f21da7ac07'},
    "tests/test_hia_retirement_state_native.py": {'bytes': 71548, 'sha256': '113b0e8dce3c2987d361ba99eacea63f67a69062372a1b65914cf958050693a0'},
    "tests/test_hia_scalar_profile_native.py": {'bytes': 38350, 'sha256': '64fb0c87c69919c5e08718b4c4274c4669a1a91e1e34bb52abf3837747558cf3'},
    "tests/test_hia_selfhost_linked_observer.py": {'bytes': 53252, 'sha256': '591e3ffb99d78491738ce5b097892723ade7fc0d6f414ea3068d2f9b2dd50cce'},
    "tests/test_hia_service_artifact_native.py": {'bytes': 45734, 'sha256': '9f63ae29e9648e833061a09687cabb757a28e8a44b50aa98612a043af91b58e6'},
    "tests/test_hia_service_context_native.py": {'bytes': 35334, 'sha256': 'bf8d756179772e973661de0bb7e69ba12db7930f6166402fabe1d3636f343156'},
    "tests/test_hia_service_discovery_native.py": {'bytes': 14818, 'sha256': '58da73051dcbf74e3d3354ce6c2b2fdcd255025f8b1bee88388a1b324a24549d'},
    "tests/test_hia_service_inspection_native.py": {'bytes': 20563, 'sha256': '60d44eb69f4052f4846164460fc6797336e88506b674c50c77f7b3ba94ab24c6'},
    "tests/test_hia_service_inspection_public_lifetime.py": {'bytes': 7814, 'sha256': 'e6dd5ca741cc87d79339ca31b5711b8086819cbf63dd26d1465330b05c61038e'},
    "tests/test_hia_service_read_native.py": {'bytes': 19336, 'sha256': '7bae72c81ce95388840d26a876355607ff86c217ac0fb7c7b801336340627e4a'},
    "tests/test_hia_service_slot_native.py": {'bytes': 19777, 'sha256': 'fc41f42b79a53aff9b71867a4d6f5c4785661bb62b379c7015eed88bc339d0e8'},
    "tests/test_hia_service_verification_finalization_native.py": {'bytes': 8334, 'sha256': '4149700ab5eb480eb901a9b82f5f9a068208469b82c9234929c9018c90bedcf5'},
    "tests/test_hia_service_verification_native.py": {'bytes': 18622, 'sha256': '8b665a4d65ddfc11ff52a50882e6f54d08428d1be3b91e2bebee716da3a0a8e8'},
    "tests/test_hia_sha256_stream_transition_equivalence.py": {'bytes': 29313, 'sha256': '3ab7b83da5747eea37801c8dd5e543ebdbeb3c0ba00fef281298ab6cb5251782'},
    "tests/test_hia_slot_ledger_native.py": {'bytes': 32390, 'sha256': '69a2824787de28d9ff642978ea5fbafd52f5877f5201e0065fb96c419c8e1161'},
    "tests/test_hia_slot_ledger_native_integration.py": {'bytes': 85231, 'sha256': '50699c2dacdf503d5d820466ab590a9786dd2023d2d4fa06bedf1c9673d9ff42'},
    "tests/test_hia_slot_operation_series_native.py": {'bytes': 13471, 'sha256': 'ad33b48304b0c91def0b6c87cf4d9c8cf9a18c91fed4e21f8d26be57879e969f'},
    "tests/test_hia_source_build.py": {'bytes': 47516, 'sha256': '19587bd848697c174bbd541a41d9646dab0adf03edc8380121bbfed05d6b80f5'},
    "tests/test_hia_static_budget_native.py": {'bytes': 22042, 'sha256': 'dce1e171396c26f8ad63c42acd3397bc1dd82e445a558b96d67d0dbadd665a50'},
    "tests/test_hia_store_artifact_profile_native.py": {'bytes': 56361, 'sha256': 'eb1f915b35f7597f8988a321777c984cdc944f8993805a44f9b3c4462d6c8541'},
    "tests/test_hia_store_file_capture_native.py": {'bytes': 14394, 'sha256': '43f3e5655b1a0e4f4e844f5fe28a38b6091263d5b41d86e1819c5f73c6a4685b'},
    "tests/test_hia_store_file_capture_owned_fd_v2.py": {'bytes': 6449, 'sha256': '4d0f9562c3549352402ebe320f468dcdf079665e746a00fe03478741c1f49256'},
    "tests/test_hia_store_lifecycle_native.py": {'bytes': 36915, 'sha256': 'dbdfaa7e6066be64a08c31d461cd2f128dec5daa2564ebc07a8401b08c31d900'},
    "tests/test_hia_store_native_delivery.py": {'bytes': 17260, 'sha256': '6e307f7360021c68d2538141f928832396a6cff94e846774487076625e62545b'},
    "tests/test_hia_store_transaction_native.py": {'bytes': 56263, 'sha256': '9358259e492e459acd14a42053a01aa7bafcbff6b95cce125e5da2018cce105d'},
    "tests/test_hia_store_transaction_owner_native.py": {'bytes': 28461, 'sha256': '5a41c9b37c76d1192d3e0560e21ee50d74662fd229326f523f47d1d08012a1df'},
    "tests/test_hia_task_helpers_native.py": {'bytes': 31002, 'sha256': '59cb97d285cc2f5d2e6c7a4bb4e331f8e534123426a88f97594b481025d88ed5'},
    "tests/test_hia_transaction_journal_cleanup.py": {'bytes': 15223, 'sha256': '332e0b12912c3d14b90d2bec22cf5f89e077f5a3bab30d3e9596cd3203968515'},
    "tests/test_hia_worker_native_helpers.py": {'bytes': 68571, 'sha256': '476d6b99573b27ba9c8ff23a60013f0633dc1fb8246438ed773f3c0444a00fec'},
    "tests/test_hia_worker_report_native.py": {'bytes': 67441, 'sha256': 'b5f6c70f53259c23ed8aa8edd57ceadf3b49554e2de1ce9bf558fcdb8007239e'},
    "tests/test_hia_worker_request_native.py": {'bytes': 17176, 'sha256': '68a4ad3da68ae5b9248623f8227ce3354e0f085568b82740936d486485e1b47b'},
    "tests/test_hia_worker_scheduling_bundle.py": {'bytes': 22471, 'sha256': 'e5797ee39859f2c4a8b24db40f42f640d400ed36e0202133ea94b545367bdc8f'},
    "tools/qualify_hia_agent_journal_callers.py": {'bytes': 9065, 'sha256': 'fc2ad819fd36889164a24069bcd77e60849e1f985406e5bbdccd65dca3cfc6a1'},
    "tools/qualify_hia_artifact_delivery_callers.py": {'bytes': 18836, 'sha256': 'd5d9f8e1ee12e09bc709fb7edadd9bcc67b66d97ce25f946659578a42bfea93a'},
    "tools/qualify_hia_byte_wrapper_callers.py": {'bytes': 42658, 'sha256': '7de7f0893323d13f94bbbd2a09f605c735844a9c4e5888622560c8ebc9785cae'},
    "tools/qualify_hia_continuation_no_child.py": {'bytes': 8363, 'sha256': '966266942311d5fb793a0c69cea0598d7895836317a46f43cbd0fa1d9a8e5ff6'},
    "tools/qualify_hia_core_emitter_callers.py": {'bytes': 39038, 'sha256': 'b66b3ddad88a7b82a51d4e118c556da8a6f2cde3c5cd7dabe811f2fbfb1ba8a9'},
    "tools/qualify_hia_core_lowering_callers.py": {'bytes': 36934, 'sha256': '497912595108075defcc718befbf3a064a7e615b760c5bb63513e776e7c66e79'},
    "tools/qualify_hia_cost_ledger_callers.py": {'bytes': 10465, 'sha256': 'bd9682ab67948b2632523b55d595becfed7fe1f860b2544bd8449f1c052a20a1'},
    "tools/qualify_hia_emission_callers.py": {'bytes': 10831, 'sha256': 'fd676590a944d191d8d06eff1b421ccb183c3d06c43d96445c6f92461453d90d'},
    "tools/qualify_hia_evaluation_callers.py": {'bytes': 15063, 'sha256': '29c40723460571b2d336e6f23adec005b3f4a89aead62c826efb391d9de762d9'},
    "tools/qualify_hia_execution_observation_callers.py": {'bytes': 7916, 'sha256': 'f2cff32b4e9fa84c80c49f2d77d5d76bec71c545e516fd67805c365bf32aad83'},
    "tools/qualify_hia_full_cost_callers.py": {'bytes': 6486, 'sha256': 'a2933c04474689512da9e1cf9f79b2df3f2b1c897d4e7bc50232e7a246b862e3'},
    "tools/qualify_hia_generation_retention_callers.py": {'bytes': 11777, 'sha256': '324fa308d3bc064d878ff5885c1c4214306d2b8e97f4c99d06e79dc813812575'},
    "tools/qualify_hia_json_wire_native_callers.py": {'bytes': 21506, 'sha256': '1dcfdd57e8c61a21b60ac238678ed220d6dce9ffa52c0ef48f807717773282c1'},
    "tools/qualify_hia_machine_encoding_native_callers.py": {'bytes': 9529, 'sha256': '95217b125d192aafbd0745b8c2a8633c531d33279c8d782cd350f5131ca23f4d'},
    "tools/qualify_hia_machine_instructions_callers.py": {'bytes': 12852, 'sha256': 'fe3d2bde44e1962de4ceed434b8e378e381bc4bb5f53b27dff8a2047df2f348a'},
    "tools/qualify_hia_machine_object_callers.py": {'bytes': 46294, 'sha256': '8c345d59cb08b126efc53a2f79cea238447081c249a05cb551a23b0f313aa131'},
    "tools/qualify_hia_machine_plan_native_callers.py": {'bytes': 7538, 'sha256': '4a57b51ed158e98d6a4d5c26d4b371b781203b8c6a4f2b8da1a1f64ae19a32a0'},
    "tools/qualify_hia_machine_state_callers.py": {'bytes': 25885, 'sha256': 'cdb5bca1f65eb88adc7704d17f6bee6c471fcfde3681ff9dc16e307193f888dd'},
    "tools/qualify_hia_native_build_admission_callers.py": {'bytes': 11036, 'sha256': 'eece82a138051c392a409c54850997e4104371b3588e8365b0ae3b6b2227d864'},
    "tools/qualify_hia_native_delivery.py": {'bytes': 13055, 'sha256': 'c8967cc610f07be6e7e2c87d4b1850d2bb201df3a41b637213519acff5fbba16'},
    "tools/qualify_hia_patch_impact_callers.py": {'bytes': 6117, 'sha256': 'c37a465a78e8a05c94ffca2c009fe36e90fb591acd15917b0100e619249319c5'},
    "tools/qualify_hia_publication_measurement_callers.py": {'bytes': 7044, 'sha256': '8cd4d198d0915d154f94723e8beeb5f3279b37e783bdfcf7c8950291f94ec591'},
    "tools/qualify_hia_scalar_profile_callers.py": {'bytes': 9793, 'sha256': '2f478c9b1e755ec93f8cb281c86ebff57f083269b183a3f3206d0bc73999f6cf'},
    "tools/qualify_hia_service_artifact_callers.py": {'bytes': 8797, 'sha256': '6c4a8f1d514a2421738f004edc51c66a8f4d6184d48e7bcf5d76776abb5b0eee'},
    "tools/qualify_hia_service_bootstrap_callers.py": {'bytes': 20824, 'sha256': '898ba13203e4fa31d91f00abd020e4d88f08ad89e72dcf9f4da77e4f4af9b351'},
    "tools/qualify_hia_service_context_callers.py": {'bytes': 11881, 'sha256': 'c4de90f655d57d0036313f5a454863bfd85b40adfbe73a16efb16ce13eff2d6f'},
    "tools/qualify_hia_service_discovery_callers.py": {'bytes': 13807, 'sha256': '5ce31de74cdf638aa420f54ce832c768b5e495ba4817f2fa3c43957c9d9a0b0e'},
    "tools/qualify_hia_service_inspection_callers.py": {'bytes': 11661, 'sha256': '223fea4a20e721bec4a24fed3c8821f3d756fff2c68e375de76b9da2c43f9ebe'},
    "tools/qualify_hia_service_lease_callers.py": {'bytes': 11521, 'sha256': '768363114e61b4aa315202de59a2f815a5abf5157c95111aebd480404e5a00ca'},
    "tools/qualify_hia_service_read_callers.py": {'bytes': 11046, 'sha256': '89506a81ee2cbf39bd4dd9f5efdfbd1264fd516d306242cfd430ccbe441bc4fc'},
    "tools/qualify_hia_service_slot_callers.py": {'bytes': 13136, 'sha256': '77b81726ad1777d4e83603c66e5ea678c6362d6505ae206bf29800a5c37aea62'},
    "tools/qualify_hia_service_verification_callers.py": {'bytes': 13569, 'sha256': '43504e98dbdac948e28fd547c6006b180636f54139f7110e70289dfdfd4e93d9'},
    "tools/qualify_hia_slot_operations_callers.py": {'bytes': 12798, 'sha256': '59a187498a565882fe3bd99a16588131d624e5ea1b218ccd3d05e85f0aa42867'},
    "tools/qualify_hia_static_budget_callers.py": {'bytes': 6420, 'sha256': '3e76206cdd4104e1024f8b69fc41f0e575778043f7636db725ad4ea92a9e04cf'},
    "tools/qualify_hia_store_artifact_profile_callers.py": {'bytes': 14867, 'sha256': '59e7e38e653a47a4c0780c95f2d073cfa2e714f8e8001c13cf640a7d255857f9'},
    "tools/qualify_hia_store_file_capture_callers.py": {'bytes': 9030, 'sha256': 'e9ca521a41babd335ae165eb39ea011823d8a1206fce366aaf4a44d993b0aeaa'},
    "tools/qualify_hia_store_lifecycle_callers.py": {'bytes': 10080, 'sha256': '2d49a7ae102d1ac11015a394a4bdf5cb71a3642b4d6818755097a699e65c3a04'},
    "tools/qualify_hia_store_transaction.py": {'bytes': 21711, 'sha256': '05dd836fd4e1bc8b4d1e556339f3c4caef86e0f8fea1d7404cb5c1e8a5df5802'},
    "tools/qualify_hia_store_transaction_callers.py": {'bytes': 8918, 'sha256': '1ee5ae3cf9d14754009ae6652536730aa7b05204cf9513763221e11298adb754'},
}
BASE_COLD_CURRENT = {**deepcopy(frozen.CURRENT),
                     frozen.EVALUATION_TEST: deepcopy(BROAD_CURRENT[frozen.EVALUATION_TEST])}
BASE_COLD_SCHEMA = 'hepta.hia.current-store-base-cold-composition-review.v1'
COMPOSITION_HELPER = 'tools/hia_native_cold_composition_history.py'
COMPOSITION_HELPER_PIN = {
    'bytes': 10987, 'sha256': 'c5a53a1adf23dfefb8f24f3a8cc82d7cf64324362746ac5d25be2f2a663d7b28',
}
COMPOSITION_CURRENT = {
    "tests/hia_caller_terminal_admission.py": {
        "bytes": 29791,
        "sha256": "46111a1e82ba4fbb7153162325ddbdda531d6e0d18de80a6ad58adcb6a3c0b0b"
    },
    "tools/read_hia_store_file_capture_callers.py": {
        "bytes": 54868,
        "sha256": "4a668e26bc920b3f648e6fb0c546673a42f997a00afaf19e70ea0705bd8c0ffe"
    },
    "tools/qualify_hia_service_lease_callers.py": {
        "bytes": 13895,
        "sha256": "0dcfdc29275f41959c1400f860d736a2220e6e1ef68bb0c34a31b5dddf3a389a"
    },
    "tests/test_hia_slot_ledger_native_integration.py": {
        "bytes": 87678,
        "sha256": "f270650c8b70ef1384d0941a85c15c68b788f8198ef88de7f3fa8c96805e853f"
    }
}


def _bind_composition(root, capture):
    actual_self = capture(root / SELF)
    engine = capture(root / ENGINE)
    helper = capture(root / COMPOSITION_HELPER)
    if (actual_self != _EXECUTED_SELF_BYTES
            or _EXECUTED_SELF_PATH.read_bytes() != _EXECUTED_SELF_BYTES
            or pin(engine) != ENGINE_PIN
            or Path(frozen.__file__).read_bytes() != engine
            or pin(helper) != COMPOSITION_HELPER_PIN):
        raise ValueError('current Store composition readers differ from executed sources')
    from tools import hia_native_cold_composition_history as composition
    if (Path(composition.__file__).read_bytes() != helper
            or composition.CURRENT != COMPOSITION_CURRENT):
        raise ValueError('current Store imported another composition source reader')
    return composition


def _bind_broad(root, capture):
    actual_self = capture(root / SELF)
    engine = capture(root / ENGINE)
    helper = capture(root / BROAD_HELPER)
    if (actual_self != _EXECUTED_SELF_BYTES
            or _EXECUTED_SELF_PATH.read_bytes() != _EXECUTED_SELF_BYTES
            or pin(engine) != ENGINE_PIN
            or Path(frozen.__file__).read_bytes() != engine
            or pin(helper) != BROAD_HELPER_PIN):
        raise ValueError('current Store native cold readers differ from executed sources')
    from tools import hia_native_cold_caller_history as broad
    if (Path(broad.__file__).read_bytes() != helper
            or broad.KNOWN_CURRENT != BROAD_CURRENT):
        raise ValueError('current Store imported another native cold source reader')
    return broad


def _base_cold_view(source, root, capture):
    # A source outside the complete group cannot introduce new group authority.
    if not any(name in source and pin(source[name]) == identity
               for name, identity in BASE_COLD_CURRENT.items()):
        return None
    evaluation = capture(root / frozen.EVALUATION_TEST)
    if pin(evaluation) != BASE_COLD_CURRENT[frozen.EVALUATION_TEST]:
        return None
    physical = {name: capture(root / name) for name in frozen.CURRENT}
    if ({name: pin(raw) for name, raw in physical.items()} != BASE_COLD_CURRENT
            or any(name in source and source[name] != raw for name, raw in physical.items())):
        raise ValueError('current Store base cold group is partial, changed or mixed')
    broad = _bind_broad(root, capture)
    projected, history = broad.prepare(root, {frozen.EVALUATION_TEST: evaluation}, take=capture)

    def prior_take(path):
        path = Path(path)
        if path == root / frozen.EVALUATION_TEST:
            return history['prior_take'](path)
        # In particular service afc remains afc here. Its Store inverse belongs
        # to the original complete five-file engine, never the generic 131 view.
        return capture(path)

    if pin(projected[frozen.EVALUATION_TEST]) != frozen.CURRENT[frozen.EVALUATION_TEST]:
        raise ValueError('current Store base cold predecessor differs')
    reviewed = {**source, **physical, frozen.EVALUATION_TEST: projected[frozen.EVALUATION_TEST]}
    return reviewed, {
        'mode': 'base-native-cold',
        'prior_take': prior_take,
        'native_cold_history': history,
    }


def _verify_base_cold(history):
    review, view = history['review'], history['base_cold_view']
    physical = {name: pin(history['captures'][name]) for name in frozen.CURRENT}
    broad_history = view['native_cold_history']
    if (review.get('schema') != BASE_COLD_SCHEMA
            or view.get('mode') != 'base-native-cold'
            or physical != BASE_COLD_CURRENT
            or review.get('complete_current') != physical
            or review.get('actual_physical_current') != physical
            or review.get('historical_current_inputs') != frozen.CURRENT
            or review.get('native_cold_caller_sources') != broad_history['review'].get(
                'native_cold_caller_sources')
            or review.get('complete_predecessors') != frozen.PREDECESSORS
            or review.get('physical_capture_rewritten') is not False
            or review.get('prior_projection_is_physical_source') is not False
            or review.get('current_source_reader') != {
                'path': SELF, **pin(_EXECUTED_SELF_BYTES)}
            or history['prior_history']['review'].get('complete_current') != frozen.CURRENT
            or history['prior_history']['review'].get('complete_predecessors') != frozen.PREDECESSORS
            or set(broad_history['review'].get('native_cold_caller_sources', {})) != {
                frozen.EVALUATION_TEST}
            or review.get('base_native_cold_review') != broad_history['review']):
        raise ValueError('current Store base cold review lost its exact physical group')
    from tools import hia_native_cold_caller_history as broad
    proof = broad_history['review']['native_cold_caller_sources'][frozen.EVALUATION_TEST]
    broad.bind_cold_caller_adjustment({
        'path': frozen.EVALUATION_TEST,
        'current_bytes': frozen.CURRENT[frozen.EVALUATION_TEST]['bytes'],
        'current_sha256': frozen.CURRENT[frozen.EVALUATION_TEST]['sha256'],
    }, history['captures'][frozen.EVALUATION_TEST], proof)
    frozen.verify_unchanged(history['prior_history'])
    _reread(history['root'], history['take'], history['captures'], view)
    review['prior_source_history_review'] = deepcopy(history['prior_history']['review'])
    review['base_native_cold_review'] = deepcopy(broad_history['review'])
    review['native_cold_caller_sources'] = deepcopy(broad_history['review']['native_cold_caller_sources'])
    review['terminal_reread_identical'] = True


def pin(raw):
    return frozen.history_pin(raw)


def _view(captured, root, take):
    root = ROOT if root is None else Path(root)
    source, saved = dict(captured), {}

    def capture(path):
        path = Path(path)
        try:
            name = path.relative_to(root).as_posix()
        except ValueError as error:
            raise ValueError('current Store source read escaped the selected root') from error
        if name in ('', '.') or any(part in ('', '.', '..', '.git') for part in name.split('/')):
            raise ValueError('current Store source path is not canonical')
        raw = take(path)
        pin(raw)
        if name in saved and saved[name] != raw:
            raise ValueError('current Store physical source changed between reads: ' + name)
        saved[name] = raw
        return raw

    base_cold = _base_cold_view(source, root, capture)
    if base_cold is not None:
        return (*base_cold, saved, capture, root)

    use_window = any(name in source and pin(source[name]) == identity
                     for name, identity in (*WINDOW_CURRENT.items(), *COLD_CURRENT.items()))
    if not use_window and any(name in source and pin(source[name]) == identity
                              for name, identity in UNCHANGED.items()):
        # The older reader also requires the complete group for these members.
        # Reading this existing production member adds no new fixture authority.
        service = capture(root / 'hepta/hia_agent_service.py')
        use_window = pin(service) == WINDOW_CURRENT['hepta/hia_agent_service.py']
    if not use_window:
        return source, None, saved, capture, root

    self_raw = capture(root / SELF)
    helper = capture(root / WINDOW_HELPER)
    engine = capture(root / ENGINE)
    if (_EXECUTED_SELF_BYTES != self_raw
            or _EXECUTED_SELF_PATH.read_bytes() != _EXECUTED_SELF_BYTES
            or pin(helper) != WINDOW_HELPER_PIN
            or pin(engine) != ENGINE_PIN or Path(frozen.__file__).read_bytes() != engine):
        raise ValueError('current Store source-history readers differ')
    from tools import hia_evaluation_window_history as window
    if Path(window.__file__).read_bytes() != helper:
        raise ValueError('current Store imported another evaluation source reader')
    affected = {name: raw for name, raw in source.items() if name in frozen.CURRENT}
    cold_history = None
    try:
        selected_take = capture
        evaluation = capture(root / frozen.EVALUATION_TEST)
        if pin(evaluation) == COLD_CURRENT[frozen.EVALUATION_TEST]:
            cold_raw = capture(root / COLD_HELPER)
            if pin(cold_raw) != COLD_HELPER_PIN:
                raise ValueError('current Store evaluation cold reader differs')
            from tools import hia_evaluation_cold_source_history as cold
            if Path(cold.__file__).read_bytes() != cold_raw:
                raise ValueError('current Store imported another evaluation cold reader')
            affected, cold_history = cold.prepare(root, affected, take=capture)
            selected_take = cold_history['prior_take']
        projected, history = window.prepare(root, affected, take=selected_take)
        if cold_history is not None:
            history['evaluation_cold_history'] = cold_history
    except ValueError as error:
        raise ValueError('Store history partially reverted or unreviewed composition: '
                         + str(error)) from error
    if history['review']['successor_applied'] is not True:
        raise ValueError('current Store successor did not bind the current complete group')
    source.update(projected)
    return source, history, saved, capture, root


def _reread(root, take, saved, window_history=None):
    if window_history is not None:
        if window_history.get('mode') == 'base-native-cold':
            from tools import hia_native_cold_caller_history as broad
            broad.verify_unchanged(window_history['native_cold_history'])
        else:
            from tools import hia_evaluation_window_history as window
            window.verify_unchanged(window_history)
            cold_history = window_history.get('evaluation_cold_history')
            if cold_history is not None:
                from tools import hia_evaluation_cold_source_history as cold
                cold.verify_unchanged(cold_history)
    if SELF in saved and (saved[SELF] != _EXECUTED_SELF_BYTES
            or _EXECUTED_SELF_PATH.read_bytes() != _EXECUTED_SELF_BYTES):
        raise ValueError('current Store executed source changed at terminal')
    for name, raw in saved.items():
        if take(root / name) != raw:
            raise ValueError('current Store physical source changed at terminal: ' + name)


def restore(captured, *, root=None, take=Path.read_bytes):
    source, window_history, saved, capture, root = _view(captured, root, take)
    prior_history = None
    try:
        prior_take = window_history['prior_take'] if window_history is not None else capture
        restored, prior_history = frozen.restore(source, root=root, take=prior_take)
        if window_history is None:
            return restored, prior_history
        if prior_history is None:
            raise ValueError('current Store lost its retained complete predecessor admission')
        review = deepcopy(prior_history['review'])
        if window_history.get('mode') == 'base-native-cold':
            review.update(
                schema=BASE_COLD_SCHEMA,
                complete_current={name: pin(saved[name]) for name in frozen.CURRENT},
                prior_source_history_review=deepcopy(prior_history['review']),
                base_native_cold_review=deepcopy(window_history['native_cold_history']['review']),
                native_cold_caller_sources=deepcopy(
                    window_history['native_cold_history']['review']['native_cold_caller_sources']),
                actual_physical_current={name: pin(saved[name]) for name in frozen.CURRENT},
                historical_current_inputs=deepcopy(frozen.CURRENT),
                physical_capture_rewritten=False,
                prior_projection_is_physical_source=False,
                current_source_reader={'path': SELF, **pin(saved[SELF])},
                terminal_reread_identical=False,
            )
            history = {'review': review, 'root': root, 'take': take, 'captures': saved,
                       'base_cold_view': window_history, 'prior_history': prior_history}
            verify_unchanged(history)
            return restored, history
        review.update(
            schema=SCHEMA,
            complete_current={name: pin(saved[name]) for name in frozen.CURRENT},
            prior_source_history_review=deepcopy(prior_history['review']),
            evaluation_window_review=deepcopy(window_history['review']),
            physical_capture_rewritten=False,
            prior_projection_is_physical_source=False,
            current_source_reader={'path': SELF, **pin(saved[SELF])},
            terminal_reread_identical=False,
        )
        if window_history.get('evaluation_cold_history') is not None:
            review['evaluation_cold_review'] = deepcopy(
                window_history['evaluation_cold_history']['review'])
        history = {'review': review, 'root': root, 'take': take, 'captures': saved,
                   'window_history': window_history, 'prior_history': prior_history}
        verify_unchanged(history)
        return restored, history
    finally:
        frozen.verify_unchanged(prior_history)
        _reread(root, take, saved, window_history)


def verify_unchanged(history):
    if history is None:
        return
    if 'base_cold_view' in history:
        _verify_base_cold(history)
        return
    if 'window_history' not in history and 'prior_history' not in history:
        frozen.verify_unchanged(history)
        return
    review = history['review']
    physical = {name: pin(history['captures'][name]) for name in frozen.CURRENT}
    cold_history = history['window_history'].get('evaluation_cold_history')
    expected = PHYSICAL_CURRENT if cold_history is not None else WINDOW_PHYSICAL_CURRENT
    if cold_history is not None and (
            cold_history['review'].get('physical') != COLD_CURRENT
            or cold_history['review'].get('prior_projection') != WINDOW_CURRENT
            or review.get('evaluation_cold_review') != cold_history['review']):
        raise ValueError('current Store lost its actual evaluation cold source review')
    if (review.get('schema') != SCHEMA or physical != expected
            or review.get('complete_current') != physical
            or review.get('complete_predecessors') != frozen.PREDECESSORS
            or review.get('physical_capture_rewritten') is not False
            or review.get('prior_projection_is_physical_source') is not False
            or review.get('current_source_reader') != {
                'path': SELF, **pin(history['captures'][SELF])}
            or history['prior_history']['review'].get('complete_current') != frozen.CURRENT
            or history['prior_history']['review'].get('complete_predecessors') != frozen.PREDECESSORS):
        raise ValueError('current Store review lost its complete physical source identity')
    frozen.verify_unchanged(history['prior_history'])
    _reread(history['root'], history['take'], history['captures'], history['window_history'])
    history['review']['prior_source_history_review'] = deepcopy(history['prior_history']['review'])
    history['review']['evaluation_window_review'] = deepcopy(history['window_history']['review'])
    if cold_history is not None:
        history['review']['evaluation_cold_review'] = deepcopy(cold_history['review'])
    history['review']['terminal_reread_identical'] = True


def restore_service(raw, *, root=None, take=Path.read_bytes):
    source, history = restore({'hepta/hia_agent_service.py': raw}, root=root, take=take)
    verify_unchanged(history)
    return source['hepta/hia_agent_service.py']


def restore_evaluation_test(raw, *, root=None, take=Path.read_bytes):
    source, history = restore({frozen.EVALUATION_TEST: raw}, root=root, take=take)
    verify_unchanged(history)
    return source[frozen.EVALUATION_TEST]


def _read_one(root, name, raw, take, reader):
    if name not in frozen.CURRENT and pin(raw) == COMPOSITION_CURRENT.get(name):
        selected_root = Path(root)
        _, _, saved, capture, selected_root = _view({name: raw}, selected_root, take)
        composition = _bind_composition(selected_root, capture)
        projected, history = composition.prepare(selected_root, {name: raw}, take=capture)
        try:
            # The next reader consumes an explicit predecessor view. Only this
            # outer capture stores physical bytes of the current source.
            return _read_one(selected_root, name, projected[name], history['prior_take'], reader)
        finally:
            composition.verify_unchanged(history)
            _reread(selected_root, take, saved)
    if name not in frozen.CURRENT and pin(raw) == BROAD_CURRENT.get(name):
        selected_root = Path(root)
        _, _, saved, capture, selected_root = _view({name: raw}, selected_root, take)
        broad = _bind_broad(selected_root, capture)
        projected, history = broad.prepare(selected_root, {name: raw}, take=capture)

        def prior_take(path):
            path = Path(path)
            try:
                dependency = path.relative_to(selected_root).as_posix()
            except ValueError as error:
                raise ValueError('current Store native cold dependency escaped its root') from error
            if dependency in frozen.CURRENT:
                return capture(path)
            return history['prior_take'](path)

        try:
            # This argument and reader are explicitly historical. Only capture()
            # records physical files, and it is re-read after the old gate.
            return reader(selected_root, name, projected[name], prior_take)
        finally:
            broad.verify_unchanged(history)
            _reread(selected_root, take, saved)
    source, history, saved, capture, root = _view({name: raw}, root, take)
    try:
        selected = history['prior_take'] if history is not None else capture
        return reader(root, name, source[name], selected)
    finally:
        _reread(root, take, saved, history)


def restore_reader_evaluation_test(raw, *, root, take=Path.read_bytes):
    return _read_one(root, frozen.EVALUATION_TEST, raw, take,
        lambda selected_root, name, data, selected_take:
            frozen.restore_reader_evaluation_test(data, root=selected_root, take=selected_take))


def reviewed_source(root, name, raw, *, take=Path.read_bytes):
    def read(selected_root, selected_name, data, selected_take):
        if selected_name == NATIVE_TOOLS and pin(data) == NATIVE_TOOLS_CURRENT:
            helper = selected_take(selected_root / CALLER_HELPER)
            if pin(helper) != CALLER_HELPER_PIN:
                raise ValueError('current Store native-result source reader differs')
            from tools import hia_current_caller_source_history as caller
            if Path(caller.__file__).read_bytes() != helper:
                raise ValueError('current Store imported another native-result source reader')
            return caller.reviewed_source(selected_root, selected_name, data, take=selected_take)
        return frozen.reviewed_source(selected_root, selected_name, data, take=selected_take)
    return _read_one(root, name, raw, take, read)


# Current native successors have a separate physical capture layer. The older
# complete readers above keep their original predicates, fixed authorities,
# inverses and error behavior for every retained historical source domain.
_retained_restore = restore
_retained_reviewed_source = reviewed_source
_retained_verify_unchanged = verify_unchanged
_retained_restore_reader_evaluation_test = restore_reader_evaluation_test


def _current_generation(captured, root, take):
    from tools import hia_current_source_generation as generation
    selected = ROOT if root is None else Path(root)
    return generation.maybe_prepare(selected, captured, take=take)


def restore(captured, *, root=None, take=Path.read_bytes):
    projected, generation = _current_generation(captured, root, take)
    if generation is None:
        return _retained_restore(captured, root=root, take=take)
    from tools import hia_current_source_generation as successor
    try:
        restored, prior = _retained_restore(
            projected, root=generation.root, take=generation.prior_take)
        if prior is None:
            raise ValueError('current native Store generation lost its complete prior admission')
        review = deepcopy(prior['review'])
        review.update(schema='hepta.hia.current-native-store-source-review.v1',
            complete_current={name: pin(generation.capture(generation.root / name))
                              for name in frozen.CURRENT},
            retained_source_history_review=deepcopy(prior['review']),
            current_source_generation=deepcopy(generation.review()),
            physical_capture_rewritten=False,
            prior_projection_is_physical_source=False,
            terminal_reread_identical=False)
        history = {'review': review, 'generation_history': generation,
                   'retained_history': prior, 'captures': generation.captures}
        verify_unchanged(history)
        return restored, history
    finally:
        successor.verify_unchanged(generation)


def verify_unchanged(history):
    if history is None or 'generation_history' not in history:
        return _retained_verify_unchanged(history)
    from tools import hia_current_source_generation as successor
    generation = history['generation_history']
    _retained_verify_unchanged(history['retained_history'])
    successor.verify_unchanged(generation)
    review = history['review']
    actual = {n: pin(generation.captures[n]) for n in frozen.CURRENT}
    if (review.get('schema') != 'hepta.hia.current-native-store-source-review.v1'
            or review.get('complete_current') != actual
            or review.get('retained_source_history_review') != history['retained_history']['review']
            or review.get('current_source_generation') != generation.review()
            or history.get('captures') is not generation.captures
            or review.get('physical_capture_rewritten') is not False
            or review.get('prior_projection_is_physical_source') is not False):
        raise ValueError('current native Store review lost physical source identity')
    review['terminal_reread_identical'] = True


def reviewed_source(root, name, raw, *, take=Path.read_bytes):
    projected, generation = _current_generation({name: raw}, root, take)
    if generation is None:
        return _retained_reviewed_source(root, name, raw, take=take)
    from tools import hia_current_source_generation as successor
    try:
        return _retained_reviewed_source(
            generation.root, name, projected[name], take=generation.prior_take)
    finally:
        successor.verify_unchanged(generation)


def restore_reader_evaluation_test(raw, *, root, take=Path.read_bytes):
    projected, generation = _current_generation({frozen.EVALUATION_TEST: raw}, root, take)
    if generation is None:
        return _retained_restore_reader_evaluation_test(raw, root=root, take=take)
    from tools import hia_current_source_generation as successor
    try:
        return _retained_restore_reader_evaluation_test(
            projected[frozen.EVALUATION_TEST], root=generation.root,
            take=generation.prior_take)
    finally:
        successor.verify_unchanged(generation)
