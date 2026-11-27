"""Data-only physical custody for the fixed native cold caller source history.

A historical view is never stored as a physical capture. Unknown source bytes
receive no exception and remain the responsibility of the original exact gate.
This module imports no product, builder, test helper, generator, or oracle.
"""
from hashlib import sha256
import json
from pathlib import Path, PurePosixPath
import re

SOURCE = 'tools/hia_cold_caller_sources.py'
HISTORY_SOURCE = 'tools/hia_native_cold_caller_history.py'
FIXTURE = 'tests/fixtures/hia_native_cold_caller_integration_20261127.json'
PREVIOUS_FIXTURE = 'tests/fixtures/hia_native_cold_caller_relations_20261127.json'
FIXTURE_PIN = {'bytes': 236242, 'sha256': 'ce9a293352ac12adb153ae91036915826f4a121a5b3668d8ffbd2f64e375e476'}
PREVIOUS_PIN = {'bytes': 234857, 'sha256': '28810aa4aea3e1297a2b09bc7f34a6aa8683f301f9aaab5eef5af1f0705f07b3'}
COLD_CALLER_HELPER_PIN = {'bytes': 15434, 'sha256': '589de0f5608946acbf66004ee55c877458ae6685825b65dcc505609b3c9e556d'}
DEPENDENCIES = (HISTORY_SOURCE, SOURCE, FIXTURE, PREVIOUS_FIXTURE)
INTEGRATED_PATHS = ('tests/test_hia_store_native_delivery.py',)
SCHEMA = 'hepta.hia.native-cold-caller-source-admission.v1'

# Both whole-file domains are declared independently of optional on-disk
# authorities, so a missing authority cannot turn a known new source into legacy.
KNOWN_PINS = {
    'hepta/hia_agent_service.py': ((268278, 'afc92b555bd0dfa23f25c4f9c2661af30853474342f4e32a036d37c1ce663a57'), (263074, '862e41dd41c2a76f3a46b515052cd597f6b186db152bf3ca17aa9a9d2a2570f7')),
    'tests/hia_composite_function_fixture.py': ((22025, 'c1e14fcee5e77563319e6ec96e536852b63e9813b46640b124858c049a5487b9'), (22283, '0d7961985bfbffe02b087283e32157b0e2ca5f5d4a22d0b74af390978101ce9d')),
    'tests/hia_service_bootstrap_controls.py': ((26208, 'cafbfb896879f7679aefe5787b9684c00e364ce01d4acb8586da9b5d67c258ab'), (26298, '603a12448b59a406c31cb5a4576909e42ad8601b5ad0e98a9fe5d8f033910eff')),
    'tests/hia_service_lease_controls.py': ((35680, '1f65b1db4aa29fe0653fd6bc5214ba13ab80dec5e5d38e3f6a1f3a24083cf587'), (35711, '2a5af81dc9596626397573e729c7ba87eb1e67490f194788209e8bd683e7b284')),
    'tests/hia_slot_operations_component_fixture.py': ((8904, '257c95b3d48ce31f261c075f9ef9b9b704311e20451d476150edece4c748b34d'), (8881, '0c5bdebff660a40fbb3e965fe370a7455fb809ef6de85b9264e65640354c417c')),
    'tests/test_hia_agent_installed_resources.py': ((74769, '03ef282856ab2f587a120a4b7e38e55c78c5f74d29dcd3a37716cdf54f8b09da'), (74950, '5e0db72475d8aa67bdc94d3e7866f0765d9e712711eaf3df0796416b80181d8f')),
    'tests/test_hia_agent_journal_extensions.py': ((16086, '41ab738562230155fd7314042e5647c6caf01baf655c92d4d97805e9838564f1'), (16157, '0436dd3fc1c2c6311af1fd6182c3553ab3b1f6923c715dcbf121151ea5a58060')),
    'tests/test_hia_agent_journal_native.py': ((48895, 'ca519da2e7dd577e30a9465544376c0bc5637d21b5a9a3eea5882127121d1933'), (48904, '97dec702780d755cc5c2ffa59e5a798c98dc48a17735f9b8983bfdb610d2f263')),
    'tests/test_hia_agent_stdio.py': ((44700, 'fa3c4279373efdb47bfaf71b179014e44f84ef1d4b9e931a5c09a3467a873531'), (44608, 'ba37c4d93dd6b15e1dcba39cfd9ba5757940f7304f2d3e799c1825921eaf16b1')),
    'tests/test_hia_artifact_delivery.py': ((13064, '11865a8a64addd4a4bbc71674572945f7150ea6d9274209489f30f5fc65d4cba'), (12736, 'e953f415a5f3aa47e2367dddd989f80ae7bf233f895cf64bfc6ca5f44eb01ec2')),
    'tests/test_hia_artifact_publication_native.py': ((19607, 'de92f2dc85c187fb0834de801899801c6cb1c36ab03909dab07554bcf15ee0dc'), (19670, '0e0b139387f69152c54b7d5f4f4533a87bfcd539552badb613c1bef60dc3ed2a')),
    'tests/test_hia_artifact_publication_route.py': ((14826, 'ed4b466b20e6c7b96c671d56263b0501b1a3d20ff314cf47e5c75e52158af740'), (14759, '55b8c074a57a58e66ea561a89f930f0302f877182f9597f67d7db40b1425d765')),
    'tests/test_hia_byte_wrapper_native.py': ((21198, 'ab6b26012e6c8b669f1ef05c8454f8e39c90a13e024241c767dfffdf41154a29'), (21269, '451e9ee80e50cf277ebb95b59107e9162c022b4a88e967e53ca641c27e2e6384')),
    'tests/test_hia_candidate_budget_native.py': ((47663, 'c57d05e69b9e646bf07f77161f16943d0ea6b3d400216439940e5902bfe994d1'), (47590, '2a5e6deed4fa86630b659084320c95fbb06a4283d00bbb54764b1e0d4d66a24c')),
    'tests/test_hia_capability_renaming_native.py': ((12366, '1d29ba34ca01a52230be92250b2e6f10a0fb3e08553e44f185d6f2cd11108004'), (12279, '956b658a8e133b8eaf4a9252a7c7d8d4fa0e46869c0a96d3cd1af37c2023d6e3')),
    'tests/test_hia_cli_native.py': ((62446, '81c45847a2c5f44cbdfee0632dc576954602067587cc8fe0eb35f740206601d6'), (62515, 'e6505160738a00e3effc7605bc52b244d5a60aed24ad9c7dcdcab297a29b29af')),
    'tests/test_hia_composite_native_composition.py': ((10163, '3765cde070080da3b1b89e660d08269f8db9f0a54b47a64860958ad3c5dd99aa'), (10087, '93fe83dd7bc4983627871f242391bc29a2e9df8df44e44d9a574d85d0541ced9')),
    'tests/test_hia_composite_types_native.py': ((45857, '58c9b06ec4a49f2faed2c7878e451d47f6565e057aef9e382b48efd6ddc4779d'), (45928, 'c6970414fe9d681aeedd2beb04a41419eba87c40c6bd989aa19899586d2fe912')),
    'tests/test_hia_continuation_native.py': ((47325, 'c7de9ccf59c488826350513c7e4197cbf35864817f249d2d6c779ac041f843f6'), (47390, 'c5c62d19790ccef49296b2783d84cfa2469aa82a83d129f82e34c098adb3ef41')),
    'tests/test_hia_core_admission_cli.py': ((31112, '5f5f7f1e40d32353b0503eeb796a0fc35af7a550d532cd2134916ebd95ccf892'), (31025, '48fdf7039d07382522452cb88a7f497465bad6d310a29ef1f07df212b5063a9f')),
    'tests/test_hia_core_admission_native.py': ((28747, '26bdf9a5223ce3e06e9a2d76bbda73213c31efbe166ce784c8e8e69ee4506757'), (28660, '45e17174348778c5ebe6ffa94675ec7102699691ccc1be64f8ba1355662c2993')),
    'tests/test_hia_core_emitter_native.py': ((24733, 'e6403926b548e782db6c09ab7b8edd922b58f5b9c8e74050dc1814cff63d3713'), (24804, 'ac187c414b69ce35abe6b245b6963de48681d08ff517563f4110082b6afabafe')),
    'tests/test_hia_core_json_bytes_native.py': ((23358, '5b5482edee36e46b517a398f852dbc2b00c0616f48a971d36c7ffdbf3f413a8e'), (23429, '6399b84252fe4daac12efb44ae3783b925f8fa0d583de454b07ab620b7d7e498')),
    'tests/test_hia_core_lowering_native.py': ((34348, '796e08806a0d633a07b8d509df3d29100042376a26db57a3599eaf10e402bc4d'), (34419, 'ac443a879d099b28f3df0234833894926a382eca9d86e7164b4e6dce14f11f62')),
    'tests/test_hia_core_module_graph_native.py': ((33305, 'ae438a098da1b0dc82a5e35271dd198a7e4d7b2f187bd47b85f131655611d640'), (33214, '5968aa881f42b0f38cc2559b37dbdafeb3a0b74dbb6eeea9b2040ce0219ba0a5')),
    'tests/test_hia_core_patch_cli.py': ((17630, '02ef8c624cfcf901e281c3169fb2e2223d495affaf1ff5107ee97aa2c8a294a2'), (17543, 'f4e5f3b4adee1840b08c99ca76caea3cf88ae0cadab95fb6ff9bba61538b77d4')),
    'tests/test_hia_core_patch_native.py': ((26329, 'e28bd4cc0adef96b8c6173cfd51a49cf7e44c151147868e844dd160e8aff5477'), (26242, '47b175805f4dd31a2b814b6196f279abdaf1380a5ba8a8af51458890f3776790')),
    'tests/test_hia_core_patch_result_cli.py': ((28818, '794fdeacc7004dbefc0a6f62544cc98bd9b3896d2d28e5c69b82f5cb3f49b04d'), (28731, '4519dd80fe7af85da764c3b74c0a184f2f5f3fa089ea4856ccb31192d348d603')),
    'tests/test_hia_core_workspace_json_native.py': ((24628, '2b31a3df83f84b86f805cb21549441457766f71a27fda0b15c658ba5e855e608'), (24537, '2558dc015f11b5fab6f0445aa1870b23f24cb269d93eef2816015a8ffb5c00bb')),
    'tests/test_hia_core_workspace_pipeline.py': ((23407, '056cc080e82bc10949e119a4922b92748871313df1ed803f9377a855e51c9ab2'), (23474, '937f1f76e2b22689360782ab9e0267f485d1d0faf5da973f727e0c454c50fc6a')),
    'tests/test_hia_cost_ledger_native.py': ((26137, '13b677939273323814166ae31aa154caa47fa8dccf83dfbf1076296ef54ed7c0'), (26206, '0acde16af9e90455567aeb10264666f121eed3c95f271e902074c6e9f4a4454e')),
    'tests/test_hia_default_native_release.py': ((58380, 'f9552d7acf5ad24a733b8b3a66724aee4a4e591b83377545287f745b79dd6c15'), (58451, '19b7d50cbf9cef84ea43f4552a581b3cb6c179f94758c18209dc169536c4b1bc')),
    'tests/test_hia_emission_native.py': ((59098, '1cf70583e3e663b9106e814fc2ba60f63ae7e7d8b94311dd28cb32a3f8a0818c'), (59167, 'd9fa91660529f031bd07553e20ae256c4877aa41c7eabef2fbdcf554bbe5a195')),
    'tests/test_hia_evaluation_capture.py': ((18026, '4e129ebb1190425823462d2046a08d79850c1f6c2fb981b473066711ec6e7214'), (18077, 'f95d2b9e4f11ab333afbae8a63ef370a09df8f7fc5e6a3363d28edf97777cf13')),
    'tests/test_hia_evaluation_native.py': ((50228, '091164ad78e1d3fab04e9410176b259b4a80f1e3b4b0c92c0da14743f2a43ab2'), (50297, 'ee3a01914f902f92cb5f440acd224926c92322d346e76e14fde081516b51fbe5')),
    'tests/test_hia_execution_budget_native.py': ((56700, '0e78c223a6b905a13497db0090405e81b42d99f75ec321f92c491e4e362b6d36'), (56631, '31becb0bf5001aa4b1cb6565a0bee2d68ecbd7248c951b1c485401eda2cf8b23')),
    'tests/test_hia_execution_observation_native.py': ((22950, '84f775dfe79c3c8a714910a52295e6d7c2521b913c65bea2bbb14cf755613336'), (23017, '7595bda181f97b5e4b4b7c020c2b008017cbe3f7b3d239609f55b8498d87c3d0')),
    'tests/test_hia_full_cost_native.py': ((27361, '93aa86e3ca9c372cf5dd9b258b631194cbce89ce45d34165ea371031a2f2ea57'), (27432, '56556dd16d89e257275b5f566f2fbf5ef1fa53aed6aa950b58ed6720c89701ab')),
    'tests/test_hia_function_shape_native.py': ((14677, '5a09d5d258c4a101c05ad4e6fc20df2da434c1ee9219dbaeef485d58ad5987f0'), (14586, '10117f0ae60fff3e47d7d17faf6be3d971f769fbc3f49fda66df8c900752cd51')),
    'tests/test_hia_generation_retention_native.py': ((51570, 'edb25b1a045a27493bea17f0290e60e48af2e019c693cc0aa632f0b61460e85a'), (51641, '1bc79ee476609f0db1c650ec354cf837c22b59eccbdff19a89b8dbb210893a0d')),
    'tests/test_hia_instruction_policy_native.py': ((12703, '22eebadc6d7df2bda771a71ca073d0b6d90e9dca90d2341c1e57d34830954deb'), (12612, 'e1464878b995d5dcdc1f54ae257e71e0724da235983460063bb905afd1826608')),
    'tests/test_hia_json_wire_native.py': ((34001, 'ee0d0bc9bf0db4104320b6ad89303d8df399b0a7df0cd717e993aa20c6a1fc65'), (34072, 'd0140b75f914c0c09886b342fe63309414e9abde9c185a88fc3d14e039e9293e')),
    'tests/test_hia_machine_encoding_native.py': ((21159, 'ed314306ce02885c077f5bc0f71277fa00f4e9428bb3d4ae81b4592b9a8fac33'), (21230, '5fa7593ead9f145c6f4716055db0f6a83671cb7a245205952008a122ffec6417')),
    'tests/test_hia_machine_instructions_native.py': ((28015, '7dbf47f0851b1e145e926763961a17c1cf7b2d62a077d0f47e7b349ba320dff1'), (28084, '72ccbff4d27a34c850e1d20aaef1b9511177405f9af5343c8954ad0fc4170fa8')),
    'tests/test_hia_machine_object_native.py': ((24116, 'ccd7731d438185b7889c788912c9b0514ca3e07fb6238736cbe49f2172be1b8b'), (24191, 'cb630e81964962a5512f92d072fccb64d8d43fa504880cbf2f6ad616e9ebec2a')),
    'tests/test_hia_machine_plan_native.py': ((22439, 'cd92bfd7774710d65f75bf1f632bcf361d35a0f74946f6595d618d16c416e40f'), (22510, 'd799a1200f0c132b1afa82995e49a90bbad600f7dca14a010affe387affef02e')),
    'tests/test_hia_machine_state_native.py': ((32718, '593217dab6ebe1d28b75b6cd4d168e9648c19bfde2896d6e283136f3289e6932'), (32787, '40e470bd016457e83cc14017b06847c2742359be887bd2d7af9cf67189cfeb83')),
    'tests/test_hia_native_admission_io.py': ((8421, '250898e812fb9de68556a5663c1a05f32fc8e3eea521a40347f59c8a237b1988'), (8470, '6d5eea28c181044dc667380aeac1121bcba13ec024a2143c30fbd15b0f03ee4c')),
    'tests/test_hia_native_build_admission_native.py': ((47949, '397d3466a30bbe4cfab9c9ce66f1554348b04f631feae1ffd9f78d44c9ae818a'), (48018, 'c46859c1a1e7d1a06a8a1c03d6da12adcd6785b24e5657cd3e727dddace8b342')),
    'tests/test_hia_native_build_dispatch.py': ((18657, '84ac9d461b11dd29111c50fdca6d9ed6dd05a76c1e5d5d41c7c055976a3369c9'), (18726, '850353cfcd5e201bfce87ab7d2310126c44f0b89387591c36d30c9d93a70f4aa')),
    'tests/test_hia_native_delivery.py': ((13403, 'f3ce861a16923a264becff4002c73c0c198c0579d75eeea8a5b7e92dabf369a8'), (13472, '0a0ffdc697284b55e7cc3ad96dc3bbf72ac77d769443d3f8e84e5a6672b0a23d')),
    'tests/test_hia_native_mapping_native.py': ((37641, 'e0dd2b6dbc6ab7131bc7c8e427c715d9d3e8392d5b05455c7060eadfe062c3d9'), (37570, '1f3508a5012c61c03d04a3f4c8361f51b61a2fb8efdc778a91b154424d230eb4')),
    'tests/test_hia_native_transport_failures.py': ((39809, '5573ffa450ff517a9193913c9b26dfb95dd7d9c46fd42b81758b4c93f7807ba9'), (39878, '6a796f3dcaaa17a778d51caa84f0630e9c37780361b24fdca4414e7e8a53733d')),
    'tests/test_hia_nominal_json_native.py': ((23922, '91b86e99c69ec41397e4cf7fe0d0daeda9094cc7b7f48f4d547da5272a5182bd'), (23993, '7028bc79d04ec8cb501b1e6bf705383218f0e770cce7f5562b63fd3c586a5ac5')),
    'tests/test_hia_nominal_tokens_native.py': ((38422, '5615afaeac4458d19177e5124442f310f44758953e9213e170d61e38d02909d8'), (38493, '21c4fd4eb71f27d565361edcb172bb456e28b49f94d8b4cb7b52cc7eeb8b1c17')),
    'tests/test_hia_patch_impact_native.py': ((16679, 'e81b445300f8de9e04f706c995610d22e5bba1209aa41fbbd6a4c38665b8f1c5'), (16750, '07feb083177ce4e7bddd5831090582c9f62175639b2761dd7bd7e5d0361d6872')),
    'tests/test_hia_program_selfhost.py': ((52005, '779b1829875aeba75a24d27e6d17414a56b5b0ecc5bc72f94c70d53a4192ed6c'), (52072, '705b660017b62b7a1b3e6686bee28113edb4a851081d1bc139e551f99de107c0')),
    'tests/test_hia_program_shape_native.py': ((13271, '2518580fd47c6121a3ea4d6bd989132f58a47def044067c7d4af94806e3a9aae'), (13180, '8b3a9e78ec9fb3cf02430bc4355f8f6db09a7c772a62cd634ec1b1897b5887b4')),
    'tests/test_hia_publication_measurement_native.py': ((29665, '8c1470d60feebda26ce89c153055e1ce731daf9580d1eee8dcb9c89283162af7'), (29736, '9a5eb9315ea8c689e1f1d53c974825fcb52f93c13368daedee2cdfc9afa1e607')),
    'tests/test_hia_release_install.py': ((35511, 'e9066cee6b34ebdf59e68f12a1493c45c57a611860b09c7d18a507b78811a240'), (35578, '1f9b8a5ebeef30f2d7d3b704e3eb0a10bece248159448da3ff31e6a0e982a782')),
    'tests/test_hia_release_selection.py': ((33303, '43c73c9d44afba887f5a60aacb2830b34025c87a27a027e8be88f5f21da7ac07'), (33366, '6d6b5b487b6f44cbc8557282b42154212a55d885d90a9bf7ba90b8faaa0bebf0')),
    'tests/test_hia_retirement_state_native.py': ((71548, '113b0e8dce3c2987d361ba99eacea63f67a69062372a1b65914cf958050693a0'), (71607, '81b8c66434fdac85252eeac8a67ce23446abaf3b62b3f5efe6ae4f6843197754')),
    'tests/test_hia_scalar_profile_native.py': ((38350, '64fb0c87c69919c5e08718b4c4274c4669a1a91e1e34bb52abf3837747558cf3'), (38421, 'e0eb80a4c03ef8613f4b7f7c3c66f8f60049c06c534551b7f0905d54fcb09a73')),
    'tests/test_hia_selfhost_linked_observer.py': ((53252, '591e3ffb99d78491738ce5b097892723ade7fc0d6f414ea3068d2f9b2dd50cce'), (52986, 'b093864e5e5830c724d99d421e22878480f3dcbcac965d31575ba0f2baca86c4')),
    'tests/test_hia_service_artifact_native.py': ((45734, '9f63ae29e9648e833061a09687cabb757a28e8a44b50aa98612a043af91b58e6'), (45803, 'fbd93c9f55f7feac7db4d20e9bf4000ec4f1a2d1d9890a196fa27629ce71fa29')),
    'tests/test_hia_service_context_native.py': ((35334, 'bf8d756179772e973661de0bb7e69ba12db7930f6166402fabe1d3636f343156'), (35403, '94bba1ba99cfeb29baa9eb34072514803af288a11d964f950c46bea431e92c1b')),
    'tests/test_hia_service_discovery_native.py': ((14818, '58da73051dcbf74e3d3354ce6c2b2fdcd255025f8b1bee88388a1b324a24549d'), (14871, '3cfb4639a0120081f50568717aee41b2e47b94868ecf109b1104d30067d387a8')),
    'tests/test_hia_service_inspection_native.py': ((20563, '60d44eb69f4052f4846164460fc6797336e88506b674c50c77f7b3ba94ab24c6'), (20632, '1492a7601563b175b675ec9ed078e987ac7ed818add09c8419453dd0c84b3ed1')),
    'tests/test_hia_service_inspection_public_lifetime.py': ((7814, 'e6dd5ca741cc87d79339ca31b5711b8086819cbf63dd26d1465330b05c61038e'), (7751, '239f327c2d0ed61d05de201fea6c278ce2481eb2e2e01c4ea3d91c59912a26c3')),
    'tests/test_hia_service_read_native.py': ((19336, '7bae72c81ce95388840d26a876355607ff86c217ac0fb7c7b801336340627e4a'), (19405, 'f363c308dd339870c94673bcf741fb406d3e595ce7e838198b283cc0d26edf9f')),
    'tests/test_hia_service_slot_native.py': ((19777, 'fc41f42b79a53aff9b71867a4d6f5c4785661bb62b379c7015eed88bc339d0e8'), (19844, 'e1dae0e3ad0445e432ade0137afb4488ac6d460c0592c3501f2c16039fa9158c')),
    'tests/test_hia_service_verification_finalization_native.py': ((8334, '4149700ab5eb480eb901a9b82f5f9a068208469b82c9234929c9018c90bedcf5'), (8135, 'd8a922c7837af9f2f43fcc8c0470f7a98bbfed58a68ff40373b81adb37519763')),
    'tests/test_hia_service_verification_native.py': ((18622, '8b665a4d65ddfc11ff52a50882e6f54d08428d1be3b91e2bebee716da3a0a8e8'), (18675, 'baef21abe03b221e65618fe3ed5a2b6d538737ba51ab405ccf0369d1c86b131f')),
    'tests/test_hia_sha256_stream_transition_equivalence.py': ((29313, '3ab7b83da5747eea37801c8dd5e543ebdbeb3c0ba00fef281298ab6cb5251782'), (28125, 'c263ea809f7e91e64fc14d0161e69a5d8cd11370adffcea2c641065fee1d1124')),
    'tests/test_hia_slot_ledger_native.py': ((32390, '69a2824787de28d9ff642978ea5fbafd52f5877f5201e0065fb96c419c8e1161'), (32364, 'cfd2224fa96ef8c6a08a5aeb44f9d7576bf7fbaa611813ee0233edac7d5dcef8')),
    'tests/test_hia_slot_ledger_native_integration.py': ((85231, '50699c2dacdf503d5d820466ab590a9786dd2023d2d4fa06bedf1c9673d9ff42'), (85213, 'e6aacdb28c34890f897b09d088ede33cd1360a9e8cf09ba44e48fecd1187ffd1')),
    'tests/test_hia_slot_operation_series_native.py': ((13471, 'ad33b48304b0c91def0b6c87cf4d9c8cf9a18c91fed4e21f8d26be57879e969f'), (13448, '121d9473f1c0c5094ffbd4ad8143bbfdf689d31fdd1d4109fa411e3552154345')),
    'tests/test_hia_source_build.py': ((47516, '19587bd848697c174bbd541a41d9646dab0adf03edc8380121bbfed05d6b80f5'), (47453, '34c4947f9dc5468b69a555c015104f681490e5b876dfd38fa58e56245b4a6215')),
    'tests/test_hia_static_budget_native.py': ((22042, 'dce1e171396c26f8ad63c42acd3397bc1dd82e445a558b96d67d0dbadd665a50'), (22113, '476ee2cefe21fa64ec7999c3200975fc76624c756915066f421808c812936adc')),
    'tests/test_hia_store_artifact_profile_native.py': ((56361, 'eb1f915b35f7597f8988a321777c984cdc944f8993805a44f9b3c4462d6c8541'), (56430, 'a311c8e029c3219440efc0751a86854d6205955ad2de1c3ce297ffb6d0f22d7a')),
    'tests/test_hia_store_file_capture_native.py': ((14394, '43f3e5655b1a0e4f4e844f5fe28a38b6091263d5b41d86e1819c5f73c6a4685b'), (14447, '89abd068044dae5fe3900d3c5888310b9352871e383e0e542a1f4687b5bb8e10')),
    'tests/test_hia_store_file_capture_owned_fd_v2.py': ((6449, '4d0f9562c3549352402ebe320f468dcdf079665e746a00fe03478741c1f49256'), (6518, 'ca7c87b1d2a4711357e5097b022c5ece270311934149482ae5c756c69e89316c')),
    'tests/test_hia_store_lifecycle_native.py': ((36915, 'dbdfaa7e6066be64a08c31d461cd2f128dec5daa2564ebc07a8401b08c31d900'), (36984, 'e25dcbcd5cc4babec23e3289a61baed5ab9696498938890072ecc528db4e1a77')),
    'tests/test_hia_store_native_delivery.py': ((17260, '6e307f7360021c68d2538141f928832396a6cff94e846774487076625e62545b'), (16789, '0aa787ba9533def4d49224aed1a4545f24a64874e4e8f14e6652ce41e0a2fbe5')),
    'tests/test_hia_store_transaction_native.py': ((56263, '9358259e492e459acd14a42053a01aa7bafcbff6b95cce125e5da2018cce105d'), (56332, 'd87b86b3216a9df09e46eb44d1ab263f8b83401da3938c0a984a165a4f964ad9')),
    'tests/test_hia_store_transaction_owner_native.py': ((28461, '5a41c9b37c76d1192d3e0560e21ee50d74662fd229326f523f47d1d08012a1df'), (28387, 'b43b2ea8df6678dac1ee3f84f67dc9aefdc07fe0785bc0afc38045207685200f')),
    'tests/test_hia_task_helpers_native.py': ((31002, '59cb97d285cc2f5d2e6c7a4bb4e331f8e534123426a88f97594b481025d88ed5'), (31073, 'ca20d5f0925b624d00d5b315154d3046426587ba85eb59c5240092e079429896')),
    'tests/test_hia_transaction_journal_cleanup.py': ((15223, '332e0b12912c3d14b90d2bec22cf5f89e077f5a3bab30d3e9596cd3203968515'), (14564, 'f20578fda6fed04028b19a20634bfff6d9df04ea307f798473155cda140366fe')),
    'tests/test_hia_worker_native_helpers.py': ((68571, '476d6b99573b27ba9c8ff23a60013f0633dc1fb8246438ed773f3c0444a00fec'), (68634, '4fef9e2f0a8188f5f3a6c81e522b5babd3a1f0c0a88f58e286cdf762433caab3')),
    'tests/test_hia_worker_report_native.py': ((67441, 'b5f6c70f53259c23ed8aa8edd57ceadf3b49554e2de1ce9bf558fcdb8007239e'), (67512, '970657085c4722bf8d92e8f1e0468be042356dd53ec344c14c487e4053c1e369')),
    'tests/test_hia_worker_request_native.py': ((17176, '68a4ad3da68ae5b9248623f8227ce3354e0f085568b82740936d486485e1b47b'), (17247, '7809eea35b246f35ca50c7a5787ed1e2812687ae49029df61c84cc1922b05663')),
    'tests/test_hia_worker_scheduling_bundle.py': ((22471, 'e5797ee39859f2c4a8b24db40f42f640d400ed36e0202133ea94b545367bdc8f'), (22542, '8db515cf0478043c94f7504a45ded88377e857c00509cd09171c3ba32a4e56cb')),
    'tools/qualify_hia_agent_journal_callers.py': ((9065, 'fc2ad819fd36889164a24069bcd77e60849e1f985406e5bbdccd65dca3cfc6a1'), (9132, '3f798cb2bfadeb0ffc45ea4833f778b8b3a7770c0b2ffd0099f3642680d682ad')),
    'tools/qualify_hia_artifact_delivery_callers.py': ((18836, 'd5d9f8e1ee12e09bc709fb7edadd9bcc67b66d97ce25f946659578a42bfea93a'), (18731, '0c989e77f32aa0f041bd5858b097d3ba6188864168e8db3445cab49d30fba0fe')),
    'tools/qualify_hia_byte_wrapper_callers.py': ((42658, '7de7f0893323d13f94bbbd2a09f605c735844a9c4e5888622560c8ebc9785cae'), (42873, '93926748bb135988887eeff4feaf52bd37e4c6e3ce8c5934ccdfdd03568408d4')),
    'tools/qualify_hia_continuation_no_child.py': ((8363, '966266942311d5fb793a0c69cea0598d7895836317a46f43cbd0fa1d9a8e5ff6'), (8414, 'd2379394aef6f51fb384973b80e57d165b3e273bf012c99928c2b964bc4a5f88')),
    'tools/qualify_hia_core_emitter_callers.py': ((39038, 'b66b3ddad88a7b82a51d4e118c556da8a6f2cde3c5cd7dabe811f2fbfb1ba8a9'), (39180, '66c86ba0ebc0d037a07735436ce7ca1a68be1da9984e2aa33b85122df27a2bf7')),
    'tools/qualify_hia_core_lowering_callers.py': ((36934, '497912595108075defcc718befbf3a064a7e615b760c5bb63513e776e7c66e79'), (37003, 'b06cc353ecb46c42508f633accb5d70ff8341e21a93f0779d2119d8713dd9f3c')),
    'tools/qualify_hia_cost_ledger_callers.py': ((10465, 'bd9682ab67948b2632523b55d595becfed7fe1f860b2544bd8449f1c052a20a1'), (10516, '30842806afddf8e493cc968740e5aa947dc906d041a466ceab8c6f7e0d34e844')),
    'tools/qualify_hia_emission_callers.py': ((10831, 'fd676590a944d191d8d06eff1b421ccb183c3d06c43d96445c6f92461453d90d'), (10894, '47aa06e0ecbc5227b09e0f3429087173637e9d429af6acc7014fa203178a806c')),
    'tools/qualify_hia_evaluation_callers.py': ((15063, '29c40723460571b2d336e6f23adec005b3f4a89aead62c826efb391d9de762d9'), (15126, '7943e4d26b8ee83c65982f84e317579c1d687216e5fd7151259a67a617b11d6b')),
    'tools/qualify_hia_execution_observation_callers.py': ((7916, 'f2cff32b4e9fa84c80c49f2d77d5d76bec71c545e516fd67805c365bf32aad83'), (7975, 'a90fac7a3a62248de150c8b533fc50df41fa13ff65050fb4393f33a99f73b48d')),
    'tools/qualify_hia_full_cost_callers.py': ((6486, 'a2933c04474689512da9e1cf9f79b2df3f2b1c897d4e7bc50232e7a246b862e3'), (6549, '377087d9cd7eb4b28741593625b98123de2d94dd47423b28b3b813ed898a3af1')),
    'tools/qualify_hia_generation_retention_callers.py': ((11777, '324fa308d3bc064d878ff5885c1c4214306d2b8e97f4c99d06e79dc813812575'), (11840, 'a54d4dd2f8c05f7186cc227f7cbe33313e6f9ad00151244cd4db39a6a488fc78')),
    'tools/qualify_hia_json_wire_native_callers.py': ((21506, '1dcfdd57e8c61a21b60ac238678ed220d6dce9ffa52c0ef48f807717773282c1'), (21575, '1ba145b158be62cd08631afb3681591dee2fd1ff338289b8561f0ce09c89b879')),
    'tools/qualify_hia_machine_encoding_native_callers.py': ((9529, '95217b125d192aafbd0745b8c2a8633c531d33279c8d782cd350f5131ca23f4d'), (9598, '14f38152527e0e771ab061e7d71f5061dd03976639f990804ba666a810992ebb')),
    'tools/qualify_hia_machine_instructions_callers.py': ((12852, 'fe3d2bde44e1962de4ceed434b8e378e381bc4bb5f53b27dff8a2047df2f348a'), (12917, '76f87d7938f9bb69526e3f1d545510b0acfd821454f5cf280406e28e4cdcb944')),
    'tools/qualify_hia_machine_object_callers.py': ((46294, '8c345d59cb08b126efc53a2f79cea238447081c249a05cb551a23b0f313aa131'), (46582, '8c723c5f03599458233e3dc1be8a42536e55976d0b7f76188827809cb4b60d7c')),
    'tools/qualify_hia_machine_plan_native_callers.py': ((7538, '4a57b51ed158e98d6a4d5c26d4b371b781203b8c6a4f2b8da1a1f64ae19a32a0'), (7476, 'c8e405b254da807407bd925a5ff53e6bdcb89d7268ec3edff2b424979f31d72a')),
    'tools/qualify_hia_machine_state_callers.py': ((25885, 'cdb5bca1f65eb88adc7704d17f6bee6c471fcfde3681ff9dc16e307193f888dd'), (24785, '06de3f8437e2013ff0e2edc005a3b7d5aa3e4af3c403008d0b914706a57515c1')),
    'tools/qualify_hia_native_build_admission_callers.py': ((11036, 'eece82a138051c392a409c54850997e4104371b3588e8365b0ae3b6b2227d864'), (11099, 'e0c09818985203b1308b2ea53277b834ae429181d1bec54a684bd00cbb47a611')),
    'tools/qualify_hia_native_delivery.py': ((13055, 'c8967cc610f07be6e7e2c87d4b1850d2bb201df3a41b637213519acff5fbba16'), (12973, 'ce4be5f9205be3f9c9f4d1045790031abca3ccd3a73aaa06d780a182ad20c663')),
    'tools/qualify_hia_patch_impact_callers.py': ((6117, 'c37a465a78e8a05c94ffca2c009fe36e90fb591acd15917b0100e619249319c5'), (6180, '6966badb93b8c5a1eb4cb68bf180fdc40412e06a2f1ed4f27a2ff4b630da10f8')),
    'tools/qualify_hia_publication_measurement_callers.py': ((7044, '8cd4d198d0915d154f94723e8beeb5f3279b37e783bdfcf7c8950291f94ec591'), (7107, 'a3a5cf35f701f88265232210cbf43d2bbbe2dffdd740350cf171ceb0f559babe')),
    'tools/qualify_hia_scalar_profile_callers.py': ((9793, '2f478c9b1e755ec93f8cb281c86ebff57f083269b183a3f3206d0bc73999f6cf'), (9856, '8488bd80ecaa1a9ccd762ae991b918b7e331adec7814c767c2876db21dc2f472')),
    'tools/qualify_hia_service_artifact_callers.py': ((8797, '6c4a8f1d514a2421738f004edc51c66a8f4d6184d48e7bcf5d76776abb5b0eee'), (8862, '0d247819fbf0ee2905745566f820e6910c0c526f2457b0558970a2d13dd0e21b')),
    'tools/qualify_hia_service_bootstrap_callers.py': ((20824, '898ba13203e4fa31d91f00abd020e4d88f08ad89e72dcf9f4da77e4f4af9b351'), (20129, 'd54a0a23a99303ebc2c233e9568bf97af5b4bdc41c497bf4e05cc21fb8d2d795')),
    'tools/qualify_hia_service_context_callers.py': ((11881, 'c4de90f655d57d0036313f5a454863bfd85b40adfbe73a16efb16ce13eff2d6f'), (11944, 'c7825a2724acb1d7137a8ad1c24aac0f865c227c5b2c27bf4ea52f05c2d8d863')),
    'tools/qualify_hia_service_discovery_callers.py': ((13807, '5ce31de74cdf638aa420f54ce832c768b5e495ba4817f2fa3c43957c9d9a0b0e'), (13860, 'c1025658abc1202fcc7027de153d62a996c632ef31e98bc3004a394c777d14f2')),
    'tools/qualify_hia_service_inspection_callers.py': ((11661, '223fea4a20e721bec4a24fed3c8821f3d756fff2c68e375de76b9da2c43f9ebe'), (11724, 'c80534d53ea05779fb1e6202a4ee03179a1750a5557f96ba5e2f40068ce810d1')),
    'tools/qualify_hia_service_lease_callers.py': ((11521, '768363114e61b4aa315202de59a2f815a5abf5157c95111aebd480404e5a00ca'), (11586, '49c32ffb40615d5fd350859e05520324ad27214df2811a62ede2d9f4f9ef4511')),
    'tools/qualify_hia_service_read_callers.py': ((11046, '89506a81ee2cbf39bd4dd9f5efdfbd1264fd516d306242cfd430ccbe441bc4fc'), (11109, 'f5fd3450b88826e161fc0294ff7fa5b0804c35cb491c53a1ebf29000c6b096d2')),
    'tools/qualify_hia_service_slot_callers.py': ((13136, '77b81726ad1777d4e83603c66e5ea678c6362d6505ae206bf29800a5c37aea62'), (13201, '4991d10e646b5ead7b61c8d22729236f298f42b82ebf02dc43ca38b60ca2c4b7')),
    'tools/qualify_hia_service_verification_callers.py': ((13569, '43504e98dbdac948e28fd547c6006b180636f54139f7110e70289dfdfd4e93d9'), (13622, 'cec5abc9329e7db68e80fb411d31dfeaa25cb42469f951ed9ff5408ea808a8a8')),
    'tools/qualify_hia_slot_operations_callers.py': ((12798, '59a187498a565882fe3bd99a16588131d624e5ea1b218ccd3d05e85f0aa42867'), (12742, 'd7195cbff9dcca5bcb937ffb11e58be23e9bfa23f6d961054ba1754666e70b26')),
    'tools/qualify_hia_static_budget_callers.py': ((6420, '3e76206cdd4104e1024f8b69fc41f0e575778043f7636db725ad4ea92a9e04cf'), (6483, 'a9baf440dd04a787f86586fcff0bd362b213f5c962298a2372361e101cce95be')),
    'tools/qualify_hia_store_artifact_profile_callers.py': ((14867, '59e7e38e653a47a4c0780c95f2d073cfa2e714f8e8001c13cf640a7d255857f9'), (14932, '4e47769f3c67a43170773aa39eb4b461af8fcc32eb513708a0cbf932b6b406ec')),
    'tools/qualify_hia_store_file_capture_callers.py': ((9030, 'e9ca521a41babd335ae165eb39ea011823d8a1206fce366aaf4a44d993b0aeaa'), (9095, 'bfa3814c32c922be0844dcfd375a7bdc7bb71c735f733f84e1ca40dae34ac6da')),
    'tools/qualify_hia_store_lifecycle_callers.py': ((10080, '2d49a7ae102d1ac11015a394a4bdf5cb71a3642b4d6818755097a699e65c3a04'), (10143, '24b530be08ed7b237b22b6f8b66a07724bdb4ea6fc4f7963f9881791e64c59c9')),
    'tools/qualify_hia_store_transaction.py': ((21711, '05dd836fd4e1bc8b4d1e556339f3c4caef86e0f8fea1d7404cb5c1e8a5df5802'), (21627, '9fed26aab23818aee9ed9934cb58febc5b0792b213e2075ea1968b43826efeb8')),
    'tools/qualify_hia_store_transaction_callers.py': ((8918, '1ee5ae3cf9d14754009ae6652536730aa7b05204cf9513763221e11298adb754'), (8983, '08744e52e18bbaac490fcf76a5f364ec246789a60858d52e383d1b70bd6032bc')),
}
PATHS = tuple(KNOWN_PINS)
KNOWN_CURRENT = {name: {'bytes': row[0][0], 'sha256': row[0][1]}
                 for name, row in KNOWN_PINS.items()}


def pin(raw):
    if type(raw) is not bytes:
        raise ValueError('native cold history requires immutable physical bytes')
    return {'bytes': len(raw), 'sha256': sha256(raw).hexdigest()}


def _name(value):
    if (type(value) is not str or not value or '\x00' in value or '\\' in value
            or PurePosixPath(value).is_absolute() or '..' in PurePosixPath(value).parts
            or str(PurePosixPath(value)) != value or value == '.'):
        raise ValueError('native cold history path is not canonical')
    return value


def _pin(value):
    if (type(value) is not dict or set(value) != {'bytes', 'sha256'}
            or type(value['bytes']) is not int or value['bytes'] < 0
            or type(value['sha256']) is not str
            or re.fullmatch('[0-9a-f]{64}', value['sha256']) is None):
        raise ValueError('native cold history pin is not precisely typed')
    return value


def _known(name, which):
    length, digest = KNOWN_PINS[name][which]
    return {'bytes': length, 'sha256': digest}


def _pairs(items):
    value = {}
    for key, item in items:
        if key in value:
            raise ValueError('native cold authority contains duplicate JSON keys')
        value[key] = item
    return value


def _record(name, row, *, current=True):
    if (type(row) is not dict or set(row) != {
            'current', 'current_git_blob', 'predecessor', 'predecessor_commit',
            'predecessor_git_blob', 'splices'}):
        raise ValueError('native cold whole-file relation has unexpected fields')
    if _pin(row['predecessor']) != _known(name, 1):
        raise ValueError('native cold original complete predecessor changed')
    if current and _pin(row['current']) != _known(name, 0):
        raise ValueError('native cold complete current source changed')
    _pin(row['current'])
    for key in ('current_git_blob', 'predecessor_git_blob', 'predecessor_commit'):
        if type(row[key]) is not str or re.fullmatch('[0-9a-f]{40}', row[key]) is None:
            raise ValueError('native cold relation Git identity differs')
    if type(row['splices']) is not list or not row['splices']:
        raise ValueError('native cold relation has no exact splices')
    end = 0
    for splice in row['splices']:
        if (type(splice) is not dict
                or set(splice) != {'offset', 'current_hex', 'predecessor_hex'}
                or type(splice['offset']) is not int or splice['offset'] < end
                or type(splice['current_hex']) is not str
                or type(splice['predecessor_hex']) is not str):
            raise ValueError('native cold splice is not precisely typed')
        try:
            after = bytes.fromhex(splice['current_hex'])
            before = bytes.fromhex(splice['predecessor_hex'])
        except ValueError as error:
            raise ValueError('native cold splice is not hexadecimal') from error
        if (not after or after.hex() != splice['current_hex']
                or before.hex() != splice['predecessor_hex']):
            raise ValueError('native cold splice is not canonical')
        end = splice['offset'] + len(after)
        if end > row['current']['bytes']:
            raise ValueError('native cold splice exceeds the complete source')
    return row


def _relations(frozen, previous):
    if pin(frozen) != FIXTURE_PIN or pin(previous) != PREVIOUS_PIN:
        raise ValueError('native cold fixed authority bytes changed')
    value = json.loads(frozen, object_pairs_hook=_pairs)
    original = json.loads(previous, object_pairs_hook=_pairs)
    if (type(value) is not dict
            or set(value) != {'schema', 'files', 'previous_authority', 'updated_paths'}
            or value['schema'] != 'hepta.hia.native-cold-caller-source-relations.v2'
            or type(value['files']) is not dict or set(value['files']) != set(PATHS)
            or value['previous_authority'] != {'path': PREVIOUS_FIXTURE, **PREVIOUS_PIN}
            or type(value['updated_paths']) is not list
            or value['updated_paths'] != list(INTEGRATED_PATHS)
            or type(original) is not dict or set(original) != {'schema', 'files'}
            or original['schema'] != 'hepta.hia.native-cold-caller-source-relations.v1'
            or type(original['files']) is not dict or set(original['files']) != set(PATHS)):
        raise ValueError('native cold fixed authority scope differs')
    original_authority = value['previous_authority']
    if (type(original_authority) is not dict
            or set(original_authority) != {'path', 'bytes', 'sha256'}):
        raise ValueError('native cold original authority descriptor differs')
    _pin({'bytes': original_authority['bytes'], 'sha256': original_authority['sha256']})
    for name, row in value['files'].items():
        _record(name, row)
        old = _record(name, original['files'][name], current=False)
        changed = {key for key in row if row[key] != old[key]}
        if (row['predecessor'] != old['predecessor']
                or not changed <= {'current', 'current_git_blob', 'splices'}
                or (name not in INTEGRATED_PATHS and row != old)):
            raise ValueError('native cold original relation was changed: ' + name)
    return value['files']


def _inverse(name, raw, row):
    _record(name, row)
    if pin(raw) != row['current']:
        raise ValueError('native cold supplied source is not its exact current image')
    pieces, end = [], 0
    for splice in row['splices']:
        at = splice['offset']
        after = bytes.fromhex(splice['current_hex'])
        before = bytes.fromhex(splice['predecessor_hex'])
        if at < end or raw[at:at + len(after)] != after:
            raise ValueError('native cold inverse does not match actual bytes')
        pieces.extend((raw[end:at], before))
        end = at + len(after)
    prior = b''.join((*pieces, raw[end:]))
    if pin(prior) != row['predecessor']:
        raise ValueError('native cold complete predecessor differs')
    pieces, end, displacement = [], 0, 0
    for splice in row['splices']:
        after = bytes.fromhex(splice['current_hex'])
        before = bytes.fromhex(splice['predecessor_hex'])
        at = splice['offset'] + displacement
        if not end <= at <= at + len(before) <= len(prior):
            raise ValueError('native cold forward coordinates differ')
        if prior[at:at + len(before)] != before:
            raise ValueError('native cold forward predecessor bytes differ')
        pieces.extend((prior[end:at], after))
        end = at + len(before)
        displacement += len(before) - len(after)
    if b''.join((*pieces, prior[end:])) != raw:
        raise ValueError('native cold complete forward replay differs')
    return prior


class _History:
    def __init__(self, root, take):
        self.root = Path(root).resolve(strict=True)
        if not self.root.is_dir() or not callable(take):
            raise ValueError('native cold history requires an explicit directory and reader')
        self.take = take
        self.captures = {}
        self.proofs = {}
        self.records = None
        self.module_path = Path(__file__).resolve(strict=True)
        self.module_bytes = self.module_path.read_bytes()
        self.review = {
            'schema': 'hepta.hia.native-cold-caller-history.v1',
            'native_cold_caller_sources': self.proofs,
            'actual_captured_files': {},
            'historical_inputs': {},
            'terminal_reread_identical': False,
            'whole_native_delivery_qualified': False,
        }

    def read(self, name):
        name = _name(name)
        raw = self.take(self.root / name)
        pin(raw)
        if name in self.captures and self.captures[name] != raw:
            raise ValueError('native cold physical source changed between reads: ' + name)
        self.captures[name] = raw
        self.review['actual_captured_files'][name] = pin(raw)
        self.review['terminal_reread_identical'] = False
        return raw

    def bind_module(self):
        if (self.read(HISTORY_SOURCE) != self.module_bytes
                or self.module_path.read_bytes() != self.module_bytes):
            raise ValueError('native cold reader module differs from supplied physical root')

    def authorities(self):
        # These reads are deliberately repeated on every new projection. Only
        # decoding is cached; physical bytes and complete source are never cached.
        frozen = self.read(FIXTURE)
        previous = self.read(PREVIOUS_FIXTURE)
        helper = self.read(SOURCE)
        if pin(helper) != COLD_CALLER_HELPER_PIN:
            raise ValueError('native cold complete authoring helper differs')
        if self.records is None:
            self.records = _relations(frozen, previous)
        return self.records

    def prior(self, name):
        raw = self.read(name)
        actual = pin(raw)
        if name not in KNOWN_PINS or actual != _known(name, 0):
            # No qualification or exception is granted. Original strict gates
            # still decide whether this unprojected legacy/unknown source is valid.
            self.review['historical_inputs'][name] = actual
            return raw
        row = self.authorities()[name]
        prior = _inverse(name, raw, row)
        self.bind_module()
        selected = (name, FIXTURE, PREVIOUS_FIXTURE, SOURCE, HISTORY_SOURCE)
        for path in selected:
            self.read(path)
        self.proofs[name] = {
            'schema': SCHEMA,
            'path': name,
            'physical_current': actual,
            'predecessor': dict(row['predecessor']),
            'authority': {'path': FIXTURE, **FIXTURE_PIN},
            'original_authority': {'path': PREVIOUS_FIXTURE, **PREVIOUS_PIN},
            'helper': {'path': SOURCE, **COLD_CALLER_HELPER_PIN},
            'reader': {'path': HISTORY_SOURCE, **pin(self.module_bytes)},
            'complete_predecessor_restored': True,
            'complete_current_replayed': True,
            'actual_captured_files': {path: pin(self.captures[path]) for path in selected},
            'terminal_reread_identical': True,
            'whole_native_delivery_qualified': False,
        }
        self.review['historical_inputs'][name] = pin(prior)
        return prior

    def prior_take(self, path):
        path = Path(path)
        try:
            name = _name(path.relative_to(self.root).as_posix())
        except ValueError as error:
            raise ValueError('native cold historical reader escaped its physical root') from error
        return self.prior(name)

    def verify(self):
        self.bind_module()
        for name, expected in tuple(self.captures.items()):
            if self.read(name) != expected:
                raise ValueError('native cold physical input changed at terminal: ' + name)
        if self.module_path.read_bytes() != self.module_bytes:
            raise ValueError('native cold reader module changed at terminal')
        self.review['terminal_reread_identical'] = True


def prepare(root, captured, *, take=Path.read_bytes):
    """Return explicit predecessor views and a live physical-capture history."""
    if type(captured) is not dict:
        raise ValueError('native cold supplied captures must be a dictionary')
    state = _History(root, take)
    state.bind_module()
    # Freeze every supplied physical input before projecting any one of them.
    for name, raw in captured.items():
        _name(name)
        pin(raw)
        if state.read(name) != raw:
            raise ValueError('native cold supplied source differs from physical root: ' + name)
    projected = {name: state.prior(name) for name in captured}
    state.verify()
    return projected, {
        'prior_take': state.prior_take,
        'review': state.review,
        'captures': state.captures,
        '_state': state,
    }


def verify_unchanged(history):
    if history is None:
        return
    if (type(history) is not dict or type(history.get('_state')) is not _History
            or history.get('captures') is not history['_state'].captures
            or history.get('review') is not history['_state'].review
            or history.get('prior_take') != history['_state'].prior_take):
        raise ValueError('native cold history identity was substituted')
    history['_state'].verify()


def cold_caller_source(root, name, raw, *, take=Path.read_bytes):
    _name(name)
    actual = pin(raw)
    if name not in KNOWN_CURRENT or actual != KNOWN_CURRENT[name]:
        path = Path(root) / name
        first = take(path)
        pin(first)
        if first != raw:
            raise ValueError('native cold supplied legacy source differs from physical root')
        last = take(path)
        pin(last)
        if last != first:
            raise ValueError('native cold legacy physical source changed at terminal')
        return raw, None
    projected, history = prepare(root, {name: raw}, take=take)
    return projected[name], history['review']['native_cold_caller_sources'].get(name)


def bind_cold_caller_adjustment(entry, physical, proof):
    if proof is None:
        return entry
    if (type(entry) is not dict or type(proof) is not dict
            or set(proof) != {'schema', 'path', 'physical_current', 'predecessor',
                'authority', 'original_authority', 'helper', 'reader',
                'complete_predecessor_restored', 'complete_current_replayed',
                'actual_captured_files', 'terminal_reread_identical',
                'whole_native_delivery_qualified'}
            or proof['schema'] != SCHEMA
            or type(proof['path']) is not str or proof['path'] not in KNOWN_PINS
            or entry.get('path') != proof['path']):
        raise ValueError('native cold adjustment path or proof scope differs')
    name = proof['path']
    actual = pin(physical)
    prior = _pin({'bytes': entry.get('current_bytes'), 'sha256': entry.get('current_sha256')})
    if (_pin(proof['physical_current']) != actual or actual != _known(name, 0)
            or _pin(proof['predecessor']) != _known(name, 1)
            or prior not in (proof['predecessor'], actual)):
        raise ValueError('native cold adjustment lost its complete physical predecessor')
    expected_maps = {
        'authority': {'path': FIXTURE, **FIXTURE_PIN},
        'original_authority': {'path': PREVIOUS_FIXTURE, **PREVIOUS_PIN},
        'helper': {'path': SOURCE, **COLD_CALLER_HELPER_PIN},
        'reader': {'path': HISTORY_SOURCE, **pin(Path(__file__).read_bytes())},
    }
    for key, expected in expected_maps.items():
        value = proof[key]
        if type(value) is not dict or set(value) != {'path', 'bytes', 'sha256'}:
            raise ValueError('native cold adjustment authority shape differs')
        _pin({'bytes': value['bytes'], 'sha256': value['sha256']})
        if value != expected:
            raise ValueError('native cold adjustment authority identity differs')
    captures = proof['actual_captured_files']
    if type(captures) is not dict:
        raise ValueError('native cold adjustment capture map differs')
    for value in captures.values():
        _pin(value)
    if captures != {name: actual, FIXTURE: FIXTURE_PIN,
                    PREVIOUS_FIXTURE: PREVIOUS_PIN, SOURCE: COLD_CALLER_HELPER_PIN,
                    HISTORY_SOURCE: {key: expected_maps['reader'][key] for key in ('bytes', 'sha256')}}:
        raise ValueError('native cold adjustment physical capture identities differ')
    if (proof['complete_predecessor_restored'] is not True
            or proof['complete_current_replayed'] is not True
            or proof['terminal_reread_identical'] is not True
            or proof['whole_native_delivery_qualified'] is not False):
        raise ValueError('native cold adjustment proof flags are not exact booleans')
    return {
        **entry, 'current_bytes': actual['bytes'], 'current_sha256': actual['sha256'],
        'native_cold_caller_source': proof,
    }
