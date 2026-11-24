"""Register the complete HIA system Jobctl in the ordinary native release DAG."""
from pathlib import Path
from tools.generate_hia_mcp_release import POLICY_PATH, FILTER_PATH, check_packer_host, check_sequential_layout
from tools.generate_hia_system_jobctl_packer import MAGIC, MODULES, template

ROOT = Path(__file__).resolve().parents[1]
PROGRAMS = 'examples/hia_bootstrap/'
PRODUCT = 'hepta-runtime-jobctl'


def component_paths():
    return {**{role: PROGRAMS + name + '.hepta' for role, name in MODULES},
            'packer': PROGRAMS + 'system_jobctl_packer.hepta'}


def source_paths():
    return tuple(sorted(set(component_paths().values()) | {
        POLICY_PATH, FILTER_PATH, PROGRAMS + 'selfhost.hepta',
        PROGRAMS + 'source_build_packer.hepta',
        'tools/hia_source_build_syscalls.S', 'tools/hia_system_jobctl_syscalls.S',
        'tools/generate_hia_system_jobctl_packer.py',
        'tools/generate_hia_system_jobctl_control.py',
        'tools/generate_hia_system_jobctl_start.py',
        'tools/generate_hia_system_jobctl_worker_profile.py',
        'tools/generate_hia_system_jobctl_release.py',
        'tools/generate_hia_mcp_release.py', 'tools/build_hia_system_jobctl.py',
    }))


def append_recipe(recipe):
    """Compile and source-bind the packer before it accepts twenty native owners."""
    paths = component_paths()
    sources, images = recipe.compile({Path(path).name: path for path in paths.values()})
    host = recipe.kit(Path(POLICY_PATH).name, Path(FILTER_PATH).name)[0]

    def concat(*parts):
        return recipe.node(16, parts)

    def extent(part):
        return recipe.node(17, (part,))

    name = Path(paths['packer']).name
    frame = concat(recipe.literal(b'HIAMCF01'), extent(sources[name]),
                   extent(images[name]), sources[name], images[name])
    packer = recipe.run(host, frame)
    check_packer_host(recipe, packer, images[name])
    parts = [images[Path(paths[role]).name] for role, _ in MODULES]
    wire = concat(recipe.literal(MAGIC), *(extent(part) for part in parts), *parts)
    product = recipe.run(packer, wire, operation=0)
    prefix, holes = template()
    check_sequential_layout(recipe, product, prefix, holes,
                            dict(zip((role for role, _ in MODULES), parts, strict=True)))
    recipe.publish(PRODUCT, product)
    return product
