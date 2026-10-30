"""Read-only Linux resource admission; an unknown limit never means capacity."""
from __future__ import annotations

from fractions import Fraction
import os
from pathlib import Path, PurePosixPath
import platform
import time

MIN_CPUS = 4
MIN_BYTES = 4 * 1024**3


def _unescape(value):
    for escaped, literal in ((r"\040", " "), (r"\011", "\t"), (r"\012", "\n"), (r"\134", "\\")):
        value = value.replace(escaped, literal)
    return value


def _absolute(value):
    path = PurePosixPath(value)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("untrusted cgroup path")
    return path


def cgroup_observation(membership, mountinfo, read_text):
    # Hybrid/v1 controllers could impose tighter invisible limits. They are
    # unsupported here; a parallel 0:: entry cannot make them disappear.
    for line in membership.splitlines():
        if line and not line.startswith("0::"):
            raise ValueError("hybrid or cgroup-v1 membership is unsupported")
    groups = [line.split(":", 2)[2] for line in membership.splitlines()
              if line.startswith("0::")]
    if len(groups) != 1:
        raise ValueError("one unified cgroup-v2 membership is required")
    member = _absolute(groups[0])
    mounts = []
    for line in mountinfo.splitlines():
        left, separator, right = line.partition(" - ")
        if not separator or right.split()[0] != "cgroup2":
            continue
        fields = left.split()
        root, target = _absolute(_unescape(fields[3])), _absolute(_unescape(fields[4]))
        if member.is_relative_to(root):
            mounts.append((root, target))
    if len(mounts) != 1:
        raise ValueError("unambiguous visible cgroup-v2 mount required")
    mount_root, mount = mounts[0]
    current = mount / member.relative_to(mount_root)
    levels = []
    cpu_bounds, memory_bounds = [], []
    node = current
    while True:
        controllers = read_text(str(node / "cgroup.controllers")).split()
        parent_control = None if node == mount else read_text(str(node.parent / "cgroup.subtree_control")).split()
        row = {"path": str(node), "controllers": controllers,
               "parent_subtree_control": parent_control}

        def limit(name, controller):
            try:
                return read_text(str(node / name)).strip()
            except FileNotFoundError:
                if node == mount and mount_root == PurePosixPath("/"):
                    row[name + "_missing_reason"] = "visible_hierarchy_root_has_no_limit_interface"
                    return "root-unlimited"
                if node != mount and controller not in controllers and controller not in parent_control:
                    row[name + "_missing_reason"] = "controller_inactive_at_this_node"
                    return "inactive"
                raise ValueError("unknown missing cgroup interface: " + str(node / name))

        cpu = limit("cpu.max", "cpu")
        row["cpu.max"] = cpu
        if cpu not in {"root-unlimited", "inactive"}:
            values = cpu.split()
            if len(values) != 2 or not values[1].isdigit() or int(values[1]) <= 0:
                raise ValueError("invalid cpu.max")
            if values[0] != "max":
                if not values[0].isdigit() or int(values[0]) <= 0:
                    raise ValueError("invalid CPU quota")
                cpu_bounds.append(Fraction(int(values[0]), int(values[1])))
        memory = limit("memory.max", "memory")
        row["memory.max"] = memory
        if memory not in {"max", "root-unlimited", "inactive"}:
            if not memory.isdigit():
                raise ValueError("invalid memory.max")
            used = read_text(str(node / "memory.current")).strip()
            if not used.isdigit():
                raise ValueError("invalid memory.current")
            row["memory.current"] = int(used)
            row["headroom_bytes"] = int(memory) - int(used)
            memory_bounds.append(row["headroom_bytes"])
        else:
            try:
                used = read_text(str(node / "memory.current")).strip()
                if not used.isdigit():
                    raise ValueError("invalid memory.current")
                row["memory.current"] = int(used)
            except FileNotFoundError:
                row["memory.current"] = None
        levels.append(row)
        if node == mount:
            break
        node = node.parent
    return {"version": 2, "membership": str(member), "mount_root": str(mount_root),
            "mount_point": str(mount), "levels": levels,
            "cpu_quota": min(cpu_bounds) if cpu_bounds else None,
            "memory_headroom_bytes": min(memory_bounds) if memory_bounds else None,
            "memory_limit_state": "finite" if memory_bounds else "no_visible_finite_limit"}


def evaluate(*, affinity, cpu_count, meminfo, membership, mountinfo, read_text,
             machine="x86_64", system="Linux"):
    """Pure decision over observed metadata; tests can supply bounded fixtures."""
    result = {"minimum_effective_cpus": MIN_CPUS, "minimum_free_bytes": MIN_BYTES,
              "system": system, "machine": machine, "cpu_count": cpu_count,
              "affinity": sorted(affinity) if affinity is not None else None,
              "cgroup_membership_text": membership,
              "eligible": False, "errors": []}
    try:
        if system != "Linux" or machine != "x86_64":
            raise ValueError("the registered native runtime requires Linux x86_64")
        if affinity is None or not affinity or type(cpu_count) is not int or cpu_count <= 0:
            raise ValueError("CPU availability is unknown")
        values = {}
        for line in meminfo.splitlines():
            key, separator, value = line.partition(":")
            if separator and key in {"MemTotal", "MemAvailable"}:
                if key in values:
                    raise ValueError("duplicate memory field")
                parts = value.split()
                if len(parts) != 2 or parts[1] != "kB" or not parts[0].isdigit():
                    raise ValueError("invalid memory field")
                values[key] = int(parts[0]) * 1024
        if "MemAvailable" not in values:
            raise ValueError("MemAvailable is unknown")
        result["host_memory_bytes"] = values
        cgroup = cgroup_observation(membership, mountinfo, read_text)
        quota = cgroup.pop("cpu_quota")
        effective = min(Fraction(len(affinity)), Fraction(cpu_count),
                        quota if quota is not None else Fraction(len(affinity)))
        cgroup["cpu_quota_fraction"] = ([quota.numerator, quota.denominator]
                                       if quota is not None else None)
        result.update(cgroup=cgroup, effective_cpus=float(effective))
        memory = cgroup["memory_headroom_bytes"]
        result["eligible"] = bool(effective >= MIN_CPUS
            and values["MemAvailable"] >= MIN_BYTES
            and (memory is None or memory >= MIN_BYTES))
        if not result["eligible"]:
            result["errors"].append("recorded CPU or memory availability is below the fixed threshold")
    except (OSError, ValueError, IndexError, TypeError) as error:
        result["errors"].append(type(error).__name__ + ": " + str(error))
    return result


def observe():
    """Use real kernel metadata only; there is no CLI override or lower limit."""
    started = time.monotonic_ns()
    try:
        affinity = os.sched_getaffinity(0)
        result = evaluate(affinity=affinity, cpu_count=os.cpu_count(),
            meminfo=Path("/proc/meminfo").read_text(),
            membership=Path("/proc/self/cgroup").read_text(),
            mountinfo=Path("/proc/self/mountinfo").read_text(),
            read_text=lambda name: Path(name).read_text(),
            machine=platform.machine(), system=platform.system())
    except (OSError, AttributeError) as error:
        result = {"eligible": False, "errors": [type(error).__name__ + ": " + str(error)]}
    result.update(observed_unix_ns=time.time_ns(), observation_wall_ns=time.monotonic_ns()-started,
                  scope="One read-only admission observation; no isolation or constant-resource guarantee")
    return result
