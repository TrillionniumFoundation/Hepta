# Standalone native HIA MCP process owner

The service executable runs the public HIA MCP protocol, configuration admission,
file capture, lifetime controller locks, request scheduling, cancellation and job
transport in checked-in HIA. The assembly adapter translates bounded offset plans
to Linux syscalls. Python in tools is development authoring and qualification,
not an installed service continuation.

## Process and custody

The command takes four administrator-owned inputs: configuration path and SHA256,
controller manifest path and SHA256. It captures the configuration, nineteen
controller roles, OpenSSH and the embedded bridge into independently checked,
sealed descriptors. Both historical controller flocks remain held for the
service lifetime. A separate writable memfd with fixed size and seals carries
the bridge's predecessor replay cache across requests.

The connection accepts the original 8 MiB public line boundary. Up to 32 request
workers run concurrently, while ping, discovery and cancellation stay responsive.
Each worker stages one complete response in a private memfd; the parent admits and
emits it only after the worker exits. Cancellation terminates the matching
canonical JSON request ID and preserves any previously published durable job.

## Typed administrator configuration

The derived configuration view retains the original authenticated bytes. Native
projection preserves typed serde behavior: unknown RuntimeConfig, HostConfig and
PrivilegedAction fields are skipped lexically with an iterative IgnoredAny
scanner; known fields are still decoded and checked. HiaWorkerProfile and native
job pins deny unknown fields. Struct duplicates fail; host and action maps retain
the final decoded string key, after parsing every overwritten typed value.
Unit enum maps are normalized to their serialized string form.

The earlier component-only acceptance of an unknown HIA profile field was
incorrect. The current component refuses it, as the original HiaWorkerProfile
uses deny_unknown_fields. Historical qualification artifacts remain unchanged.

## Evidence at this checkpoint

The service owner v4 executable (SHA256
7ded49fd6c2636aa4b81c35fb42c0ace3d974a21404942521fbc7a363ce9ead8)
passed 69 actual-process custody and concurrency cases. These cover nineteen role
pin mutations and size caps, lock ownership, exact public line size, responsive
ping while the actual bridge waits on the controller lock, Unicode request-ID
cancellation, and descriptor recovery after 64 concurrent rejections.

The typed-projection v5 executable (SHA256
14b921b5734c496feb98982bf699896dd199e3302510eea55e209b5a9814a437)
passed 62 actual-process configuration admission pairs against frozen runtime
d022649c64b48fb2a43263faf90103a9a8957b94. The pairs include 56,000 nested ignored
containers, ignored non-UTF8 strings, invalid known keys, duplicate typed fields,
last-value-wins host maps, required fields and both unit-enum representations.
The matching pure session component passed 80 cases and profile component 86.

These are component and process-owner results, not a whole-stack release claim.
The full request-audit ticket lifetime, installed isolated jobctl lifecycle,
ordinary-release registration and whole-stack final gates remain required.
The real eleven-tool SSH/Worker campaign and source-pinned job bridge have
separate evidence; the process-owner gate does not substitute for them.
