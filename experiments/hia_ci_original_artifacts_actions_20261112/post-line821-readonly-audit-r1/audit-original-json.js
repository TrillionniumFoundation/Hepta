"use strict";
// Independent read-only analysis of already recovered JSON text.
// Never imports project code, touches a filesystem, or changes an original result.
function parseExactJSON(text) {
  let i = 0;
  function ws() { while (i < text.length && /[ \t\r\n]/.test(text[i])) i++; }
  function str() {
    const start = i++;
    while (i < text.length) {
      if (text[i] === "\\") { i += 2; continue; }
      if (text[i++] === '"') return JSON.parse(text.slice(start, i));
    }
    throw Error("Unterminated JSON string");
  }
  function value() {
    ws(); const c = text[i];
    if (c === '"') return str();
    if (c === "[") {
      i++; const out = []; ws();
      if (text[i] === "]") { i++; return out; }
      for (;;) { out.push(value()); ws(); if (text[i] === "]") { i++; return out; }
        if (text[i++] !== ",") throw Error("Expected array comma"); }
    }
    if (c === "{") {
      i++; const out = Object.create(null); ws();
      if (text[i] === "}") { i++; return out; }
      for (;;) {
        ws(); if (text[i] !== '"') throw Error("Expected object key");
        const key = str(); if (Object.hasOwn(out, key)) throw Error("Duplicate JSON key");
        ws(); if (text[i++] !== ":") throw Error("Expected colon"); out[key] = value(); ws();
        if (text[i] === "}") { i++; return out; }
        if (text[i++] !== ",") throw Error("Expected object comma");
      }
    }
    for (const [word, result] of [["true", true], ["false", false], ["null", null]])
      if (text.startsWith(word, i)) { i += word.length; return result; }
    const match = text.slice(i).match(/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/);
    if (!match) throw Error("Invalid JSON value");
    i += match[0].length; return new JSONNumber(match[0]);
  }
  const out = value(); ws(); if (i !== text.length) throw Error("Trailing JSON data"); return out;
}
class JSONNumber { constructor(lexeme) { this.lexeme = lexeme; } }
function stable(value) {
  if (value instanceof JSONNumber) return "N" + value.lexeme;
  if (Array.isArray(value)) return "[" + value.map(stable).join(",") + "]";
  if (value !== null && typeof value === "object")
    return "{" + Object.keys(value).sort().map(k => JSON.stringify(k) + ":" + stable(value[k])).join(",") + "}";
  return JSON.stringify(value);
}
function equal(a, b) { return stable(a) === stable(b); }
function number(value) {
  if (!(value instanceof JSONNumber) || !/^-?(?:0|[1-9][0-9]*)$/.test(value.lexeme))
    throw Error("Expected original JSON integer");
  const result = Number(value.lexeme);
  if (!Number.isSafeInteger(result)) throw Error("Unsafe integer conversion");
  return result;
}
function plain(value) {
  if (value instanceof JSONNumber) return value.lexeme;
  if (Array.isArray(value)) return value.map(plain);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(Object.entries(value).map(([k,v]) => [k,plain(v)]));
  return value;
}
function auditELFOriginals(originals, pins, ownedSources, moduleSourcePins) {
  const rows = [];
  const rawControl = { nanosecond_precision_preserved:
      !equal(parseExactJSON('{"n":1794440489639443001}'), parseExactJSON('{"n":1794440489639443002}')),
    ordinary_order_independence: equal(parseExactJSON('{"x":1,"y":true}'), parseExactJSON('{"y":true,"x":1}')) };
  for (const id of ["13901601239", "13900618647"]) {
    const prefix = "original/" + id + "/";
    const read = name => parseExactJSON(originals[prefix + name]);
    const gate = read("hia-machine-elf-caller-gate.json");
    const report = read("hia-machine-elf-callers-evidence/report.json");
    const wrapper = read("hia-machine-elf-callers-owner/run-result.json");
    const owner = read("hia-machine-elf-callers-owner/process-owner.json");
    const observations = read("OBSERVATIONS.json");
    const selected = read("SELECTED.json");
    const members = Object.fromEntries(selected.selected_members.map(m => [m.original_name, m]));
    const checks = [];
    const check = (predicate, condition, basis, detail = null) =>
      checks.push({ predicate, observed_condition: condition, basis, detail });
    const missing = Object.keys(report.expected_module_sources).filter(k => gate.source_before[k] === undefined);
    check("821: actual == fixed expected module digests", equal(report.actual_module_sources, report.expected_module_sources) && equal(report.expected_module_sources, moduleSourcePins),
      "RAW_REPORT_AND_FIXED_QUALIFIER_SOURCE", { actual: report.actual_module_sources });
    check("821: module membership in original cold source closure",
      Object.entries(report.expected_module_sources).every(([k,v]) => gate.source_before[k] === v),
      "RAW_REPORT_AND_OUTER_GATE", { missing });
    check("824: report source_before == admitted source == source_after",
      equal(report.source_before, gate.source_before) && equal(report.source_after, gate.source_before),
      "RAW_REPORT_AND_OUTER_GATE", { source_count: Object.keys(gate.source_before).length });
    check("825: source_stable is true", report.source_stable === true, "RAW_REPORT");
    check("826: cold_report_sha256 equals originally admitted cold SHA",
      report.cold_report_sha256 === gate.cold_inputs[0].sha256, "RAW_REPORT_AND_OUTER_GATE");
    const manifest = observations.manifest;
    const build = observations.build;
    const compiler = gate.cold_inputs[2].sha256;
    check("single_build: manifest exact five fields",
      equal(Object.keys(manifest).sort(), ["schema","source_sha256","image_path","image_sha256","compiler_sha256"].sort()),
      "RECOVERED_HEADER_PROJECTION");
    check("manifest_image: schema/source/compiler", manifest.schema === "hepta.hia.machine-elf-native.v1"
      && manifest.source_sha256 === gate.source_before["examples/hia_bootstrap/machine_elf.hiaasm"]
      && manifest.compiler_sha256 === compiler, "RECOVERED_HEADER_PROJECTION");
    check("single_build: image_path is original basename", manifest.image_path === "machine-elf.image.bin"
      && report.bundle_before.image.path.endsWith("/qualified/" + manifest.image_path), "RECOVERED_HEADER_PROJECTION_AND_REPORT");
    check("single_build: projected build status/schema/scope/cold/compiler",
      build.status === "NATIVE_CANDIDATE_BUILT" && build.schema === "hepta.hia.machine-elf-build.v1"
      && build.scope === "MATCHING_SOURCE_COLD_BUILD" && build.cold_report_sha256 === gate.cold_inputs[0].sha256
      && build.compiler_sha256 === compiler && build.build_inputs_stable === true, "RECOVERED_HEADER_PROJECTION");
    check("single_build: all declared owned source inputs belong to original cold map",
      ownedSources.every(p => typeof gate.source_before[p] === "string"), "ACTUAL_READER_SOURCE_AND_OUTER_GATE",
      { count: ownedSources.length, missing: ownedSources.filter(p => !(p in gate.source_before)) });
    const compile = build.native_compile_receipt;
    check("compile_receipt: status returned/abi zero", compile.status === "returned" && number(compile.abi_status) === 0,
      "RECOVERED_HEADER_PROJECTION");
    check("compile_receipt: five compiler/source/output identities",
      compile.source_sha256 === manifest.source_sha256 && compile.input_sha256 === manifest.source_sha256
      && compile.produced_sha256 === manifest.image_sha256 && compile.image_sha256 === compiler
      && compile.artifact_sha256 === compiler, "RECOVERED_HEADER_PROJECTION");
    check("compile_receipt: unchanged source and no authoring modules",
      compile.source_unchanged === true && equal(compile.forbidden_compiler_modules_loaded, []),
      "RECOVERED_HEADER_PROJECTION");
    const limits = parseExactJSON('{"address_bytes":268435456,"core_dumpable":false,"cpu_seconds":10,"output_capacity":1048576,"stack_bytes":8388608,"workspace_bytes":1048576}');
    check("compile_receipt: exact original limits", equal(compile.limits, limits), "RECOVERED_HEADER_PROJECTION");
    check("compile_receipt: output extent agrees with reported image observation",
      equal(compile.produced_bytes, report.bundle_before.image.bytes) && number(compile.produced_bytes) > 0,
      "RECOVERED_HEADER_PROJECTION_AND_REPORT_NOT_PHYSICAL_STAT");
    check("830: bundle_before == bundle_after with every original integer preserved",
      equal(report.bundle_before, report.bundle_after), "RAW_REPORT_LOSSLESS_INTEGER_COMPARISON");
    check("831: bundle_stable is true", report.bundle_stable === true, "RAW_REPORT");
    check("832: manifest SHA agrees with selected original manifest member and build header",
      report.manifest_sha256 === members["hia-machine-elf-callers-evidence/qualified/manifest.json"].sha256
      && report.manifest_sha256 === report.bundle_before.manifest.sha256
      && report.manifest_sha256 === build.manifest_sha256, "RAW_REPORT_SELECTED_DIGEST_AND_HEADER_PROJECTION");
    check("833: image SHA agrees across reported image, manifest and compilation",
      report.image_sha256 === report.bundle_before.image.sha256 && report.image_sha256 === manifest.image_sha256
      && report.image_sha256 === compile.produced_sha256, "RAW_REPORT_AND_HEADER_PROJECTION");
    const counts = report.native_operation_counts;
    check("835: native counters nonempty and exact positive integers",
      counts && !Array.isArray(counts) && Object.keys(counts).length > 0
      && Object.values(counts).every(v => v instanceof JSONNumber && /^[1-9][0-9]*$/.test(v.lexeme)),
      "RAW_REPORT", { operations: Object.keys(counts).length, total: Object.values(counts).reduce((n,v) => n+number(v), 0) });
    check("836-838: retained scope all false", report.whole_writer_qualified === false
      && report.whole_native_delivery_qualified === false && report.foreign_timsort_schedule_closed === false,
      "RAW_REPORT");
    check("later owned readback: wrapper original source/cold snapshots",
      equal(wrapper.source_before, gate.source_before) && equal(wrapper.source_after, gate.source_before)
      && equal(wrapper.cold_inputs, gate.cold_inputs) && wrapper.source_preserved === true
      && wrapper.cold_inputs_preserved === true, "RAW_WRAPPER_AND_OUTER_GATE");
    check("later owned readback: command/cwd agree with originally captured request projection",
      equal(wrapper.command, observations.request.command) && wrapper.cwd === observations.request.cwd,
      "RAW_WRAPPER_AND_REQUEST_HEADER_PROJECTION");
    check("later owned readback: original request digest", owner.request_sha256 ===
      members["hia-machine-elf-callers-owner/process-owner.json.request.json"].sha256, "RAW_OWNER_AND_SELECTED_DIGEST");
    check("later owned readback: owner schema/implementation/180/3",
      owner.schema === "hepta.hia.selfhost-process-owner.v1"
      && owner.implementation_sha256 === gate.source_before["tools/hia_selfhost_process_owner.py"]
      && number(owner.qualification_seconds) === 180 && number(owner.cleanup_seconds) === 3, "RAW_OWNER_AND_OUTER_GATE");
    check("later owned readback: natural completion with no owner_error key",
      owner.status === "OWNED_PROCESS_COMPLETED" && number(owner.returncode) === 0 && owner.timed_out === false
      && owner.qualification_started === true && owner.exit_observed_before_deadline === true
      && owner.subreaper_enabled === true && equal(owner.interrupted_signals, [])
      && !Object.hasOwn(owner, "owner_error") && owner.event_overflow === false, "RAW_OWNER");
    const clean = owner.cleanup;
    check("later owned readback: cleanup/ECHILD", clean.attempted === true && clean.complete === true
      && clean.leader_reaped === true && clean.observed_echild === true && clean.deadline_exceeded === false
      && equal(clean.errors, []) && equal(clean.remaining_direct_children, []), "RAW_OWNER");
    const natural = new Set(["qualification_started","owned_child_observed","qualification_exit_observed","owned_child_reaped"]);
    check("later owned readback: natural event allowlist", owner.events.length > 0
      && owner.events.every(x => natural.has(x.kind))
      && ["qualification_started","qualification_exit_observed","owned_child_reaped"].every(k => owner.events.some(x => x.kind === k)),
      "RAW_OWNER");
    const returned = wrapper.returned_owner;
    const projection = Object.fromEntries(Object.entries(returned).filter(([k]) => !["supervisor_returncode","receipt_sha256"].includes(k)));
    check("later owned readback: full return equals original receipt except two API-added fields",
      number(returned.supervisor_returncode) === 0
      && returned.receipt_sha256 === pins[prefix+"hia-machine-elf-callers-owner/process-owner.json"].sha256
      && equal(projection, owner), "RAW_WRAPPER_AND_RAW_OWNER_LOSSLESS_COMPARISON");
    check("finally: actual outer source/cold stable after original failure",
      equal(gate.source_before, gate.source_after) && gate.source_preserved === true
      && gate.cold_inputs_preserved === true && !Object.hasOwn(gate, "final_identity_error"),
      "RAW_OUTER_GATE_ORIGINAL_FAILURE_FINALLY");
    const unseen = [
      "Re-read original qualified/manifest.json and validate actual file identity; only its complete header projection and selected digest are recovered here.",
      "Re-read original qualified/build.json source_manifest, manifest, production_activated and owned_source_sha256; these fields were not retained in the header projection.",
      "Re-read physical machine-elf.image.bin bytes/hash/extent and current resolved-path containment. The original image bytes are not in these frames.",
      "Compare current actual elf_file_observation dev/ino/mode/size/mtime_ns/ctime_ns to the two historical bundle snapshots.",
      "Re-read the original owner request full env, implementation/stdout/stderr/receipt paths; request bytes are sealed in the earlier small ZIP but not among these frames.",
      "Execute the later second inspect_owned_product and source_now/cold_inputs reads on the same original filesystem. The original gate stopped at line821."
    ];
    rows.push({ artifact_id:id, original_gate_status:gate.status, original_gate_error:gate.error,
      original_caller_status:report.status, checks, not_independently_revalidated:unseen,
      successor_gate_pass_claimed:false, original_HOLD_preserved:true });
  }
  return {schema:"hia.elf-original-post-failure-readonly-audit.v1",
    scope:"ORIGINAL_BYTES_AND_EXPORTED_HEADER_PREDICATES_ONLY_NOT_QUALIFICATION",
    original_result_reclassified:false, project_code_executed:false, process_or_native_test_started:false,
    integer_comparison:"All JSON number lexemes preserved; nanosecond identities never parsed through binary64",
    parser_controls:rawControl, originals:rows};
}

