#!/usr/bin/env node
import { readFile, stat, writeFile } from "node:fs/promises";
import { simulatePolicyV1, validatePolicyV1 } from "../policy.mjs";
import { simulateIdentityPolicyV2, validateIdentityPolicyV2 } from "../identity-policy.mjs";
import { replayIdentityPolicyV2, replayPolicyV1 } from "../replay-policy.mjs";
import { comparePolicySimulation, diffPolicies } from "../policy-diff.mjs";
import { checkBuilderProject, initBuilderProject, listBuilderTemplates, writeBuilderReview } from "../builder-kit.mjs";

const usage = "Usage: nodeguard builder templates | nodeguard builder init <directory> [--template login-abuse|api-probing|webhook-replay|tenant-api] | nodeguard builder check <directory> | nodeguard builder review <directory> --output <review.json> | nodeguard init [--output <policy.json>] | nodeguard doctor [policy.json] | nodeguard policy validate <policy.json> | nodeguard policy diff <current-policy.json> <proposed-policy.json> | nodeguard policy compare <current-policy.json> <proposed-policy.json> <observations.json> --at <UTC timestamp> [--redact] | nodeguard policy test <policy.json> <observations.json> --at <UTC timestamp> | nodeguard replay <policy.json> <observations.json> --at <UTC timestamp> [--protected <source-ips.json>] [--redact] | nodeguard inspect <policy.json> | nodeguard export <policy.json> --output <file>";
const examplePolicy = new URL("../examples/auth-policy.json", import.meta.url);

async function readJson(path) {
  const info = await stat(path);
  if (!info.isFile() || info.size > 1_048_576) throw new Error("input must be a JSON file no larger than 1 MiB");
  return JSON.parse(await readFile(path, "utf8"));
}

function validatePolicy(input) {
  return input?.schema_version === 2 ? validateIdentityPolicyV2(input) : validatePolicyV1(input);
}

async function main(args) {
  if (args[0] === "builder") {
    if (args.length === 2 && args[1] === "templates") {
      process.stdout.write(`${JSON.stringify(listBuilderTemplates(), null, 2)}\n`);
      return;
    }
    if (args[1] === "init" && (args.length === 3 || (args.length === 5 && args[3] === "--template"))) {
      const result = await initBuilderProject(args[2], { template: args[4] });
      process.stdout.write(`Created local Builder project: ${result.directory}\nFiles: ${result.files.join(', ')}\n`);
      return;
    }
    if (args.length === 3 && args[1] === "check") {
      process.stdout.write(`${JSON.stringify(await checkBuilderProject(args[2]), null, 2)}\n`);
      return;
    }
    if (args.length === 5 && args[1] === "review" && args[3] === "--output") {
      process.stdout.write(`${JSON.stringify(await writeBuilderReview(args[2], args[4]), null, 2)}\n`);
      return;
    }
    throw new Error(usage);
  }
  if (args[0] === "init" && (args.length === 1 || (args.length === 3 && args[1] === "--output"))) {
    const output = args.length === 3 ? args[2] : "nodeguard.policy.json";
    if (!output || output.startsWith("-")) throw new Error("choose a policy output path");
    const policyText = await readFile(examplePolicy, "utf8");
    validatePolicyV1(JSON.parse(policyText));
    await writeFile(output, policyText, { flag: "wx", mode: 0o600 });
    process.stdout.write(`Created OBSERVE policy: ${output}\nReview application_id, route_id, trusted source, and exclusions before integration.\n`);
    return;
  }
  if (args[0] === "doctor" && (args.length === 1 || args.length === 2)) {
    const major = Number(process.versions.node.split(".")[0]);
    if (major < 20) throw new Error("Node.js 20 or newer is required");
    const output = { node: process.version, runtime: "supported", source_trust: "not checked",
      state_scope: "one_process", multi_worker_consistency: "not provided" };
    if (args.length === 2) {
      const policy = validatePolicy(await readJson(args[1]));
      output.policy_id = policy.policy_id;
      output.policy_mode = policy.mode;
      output.policy_schema_version = policy.schema_version;
    }
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    return;
  }
  if (args[0] === "inspect" && args.length === 2) {
    const policy = validatePolicy(await readJson(args[1]));
    process.stdout.write(`${JSON.stringify({ schema_version: policy.schema_version, policy_id: policy.policy_id,
      application_id: policy.application_id, route_id: policy.route_id, mode: policy.mode,
      action: policy.action, threshold: policy.threshold, window_seconds: policy.window_seconds,
      restriction_seconds: policy.restriction_seconds, state_scope: "one_process",
      ...(policy.schema_version === 2 ? { identity_scope: policy.identity_scope, excluded_route_ids: policy.excluded_route_ids } : {}) }, null, 2)}\n`);
    return;
  }
  if (args[0] === "export" && args.length === 4 && args[2] === "--output") {
    const policy = validatePolicy(await readJson(args[1]));
    if (!args[3] || args[3].startsWith("-")) throw new Error("choose an export output path");
    const exported = { schema_version: policy.schema_version, policy_id: policy.policy_id,
      application_id: policy.application_id, mode: policy.mode, route_id: policy.route_id,
      reason_code: policy.reason_code, window_seconds: policy.window_seconds,
      threshold: policy.threshold, action: policy.action,
      restriction_seconds: policy.restriction_seconds,
      ...(policy.schema_version === 2 ? { identity_scope: policy.identity_scope, excluded_route_ids: policy.excluded_route_ids } : {}) };
    await writeFile(args[3], `${JSON.stringify(exported, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    process.stdout.write(`Exported policy without runtime events: ${args[3]}\n`);
    return;
  }
  if (args[0] === "replay" && args.length >= 5 && args[3] === "--at") {
    const policy = validatePolicy(await readJson(args[1]));
    let position = 5;
    let protectedSources = [];
    let hasProtectedSources = false;
    if (args[position] === "--protected" && typeof args[position + 1] === "string") {
      protectedSources = await readJson(args[position + 1]);
      hasProtectedSources = true;
      position += 2;
    }
    const redactSources = args[position] === "--redact";
    if (redactSources) position += 1;
    if (position !== args.length) throw new Error(usage);
    if (policy.mode === "ENFORCE" && !hasProtectedSources) {
      throw new Error("ENFORCE replay requires --protected <source-ips.json>; use [] if none apply");
    }
    const input = await readJson(args[2]);
    const result = policy.schema_version === 2
      ? replayIdentityPolicyV2({ policy, entries: input, at: args[4], protectedSources, redactSources })
      : replayPolicyV1({ policy, observations: input, at: args[4], protectedSources, redactSources });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  if (args[0] !== "policy") throw new Error(usage);
  if (args[1] === "validate" && args.length === 3) {
    const policy = validatePolicy(await readJson(args[2]));
    process.stdout.write(`Valid policy v${policy.schema_version}: ${policy.policy_id}\n`);
    return;
  }
  if (args[1] === "diff" && args.length === 4) {
    const result = diffPolicies(await readJson(args[2]), await readJson(args[3]));
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  if (args[1] === "compare" && (args.length === 7 || (args.length === 8 && args[7] === "--redact")) && args[5] === "--at") {
    const result = comparePolicySimulation(await readJson(args[2]), await readJson(args[3]),
      await readJson(args[4]), { at: args[6], redactSources: args[7] === "--redact" });
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    return;
  }
  if (args[1] === "test" && args.length === 6 && args[4] === "--at") {
    const policy = validatePolicy(await readJson(args[2]));
    const observations = await readJson(args[3]);
    const results = policy.schema_version === 2
      ? simulateIdentityPolicyV2(policy, observations, { at: args[5] })
      : simulatePolicyV1(policy, observations, { at: args[5] });
    process.stdout.write(`${JSON.stringify({ schema_version: policy.schema_version, results }, null, 2)}\n`);
    return;
  }
  throw new Error(usage);
}

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`nodeguard: ${error.message}\n`);
  process.exitCode = 1;
});
