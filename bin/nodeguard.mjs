#!/usr/bin/env node
import { readFile, stat, writeFile } from "node:fs/promises";
import { simulatePolicyV1, validatePolicyV1 } from "../policy.mjs";

const usage = "Usage: nodeguard init [--output <policy.json>] | nodeguard doctor [policy.json] | nodeguard policy validate <policy.json> | nodeguard policy test <policy.json> <observations.json> --at <UTC timestamp> | nodeguard inspect <policy.json> | nodeguard export <policy.json> --output <file>";
const examplePolicy = new URL("../examples/auth-policy.json", import.meta.url);

async function readJson(path) {
  const info = await stat(path);
  if (!info.isFile() || info.size > 1_048_576) throw new Error("input must be a JSON file no larger than 1 MiB");
  return JSON.parse(await readFile(path, "utf8"));
}

async function main(args) {
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
      const policy = validatePolicyV1(await readJson(args[1]));
      output.policy_id = policy.policy_id;
      output.policy_mode = policy.mode;
    }
    process.stdout.write(`${JSON.stringify(output, null, 2)}\n`);
    return;
  }
  if (args[0] === "inspect" && args.length === 2) {
    const policy = validatePolicyV1(await readJson(args[1]));
    process.stdout.write(`${JSON.stringify({ schema_version: 1, policy_id: policy.policy_id,
      application_id: policy.application_id, route_id: policy.route_id, mode: policy.mode,
      action: policy.action, threshold: policy.threshold, window_seconds: policy.window_seconds,
      restriction_seconds: policy.restriction_seconds, state_scope: "one_process" }, null, 2)}\n`);
    return;
  }
  if (args[0] === "export" && args.length === 4 && args[2] === "--output") {
    const policy = validatePolicyV1(await readJson(args[1]));
    if (!args[3] || args[3].startsWith("-")) throw new Error("choose an export output path");
    const exported = { schema_version: policy.schema_version, policy_id: policy.policy_id,
      application_id: policy.application_id, mode: policy.mode, route_id: policy.route_id,
      reason_code: policy.reason_code, window_seconds: policy.window_seconds,
      threshold: policy.threshold, action: policy.action,
      restriction_seconds: policy.restriction_seconds };
    await writeFile(args[3], `${JSON.stringify(exported, null, 2)}\n`, { flag: "wx", mode: 0o600 });
    process.stdout.write(`Exported policy without runtime events: ${args[3]}\n`);
    return;
  }
  if (args[0] !== "policy") throw new Error(usage);
  if (args[1] === "validate" && args.length === 3) {
    const policy = validatePolicyV1(await readJson(args[2]));
    process.stdout.write(`Valid policy v1: ${policy.policy_id}\n`);
    return;
  }
  if (args[1] === "test" && args.length === 6 && args[4] === "--at") {
    const policy = await readJson(args[2]);
    const observations = await readJson(args[3]);
    const results = simulatePolicyV1(policy, observations, { at: args[5] });
    process.stdout.write(`${JSON.stringify({ schema_version: 1, results }, null, 2)}\n`);
    return;
  }
  throw new Error(usage);
}

main(process.argv.slice(2)).catch((error) => {
  process.stderr.write(`nodeguard: ${error.message}\n`);
  process.exitCode = 1;
});
