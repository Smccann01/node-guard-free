import { lstat, mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { simulatePolicyV1, validateObservationV1, validatePolicyV1 } from './policy.mjs';
import { simulateIdentityPolicyV2, validateIdentityPolicyV2 } from './identity-policy.mjs';
import { comparePolicySimulation } from './policy-diff.mjs';

const MAX_FILE_BYTES = 1_048_576;
const files = Object.freeze(['builder.json', 'current-policy.json', 'proposed-policy.json', 'observations.json', 'README.md']);
const fixtureAt = '2026-11-04T10:00:20Z';
const templates = Object.freeze({
  'login-abuse': { route: 'auth.login', reason: 'authentication_failure', action: 'THROTTLE', threshold: 2,
    description: 'An application records verified failed logins; compare a short throttle with an unaffected control source.' },
  'api-probing': { route: 'api.catalog', reason: 'api_probe_burst', action: 'THROTTLE', threshold: 3,
    description: 'An application records verified API probing events; compare a route-scoped throttle with normal traffic.' },
  'webhook-replay': { route: 'webhooks.inbound', reason: 'replay_burst', action: 'DENY', threshold: 2,
    description: 'An application records verified replay attempts; compare a short deny with an unaffected control source. Signature verification is separate.' },
  'tenant-api': { route: 'api.usage', reason: 'anonymous_rate_burst', action: 'THROTTLE', threshold: 2,
    description: 'Compare a tenant-scoped throttle with a second tenant behind the same source IP. Identity fixtures are synthetic and require application-authenticated tenant IDs in production.', identity_scope: 'tenant_id' },
});

export function listBuilderTemplates() {
  return Object.entries(templates).map(([id, value]) => ({ id, description: value.description }));
}

function fixture(template) {
  const spec = templates[template];
  if (!spec) throw new Error(`unknown Builder template: ${template}`);
  const policy = {
    schema_version: spec.identity_scope ? 2 : 1, policy_id: `builder-${template}`, application_id: 'sample-api',
    mode: 'OBSERVE', route_id: spec.route, reason_code: spec.reason,
    window_seconds: 60, threshold: spec.threshold, action: spec.action, restriction_seconds: 60,
    ...(spec.identity_scope ? { identity_scope: spec.identity_scope } : {}),
  };
  const observations = Array.from({ length: spec.threshold }, (_, index) => ({
    schema_version: policy.schema_version, application_id: 'sample-api', event_id: `sample-${template}-${index + 1}`,
    observed_at: new Date(Date.parse(fixtureAt) - (spec.threshold - index) * 1000).toISOString(),
    route_id: spec.route, reason_code: spec.reason, source_ip: '8.8.8.8', protocol: 'HTTPS',
  }));
  observations.push({ ...observations[0], event_id: `control-${template}-1`,
    source_ip: spec.identity_scope ? '8.8.8.8' : '1.1.1.1' });
  return { policy, observations: spec.identity_scope
    ? observations.map((observation, index) => ({ observation,
      fixture_identity: index === observations.length - 1 ? 'fixture:control_tenant' : 'fixture:selected_tenant' }))
    : observations };
}

function json(value) { return `${JSON.stringify(value, null, 2)}\n`; }

async function readBoundedJson(path) {
  const info = await lstat(path);
  if (!info.isFile() || info.size > MAX_FILE_BYTES) throw new Error(`${path} must be a JSON file no larger than 1 MiB`);
  const bytes = await readFile(path);
  if (bytes.length > MAX_FILE_BYTES) throw new Error(`${path} exceeds 1 MiB`);
  return JSON.parse(bytes.toString('utf8'));
}

export async function initBuilderProject(directory, { template = 'login-abuse' } = {}) {
  if (typeof directory !== 'string' || !directory || directory.startsWith('-')) throw new Error('choose a project directory');
  const { policy, observations } = fixture(template);
  await mkdir(directory);
  const manifest = {
    schema_version: 1, tool_id: `sample-${template}`, data_location: 'local', template,
    capabilities: ['policy_simulation'], evaluated_at: fixtureAt,
  };
  const contents = [
    json(manifest), json(policy), json({ ...policy, mode: 'ENFORCE' }),
    json(observations),
    `# Local Builder project: ${template}\n\n${templates[template].description}\n\nThis project uses synthetic observations. It does not connect to Network Decode, install an agent, or apply a host rule.\n\nRun \`nodeguard builder check ${directory}\` from the parent directory. Use \`nodeguard builder review ${directory} --output review.json\` to save a redacted review. The review file is local and should be kept out of source control.\n\nThe application must verify source and identity before recording a real observation. Keep real events and credentials in your own systems; never commit them. Do not infer a live packet drop from this simulation.\n`,
  ];
  for (const [index, file] of files.entries()) {
    await writeFile(join(directory, file), contents[index], { flag: 'wx', mode: 0o600 });
  }
  return { directory, template, files };
}

export async function checkBuilderProject(directory) {
  if (typeof directory !== 'string' || !directory || directory.startsWith('-')) throw new Error('choose a project directory');
  const [manifest, current, proposed, observations] = await Promise.all(
    files.slice(0, 4).map((file) => readBoundedJson(join(directory, file))),
  );
  if (manifest?.schema_version !== 1 || typeof manifest.tool_id !== 'string' ||
      !/^[a-z][a-z0-9-]{0,63}$/.test(manifest.tool_id) || manifest.data_location !== 'local' ||
      (manifest.template !== undefined && !Object.hasOwn(templates, manifest.template)) ||
      !Array.isArray(manifest.capabilities) || manifest.capabilities.length !== 1 ||
      manifest.capabilities[0] !== 'policy_simulation' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(manifest.evaluated_at) ||
      !Number.isFinite(Date.parse(manifest.evaluated_at))) {
    throw new Error('invalid Builder manifest');
  }
  const identityScoped = current.schema_version === 2;
  (identityScoped ? validateIdentityPolicyV2 : validatePolicyV1)(current);
  (identityScoped ? validateIdentityPolicyV2 : validatePolicyV1)(proposed);
  if (!Array.isArray(observations) || observations.length > 1000) throw new Error('observations must be an array of at most 1000 events');
  if (!identityScoped) observations.forEach(validateObservationV1);
  const review = comparePolicySimulation(current, proposed, observations, { at: manifest.evaluated_at, redactSources: true });
  const currentFingerprint = review.before_fingerprint_sha256;
  const proposedFingerprint = review.after_fingerprint_sha256;
  const simulate = identityScoped ? simulateIdentityPolicyV2 : simulatePolicyV1;
  const key = identityScoped ? 'identity_ref' : 'source_ip';
  const before = new Map(simulate(current, observations, { at: manifest.evaluated_at }).map((result) => [result[key], result]));
  const after = new Map(simulate(proposed, observations, { at: manifest.evaluated_at }).map((result) => [result[key], result]));
  const unchangedControlCount = [...before].filter(([source, result]) => result.decision === 'NONE' && after.get(source)?.decision === 'NONE').length;
  const selectedChangeCount = review.decision_changes.length;
  return {
    tool_id: manifest.tool_id, event_count: observations.length,
    template: manifest.template ?? 'custom',
    canonical_current_policy_sha256: currentFingerprint, canonical_proposed_policy_sha256: proposedFingerprint,
    unchanged_control_evidence: unchangedControlCount > 0,
    review_gates: {
      changed_decision_observed: selectedChangeCount > 0,
      unchanged_control_observed: unchangedControlCount > 0,
      source_attribution_verified: false,
      ...(identityScoped ? { application_identity_verified: false } : {}),
      production_approved: false,
    },
    next_checks: [
      ...(!selectedChangeCount ? ['Add a synthetic case that changes under the proposed policy.'] : []),
      ...(!unchangedControlCount ? ['Add an unaffected control source to the fixture.'] : []),
      'Verify source attribution in the deployed application.',
      ...(identityScoped ? ['Verify the selected identity scope from application authentication; never trust a request-supplied identity.'] : []),
      'Test protected management sources and rollback in the deployed application before ENFORCE.',
    ],
    review,
  };
}

export async function writeBuilderReview(directory, output) {
  if (typeof output !== 'string' || !output || output.startsWith('-')) throw new Error('choose a review output path');
  const result = await checkBuilderProject(directory);
  const report = {
    schema_version: 1, kind: 'nodeguard_builder_policy_review',
    activation: 'none', data_location: 'local',
    ...result,
  };
  await writeFile(output, json(report), { flag: 'wx', mode: 0o600 });
  return { output, policy_changed: report.review.changed, decision_change_count: report.review.decision_changes.length };
}
