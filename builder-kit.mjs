import { createHash } from 'node:crypto';
import { mkdir, readFile, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { validateObservationV1, validatePolicyV1 } from './policy.mjs';
import { comparePolicySimulation } from './policy-diff.mjs';

const MAX_FILE_BYTES = 1_048_576;
const files = Object.freeze(['builder.json', 'current-policy.json', 'proposed-policy.json', 'observations.json', 'README.md']);
const fixtureAt = '2026-11-04T10:00:20Z';
const samplePolicy = {
  schema_version: 1, policy_id: 'builder-login-review', application_id: 'sample-api',
  mode: 'OBSERVE', route_id: 'auth.login', reason_code: 'authentication_failure',
  window_seconds: 60, threshold: 2, action: 'THROTTLE', restriction_seconds: 60,
};
const sampleObservations = ['2026-11-04T10:00:00Z', '2026-11-04T10:00:01Z'].map((observed_at, index) => ({
  schema_version: 1, application_id: 'sample-api', event_id: `sample-${index + 1}`,
  observed_at, route_id: 'auth.login', reason_code: 'authentication_failure',
  source_ip: '8.8.8.8', protocol: 'HTTPS',
}));

function json(value) { return `${JSON.stringify(value, null, 2)}\n`; }
function digest(value) { return createHash('sha256').update(value).digest('hex'); }

async function readBoundedJson(path) {
  const info = await stat(path);
  if (!info.isFile() || info.size > MAX_FILE_BYTES) throw new Error(`${path} must be a JSON file no larger than 1 MiB`);
  const bytes = await readFile(path);
  if (bytes.length > MAX_FILE_BYTES) throw new Error(`${path} exceeds 1 MiB`);
  return JSON.parse(bytes.toString('utf8'));
}

export async function initBuilderProject(directory) {
  if (typeof directory !== 'string' || !directory || directory.startsWith('-')) throw new Error('choose a project directory');
  await mkdir(directory);
  const manifest = {
    schema_version: 1, tool_id: 'sample-login-review', data_location: 'local',
    capabilities: ['policy_simulation'], evaluated_at: fixtureAt,
  };
  const contents = [
    json(manifest), json(samplePolicy), json({ ...samplePolicy, mode: 'ENFORCE' }),
    json(sampleObservations),
    `# Local Builder project\n\nThis project uses synthetic observations. It does not connect to Network Decode, install an agent, or apply a host rule.\n\nRun \`nodeguard builder check ${directory}\` from the parent directory. Review the reported policy hashes and changed decisions before adapting the fixture to your application.\n\nThe application must verify source identity before recording a real observation. Keep real events and credentials in your own systems; never commit them. Do not infer a live packet drop from this simulation.\n`,
  ];
  for (const [index, file] of files.entries()) {
    await writeFile(join(directory, file), contents[index], { flag: 'wx', mode: 0o600 });
  }
  return { directory, files };
}

export async function checkBuilderProject(directory) {
  if (typeof directory !== 'string' || !directory || directory.startsWith('-')) throw new Error('choose a project directory');
  const [manifest, current, proposed, observations] = await Promise.all(
    files.slice(0, 4).map((file) => readBoundedJson(join(directory, file))),
  );
  if (manifest?.schema_version !== 1 || typeof manifest.tool_id !== 'string' ||
      !/^[a-z][a-z0-9-]{0,63}$/.test(manifest.tool_id) || manifest.data_location !== 'local' ||
      !Array.isArray(manifest.capabilities) || manifest.capabilities.length !== 1 ||
      manifest.capabilities[0] !== 'policy_simulation' ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/.test(manifest.evaluated_at) ||
      !Number.isFinite(Date.parse(manifest.evaluated_at))) {
    throw new Error('invalid Builder manifest');
  }
  validatePolicyV1(current);
  validatePolicyV1(proposed);
  if (!Array.isArray(observations) || observations.length > 1000) throw new Error('observations must be an array of at most 1000 events');
  observations.forEach(validateObservationV1);
  const review = comparePolicySimulation(current, proposed, observations, { at: manifest.evaluated_at, redactSources: true });
  return {
    tool_id: manifest.tool_id, event_count: observations.length,
    canonical_current_policy_sha256: digest(json(current)), canonical_proposed_policy_sha256: digest(json(proposed)),
    review,
  };
}
