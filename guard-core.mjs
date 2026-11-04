import { BlockList, isIP } from "node:net";

export const REASON_CODES = Object.freeze([
  "invalid_signature_burst",
  "replay_burst",
  "anonymous_rate_burst",
  "oversized_body_burst",
  "api_probe_burst",
]);

const DEFAULT_THRESHOLDS = Object.freeze({
  invalid_signature_burst: 12,
  replay_burst: 12,
  anonymous_rate_burst: 40,
  oversized_body_burst: 12,
  api_probe_burst: 20,
});

const nonPublic = new BlockList();
const globalV6 = new BlockList();
globalV6.addSubnet("2000::", 3, "ipv6");
for (const [address, prefix] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["127.0.0.0", 8],
  ["100.64.0.0", 10], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16],
  ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
]) nonPublic.addSubnet(address, prefix, "ipv4");
for (const [address, prefix] of [
  ["::", 128], ["::1", 128], ["2001:db8::", 32], ["fc00::", 7],
  ["fe80::", 10], ["ff00::", 8],
]) nonPublic.addSubnet(address, prefix, "ipv6");

function validPositiveInteger(value, name) {
  if (!Number.isSafeInteger(value) || value < 1) throw new TypeError(`${name} must be a positive integer`);
  return value;
}

function eligibleAddress(address) {
  const family = isIP(address);
  return family !== 0 && !address.toLowerCase().startsWith("::ffff:") &&
    (family === 4 || globalV6.check(address, "ipv6")) &&
    !nonPublic.check(address, family === 4 ? "ipv4" : "ipv6");
}

export function isEligibleSource(address) {
  return typeof address === "string" && eligibleAddress(address);
}

/**
 * A bounded application-level guard. The caller must provide a verified client IP.
 * This does not attach XDP or infer an attacker from arbitrary HTTP traffic.
 */
export function createGuardCore(options = {}) {
  const mode = options.mode ?? "observe";
  if (mode !== "observe" && mode !== "enforce") throw new TypeError("mode must be observe or enforce");
  if (mode === "enforce" && typeof options.canActOnSource !== "function") {
    throw new TypeError("enforce mode requires canActOnSource");
  }
  const canActOnSource = options.canActOnSource ?? (() => true);
  const onDecision = options.onDecision ?? (() => {});
  const now = options.now ?? Date.now;
  if (typeof canActOnSource !== "function" || typeof onDecision !== "function" || typeof now !== "function") {
    throw new TypeError("callbacks must be functions");
  }
  const windowMs = validPositiveInteger(options.windowMs ?? 60_000, "windowMs");
  const blockMs = validPositiveInteger(options.blockMs ?? 120_000, "blockMs");
  const maxSources = validPositiveInteger(options.maxSources ?? 20_000, "maxSources");
  if (windowMs > 300_000 || blockMs > 300_000 || maxSources > 100_000) {
    throw new RangeError("guard windows and capacity exceed safety limits");
  }
  const thresholds = { ...DEFAULT_THRESHOLDS, ...options.thresholds };
  if (Object.keys(thresholds).some((key) => !REASON_CODES.includes(key))) {
    throw new TypeError("unknown reason code in thresholds");
  }
  for (const [reason, threshold] of Object.entries(thresholds)) {
    validPositiveInteger(threshold, reason);
    if (threshold < 2) throw new RangeError(`${reason} requires at least two observations`);
  }

  const state = new Map();
  const keyFor = (reasonCode, sourceIp) => `${reasonCode}|${sourceIp}`;
  function policyAllows(sourceIp) {
    try { return canActOnSource(sourceIp) === true; }
    catch { return false; }
  }

  function prune(at) {
    for (const [key, entry] of state) {
      entry.hits = entry.hits.filter((hit) => at - hit < windowMs);
      if (entry.hits.length === 0 && entry.blockedUntil <= at && entry.reportedUntil <= at) state.delete(key);
    }
  }

  function record({ sourceIp, reasonCode, protocol = "HTTP" } = {}) {
    if (typeof sourceIp !== "string" || !eligibleAddress(sourceIp)) return { accepted: false, reason: "ineligible_source" };
    if (!REASON_CODES.includes(reasonCode)) return { accepted: false, reason: "unknown_reason" };
    if (protocol !== "HTTP" && protocol !== "HTTPS") return { accepted: false, reason: "invalid_protocol" };
    if (!policyAllows(sourceIp)) return { accepted: false, reason: "source_excluded" };
    const at = now();
    const key = keyFor(reasonCode, sourceIp);
    let entry = state.get(key);
    if (!entry) {
      if (state.size >= maxSources) prune(at);
      if (state.size >= maxSources) return { accepted: false, reason: "capacity_exhausted" };
      entry = { hits: [], blockedUntil: 0, reportedUntil: 0, protocol };
      state.set(key, entry);
    }
    entry.hits = entry.hits.filter((hit) => at - hit < windowMs);
    entry.hits.push(at);
    const threshold = thresholds[reasonCode];
    if (entry.hits.length > threshold) entry.hits.shift();
    entry.protocol = protocol;
    if (entry.hits.length < threshold || entry.reportedUntil > at) return { accepted: true, action: "recorded" };

    entry.reportedUntil = at + windowMs;
    if (mode === "enforce") entry.blockedUntil = at + blockMs;
    const decision = Object.freeze({
      sourceIp, reasonCode, protocol, hitCount: entry.hits.length,
      observedAt: new Date(at).toISOString(),
      action: mode === "enforce" ? "limit_armed" : "observed",
      expiresAt: mode === "enforce" ? new Date(entry.blockedUntil).toISOString() : null,
    });
    Promise.resolve().then(() => onDecision(decision)).catch(() => {});
    return { accepted: true, action: decision.action, decision };
  }

  function restriction(sourceIp) {
    if (mode !== "enforce" || typeof sourceIp !== "string" || !eligibleAddress(sourceIp) || !policyAllows(sourceIp)) return null;
    const at = now();
    let blockedUntil = 0;
    for (const reasonCode of REASON_CODES) {
      blockedUntil = Math.max(blockedUntil, state.get(keyFor(reasonCode, sourceIp))?.blockedUntil ?? 0);
    }
    if (blockedUntil <= at) return null;
    return { expiresAt: new Date(blockedUntil).toISOString(), retryAfterSeconds: Math.ceil((blockedUntil - at) / 1_000) };
  }

  function isBlocked(sourceIp) {
    return restriction(sourceIp) !== null;
  }

  function release(sourceIp) {
    let removed = 0;
    for (const reasonCode of REASON_CODES) removed += Number(state.delete(keyFor(reasonCode, sourceIp)));
    return removed;
  }

  function snapshot() {
    const at = now();
    prune(at);
    return [...state.entries()].filter(([key, entry]) => entry.blockedUntil > at && policyAllows(key.slice(key.indexOf("|") + 1))).map(([key, entry]) => {
      const separator = key.indexOf("|");
      return {
        reasonCode: key.slice(0, separator), sourceIp: key.slice(separator + 1),
        protocol: entry.protocol, expiresAt: new Date(entry.blockedUntil).toISOString(),
      };
    });
  }

  return Object.freeze({ record, restriction, isBlocked, release, snapshot });
}
