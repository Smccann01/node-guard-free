import { isIP } from "node:net";

const MAX_TRUSTED_PROXIES = 32;
const MAX_FORWARDED_HOPS = 16;
const MAX_FORWARDED_LENGTH = 1024;

function normalizeIp(value, name) {
  if (typeof value !== "string" || value.length === 0 || value !== value.trim()) {
    throw new TypeError(`${name} must be an IP address`);
  }
  const mapped = value.toLowerCase().startsWith("::ffff:") && isIP(value.slice(7)) === 4 ? value.slice(7) : value;
  const family = isIP(mapped);
  if (family === 0) throw new TypeError(`${name} must be an IP address`);
  return family === 6 ? new URL(`http://[${mapped}]/`).hostname.slice(1, -1) : mapped;
}

/** Resolve an address using only explicitly named immediate and upstream proxies. */
export function createTrustedSourceResolver({ trustedProxyIps = [] } = {}) {
  if (!Array.isArray(trustedProxyIps) || trustedProxyIps.length > MAX_TRUSTED_PROXIES) {
    throw new TypeError(`trustedProxyIps must contain at most ${MAX_TRUSTED_PROXIES} addresses`);
  }
  const trusted = new Set(trustedProxyIps.map((ip) => normalizeIp(ip, "trusted proxy")));

  return function getVerifiedSourceIp(request) {
    const remote = normalizeIp(request?.socket?.remoteAddress, "socket remoteAddress");
    if (!trusted.has(remote)) return remote;

    const forwarded = request?.headers?.["x-forwarded-for"];
    if (typeof forwarded !== "string" || forwarded.length === 0 || forwarded.length > MAX_FORWARDED_LENGTH) {
      throw new TypeError("trusted proxy must provide one bounded X-Forwarded-For header");
    }
    const hops = forwarded.split(",");
    if (hops.length > MAX_FORWARDED_HOPS) throw new RangeError("too many forwarded hops");
    const chain = hops.map((hop) => normalizeIp(hop.trim(), "forwarded hop"));
    for (let index = chain.length - 1; index >= 0; index--) {
      if (!trusted.has(chain[index])) return chain[index];
    }
    throw new TypeError("forwarded chain has no untrusted source");
  };
}
