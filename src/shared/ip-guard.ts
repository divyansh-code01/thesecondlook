/**
 * Second Look® — IP/host blocklist for SSRF defence (spec §7/§10).
 * Isomorphic so it can be unit-tested and reused by validation and the pipeline.
 */

const BLOCKED_HOSTNAMES = new Set(["localhost", "metadata", "metadata.google.internal"]);

function isBlockedHostnameSuffix(host: string): boolean {
  const h = host.toLowerCase();
  return (
    h === "localhost" ||
    h.endsWith(".localhost") ||
    h.endsWith(".local") ||
    h.endsWith(".internal") ||
    h.endsWith(".home.arpa") ||
    h.endsWith(".corp") ||
    BLOCKED_HOSTNAMES.has(h)
  );
}

/** Expand decimal / hex / octal / dotted IPv4 literals to a dotted quad, or return null. */
export function expandIpV4Literal(host: string): string | null {
  const h = host.toLowerCase();
  if (/^\d+$/.test(h) && !h.startsWith("0")) {
    const n = Number(h);
    if (n > 4294967295 || n < 0) return null;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }
  if (h.startsWith("0x")) {
    const n = Number(h);
    if (Number.isNaN(n) || n > 4294967295) return null;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }
  if (!/^[0-9.]+$/.test(h)) return null;
  const parts = h.split(".");
  if (parts.length < 1 || parts.length > 4) return null;
  if (parts.length === 1) {
    // Single octal like 017700000001
    const n = Number.parseInt(parts[0], 8);
    if (Number.isNaN(n) || n > 4294967295) return null;
    return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
  }
  const out: number[] = [];
  for (let i = 0; i < 4; i++) {
    const p = parts[i] ?? "0";
    let n: number;
    if (/^0\d+$/.test(p)) n = Number.parseInt(p, 8);
    else if (/^0x[0-9a-f]+$/.test(p)) n = Number.parseInt(p, 16);
    else n = Number.parseInt(p, 10);
    if (Number.isNaN(n) || n > 255) return null;
    out.push(n);
  }
  return out.join(".");
}

function v4ToLong(dotted: string): number {
  const [a, b, c, d] = dotted.split(".").map(Number);
  return ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
}

function inRange4(ip: string, cidr: [number, number, number, number, number]): boolean {
  const n = v4ToLong(ip);
  const [a, b, c, d, bits] = cidr;
  const base = ((a << 24) | (b << 16) | (c << 8) | d) >>> 0;
  const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
  return (n & mask) === (base & mask);
}

const PRIVATE_V4: [number, number, number, number, number][] = [
  [0, 0, 0, 0, 8], // 0.0.0.0/8 "this network"
  [10, 0, 0, 0, 8], // 10/8
  [100, 64, 0, 0, 10], // CGNAT
  [127, 0, 0, 0, 8], // loopback
  [169, 254, 0, 0, 16], // link-local (incl. cloud metadata 169.254.169.254)
  [172, 16, 0, 0, 12], // 172.16/12
  [192, 0, 0, 0, 24], // IETF protocol assignments
  [192, 0, 2, 0, 24], // TEST-NET-1
  [192, 168, 0, 0, 16], // 192.168/16
  [198, 18, 0, 0, 15], // benchmarking
  [198, 51, 100, 0, 24], // TEST-NET-2
  [203, 0, 113, 0, 24], // TEST-NET-3
  [224, 0, 0, 0, 4], // multicast
  [240, 0, 0, 0, 4], // reserved
  [255, 255, 255, 255, 32], // broadcast
];

export function isPrivateV4(dotted: string): boolean {
  return PRIVATE_V4.some((r) => inRange4(dotted, r));
}

function parseV6(host: string): string | null {
  let h = host.toLowerCase().replace(/^\[|\]$/g, "");
  // IPv4-mapped / IPv4-in-IPv6 endings
  const v4Match = h.match(/^(.*:)((?:\d+\.){3}\d+|0x[0-9a-f]+|\d+)$/);
  if (v4Match) {
    const dotted = expandIpV4Literal(v4Match[2]);
    if (!dotted) return null;
    const [a, b] = dotted.split(".").map(Number);
    h = `${v4Match[1]}${(a / 16).toString(16)}${(a % 16).toString(16)}:${(b / 16).toString(16)}${(b % 16).toString(16)}`;
  }
  if (!h.includes(":")) return null;
  // Handle "::"
  const doubleColonCount = (h.match(/::/g) ?? []).length;
  if (doubleColonCount > 1) return null;
  let head: string[] = [];
  let tail: string[] = [];
  if (doubleColonCount === 1) {
    const [l, r] = h.split("::");
    head = l ? l.split(":") : [];
    tail = r ? r.split(":") : [];
  } else {
    head = h.split(":");
  }
  const missing = 8 - head.length - tail.length;
  if (doubleColonCount === 1 ? missing < 0 : missing !== 0) return null;
  const groups = [...head, ...Array(Math.max(0, missing)).fill("0"), ...tail];
  if (groups.length !== 8) return null;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
  }
  return groups.map((g) => g.padStart(4, "0")).join("");
}

function v6Groups(v6: string): number[] {
  return (v6.match(/.{4}/g) ?? []).map((g) => parseInt(g, 16));
}

export function isPrivateV6(v6: string): boolean {
  const g = v6Groups(v6);
  const at = (i: number) => g[i] ?? 0;
  const isZero = (i: number, n: number) => g.slice(i, i + n).every((x) => x === 0);
  // :: (unspecified), ::1 (loopback)
  if (g.every((x) => x === 0)) return true;
  if (isZero(0, 7) && at(7) === 1) return true;
  // fc00::/7 unique-local
  if ((at(0) & 0xfe00) === 0xfc00) return true;
  // fe80::/10 link-local
  if ((at(0) & 0xffc0) === 0xfe80) return true;
  // ff00::/8 multicast
  if ((at(0) & 0xff00) === 0xff00) return true;
  // ::ffff:0:0/96 IPv4-mapped — check embedded IPv4
  if (isZero(0, 5) && at(5) === 0xffff) {
    const hi = at(6);
    const lo = at(7);
    const dotted = `${(hi >> 8) & 255}.${hi & 255}.${(lo >> 8) & 255}.${lo & 255}`;
    if (isPrivateV4(dotted)) return true;
  }
  // 64:ff9b::/96 NAT64 well-known prefix maps IPv4
  if (at(0) === 0x64 && at(1) === 0xff9b && isZero(2, 4)) {
    const dotted = `${(at(6) >> 8) & 255}.${at(6) & 255}.${(at(7) >> 8) & 255}.${at(7) & 255}`;
    if (isPrivateV4(dotted)) return true;
  }
  return false;
}

export type HostKind = "blocked" | "public" | "unresolvable";

/**
 * Classify a hostname (no port, no credentials). "public" means "not obviously
 * private by name or literal form" — DNS-based checks still apply before fetching.
 */
export function classifyHost(rawHost: string): { kind: HostKind; reason?: string } {
  const host = rawHost.toLowerCase().replace(/\.$/, "");
  if (!host) return { kind: "blocked", reason: "empty" };
  if (isBlockedHostnameSuffix(host)) return { kind: "blocked", reason: "local_or_internal_hostname" };

  // Strip zone id in IPv6 (fe80::1%eth0)
  const v6candidate = host.includes("%") ? host.split("%")[0] : host;
  const v6 = parseV6(v6candidate);
  if (v6) {
    return isPrivateV6(v6)
      ? { kind: "blocked", reason: "private_or_reserved_ip" }
      : { kind: "public" };
  }

  const v4 = expandIpV4Literal(host);
  if (v4) {
    return isPrivateV4(v4)
      ? { kind: "blocked", reason: "private_or_reserved_ip" }
      : { kind: "public" };
  }

  if (!host.includes(".")) {
    // Single-label hostname (intranet-style names never resolve publicly)
    return { kind: "blocked", reason: "local_or_internal_hostname" };
  }
  return { kind: "public" };
}

/** True when the literal form hides a private address even though it parses as a public-looking host. */
export function isDisguisedPrivateLiteral(rawHost: string): boolean {
  const v4 = expandIpV4Literal(rawHost.toLowerCase());
  return v4 !== null && isPrivateV4(v4);
}
