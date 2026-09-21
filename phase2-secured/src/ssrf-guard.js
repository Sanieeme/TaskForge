// ssrf-guard.js — Phase 2
// FIX (#11 SSRF): validates a user-supplied URL BEFORE the server fetches
// it, blocking loopback/private/link-local addresses and non-http(s)
// schemes. This is the standard mitigation pattern for any "server fetches
// a user-supplied URL" feature (link previews, webhooks, image proxies,
// PDF-from-URL generators, etc.).
"use strict";

const dns = require("node:dns").promises;
const net = require("node:net");

function isPrivateOrReservedIp(ip) {
  const type = net.isIP(ip);
  if (type === 4) {
    const octets = ip.split(".").map(Number);
    const [a, b] = octets;
    if (a === 127) return true; // loopback
    if (a === 10) return true; // private
    if (a === 172 && b >= 16 && b <= 31) return true; // private
    if (a === 192 && b === 168) return true; // private
    if (a === 169 && b === 254) return true; // link-local / cloud metadata range
    if (a === 0) return true; // "this network"
    return false;
  }
  if (type === 6) {
    const lower = ip.toLowerCase();
    if (lower === "::1") return true; // loopback
    if (lower.startsWith("fc") || lower.startsWith("fd")) return true; // unique local
    if (lower.startsWith("fe80")) return true; // link-local
    return false;
  }
  return true; // couldn't parse - treat as unsafe
}

/**
 * Returns { safe: true } or { safe: false, reason } for a user-supplied URL.
 * Call this BEFORE fetching, and resolve+recheck redirects too (this
 * implementation disables automatic redirects for that reason - see
 * server.js's use of `redirect: 'manual'`).
 */
async function checkUrlIsSafe(rawUrl) {
  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { safe: false, reason: "not a valid URL" };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return { safe: false, reason: "only http/https URLs are allowed" };
  }

  const hostname = parsed.hostname;
  if (hostname === "localhost") {
    return { safe: false, reason: "requests to localhost are not allowed" };
  }

  // Resolve the hostname ourselves and check the ACTUAL destination IP -
  // checking the hostname string alone isn't enough (DNS rebinding / a
  // hostname that simply resolves to 127.0.0.1 would slip past a
  // string-only check).
  let addresses;
  try {
    addresses = await dns.lookup(hostname, { all: true });
  } catch {
    return { safe: false, reason: "could not resolve hostname" };
  }

  for (const { address } of addresses) {
    if (isPrivateOrReservedIp(address)) {
      return { safe: false, reason: `destination resolves to a private/reserved address (${address})` };
    }
  }

  return { safe: true };
}

module.exports = { checkUrlIsSafe, isPrivateOrReservedIp };
