"use strict";
// Fake credentials for tests. They are assembled at runtime so no token-shaped literal
// lives in the source (keeps push protection and secret scanners quiet). None are real.

const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const UPPER_DIGITS = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/**
 * Deterministic string from `alphabet`: a seeded shuffle (mulberry32 + Fisher-Yates), read
 * cyclically, so up to alphabet.length characters are all distinct and entropy is high.
 */
function rand(len, seed, alphabet = ALNUM) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  const chars = alphabet.split("");
  for (let i = chars.length - 1; i > 0; i--) {
    const j = Math.floor(next() * (i + 1));
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  let s = "";
  for (let i = 0; i < len; i++) s += chars[i % chars.length];
  return s;
}

const fakes = {
  aws: (seed = 1) => "AK" + "IA" + rand(16, seed, UPPER_DIGITS),
  github: (seed = 2) => "gh" + "p_" + rand(36, seed),
  openai: (seed = 3) => "sk" + "-proj-" + rand(40, seed),
  anthropic: (seed = 4) => "sk" + "-ant-" + rand(40, seed),
  slack: (seed = 5) => "xo" + "xb-" + rand(12, seed, "0123456789") + "-" + rand(24, seed + 1),
  entropy: (seed = 6) => rand(40, seed),
  keyHeader: () => "-----BEGIN " + "RSA PRIVATE KEY-----",
};

module.exports = { rand, fakes };
