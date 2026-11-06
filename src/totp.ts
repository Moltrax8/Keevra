/**
 * TOTP (RFC 6238, SHA-1, 30-second period, 6 digits) for `TOTP` fields.
 * Seeds are base32 vault content; HMAC itself runs on the platform WebCrypto
 * implementation — no custom cryptographic primitives here.
 */

const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function normalizeTotpSeed(seed: string): string {
  return seed.trim().toUpperCase().replace(/[\s-]/g, "");
}

export function isValidTotpSeed(seed: string): boolean {
  if (seed === "") return true;
  const data = normalizeTotpSeed(seed).replace(/=+$/, "");
  // Unpadded base32 lengths carry whole bytes only for len % 8 in {0,2,4,5,7}.
  if (data.length < 16 || ![0, 2, 4, 5, 7].includes(data.length % 8)) return false;
  return /^[A-Z2-7]+$/.test(data);
}

export function decodeBase32Seed(seed: string): Uint8Array {
  const normalized = normalizeTotpSeed(seed).replace(/=+$/, "");
  let bits = 0;
  let bitsAvailable = 0;
  const bytes: number[] = [];
  for (const char of normalized) {
    const value = BASE32_ALPHABET.indexOf(char);
    if (value < 0) throw new Error("invalid_base32");
    bits = (bits << 5) | value;
    bitsAvailable += 5;
    if (bitsAvailable >= 8) {
      bitsAvailable -= 8;
      bytes.push((bits >>> bitsAvailable) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

export const TOTP_PERIOD_SECONDS = 30;
export const TOTP_DIGITS = 6;

export function totpCounterAt(timeSeconds: number): bigint {
  return BigInt(Math.floor(timeSeconds / TOTP_PERIOD_SECONDS));
}

export function totpSecondsRemaining(timeSeconds: number): number {
  const elapsed = Math.floor(timeSeconds) % TOTP_PERIOD_SECONDS;
  return TOTP_PERIOD_SECONDS - elapsed;
}

async function hmacSha1(key: Uint8Array, data: Uint8Array): Promise<Uint8Array> {
  const keyBytes = Uint8Array.from(key);
  const dataBytes = Uint8Array.from(data);
  const cryptoKey = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-1" }, false, [
    "sign",
  ]);
  const signature = await crypto.subtle.sign("HMAC", cryptoKey, dataBytes);
  return new Uint8Array(signature);
}

/** Current 6-digit code for a base32 seed at `atSeconds` (defaults to now). */
export async function totpCodeAt(seed: string, atSeconds: number = Date.now() / 1000): Promise<string> {
  const key = decodeBase32Seed(seed);
  const counter = totpCounterAt(atSeconds);
  const data = new Uint8Array(8);
  let rest = counter;
  for (let i = 7; i >= 0; i--) {
    data[i] = Number(rest & 0xffn);
    rest >>= 8n;
  }
  const hmac = await hmacSha1(key, data);
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    (hmac[offset + 1] << 16) |
    (hmac[offset + 2] << 8) |
    hmac[offset + 3];
  return (binary % 10 ** TOTP_DIGITS).toString().padStart(TOTP_DIGITS, "0");
}
