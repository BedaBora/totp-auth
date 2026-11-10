import QRCode from "qrcode";

const DEFAULT_PERIOD = 30; // seconds;
const QUIET_ZONE = 4; 
const MAX_WINDOW = 10;
const MIN_SECRET_BYTES = 16;
const SECRET_BYTES = 20;
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export interface VerifyOptions {
  window?: number;
  now?: number;
  period?: number;
}

export interface KeyParams {
  secret: string;
  accountName: string;
  issuer: string;
  period?: number;
}

export function generateSecret(): string {
  return encodeBase32(crypto.getRandomValues(new Uint8Array(SECRET_BYTES)));
}

export function otpauthUri({ secret, accountName, issuer, period = DEFAULT_PERIOD }: KeyParams): string {
  checkPeriod(period);
  const canonical = encodeBase32(decodeBase32(secret));
  const account = encodeLabel(accountName, "accountName");
  const encodedIssuer = encodeLabel(issuer, "issuer");
  return (
    `otpauth://totp/${encodedIssuer}:${account}?secret=${canonical}&issuer=${encodedIssuer}` +
    `&algorithm=SHA1&digits=6&period=${period}`
  );
}

export function qrSvg(params: KeyParams): string {
  const { modules } = QRCode.create(otpauthUri(params), { errorCorrectionLevel: "L" });
  const size = modules.size + QUIET_ZONE * 2;
  let path = "";
  for (let y = 0; y < modules.size; y++) {
    for (let x = 0; x < modules.size; x++) {
      if (modules.get(y, x)) path += `M${x + QUIET_ZONE} ${y + QUIET_ZONE}h1v1h-1z`;
    }
  }
  return (
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${size} ${size}" ` +
    `shape-rendering="crispEdges" role="img" aria-label="QR code for authenticator app setup">` +
    `<rect width="${size}" height="${size}" fill="#fff"/><path d="${path}" fill="#000"/></svg>`
  );
}

function encodeLabel(value: string, name: string): string {
  if (typeof value !== "string" || !value.trim() || value.includes(":")) {
    throw new TypeError(`${name} must be non-empty and must not contain ":"`);
  }
  return encodeURIComponent(value);
}

export async function verifyCode(
  secret: string,
  code: string,
  { window = 1, now = Date.now(), period = DEFAULT_PERIOD }: VerifyOptions = {},
): Promise<number | null> {
  const key = await importKey(decodeBase32(secret));
  if (!Number.isInteger(window) || window < 0 || window > MAX_WINDOW) {
    throw new TypeError(`window must be an integer from 0 to ${MAX_WINDOW}`);
  }
  checkPeriod(period);
  if (!/^[0-9]{6}$/.test(code)) return null;

  const current = Math.floor(now / 1000 / period);
  if (!Number.isSafeInteger(current)) return null;

  let matched: number | null = null;
  for (let step = Math.max(0, current - window); step <= current + window; step++) {
    if (equalInConstantTime(await hotp(key, step), code)) matched = step;
  }
  return matched;
}

function checkPeriod(period: number): void {
  if (!Number.isSafeInteger(period) || period < 1) {
    throw new TypeError("period must be a positive whole number of seconds");
  }
}

function encodeBase32(bytes: Uint8Array): string {
  let output = "";
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += BASE32_ALPHABET[(buffer >>> bits) & 0x1f];
    }
    buffer &= (1 << bits) - 1;
  }
  if (bits > 0) output += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f];
  return output;
}

function decodeBase32(secret: string): Uint8Array<ArrayBuffer> {
  const cleaned = typeof secret === "string" ? secret.replace(/ /g, "").replace(/=+$/, "") : "";
  if (!/^[A-Za-z2-7]+$/.test(cleaned)) throw new TypeError("secret must be base32");

  const bytes: number[] = [];
  let buffer = 0;
  let bits = 0;
  for (const char of cleaned.toUpperCase()) {
    buffer = (buffer << 5) | BASE32_ALPHABET.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((buffer >>> bits) & 0xff);
    }
    buffer &= (1 << bits) - 1;
  }
  if (bytes.length < MIN_SECRET_BYTES) {
    throw new TypeError(`secret must decode to at least ${MIN_SECRET_BYTES} bytes`);
  }
  return new Uint8Array(bytes);
}

function importKey(bytes: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", bytes, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
}

async function hotp(key: CryptoKey, step: number): Promise<string> {
  const counter = new DataView(new ArrayBuffer(8));
  counter.setBigUint64(0, BigInt(step));
  const mac = new DataView(await crypto.subtle.sign("HMAC", key, counter.buffer));
  const offset = mac.getUint8(mac.byteLength - 1) & 0x0f;
  const value = mac.getUint32(offset) & 0x7fffffff;
  return String(value % 1_000_000).padStart(6, "0");
}

function equalInConstantTime(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let difference = 0;
  for (let i = 0; i < a.length; i++) difference |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return difference === 0;
}
