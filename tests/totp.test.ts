import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { test } from "node:test";
import QRCode from "qrcode";
import { generateSecret, otpauthUri, qrSvg, verifyCode } from "../src/index.ts";

// ASCII "12345678901234567890", the RFC 6238 Appendix B SHA1 seed.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const STEP_1_CODE = "287082"; // valid for T=30..59s, i.e. step 1

const atSeconds = (seconds: number) => ({ window: 0, now: seconds * 1000 });
const atStep = (step: number, window?: number) => ({ window, now: step * 30_000 });

test("verifyCode matches RFC 6238 SHA1 vectors (last 6 digits)", async () => {
  const vectors: [seconds: number, code: string][] = [
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
    [20000000000, "353130"],
  ];
  for (const [seconds, code] of vectors) {
    const step = Math.floor(seconds / 30);
    assert.equal(await verifyCode(RFC_SECRET, code, atSeconds(seconds)), step, `T=${seconds}`);
  }
});

test("verifyCode returns null for a wrong code", async () => {
  assert.equal(await verifyCode(RFC_SECRET, "000000", atSeconds(59)), null);
});

test("verifyCode accepts the default window of one step either side", async () => {
  assert.equal(await verifyCode(RFC_SECRET, STEP_1_CODE, atStep(0)), 1);
  assert.equal(await verifyCode(RFC_SECRET, STEP_1_CODE, atStep(2)), 1);
  assert.equal(await verifyCode(RFC_SECRET, STEP_1_CODE, atStep(3)), null);
});

test("verifyCode honours a custom window", async () => {
  assert.equal(await verifyCode(RFC_SECRET, STEP_1_CODE, atStep(2, 0)), null);
  assert.equal(await verifyCode(RFC_SECRET, STEP_1_CODE, atStep(4, 3)), 1);
  assert.equal(await verifyCode(RFC_SECRET, STEP_1_CODE, atStep(5, 3)), null);
});

test("verifyCode defaults to the current time", async () => {
  const hmac = createHmac("sha1", "12345678901234567890");
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30_000)));
  const mac = hmac.update(counter).digest();
  const code = String((mac.readUInt32BE(mac[19]! & 0x0f) & 0x7fffffff) % 1_000_000).padStart(6, "0");

  assert.notEqual(await verifyCode(RFC_SECRET, code), null);
});

test("verifyCode doesn't test steps below zero", async () => {
  // setBigUint64 wraps -1 to 2^64-1, so an unguarded loop would accept this code at time zero.
  const counter = Buffer.alloc(8, 0xff);
  const mac = createHmac("sha1", "12345678901234567890").update(counter).digest();
  const code = String((mac.readUInt32BE(mac[19]! & 0x0f) & 0x7fffffff) % 1_000_000).padStart(6, "0");

  assert.equal(await verifyCode(RFC_SECRET, code, { now: 0, window: 1 }), null);
});

test("verifyCode returns null for a time that has no valid step", async () => {
  for (const now of [NaN, Infinity, -Infinity, 1e300, -1e300]) {
    assert.equal(await verifyCode(RFC_SECRET, STEP_1_CODE, { now }), null, `now=${now}`);
  }
});

test("verifyCode returns null for malformed codes without throwing", async () => {
  const malformed: unknown[] = [
    "",
    "28708",
    "2870820",
    "28708a",
    "287 082",
    "287082\n",
    "٢٨٧٠٨٢", // same digits, Arabic-Indic
    undefined,
    null,
    287082,
    ["287082"],
    {},
  ];
  for (const code of malformed) {
    const result = await verifyCode(RFC_SECRET, code as string, atStep(1, 0));
    assert.equal(result, null, JSON.stringify(code));
  }
});

test("verifyCode reads secrets regardless of case, spaces or padding", async () => {
  const forms = [
    RFC_SECRET.toLowerCase(),
    "GEZD GNBV GY3T QOJQ GEZD GNBV GY3T QOJQ",
    "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ======",
  ];
  for (const secret of forms) {
    assert.equal(await verifyCode(secret, STEP_1_CODE, atStep(1, 0)), 1, secret);
  }
});

test("verifyCode throws TypeError for an invalid secret, never echoing it", async () => {
  const invalid: unknown[] = [
    "",
    "GEZDGNBVGY3TQOJ", // 15 characters decode to 9 bytes
    "GEZDGNBVGY3TQOJQGEZDGNB1", // 1 isn't in the alphabet
    "GEZDGNBVGY3TQOJQGEZDGNB=VGY3", // padding only allowed at the end
    "ſEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", // long s, which uppercases to a valid S
    undefined,
    12345,
  ];
  for (const secret of invalid) {
    await assert.rejects(
      verifyCode(secret as string, "000000"),
      (error: Error) => {
        assert.ok(error instanceof TypeError, String(secret));
        assert.ok(!String(secret) || !error.message.includes(String(secret)));
        return true;
      },
    );
  }
});

test("verifyCode accepts a secret at the 16-byte minimum", async () => {
  // 26 characters decode to 16 bytes.
  assert.equal(await verifyCode("A".repeat(26), "abc"), null);
});

test("verifyCode throws TypeError for an invalid window", async () => {
  for (const window of [-1, 11, 1.5, NaN, Infinity]) {
    await assert.rejects(verifyCode(RFC_SECRET, "000000", { window }), TypeError, `window=${window}`);
  }
});

test("verifyCode checks the secret even when the code is malformed", async () => {
  await assert.rejects(verifyCode("not base32!", "abc"), TypeError);
});

test("generateSecret returns 32 uppercase base32 characters", () => {
  assert.match(generateSecret(), /^[A-Z2-7]{32}$/);
});

test("generateSecret returns a different secret each call", () => {
  assert.notEqual(generateSecret(), generateSecret());
});

test("generateSecret output is accepted by verifyCode", async () => {
  assert.equal(await verifyCode(generateSecret(), "abc"), null);
});

test("otpauthUri builds the full key URI", () => {
  assert.equal(
    otpauthUri({ secret: RFC_SECRET, accountName: "alice@example.com", issuer: "Acme" }),
    `otpauth://totp/Acme:alice%40example.com?secret=${RFC_SECRET}&issuer=Acme&algorithm=SHA1&digits=6&period=30`,
  );
});

test("otpauthUri encodes spaces as %20, never +", () => {
  const uri = otpauthUri({ secret: RFC_SECRET, accountName: "Alice B", issuer: "Acme Inc" });
  assert.ok(uri.startsWith("otpauth://totp/Acme%20Inc:Alice%20B?"));
  assert.ok(uri.includes("&issuer=Acme%20Inc&"));
  assert.ok(!uri.includes("+"));
});

test("otpauthUri writes the secret in canonical form", () => {
  const uri = otpauthUri({ secret: "gezd gnbv gy3t qojq gezd gnbv gy3t qojq==", accountName: "a", issuer: "b" });
  assert.ok(uri.includes(`?secret=${RFC_SECRET}&`));
});

test("qrSvg draws the otpauth URI at error correction L with a 4-module quiet zone", () => {
  const params = { secret: RFC_SECRET, accountName: "alice@example.com", issuer: "Acme" };
  const { modules } = QRCode.create(otpauthUri(params), { errorCorrectionLevel: "L" });
  const size = modules.size + 8;
  const expectedDark: string[] = [];
  for (let y = 0; y < modules.size; y++) {
    for (let x = 0; x < modules.size; x++) {
      if (modules.get(y, x)) expectedDark.push(`M${x + 4} ${y + 4}h1v1h-1z`);
    }
  }

  const svg = qrSvg(params);

  assert.ok(svg.includes(`viewBox="0 0 ${size} ${size}"`), svg.slice(0, 120));
  // Exact match with the level-L matrix: other levels differ at least in their format bits.
  assert.deepEqual(svg.match(/M\d+ \d+h1v1h-1z/g), expectedDark);
  assert.ok(svg.includes('d="M4 4h1v1h-1z'), "top-left finder corner sits inside the quiet zone");
});

test("qrSvg output is a labelled, crisp, black on white image", () => {
  const svg = qrSvg({ secret: RFC_SECRET, accountName: "alice", issuer: "Acme" });
  assert.match(svg, /^<svg [^>]*xmlns="http:\/\/www\.w3\.org\/2000\/svg"/);
  assert.match(svg, /<\/svg>$/);
  assert.equal(svg.match(/<path /g)?.length, 1);
  assert.ok(svg.includes('shape-rendering="crispEdges"'));
  assert.ok(svg.includes('role="img"'));
  assert.ok(svg.includes('aria-label="'));
  assert.ok(svg.includes('fill="#fff"') && svg.includes('fill="#000"'));
});

test("qrSvg contains no user-supplied text", () => {
  const svg = qrSvg({ secret: RFC_SECRET, accountName: '"><script>', issuer: "Acme" });
  assert.ok(!svg.includes("script"));
  assert.ok(!svg.includes(RFC_SECRET));
});

test("qrSvg throws the same errors as otpauthUri", () => {
  assert.throws(() => qrSvg({ secret: RFC_SECRET, accountName: "a:b", issuer: "Acme" }), TypeError);
  assert.throws(() => qrSvg({ secret: "not base32!", accountName: "a", issuer: "Acme" }), TypeError);
});

test("otpauthUri throws TypeError for invalid labels or secret", () => {
  const valid = { secret: RFC_SECRET, accountName: "alice", issuer: "Acme" };
  const invalid: Record<string, unknown>[] = [
    { ...valid, issuer: "" },
    { ...valid, issuer: "   " },
    { ...valid, issuer: "Ac:me" },
    { ...valid, issuer: undefined },
    { ...valid, accountName: "" },
    { ...valid, accountName: "ali:ce" },
    { ...valid, accountName: 42 },
    { ...valid, secret: "not base32!" },
  ];
  for (const params of invalid) {
    assert.throws(() => otpauthUri(params as never), TypeError, JSON.stringify(params));
  }
});

// Independent HOTP using node:crypto, for codes the RFC vectors don't cover.
function referenceCode(step: number): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(step));
  const mac = createHmac("sha1", "12345678901234567890").update(counter).digest();
  return String((mac.readUInt32BE(mac[19]! & 0x0f) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

test("verifyCode uses a custom period to pick the time step", async () => {
  const seconds = 1111111111;
  const step = Math.floor(seconds / 60);
  const code = referenceCode(step);

  assert.equal(await verifyCode(RFC_SECRET, code, { window: 0, now: seconds * 1000, period: 60 }), step);
  assert.equal(await verifyCode(RFC_SECRET, code, { window: 0, now: seconds * 1000 }), null);
});

test("verifyCode measures the window in periods", async () => {
  const code = referenceCode(100);
  assert.equal(await verifyCode(RFC_SECRET, code, { window: 1, now: 101 * 60_000, period: 60 }), 100);
  assert.equal(await verifyCode(RFC_SECRET, code, { window: 1, now: 102 * 60_000, period: 60 }), null);
});

test("verifyCode throws TypeError for an invalid period", async () => {
  for (const period of [0, -30, 1.5, NaN, Infinity, null, "30"]) {
    await assert.rejects(
      verifyCode(RFC_SECRET, "000000", { period: period as number }),
      TypeError,
      `period=${String(period)}`,
    );
  }
});

test("otpauthUri writes a custom period", () => {
  const uri = otpauthUri({ secret: RFC_SECRET, accountName: "alice", issuer: "Acme", period: 60 });
  assert.ok(uri.endsWith("&digits=6&period=60"), uri);
});

test("otpauthUri throws TypeError for an invalid period", () => {
  for (const period of [0, -30, 1.5, NaN, null, "30"]) {
    assert.throws(
      () => otpauthUri({ secret: RFC_SECRET, accountName: "alice", issuer: "Acme", period: period as number }),
      TypeError,
      `period=${String(period)}`,
    );
  }
});

test("qrSvg passes the period into the QR code", () => {
  const params = { secret: RFC_SECRET, accountName: "alice", issuer: "Acme" };
  assert.notEqual(qrSvg({ ...params, period: 60 }), qrSvg(params));
  assert.throws(() => qrSvg({ ...params, period: 0 }), TypeError);
});
