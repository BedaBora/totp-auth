# totp-auth

Add TOTP two-factor login to your app. It generates the secret, draws the QR code for authenticator apps such as Google Authenticator, Authy and 1Password, and verifies the 6-digit codes.

It runs on Node 20+ and in modern browsers. Browsers need a bundler, because its one dependency, `qrcode`, is CommonJS.

> The package name isn't final: `totp-auth` is already taken on npm, so this package is currently `private`. Replace the name in the import below once it's published.

## Enroll a user

```js
import { generateSecret, qrSvg } from "totp-auth";

const secret = generateSecret(); // e.g. "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
// Save `secret` against the user, then show them one or both of these:

const svg = qrSvg({ secret, accountName: "alice@example.com", issuer: "Acme" });
// `svg` is an SVG string to place in your page. It contains no user-supplied text.
// `secret` itself is what the user types into their app if they can't scan.
```

`issuer` and `accountName` are what the app displays. They can't be empty or contain `:`.

## Verify a code

```js
import { verifyCode } from "totp-auth";

const step = await verifyCode(user.totpSecret, input);
if (step === null || step <= user.lastTotpStep) return reject();

user.lastTotpStep = step; // save this before granting access
```

`verifyCode` returns the matched time step, or `null` if the code doesn't match. Malformed codes return `null`; an invalid secret, `window` or `period` throws `TypeError`.

Options:

| Option | Default | Meaning |
|---|---|---|
| `window` | `1` | Steps accepted either side of the current one (integer, 0–10). Each step lasts one `period`. Raise it if users' clocks drift. |
| `period` | `30` | Seconds each code lasts (positive integer). Must match the `period` used for `qrSvg` or `otpauthUri`. |
| `now` | `Date.now()` | The time to verify against, in milliseconds |

## What your app must do

This library keeps no state, so these are your responsibility:

- **Reject reused codes.** A code stays valid for its whole window, and RFC 6238 requires each one to work only once. Store the returned step and use the check above. It must be `<=`, not `===`, or an older code still inside the window would pass after a newer one was used.
- **Rate-limit attempts.** A 6-digit code can be brute-forced without a limit on attempts.
- **Protect stored secrets.** Anyone with a user's secret can generate their codes, so encrypt secrets at rest and keep them out of logs.

## Other functions

`otpauthUri({ secret, accountName, issuer })` returns the `otpauth://` link that the QR code contains, for building your own QR or a tap-to-add link.

## Changing the period

Codes last 30 seconds by default. To change that, pass the same `period` when enrolling and when verifying:

```js
const svg = qrSvg({ secret, accountName: "alice@example.com", issuer: "Acme", period: 60 });
const step = await verifyCode(user.totpSecret, input, { period: 60 });
```

Some authenticator apps ignore the period and always use 30 seconds, so test a custom period with the apps your users have. The returned step number depends on the period, so if you change a user's period, reset their stored `lastTotpStep`.

The algorithm (SHA1) and code length (6 digits) are fixed, because they're what authenticator apps support reliably.
