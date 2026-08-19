# @jarvisclaw-ai/sdk

TypeScript SDK for the [JarvisClaw](https://jarvisclaw.ai) AI gateway, with x402
USDC payments built in on Base and Solana.

This is the payment and transport layer. It is what
[`jarvisclaw`](https://github.com/api-jarvisclaw/jarvisclaw-cli) (the terminal
agent) runs on, and it is usable on its own.

Sibling SDKs: [python-sdk](https://github.com/api-jarvisclaw/python-sdk) ·
[go-sdk](https://github.com/api-jarvisclaw/go-sdk)

## Install

```bash
npm install @jarvisclaw-ai/sdk
```

The chain libraries are optional peers — install only the one you need:

```bash
npm install viem                # to pay with an EVM (Base) wallet
npm install @solana/web3.js     # to pay with a Solana wallet
```

Neither is needed in API-key mode.

## Two ways to pay

```ts
import { BaseClient } from '@jarvisclaw-ai/sdk'

// 1. API key — the account's balance covers the call.
const client = await BaseClient.create({ apiKey: 'sk-...' })

// 2. x402 wallet — the SDK pays per call out of your own USDC.
const client = await BaseClient.create({ privateKey: '0x...' })
```

In wallet mode there is no API key and no account. The first request goes out
unauthenticated, the gateway answers `402` with a price, the SDK signs a payment
authorisation and replays the request. That whole exchange happens inside
`request()`; callers just see the result.

Credentials also resolve from the environment, so a script needs no arguments:

| variable | meaning |
| --- | --- |
| `JARVISCLAW_API_KEY` | gateway API key |
| `JARVISCLAW_WALLET_KEY` | wallet private key (EVM hex or Solana base58) |
| `JARVISCLAW_BASE_URL` | gateway URL, for self-hosted deployments |

An explicitly passed credential always beats one in the environment.

## Balance

```ts
const usd = await client.getBalanceUsd()
```

In wallet mode this reads the chain directly, because that is what x402 settles
against. In API-key mode it reads the gateway's wallet endpoint. Note what it
deliberately does *not* include: the account's quota column. x402 settles against
the wallet and never debits quota, so counting quota would overstate spendable
funds by the lifetime deposit total.

## Paying safely

Every payment is checked before it is signed. A challenge is refused, rather than
signed and sorted out later, if it has an empty `payTo`, a non-positive or
fractional amount, an asset that is not USDC, or a network whose chain id cannot
be determined.

There is also a client-side ceiling, defaulting to 100 USDC per call:

```ts
const client = await BaseClient.create({
  privateKey: '0x...',
  maxAmountBaseUnits: 50_000n,  // 0.05 USDC, in base units (6 decimals)
})
```

This is a circuit breaker against a misconfigured or hostile server naming an
absurd price, not a spending budget — it bounds one call, not the total. For
account-level limits use the gateway's own spending limits.

A paid retry that the server still rejects is final. The SDK does not sign a
second authorisation for a request that has already been refused, since that
would spend real money twice on the same failure.

## Errors

Everything thrown descends from `JarvisClawError`, including transport failures,
so one catch covers every mode:

```ts
import {
  APIError, AuthenticationError, ConnectionError,
  InsufficientBalanceError, JarvisClawError, PaymentError,
  RateLimitError, TimeoutError,
} from '@jarvisclaw-ai/sdk'
```

| error | when |
| --- | --- |
| `AuthenticationError` | 401 — key or credential rejected |
| `RateLimitError` | 429 — has `.retryAfter` when the server sends one |
| `InsufficientBalanceError` | 402 that could not be paid |
| `PaymentError` | signing refused, before anything was sent |
| `TimeoutError` / `ConnectionError` | no HTTP response at all |
| `APIError` | any other 4xx/5xx; has `.statusCode` and `.body` |

A 402 means two different things worth distinguishing by message: in API-key mode
the account cannot cover the call; in wallet mode signing or settlement failed.

429 and 5xx are retried automatically with exponential backoff and jitter (3
attempts by default, `maxRetries`). 4xx is not retried.

## Signing directly

The signers are exported for use without the client — for a proxy, a facilitator
test, or another HTTP stack:

```ts
import { EvmX402Signer, SolanaX402Signer } from '@jarvisclaw-ai/sdk'

const signer = await EvmX402Signer.fromPrivateKey('0x...')
const header = await signer.signFrom402(response402, requestUrl)
// → set as the PAYMENT-SIGNATURE header on the replayed request
```

`EvmX402Signer.fromAccount()` takes anything that can sign EIP-712 — a viem
account, or a shim over a KMS or hardware wallet — so the private key never has to
be in the process.

## How the two chains differ

**Base (EVM)** signs an EIP-3009 `TransferWithAuthorization` over EIP-712. It is
an authorisation, not a transaction: the facilitator submits it and pays the gas,
which is why a wallet holding USDC and no ETH can still pay. `validAfter` is
backdated ten minutes so clock skew cannot make it not-yet-valid at settlement.

**Solana** builds a partially-signed SPL `TransferChecked` transaction. The server
is the fee payer and signs its own slot on verification, so we fill only ours. A
random memo instruction keeps two identical-looking payments distinct. The
blockhash comes straight from public RPC rather than through the gateway, because
a proxied one can be cached long enough to fail simulation.

Both produce the same envelope shape, base64 in the `PAYMENT-SIGNATURE` header.

## Tests

```bash
npm test
npm run typecheck
```

The signing tests check envelopes against fixtures generated by the Python SDK
(`test/fixtures/generate_reference.py`), not against this SDK's own output. Both
SDKs are verified by the same facilitator, so byte-identical output is the actual
requirement — a test that only proved self-consistency would pass while the
envelope silently drifted out of what the facilitator accepts. On top of that, the
EVM signature is recovered back to the signing address and the Solana signature is
Ed25519-verified against the serialized message, so a structurally plausible but
wrong signature fails rather than passing as 64 non-zero bytes.

## License

MIT
