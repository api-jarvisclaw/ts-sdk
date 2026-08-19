/**
 * Parsing and validating an HTTP 402 challenge.
 *
 * Shared by both signers. The Python SDK duplicates this per chain, which is why
 * only its EVM path reads the base64 `payment-required` header and its Solana
 * path reads the body alone; here both get the same treatment.
 */
import { PaymentError } from '../errors.js'
import type { PaymentChallenge, PaymentOption, ResolvedPayment } from './types.js'

/** Default client-side ceiling: 100 USDC, in base units (6 decimals). */
export const DEFAULT_MAX_AMOUNT_BASE_UNITS = 100_000_000n

/**
 * Read the challenge out of a 402 response.
 *
 * The server may put it in a base64 header or in the JSON body. The response is
 * consumed here, so callers must not have read the body already.
 */
export async function parseChallenge(resp: Response): Promise<PaymentChallenge> {
  const header =
    resp.headers.get('payment-required') ?? resp.headers.get('x-payment-required')

  if (header) {
    try {
      return JSON.parse(base64Decode(header)) as PaymentChallenge
    } catch {
      // A malformed header is not fatal on its own — the body usually carries
      // the same challenge, so fall through to it rather than giving up.
    }
  }

  try {
    return (await resp.json()) as PaymentChallenge
  } catch (err) {
    throw new PaymentError(
      `x402: 402 response carried no readable payment challenge (${String(err)})`,
    )
  }
}

/** Every payment option in the challenge, under either the v2 or v1 field name. */
export function paymentOptions(challenge: PaymentChallenge): PaymentOption[] {
  return challenge.accepts ?? challenge.payments ?? []
}

/**
 * Pick the option whose network matches `networkPrefix` (`eip155:` / `solana:`).
 *
 * Returns undefined rather than throwing so a caller holding one kind of key can
 * report that this server wants the other kind.
 */
export function findOption(
  challenge: PaymentChallenge,
  networkPrefix: string,
): PaymentOption | undefined {
  return paymentOptions(challenge).find((p) => (p.network ?? '').startsWith(networkPrefix))
}

/**
 * Validate an option and normalise it, or throw explaining what was wrong.
 *
 * The checks matter: an empty `payTo` would sign away funds to the zero address,
 * a non-positive amount would produce a signature the facilitator rejects after
 * the fact, an unexpected asset would authorise a transfer of some other token,
 * and no ceiling at all would let a server name any price it liked.
 */
export function resolvePayment(
  option: PaymentOption,
  opts: {
    challenge: PaymentChallenge
    expectedAsset: string
    defaultAsset?: string
    defaultNetwork: string
    maxAmountBaseUnits?: bigint
    /** Compare assets case-insensitively (EVM hex addresses) or exactly (Solana base58). */
    assetCaseInsensitive: boolean
  },
): ResolvedPayment {
  const payTo = option.payTo ?? ''
  if (!payTo) {
    throw new PaymentError('x402: server returned an empty payTo address')
  }

  const amount = parseAmount(option.amount ?? option.maxAmountRequired ?? '0')
  if (amount <= 0n) {
    throw new PaymentError(`x402: invalid payment amount ${amount} (must be positive)`)
  }

  const cap = opts.maxAmountBaseUnits ?? DEFAULT_MAX_AMOUNT_BASE_UNITS
  if (amount > cap) {
    throw new PaymentError(
      `x402: amount ${amount} exceeds the client safety cap of ${cap} base units ` +
        `(${formatUsdc(cap)} USDC) — raise maxAmountBaseUnits if this is expected`,
    )
  }

  const asset = option.asset ?? opts.defaultAsset ?? opts.expectedAsset
  const sameAsset = opts.assetCaseInsensitive
    ? asset.toLowerCase() === opts.expectedAsset.toLowerCase()
    : asset === opts.expectedAsset
  if (!sameAsset) {
    throw new PaymentError(`x402: unexpected asset ${asset}, expected USDC ${opts.expectedAsset}`)
  }

  return {
    payTo,
    amount,
    asset,
    network: option.network ?? opts.defaultNetwork,
    maxTimeoutSeconds: option.maxTimeoutSeconds ?? 300,
    extra: option.extra ?? {},
    description: opts.challenge.resource?.description ?? 'API request',
  }
}

/**
 * Parse an amount that arrives as a decimal string or a number.
 *
 * Rejects anything non-integral: base units are indivisible, so a fractional
 * amount means a unit mix-up somewhere upstream, and silently truncating it
 * would sign for the wrong sum.
 */
export function parseAmount(raw: string | number): bigint {
  const text = typeof raw === 'number' ? String(raw) : raw.trim()
  if (!/^-?\d+$/.test(text)) {
    throw new PaymentError(
      `x402: amount ${JSON.stringify(raw)} is not an integer number of base units`,
    )
  }
  return BigInt(text)
}

/** Base units to a human USDC string, for messages only. */
export function formatUsdc(baseUnits: bigint): string {
  const whole = baseUnits / 1_000_000n
  const frac = (baseUnits % 1_000_000n).toString().padStart(6, '0').replace(/0+$/, '')
  return frac ? `${whole}.${frac}` : String(whole)
}

/** Base64-encode the envelope for the `PAYMENT-SIGNATURE` header. */
export function encodeEnvelope(envelope: unknown): string {
  return base64Encode(JSON.stringify(envelope))
}

function base64Encode(text: string): string {
  return Buffer.from(text, 'utf8').toString('base64')
}

function base64Decode(text: string): string {
  return Buffer.from(text, 'base64').toString('utf8')
}
