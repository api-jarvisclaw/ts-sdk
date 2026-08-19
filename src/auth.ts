/**
 * Credential strategies: an API key, an EVM wallet, or a Solana wallet.
 *
 * Each one knows how to put itself on an outgoing request and, if it can pay,
 * how to answer a 402 challenge.
 */
import { PaymentError } from './errors.js'
import { EvmX402Signer, type EvmSignerOptions } from './x402/evm.js'
import { SolanaX402Signer, type SolanaSignerOptions } from './x402/solana.js'

/** Which chain a raw private key belongs to. */
export type KeyType = 'evm' | 'solana'

/**
 * Guess whether a private key is EVM or Solana.
 *
 * The ambiguous case is a 64-character hex string, which is a valid EVM key and
 * also decodes as base58 often enough to be mistaken for a Solana one — hex wins,
 * because a Solana secret key is normally 87-88 base58 characters.
 */
export function detectKeyType(key: string): KeyType {
  const trimmed = key.trim()
  if (/^0[xX]/.test(trimmed)) return 'evm'
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return 'evm'
  // Base58 excludes 0, O, I and l; a string containing any of them is not base58.
  if (/^[1-9A-HJ-NP-Za-km-z]{32,90}$/.test(trimmed)) return 'solana'
  if (/^[0-9a-fA-F]+$/.test(trimmed)) return 'evm'

  throw new PaymentError(
    `Cannot tell whether this key is EVM or Solana (length ${trimmed.length}). ` +
      "Pass network: 'base' or network: 'solana' to say which.",
  )
}

/** How a credential authenticates and, if it can, pays. */
export interface AuthStrategy {
  /** Add whatever identifies the caller to an outgoing request. */
  prepareHeaders(headers: Headers): void
  /** Whether this credential can answer a 402 by signing a payment. */
  readonly supportsX402: boolean
  /** The wallet address, or undefined in API-key mode. */
  readonly address: string | undefined
  /**
   * Turn a 402 response into a `PAYMENT-SIGNATURE` header value.
   *
   * Throws PaymentError if the challenge cannot be satisfied; returns undefined
   * only when this credential cannot pay at all.
   */
  signPayment(resp: Response, resourceUrl: string): Promise<string | undefined>
}

/** Bearer-token authentication with a gateway API key. */
export class ApiKeyAuth implements AuthStrategy {
  readonly supportsX402 = false
  readonly address = undefined

  constructor(private readonly apiKey: string) {}

  prepareHeaders(headers: Headers): void {
    headers.set('Authorization', `Bearer ${this.apiKey}`)
  }

  async signPayment(): Promise<undefined> {
    return undefined
  }
}

/** x402 payment with an EVM key. Sends no credential until challenged. */
export class EvmX402Auth implements AuthStrategy {
  readonly supportsX402 = true

  constructor(private readonly signer: EvmX402Signer) {}

  static async fromPrivateKey(
    privateKey: string,
    opts: EvmSignerOptions = {},
  ): Promise<EvmX402Auth> {
    return new EvmX402Auth(await EvmX402Signer.fromPrivateKey(privateKey, opts))
  }

  get address(): string {
    return this.signer.address
  }

  prepareHeaders(): void {
    // Nothing to add: the wallet proves itself by signing the 402 challenge, so
    // an unpaid first request is deliberately anonymous.
  }

  async signPayment(resp: Response, resourceUrl: string): Promise<string> {
    return this.signer.signFrom402(resp, resourceUrl)
  }
}

/** x402 payment with a Solana key. */
export class SolanaX402Auth implements AuthStrategy {
  readonly supportsX402 = true

  constructor(private readonly signer: SolanaX402Signer) {}

  static async fromPrivateKey(
    privateKey: string,
    opts: SolanaSignerOptions = {},
  ): Promise<SolanaX402Auth> {
    return new SolanaX402Auth(await SolanaX402Signer.fromPrivateKey(privateKey, opts))
  }

  get address(): string {
    return this.signer.address
  }

  prepareHeaders(): void {
    // See EvmX402Auth.prepareHeaders.
  }

  async signPayment(resp: Response, resourceUrl: string): Promise<string> {
    return this.signer.signFrom402(resp, resourceUrl)
  }
}
