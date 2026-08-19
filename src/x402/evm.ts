/**
 * x402 EVM signing — EIP-3009 `TransferWithAuthorization` over EIP-712.
 *
 * We sign an authorisation rather than sending a transaction: the facilitator
 * submits it and pays the gas. That is the whole reason a caller with USDC but no
 * ETH can still pay for an API call.
 */
import { PaymentError } from '../errors.js'
import {
  encodeEnvelope,
  findOption,
  parseChallenge,
  resolvePayment,
} from './challenge.js'
import type { PaymentEnvelope, SignerLimits } from './types.js'

/** Base mainnet, in CAIP-2 form. */
export const DEFAULT_EVM_NETWORK = 'eip155:8453'
/** Circle's USDC on Base. */
export const USDC_BASE_CONTRACT = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913'
export const USDC_NAME = 'USD Coin'
export const USDC_VERSION = '2'

const CHAIN_ID_MAP: Record<string, number> = {
  base: 8453,
  'base-sepolia': 84532,
  'eip155:8453': 8453,
  'eip155:84532': 84532,
}

const TRANSFER_WITH_AUTHORIZATION_TYPES = {
  TransferWithAuthorization: [
    { name: 'from', type: 'address' },
    { name: 'to', type: 'address' },
    { name: 'value', type: 'uint256' },
    { name: 'validAfter', type: 'uint256' },
    { name: 'validBefore', type: 'uint256' },
    { name: 'nonce', type: 'bytes32' },
  ],
} as const

/**
 * Resolve `network` to a numeric chain id.
 *
 * An unknown `eip155:N` is honoured by reading N out of the string, so a new
 * chain does not need an SDK release. Anything else is rejected instead of
 * defaulting to Base: signing for the wrong chain id produces a signature that
 * looks valid and settles nowhere.
 */
export function chainIdForNetwork(network: string): number {
  const known = CHAIN_ID_MAP[network]
  if (known !== undefined) return known

  if (network.startsWith('eip155:')) {
    const raw = network.slice('eip155:'.length)
    if (/^\d+$/.test(raw)) {
      const id = Number(raw)
      if (Number.isSafeInteger(id) && id > 0) return id
    }
  }

  throw new PaymentError(
    `x402: cannot determine an EVM chain id for network ${JSON.stringify(network)}`,
  )
}

/** A private key holder that can sign EIP-712 payloads. Satisfied by viem accounts. */
export interface EvmSigningAccount {
  address: string
  signTypedData(parameters: {
    domain: { name: string; version: string; chainId: number; verifyingContract: `0x${string}` }
    types: typeof TRANSFER_WITH_AUTHORIZATION_TYPES
    primaryType: 'TransferWithAuthorization'
    message: {
      from: `0x${string}`
      to: `0x${string}`
      value: bigint
      validAfter: bigint
      validBefore: bigint
      nonce: `0x${string}`
    }
  }): Promise<`0x${string}`>
}

export interface EvmSignerOptions extends SignerLimits {
  network?: string
  /** Injectable for tests; defaults to `crypto.getRandomValues`. */
  randomBytes?: (length: number) => Uint8Array
  /** Injectable for tests; defaults to `Date.now`. */
  now?: () => number
}

/** Signs x402 payment envelopes with an EVM key. */
export class EvmX402Signer {
  private readonly account: EvmSigningAccount
  private readonly network: string
  private readonly limits: SignerLimits
  private readonly randomBytes: (length: number) => Uint8Array
  private readonly now: () => number

  private constructor(account: EvmSigningAccount, opts: EvmSignerOptions) {
    this.account = account
    this.network = opts.network ?? DEFAULT_EVM_NETWORK
    this.limits = opts.maxAmountBaseUnits === undefined
      ? {}
      : { maxAmountBaseUnits: opts.maxAmountBaseUnits }
    this.randomBytes = opts.randomBytes ?? defaultRandomBytes
    this.now = opts.now ?? (() => Date.now())
  }

  /**
   * Build a signer from a raw private key.
   *
   * `viem` is loaded here rather than imported at module scope so that installs
   * that only ever use an API key, or only Solana, do not need it.
   */
  static async fromPrivateKey(
    privateKey: string,
    opts: EvmSignerOptions = {},
  ): Promise<EvmX402Signer> {
    let privateKeyToAccount: (key: `0x${string}`) => EvmSigningAccount
    try {
      const viem = await import('viem/accounts')
      privateKeyToAccount = viem.privateKeyToAccount as unknown as typeof privateKeyToAccount
    } catch (err) {
      throw new PaymentError(
        'x402 EVM mode needs the optional peer dependency `viem`. ' +
          `Install it with: npm install viem (${String(err)})`,
      )
    }

    const normalised = privateKey.startsWith('0x') ? privateKey : `0x${privateKey}`
    return new EvmX402Signer(privateKeyToAccount(normalised as `0x${string}`), opts)
  }

  /** Build a signer from any object that can sign EIP-712 — a viem account, a KMS shim. */
  static fromAccount(account: EvmSigningAccount, opts: EvmSignerOptions = {}): EvmX402Signer {
    return new EvmX402Signer(account, opts)
  }

  get address(): string {
    return this.account.address
  }

  /** Read a 402 response and return the base64 `PAYMENT-SIGNATURE` value. */
  async signFrom402(resp: Response, resourceUrl: string): Promise<string> {
    const challenge = await parseChallenge(resp)
    const option = findOption(challenge, 'eip155:')
    if (!option) {
      throw new PaymentError(
        'x402: the server offered no EVM payment option — ' +
          'it may want a Solana key instead, or no options at all',
      )
    }

    const payment = resolvePayment(option, {
      challenge,
      expectedAsset: USDC_BASE_CONTRACT,
      defaultAsset: USDC_BASE_CONTRACT,
      defaultNetwork: this.network,
      assetCaseInsensitive: true,
      ...(this.limits.maxAmountBaseUnits === undefined
        ? {}
        : { maxAmountBaseUnits: this.limits.maxAmountBaseUnits }),
    })

    const chainId = chainIdForNetwork(payment.network)
    const nonce = `0x${toHex(this.randomBytes(32))}` as `0x${string}`
    const nowSeconds = BigInt(Math.floor(this.now() / 1000))
    // Backdated by 10 minutes so a small clock skew between us and the chain
    // cannot make the authorisation not-yet-valid at settlement time.
    const validAfter = nowSeconds - 600n
    const validBefore = nowSeconds + BigInt(payment.maxTimeoutSeconds)

    const signature = await this.account.signTypedData({
      domain: {
        name: USDC_NAME,
        version: USDC_VERSION,
        chainId,
        verifyingContract: payment.asset as `0x${string}`,
      },
      types: TRANSFER_WITH_AUTHORIZATION_TYPES,
      primaryType: 'TransferWithAuthorization',
      message: {
        from: this.account.address as `0x${string}`,
        to: payment.payTo as `0x${string}`,
        value: payment.amount,
        validAfter,
        validBefore,
        nonce,
      },
    })

    const envelope: PaymentEnvelope = {
      x402Version: 2,
      resource: {
        url: resourceUrl,
        description: payment.description,
        mimeType: 'application/json',
      },
      accepted: {
        scheme: 'exact',
        network: payment.network,
        amount: payment.amount.toString(),
        asset: payment.asset,
        payTo: payment.payTo,
        maxTimeoutSeconds: payment.maxTimeoutSeconds,
        extra:
          Object.keys(payment.extra).length > 0
            ? payment.extra
            : { name: USDC_NAME, version: USDC_VERSION },
      },
      payload: {
        signature,
        authorization: {
          from: this.account.address,
          to: payment.payTo,
          value: payment.amount.toString(),
          validAfter: validAfter.toString(),
          validBefore: validBefore.toString(),
          nonce,
        },
      },
      extensions: {},
    }

    return encodeEnvelope(envelope)
  }
}

function defaultRandomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length)
  crypto.getRandomValues(out)
  return out
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}
