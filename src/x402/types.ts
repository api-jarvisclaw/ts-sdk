/** Shapes of the x402 402-challenge and the payment envelope we send back. */

/** One payment option offered by the server inside a 402 challenge. */
export interface PaymentOption {
  scheme?: string
  network?: string
  /** Amount in the asset's smallest unit. v2 name. */
  amount?: string | number
  /** v1 name for the same field. */
  maxAmountRequired?: string | number
  asset?: string
  payTo?: string
  maxTimeoutSeconds?: number
  /** Scheme-specific extras: EIP-712 domain fields on EVM, `feePayer` on Solana. */
  extra?: Record<string, unknown>
}

/** The body (or base64 header) of a 402 response. */
export interface PaymentChallenge {
  x402Version?: number
  /** x402 v2 name. */
  accepts?: PaymentOption[]
  /** x402 v1 name. */
  payments?: PaymentOption[]
  resource?: { url?: string; description?: string; mimeType?: string }
  [key: string]: unknown
}

/** The envelope that gets base64-encoded into the `PAYMENT-SIGNATURE` header. */
export interface PaymentEnvelope {
  x402Version: 2
  resource: { url: string; description: string; mimeType: string }
  accepted: {
    scheme: string
    network: string
    amount: string
    asset: string
    payTo: string
    maxTimeoutSeconds: number
    extra: Record<string, unknown>
  }
  payload: Record<string, unknown>
  extensions: Record<string, unknown>
}

/** A payment option after validation, with every field we depend on present. */
export interface ResolvedPayment {
  payTo: string
  /** Smallest unit of the asset. BigInt because USDC amounts are uint256 on-chain. */
  amount: bigint
  network: string
  asset: string
  maxTimeoutSeconds: number
  extra: Record<string, unknown>
  description: string
}

/** What a signer needs to know about the caller's payment policy. */
export interface SignerLimits {
  /**
   * Reject any challenge above this, in the asset's smallest unit.
   *
   * This is a client-side circuit breaker against a compromised or misconfigured
   * server asking for far more than a call is worth — it is not a spending
   * budget. Defaults to 100 USDC (100_000_000 base units).
   */
  maxAmountBaseUnits?: bigint
}
