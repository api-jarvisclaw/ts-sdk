/**
 * `@jarvisclaw-ai/sdk` — TypeScript client for the JarvisClaw gateway.
 *
 * Two ways to authenticate, both through the same clients:
 *
 * ```ts
 * // API key
 * const chat = await ChatClient.create({ apiKey: 'sk-...' })
 *
 * // x402 wallet: unpaid request, 402, sign, replay — handled inside request()
 * const chat = await ChatClient.create({ privateKey: '0x...' })
 * ```
 */
export {
  BaseClient,
  DEFAULT_BASE_URL,
  DEFAULT_MAX_RETRIES,
  DEFAULT_TIMEOUT_MS,
  type ClientOptions,
  type PaymentApprover,
  type PaymentRequest,
  type RequestOptions,
} from './client.js'

export {
  AnonymousAuth,
  ApiKeyAuth,
  EvmX402Auth,
  SolanaX402Auth,
  detectKeyType,
  type AuthStrategy,
  type KeyType,
} from './auth.js'

export {
  APIError,
  AuthenticationError,
  ConnectionError,
  InsufficientBalanceError,
  JarvisClawError,
  PaymentDeclinedError,
  PaymentError,
  RateLimitError,
  TimeoutError,
} from './errors.js'

export {
  DEFAULT_MAX_AMOUNT_BASE_UNITS,
  encodeEnvelope,
  findOption,
  formatUsdc,
  parseAmount,
  parseChallenge,
  paymentOptions,
  resolvePayment,
} from './x402/challenge.js'

export {
  DEFAULT_EVM_NETWORK,
  EvmX402Signer,
  USDC_BASE_CONTRACT,
  USDC_NAME,
  USDC_VERSION,
  chainIdForNetwork,
  type EvmSignerOptions,
  type EvmSigningAccount,
} from './x402/evm.js'

export {
  DEFAULT_SOLANA_RPC,
  SOLANA_NETWORK,
  SolanaX402Signer,
  USDC_DECIMALS,
  USDC_MINT,
  solanaUsdcBalance,
  type SolanaSignerOptions,
} from './x402/solana.js'

export type {
  PaymentChallenge,
  PaymentEnvelope,
  PaymentOption,
  ResolvedPayment,
  SignerLimits,
} from './x402/types.js'
