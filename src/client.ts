/** The shared HTTP engine: retries, error mapping, and the x402 402→pay→retry loop. */
import {
  ApiKeyAuth,
  EvmX402Auth,
  SolanaX402Auth,
  detectKeyType,
  type AuthStrategy,
} from './auth.js'
import {
  APIError,
  AuthenticationError,
  ConnectionError,
  InsufficientBalanceError,
  JarvisClawError,
  RateLimitError,
  TimeoutError,
} from './errors.js'
import { USDC_BASE_CONTRACT } from './x402/evm.js'
import { solanaUsdcBalance } from './x402/solana.js'

export const DEFAULT_BASE_URL = 'https://api.jarvisclaw.ai'
export const DEFAULT_TIMEOUT_MS = 120_000
export const DEFAULT_MAX_RETRIES = 3

const RETRY_STATUS_CODES = new Set([429, 500, 502, 503, 504])

/** How to authenticate, and where. */
export interface ClientOptions {
  /** Gateway API key. Falls back to `JARVISCLAW_API_KEY`. */
  apiKey?: string
  /** Wallet private key for x402. Falls back to `JARVISCLAW_WALLET_KEY`. */
  privateKey?: string
  /** Force which chain `privateKey` belongs to instead of guessing. */
  network?: 'base' | 'solana'
  /** Gateway base URL. Falls back to `JARVISCLAW_BASE_URL`, then the public gateway. */
  baseUrl?: string
  timeoutMs?: number
  maxRetries?: number
  /**
   * Reject any single x402 charge above this, in USDC base units (6 decimals).
   * A client-side circuit breaker, not a budget. Defaults to 100 USDC.
   */
  maxAmountBaseUnits?: bigint
  /** Injectable for tests. */
  fetchImpl?: typeof fetch
}

/** One HTTP call. `body` is JSON-encoded so it can be replayed after a 402. */
export interface RequestOptions {
  method?: string
  query?: Record<string, string | number | boolean | undefined>
  body?: unknown
  headers?: Record<string, string>
  timeoutMs?: number
}

/**
 * Base client. Concrete capability clients extend this.
 *
 * Construction is async because loading a chain library and deriving an address
 * from a private key both are; use `BaseClient.create` rather than `new`.
 */
export class BaseClient {
  readonly baseUrl: string
  protected readonly auth: AuthStrategy
  protected readonly timeoutMs: number
  protected readonly maxRetries: number
  protected readonly fetchImpl: typeof fetch

  /**
   * Prefer `create()`. This is public only because `create()` constructs `this`
   * polymorphically, which TypeScript cannot express against a protected
   * constructor — a subclass could not inherit `create` at all otherwise.
   */
  constructor(auth: AuthStrategy, resolved: {
    baseUrl: string
    timeoutMs: number
    maxRetries: number
    fetchImpl: typeof fetch
  }) {
    this.auth = auth
    this.baseUrl = resolved.baseUrl
    this.timeoutMs = resolved.timeoutMs
    this.maxRetries = resolved.maxRetries
    this.fetchImpl = resolved.fetchImpl
  }

  /** Build a client, resolving credentials from options then the environment. */
  static async create<T extends BaseClient>(
    this: new (auth: AuthStrategy, resolved: {
      baseUrl: string
      timeoutMs: number
      maxRetries: number
      fetchImpl: typeof fetch
    }) => T,
    opts: ClientOptions = {},
  ): Promise<T> {
    const baseUrl = (opts.baseUrl ?? env('JARVISCLAW_BASE_URL') ?? DEFAULT_BASE_URL).replace(
      /\/+$/,
      '',
    )
    const auth = await resolveAuth(opts, baseUrl)
    return new this(auth, {
      baseUrl,
      timeoutMs: opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
      maxRetries: opts.maxRetries ?? DEFAULT_MAX_RETRIES,
      fetchImpl: opts.fetchImpl ?? fetch,
    })
  }

  /** The wallet address, or undefined in API-key mode. */
  get address(): string | undefined {
    return this.auth.address
  }

  /** Whether this client can pay for calls itself. */
  get canPay(): boolean {
    return this.auth.supportsX402
  }

  // ─── Requests ─────────────────────────────────────────────────────────────

  protected async get<T>(path: string, opts: RequestOptions = {}): Promise<T> {
    return this.requestJson<T>(path, { ...opts, method: 'GET' })
  }

  protected async post<T>(path: string, opts: RequestOptions = {}): Promise<T> {
    return this.requestJson<T>(path, { ...opts, method: 'POST' })
  }

  protected async put<T>(path: string, opts: RequestOptions = {}): Promise<T> {
    return this.requestJson<T>(path, { ...opts, method: 'PUT' })
  }

  protected async del<T>(path: string, opts: RequestOptions = {}): Promise<T> {
    return this.requestJson<T>(path, { ...opts, method: 'DELETE' })
  }

  protected async requestJson<T>(path: string, opts: RequestOptions = {}): Promise<T> {
    const resp = await this.request(path, opts)
    return (await resp.json()) as T
  }

  /**
   * Issue a request, paying and retrying once if the gateway answers 402.
   *
   * The returned Response has an unread body. Errors are already mapped to the
   * SDK's exception types, so a returned response is always 2xx/3xx.
   */
  async request(path: string, opts: RequestOptions = {}): Promise<Response> {
    const url = this.buildUrl(path, opts.query)
    const method = (opts.method ?? 'GET').toUpperCase()
    const encodedBody = opts.body === undefined ? undefined : JSON.stringify(opts.body)

    let lastRetryable: Response | undefined

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        // Exponential backoff with jitter, capped so a long outage does not
        // stall a caller for minutes on the last attempt.
        await sleep(Math.min(2 ** attempt * 1000 + Math.random() * 1000, 30_000))
      }

      let resp = await this.send(url, method, encodedBody, opts)

      if (resp.status === 402) {
        resp = await this.payAndRetry(resp, url, method, encodedBody, opts)
        // A paid retry that still failed is final: re-entering the loop would
        // sign and pay a second time for a request the server already refused.
        if (resp.status >= 400) {
          const body = await safeJson(resp)
          const message = extractMessage(body, `Payment rejected (status ${resp.status})`)
          if (resp.status === 402) throw new InsufficientBalanceError(402, message, body)
          throw new APIError(resp.status, message, body)
        }
        return resp
      }

      if (RETRY_STATUS_CODES.has(resp.status) && attempt < this.maxRetries) {
        lastRetryable = resp
        continue
      }

      if (resp.status >= 400) throw await toError(resp)
      return resp
    }

    if (lastRetryable) {
      const body = await safeJson(lastRetryable)
      throw new APIError(
        lastRetryable.status,
        extractMessage(body, `Request failed after ${this.maxRetries} retries`),
        body,
      )
    }
    throw new APIError(500, `Request failed after ${this.maxRetries} retries`, {})
  }

  /** Sign the 402 challenge and replay the request with the payment attached. */
  private async payAndRetry(
    challenge: Response,
    url: string,
    method: string,
    encodedBody: string | undefined,
    opts: RequestOptions,
  ): Promise<Response> {
    if (!this.auth.supportsX402) {
      const body = await safeJson(challenge)
      throw new InsufficientBalanceError(
        402,
        extractMessage(
          body,
          'Payment required, and this client has no wallet to pay with ' +
            '(construct it with privateKey to enable x402)',
        ),
        body,
      )
    }

    const signature = await this.auth.signPayment(challenge, url)
    if (!signature) {
      const body = await safeJson(challenge)
      throw new InsufficientBalanceError(402, 'x402: payment signing produced nothing', body)
    }

    return this.send(url, method, encodedBody, opts, { 'PAYMENT-SIGNATURE': signature })
  }

  private async send(
    url: string,
    method: string,
    encodedBody: string | undefined,
    opts: RequestOptions,
    extraHeaders: Record<string, string> = {},
  ): Promise<Response> {
    const headers = new Headers(opts.headers ?? {})
    this.auth.prepareHeaders(headers)
    for (const [key, value] of Object.entries(extraHeaders)) headers.set(key, value)
    if (encodedBody !== undefined && !headers.has('content-type')) {
      headers.set('content-type', 'application/json')
    }

    const timeoutMs = opts.timeoutMs ?? this.timeoutMs
    try {
      return await this.fetchImpl(url, {
        method,
        headers,
        ...(encodedBody === undefined ? {} : { body: encodedBody }),
        signal: AbortSignal.timeout(timeoutMs),
      })
    } catch (err) {
      if (err instanceof JarvisClawError) throw err
      if (isTimeout(err)) {
        throw new TimeoutError(`request to ${url} timed out after ${timeoutMs}ms`, err)
      }
      throw new ConnectionError(`request to ${url} failed: ${String(err)}`, err)
    }
  }

  private buildUrl(path: string, query?: RequestOptions['query']): string {
    const url = new URL(this.baseUrl + path)
    for (const [key, value] of Object.entries(query ?? {})) {
      if (value !== undefined) url.searchParams.set(key, String(value))
    }
    return url.toString()
  }

  // ─── Balance ──────────────────────────────────────────────────────────────

  /**
   * Spendable balance in USD.
   *
   * In wallet mode this reads the chain directly — the wallet's own USDC is what
   * x402 settles against. In API-key mode it reads the gateway's wallet endpoint,
   * which reports the HD deposit wallet's on-chain balance. Note that the account
   * quota column is deliberately not part of this: x402 settles against the
   * wallet and never debits quota, so adding quota in would overstate what is
   * actually spendable by the lifetime deposit total.
   */
  async getBalanceUsd(): Promise<number> {
    const address = this.auth.address
    if (address) {
      return this.auth instanceof SolanaX402Auth
        ? solanaUsdcBalance(address, { fetchImpl: this.fetchImpl })
        : this.baseUsdcBalance(address)
    }

    const data = await this.get<{ balance_usd?: string | number; error?: unknown }>(
      '/v1/wallet/balance',
    )
    const raw = data.balance_usd
    const parsed = typeof raw === 'number' ? raw : Number.parseFloat(String(raw ?? ''))
    return Number.isFinite(parsed) ? parsed : 0
  }

  /** USDC balance on Base, via `balanceOf` on the token contract. */
  private async baseUsdcBalance(address: string): Promise<number> {
    const hex = address.toLowerCase().startsWith('0x') ? address.slice(2) : address
    if (!/^[0-9a-fA-F]{40}$/.test(hex)) {
      throw new APIError(400, `Cannot read a Base balance for non-EVM address ${address}`, {})
    }
    // balanceOf(address): the 4-byte selector plus the address right-aligned in
    // a 32-byte word.
    const callData = `0x70a08231${hex.toLowerCase().padStart(64, '0')}`

    const resp = await this.fetchImpl('https://mainnet.base.org', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'eth_call',
        params: [{ to: USDC_BASE_CONTRACT, data: callData }, 'latest'],
      }),
      signal: AbortSignal.timeout(10_000),
    })
    const body = (await resp.json()) as { result?: string; error?: unknown }
    if (body.error) {
      throw new APIError(502, `Base RPC error: ${JSON.stringify(body.error)}`, {})
    }
    // USDC has 6 decimals. Divided as a Number after the BigInt parse, because a
    // realistic balance is far inside Number's exact-integer range.
    return Number(BigInt(body.result ?? '0x0')) / 1_000_000
  }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

async function resolveAuth(opts: ClientOptions, baseUrl: string): Promise<AuthStrategy> {
  const limits = opts.maxAmountBaseUnits === undefined
    ? {}
    : { maxAmountBaseUnits: opts.maxAmountBaseUnits }

  const apiKey = opts.apiKey ?? env('JARVISCLAW_API_KEY')
  const privateKey = opts.privateKey ?? env('JARVISCLAW_WALLET_KEY')

  // An explicitly passed private key wins over an API key left in the
  // environment, and vice versa — an explicit argument always beats an env var.
  if (opts.apiKey) return new ApiKeyAuth(opts.apiKey)
  if (opts.privateKey) return walletAuth(opts.privateKey, opts, baseUrl, limits)
  if (apiKey) return new ApiKeyAuth(apiKey)
  if (privateKey) return walletAuth(privateKey, opts, baseUrl, limits)

  throw new JarvisClawError(
    'No credential. Pass apiKey or privateKey, or set JARVISCLAW_API_KEY ' +
      'or JARVISCLAW_WALLET_KEY in the environment.',
  )
}

async function walletAuth(
  privateKey: string,
  opts: ClientOptions,
  baseUrl: string,
  limits: { maxAmountBaseUnits?: bigint },
): Promise<AuthStrategy> {
  const keyType = opts.network === 'solana'
    ? 'solana'
    : opts.network === 'base'
      ? 'evm'
      : detectKeyType(privateKey)

  if (keyType === 'solana') {
    return SolanaX402Auth.fromPrivateKey(privateKey, {
      baseUrl,
      ...limits,
      ...(opts.fetchImpl ? { fetchImpl: opts.fetchImpl } : {}),
    })
  }
  return EvmX402Auth.fromPrivateKey(privateKey, limits)
}

function env(name: string): string | undefined {
  const value = globalThis.process?.env?.[name]
  return value && value.length > 0 ? value : undefined
}

async function toError(resp: Response): Promise<APIError> {
  const body = await safeJson(resp)
  if (resp.status === 401) {
    return new AuthenticationError(401, extractMessage(body, 'Unauthorized'), body)
  }
  if (resp.status === 429) {
    return new RateLimitError(429, extractMessage(body, 'Rate limit exceeded'), body)
  }
  return new APIError(resp.status, extractMessage(body, resp.statusText || 'Unknown error'), body)
}

async function safeJson(resp: Response): Promise<Record<string, unknown>> {
  try {
    const parsed = await resp.json()
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : {}
  } catch {
    return {}
  }
}

/** Pull a message out of either the OpenAI-style or the flat error shape. */
function extractMessage(body: Record<string, unknown>, fallback: string): string {
  const nested = body['error']
  if (typeof nested === 'object' && nested !== null) {
    const message = (nested as Record<string, unknown>)['message']
    if (typeof message === 'string' && message) return message
  }
  if (typeof nested === 'string' && nested) return nested
  const flat = body['message']
  if (typeof flat === 'string' && flat) return flat
  return fallback
}

function isTimeout(err: unknown): boolean {
  return (
    err instanceof DOMException &&
    (err.name === 'TimeoutError' || err.name === 'AbortError')
  )
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms))
}
