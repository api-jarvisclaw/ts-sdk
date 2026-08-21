/** The shared HTTP engine: retries, error mapping, and the x402 402→pay→retry loop. */
import {
  AnonymousAuth,
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
  PaymentDeclinedError,
  PaymentError,
  RateLimitError,
  TimeoutError,
} from './errors.js'
import { parseChallenge, paymentOptions } from './x402/challenge.js'
import { USDC_BASE_CONTRACT } from './x402/evm.js'
import { solanaUsdcBalance } from './x402/solana.js'

export const DEFAULT_BASE_URL = 'https://api.jarvisclaw.ai'
export const DEFAULT_TIMEOUT_MS = 120_000
export const DEFAULT_MAX_RETRIES = 3

const RETRY_STATUS_CODES = new Set([429, 500, 502, 503, 504])

/** What an approval hook is told about a charge before it is signed. */
export interface PaymentRequest {
  /** The quoted charge in USD. x402 prepays this exact amount — see approvePayment. */
  amountUsd: number
  /** Raw quote in USDC base units, for a caller that needs it undivided. */
  amountBaseUnits: bigint
  /** The endpoint being paid for. */
  resourceUrl: string
  /** The chain the quote names, e.g. "eip155:8453". */
  network: string
  /** The gateway's own description of the resource, when it sent one. */
  description?: string
}

/**
 * Decide one charge. Return false (or a reason) to refuse.
 *
 * May be async, so a caller can prompt a human.
 */
export type PaymentApprover = (
  req: PaymentRequest,
) => boolean | { approved: boolean; reason?: string } | Promise<boolean | { approved: boolean; reason?: string }>

/** USDC has 6 decimals on both chains the SDK supports. */
const USDC_DECIMALS = 1_000_000

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
  /**
   * Called before signing any x402 payment. Return false to refuse the charge.
   *
   * This is the only place that sees EVERY charge. A caller that gates spending at
   * its own call sites gates only the calls it remembered to wrap: the CLI's
   * per-call and per-session limits governed its `call_api` tool and nothing else,
   * so six LLM turns quoted at $0.21 each went through untouched while the user
   * held a $0.05 per-call limit and a $1 session limit. The most expensive
   * component was the one outside the gate.
   *
   * Receives the quoted amount, which is the amount that will actually be charged:
   * x402 prepays a fixed authorisation, so there is no later reconciliation to a
   * smaller number.
   *
   * Refusal raises PaymentDeclinedError rather than returning an unpaid response,
   * so a declined charge cannot be mistaken for a failed request.
   */
  approvePayment?: PaymentApprover
  /**
   * Proceed with no credential instead of throwing when none is found.
   *
   * Sends no auth header at all, which is what reaches the gateway's free tier and
   * public catalogue — a placeholder key would be rejected with 401. Paid endpoints
   * still answer 402. Use this for read-only browsing and free-model calls before a
   * user has logged in.
   */
  allowAnonymous?: boolean
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
  protected readonly approvePayment?: PaymentApprover

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
    approvePayment?: PaymentApprover
  }) {
    this.auth = auth
    this.baseUrl = resolved.baseUrl
    this.timeoutMs = resolved.timeoutMs
    this.maxRetries = resolved.maxRetries
    this.fetchImpl = resolved.fetchImpl
    if (resolved.approvePayment) this.approvePayment = resolved.approvePayment
  }

  /** Build a client, resolving credentials from options then the environment. */
  static async create<T extends BaseClient>(
    this: new (auth: AuthStrategy, resolved: {
      baseUrl: string
      timeoutMs: number
      maxRetries: number
      fetchImpl: typeof fetch
      approvePayment?: PaymentApprover
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
      ...(opts.approvePayment ? { approvePayment: opts.approvePayment } : {}),
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

  /** True when no credential is attached: free endpoints only. */
  get isAnonymous(): boolean {
    return this.auth instanceof AnonymousAuth
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

    // Gate BEFORE signing. A signature is an irrevocable authorisation for a fixed
    // amount, so this is the last moment a charge can still be refused.
    //
    // The clone is required: parseChallenge consumes the body, and the signer needs
    // it intact afterwards. Reading the original here would leave the signer with an
    // empty body and turn an approved payment into a signing failure.
    if (this.approvePayment) {
      await this.gatePayment(challenge.clone(), url)
    }

    const signature = await this.auth.signPayment(challenge, url)
    if (!signature) {
      const body = await safeJson(challenge)
      throw new InsufficientBalanceError(402, 'x402: payment signing produced nothing', body)
    }

    return this.send(url, method, encodedBody, opts, { 'PAYMENT-SIGNATURE': signature })
  }

  /**
   * Run the caller's approval hook against a 402 quote, throwing if it refuses.
   *
   * An unreadable quote is refused rather than waved through. The hook exists to
   * bound spending, and "we could not tell how much this costs" is not a reason to
   * pay it — it is the strongest reason not to.
   */
  private async gatePayment(challengeCopy: Response, url: string): Promise<void> {
    let req: PaymentRequest
    try {
      const parsed = await parseChallenge(challengeCopy)
      const option = paymentOptions(parsed)[0]
      const raw = option?.amount ?? option?.maxAmountRequired
      if (raw === undefined || raw === null || raw === '') {
        throw new PaymentError('x402: challenge named no amount')
      }
      const amountBaseUnits = BigInt(String(raw))
      req = {
        amountUsd: Number(amountBaseUnits) / USDC_DECIMALS,
        amountBaseUnits,
        resourceUrl: url,
        network: option?.network ?? '',
        ...(parsed.resource?.description ? { description: parsed.resource.description } : {}),
      }
    } catch (err) {
      throw new PaymentDeclinedError({
        amountUsd: 0,
        resourceUrl: url,
        reason: `the quoted amount could not be read (${String(err)}), so it was not paid`,
      })
    }

    const verdict = await this.approvePayment!(req)
    const approved = typeof verdict === 'boolean' ? verdict : verdict.approved
    if (!approved) {
      throw new PaymentDeclinedError({
        amountUsd: req.amountUsd,
        resourceUrl: url,
        reason: typeof verdict === 'boolean' ? '' : (verdict.reason ?? ''),
      })
    }
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
    if (this.isAnonymous) {
      // There is no account and no wallet to read. Returning 0 here would be
      // indistinguishable from an empty wallet and would send someone to top up
      // an account they do not have.
      throw new JarvisClawError(
        'No credential, so there is no balance to read. Add an API key or a wallet ' +
          'key to see one; free models need neither.',
      )
    }
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
  if (opts.allowAnonymous) return new AnonymousAuth()

  throw new JarvisClawError(
    'No credential. Pass apiKey or privateKey, or set JARVISCLAW_API_KEY ' +
      'or JARVISCLAW_WALLET_KEY in the environment. Pass allowAnonymous to ' +
      'browse and use free models without one.',
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
