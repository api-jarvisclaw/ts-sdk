/** Error types, mirroring the Python SDK's `jarvisclaw.errors` hierarchy. */

/** Base class for every error this SDK raises. Catch this to catch them all. */
export class JarvisClawError extends Error {
  constructor(message: string) {
    super(message)
    this.name = new.target.name
  }
}

/** An HTTP error from the API (4xx/5xx). */
export class APIError extends JarvisClawError {
  readonly statusCode: number
  readonly body: Record<string, unknown>

  constructor(statusCode: number, message: string, body?: Record<string, unknown>) {
    super(`[${statusCode}] ${message}`)
    this.statusCode = statusCode
    this.body = body ?? {}
  }
}

/** 401 — the API key or wallet credential was rejected. */
export class AuthenticationError extends APIError {}

/** 429 — too many requests. */
export class RateLimitError extends APIError {
  get retryAfter(): number | undefined {
    const v = this.body['retry_after']
    return typeof v === 'number' ? v : undefined
  }
}

/**
 * 402 — the request needs payment and could not be paid for.
 *
 * In API-key mode this means the account cannot cover the call. In x402 mode it
 * means signing or settlement failed, which is a different problem with the
 * same status code, so read `.message` rather than assuming "out of funds".
 */
export class InsufficientBalanceError extends APIError {}

/** x402 signing or settlement failed before any request was retried. */
export class PaymentError extends JarvisClawError {}

/**
 * The request never produced an HTTP response.
 *
 * Covers DNS failures, refused connections, dropped sockets and aborts. Without
 * this, transport failures would surface as raw `fetch` TypeErrors and callers
 * could not catch every failure mode through JarvisClawError.
 */
export class ConnectionError extends JarvisClawError {
  override readonly cause: unknown
  readonly isTimeout: boolean

  constructor(message: string, cause?: unknown, opts: { isTimeout?: boolean } = {}) {
    super(message)
    this.cause = cause
    this.isTimeout = opts.isTimeout ?? false
  }
}

/** The request exceeded the client timeout before a response arrived. */
export class TimeoutError extends ConnectionError {
  constructor(message: string, cause?: unknown) {
    super(message, cause, { isTimeout: true })
  }
}
