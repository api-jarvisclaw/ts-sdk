import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import {
  APIError,
  AuthenticationError,
  BaseClient,
  ConnectionError,
  InsufficientBalanceError,
  InsufficientBalanceError as PaymentRequired,
  JarvisClawError,
  RateLimitError,
  detectKeyType,
} from '../src/index.js'
import reference from './fixtures/reference.json' with { type: 'json' }

/** One recorded outgoing request. */
interface Recorded {
  url: string
  method: string
  headers: Record<string, string>
  body: string | undefined
}

/** A fetch stub that answers from a queue and records what it was asked. */
function stubFetch(responses: Array<Response | (() => Response | Promise<Response>)>) {
  const calls: Recorded[] = []
  const queue = [...responses]
  const impl = vi.fn(async (url: unknown, init?: RequestInit) => {
    calls.push({
      url: String(url),
      method: init?.method ?? 'GET',
      headers: Object.fromEntries(new Headers(init?.headers).entries()),
      body: typeof init?.body === 'string' ? init.body : undefined,
    })
    const next = queue.shift()
    if (!next) throw new Error(`stubFetch: unexpected call #${calls.length} to ${String(url)}`)
    return typeof next === 'function' ? await next() : next
  })
  return { impl: impl as unknown as typeof fetch, calls }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

/** Await a rejection and get the error back typed, without `as any` at each site. */
async function rejection<T extends Error = APIError>(promise: Promise<unknown>): Promise<T> {
  try {
    await promise
    throw new Error('expected the promise to reject, but it resolved')
  } catch (err) {
    return err as T
  }
}

/** BaseClient is abstract-by-convention; this exposes the protected verbs. */
class TestClient extends BaseClient {
  callGet<T>(path: string, opts = {}) {
    return this.get<T>(path, opts)
  }
  callPost<T>(path: string, body: unknown) {
    return this.post<T>(path, { body })
  }
}

const CHALLENGE = reference.challengeEvm

beforeEach(() => {
  // The environment must not leak a real credential into these tests, or a
  // "no credential" case would silently pass by using someone's key.
  delete process.env['JARVISCLAW_API_KEY']
  delete process.env['JARVISCLAW_WALLET_KEY']
  delete process.env['JARVISCLAW_BASE_URL']
  vi.useFakeTimers({ shouldAdvanceTime: true })
})

afterEach(() => {
  vi.useRealTimers()
})

describe('credential resolution', () => {
  it('uses the API key as a bearer token', async () => {
    const { impl, calls } = stubFetch([json({ ok: true })])
    const client = await TestClient.create({ apiKey: 'sk-test', fetchImpl: impl })
    await client.callGet('/v1/models')
    expect(calls[0]?.headers['authorization']).toBe('Bearer sk-test')
    expect(client.canPay).toBe(false)
    expect(client.address).toBeUndefined()
  })

  it('sends no credential header in wallet mode until challenged', async () => {
    const { impl, calls } = stubFetch([json({ ok: true })])
    const client = await TestClient.create({
      privateKey: reference.evmTestKey,
      fetchImpl: impl,
    })
    await client.callGet('/v1/models')
    expect(calls[0]?.headers['authorization']).toBeUndefined()
    expect(client.canPay).toBe(true)
    expect(client.address).toBe(reference.evm.address)
  })

  it('reads credentials from the environment when none are passed', async () => {
    process.env['JARVISCLAW_API_KEY'] = 'sk-from-env'
    const { impl, calls } = stubFetch([json({ ok: true })])
    const client = await TestClient.create({ fetchImpl: impl })
    await client.callGet('/v1/models')
    expect(calls[0]?.headers['authorization']).toBe('Bearer sk-from-env')
  })

  it('lets an explicit private key win over an API key in the environment', async () => {
    // Otherwise a stale JARVISCLAW_API_KEY in a shell would silently override the
    // wallet the caller just constructed the client with.
    process.env['JARVISCLAW_API_KEY'] = 'sk-from-env'
    const { impl } = stubFetch([json({ ok: true })])
    const client = await TestClient.create({
      privateKey: reference.evmTestKey,
      fetchImpl: impl,
    })
    expect(client.canPay).toBe(true)
    expect(client.address).toBe(reference.evm.address)
  })

  it('refuses to construct with no credential at all', async () => {
    await expect(TestClient.create({ fetchImpl: stubFetch([]).impl })).rejects.toThrow(
      JarvisClawError,
    )
    await expect(TestClient.create({ fetchImpl: stubFetch([]).impl })).rejects.toThrow(
      /No credential/,
    )
  })

  it('strips a trailing slash from the base URL', async () => {
    const { impl, calls } = stubFetch([json({ ok: true })])
    const client = await TestClient.create({
      apiKey: 'sk-test',
      baseUrl: 'https://gateway.example/',
      fetchImpl: impl,
    })
    await client.callGet('/v1/models')
    expect(calls[0]?.url).toBe('https://gateway.example/v1/models')
  })
})

describe('the x402 402 → pay → retry loop', () => {
  it('signs the challenge and replays the request with the payment attached', async () => {
    const { impl, calls } = stubFetch([json(CHALLENGE, 402), json({ id: 'chat-1' })])
    const client = await TestClient.create({
      privateKey: reference.evmTestKey,
      fetchImpl: impl,
    })

    const result = await client.callPost<{ id: string }>('/v1/chat/completions', {
      model: 'gpt-5',
    })
    expect(result.id).toBe('chat-1')
    expect(calls).toHaveLength(2)

    // The retry must be the same request plus the payment, or the caller pays for
    // one thing and receives another.
    expect(calls[1]?.method).toBe('POST')
    expect(calls[1]?.url).toBe(calls[0]?.url)
    expect(calls[1]?.body).toBe(calls[0]?.body)
    expect(calls[0]?.headers['payment-signature']).toBeUndefined()

    const header = calls[1]?.headers['payment-signature']
    expect(header).toBeTruthy()
    const envelope = JSON.parse(Buffer.from(header!, 'base64').toString())
    expect(envelope.accepted.amount).toBe('12345')
    expect(envelope.resource.url).toBe(calls[0]?.url)
  })

  it('does not pay twice when the paid retry is itself refused', async () => {
    // Re-entering the retry loop would sign a second authorization for a request
    // the server has already rejected — that is real money spent on nothing.
    const { impl, calls } = stubFetch([
      json(CHALLENGE, 402),
      json({ error: { message: 'settlement failed on chain' } }, 402),
    ])
    const client = await TestClient.create({
      privateKey: reference.evmTestKey,
      fetchImpl: impl,
    })

    await expect(client.callPost('/v1/chat/completions', { model: 'gpt-5' })).rejects.toThrow(
      /settlement failed on chain/,
    )
    expect(calls).toHaveLength(2)
  })

  it('surfaces the server message when a paid retry fails with a non-402', async () => {
    const { impl } = stubFetch([
      json(CHALLENGE, 402),
      json({ error: { message: 'model not found' } }, 404),
    ])
    const client = await TestClient.create({
      privateKey: reference.evmTestKey,
      fetchImpl: impl,
    })
    const err = await rejection(client.callPost('/v1/chat/completions', {}))
    expect(err).toBeInstanceOf(APIError)
    expect(err).not.toBeInstanceOf(InsufficientBalanceError)
    expect(err.statusCode).toBe(404)
    expect(err.message).toContain('model not found')
  })

  it('explains that an API-key client cannot pay a 402', async () => {
    const { impl, calls } = stubFetch([json(CHALLENGE, 402)])
    const client = await TestClient.create({ apiKey: 'sk-test', fetchImpl: impl })

    const err = await rejection(client.callPost('/v1/chat/completions', {}))
    expect(err).toBeInstanceOf(PaymentRequired)
    expect(err.message).toMatch(/no wallet to pay with/)
    // It must not silently retry unpaid and look like a different failure.
    expect(calls).toHaveLength(1)
  })

  it('propagates a signing refusal rather than retrying unpaid', async () => {
    const overpriced = {
      accepts: [{ ...CHALLENGE.accepts[0], amount: '999999999999' }],
    }
    const { impl, calls } = stubFetch([json(overpriced, 402)])
    const client = await TestClient.create({
      privateKey: reference.evmTestKey,
      fetchImpl: impl,
    })

    await expect(client.callPost('/v1/chat/completions', {})).rejects.toThrow(
      /exceeds the client safety cap/,
    )
    expect(calls).toHaveLength(1)
  })

  it('honours a client-level spending cap on the wallet', async () => {
    const { impl } = stubFetch([json(CHALLENGE, 402)])
    const client = await TestClient.create({
      privateKey: reference.evmTestKey,
      maxAmountBaseUnits: 1000n,
      fetchImpl: impl,
    })
    await expect(client.callPost('/v1/chat/completions', {})).rejects.toThrow(
      /exceeds the client safety cap of 1000/,
    )
  })
})

describe('retries and error mapping', () => {
  it('retries a 503 and returns the eventual success', async () => {
    const { impl, calls } = stubFetch([json({}, 503), json({}, 503), json({ ok: true })])
    const client = await TestClient.create({ apiKey: 'sk-test', fetchImpl: impl })

    const promise = client.callGet<{ ok: boolean }>('/v1/models')
    await vi.advanceTimersByTimeAsync(60_000)
    expect(await promise).toEqual({ ok: true })
    expect(calls).toHaveLength(3)
  })

  it('gives up after maxRetries and reports the last status', async () => {
    const { impl, calls } = stubFetch([
      json({ message: 'upstream down' }, 502),
      json({ message: 'upstream down' }, 502),
    ])
    const client = await TestClient.create({
      apiKey: 'sk-test',
      maxRetries: 1,
      fetchImpl: impl,
    })

    const promise = rejection(client.callGet('/v1/models'))
    await vi.advanceTimersByTimeAsync(60_000)
    const err = await promise
    expect(err).toBeInstanceOf(APIError)
    expect(err.statusCode).toBe(502)
    expect(calls).toHaveLength(2)
  })

  it('does not retry a 400', async () => {
    const { impl, calls } = stubFetch([json({ error: { message: 'bad model' } }, 400)])
    const client = await TestClient.create({ apiKey: 'sk-test', fetchImpl: impl })
    await expect(client.callGet('/v1/models')).rejects.toThrow(/bad model/)
    expect(calls).toHaveLength(1)
  })

  it('maps 401 to AuthenticationError', async () => {
    const { impl } = stubFetch([json({ error: { message: 'invalid key' } }, 401)])
    const client = await TestClient.create({ apiKey: 'sk-bad', fetchImpl: impl })
    const err = await rejection(client.callGet('/v1/models'))
    expect(err).toBeInstanceOf(AuthenticationError)
    expect(err.message).toContain('invalid key')
  })

  it('maps 429 to RateLimitError and exposes retryAfter', async () => {
    const { impl } = stubFetch([
      json({ message: 'slow down', retry_after: 30 }, 429),
      json({ message: 'slow down', retry_after: 30 }, 429),
    ])
    const client = await TestClient.create({
      apiKey: 'sk-test',
      maxRetries: 1,
      fetchImpl: impl,
    })
    const promise = rejection(client.callGet('/v1/models'))
    await vi.advanceTimersByTimeAsync(60_000)
    const err = await promise
    expect(err).toBeInstanceOf(APIError)
    expect(err.statusCode).toBe(429)
  })

  it('reads a flat error message as well as the OpenAI-nested one', async () => {
    const { impl } = stubFetch([json({ message: 'flat style' }, 400)])
    const client = await TestClient.create({ apiKey: 'sk-test', fetchImpl: impl })
    await expect(client.callGet('/v1/models')).rejects.toThrow(/flat style/)
  })

  it('falls back to the status text when the body carries no message', async () => {
    const { impl } = stubFetch([new Response('<html>oops</html>', { status: 500 })])
    const client = await TestClient.create({
      apiKey: 'sk-test',
      maxRetries: 0,
      fetchImpl: impl,
    })
    const err = await rejection(client.callGet('/v1/models'))
    expect(err).toBeInstanceOf(APIError)
    expect(err.statusCode).toBe(500)
  })

  it('wraps a transport failure as ConnectionError, not a raw fetch TypeError', async () => {
    // Callers catch JarvisClawError; a leaked TypeError would escape that.
    const impl = vi.fn(async () => {
      throw new TypeError('fetch failed')
    }) as unknown as typeof fetch
    const client = await TestClient.create({
      apiKey: 'sk-test',
      maxRetries: 0,
      fetchImpl: impl,
    })
    const err = await rejection(client.callGet('/v1/models'))
    expect(err).toBeInstanceOf(ConnectionError)
    expect(err).toBeInstanceOf(JarvisClawError)
  })
})

describe('requests', () => {
  it('appends query parameters and omits undefined ones', async () => {
    const { impl, calls } = stubFetch([json({ ok: true })])
    const client = await TestClient.create({ apiKey: 'sk-test', fetchImpl: impl })
    await client.callGet('/v1/wallet/history', {
      query: { page: 2, page_size: 20, cursor: undefined },
    })
    const url = new URL(calls[0]!.url)
    expect(url.searchParams.get('page')).toBe('2')
    expect(url.searchParams.get('page_size')).toBe('20')
    expect(url.searchParams.has('cursor')).toBe(false)
  })

  it('sets a JSON content type when there is a body', async () => {
    const { impl, calls } = stubFetch([json({ ok: true })])
    const client = await TestClient.create({ apiKey: 'sk-test', fetchImpl: impl })
    await client.callPost('/v1/chat/completions', { model: 'gpt-5' })
    expect(calls[0]?.headers['content-type']).toBe('application/json')
    expect(calls[0]?.body).toBe('{"model":"gpt-5"}')
  })

  it('sends no body or content type on a GET', async () => {
    const { impl, calls } = stubFetch([json({ ok: true })])
    const client = await TestClient.create({ apiKey: 'sk-test', fetchImpl: impl })
    await client.callGet('/v1/models')
    expect(calls[0]?.body).toBeUndefined()
    expect(calls[0]?.headers['content-type']).toBeUndefined()
  })
})

describe('balance', () => {
  it('reads the chain in EVM wallet mode, not the gateway ledger', async () => {
    // x402 settles against the wallet, so the wallet's own USDC is what is
    // spendable — the gateway's quota column is not.
    const { impl, calls } = stubFetch([
      json({ jsonrpc: '2.0', id: 1, result: '0x' + (2_500_000).toString(16) }),
    ])
    const client = await TestClient.create({
      privateKey: reference.evmTestKey,
      fetchImpl: impl,
    })
    expect(await client.getBalanceUsd()).toBeCloseTo(2.5)
    expect(calls[0]?.url).toBe('https://mainnet.base.org')

    const rpc = JSON.parse(calls[0]!.body!)
    expect(rpc.method).toBe('eth_call')
    // balanceOf selector plus the address right-aligned in a 32-byte word.
    expect(rpc.params[0].data).toBe(
      '0x70a08231' + reference.evm.address.slice(2).toLowerCase().padStart(64, '0'),
    )
  })

  it('reports zero for an empty wallet rather than failing', async () => {
    const { impl } = stubFetch([json({ result: '0x0' })])
    const client = await TestClient.create({
      privateKey: reference.evmTestKey,
      fetchImpl: impl,
    })
    expect(await client.getBalanceUsd()).toBe(0)
  })

  it('raises on an RPC error instead of reporting zero', async () => {
    const { impl } = stubFetch([json({ error: { code: -32000, message: 'rate limited' } })])
    const client = await TestClient.create({
      privateKey: reference.evmTestKey,
      fetchImpl: impl,
    })
    await expect(client.getBalanceUsd()).rejects.toThrow(/Base RPC error/)
  })

  it('reads the gateway wallet endpoint in API-key mode', async () => {
    const { impl, calls } = stubFetch([json({ balance_usd: '12.345678' })])
    const client = await TestClient.create({ apiKey: 'sk-test', fetchImpl: impl })
    expect(await client.getBalanceUsd()).toBeCloseTo(12.345678)
    expect(calls[0]?.url).toContain('/v1/wallet/balance')
  })

  it('reports zero when the gateway sends an unparseable balance', async () => {
    const { impl } = stubFetch([json({ balance_usd: null })])
    const client = await TestClient.create({ apiKey: 'sk-test', fetchImpl: impl })
    expect(await client.getBalanceUsd()).toBe(0)
  })
})

describe('detectKeyType', () => {
  it('recognises a 0x-prefixed EVM key', () => {
    expect(detectKeyType(reference.evmTestKey)).toBe('evm')
  })

  it('recognises a bare 64-hex EVM key', () => {
    expect(detectKeyType(reference.evmTestKey.slice(2))).toBe('evm')
  })

  it('recognises a base58 Solana key', () => {
    expect(detectKeyType(reference.solana.keyBase58)).toBe('solana')
  })

  it('refuses a key it cannot classify instead of guessing a chain', () => {
    // Guessing wrong would sign for the wrong chain entirely.
    expect(() => detectKeyType('not a key at all!')).toThrow(/Cannot tell whether/)
  })

  it('lets an explicit network override the guess', async () => {
    const { impl } = stubFetch([])
    const client = await TestClient.create({
      privateKey: reference.solana.keyBase58,
      network: 'solana',
      fetchImpl: impl,
    })
    expect(client.address).toBe(reference.solana.address)
  })
})
