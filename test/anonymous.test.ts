/**
 * Anonymous mode.
 *
 * Its own file because it fixes a bug that mocked tests could not have found: the
 * CLI passed `apiKey: 'anonymous'` as a stand-in, and the real gateway rejects any
 * credential it does not recognise with 401 — while a request carrying no auth
 * header at all reaches the free tier and the public catalogue. A placeholder key
 * therefore fails exactly where sending nothing succeeds. Only a live call showed
 * that; these tests pin the fix.
 */
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { AnonymousAuth, BaseClient, JarvisClawError } from '../src/index.js'

class TestClient extends BaseClient {
  callGet<T>(path: string) {
    return this.get<T>(path)
  }
  callPost<T>(path: string, body: unknown) {
    return this.post<T>(path, { body })
  }
}

function stubFetch(responses: Response[]) {
  const headersSeen: Array<Record<string, string>> = []
  const queue = [...responses]
  const impl = vi.fn(async (_url: unknown, init?: RequestInit) => {
    headersSeen.push(Object.fromEntries(new Headers(init?.headers).entries()))
    const next = queue.shift()
    if (!next) throw new Error('unexpected extra call')
    return next
  })
  return { impl: impl as unknown as typeof fetch, headersSeen }
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json' },
  })
}

beforeEach(() => {
  delete process.env['JARVISCLAW_API_KEY']
  delete process.env['JARVISCLAW_WALLET_KEY']
})

afterEach(() => {
  vi.useRealTimers()
})

describe('anonymous mode', () => {
  it('sends no authorization header at all', async () => {
    // The distinction that matters: the gateway 401s `Bearer anonymous` but serves
    // a request with no header.
    const { impl, headersSeen } = stubFetch([json({ data: [] })])
    const client = await TestClient.create({ allowAnonymous: true, fetchImpl: impl })
    await client.callGet('/api/discovery/models')

    expect(headersSeen[0]).not.toHaveProperty('authorization')
    expect(client.isAnonymous).toBe(true)
    expect(client.canPay).toBe(false)
    expect(client.address).toBeUndefined()
  })

  it('is not used when a real credential exists', async () => {
    const { impl, headersSeen } = stubFetch([json({ ok: true })])
    const client = await TestClient.create({
      apiKey: 'sk-real',
      allowAnonymous: true,
      fetchImpl: impl,
    })
    await client.callGet('/v1/models')
    expect(headersSeen[0]?.['authorization']).toBe('Bearer sk-real')
    expect(client.isAnonymous).toBe(false)
  })

  it('still requires an explicit opt-in', async () => {
    // Defaulting to anonymous would turn a forgotten credential into a silent
    // downgrade to free-only, which reads as the gateway being broken.
    await expect(TestClient.create({ fetchImpl: stubFetch([]).impl })).rejects.toThrow(
      /No credential/,
    )
  })

  it('mentions the anonymous option in the no-credential error', async () => {
    const err = await TestClient.create({ fetchImpl: stubFetch([]).impl }).catch((e) => e)
    expect(String(err)).toMatch(/allowAnonymous/)
  })

  it('reports that a paid endpoint needs a wallet, on a 402', async () => {
    const { impl } = stubFetch([json({ accepts: [] }, 402)])
    const client = await TestClient.create({ allowAnonymous: true, fetchImpl: impl })
    await expect(client.callPost('/v1/chat/completions', {})).rejects.toThrow(
      /no wallet to pay with/,
    )
  })

  it('refuses to report a balance rather than reporting zero', async () => {
    // Zero would be indistinguishable from an empty wallet and would send someone
    // to top up an account that does not exist.
    const { impl } = stubFetch([])
    const client = await TestClient.create({ allowAnonymous: true, fetchImpl: impl })
    await expect(client.getBalanceUsd()).rejects.toThrow(JarvisClawError)
    await expect(client.getBalanceUsd()).rejects.toThrow(/no balance to read/)
  })

  it('AnonymousAuth adds nothing to the headers it is given', () => {
    const auth = new AnonymousAuth()
    const headers = new Headers({ 'content-type': 'application/json' })
    auth.prepareHeaders(headers)
    expect([...headers.keys()]).toEqual(['content-type'])
  })
})
