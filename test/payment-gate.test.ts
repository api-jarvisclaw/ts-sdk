import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { BaseClient, PaymentDeclinedError, type PaymentRequest } from '../src/index.js'

const reference = JSON.parse(
  readFileSync(new URL('./fixtures/reference.json', import.meta.url), 'utf8'),
) as {
  evmTestKey: string
  challengeEvm: { accepts: Array<Record<string, unknown>>; resource?: { description?: string } }
}

// approvePayment is the ONLY place that sees every x402 charge.
//
// Before it existed, the CLI gated spending at its own call sites — which meant it
// gated the one tool it remembered to wrap. Six LLM turns quoted at $0.21 each went
// through untouched while the user held a $0.05 per-call limit and a $1 session
// limit, because LLM inference is not `call_api`. The most expensive component was
// the only one outside the gate.
//
// These tests pin the properties that make the hook worth having: it runs before
// signing, it sees the real quoted amount, refusal is distinguishable from failure,
// and an unreadable quote is refused rather than paid.

/** A 402 challenge, then a 200 — the gateway's pay-and-retry sequence. */
function payThenOk(challengeBody: unknown): {
  fetchImpl: typeof fetch
  calls: () => number
  paidCalls: () => number
} {
  let calls = 0
  let paidCalls = 0
  const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
    calls += 1
    const headers = new Headers(init?.headers ?? {})
    if (headers.has('PAYMENT-SIGNATURE')) {
      paidCalls += 1
      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'content-type': 'application/json' },
      })
    }
    return new Response(JSON.stringify(challengeBody), {
      status: 402,
      headers: { 'content-type': 'application/json' },
    })
  }) as unknown as typeof fetch
  return { fetchImpl, calls: () => calls, paidCalls: () => paidCalls }
}

async function clientWith(
  approvePayment: ((req: PaymentRequest) => unknown) | undefined,
  fetchImpl: typeof fetch,
) {
  return BaseClient.create({
    privateKey: reference.evmTestKey,
    network: 'base',
    baseUrl: 'https://gateway.test',
    fetchImpl,
    maxRetries: 1,
    ...(approvePayment ? { approvePayment: approvePayment as never } : {}),
  })
}

describe('approvePayment', () => {
  it('is consulted with the real quoted amount before signing', async () => {
    const seen: PaymentRequest[] = []
    const t = payThenOk(reference.challengeEvm)
    const client = await clientWith((req) => {
      seen.push(req)
      return true
    }, t.fetchImpl)

    await client.request('/v1/chat/completions', { method: 'POST', body: { hi: 1 } })

    expect(seen).toHaveLength(1)
    // 12345 base units = $0.012345. The quote IS the charge: x402 prepays a fixed
    // authorisation and never reconciles down to actual usage.
    expect(seen[0]!.amountBaseUnits).toBe(12345n)
    expect(seen[0]!.amountUsd).toBeCloseTo(0.012345, 9)
    expect(seen[0]!.network).toBe('eip155:8453')
    expect(seen[0]!.resourceUrl).toContain('/v1/chat/completions')
    expect(seen[0]!.description).toBe('chat completion')
    expect(t.paidCalls()).toBe(1)
  })

  it('refusing means nothing is signed and nothing is charged', async () => {
    const t = payThenOk(reference.challengeEvm)
    const client = await clientWith(() => false, t.fetchImpl)

    await expect(
      client.request('/v1/chat/completions', { method: 'POST', body: { hi: 1 } }),
    ).rejects.toThrow(PaymentDeclinedError)

    // The 402 happened; the paid retry must not have.
    expect(t.paidCalls()).toBe(0)
  })

  it('carries the amount and reason so the caller can say what it refused', async () => {
    const t = payThenOk(reference.challengeEvm)
    const client = await clientWith(
      () => ({ approved: false, reason: 'above the $0.005 per-call limit' }),
      t.fetchImpl,
    )

    await expect(
      client.request('/v1/chat/completions', { method: 'POST', body: {} }),
    ).rejects.toMatchObject({
      amountUsd: 0.012345,
      reason: 'above the $0.005 per-call limit',
    })
  })

  it('refuses a quote it cannot read rather than paying it', async () => {
    // A challenge with no amount. Paying an unreadable quote is the failure this
    // hook exists to prevent, so it must not fall through to signing.
    const t = payThenOk({ x402Version: 2, accepts: [{ network: 'eip155:8453' }] })
    let asked = false
    const client = await clientWith(() => {
      asked = true
      return true
    }, t.fetchImpl)

    await expect(client.request('/v1/x', { method: 'POST', body: {} })).rejects.toThrow(
      PaymentDeclinedError,
    )
    expect(asked, 'the hook cannot approve what it was never shown').toBe(false)
    expect(t.paidCalls()).toBe(0)
  })

  it('supports an async hook, so a human can be prompted', async () => {
    const t = payThenOk(reference.challengeEvm)
    const client = await clientWith(async (req) => {
      await new Promise((r) => setTimeout(r, 1))
      return req.amountUsd < 1
    }, t.fetchImpl)

    const resp = await client.request('/v1/x', { method: 'POST', body: {} })
    expect(resp.status).toBe(200)
    expect(t.paidCalls()).toBe(1)
  })

  it('does not disturb the existing flow when no hook is given', async () => {
    const t = payThenOk(reference.challengeEvm)
    const client = await clientWith(undefined, t.fetchImpl)

    const resp = await client.request('/v1/x', { method: 'POST', body: {} })
    expect(resp.status).toBe(200)
    expect(t.paidCalls()).toBe(1)
  })

  it('leaves the challenge body readable for the signer', async () => {
    // The gate parses the challenge, and parsing consumes the body. Reading the
    // original instead of a clone would leave the signer with an empty body and turn
    // an APPROVED payment into a signing failure — a bug that only appears once the
    // hook is in use, which is why it gets its own test.
    const t = payThenOk(reference.challengeEvm)
    const client = await clientWith(() => true, t.fetchImpl)

    const resp = await client.request('/v1/x', { method: 'POST', body: {} })
    expect(resp.status).toBe(200)
    expect(t.paidCalls(), 'the signed retry must have gone out').toBe(1)
  })
})
