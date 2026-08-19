import { describe, expect, it } from 'vitest'
import { recoverTypedDataAddress } from 'viem'
import { PaymentError } from '../src/errors.js'
import {
  EvmX402Signer,
  USDC_BASE_CONTRACT,
  chainIdForNetwork,
} from '../src/x402/evm.js'
import reference from './fixtures/reference.json' with { type: 'json' }

/** A 402 response carrying `body` as JSON, as the gateway sends it. */
function challenge402(body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), {
    status: 402,
    headers: { 'content-type': 'application/json', ...headers },
  })
}

/** Decode the base64 `PAYMENT-SIGNATURE` value back into the envelope. */
function decode(header: string): any {
  return JSON.parse(Buffer.from(header, 'base64').toString('utf8'))
}

const fixedNonce = Buffer.from(reference.fixedNonceHex, 'hex')
const RESOURCE = reference.resourceUrl

/** A signer pinned to the fixture's nonce and clock, so output is deterministic. */
async function pinnedSigner(overrides: Record<string, unknown> = {}) {
  return EvmX402Signer.fromPrivateKey(reference.evmTestKey, {
    randomBytes: (n) => new Uint8Array(fixedNonce.subarray(0, n)),
    now: () => reference.fixedTimeSeconds * 1000,
    ...overrides,
  })
}

describe('EvmX402Signer', () => {
  it('derives the same address as the Python SDK from the same key', async () => {
    const signer = await pinnedSigner()
    expect(signer.address).toBe(reference.evm.address)
  })

  it('produces a byte-identical envelope to the Python SDK', async () => {
    const signer = await pinnedSigner()
    const header = await signer.signFrom402(challenge402(reference.challengeEvm), RESOURCE)

    // The whole point of the fixture: the facilitator verifies both SDKs, so an
    // envelope that differs anywhere is a bug in whichever one drifted.
    expect(decode(header)).toEqual(reference.evm.envelope)
    expect(header).toBe(reference.evm.header)
  })

  it('signs a recoverable EIP-712 authorization', async () => {
    const signer = await pinnedSigner()
    const header = await signer.signFrom402(challenge402(reference.challengeEvm), RESOURCE)
    const envelope = decode(header)
    const auth = envelope.payload.authorization

    // Recovering the signer proves the typed-data struct we hashed is the one the
    // authorization describes — a field mismatch would recover a different address.
    const recovered = await recoverTypedDataAddress({
      domain: {
        name: 'USD Coin',
        version: '2',
        chainId: 8453,
        verifyingContract: USDC_BASE_CONTRACT as `0x${string}`,
      },
      types: {
        TransferWithAuthorization: [
          { name: 'from', type: 'address' },
          { name: 'to', type: 'address' },
          { name: 'value', type: 'uint256' },
          { name: 'validAfter', type: 'uint256' },
          { name: 'validBefore', type: 'uint256' },
          { name: 'nonce', type: 'bytes32' },
        ],
      },
      primaryType: 'TransferWithAuthorization',
      message: {
        from: auth.from,
        to: auth.to,
        value: BigInt(auth.value),
        validAfter: BigInt(auth.validAfter),
        validBefore: BigInt(auth.validBefore),
        nonce: auth.nonce,
      },
      signature: envelope.payload.signature,
    })
    expect(recovered.toLowerCase()).toBe(signer.address.toLowerCase())
  })

  it('backdates validAfter so clock skew cannot invalidate the authorization', async () => {
    const signer = await pinnedSigner()
    const envelope = decode(
      await signer.signFrom402(challenge402(reference.challengeEvm), RESOURCE),
    )
    const auth = envelope.payload.authorization
    expect(Number(auth.validAfter)).toBe(reference.fixedTimeSeconds - 600)
    expect(Number(auth.validBefore)).toBe(reference.fixedTimeSeconds + 300)
  })

  it('reads the challenge from the base64 payment-required header', async () => {
    const signer = await pinnedSigner()
    const encoded = Buffer.from(JSON.stringify(reference.challengeEvm)).toString('base64')
    const resp = new Response('not json at all', {
      status: 402,
      headers: { 'payment-required': encoded },
    })
    const envelope = decode(await signer.signFrom402(resp, RESOURCE))
    expect(envelope.accepted.amount).toBe('12345')
  })

  it('falls back to the body when the header is malformed', async () => {
    const signer = await pinnedSigner()
    const resp = challenge402(reference.challengeEvm, { 'payment-required': '!!!not-base64!!!' })
    const envelope = decode(await signer.signFrom402(resp, RESOURCE))
    expect(envelope.accepted.amount).toBe('12345')
  })

  it('accepts the x402 v1 field names', async () => {
    const signer = await pinnedSigner()
    const v1 = {
      payments: [
        {
          network: 'eip155:8453',
          maxAmountRequired: '999',
          asset: USDC_BASE_CONTRACT,
          payTo: '0x2222222222222222222222222222222222222222',
        },
      ],
    }
    const envelope = decode(await signer.signFrom402(challenge402(v1), RESOURCE))
    expect(envelope.accepted.amount).toBe('999')
    expect(envelope.accepted.maxTimeoutSeconds).toBe(300)
  })
})

describe('EvmX402Signer refusals', () => {
  const base = reference.challengeEvm.accepts[0]

  async function expectRefusal(option: Record<string, unknown>, pattern: RegExp) {
    const signer = await pinnedSigner()
    await expect(
      signer.signFrom402(challenge402({ accepts: [{ ...base, ...option }] }), RESOURCE),
    ).rejects.toThrow(pattern)
  }

  it('refuses an empty payTo rather than signing funds to nowhere', async () => {
    await expectRefusal({ payTo: '' }, /empty payTo/)
  })

  it('refuses a zero amount', async () => {
    await expectRefusal({ amount: '0' }, /must be positive/)
  })

  it('refuses a negative amount', async () => {
    await expectRefusal({ amount: '-1' }, /must be positive/)
  })

  it('refuses a fractional amount instead of truncating it', async () => {
    // Truncating would sign for a different sum than the server asked for.
    await expectRefusal({ amount: '1.5' }, /not an integer number of base units/)
  })

  it('refuses an amount above the default 100 USDC cap', async () => {
    await expectRefusal({ amount: '100000001' }, /exceeds the client safety cap/)
  })

  it('honours a caller-supplied cap', async () => {
    const signer = await pinnedSigner({ maxAmountBaseUnits: 1000n })
    await expect(
      signer.signFrom402(
        challenge402({ accepts: [{ ...base, amount: '1001' }] }),
        RESOURCE,
      ),
    ).rejects.toThrow(/exceeds the client safety cap of 1000/)
  })

  it('signs an amount exactly at the cap', async () => {
    const signer = await pinnedSigner({ maxAmountBaseUnits: 1000n })
    const envelope = decode(
      await signer.signFrom402(
        challenge402({ accepts: [{ ...base, amount: '1000' }] }),
        RESOURCE,
      ),
    )
    expect(envelope.accepted.amount).toBe('1000')
  })

  it('refuses an asset that is not USDC', async () => {
    // Signing this would authorise a transfer of some other token entirely.
    await expectRefusal(
      { asset: '0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' },
      /unexpected asset/,
    )
  })

  it('accepts USDC written in a different case', async () => {
    const signer = await pinnedSigner()
    const envelope = decode(
      await signer.signFrom402(
        challenge402({ accepts: [{ ...base, asset: USDC_BASE_CONTRACT.toLowerCase() }] }),
        RESOURCE,
      ),
    )
    expect(envelope.accepted.asset.toLowerCase()).toBe(USDC_BASE_CONTRACT.toLowerCase())
  })

  it('says so when the server offers only Solana', async () => {
    const signer = await pinnedSigner()
    await expect(
      signer.signFrom402(
        challenge402({ accepts: [{ network: 'solana:5eykt4Us', payTo: 'x', amount: '1' }] }),
        RESOURCE,
      ),
    ).rejects.toThrow(/no EVM payment option/)
  })

  it('says so when there are no options at all', async () => {
    const signer = await pinnedSigner()
    await expect(
      signer.signFrom402(challenge402({ accepts: [] }), RESOURCE),
    ).rejects.toThrow(/no EVM payment option/)
  })

  it('reports an unreadable challenge instead of signing a guess', async () => {
    const signer = await pinnedSigner()
    const resp = new Response('<html>gateway error</html>', { status: 402 })
    await expect(signer.signFrom402(resp, RESOURCE)).rejects.toThrow(
      /no readable payment challenge/,
    )
  })
})

describe('chainIdForNetwork', () => {
  it('maps the known aliases', () => {
    expect(chainIdForNetwork('base')).toBe(8453)
    expect(chainIdForNetwork('eip155:8453')).toBe(8453)
    expect(chainIdForNetwork('base-sepolia')).toBe(84532)
  })

  it('reads an unknown eip155 chain out of the identifier', () => {
    expect(chainIdForNetwork('eip155:42161')).toBe(42161)
  })

  it('refuses an unparseable network rather than defaulting to Base', () => {
    // Defaulting would produce a signature that verifies locally and settles on
    // no chain at all — the failure would only show up after the money moved.
    expect(() => chainIdForNetwork('solana:5eykt4Us')).toThrow(PaymentError)
    expect(() => chainIdForNetwork('eip155:not-a-number')).toThrow(/cannot determine an EVM chain id/)
    expect(() => chainIdForNetwork('')).toThrow(PaymentError)
  })

  it('signs for the chain the challenge names, not the configured default', async () => {
    const signer = await pinnedSigner({ network: 'eip155:8453' })
    const envelope = decode(
      await signer.signFrom402(
        challenge402({
          accepts: [{ ...reference.challengeEvm.accepts[0], network: 'eip155:84532' }],
        }),
        RESOURCE,
      ),
    )
    expect(envelope.accepted.network).toBe('eip155:84532')
  })
})
