import { Keypair, VersionedTransaction } from '@solana/web3.js'
import bs58 from 'bs58'
import { describe, expect, it, vi } from 'vitest'
import {
  SOLANA_NETWORK,
  SolanaX402Signer,
  USDC_MINT,
  solanaUsdcBalance,
} from '../src/x402/solana.js'
import reference from './fixtures/reference.json' with { type: 'json' }

const RESOURCE = reference.resourceUrl
const fixedMemo = Buffer.from(reference.fixedMemoHex, 'hex')
const solOption = reference.challengeSolana.accepts[0]!

function challenge402(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 402,
    headers: { 'content-type': 'application/json' },
  })
}

function decode(header: string): any {
  return JSON.parse(Buffer.from(header, 'base64').toString('utf8'))
}

/** A fetch that always answers the blockhash RPC with the fixture's blockhash. */
function blockhashFetch(): typeof fetch {
  return vi.fn(async () =>
    new Response(
      JSON.stringify({ result: { value: { blockhash: reference.solana.blockhash } } }),
      { headers: { 'content-type': 'application/json' } },
    ),
  ) as unknown as typeof fetch
}

/** A signer pinned to the fixture's memo nonce and blockhash. */
async function pinnedSigner(overrides: Record<string, unknown> = {}) {
  return SolanaX402Signer.fromPrivateKey(reference.solana.keyBase58, {
    randomBytes: (n) => new Uint8Array(fixedMemo.subarray(0, n)),
    fetchImpl: blockhashFetch(),
    ...overrides,
  })
}

describe('SolanaX402Signer', () => {
  it('derives the same address as the Python SDK from the same seed', async () => {
    const signer = await pinnedSigner()
    expect(signer.address).toBe(reference.solana.address)
  })

  it('accepts a 64-byte secret key as well as a 32-byte seed', async () => {
    const seed = Buffer.from(reference.solana.seedHex, 'hex')
    const full = Keypair.fromSeed(new Uint8Array(seed))
    const signer = await SolanaX402Signer.fromPrivateKey(bs58.encode(full.secretKey), {
      fetchImpl: blockhashFetch(),
    })
    expect(signer.address).toBe(reference.solana.address)
  })

  it('builds a transaction byte-identical to the Python SDK', async () => {
    const signer = await pinnedSigner()
    const header = await signer.signFrom402(challenge402(reference.challengeSolana), RESOURCE)

    // Both SDKs are verified by the same facilitator, which simulates the
    // transaction — any structural difference means one of them stopped working.
    expect(decode(header)).toEqual(reference.solana.envelope)
    expect(header).toBe(reference.solana.header)
  })

  it('leaves the fee payer slot unsigned and signs only its own', async () => {
    const signer = await pinnedSigner()
    const envelope = decode(
      await signer.signFrom402(challenge402(reference.challengeSolana), RESOURCE),
    )
    const tx = VersionedTransaction.deserialize(
      Buffer.from(envelope.payload.transaction, 'base64'),
    )

    const keys = tx.message.staticAccountKeys
    const numSigners = tx.message.header.numRequiredSignatures
    expect(numSigners).toBe(2)

    // Index 0 is the fee payer — the server's key, which we cannot sign for.
    const feePayer = solOption.extra.feePayer
    expect(keys[0]?.toBase58()).toBe(feePayer)
    expect(tx.signatures[0]?.every((b) => b === 0)).toBe(true)

    const ourIndex = keys.slice(0, numSigners).findIndex((k) => k.toBase58() === signer.address)
    expect(ourIndex).toBeGreaterThan(0)
    expect(tx.signatures[ourIndex]?.every((b) => b === 0)).toBe(false)
  })

  it('verifies against the transaction message, not just a non-zero byte string', async () => {
    const signer = await pinnedSigner()
    const envelope = decode(
      await signer.signFrom402(challenge402(reference.challengeSolana), RESOURCE),
    )
    const tx = VersionedTransaction.deserialize(
      Buffer.from(envelope.payload.transaction, 'base64'),
    )
    const keys = tx.message.staticAccountKeys
    const ourIndex = keys.findIndex((k) => k.toBase58() === signer.address)
    const signature = tx.signatures[ourIndex]!

    // Ed25519-verify the signature over the serialized message. A signature over
    // the wrong bytes would still be 64 non-zero bytes and pass the check above.
    const { verify } = await import('node:crypto')
    const rawPublicKey = bs58.decode(signer.address)
    const spki = Buffer.concat([
      Buffer.from('302a300506032b6570032100', 'hex'),
      Buffer.from(rawPublicKey),
    ])
    const { createPublicKey } = await import('node:crypto')
    const key = createPublicKey({ key: spki, format: 'der', type: 'spki' })
    expect(verify(null, Buffer.from(tx.message.serialize()), key, signature)).toBe(true)
  })

  it('sends the amount as TransferChecked with 6 decimals', async () => {
    const signer = await pinnedSigner()
    const envelope = decode(
      await signer.signFrom402(challenge402(reference.challengeSolana), RESOURCE),
    )
    const tx = VersionedTransaction.deserialize(
      Buffer.from(envelope.payload.transaction, 'base64'),
    )
    const amount = BigInt(solOption.amount)

    // Instruction data: discriminator 12, u64 amount LE, u8 decimals.
    const expected = Buffer.alloc(10)
    expected.writeUInt8(12, 0)
    expected.writeBigUInt64LE(amount, 1)
    expected.writeUInt8(6, 9)

    const datas = tx.message.compiledInstructions.map((ix) => Buffer.from(ix.data).toString('hex'))
    expect(datas).toContain(expected.toString('hex'))
  })

  it('echoes the server extra, including feePayer, back in the envelope', async () => {
    const signer = await pinnedSigner()
    const envelope = decode(
      await signer.signFrom402(challenge402(reference.challengeSolana), RESOURCE),
    )
    expect(envelope.accepted.extra).toEqual(solOption.extra)
    expect(envelope.accepted.network).toBe(SOLANA_NETWORK)
  })

  it('falls back to the gateway proxy when the RPC fails', async () => {
    const calls: string[] = []
    const fetchImpl = vi.fn(async (url: unknown) => {
      const href = String(url)
      calls.push(href)
      if (href.includes('mainnet-beta')) throw new Error('rpc down')
      return new Response(JSON.stringify({ blockhash: reference.solana.blockhash }), {
        headers: { 'content-type': 'application/json' },
      })
    }) as unknown as typeof fetch

    const signer = await pinnedSigner({
      fetchImpl,
      baseUrl: 'https://api.jarvisclaw.ai',
    })
    const header = await signer.signFrom402(challenge402(reference.challengeSolana), RESOURCE)
    expect(header).toBe(reference.solana.header)
    expect(calls.some((c) => c.endsWith('/api/solana/blockhash'))).toBe(true)
  })

  it('refuses to sign when no blockhash can be obtained', async () => {
    // Inventing a blockhash would produce a transaction that fails simulation
    // after the caller already believes they paid.
    const fetchImpl = vi.fn(async () => {
      throw new Error('network unreachable')
    }) as unknown as typeof fetch
    const signer = await pinnedSigner({ fetchImpl, baseUrl: 'https://api.jarvisclaw.ai' })
    await expect(
      signer.signFrom402(challenge402(reference.challengeSolana), RESOURCE),
    ).rejects.toThrow(/could not get a Solana blockhash/)
  })
})

describe('SolanaX402Signer refusals', () => {
  const base = solOption

  async function expectRefusal(option: Record<string, unknown>, pattern: RegExp) {
    const signer = await pinnedSigner()
    await expect(
      signer.signFrom402(challenge402({ accepts: [{ ...base, ...option }] }), RESOURCE),
    ).rejects.toThrow(pattern)
  }

  it('refuses when the server gave no feePayer', async () => {
    await expectRefusal({ extra: {} }, /did not provide a feePayer/)
  })

  it('refuses an empty payTo', async () => {
    await expectRefusal({ payTo: '' }, /empty payTo/)
  })

  it('refuses a zero amount', async () => {
    await expectRefusal({ amount: '0' }, /must be positive/)
  })

  it('refuses an amount above the safety cap', async () => {
    await expectRefusal({ amount: '100000001' }, /exceeds the client safety cap/)
  })

  it('refuses a mint that is not USDC', async () => {
    await expectRefusal({ asset: 'So11111111111111111111111111111111111111112' }, /unexpected asset/)
  })

  it('compares the mint case-sensitively', async () => {
    // Base58 is case-significant: a lowercased mint is a different address, not
    // the same one written differently, so it must not be waved through.
    await expectRefusal({ asset: USDC_MINT.toLowerCase() }, /unexpected asset/)
  })

  it('says so when the server offers only EVM', async () => {
    const signer = await pinnedSigner()
    await expect(
      signer.signFrom402(
        challenge402({ accepts: [{ network: 'eip155:8453', payTo: '0x1', amount: '1' }] }),
        RESOURCE,
      ),
    ).rejects.toThrow(/no Solana payment option/)
  })

  it('rejects a key of the wrong length', async () => {
    await expect(
      SolanaX402Signer.fromPrivateKey(bs58.encode(Buffer.alloc(16))),
    ).rejects.toThrow(/invalid Solana key length 16 bytes/)
  })

  it('rejects a key that is not base58', async () => {
    await expect(SolanaX402Signer.fromPrivateKey('0OIl-not-base58')).rejects.toThrow(
      /not valid base58/,
    )
  })
})

describe('solanaUsdcBalance', () => {
  function rpc(body: unknown): typeof fetch {
    return vi.fn(async () =>
      new Response(JSON.stringify(body), { headers: { 'content-type': 'application/json' } }),
    ) as unknown as typeof fetch
  }

  it('sums every USDC account the wallet owns', async () => {
    // A wallet can hold USDC in more than one token account; deriving only the
    // associated token account would under-report the balance.
    const fetchImpl = rpc({
      result: {
        value: [
          { account: { data: { parsed: { info: { tokenAmount: { uiAmount: 1.5 } } } } } },
          { account: { data: { parsed: { info: { tokenAmount: { uiAmount: 2.25 } } } } } },
        ],
      },
    })
    expect(await solanaUsdcBalance(reference.solana.address, { fetchImpl })).toBeCloseTo(3.75)
  })

  it('reports zero for a wallet with no USDC accounts', async () => {
    const fetchImpl = rpc({ result: { value: [] } })
    expect(await solanaUsdcBalance(reference.solana.address, { fetchImpl })).toBe(0)
  })

  it('raises on an RPC error instead of reporting zero', async () => {
    // Reporting 0 would look identical to an empty wallet and send a caller
    // topping up an account that already has funds.
    const fetchImpl = rpc({ error: { code: -32000, message: 'rate limited' } })
    await expect(
      solanaUsdcBalance(reference.solana.address, { fetchImpl }),
    ).rejects.toThrow(/Solana RPC error/)
  })
})
