/**
 * x402 Solana signing — a partially-signed SPL `TransferChecked` transaction.
 *
 * The server is the fee payer and signs its own slot when it verifies the
 * payment, so we build the message around *their* fee payer and fill only our
 * signature slot. A fully-signed transaction would be rejected: we cannot sign
 * for their key, and they cannot re-sign a message we changed.
 */
import { PaymentError } from '../errors.js'
import {
  encodeEnvelope,
  findOption,
  parseChallenge,
  resolvePayment,
} from './challenge.js'
import type { PaymentEnvelope, SignerLimits } from './types.js'

/** Circle's USDC mint on Solana mainnet. */
export const USDC_MINT = 'EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v'
/** Solana mainnet in CAIP-2 form (genesis hash, truncated as the spec has it). */
export const SOLANA_NETWORK = 'solana:5eykt4UsFv8P8NJdTREpY1vzqKqZKvdp'
export const USDC_DECIMALS = 6

export const TOKEN_PROGRAM_ID = 'TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA'
export const ASSOCIATED_TOKEN_PROGRAM_ID = 'ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL'
export const COMPUTE_BUDGET_PROGRAM_ID = 'ComputeBudget111111111111111111111111111111'
export const MEMO_PROGRAM_ID = 'MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr'

export const DEFAULT_SOLANA_RPC = 'https://api.mainnet-beta.solana.com'

const COMPUTE_UNIT_LIMIT = 200_000
const COMPUTE_UNIT_PRICE_MICROLAMPORTS = 10_000n

export interface SolanaSignerOptions extends SignerLimits {
  /**
   * Where to read the recent blockhash from. Public mainnet RPC by default,
   * queried directly rather than through the gateway: a proxied blockhash can be
   * cached long enough that the facilitator's simulation rejects it as stale.
   */
  rpcUrl?: string
  /** Gateway base URL, used only as a blockhash fallback if the RPC is down. */
  baseUrl?: string
  /** Injectable for tests; defaults to `crypto.getRandomValues`. */
  randomBytes?: (length: number) => Uint8Array
  /** Injectable for tests; defaults to `fetch`. */
  fetchImpl?: typeof fetch
}

/** Signs x402 payment envelopes with a Solana key. */
export class SolanaX402Signer {
  private readonly keypair: SolanaKeypair
  private readonly web3: Web3Module
  private readonly rpcUrl: string
  private readonly baseUrl: string
  private readonly limits: SignerLimits
  private readonly randomBytes: (length: number) => Uint8Array
  private readonly fetchImpl: typeof fetch

  private constructor(keypair: SolanaKeypair, web3: Web3Module, opts: SolanaSignerOptions) {
    this.keypair = keypair
    this.web3 = web3
    this.rpcUrl = opts.rpcUrl ?? DEFAULT_SOLANA_RPC
    this.baseUrl = (opts.baseUrl ?? '').replace(/\/+$/, '')
    this.limits = opts.maxAmountBaseUnits === undefined
      ? {}
      : { maxAmountBaseUnits: opts.maxAmountBaseUnits }
    this.randomBytes = opts.randomBytes ?? defaultRandomBytes
    this.fetchImpl = opts.fetchImpl ?? fetch
  }

  /**
   * Build a signer from a base58 secret key — either the 64-byte keypair that
   * Phantom and the Solana CLI export, or a bare 32-byte seed.
   */
  static async fromPrivateKey(
    secretKeyBase58: string,
    opts: SolanaSignerOptions = {},
  ): Promise<SolanaX402Signer> {
    const web3 = await loadWeb3()
    const bs58 = await loadBs58()

    let decoded: Uint8Array
    try {
      decoded = bs58.decode(secretKeyBase58)
    } catch (err) {
      throw new PaymentError(`x402: Solana key is not valid base58 (${String(err)})`)
    }

    if (decoded.length === 64) {
      return new SolanaX402Signer(web3.Keypair.fromSecretKey(decoded), web3, opts)
    }
    if (decoded.length === 32) {
      return new SolanaX402Signer(web3.Keypair.fromSeed(decoded), web3, opts)
    }
    throw new PaymentError(
      `x402: invalid Solana key length ${decoded.length} bytes (expected 32 or 64)`,
    )
  }

  get address(): string {
    return this.keypair.publicKey.toBase58()
  }

  /** Read a 402 response and return the base64 `PAYMENT-SIGNATURE` value. */
  async signFrom402(resp: Response, resourceUrl: string): Promise<string> {
    const challenge = await parseChallenge(resp)
    const option = findOption(challenge, 'solana:')
    if (!option) {
      throw new PaymentError(
        'x402: the server offered no Solana payment option — ' +
          'it may want an EVM key instead, or no options at all',
      )
    }

    const payment = resolvePayment(option, {
      challenge,
      expectedAsset: USDC_MINT,
      defaultAsset: USDC_MINT,
      defaultNetwork: SOLANA_NETWORK,
      // Solana addresses are base58, where case is significant.
      assetCaseInsensitive: false,
      ...(this.limits.maxAmountBaseUnits === undefined
        ? {}
        : { maxAmountBaseUnits: this.limits.maxAmountBaseUnits }),
    })

    const feePayer = payment.extra['feePayer']
    if (typeof feePayer !== 'string' || !feePayer) {
      throw new PaymentError(
        'x402: the server did not provide a feePayer for Solana, so no ' +
          'partially-signed transaction can be built',
      )
    }

    const blockhash = await this.recentBlockhash()
    const transaction = await this.buildPartialTransaction({
      amount: payment.amount,
      mint: payment.asset,
      recipient: payment.payTo,
      feePayer,
      blockhash,
    })

    const envelope: PaymentEnvelope = {
      x402Version: 2,
      resource: {
        url: resourceUrl,
        description: payment.description,
        mimeType: 'application/json',
      },
      accepted: {
        scheme: 'exact',
        network: payment.network,
        amount: payment.amount.toString(),
        asset: payment.asset,
        payTo: payment.payTo,
        maxTimeoutSeconds: payment.maxTimeoutSeconds,
        extra: payment.extra,
      },
      payload: { transaction },
      extensions: {},
    }

    return encodeEnvelope(envelope)
  }

  /** Latest finalized blockhash, from RPC with the gateway as a fallback. */
  private async recentBlockhash(): Promise<string> {
    try {
      const resp = await this.fetchImpl(this.rpcUrl, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'getLatestBlockhash',
          params: [{ commitment: 'finalized' }],
        }),
        signal: AbortSignal.timeout(10_000),
      })
      const body = (await resp.json()) as {
        result?: { value?: { blockhash?: string } }
      }
      const blockhash = body.result?.value?.blockhash
      if (blockhash) return blockhash
    } catch {
      // Fall through to the gateway proxy below.
    }

    if (this.baseUrl) {
      try {
        const resp = await this.fetchImpl(`${this.baseUrl}/api/solana/blockhash`, {
          signal: AbortSignal.timeout(5_000),
        })
        if (resp.ok) {
          const body = (await resp.json()) as { blockhash?: string }
          if (body.blockhash) return body.blockhash
        }
      } catch {
        // Both sources failed; report it below rather than signing against a
        // blockhash we invented.
      }
    }

    throw new PaymentError(
      `x402: could not get a Solana blockhash from ${this.rpcUrl}` +
        (this.baseUrl ? ` or ${this.baseUrl}/api/solana/blockhash` : ''),
    )
  }

  private async buildPartialTransaction(args: {
    amount: bigint
    mint: string
    recipient: string
    feePayer: string
    blockhash: string
  }): Promise<string> {
    const { PublicKey, MessageV0, VersionedTransaction } = this.web3

    const feePayerPk = new PublicKey(args.feePayer)
    const mintPk = new PublicKey(args.mint)
    const recipientPk = new PublicKey(args.recipient)
    const ourPk = this.keypair.publicKey
    const tokenProgram = new PublicKey(TOKEN_PROGRAM_ID)
    const ataProgram = new PublicKey(ASSOCIATED_TOKEN_PROGRAM_ID)
    const computeBudget = new PublicKey(COMPUTE_BUDGET_PROGRAM_ID)
    const memoProgram = new PublicKey(MEMO_PROGRAM_ID)

    const sourceAta = findAssociatedTokenAddress(
      this.web3, ourPk, mintPk, tokenProgram, ataProgram,
    )
    const destAta = findAssociatedTokenAddress(
      this.web3, recipientPk, mintPk, tokenProgram, ataProgram,
    )

    const instructions: RawInstruction[] = [
      // SetComputeUnitLimit: discriminator 2, u32 limit.
      { programId: computeBudget, keys: [], data: encodeU8U32(2, COMPUTE_UNIT_LIMIT) },
      // SetComputeUnitPrice: discriminator 3, u64 microlamports.
      {
        programId: computeBudget,
        keys: [],
        data: encodeU8U64(3, COMPUTE_UNIT_PRICE_MICROLAMPORTS),
      },
      // TransferChecked: discriminator 12, u64 amount, u8 decimals. The checked
      // variant is used so the chain rejects a decimals mismatch instead of
      // moving 1000x the intended sum.
      {
        programId: tokenProgram,
        keys: [
          { pubkey: sourceAta, isSigner: false, isWritable: true },
          { pubkey: mintPk, isSigner: false, isWritable: false },
          { pubkey: destAta, isSigner: false, isWritable: true },
          { pubkey: ourPk, isSigner: true, isWritable: false },
        ],
        data: encodeU8U64U8(12, args.amount, USDC_DECIMALS),
      },
      // A random memo, so two payments of the same amount to the same recipient
      // in the same block are distinct transactions. The facilitator requires it.
      {
        programId: memoProgram,
        keys: [],
        data: Buffer.from(toHex(this.randomBytes(16)), 'utf8'),
      },
    ]

    const message = compileV0Message(MessageV0, {
      feePayer: feePayerPk,
      recentBlockhash: args.blockhash,
      instructions,
    })

    const transaction = new VersionedTransaction(message)
    // `sign` fills only the slots whose keys we hold and leaves the fee payer's
    // slot as the all-zero placeholder VersionedTransaction pre-allocated.
    transaction.sign([this.keypair])

    const ourIndex = message.staticAccountKeys
      .slice(0, message.header.numRequiredSignatures)
      .findIndex((key) => key.equals(ourPk))
    if (ourIndex < 0) {
      throw new PaymentError(
        'x402: our public key is not among the transaction signers — ' +
          'the built message does not match the key we hold',
      )
    }
    const ourSignature = transaction.signatures[ourIndex]
    if (!ourSignature || ourSignature.every((b) => b === 0)) {
      throw new PaymentError('x402: signing produced an empty signature for our slot')
    }

    return Buffer.from(transaction.serialize()).toString('base64')
  }
}

/**
 * Query the wallet's total USDC across every token account it owns.
 *
 * Enumerated rather than derived from the associated token account, because a
 * wallet can legitimately hold USDC in more than one account and deriving only
 * the ATA would under-report the balance.
 */
export async function solanaUsdcBalance(
  address: string,
  opts: { rpcUrl?: string; fetchImpl?: typeof fetch } = {},
): Promise<number> {
  const fetchImpl = opts.fetchImpl ?? fetch
  const resp = await fetchImpl(opts.rpcUrl ?? DEFAULT_SOLANA_RPC, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'getTokenAccountsByOwner',
      params: [address, { mint: USDC_MINT }, { encoding: 'jsonParsed' }],
    }),
    signal: AbortSignal.timeout(10_000),
  })

  const body = (await resp.json()) as {
    error?: unknown
    result?: {
      value?: Array<{
        account?: { data?: { parsed?: { info?: { tokenAmount?: { uiAmount?: number } } } } }
      }>
    }
  }
  if (body.error) {
    throw new PaymentError(`Solana RPC error: ${JSON.stringify(body.error)}`)
  }

  let total = 0
  for (const account of body.result?.value ?? []) {
    const amount = account.account?.data?.parsed?.info?.tokenAmount?.uiAmount
    if (typeof amount === 'number') total += amount
  }
  return total
}

/**
 * Compile a v0 message with the account ordering the gateway's facilitator has
 * been proven to accept.
 *
 * `TransactionMessage.compileToV0Message()` is not used, even though it is the
 * obvious call, because it orders the account table by first appearance while the
 * Rust/solders path the Python SDK uses orders it by pubkey bytes within each
 * privilege category. Both produce a transaction the chain would run, but only
 * the sorted layout is the one that has actually settled against this
 * facilitator, so it is reproduced here rather than assumed to be interchangeable.
 */
function compileV0Message(
  MessageV0: Web3Module['MessageV0'],
  args: {
    feePayer: SolanaPublicKey
    recentBlockhash: string
    instructions: RawInstruction[]
  },
): CompiledV0Message {
  // Collect each account's maximum privilege across all instructions. A program
  // id is always readonly and never a signer.
  const privileges = new Map<string, { key: SolanaPublicKey; signer: boolean; writable: boolean }>()
  const note = (key: SolanaPublicKey, signer: boolean, writable: boolean) => {
    const id = key.toBase58()
    const existing = privileges.get(id)
    if (existing) {
      existing.signer ||= signer
      existing.writable ||= writable
    } else {
      privileges.set(id, { key, signer, writable })
    }
  }

  // The fee payer is a writable signer and must end up at index 0.
  note(args.feePayer, true, true)
  for (const ix of args.instructions) {
    for (const meta of ix.keys) note(meta.pubkey, meta.isSigner, meta.isWritable)
    note(ix.programId, false, false)
  }

  const feePayerId = args.feePayer.toBase58()
  const rest = [...privileges.values()].filter((a) => a.key.toBase58() !== feePayerId)
  const byBytes = (
    a: { key: SolanaPublicKey },
    b: { key: SolanaPublicKey },
  ) => compareBytes(a.key.toBuffer(), b.key.toBuffer())

  const writableSigners = rest.filter((a) => a.signer && a.writable).sort(byBytes)
  const readonlySigners = rest.filter((a) => a.signer && !a.writable).sort(byBytes)
  const writableUnsigned = rest.filter((a) => !a.signer && a.writable).sort(byBytes)
  const readonlyUnsigned = rest.filter((a) => !a.signer && !a.writable).sort(byBytes)

  const ordered = [
    args.feePayer,
    ...writableSigners.map((a) => a.key),
    ...readonlySigners.map((a) => a.key),
    ...writableUnsigned.map((a) => a.key),
    ...readonlyUnsigned.map((a) => a.key),
  ]
  const indexOf = new Map(ordered.map((key, i) => [key.toBase58(), i]))
  const index = (key: SolanaPublicKey): number => {
    const i = indexOf.get(key.toBase58())
    if (i === undefined) {
      throw new PaymentError(`x402: account ${key.toBase58()} missing from the compiled key table`)
    }
    return i
  }

  return new MessageV0({
    header: {
      numRequiredSignatures: 1 + writableSigners.length + readonlySigners.length,
      numReadonlySignedAccounts: readonlySigners.length,
      numReadonlyUnsignedAccounts: readonlyUnsigned.length,
    },
    staticAccountKeys: ordered,
    recentBlockhash: args.recentBlockhash,
    compiledInstructions: args.instructions.map((ix) => ({
      programIdIndex: index(ix.programId),
      accountKeyIndexes: ix.keys.map((meta) => index(meta.pubkey)),
      data: new Uint8Array(ix.data),
    })),
    addressTableLookups: [],
  })
}

/** Lexicographic byte comparison, matching how Rust orders pubkeys. */
function compareBytes(a: Uint8Array, b: Uint8Array): number {
  for (let i = 0; i < Math.min(a.length, b.length); i++) {
    const diff = (a[i] as number) - (b[i] as number)
    if (diff !== 0) return diff
  }
  return a.length - b.length
}

// ─── Solana library surface, kept narrow so tests can substitute it ──────────

interface SolanaPublicKey {
  toBase58(): string
  toBuffer(): Buffer
  equals(other: SolanaPublicKey): boolean
}

interface SolanaKeypair {
  publicKey: SolanaPublicKey
}

/** An instruction before account indexes are assigned. */
interface RawInstruction {
  programId: SolanaPublicKey
  keys: Array<{ pubkey: SolanaPublicKey; isSigner: boolean; isWritable: boolean }>
  data: Buffer
}

interface CompiledV0Message {
  staticAccountKeys: SolanaPublicKey[]
  header: { numRequiredSignatures: number }
  serialize(): Uint8Array
}

interface Web3Module {
  PublicKey: {
    new (value: string): SolanaPublicKey
    findProgramAddressSync(
      seeds: Array<Buffer | Uint8Array>,
      programId: SolanaPublicKey,
    ): [SolanaPublicKey, number]
  }
  Keypair: {
    fromSecretKey(secretKey: Uint8Array): SolanaKeypair
    fromSeed(seed: Uint8Array): SolanaKeypair
  }
  MessageV0: new (args: {
    header: {
      numRequiredSignatures: number
      numReadonlySignedAccounts: number
      numReadonlyUnsignedAccounts: number
    }
    staticAccountKeys: SolanaPublicKey[]
    recentBlockhash: string
    compiledInstructions: Array<{
      programIdIndex: number
      accountKeyIndexes: number[]
      data: Uint8Array
    }>
    addressTableLookups: never[]
  }) => CompiledV0Message
  VersionedTransaction: new (message: CompiledV0Message) => {
    signatures: Uint8Array[]
    sign(signers: SolanaKeypair[]): void
    serialize(): Uint8Array
  }
}

async function loadWeb3(): Promise<Web3Module> {
  try {
    return (await import('@solana/web3.js')) as unknown as Web3Module
  } catch (err) {
    throw new PaymentError(
      'x402 Solana mode needs the optional peer dependency `@solana/web3.js`. ' +
        `Install it with: npm install @solana/web3.js (${String(err)})`,
    )
  }
}

async function loadBs58(): Promise<{ decode(value: string): Uint8Array }> {
  const mod = (await import('bs58')) as unknown as {
    default?: { decode(value: string): Uint8Array }
    decode?(value: string): Uint8Array
  }
  const impl = mod.default ?? mod
  if (typeof impl.decode !== 'function') {
    throw new PaymentError('x402: bs58 module exposes no decode()')
  }
  return impl as { decode(value: string): Uint8Array }
}

function findAssociatedTokenAddress(
  web3: Web3Module,
  owner: SolanaPublicKey,
  mint: SolanaPublicKey,
  tokenProgram: SolanaPublicKey,
  ataProgram: SolanaPublicKey,
): SolanaPublicKey {
  const [address] = web3.PublicKey.findProgramAddressSync(
    [owner.toBuffer(), tokenProgram.toBuffer(), mint.toBuffer()],
    ataProgram,
  )
  return address
}

function encodeU8U32(discriminator: number, value: number): Buffer {
  const buf = Buffer.alloc(5)
  buf.writeUInt8(discriminator, 0)
  buf.writeUInt32LE(value, 1)
  return buf
}

function encodeU8U64(discriminator: number, value: bigint): Buffer {
  const buf = Buffer.alloc(9)
  buf.writeUInt8(discriminator, 0)
  buf.writeBigUInt64LE(value, 1)
  return buf
}

function encodeU8U64U8(discriminator: number, value: bigint, trailing: number): Buffer {
  const buf = Buffer.alloc(10)
  buf.writeUInt8(discriminator, 0)
  buf.writeBigUInt64LE(value, 1)
  buf.writeUInt8(trailing, 9)
  return buf
}

function defaultRandomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length)
  crypto.getRandomValues(out)
  return out
}

function toHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('')
}
