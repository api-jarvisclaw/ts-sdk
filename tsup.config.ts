import { defineConfig } from 'tsup'

export default defineConfig({
  entry: ['src/index.ts'],
  format: ['esm', 'cjs'],
  dts: true,
  clean: true,
  sourcemap: true,
  target: 'node20',
  // viem and @solana/web3.js are optional peers, loaded lazily at the point a
  // key of that kind is actually used. Bundling them would drag both chains
  // into every install and defeat the optional-peer arrangement.
  external: ['viem', '@solana/web3.js', 'bs58'],
})
