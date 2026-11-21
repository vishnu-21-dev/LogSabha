'use strict'
// ===========================================================================
//  Quai mode (quais.js): Orchard Cyprus-1 testnet only.
//
//  Keys come ONLY from named environment variables (see ROLE_ENV_VARS below),
//  read by dotenv in cli.js before connect() runs. A key's VALUE is never
//  printed, logged, or put in an error message -- only the env var NAME is.
//
//  Returns the same shape local.js does: { mode, provider, chainId,
//  accounts(), signerFor(address), startIntervalMining(ms), close() },
//  plus a few Quai-only extras cli.js uses: network, quais, verifyReachable().
// ===========================================================================

// Quai Network mainnet. NEVER used by this project; refused unconditionally.
const MAINNET_CHAIN_ID = 9000
// Orchard, the public Quai testnet. The only chain id this project ever talks to.
const EXPECTED_CHAIN_ID = 15000

// Which environment variable holds which role's private key. A role with no
// variable set simply has no signer available (fine for read-only commands).
const ROLE_ENV_VARS = {
  deployer: 'CYPRUS1_PK', // the account that sends `deploy`; never one of the 3 owners
  owner1: 'CYPRUS1_OWNER1_PK',
  owner2: 'CYPRUS1_OWNER2_PK',
  owner3: 'CYPRUS1_OWNER3_PK',
  app: 'CYPRUS1_APP_PK',
  network: 'CYPRUS1_NETWORK_PK',
  outside: 'CYPRUS1_OUTSIDE_PK',
  baseline: 'CYPRUS1_BASELINE_PK',
}

function assertSafeChainId(chainId) {
  if (chainId === MAINNET_CHAIN_ID) {
    throw new Error(
      'refusing to use chain id ' + MAINNET_CHAIN_ID + ': that is Quai MAINNET. ' +
      'This project only ever talks to Orchard Cyprus-1 (chain id ' + EXPECTED_CHAIN_ID + ').'
    )
  }
  if (chainId !== EXPECTED_CHAIN_ID) {
    throw new Error(
      'CHAIN_ID=' + chainId + ' is not Orchard Cyprus-1 (expected ' + EXPECTED_CHAIN_ID + '). Refusing to connect.'
    )
  }
}

async function connect(quais, mode) {
  if (mode !== 'cyprus1') {
    throw new Error('NETWORK=' + mode + ' is not supported. Use NETWORK=localhost or NETWORK=cyprus1.')
  }

  const rawChainId = process.env.CHAIN_ID
  const chainId = Number(rawChainId)
  if (!rawChainId || !Number.isInteger(chainId) || chainId <= 0) {
    throw new Error('CHAIN_ID is not set to a whole number (see .env.dist). Expected ' + EXPECTED_CHAIN_ID + '.')
  }
  assertSafeChainId(chainId) // checked from the env var alone: no network needed to refuse mainnet

  const rpcUrl = process.env.RPC_URL
  if (!rpcUrl) throw new Error('RPC_URL is not set (see .env.dist)')

  // A fixed request timeout means an unreachable or filtered RPC fails quickly instead of
  // hanging on the operating system's own, much longer, connection timeout. staticNetwork
  // stops the provider from repeatedly re-detecting the network on every call (the same
  // reason local.js sets it for the local node).
  const request = new quais.FetchRequest(rpcUrl)
  request.timeout = 8000
  const provider = new quais.JsonRpcProvider(request, undefined, {
    staticNetwork: quais.Network.from(chainId),
    usePathing: true,
  })

  const wallets = {} // role -> quais.Wallet
  const byAddress = {} // lowercase address -> quais.Wallet
  for (const [role, envName] of Object.entries(ROLE_ENV_VARS)) {
    const pk = process.env[envName]
    if (!pk) continue // this role's key was not configured: fine for read-only use
    let wallet
    try {
      wallet = new quais.Wallet(pk, provider)
    } catch (e) {
      // Never let the library's own error message repeat the bad key value.
      throw new Error('the private key in ' + envName + ' is not a valid key (its value is never shown)')
    }
    wallets[role] = wallet
    byAddress[wallet.address.toLowerCase()] = wallet
  }

  const roleAddress = {} // role -> address, for commands that need to know WHICH role an address is
  for (const [role, wallet] of Object.entries(wallets)) roleAddress[role] = wallet.address

  return {
    mode: 'cyprus1',
    network: 'Quai Orchard testnet (Cyprus-1)',
    chainId,
    provider,
    quais,
    roleAddress,
    shard: quais.Shard.Cyprus1, // quais block queries take the shard as their first argument

    async accounts() {
      return Object.values(wallets).map((w) => w.address)
    },

    async hasSigner(address) {
      return Boolean(byAddress[String(address).toLowerCase()])
    },

    async signerFor(address) {
      const wallet = byAddress[String(address).toLowerCase()]
      if (!wallet) {
        throw new Error(
          'no private key is configured for address ' + address + ' (set the matching CYPRUS1_*_PK in .env)'
        )
      }
      return wallet
    },

    async startIntervalMining() {
      throw new Error('startIntervalMining is a local-testing-only feature; there is no such thing on a real chain')
    },

    // NOT called at connect time, on purpose: offline checks (addresses, mainnet refusal,
    // argument checks) must never need a reachable RPC. Commands that are about to really
    // read or send something call this first.
    async verifyReachable() {
      let reported
      try {
        reported = Number(BigInt(await provider.send('eth_chainId', [])))
      } catch (e) {
        throw new Error('cannot reach the Quai RPC at the configured URL')
      }
      if (reported !== chainId) {
        throw new Error('chain id mismatch: the RPC reports ' + reported + ', expected ' + chainId)
      }
    },

    close() {
      if (provider && provider.destroy) provider.destroy()
    },
  }
}

module.exports = { connect, assertSafeChainId, MAINNET_CHAIN_ID, EXPECTED_CHAIN_ID, ROLE_ENV_VARS }
