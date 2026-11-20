'use strict'
// Local mode: talks to a Hardhat node on THIS machine only.
//
// No private key is needed anywhere. The local node unlocks its own test
// accounts, so provider.getSigner(address) can send transactions for them.
// Accounts 0-2 are the 3 registry owners, 3-5 are the 3 witnesses' anchor accounts.

const LOCAL_HOSTS = new Set(['127.0.0.1', 'localhost', '[::1]', '::1'])

async function connect(ethers) {
  const url = process.env.LOCAL_RPC_URL || 'http://127.0.0.1:8545'
  const host = new URL(url).hostname
  if (!LOCAL_HOSTS.has(host)) {
    throw new Error('refusing to use host "' + host + '": localhost mode only talks to this machine')
  }
  const chainId = Number(process.env.LOCAL_CHAIN_ID || 31337)

  // A fixed network + a request timeout means a dead node gives an error quickly
  // instead of ethers retrying forever.
  const request = new ethers.FetchRequest(url)
  request.timeout = 15000
  const provider = new ethers.JsonRpcProvider(request, chainId, {
    staticNetwork: ethers.Network.from(chainId),
    batchMaxCount: 1,
  })

  let reported
  try {
    reported = Number(BigInt(await provider.send('eth_chainId', [])))
  } catch (e) {
    provider.destroy()
    throw new Error('cannot reach the local chain at ' + url)
  }
  if (reported !== chainId) {
    provider.destroy()
    throw new Error('chain id mismatch: node says ' + reported + ', expected ' + chainId)
  }

  return {
    mode: 'localhost',
    provider,
    chainId,
    async accounts() {
      return (await provider.send('eth_accounts', [])).map((a) => ethers.getAddress(a))
    },
    async signerFor(address) {
      return provider.getSigner(address)
    },
    // The node mines a block per transaction. Interval mining also adds a block
    // every `ms`, so confirmations keep growing like on a real chain.
    async startIntervalMining(ms) {
      await provider.send('evm_setIntervalMining', [ms])
    },
    close() {
      provider.destroy()
    },
  }
}

module.exports = { connect }
