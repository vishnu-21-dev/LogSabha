'use strict'
// Test harness for chain/cli.js in Quai mode, with a FAKE provider and a FAKE contract. No network
// is ever reached and no real key is ever used: the "signers" are just addresses. Run by
// test_chain_quai_mock.py as:  node quai_mock_harness.js <scenario> [--dry-run]
// Prints ONE line of JSON: { result | error, calls, prompts }.
const path = require('path')
const fs = require('fs')

const REPO = path.join(__dirname, '..', '..')
const quais = require(path.join(REPO, 'Solidity', 'node_modules', 'quais'))
const scenario = process.argv[2]
// cli.js reads --dry-run straight from process.argv, so it is left in place for it.

const cli = require(path.join(REPO, 'chain', 'cli.js'))

// ------------------------------------------------------------------ addresses (fixed, offline)
function grind(label) {
  for (let i = 0; i < 200000; i++) {
    const pk = quais.keccak256(quais.toUtf8Bytes('mock-' + label + '-' + i))
    const addr = quais.computeAddress(pk)
    if (quais.getZoneForAddress(addr) === quais.Zone.Cyprus1 && quais.isQuaiAddress(addr)) return addr
  }
  throw new Error('could not grind an address')
}
const A = {
  deployer: grind('deployer'), owner1: grind('owner1'), owner2: grind('owner2'), owner3: grind('owner3'),
  app: grind('app'), network: grind('network'), outside: grind('outside'),
}
const REGISTRY = grind('registry')
const ZERO32 = '0x' + '00'.repeat(32)

// ------------------------------------------------------------------ fake chain state
const calls = [] // every transaction the fake chain was asked to send
const chain = { witnesses: {}, approvals: {}, anchors: {}, logs: [], block: 1000 }

function newTx(method, from, args) {
  chain.block += 1
  const hash = '0x' + chain.block.toString(16).padStart(64, '0')
  calls.push({ method, from, args: args.map(String) })
  return {
    hash,
    wait: async () => ({ status: 1, blockNumber: chain.block, gasUsed: BigInt(100000 + chain.block), hash }),
  }
}

class FakeContract {
  constructor(address, abi, runner) {
    this.address = address
    this.runner = runner
    this.filters = {
      Anchored: (id, batchNo) => ({ event: 'Anchored', id, batchNo }),
      WitnessRegistered: () => ({ event: 'WitnessRegistered' }),
      WitnessSilent: () => ({ event: 'WitnessSilent' }),
      PauseBegun: () => ({ event: 'PauseBegun' }),
      PauseEnded: () => ({ event: 'PauseEnded' }),
    }
    const self = this
    const method = (name, fn) => {
      const f = (...args) => fn.call(self, ...args)
      f.estimateGas = async () => 90000n
      this[name] = f
    }
    method('registerWitness', function (id, acct, key, gap) {
      const from = this.runner.address
      if (!Object.values(A).slice(1, 4).includes(from)) throw new Error('not an owner')
      const fp = [id, acct, key, gap].join('|')
      const set = (chain.approvals[fp] = chain.approvals[fp] || new Set())
      set.add(from)
      const tx = newTx('registerWitness', from, [id, acct, key, gap])
      if (set.size >= 2) {
        chain.witnesses[id] = { anchorAccount: acct, edPubKey: key, active: true, lastBatchNo: 0, lastSeq: 0 }
        chain.logs.push({ event: 'WitnessRegistered', args: { id }, transactionHash: tx.hash })
      }
      return tx
    })
    method('anchor', function (batchNo, er, rr, ph, fs_, ls) {
      const from = this.runner.address
      const w = Object.values(chain.witnesses).find((x) => x.anchorAccount === from)
      if (!w) throw new Error('only the witness account may anchor')
      const tx = newTx('anchor', from, [batchNo, er, rr, ph, fs_, ls])
      w.lastBatchNo = batchNo
      w.lastSeq = ls
      const id = Object.keys(chain.witnesses).find((k) => chain.witnesses[k] === w)
      chain.anchors[id + ':' + batchNo] = { entriesRoot: er, receiptsRoot: rr, policyHash: ph, firstSeq: fs_, lastSeq: ls, blockTime: 1700000000 + batchNo }
      chain.logs.push({ event: 'Anchored', args: { batchNo, restart: false }, id, transactionHash: tx.hash, blockNumber: chain.block })
      return tx
    })
    method('flagSilence', function (id) {
      return newTx('flagSilence', this.runner.address, [id])
    })
    method('beginPause', function (id, reason, until) {
      return newTx('beginPause', this.runner.address, [id, reason, until])
    })
    this.witnesses = async (id) => {
      const w = chain.witnesses[id]
      return w
        ? { ...w, maxGapSeconds: 600, lastSeenBlockTime: 1700000000 }
        : { anchorAccount: '0x' + '00'.repeat(20), edPubKey: ZERO32, active: false, maxGapSeconds: 0, lastSeenBlockTime: 0, lastBatchNo: 0, lastSeq: 0 }
    }
    this.anchors = async (id, n) =>
      chain.anchors[id + ':' + n] || { entriesRoot: ZERO32, receiptsRoot: ZERO32, policyHash: ZERO32, firstSeq: 0, lastSeq: 0, blockTime: 0 }
    this.pauseCount = async () => 1
    this.queryFilter = async (filter) =>
      chain.logs.filter((l) => l.event === filter.event && (!filter.id || l.id === filter.id || (l.args && l.args.id === filter.id)))
        .map((l) => ({ ...l, args: { ...l.args, id: l.args.id || l.id } }))
    this.connect = (runner) => new FakeContract(address, abi, runner)
  }
}

class FakeFactory {
  constructor(abi, bytecode, signer, ipfsHash) { this.signer = signer; this.ipfsHash = ipfsHash }
  async getDeployTransaction() { return { data: '0x' } }
  async deploy(owners) {
    if (!this.ipfsHash) throw new Error('IPFSHash is null not set or not 46 characters long')
    const tx = newTx('deploy', this.signer.address, [owners.join(','), 'ipfs:' + this.ipfsHash])
    return {
      waitForDeployment: async () => {},
      deploymentTransaction: () => ({ hash: tx.hash, wait: tx.wait }),
      getAddress: async () => REGISTRY,
    }
  }
}

// A provider where the SHARD argument is mandatory, like quais: asking the ethers way fails.
const provider = {
  getBlockNumber: async (shard) => {
    if (shard !== quais.Shard.Cyprus1) throw new Error('getBlockNumber needs a shard')
    return chain.block
  },
  getBlock: async (shard, tag) => {
    if (shard !== quais.Shard.Cyprus1) throw new Error('getBlock needs a shard first')
    return { woHeader: { timestamp: String(1700000000 + 5) }, tag }
  },
  getTransactionReceipt: async (hash) => ({ status: 1, blockNumber: chain.block - 2, gasUsed: 123456n, hash }),
  estimateGas: async () => 555000n,
}

const GOOD_HASH = 'Qm' + 'a'.repeat(44)
let uploads = 0

function makeNet(opts = {}) {
  const roles = opts.roles || ['deployer', 'owner1', 'owner2', 'owner3', 'app', 'network', 'outside']
  const roleAddress = {}
  for (const r of roles) roleAddress[r] = opts.override && opts.override[r] ? opts.override[r] : A[r]
  const have = new Set(Object.values(roleAddress).map((a) => a.toLowerCase()))
  const fakeQuais = Object.create(quais)
  Object.defineProperty(fakeQuais, 'Contract', { value: FakeContract })
  Object.defineProperty(fakeQuais, 'ContractFactory', { value: FakeFactory })
  return {
    mode: 'cyprus1', network: 'Quai Orchard testnet (Cyprus-1)', chainId: 15000, quais: fakeQuais,
    provider, shard: quais.Shard.Cyprus1, roleAddress,
    localIpfsHash: () => (opts.localHash === undefined ? 'Qm' + 'b'.repeat(44) : opts.localHash),
    pushMetadata: async (name) => { uploads += 1; calls.push({ method: 'uploadMetadata', from: name, args: [] }); return opts.hash === undefined ? GOOD_HASH : opts.hash },
    async accounts() { return Object.values(roleAddress) },
    async hasSigner(a) { return have.has(String(a).toLowerCase()) },
    async signerFor(a) {
      if (!have.has(String(a).toLowerCase())) throw new Error('no key')
      return { address: a }
    },
  }
}

// A deployment as the real deploy would have written it.
function writeDeployment() {
  const file = cli.deploymentFile()
  fs.writeFileSync(file, JSON.stringify({
    network: 'cyprus1', chainId: 15000, registry: REGISTRY, deployBlock: 1, owners: [A.owner1, A.owner2, A.owner3], witnesses: {},
  }))
  return file
}

const KEY = '0x' + 'ab'.repeat(32)
const ROOT = '0x' + 'cd'.repeat(32)
const anchorInput = (n) => ({ witnessId: 'app', batchNo: n, firstSeq: 1, lastSeq: 5, entriesRoot: ROOT, receiptsRoot: ROOT, policyHash: ROOT })

async function register(net, id = 'app', extra = {}) {
  return cli.registerWitness(net, { id, edPubKey: KEY, ...extra })
}

const scenarios = {
  deployment_file_names: async () => {
    const out = {}
    const saved = { n: process.env.NETWORK, f: process.env.CHAIN_DEPLOYMENT_FILE }
    delete process.env.CHAIN_DEPLOYMENT_FILE
    process.env.NETWORK = 'cyprus1'
    out.cyprus1 = path.basename(cli.deploymentFile())
    delete process.env.NETWORK
    out.localhost = path.basename(cli.deploymentFile())
    return out
  },
  deploy: async () => cli.deploy(makeNet({ roles: ['deployer', 'app', 'network', 'outside'] }), { owners: [A.owner1, A.owner2, A.owner3] }),
  deploy_upload_fails: async () => cli.deploy(makeNet({ roles: ['deployer'], hash: '' }), { owners: [A.owner1, A.owner2, A.owner3] }),
  deploy_no_hash_at_all: async () => cli.deploy(makeNet({ roles: ['deployer'], hash: '', localHash: '' }), { owners: [A.owner1, A.owner2, A.owner3] }),
  register_two_owners: async () => { const net = makeNet(); writeDeployment(); return register(net) },
  register_step: async () => { const net = makeNet(); writeDeployment(); return register(net, 'app', { step: 2 }) },
  register_unconfigured_role: async () => { const net = makeNet({ roles: ['deployer', 'owner1', 'owner2', 'owner3', 'app'] }); writeDeployment(); return register(net, 'baseline') },
  register_witness_is_owner: async () => { const net = makeNet({ override: { app: A.owner1 } }); writeDeployment(); return register(net) },
  register_witness_is_deployer: async () => { const net = makeNet({ override: { app: A.deployer } }); writeDeployment(); return register(net) },
  register_one_owner_key: async () => { const net = makeNet({ roles: ['deployer', 'owner1', 'app'] }); writeDeployment(); return register(net) },
  register_then_anchor: async () => {
    const net = makeNet(); writeDeployment()
    await register(net)
    return cli.anchor(net, anchorInput(1))
  },
  anchor_then_read: async () => {
    const net = makeNet(); writeDeployment()
    await register(net)
    await cli.anchor(net, anchorInput(1))
    const read = await cli.readAnchors(net, 'app', 1, 3)
    const witness = await cli.readWitness(net, ['app', 'ghost'])
    const conf = await cli.confirmations(net, '0x' + '11'.repeat(32))
    const events = await cli.readEvents(net)
    return { read, witness, conf, events }
  },
  admin_pause: async () => { const net = makeNet(); writeDeployment(); await register(net); return cli.admin(net, { action: 'beginPause', witnessId: 'app', seconds: 60 }) },
  admin_flag: async () => { const net = makeNet(); writeDeployment(); await register(net); return cli.admin(net, { action: 'flagSilence', witnessId: 'app' }) },
}

async function main() {
  // A quick way to see which prompts were shown: they go to stderr as text, the harness prints calls.
  try {
    const result = await scenarios[scenario]()
    process.stdout.write(JSON.stringify({ result, calls }, (k, v) => (typeof v === 'bigint' ? v.toString() : v)) + '\n')
  } catch (e) {
    process.stdout.write(JSON.stringify({ error: String(e.message || e), calls }) + '\n')
  }
  process.exit(0)
}

// Addresses the test file needs to compare against.
if (scenario === 'addresses') {
  process.stdout.write(JSON.stringify({ ...A, registry: REGISTRY }) + '\n')
  process.exit(0)
}
main()
