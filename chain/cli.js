#!/usr/bin/env node
'use strict'
/*
 * Chain helper: a small JSON command line that Python calls.
 *
 *   node chain/cli.js setup-local   '<json>'   deploy WitnessRegistry + register the 3 witnesses
 *   node chain/cli.js anchor        '<json>'   send one anchor from the witness's own account
 *   node chain/cli.js confirmations <txhash>   how many blocks since the transaction
 *   node chain/cli.js readAnchors   <witnessId> <fromBatch> <toBatch>
 *   node chain/cli.js readWitness   [<witnessId> ...]   registered Ed25519 public key of each witness
 *                                                        (no names given: every witness registered on the chain)
 *
 * The JSON argument may also be sent on stdin (the Python side does that, so there are
 * no quoting problems). Output is ONE line of JSON: {"ok":true,...} or {"ok":false,"error":"..."}.
 *
 * NETWORK (from the environment or ../.env) picks the mode. Only "localhost" works for now.
 */
const fs = require('fs')
const path = require('path')

// ethers and dotenv: use chain/node_modules if present, else the ones in Solidity/node_modules.
function load(name) {
  try {
    return require(name)
  } catch (e) {
    if (e.code !== 'MODULE_NOT_FOUND') throw e
    return require(path.join(__dirname, '..', 'Solidity', 'node_modules', name))
  }
}
const ethers = load('ethers')
try {
  // Existing environment variables win over .env. Nothing from .env is ever printed.
  load('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true })
} catch (e) {
  /* no dotenv or no .env: fine */
}

const EMPTY_ROOT = ethers.sha256('0x') // root of an empty Merkle tree

function print(obj) {
  process.stdout.write(JSON.stringify(obj, (k, v) => (typeof v === 'bigint' ? v.toString() : v)) + '\n')
}

function errorText(e) {
  return String((e && (e.reason || e.shortMessage || e.message)) || e).slice(0, 300)
}

async function readJson(arg) {
  let text = arg
  if (text === undefined) {
    text = await new Promise((resolve) => {
      let data = ''
      process.stdin.setEncoding('utf8')
      process.stdin.on('data', (c) => (data += c))
      process.stdin.on('end', () => resolve(data))
    })
  }
  return text.trim() ? JSON.parse(text) : {}
}

function hex32(value, label) {
  let x = String(value)
  if (!x.startsWith('0x')) x = '0x' + x
  if (!/^0x[0-9a-fA-F]{64}$/.test(x)) throw new Error(label + ' must be 32 bytes of hex')
  return x.toLowerCase()
}

function loadArtifact() {
  const file =
    process.env.CHAIN_ARTIFACT ||
    path.join(__dirname, '..', 'Solidity', 'artifacts', 'contracts', 'WitnessRegistry.sol', 'WitnessRegistry.json')
  if (!fs.existsSync(file)) throw new Error('contract not compiled yet: run "npx hardhat compile" in Solidity/')
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

function deploymentFile() {
  return process.env.CHAIN_DEPLOYMENT_FILE || path.join(__dirname, 'deployment.localhost.json')
}

function loadDeployment() {
  const file = deploymentFile()
  if (!fs.existsSync(file)) throw new Error('no deployment file: run setup-local first')
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

async function connect() {
  const mode = process.env.NETWORK || 'localhost'
  if (mode !== 'localhost') return require('./quai').connect(ethers, mode) // stub: throws
  return require('./local').connect(ethers)
}

function registryAt(net, address, signerOrProvider) {
  return new ethers.Contract(address, loadArtifact().abi, signerOrProvider || net.provider)
}

// ------------------------------------------------------------ setup-local
async function setupLocal(net, input) {
  const names = Object.keys(input.witnesses || {})
  if (names.length !== 3) throw new Error('setup-local needs exactly 3 witnesses: {"witnesses":{"app":"<ed25519 public key hex>",...}}')

  const accounts = await net.accounts()
  if (accounts.length < 6) throw new Error('the local chain needs at least 6 accounts, found ' + accounts.length)
  const owners = accounts.slice(0, 3)
  const anchorAccounts = accounts.slice(3, 6)
  if (new Set([...owners, ...anchorAccounts].map((a) => a.toLowerCase())).size !== 6) {
    throw new Error('owners and witness accounts must be 6 different accounts')
  }

  const art = loadArtifact()
  const ownerSigners = []
  for (const a of owners) ownerSigners.push(await net.signerFor(a))

  const factory = new ethers.ContractFactory(art.abi, art.bytecode, ownerSigners[0])
  const reg = await factory.deploy(owners)
  await reg.waitForDeployment()
  const deployReceipt = await reg.deploymentTransaction().wait()
  const registry = await reg.getAddress()

  const maxGap = input.maxGapSeconds === undefined ? 600 : Number(input.maxGapSeconds)
  const witnesses = {}
  for (let i = 0; i < names.length; i++) {
    const name = names[i]
    const id = ethers.encodeBytes32String(name)
    const edPubKey = hex32(input.witnesses[name], 'public key of ' + name)
    const args = [id, anchorAccounts[i], edPubKey, maxGap]
    // 2 of 3 owners must send the same call: the first only records approval, the second runs it.
    await (await reg.connect(ownerSigners[0]).registerWitness(...args)).wait()
    await (await reg.connect(ownerSigners[1]).registerWitness(...args)).wait()
    const w = await reg.witnesses(id)
    if (!w.active) throw new Error('registration of ' + name + ' did not go through')
    witnesses[name] = { id, anchorAccount: anchorAccounts[i], edPubKey }
  }

  await net.startIntervalMining(Number(input.blockIntervalMs || 1000))

  const deployment = {
    network: net.mode,
    chainId: net.chainId,
    registry,
    deployBlock: deployReceipt.blockNumber,
    owners,
    witnesses,
  }
  fs.writeFileSync(deploymentFile(), JSON.stringify(deployment, null, 2)) // addresses only, no keys
  return { ok: true, ...deployment, deploymentFile: deploymentFile() }
}

// ------------------------------------------------------------------ anchor
async function anchor(net, input) {
  const dep = loadDeployment()
  const reg = registryAt(net, dep.registry)
  const id = ethers.encodeBytes32String(String(input.witnessId))
  const batchNo = Number(input.batchNo)
  const firstSeq = Number(input.firstSeq)
  const lastSeq = Number(input.lastSeq)
  const entriesRoot = hex32(input.entriesRoot, 'entriesRoot')
  const receiptsRoot = hex32(input.receiptsRoot, 'receiptsRoot')
  const policyHash = hex32(input.policyHash, 'policyHash')

  const w = await reg.witnesses(id)
  if (!w.active) throw new Error('witness "' + input.witnessId + '" is not registered or not active')
  const lastBatchNo = Number(w.lastBatchNo)

  if (!input.skipPrecheck) {
    // Safe to repeat: if this exact anchor is already on chain (for example the answer got
    // lost after the transaction landed), return the existing transaction instead of sending again.
    if (batchNo <= lastBatchNo) {
      const s = await reg.anchors(id, batchNo)
      const same =
        s.entriesRoot === entriesRoot && s.receiptsRoot === receiptsRoot && s.policyHash === policyHash &&
        Number(s.firstSeq) === firstSeq && Number(s.lastSeq) === lastSeq
      if (!same) throw new Error('conflict: batch ' + batchNo + ' is already anchored with different content')
      const logs = await reg.queryFilter(reg.filters.Anchored(id, batchNo), dep.deployBlock || 0)
      if (!logs.length) throw new Error('batch ' + batchNo + ' is on chain but its event was not found')
      return { ok: true, alreadyAnchored: true, txHash: logs[0].transactionHash, blockNumber: logs[0].blockNumber }
    }
    if (batchNo > lastBatchNo + 1) {
      throw new Error('out of order: the next batch the chain expects is ' + (lastBatchNo + 1))
    }
  }

  // The witness's OWN account sends it (the contract only accepts that account).
  const signer = await net.signerFor(w.anchorAccount)
  const method = input.restart ? 'anchorRestart' : 'anchor'
  const tx = await reg.connect(signer)[method](batchNo, entriesRoot, receiptsRoot, policyHash, firstSeq, lastSeq)
  const receipt = await tx.wait(1, 60000)
  return {
    ok: true,
    alreadyAnchored: false,
    txHash: tx.hash,
    blockNumber: receipt.blockNumber,
    gasUsed: receipt.gasUsed.toString(),
  }
}

// ----------------------------------------------------------- confirmations
async function confirmations(net, txHash) {
  const receipt = await net.provider.getTransactionReceipt(txHash)
  if (!receipt) return { ok: true, confirmations: 0 }
  if (receipt.status !== 1) throw new Error('transaction failed on chain')
  const latest = await net.provider.getBlockNumber()
  return { ok: true, confirmations: latest - receipt.blockNumber + 1, blockNumber: receipt.blockNumber, latestBlock: latest }
}

// ------------------------------------------------------------- readAnchors
async function readAnchors(net, witnessId, fromBatch, toBatch) {
  const dep = loadDeployment()
  const reg = registryAt(net, dep.registry)
  const id = ethers.encodeBytes32String(String(witnessId))
  const logs = await reg.queryFilter(reg.filters.Anchored(id), dep.deployBlock || 0)
  const byBatch = new Map(logs.map((l) => [Number(l.args.batchNo), l]))

  const anchors = []
  for (let n = Number(fromBatch); n <= Number(toBatch); n++) {
    const a = await reg.anchors(id, n)
    if (Number(a.blockTime) === 0) continue // nothing anchored under this number
    const log = byBatch.get(n)
    const receipt = log ? await net.provider.getTransactionReceipt(log.transactionHash) : null
    anchors.push({
      batchNo: n,
      entriesRoot: a.entriesRoot,
      receiptsRoot: a.receiptsRoot,
      policyHash: a.policyHash,
      firstSeq: Number(a.firstSeq),
      lastSeq: Number(a.lastSeq),
      blockTime: Number(a.blockTime),
      restart: log ? log.args.restart : null,
      txHash: log ? log.transactionHash : null,
      blockNumber: log ? log.blockNumber : null,
      gasUsed: receipt ? receipt.gasUsed.toString() : null,
    })
  }
  const w = await reg.witnesses(id)
  return { ok: true, witnessId, lastBatchNo: Number(w.lastBatchNo), lastSeq: Number(w.lastSeq), anchors, emptyRoot: EMPTY_ROOT }
}

// ------------------------------------------------------------- readWitness
// The verifier takes witness public keys from HERE (the chain), never from an evidence bundle.
async function readWitness(net, names) {
  const dep = loadDeployment()
  const reg = registryAt(net, dep.registry)
  let list = names
  if (!list.length) {
    const logs = await reg.queryFilter(reg.filters.WitnessRegistered(), dep.deployBlock || 0)
    list = [...new Set(logs.map((l) => ethers.decodeBytes32String(l.args.id)))]
  }
  const witnesses = {}
  for (const name of list) {
    const w = await reg.witnesses(ethers.encodeBytes32String(String(name)))
    const registered = w.edPubKey !== ethers.ZeroHash
    witnesses[name] = {
      registered,
      active: registered && Boolean(w.active),
      edPubKey: registered ? w.edPubKey.slice(2) : null, // 64 hex characters, no 0x
      anchorAccount: registered ? w.anchorAccount : null,
      maxGapSeconds: Number(w.maxGapSeconds),
      lastBatchNo: Number(w.lastBatchNo),
      lastSeq: Number(w.lastSeq),
    }
  }
  return { ok: true, registry: dep.registry, witnesses }
}

// -------------------------------------------------------------------- main
async function main() {
  const [command, arg1, arg2, arg3] = process.argv.slice(2)
  const names = process.argv.slice(3)
  let net
  try {
    net = await connect()
    let result
    if (command === 'setup-local') result = await setupLocal(net, await readJson(arg1))
    else if (command === 'anchor') result = await anchor(net, await readJson(arg1))
    else if (command === 'confirmations') result = await confirmations(net, arg1 || (await readJson()).txHash)
    else if (command === 'readAnchors') result = await readAnchors(net, arg1, arg2, arg3)
    else if (command === 'readWitness') result = await readWitness(net, names)
    else throw new Error('unknown command "' + command + '". Use: setup-local, anchor, confirmations, readAnchors, readWitness')
    print(result)
    return 0
  } catch (e) {
    print({ ok: false, error: errorText(e) })
    return 1
  } finally {
    if (net) net.close()
  }
}

main().then((code) => process.exit(code))
