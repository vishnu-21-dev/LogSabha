#!/usr/bin/env node
'use strict'
/*
 * Chain helper: a small JSON command line that Python calls.
 *
 *   node chain/cli.js setup-local   '<json>'   LOCAL ONLY: deploy WitnessRegistry + register the 3 witnesses
 *   node chain/cli.js deploy        '<json>'   deploy WitnessRegistry with 3 owner addresses (Quai mode only)
 *   node chain/cli.js registerWitness '<json>'  register ONE MORE witness on an EXISTING deployment
 *                                                 (for example a baseline). Needs 2 of the 3 owners,
 *                                                 same as setup-local; the contract itself is unchanged.
 *                                                 On Quai, "step":1 or 2 sends just that owner's transaction
 *                                                 (admin beginPause/endPause take "step" too).
 *   node chain/cli.js anchor        '<json>'   send one anchor from the witness's own account
 *   node chain/cli.js confirmations <txhash>   how many blocks since the transaction
 *   node chain/cli.js readAnchors   <witnessId> <fromBatch> <toBatch>
 *   node chain/cli.js readEvents    [<witnessId>]   WitnessSilent flags and planned pauses, with block times
 *   node chain/cli.js admin         '<json>'        flagSilence / beginPause / endPause (LOCAL TEST SUPPORT on
 *                                                     localhost; on Quai mode these are real, confirmed sends)
 *   node chain/cli.js readWitness   [<witnessId> ...]   registered Ed25519 public key of each witness
 *                                                        (no names given: every witness registered on the chain)
 *
 * The JSON argument may also be sent on stdin (the Python side does that, so there are
 * no quoting problems). Output is ONE line of JSON: {"ok":true,...} or {"ok":false,"error":"..."}.
 *
 * NETWORK (from the environment or ../.env) picks the mode: "localhost" (ethers, a local Hardhat
 * node, as before) or "cyprus1" (quais.js, the real Quai Orchard testnet, chain id 15000 only --
 * mainnet, chain id 9000, is refused unconditionally).
 *
 * A --dry-run flag (anywhere on the command line) prints what a Quai command WOULD do -- network,
 * chain id, sender, contract address, estimated gas -- and sends nothing. Without it, every
 * state-changing command on Quai mode prints that same summary and then asks for a typed "yes" on
 * stdin before it sends anything; localhost mode never asks (it is for automated local testing).
 * Keys come only from named environment variables (see chain/quai.js); their values are never
 * printed, logged, or put in an error message.
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
  // One file per network, so a Quai deployment can never overwrite the local one (and the
  // other way round). Both match the chain/deployment*.json rule in .gitignore.
  const network = process.env.NETWORK || 'localhost'
  return process.env.CHAIN_DEPLOYMENT_FILE || path.join(__dirname, 'deployment.' + network + '.json')
}

function loadDeployment() {
  const file = deploymentFile()
  if (!fs.existsSync(file)) throw new Error('no deployment file: run setup-local first')
  return JSON.parse(fs.readFileSync(file, 'utf8'))
}

async function connect() {
  const mode = process.env.NETWORK || 'localhost'
  if (mode !== 'localhost') return require('./quai').connect(load('quais'), mode)
  return require('./local').connect(ethers)
}

const isQuai = (net) => net.mode === 'cyprus1'

// Quai mode uses quais' own Contract (Quai's RPC is zone-aware); localhost keeps ethers.
function registryAt(net, address, signerOrProvider) {
  const Contract = isQuai(net) ? net.quais.Contract : ethers.Contract
  return new Contract(address, loadArtifact().abi, signerOrProvider || net.provider)
}

// quais block queries take the shard as their first argument; ethers ones do not.
function latestBlockNumber(net) {
  return isQuai(net) ? net.provider.getBlockNumber(net.shard) : net.provider.getBlockNumber()
}
function getBlockAt(net, tag) {
  return isQuai(net) ? net.provider.getBlock(net.shard, tag) : net.provider.getBlock(tag)
}
// ethers blocks have .timestamp; quais keeps it in the header.
function blockTime(block) {
  const t = block.timestamp !== undefined ? block.timestamp
    : block.woHeader && block.woHeader.timestamp !== undefined ? block.woHeader.timestamp
    : block.header && block.header.timestamp
  return Number(t)
}

// Wait for a sent transaction to be mined and make sure it did not fail.
async function mined(tx) {
  const receipt = await tx.wait(1, 120000)
  if (!receipt) throw new Error('transaction ' + tx.hash + ' was not confirmed in time')
  if (receipt.status !== undefined && receipt.status !== null && Number(receipt.status) !== 1) {
    throw new Error('transaction ' + tx.hash + ' failed on chain')
  }
  return receipt
}

// Wait for a sent transaction, then report its hash, block and gas used (from the receipt).
async function sentInfo(tx) {
  const receipt = await mined(tx)
  return { txHash: tx.hash, blockNumber: receipt.blockNumber, gasUsed: receipt.gasUsed.toString() }
}

// Runs several sends. Localhost: just sends, no summary, no prompt, no extra RPC call (unchanged).
// Quai: every step gets its own summary (with ITS sender) and its own typed "yes"; --dry-run
// prints each summary and sends nothing. `finish` builds the answer after the last send.
async function runSteps(net, steps, finish, only) {
  // `only` (1-based) sends just that one step, so each owner transaction can be approved and run on its own.
  const chosen = only ? [steps[Number(only) - 1]] : steps
  if (chosen.some((x) => !x)) throw new Error('there is no step ' + only + ' (this command has ' + steps.length + ')')
  const results = []
  if (!isQuai(net)) {
    for (const s of chosen) results.push(await s.send())
    return finish && !only ? finish(results[results.length - 1], results) : results[results.length - 1]
  }
  const summaries = []
  for (const s of chosen) {
    const r = await runWithConfirmation(net, s, s.send)
    if (DRY_RUN) summaries.push(r.summary)
    else results.push(r)
  }
  if (DRY_RUN) return { ok: true, dryRun: true, summary: summaries[0], summaries }
  const last = results[results.length - 1]
  if (only) return { ok: true, partial: true, step: Number(only), ...last }
  return finish ? finish(last, results) : last
}

// The first `count` owners we can sign for. Localhost: the first owners, as before. Quai: owner
// keys are separate variables, so use whichever owners have a key configured.
async function ownerSignerList(net, dep, count) {
  const list = []
  for (const o of dep.owners) {
    if (isQuai(net) && !(await net.hasSigner(o))) continue
    list.push({ address: o, signer: await net.signerFor(o) })
    if (list.length === count) return list
  }
  throw new Error('need ' + count + ' owner keys but only ' + list.length +
    ' are configured (CYPRUS1_OWNER1_PK, CYPRUS1_OWNER2_PK, CYPRUS1_OWNER3_PK in .env)')
}

// ----------------------------------------------------------------- --dry-run
// Recognised anywhere on the command line, then removed so command/argument
// parsing below never sees it.
const DRY_RUN = process.argv.includes('--dry-run')
if (DRY_RUN) process.argv = process.argv.filter((a) => a !== '--dry-run')

// One typed line of input, read without ever printing a prompt echo of secrets
// (there are none to echo here: this only ever asks "yes" or not). Resolves
// false on EOF (for example when something runs this non-interactively without
// answering) instead of hanging forever.

// A hard, self-imposed deadline, independent of whatever retry/backoff behavior the network
// library itself has internally (quais can spend a long time trying to discover Quai's shards
// against an unreachable RPC). Used only for the "nice to have" preview values in a dry run.
function withTimeout(promise, ms) {
  let timer
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(new Error('timed out after ' + ms + 'ms')), ms)
  })
  return Promise.race([promise, timeout]).finally(() => clearTimeout(timer))
}

// One shared reader for every prompt in this run, so several typed (or piped) "yes" lines are each
// used for their own prompt and none is lost. null means stdin ended with no more lines.
const stdinQueue = []
let stdinWaiter = null
let stdinEnded = false
let stdinStarted = false
function readStdinLine() {
  if (!stdinStarted) {
    stdinStarted = true
    const rl = require('readline').createInterface({ input: process.stdin, terminal: false })
    rl.on('line', (line) => {
      if (stdinWaiter) {
        const w = stdinWaiter
        stdinWaiter = null
        w(line)
      } else stdinQueue.push(line)
    })
    rl.on('close', () => {
      stdinEnded = true
      if (stdinWaiter) {
        const w = stdinWaiter
        stdinWaiter = null
        w(null)
      }
    })
  }
  if (stdinQueue.length) return Promise.resolve(stdinQueue.shift())
  if (stdinEnded) return Promise.resolve(null)
  return new Promise((resolve) => (stdinWaiter = resolve))
}

async function askYesNo(promptText) {
  process.stderr.write(promptText)
  const line = await readStdinLine()
  return line !== null && line.trim().toLowerCase() === 'yes'
}

function printSummaryToStderr(summary) {
  process.stderr.write(
    '\n' +
      [
        'About to ' + summary.action + ':',
        '  network:        ' + summary.network,
        '  chain id:       ' + summary.chainId,
        '  sender address: ' + summary.sender,
        '  contract:       ' + summary.contract,
        '  estimated gas:  ' + summary.estimatedGas,
      ].join('\n') +
      '\n\n'
  )
}

// Every address that matters for a Quai deployment must really be a Cyprus-1,
// Quai-ledger address (never a Qi address, never another zone), and the roles
// must not overlap: an owner cannot also be the deployer or a witness account.
function checkCyprus1Address(quais, address, label) {
  if (!quais.isAddress(address)) throw new Error(label + ' (' + address + ') is not a valid address')
  if (!quais.isQuaiAddress(address)) throw new Error(label + ' (' + address + ') is a Qi-ledger address, not Quai')
  if (quais.getZoneForAddress(address) !== quais.Zone.Cyprus1) {
    throw new Error(label + ' (' + address + ') is not a Cyprus-1 address')
  }
}

function checkDeployAddresses(quais, { deployer, owners, witnesses }) {
  if (!Array.isArray(owners) || owners.length !== 3) {
    throw new Error('deploy needs exactly 3 owner addresses, got ' + (Array.isArray(owners) ? owners.length : 0))
  }
  checkCyprus1Address(quais, deployer, 'the deployer address')
  owners.forEach((a, i) => checkCyprus1Address(quais, a, 'owner ' + (i + 1)))
  const lower = (a) => String(a).toLowerCase()
  if (new Set(owners.map(lower)).size !== 3) throw new Error('the 3 owner addresses must all be different')
  if (owners.some((a) => lower(a) === lower(deployer))) {
    throw new Error('an owner address must not be the same as the deployer address')
  }
  for (const [name, addr] of Object.entries(witnesses || {})) {
    if (owners.some((a) => lower(a) === lower(addr))) {
      throw new Error('an owner address must not be the same as the ' + name + " witness's account")
    }
  }
}

// Shared by every Quai command that sends a transaction. Prints the summary (network, chain id,
// sender, contract, estimated gas) to stderr, then: --dry-run sends nothing and returns that
// summary; localhost mode sends right away (no prompt: it is for automated local testing);
// real Quai mode asks for a typed "yes" on stdin first and refuses to send without it.
async function runWithConfirmation(net, { action, sender, contract, estimateGas }, send) {
  let estimatedGas = 'unavailable'
  try {
    const g = await withTimeout(estimateGas(), 25000)
    if (g !== undefined && g !== null) estimatedGas = String(g)
  } catch (e) {
    estimatedGas = 'unavailable (' + errorText(e) + ')'
  }
  const summary = { action, network: net.network || net.mode, chainId: net.chainId, sender, contract, estimatedGas }
  printSummaryToStderr(summary)
  if (DRY_RUN) return { ok: true, dryRun: true, summary }
  if (net.mode === 'localhost') return send()
  const confirmed = await askYesNo('Type "yes" to send this on ' + summary.network + ': ')
  if (!confirmed) throw new Error('refused: confirmation was not "yes"; nothing was sent')
  return send()
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

// ------------------------------------------------------------------ deploy
// Uses the hardhat plugin the reference project uses (@quai/hardhat-deploy-metadata) to upload the
// compiled contract's metadata to Quai's own IPFS node and return its hash. Hardhat reads
// Solidity/hardhat.config.js and ../.env itself; nothing from .env is printed here.
async function pushMetadataToIPFS(contractName) {
  const solidityDir = path.join(__dirname, '..', 'Solidity')
  process.chdir(solidityDir)
  const hre = require(path.join(solidityDir, 'node_modules', 'hardhat'))
  return hre.deployMetadata.pushMetadataToIPFS(contractName)
}

// Quai mode only. Owners are given explicitly (there is no "pick a local test account" here):
// {"owners": ["0x...", "0x...", "0x..."]}. No witness is registered by this call; use
// registerWitness afterwards for each one, same as on localhost.
async function deploy(net, input) {
  if (net.mode !== 'cyprus1') {
    throw new Error('deploy is for NETWORK=cyprus1 only; the local test chain uses setup-local instead')
  }
  const owners = Array.isArray(input.owners) ? input.owners.map(String) : input.owners
  const deployerAddress = net.roleAddress && net.roleAddress.deployer
  if (!deployerAddress) {
    throw new Error('no deployer key is configured (set CYPRUS1_PK in .env)')
  }
  // Only the already-validated addresses net.quai built at connect time are used here (never
  // re-reading a key from the environment): app/network/outside/baseline, whichever are configured.
  const { deployer, owner1, owner2, owner3, ...witnessAddresses } = net.roleAddress || {}
  checkDeployAddresses(net.quais, { deployer: deployerAddress, owners, witnesses: witnessAddresses })

  const art = loadArtifact()
  const signer = await net.signerFor(deployerAddress)
  const factory = new net.quais.ContractFactory(art.abi, art.bytecode, signer)

  return runWithConfirmation(
    net,
    {
      action: 'deploy WitnessRegistry with owners ' + owners.join(', ') + ' (first uploads its metadata, i.e. source and ABI, to Quai IPFS at ipfs.qu.ai)',
      sender: deployerAddress,
      // quais picks a salt so the new contract lands in Cyprus-1, so the address is not known before sending.
      contract: 'new contract (its address is set when it is deployed)',
      estimateGas: async () => {
        const tx = await factory.getDeployTransaction(owners)
        // quais needs a `from` to work out which zone to ask.
        return net.provider.estimateGas({ ...tx, from: deployerAddress })
      },
    },
    async () => {
      // quais needs the IPFS hash of the contract's metadata (the reference project does the same).
      // This is the one step that publishes something outside the chain, so it only runs after the "yes".
      const ipfsHash = await (net.pushMetadata || pushMetadataToIPFS)('WitnessRegistry')
      if (typeof ipfsHash !== 'string' || ipfsHash.length !== 46) {
        throw new Error('the metadata upload to IPFS did not give a valid hash; nothing was deployed')
      }
      const withHash = new net.quais.ContractFactory(art.abi, art.bytecode, signer, ipfsHash)
      const reg = await withHash.deploy(owners)
      await reg.waitForDeployment()
      const receipt = await reg.deploymentTransaction().wait()
      const registry = await reg.getAddress()
      const deployTxHash = reg.deploymentTransaction().hash
      const deployment = {
        network: net.mode, chainId: net.chainId, registry, deployTxHash, ipfsHash, deployBlock: receipt.blockNumber, owners, witnesses: {},
      }
      fs.writeFileSync(deploymentFile(), JSON.stringify(deployment, null, 2)) // addresses only, no keys
      return { ok: true, ...deployment, deploymentFile: deploymentFile() }
    }
  )
}

// ------------------------------------------------------- registerWitness
// Register one more witness on an existing deployment. Same approval rule as setup-local (2 of
// the 3 owners send the identical call). Localhost: picks the first local account that is not
// already an owner or another witness's anchor account. Quai: the witness's own account is the
// one named for that role in .env (app, network, outside, baseline), never a guess. On Quai each
// of the two owner transactions is shown and confirmed on its own.
async function registerWitness(net, input) {
  const dep = loadDeployment()
  const reg = registryAt(net, dep.registry)
  const id = ethers.encodeBytes32String(String(input.id))
  const edPubKey = hex32(input.edPubKey, 'edPubKey')
  const maxGap = input.maxGapSeconds === undefined ? 600 : Number(input.maxGapSeconds)

  const existing = await reg.witnesses(id)
  if (existing.edPubKey !== ethers.ZeroHash) {
    return { ok: true, alreadyRegistered: true, anchorAccount: existing.anchorAccount }
  }

  let anchorAccount
  if (isQuai(net)) {
    anchorAccount = net.roleAddress[String(input.id)]
    if (!anchorAccount || input.id === 'deployer' || /^owner[123]$/.test(String(input.id))) {
      throw new Error('no account is configured for witness "' + input.id + '" (set its CYPRUS1_*_PK in .env)')
    }
    const lower = (a) => String(a).toLowerCase()
    if (dep.owners.some((o) => lower(o) === lower(anchorAccount))) {
      throw new Error('the account for witness "' + input.id + '" is also an owner: refusing')
    }
    if (net.roleAddress.deployer && lower(net.roleAddress.deployer) === lower(anchorAccount)) {
      throw new Error('the account for witness "' + input.id + '" is also the deployer: refusing')
    }
    checkCyprus1Address(net.quais, anchorAccount, 'the account for witness "' + input.id + '"')
  } else {
    const accounts = await net.accounts()
    const used = new Set(
      [...dep.owners, ...Object.values(dep.witnesses || {}).map((w) => w.anchorAccount)].map((a) => a.toLowerCase())
    )
    anchorAccount = accounts.find((a) => !used.has(a.toLowerCase()))
    if (!anchorAccount) throw new Error('no free local account left to register another witness')
  }

  const approvers = await ownerSignerList(net, dep, 2)
  const args = [id, anchorAccount, edPubKey, maxGap]
  const steps = approvers.map((o, i) => ({
    action: 'register witness "' + input.id + '" with account ' + anchorAccount + ' (owner approval ' + (i + 1) + ' of 2)',
    sender: o.address,
    contract: dep.registry,
    estimateGas: () => reg.connect(o.signer).registerWitness.estimateGas(...args),
    send: async () => sentInfo(await reg.connect(o.signer).registerWitness(...args)),
  }))
  return runSteps(net, steps, async (last, results) => {
    const w = await reg.witnesses(id)
    if (!w.active) throw new Error('registration did not go through')
    const done = { ok: true, alreadyRegistered: false, anchorAccount }
    return isQuai(net) ? { ...done, txs: results } : done // Quai: report each owner transaction (hash, gas)
  }, input.step)
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
  const contract = reg.connect(signer)
  const send = async () => {
    const tx = await contract[method](batchNo, entriesRoot, receiptsRoot, policyHash, firstSeq, lastSeq)
    const receipt = await mined(tx)
    return { ok: true, alreadyAnchored: false, txHash: tx.hash, blockNumber: receipt.blockNumber, gasUsed: receipt.gasUsed.toString() }
  }
  if (net.mode === 'localhost') return send() // unchanged: no summary, no prompt, no extra RPC call
  return runWithConfirmation(net, {
    action: 'anchor batch ' + batchNo + ' for witness "' + input.witnessId + '"',
    sender: w.anchorAccount, contract: dep.registry,
    estimateGas: () => contract[method].estimateGas(batchNo, entriesRoot, receiptsRoot, policyHash, firstSeq, lastSeq),
  }, send)
}

// ----------------------------------------------------------- confirmations
async function confirmations(net, txHash) {
  const receipt = await net.provider.getTransactionReceipt(txHash)
  if (!receipt) return { ok: true, confirmations: 0 }
  if (receipt.status !== 1) throw new Error('transaction failed on chain')
  const latest = await latestBlockNumber(net)
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
      lastSeenBlockTime: Number(w.lastSeenBlockTime),
    }
  }
  return { ok: true, registry: dep.registry, witnesses }
}

// ------------------------------------------------------------- readEvents
// What the chain recorded about silence and planned pauses. Block times come from the blocks
// themselves (PauseEnded carries no time of its own).
async function readEvents(net, onlyName) {
  const dep = loadDeployment()
  const reg = registryAt(net, dep.registry)
  const from = dep.deployBlock || 0
  const times = new Map()
  async function timeOf(blockNumber) {
    if (!times.has(blockNumber)) times.set(blockNumber, blockTime(await getBlockAt(net, blockNumber)))
    return times.get(blockNumber)
  }
  const events = []
  const wanted = (idHex) => {
    const name = ethers.decodeBytes32String(idHex)
    return !onlyName || name === onlyName ? name : null
  }
  for (const l of await reg.queryFilter(reg.filters.WitnessSilent(), from)) {
    const name = wanted(l.args.id)
    if (name === null) continue
    events.push({
      type: 'WitnessSilent', witnessId: name, blockNumber: l.blockNumber, blockTime: await timeOf(l.blockNumber),
      txHash: l.transactionHash, lastSeenBlockTime: Number(l.args.lastSeenBlockTime), flaggedAt: Number(l.args.flaggedAt),
    })
  }
  for (const l of await reg.queryFilter(reg.filters.PauseBegun(), from)) {
    const name = wanted(l.args.id)
    if (name === null) continue
    events.push({
      type: 'PauseBegun', witnessId: name, pauseId: Number(l.args.pauseId), blockNumber: l.blockNumber,
      blockTime: await timeOf(l.blockNumber), txHash: l.transactionHash, start: Number(l.args.start),
      pauseUntil: Number(l.args.pauseUntil), reasonHash: l.args.reasonHash,
    })
  }
  for (const l of await reg.queryFilter(reg.filters.PauseEnded(), from)) {
    const name = wanted(l.args.id)
    if (name === null) continue
    events.push({
      type: 'PauseEnded', witnessId: name, pauseId: Number(l.args.pauseId), blockNumber: l.blockNumber,
      blockTime: await timeOf(l.blockNumber), txHash: l.transactionHash,
    })
  }
  events.sort((a, b) => a.blockNumber - b.blockNumber)
  const latest = await getBlockAt(net, 'latest')
  return { ok: true, events, latestBlockTime: blockTime(latest) }
}

// ------------------------------------------------------------------- admin
// Makes the events the verifier reads: a silence flag, or a planned pause approved by two owners.
// Localhost: the local node unlocks the owner accounts. Quai: real sends, one confirmation per
// transaction, owners are the ones with a key configured.
async function admin(net, input) {
  const dep = loadDeployment()
  const reg = registryAt(net, dep.registry)
  const id = ethers.encodeBytes32String(String(input.witnessId || ''))
  if (input.action === 'flagSilence') {
    // Anyone may flag silence; on Quai the deployer account sends it.
    const sender = isQuai(net) ? net.roleAddress.deployer : (await net.accounts())[0]
    if (!sender) throw new Error('no account is configured to send flagSilence (set CYPRUS1_PK in .env)')
    const contract = reg.connect(await net.signerFor(sender))
    return runSteps(net, [{
      action: 'flag witness "' + input.witnessId + '" silent', sender, contract: dep.registry,
      estimateGas: () => contract.flagSilence.estimateGas(id),
      send: async () => {
        const tx = await contract.flagSilence(id)
        const receipt = await mined(tx)
        return { ok: true, txHash: tx.hash, blockNumber: receipt.blockNumber }
      },
    }])
  }
  const owners = await ownerSignerList(net, dep, 2)
  const twoOwnerSteps = (label, method, args) => owners.map((o, i) => ({
    action: label + ' (owner approval ' + (i + 1) + ' of 2)', sender: o.address, contract: dep.registry,
    estimateGas: () => reg.connect(o.signer)[method].estimateGas(...args),
    send: async () => sentInfo(await reg.connect(o.signer)[method](...args)),
  }))
  if (input.action === 'beginPause') {
    // Both owners must send the IDENTICAL call, so pauseUntil is worked out once, here.
    const latest = await getBlockAt(net, 'latest')
    const pauseUntil = blockTime(latest) + Number(input.seconds || 60)
    const reason = ethers.id(String(input.reason || 'planned maintenance'))
    return runSteps(net, twoOwnerSteps('begin a pause for witness "' + input.witnessId + '" until ' + pauseUntil,
      'beginPause', [id, reason, pauseUntil]),
    async () => ({ ok: true, pauseUntil, pauseId: Number(await reg.pauseCount()) }), input.step)
  }
  if (input.action === 'endPause') {
    return runSteps(net, twoOwnerSteps('end pause ' + input.pauseId, 'endPause', [Number(input.pauseId)]),
      async () => ({ ok: true }), input.step)
  }
  throw new Error('unknown admin action "' + input.action + '"')
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
    else if (command === 'deploy') result = await deploy(net, await readJson(arg1))
    else if (command === 'anchor') result = await anchor(net, await readJson(arg1))
    else if (command === 'confirmations') result = await confirmations(net, arg1 || (await readJson()).txHash)
    else if (command === 'readAnchors') result = await readAnchors(net, arg1, arg2, arg3)
    else if (command === 'readWitness') result = await readWitness(net, names)
    else if (command === 'registerWitness') result = await registerWitness(net, await readJson(arg1))
    else if (command === 'readEvents') result = await readEvents(net, arg1)
    else if (command === 'admin') result = await admin(net, await readJson(arg1))
    else throw new Error('unknown command "' + command + '". Use: setup-local, deploy, anchor, confirmations, readAnchors, readWitness, readEvents, admin, registerWitness')
    print(result)
    return 0
  } catch (e) {
    print({ ok: false, error: errorText(e) })
    return 1
  } finally {
    if (net) net.close()
  }
}

if (require.main === module) {
  main().then((code) => process.exit(code))
} else {
  // Loaded by a test: expose the command functions so they can be run against a fake provider.
  module.exports = {
    deploy, registerWitness, anchor, confirmations, readAnchors, readWitness, readEvents, admin,
    runSteps, ownerSignerList, deploymentFile, loadDeployment, blockTime,
  }
}
