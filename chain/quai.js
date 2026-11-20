'use strict'
// ===========================================================================
//  STUB: Quai mode (quais.js). NOT IMPLEMENTED ON PURPOSE.
//
//  Later, this file will connect to the real Quai network with quais.js.
//  Keys for the witness anchor accounts must then come from .env or key files
//  and must never be printed or logged.
//
//  It must return the same shape as local.js: { mode, provider, chainId,
//  accounts(), signerFor(address), startIntervalMining(ms), close() }.
// ===========================================================================

async function connect(_ethers, mode) {
  throw new Error(
    'NETWORK=' + mode + ' is not supported yet: Quai mode (chain/quai.js) is only a stub. Use NETWORK=localhost.'
  )
}

module.exports = { connect }
