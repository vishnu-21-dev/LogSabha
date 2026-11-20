# LogSabha

Tamper-evident logging for an application, built around independent witnesses. Each witness keeps its own
hash-chained log of what it saw, and periodically anchors a batch commitment on a chain. A verifier that never
talks to a live witness later checks the exported evidence against the chain.

## Layout

| Path | What it is |
| --- | --- |
| `Solidity/contracts/WitnessRegistry.sol` | On-chain registry of the 3 witnesses and their anchors. Tests in `Solidity/test/`. |
| `chain/` | Small JSON command line that Python calls to anchor witness batches and read chain data. |
| `python/logsabha_core/` | Shared crypto library: canonical JSON, entries, hash chain, Merkle tree, signing, policy. |
| `python/witness/` | The witness agent: SQLite storage, peer exchange, anchor queue, evidence export. |
| `python/outside/` | The outside witness's own observation point (sink / packet capture). |
| `python/verifier/` | Offline verifier. Integrity rules I1 to I7 and consistency rules C1 to C4 and C6. Verdicts: MATCH, MISMATCH or CANNOT VERIFY. |
| `python/demo_app/`, `python/gateway/` | QuickPay, a fake fintech used for the demo, and the forward proxy that watches its outbound calls. |
| `python/launcher/`, `python/clean_run.py`, `python/demo.config.json` | Starts and stops the whole demo from one config file. |

## Running the tests

```
cd Solidity && npm install && npx hardhat test --network hardhat
cd python && python -m pytest
```

`Solidity/hardhat.config.js` reads `../.env`; copy `.env.dist` to `.env` first (the defaults select a local network).
Witness key files (`*.seed`, `*.key`) are git-ignored and must never be committed.
