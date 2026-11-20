/**
 * @type import('hardhat/config').HardhatUserConfig
 */

require('@nomicfoundation/hardhat-toolbox')
require('@quai/quais-upgrades');
require("@quai/hardhat-deploy-metadata");

const dotenv = require('dotenv')
dotenv.config({ path: '../.env' })

module.exports = {
  // Switch networks by setting NETWORK=localhost or NETWORK=cyprus1 in ../.env
  defaultNetwork: process.env.NETWORK || 'cyprus1',
  networks: {
    localhost: {
      url: process.env.LOCAL_RPC_URL || 'http://127.0.0.1:8545',
      chainId: Number(process.env.LOCAL_CHAIN_ID || 31337),
      // No LOCAL_PK set -> use the accounts the local node provides
      accounts: process.env.LOCAL_PK ? [process.env.LOCAL_PK] : 'remote',
    },
    cyprus1: {
      url: process.env.RPC_URL,
      accounts: [process.env.CYPRUS1_PK],
      chainId: Number(process.env.CHAIN_ID),
    },
    cyprus1_fullpath: {
      url: "https://orchard.rpc.quai.network/cyprus1",
      accounts: [process.env.CYPRUS1_PK],
      chainId: Number(process.env.CHAIN_ID),
    },
  },

  solidity: {
    compilers: [
      {
      version: '0.8.17',
      settings: {
        optimizer: {
          enabled: true,
          runs: 1000,
        },
        metadata: {
          bytecodeHash: 'ipfs',
          useLiteralContent: true, // Include the source code in the metadata
        },
        evmVersion: 'london',
      },
    },
    {
      version: '0.8.20',
      settings: {
        optimizer: {
          enabled: true,
          runs: 1000,
        },
        metadata: {
          bytecodeHash: 'ipfs',
          useLiteralContent: true, // Include the source code in the metadata
        },
        evmVersion: 'london',
      },
    },
  ]
  },

  // etherscan: {
  //   apiKey: {
  //     cyprus1: 'abc',
  //   },
  //   customChains: [
  //     {
  //       network: 'cyprus1',
  //       chainId: Number(process.env.CHAINID),
  //       urls: {
  //         apiURL: 'https://quaiscan.io/api/v2',
  //         browserURL: 'https://quaiscan.io/',
  //       },
  //     },
  //   ],
  // },

  paths: {
    sources: './contracts',
    cache: './cache',
    artifacts: './artifacts',
  },
  mocha: {
    timeout: 20000,
  },
}
