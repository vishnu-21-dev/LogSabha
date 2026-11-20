const { expect } = require('chai')
const { ethers } = require('hardhat')
const { time } = require('@nomicfoundation/hardhat-network-helpers')

const b32 = (s) => ethers.encodeBytes32String(s)
const root = (s) => ethers.keccak256(ethers.toUtf8Bytes(s))

describe('WitnessRegistry', function () {
  let reg, owner1, owner2, owner3, appAcct, netAcct, outAcct, stranger
  const APP = b32('app')
  const EDKEY = root('app-ed25519-public-key')

  beforeEach(async function () {
    ;[owner1, owner2, owner3, appAcct, netAcct, outAcct, stranger] = await ethers.getSigners()
    const Reg = await ethers.getContractFactory('WitnessRegistry')
    reg = await Reg.deploy([owner1.address, owner2.address, owner3.address])
    await reg.waitForDeployment()
  })

  // 2 different owners send the same call -> it runs
  async function register(id = APP, acct = appAcct, gap = 60) {
    await reg.connect(owner1).registerWitness(id, acct.address, EDKEY, gap)
    return reg.connect(owner2).registerWitness(id, acct.address, EDKEY, gap)
  }

  const batch = (reg_, signer, n, first, last) =>
    reg_.connect(signer).anchor(n, root('e' + n), root('r' + n), root('p'), first, last)

  describe('registration (2-of-3 owners)', function () {
    it('non-owner registration fails', async function () {
      await expect(
        reg.connect(stranger).registerWitness(APP, appAcct.address, EDKEY, 60)
      ).to.be.revertedWith('not an owner')
    })

    it('one owner alone cannot register', async function () {
      const ret = await reg.connect(owner1).registerWitness.staticCall(APP, appAcct.address, EDKEY, 60)
      expect(ret).to.equal(false)
      await reg.connect(owner1).registerWitness(APP, appAcct.address, EDKEY, 60)
      expect((await reg.witnesses(APP)).active).to.equal(false)
    })

    it('the same owner approving twice still does not register', async function () {
      await reg.connect(owner1).registerWitness(APP, appAcct.address, EDKEY, 60)
      await reg.connect(owner1).registerWitness(APP, appAcct.address, EDKEY, 60)
      expect((await reg.witnesses(APP)).active).to.equal(false)
    })

    it('two different owners register, and WitnessRegistered is emitted', async function () {
      await reg.connect(owner1).registerWitness(APP, appAcct.address, EDKEY, 60)
      await expect(reg.connect(owner3).registerWitness(APP, appAcct.address, EDKEY, 60))
        .to.emit(reg, 'WitnessRegistered')
        .withArgs(APP, appAcct.address, EDKEY, 60)
      const w = await reg.witnesses(APP)
      expect(w.active).to.equal(true)
      expect(w.anchorAccount).to.equal(appAcct.address)
    })

    it('duplicate witness IDs fail', async function () {
      await register()
      await expect(
        reg.connect(owner1).registerWitness(APP, netAcct.address, EDKEY, 60)
      ).to.be.revertedWith('witness id exists')
    })

    it('a witness account cannot be an owner account', async function () {
      await expect(
        reg.connect(owner1).registerWitness(APP, owner2.address, EDKEY, 60)
      ).to.be.revertedWith('witness account is an owner')
    })

    it('two witnesses cannot share one account', async function () {
      await register()
      await expect(
        reg.connect(owner1).registerWitness(b32('network'), appAcct.address, EDKEY, 60)
      ).to.be.revertedWith('account already used')
    })
  })

  describe('maxGap', function () {
    it('lowering maxGap works with 2 owners', async function () {
      await register()
      await reg.connect(owner1).lowerMaxGap(APP, 30)
      await expect(reg.connect(owner2).lowerMaxGap(APP, 30)).to.emit(reg, 'MaxGapLowered').withArgs(APP, 60, 30)
      expect((await reg.witnesses(APP)).maxGapSeconds).to.equal(30)
    })

    it('raising maxGap fails', async function () {
      await register()
      await expect(reg.connect(owner1).lowerMaxGap(APP, 120)).to.be.revertedWith('gap can only decrease')
      await expect(reg.connect(owner1).lowerMaxGap(APP, 60)).to.be.revertedWith('gap can only decrease')
    })
  })

  describe('anchor', function () {
    beforeEach(async function () {
      await register()
    })

    it('a normal anchor works and emits Anchored', async function () {
      await expect(batch(reg, appAcct, 1, 1, 10))
        .to.emit(reg, 'Anchored')
        .withArgs(APP, 1, root('e1'), root('r1'), root('p'), 1, 10, false)
      const a = await reg.anchors(APP, 1)
      expect(a.entriesRoot).to.equal(root('e1'))
      expect(a.lastSeq).to.equal(10)
      const w = await reg.witnesses(APP)
      expect(w.lastBatchNo).to.equal(1)
      expect(w.lastSeq).to.equal(10)
    })

    it('only the witness own account can anchor', async function () {
      await expect(batch(reg, stranger, 1, 1, 10)).to.be.revertedWith('not a witness account')
      await expect(batch(reg, owner1, 1, 1, 10)).to.be.revertedWith('not a witness account')
    })

    it('sequence gaps fail', async function () {
      await batch(reg, appAcct, 1, 1, 10)
      await expect(batch(reg, appAcct, 2, 12, 20)).to.be.revertedWith('sequence gap')
    })

    it('replayed batches fail', async function () {
      await batch(reg, appAcct, 1, 1, 10)
      await expect(batch(reg, appAcct, 1, 1, 10)).to.be.revertedWith('bad batch number (gap or replay)')
    })

    it('skipping a batch number fails', async function () {
      await expect(batch(reg, appAcct, 2, 1, 10)).to.be.revertedWith('bad batch number (gap or replay)')
    })

    it('a restart marker may jump the sequence forward, and says so', async function () {
      await batch(reg, appAcct, 1, 1, 10)
      await expect(
        reg.connect(appAcct).anchorRestart(2, root('e2'), root('r2'), root('p'), 500, 510)
      )
        .to.emit(reg, 'Anchored')
        .withArgs(APP, 2, root('e2'), root('r2'), root('p'), 500, 510, true)
      // after the restart, normal anchoring continues from 511
      await batch(reg, appAcct, 3, 511, 520)
    })

    it('a restart cannot go backwards', async function () {
      await batch(reg, appAcct, 1, 1, 10)
      await expect(
        reg.connect(appAcct).anchorRestart(2, root('e2'), root('r2'), root('p'), 5, 15)
      ).to.be.revertedWith('restart must move forward')
    })
  })

  describe('heartbeat anchors (empty windows)', function () {
    const EMPTY = ethers.sha256('0x') // SHA-256 of nothing = empty Merkle tree root
    // heartbeat: lastSeq == firstSeq - 1
    const beat = (signer, n, first, receipts = root('r' + n)) =>
      reg.connect(signer).anchor(n, EMPTY, receipts, ethers.ZeroHash, first, first - 1)

    beforeEach(async function () {
      await register()
    })

    it('the empty-root constant is SHA-256 of nothing', async function () {
      expect(await reg.EMPTY_ENTRIES_ROOT()).to.equal(EMPTY)
    })

    it('an empty heartbeat is accepted, uses a batch number, and keeps lastSeq', async function () {
      await batch(reg, appAcct, 1, 1, 10)
      await expect(beat(appAcct, 2, 11))
        .to.emit(reg, 'Anchored')
        .withArgs(APP, 2, EMPTY, root('r2'), ethers.ZeroHash, 11, 10, false)
      const w = await reg.witnesses(APP)
      expect(w.lastBatchNo).to.equal(2)
      expect(w.lastSeq).to.equal(10) // unchanged: nothing was logged
      // a heartbeat can also come first, and also with an empty receipts root
      await beat(appAcct, 3, 11, EMPTY)
      // normal anchoring carries on from the same sequence number
      await batch(reg, appAcct, 4, 11, 20)
    })

    it('a gap is still rejected after heartbeats', async function () {
      await batch(reg, appAcct, 1, 1, 10)
      await beat(appAcct, 2, 11)
      await expect(batch(reg, appAcct, 3, 12, 20)).to.be.revertedWith('sequence gap') // skipped seq 11
      await expect(beat(appAcct, 3, 12)).to.be.revertedWith('sequence gap')
      await expect(beat(appAcct, 3, 9)).to.be.revertedWith('sequence gap')
    })

    it('a replayed heartbeat or anchor is still rejected', async function () {
      await batch(reg, appAcct, 1, 1, 10)
      await beat(appAcct, 2, 11)
      await expect(beat(appAcct, 2, 11)).to.be.revertedWith('bad batch number (gap or replay)')
      await expect(batch(reg, appAcct, 1, 1, 10)).to.be.revertedWith('bad batch number (gap or replay)')
      await expect(batch(reg, appAcct, 2, 11, 20)).to.be.revertedWith('bad batch number (gap or replay)')
    })

    it('a heartbeat must use the empty entries root, and cannot be a restart', async function () {
      await expect(
        reg.connect(appAcct).anchor(1, root('not-empty'), root('r'), ethers.ZeroHash, 1, 0)
      ).to.be.revertedWith('heartbeat needs the empty entries root')
      await expect(
        reg.connect(appAcct).anchor(1, ethers.ZeroHash, root('r'), ethers.ZeroHash, 1, 0)
      ).to.be.revertedWith('heartbeat needs the empty entries root')
      await expect(
        reg.connect(appAcct).anchorRestart(1, EMPTY, root('r'), ethers.ZeroHash, 1, 0)
      ).to.be.revertedWith('restart cannot be a heartbeat')
    })

    it('normal anchors still need lastSeq >= firstSeq', async function () {
      await expect(batch(reg, appAcct, 1, 5, 3)).to.be.revertedWith('bad sequence range')
    })
  })

  describe('pauses and silence', function () {
    beforeEach(async function () {
      await register(APP, appAcct, 60)
    })

    async function pause(untilOffset) {
      const until = (await time.latest()) + untilOffset
      await reg.connect(owner1).beginPause(APP, root('maintenance'), until)
      return reg.connect(owner2).beginPause(APP, root('maintenance'), until)
    }

    it('a pause over 10 minutes fails', async function () {
      const until = (await time.latest()) + 11 * 60
      await expect(
        reg.connect(owner1).beginPause(APP, root('maintenance'), until)
      ).to.be.revertedWith('pause longer than 10 minutes')
    })

    it('a valid pause begins, emits PauseBegun, and blocks silence flags', async function () {
      await expect(pause(5 * 60)).to.emit(reg, 'PauseBegun')
      expect(await reg.isPaused(APP)).to.equal(true)
      await time.increase(120) // past the 60s gap, still inside the pause
      await expect(reg.connect(stranger).flagSilence(APP)).to.be.revertedWith('witness is paused')
    })

    it('a running pause cannot be extended by a second pause', async function () {
      await pause(5 * 60)
      const until = (await time.latest()) + 8 * 60
      await expect(
        reg.connect(owner1).beginPause(APP, root('again'), until)
      ).to.be.revertedWith('pause already running')
    })

    it('endPause ends a pause early', async function () {
      await pause(5 * 60)
      await reg.connect(owner1).endPause(1)
      await expect(reg.connect(owner2).endPause(1)).to.emit(reg, 'PauseEnded').withArgs(1, APP)
      expect(await reg.isPaused(APP)).to.equal(false)
    })

    it('an expired pause flags silence', async function () {
      await pause(5 * 60)
      await time.increase(6 * 60) // pause over, witness never anchored
      expect(await reg.isPaused(APP)).to.equal(false)
      await expect(reg.connect(stranger).flagSilence(APP)).to.emit(reg, 'WitnessSilent')
    })

    it('no silence flag while the witness is on time', async function () {
      await expect(reg.connect(stranger).flagSilence(APP)).to.be.revertedWith('witness not silent')
    })

    it('silence is flagged once per missed gap, not every block', async function () {
      await time.increase(61)
      await reg.connect(stranger).flagSilence(APP)
      await expect(reg.connect(stranger).flagSilence(APP)).to.be.revertedWith('witness not silent')
      await time.increase(61)
      await expect(reg.connect(stranger).flagSilence(APP)).to.emit(reg, 'WitnessSilent')
    })
  })

  describe('retire', function () {
    it('retiring needs 2 owners, emits WitnessRetired, and stops anchoring', async function () {
      await register()
      await reg.connect(owner1).retireWitness(APP)
      expect((await reg.witnesses(APP)).active).to.equal(true)
      await expect(reg.connect(owner2).retireWitness(APP)).to.emit(reg, 'WitnessRetired').withArgs(APP)
      await expect(batch(reg, appAcct, 1, 1, 10)).to.be.revertedWith('witness not active')
    })
  })

  describe('gas report', function () {
    it('prints gasUsed for registerWitness and anchor', async function () {
      const t1 = await reg.connect(owner1).registerWitness(APP, appAcct.address, EDKEY, 60)
      const r1 = await t1.wait()
      const t2 = await reg.connect(owner2).registerWitness(APP, appAcct.address, EDKEY, 60)
      const r2 = await t2.wait()
      const a1 = await (await batch(reg, appAcct, 1, 1, 10)).wait()
      const a2 = await (await batch(reg, appAcct, 2, 11, 20)).wait()

      console.log('\n      GAS USED')
      console.log('      registerWitness, 1st owner (approval only):', r1.gasUsed.toString())
      console.log('      registerWitness, 2nd owner (executes)    :', r2.gasUsed.toString())
      console.log('      anchor, first batch                      :', a1.gasUsed.toString())
      console.log('      anchor, later batch                      :', a2.gasUsed.toString())
    })
  })
})
