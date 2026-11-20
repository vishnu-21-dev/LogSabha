// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

/**
 * WitnessRegistry
 *
 * Three independent witnesses (app, network, outside) seal their log entries
 * into batches and anchor each batch's fingerprint here.
 *
 * PRIVACY: only roots, hashes and sequence numbers are stored. No raw logs,
 * request IDs, IPs or payloads ever go on-chain.
 *
 * ADMIN: 3 owner accounts. Every admin change needs 2 of the 3 owners to send
 * the same call with the same arguments (built-in multisig, no external one).
 */
contract WitnessRegistry {
    // ---------------------------------------------------------------- data

    struct Witness {
        address anchorAccount; // the only account allowed to anchor for this witness
        bytes32 edPubKey;      // witness signing key (ed25519), stored for reference
        bool active;
        uint32 maxGapSeconds;  // longest allowed silence between anchors
        uint64 lastSeenBlockTime;
        uint64 lastBatchNo;
        uint64 lastSeq;
    }

    struct Anchor {
        bytes32 entriesRoot;
        bytes32 receiptsRoot;
        bytes32 policyHash;
        uint64 firstSeq;
        uint64 lastSeq;
        uint64 blockTime;
    }

    struct Pause {
        bytes32 witnessId;
        bytes32 reasonHash;
        uint64 start;
        uint64 pauseUntil;
        bool ended;
    }

    uint256 public constant MAX_PAUSE_SECONDS = 10 minutes;
    uint256 public constant APPROVAL_TTL = 1 days;
    uint256 public constant REQUIRED_APPROVALS = 2;

    address[3] public owners;
    mapping(address => bool) public isOwner;

    mapping(bytes32 => Witness) public witnesses;
    mapping(address => bytes32) public witnessByAccount;
    mapping(bytes32 => mapping(uint64 => Anchor)) public anchors;

    mapping(uint256 => Pause) public pauses;
    mapping(bytes32 => uint256) public activePauseId; // 0 = none
    uint256 public pauseCount;

    mapping(bytes32 => uint64) public lastSilenceFlag;

    // owner approvals: action fingerprint => owner => time of approval
    mapping(bytes32 => mapping(address => uint256)) private approvedAt;

    // -------------------------------------------------------------- events

    event WitnessRegistered(bytes32 indexed id, address anchorAccount, bytes32 edPubKey, uint32 maxGapSeconds);
    event WitnessRetired(bytes32 indexed id);
    event MaxGapLowered(bytes32 indexed id, uint32 oldGap, uint32 newGap);
    event Anchored(
        bytes32 indexed id,
        uint64 indexed batchNo,
        bytes32 entriesRoot,
        bytes32 receiptsRoot,
        bytes32 policyHash,
        uint64 firstSeq,
        uint64 lastSeq,
        bool restart
    );
    event PauseBegun(uint256 indexed pauseId, bytes32 indexed id, bytes32 reasonHash, uint64 start, uint64 pauseUntil);
    event PauseEnded(uint256 indexed pauseId, bytes32 indexed id);
    event WitnessSilent(bytes32 indexed id, uint64 lastSeenBlockTime, uint64 flaggedAt);
    event ActionApproved(bytes32 indexed actionHash, address indexed owner, uint256 approvals);

    // ------------------------------------------------------------ modifiers

    modifier onlyOwner() {
        require(isOwner[msg.sender], "not an owner");
        _;
    }

    constructor(address[3] memory _owners) {
        for (uint256 i = 0; i < 3; i++) {
            address o = _owners[i];
            require(o != address(0), "zero owner");
            require(!isOwner[o], "duplicate owner");
            isOwner[o] = true;
            owners[i] = o;
        }
    }

    // ------------------------------------------------- 2-of-3 owner approval

    /// Records msg.sender's approval of this exact action. Returns true only
    /// when the 2nd distinct owner approves; then approvals are cleared.
    function _approve(bytes32 actionHash) internal returns (bool) {
        approvedAt[actionHash][msg.sender] = block.timestamp;

        uint256 count = 0;
        for (uint256 i = 0; i < 3; i++) {
            uint256 t = approvedAt[actionHash][owners[i]];
            if (t != 0 && block.timestamp - t <= APPROVAL_TTL) count++;
        }
        emit ActionApproved(actionHash, msg.sender, count);

        if (count >= REQUIRED_APPROVALS) {
            for (uint256 i = 0; i < 3; i++) delete approvedAt[actionHash][owners[i]];
            return true;
        }
        return false;
    }

    // --------------------------------------------------- admin (2-of-3 owners)

    /// All admin functions return true if the action ran, false if it only
    /// recorded this owner's approval and is waiting for a second owner.
    function registerWitness(bytes32 id, address anchorAccount, bytes32 edPubKey, uint32 maxGapSeconds)
        external
        onlyOwner
        returns (bool)
    {
        require(id != bytes32(0), "empty id");
        require(witnesses[id].anchorAccount == address(0), "witness id exists");
        require(anchorAccount != address(0), "zero account");
        require(!isOwner[anchorAccount], "witness account is an owner");
        require(witnessByAccount[anchorAccount] == bytes32(0), "account already used");
        require(edPubKey != bytes32(0), "empty key");
        require(maxGapSeconds > 0, "zero gap");

        if (!_approve(keccak256(abi.encode(msg.sig, id, anchorAccount, edPubKey, maxGapSeconds)))) return false;

        Witness storage w = witnesses[id];
        w.anchorAccount = anchorAccount;
        w.edPubKey = edPubKey;
        w.active = true;
        w.maxGapSeconds = maxGapSeconds;
        w.lastSeenBlockTime = uint64(block.timestamp);
        witnessByAccount[anchorAccount] = id;

        emit WitnessRegistered(id, anchorAccount, edPubKey, maxGapSeconds);
        return true;
    }

    function retireWitness(bytes32 id) external onlyOwner returns (bool) {
        require(witnesses[id].active, "witness not active");

        if (!_approve(keccak256(abi.encode(msg.sig, id)))) return false;

        witnesses[id].active = false;
        emit WitnessRetired(id);
        return true;
    }

    /// The gap can only go down, never up.
    function lowerMaxGap(bytes32 id, uint32 newGap) external onlyOwner returns (bool) {
        Witness storage w = witnesses[id];
        require(w.active, "witness not active");
        require(newGap > 0, "zero gap");
        require(newGap < w.maxGapSeconds, "gap can only decrease");

        if (!_approve(keccak256(abi.encode(msg.sig, id, newGap)))) return false;

        uint32 oldGap = w.maxGapSeconds;
        w.maxGapSeconds = newGap;
        emit MaxGapLowered(id, oldGap, newGap);
        return true;
    }

    // ---------------------------------------------------------------- pauses

    /// Planned maintenance. At most 10 minutes ahead, and no extending: a
    /// witness with a running pause cannot get another one.
    function beginPause(bytes32 id, bytes32 reasonHash, uint64 pauseUntil) external onlyOwner returns (bool) {
        require(witnesses[id].active, "witness not active");
        require(pauseUntil > block.timestamp, "pause end in the past");
        require(pauseUntil <= block.timestamp + MAX_PAUSE_SECONDS, "pause longer than 10 minutes");
        require(!isPaused(id), "pause already running");

        if (!_approve(keccak256(abi.encode(msg.sig, id, reasonHash, pauseUntil)))) return false;

        uint256 pauseId = ++pauseCount;
        pauses[pauseId] = Pause(id, reasonHash, uint64(block.timestamp), pauseUntil, false);
        activePauseId[id] = pauseId;

        emit PauseBegun(pauseId, id, reasonHash, uint64(block.timestamp), pauseUntil);
        return true;
    }

    function endPause(uint256 pauseId) external onlyOwner returns (bool) {
        Pause storage p = pauses[pauseId];
        require(p.witnessId != bytes32(0), "no such pause");
        require(!p.ended, "pause already ended");

        if (!_approve(keccak256(abi.encode(msg.sig, pauseId)))) return false;

        p.ended = true;
        emit PauseEnded(pauseId, p.witnessId);
        return true;
    }

    function isPaused(bytes32 id) public view returns (bool) {
        uint256 pid = activePauseId[id];
        if (pid == 0) return false;
        Pause storage p = pauses[pid];
        return !p.ended && block.timestamp < p.pauseUntil;
    }

    // ---------------------------------------------------------------- anchor

    /// Normal anchor: batch numbers and sequence numbers must follow on exactly.
    function anchor(
        uint64 batchNo,
        bytes32 entriesRoot,
        bytes32 receiptsRoot,
        bytes32 policyHash,
        uint64 firstSeq,
        uint64 lastSeq
    ) external {
        _anchor(batchNo, entriesRoot, receiptsRoot, policyHash, firstSeq, lastSeq, false);
    }

    /// Restart marker: used after a witness lost data and starts a new range.
    /// The batch number still follows on, but firstSeq may jump forward. The
    /// jump is public (restart=true in the event), never hidden.
    function anchorRestart(
        uint64 batchNo,
        bytes32 entriesRoot,
        bytes32 receiptsRoot,
        bytes32 policyHash,
        uint64 firstSeq,
        uint64 lastSeq
    ) external {
        _anchor(batchNo, entriesRoot, receiptsRoot, policyHash, firstSeq, lastSeq, true);
    }

    function _anchor(
        uint64 batchNo,
        bytes32 entriesRoot,
        bytes32 receiptsRoot,
        bytes32 policyHash,
        uint64 firstSeq,
        uint64 lastSeq,
        bool restart
    ) internal {
        bytes32 id = witnessByAccount[msg.sender];
        require(id != bytes32(0), "not a witness account");

        Witness storage w = witnesses[id];
        require(w.active, "witness not active");
        require(batchNo == w.lastBatchNo + 1, "bad batch number (gap or replay)");
        require(entriesRoot != bytes32(0), "empty entries root");
        require(lastSeq >= firstSeq, "bad sequence range");
        if (restart) {
            require(firstSeq > w.lastSeq, "restart must move forward");
        } else {
            require(firstSeq == w.lastSeq + 1, "sequence gap");
        }

        anchors[id][batchNo] = Anchor(entriesRoot, receiptsRoot, policyHash, firstSeq, lastSeq, uint64(block.timestamp));
        w.lastBatchNo = batchNo;
        w.lastSeq = lastSeq;
        w.lastSeenBlockTime = uint64(block.timestamp);

        emit Anchored(id, batchNo, entriesRoot, receiptsRoot, policyHash, firstSeq, lastSeq, restart);
    }

    // --------------------------------------------------------------- silence

    /// Anyone can call. Contracts have no timers, so an off-chain keeper calls
    /// this. It flags a witness that missed its maxGapSeconds (not during a
    /// pause). Flags are rate-limited: one per missed gap.
    function flagSilence(bytes32 id) external {
        Witness storage w = witnesses[id];
        require(w.active, "witness not active");
        require(!isPaused(id), "witness is paused");

        uint256 since = w.lastSeenBlockTime;
        if (lastSilenceFlag[id] > since) since = lastSilenceFlag[id];
        require(block.timestamp > since + w.maxGapSeconds, "witness not silent");

        lastSilenceFlag[id] = uint64(block.timestamp);
        emit WitnessSilent(id, w.lastSeenBlockTime, uint64(block.timestamp));
    }
}
