// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "./IStarkVerifier.sol";

/// @title StarkZkAceAccount
/// @notice ERC-4337 account that validates transactions via ZK-ACE STARK proofs
///         instead of ECDSA signatures. This is the quantum-resistant counterpart
///         to ZkAceAccount (which uses Groth16/BN254).
///
/// @dev Key differences from ZkAceAccount:
///      - Uses STARK proofs (Winterfell, ~3.4KB) instead of Groth16 (~260B)
///      - Field: Goldilocks (2^64 - 2^32 + 1) instead of BN254 scalar field
///      - Hash: Keccak256 (native EVM opcode) instead of Poseidon
///      - No trusted setup required
///      - Post-quantum secure (hash-based, no elliptic curve assumptions)
///
///      Security model identical to ZkAceAccount:
///      1. TxHash recomputed from callData -- never trusted from prover
///      2. Domain checked against block.chainid -- prevents cross-chain replay
///      3. Verifier result enforced with require -- prevents silent failures
///      4. Internal zkNonce advances only after a verifier-accepted proof
///      5. Identity rotation via 2-step timelock (propose -> confirm after delay)
///      6. Emergency pause halts all operations
contract StarkZkAceAccount is BaseAccount {
    IEntryPoint private immutable _entryPoint;
    IStarkVerifier public immutable verifier;

    /// @notice Domain tag set at deployment (block.chainid).
    uint256 public immutable domainTag;

    /// @notice The identity commitment anchoring this account (paper: ID_com).
    ///         Stored as bytes32: 4 packed Goldilocks elements (4 × 8 bytes = 32 bytes).
    ///         Provides 256-bit classical / 128-bit post-quantum security.
    ///         Mutable to support identity rotation.
    bytes32 public idCom;

    /// @notice ZK-ACE replay-prevention nonce (monotonically increasing).
    uint256 public zkNonce;

    /// @notice Emergency pause flag.
    bool public paused;

    // --- Identity Rotation (2-step timelock) ---
    bytes32 public pendingIdCom;
    uint256 public rotationUnlocksAt;
    uint256 public constant ROTATION_DELAY = 2 days;

    /// @dev Goldilocks prime: p = 2^64 - 2^32 + 1
    uint256 private constant _GOLDILOCKS_P = 18446744069414584321;

    // ========== Errors ==========

    error InvalidProof();
    error TxHashMismatch(uint256 index, uint64 expected, uint64 provided);
    error IdComMismatch(bytes32 expected, bytes32 provided);
    error DomainMismatch(uint64 expected, uint64 provided);
    error AccountPaused();
    error NoRotationPending();
    error RotationTimelockActive(uint256 unlocksAt);

    // ========== Events ==========

    event IdentityRotationProposed(bytes32 indexed oldIdCom, bytes32 indexed newIdCom, uint256 unlocksAt);
    event IdentityRotated(bytes32 indexed oldIdCom, bytes32 indexed newIdCom);
    event Paused(bool isPaused);

    // ========== Constructor ==========

    constructor(
        IEntryPoint entryPoint_,
        IStarkVerifier verifier_,
        bytes32 idCom_
    ) {
        _entryPoint = entryPoint_;
        verifier = verifier_;
        idCom = idCom_;
        domainTag = block.chainid;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    // ========== Signature Validation ==========

    /// @notice Validate a ZK-ACE STARK authorization proof.
    /// @dev The signature field of the UserOp contains:
    ///      - bytes proof:          The serialized STARK proof
    ///      - uint64[17] pubInputs: 17 Goldilocks elements
    ///        [0..4]   id_com   — identity commitment (4 elements, 256-bit)
    ///        [4..8]   target   — derivation target (4 elements)
    ///        [8..12]  rp_com   — replay prevention commitment (4 elements)
    ///        [12]     domain   — chain/application domain (1 element)
    ///        [13], [14], [15], [16] tx_hash  — transaction hash (4 elements)
    ///      Encoded as: abi.encode(bytes proof, uint64[17] pubInputs)
    ///      This account recomputes callData-derived txHash and checks idCom/domain
    ///      directly, but it does not recompute rp_com in Solidity and it does not
    ///      bind validation to userOpHash. Replay resistance therefore composes the
    ///      STARK statement, zkNonce progression, and ERC-4337 nonce semantics.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 /*userOpHash*/
    ) internal override returns (uint256 validationData) {
        // CRITICAL-1 fix: Don't block validation when paused — only block execute().
        // This allows the owner to submit an unpause transaction even while paused.
        // The pause blocks execution of user transactions, not signature validation.
        // Paused state is checked in _requireForExecute() which gates execute().

        // Decode the STARK proof and public inputs from the signature field.
        (
            bytes memory proof,
            uint64[17] memory pubInputs
        ) = abi.decode(userOp.signature, (bytes, uint64[17]));

        // --- Step 6: Context binding -- recompute txHash from callData ---
        // Split keccak256(callData) into 4 Goldilocks elements (each < P)
        {
            bytes32 h = keccak256(userOp.callData);
            uint256 hval = uint256(h);
            uint64 th0 = uint64((hval >> 192) % _GOLDILOCKS_P);
            uint64 th1 = uint64(((hval >> 128) & 0xFFFFFFFFFFFFFFFF) % _GOLDILOCKS_P);
            uint64 th2 = uint64(((hval >> 64) & 0xFFFFFFFFFFFFFFFF) % _GOLDILOCKS_P);
            uint64 th3 = uint64((hval & 0xFFFFFFFFFFFFFFFF) % _GOLDILOCKS_P);
            if (pubInputs[13] != th0) revert TxHashMismatch(0, th0, pubInputs[13]);
            if (pubInputs[14] != th1) revert TxHashMismatch(1, th1, pubInputs[14]);
            if (pubInputs[15] != th2) revert TxHashMismatch(2, th2, pubInputs[15]);
            if (pubInputs[16] != th3) revert TxHashMismatch(3, th3, pubInputs[16]);
        }

        // --- Step 7a: Verify identity commitment matches this account ---
        // idCom on-chain = packed 4 Goldilocks elements (4 × 8 bytes = 32 bytes)
        bytes32 proofIdCom = bytes32(
            (uint256(pubInputs[0]) << 192) |
            (uint256(pubInputs[1]) << 128) |
            (uint256(pubInputs[2]) << 64) |
            uint256(pubInputs[3])
        );
        if (proofIdCom != idCom) {
            revert IdComMismatch(idCom, proofIdCom);
        }

        // --- Step 7b: Verify domain matches block.chainid ---
        // MED-2 fix: Require chain ID fits in Goldilocks field to prevent collisions
        require(domainTag < _GOLDILOCKS_P, "chain ID exceeds Goldilocks field");
        uint64 expectedDomain = uint64(domainTag);
        if (pubInputs[12] != expectedDomain) {
            revert DomainMismatch(expectedDomain, pubInputs[12]);
        }

        // --- Step 8: Verify the STARK proof ---
        // Convert memory bytes to calldata-compatible call
        bool valid = _callVerifier(proof, pubInputs);
        if (!valid) {
            revert InvalidProof();
        }

        // --- Step 9: Advance the account-local zkNonce after a verified proof ---
        // The contract does not recompute rp_com in Solidity. Instead, it relies on
        // the verifier-accepted proof statement plus monotonic zkNonce progression.
        // This keeps the on-chain checks aligned with what is actually enforced today.
        zkNonce++;

        // --- Step 10: Accept ---
        return 0; // SIG_VALIDATION_SUCCESS
    }

    /// @dev Call the verifier contract. We need this wrapper because the proof
    ///      comes from abi.decode (memory) but IStarkVerifier expects calldata.
    ///      We use a low-level staticcall with the proper encoding.
    function _callVerifier(
        bytes memory proof,
        uint64[17] memory pubInputs
    ) internal view returns (bool) {
        // Encode the call to verifyProof(bytes,uint64[17])
        bytes memory callData = abi.encodeWithSelector(
            IStarkVerifier.verifyProof.selector,
            proof,
            pubInputs
        );

        (bool success, bytes memory returnData) = address(verifier).staticcall(callData);
        if (!success || returnData.length < 32) {
            return false;
        }

        return abi.decode(returnData, (bool));
    }

    // ========== Identity Rotation (2-step timelock) ==========

    /// @notice Propose a new identity commitment. Must be called via a valid
    ///         ZK-ACE proof through the EntryPoint.
    function proposeIdentityRotation(bytes32 newIdCom) external {
        _requireForExecute();
        pendingIdCom = newIdCom;
        rotationUnlocksAt = block.timestamp + ROTATION_DELAY;
        emit IdentityRotationProposed(idCom, newIdCom, rotationUnlocksAt);
    }

    /// @notice Confirm a pending identity rotation after the timelock expires.
    function confirmIdentityRotation() external {
        _requireForExecute();
        if (pendingIdCom == bytes32(0)) revert NoRotationPending();
        if (block.timestamp < rotationUnlocksAt) revert RotationTimelockActive(rotationUnlocksAt);

        bytes32 oldIdCom = idCom;
        idCom = pendingIdCom;
        // HIGH-4 fix: Do NOT reset zkNonce. The nonce is monotonically increasing
        // across identity rotations. Since rpCom = H(newIdCom, nonce), a proof
        // generated for the old identity cannot produce a valid rpCom for the new
        // identity (different idCom), regardless of the nonce value.
        // Resetting would create a replay window where old proofs with nonce=0
        // could theoretically match if rpCom collides (64-bit birthday = 2^32).
        pendingIdCom = bytes32(0);
        rotationUnlocksAt = 0;
        emit IdentityRotated(oldIdCom, idCom);
    }

    /// @notice Cancel a pending identity rotation.
    function cancelIdentityRotation() external {
        _requireForExecute();
        pendingIdCom = bytes32(0);
        rotationUnlocksAt = 0;
    }

    // ========== Emergency Pause ==========

    /// @dev Override to enforce pause on execute/executeBatch, but NOT on setPaused.
    function _requireForExecute() internal view override {
        _requireFromEntryPoint();
        // When paused, only setPaused(false) is allowed via direct call below.
        // All other executions (transfers, contract calls) are blocked.
        if (paused) revert AccountPaused();
    }

    /// @notice Toggle emergency pause. Bypasses the pause check so the account
    ///         can be unpaused even when paused. Still requires a valid ZK proof
    ///         through the EntryPoint (i.e., only the identity holder can unpause).
    function setPaused(bool _paused) external {
        _requireFromEntryPoint(); // requires valid proof, but NOT blocked by pause
        paused = _paused;
        emit Paused(_paused);
    }

    /// @notice Allow receiving ETH.
    receive() external payable {}
}
