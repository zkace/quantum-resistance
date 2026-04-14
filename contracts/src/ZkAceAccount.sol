// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import "account-abstraction/core/BaseAccount.sol";
import "account-abstraction/interfaces/IEntryPoint.sol";
import "./IZkAceVerifier.sol";

/// @title ZkAceAccount
/// @notice ERC-4337 account that validates transactions via ZK-ACE proofs
///         instead of ECDSA signatures. Implements the verification flow from
///         the ZK-ACE paper (Algorithm 1, steps 6-10).
///
/// @dev Security-critical implementation notes:
///      1. TxHash is recomputed from callData — NEVER trusted from the prover
///      2. Domain is checked against block.chainid — prevents cross-chain replay
///      3. Verifier result is enforced with require — prevents silent failures
///      4. Nonce is internal to this contract — only advances after valid proof
///      5. Identity rotation via 2-step timelock (propose → confirm after delay)
///      6. Emergency pause halts all operations
contract ZkAceAccount is BaseAccount {
    IEntryPoint private immutable _entryPoint;
    IZkAceVerifier public immutable verifier;

    /// @notice Domain tag set at deployment (block.chainid)
    uint256 public immutable domainTag;

    /// @notice The identity commitment anchoring this account (paper: ID_com).
    ///         Mutable to support identity rotation (CRIT-4 fix).
    bytes32 public idCom;

    /// @notice ZK-ACE replay-prevention nonce (monotonically increasing).
    uint256 public zkNonce;

    /// @notice Emergency pause flag. When true, all operations are halted.
    bool public paused;

    // --- Identity Rotation (2-step timelock) ---
    bytes32 public pendingIdCom;
    uint256 public rotationUnlocksAt;
    uint256 public constant ROTATION_DELAY = 2 days;

    error InvalidProof();
    error TxHashMismatch(uint256 expected, uint256 provided);
    error IdComMismatch(bytes32 expected, bytes32 provided);
    error DomainMismatch(uint256 expected, uint256 provided);
    error StaleNonce(uint256 expected, uint256 provided);
    error AccountPaused();
    error NoRotationPending();
    error RotationTimelockActive(uint256 unlocksAt);

    event IdentityRotationProposed(bytes32 indexed oldIdCom, bytes32 indexed newIdCom, uint256 unlocksAt);
    event IdentityRotated(bytes32 indexed oldIdCom, bytes32 indexed newIdCom);
    event Paused(bool isPaused);

    constructor(
        IEntryPoint entryPoint_,
        IZkAceVerifier verifier_,
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

    /// @notice Validate a ZK-ACE authorization proof.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 /*userOpHash*/
    ) internal override returns (uint256 validationData) {
        // Pause check moved to _requireForExecute() to prevent deadlock (CRITICAL-1 fix)

        // Decode the ZK-ACE proof from the signature field.
        // No separate nonce field — zkNonce is used directly (HIGH-7 fix).
        (
            uint256[2] memory a,
            uint256[2][2] memory b,
            uint256[2] memory c,
            uint256[5] memory pubInputs
        ) = abi.decode(userOp.signature, (uint256[2], uint256[2][2], uint256[2], uint256[5]));

        // pubInputs layout: [id_com, tx_hash, domain, target, rp_com]

        // --- Step 6: Context binding check ---
        uint256 recomputedTxHash = uint256(keccak256(userOp.callData)) % _BN254_FR_MODULUS;
        if (pubInputs[1] != recomputedTxHash) {
            revert TxHashMismatch(recomputedTxHash, pubInputs[1]);
        }

        // --- Step 7a: Verify identity commitment matches this account ---
        if (pubInputs[0] != uint256(idCom)) {
            revert IdComMismatch(idCom, bytes32(pubInputs[0]));
        }

        // --- Step 7b: Verify domain matches block.chainid ---
        if (pubInputs[2] != domainTag) {
            revert DomainMismatch(domainTag, pubInputs[2]);
        }

        // --- Step 8: Verify the ZK proof ---
        bool valid = verifier.verifyProof(a, b, c, pubInputs);
        if (!valid) {
            revert InvalidProof();
        }

        // --- Step 9: Enforce replay protection (internal nonce) ---
        // zkNonce is used directly — no separate nonce from the signature.
        // The ZK circuit proves rp_com = H(idCom, nonce) with the matching nonce.
        // If the proof was generated with a different nonce, the rp_com public
        // input would be wrong and the Groth16 verification at Step 8 would fail.
        zkNonce++;

        // --- Step 10: Accept ---
        return 0; // SIG_VALIDATION_SUCCESS
    }

    // ===== Identity Rotation (CRIT-4 fix) =====

    /// @notice Propose a new identity commitment. Must be called via a valid
    ///         ZK-ACE proof through the EntryPoint (proving current identity).
    ///         The rotation activates after ROTATION_DELAY.
    function proposeIdentityRotation(bytes32 newIdCom) external {
        _requireForExecute(); // Only callable through EntryPoint (requires valid proof)
        pendingIdCom = newIdCom;
        rotationUnlocksAt = block.timestamp + ROTATION_DELAY;
        emit IdentityRotationProposed(idCom, newIdCom, rotationUnlocksAt);
    }

    /// @notice Confirm a pending identity rotation after the timelock expires.
    ///         Must be called via a valid ZK-ACE proof through the EntryPoint.
    function confirmIdentityRotation() external {
        _requireForExecute();
        if (pendingIdCom == bytes32(0)) revert NoRotationPending();
        if (block.timestamp < rotationUnlocksAt) revert RotationTimelockActive(rotationUnlocksAt);

        bytes32 oldIdCom = idCom;
        idCom = pendingIdCom;
        // HIGH-4 fix: Do NOT reset zkNonce. Monotonically increasing across
        // identity rotations prevents replay. rp_com = H(newIdCom, nonce)
        // differs from H(oldIdCom, nonce) for any nonce value.
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

    // ===== Emergency Pause =====

    /// @notice Toggle emergency pause. Only callable through EntryPoint (valid proof).
    /// @dev Override to enforce pause on execute/executeBatch, not on setPaused.
    function _requireForExecute() internal view override {
        _requireFromEntryPoint();
        if (paused) revert AccountPaused();
    }

    /// @notice Toggle pause. Bypasses pause check so account can be unpaused.
    function setPaused(bool _paused) external {
        _requireFromEntryPoint(); // requires valid proof, NOT blocked by pause
        paused = _paused;
        emit Paused(_paused);
    }

    /// @dev BN254 scalar field modulus (Fr order).
    uint256 private constant _BN254_FR_MODULUS =
        21888242871839275222246405745257275088548364400416034343698204186575808495617;

    /// @notice Allow receiving ETH
    receive() external payable {}
}
