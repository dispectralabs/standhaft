// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IVaultVerifier} from "../engine/IVaultVerifier.sol";

/// @title StandhaftAccount — ERC-4337 (v0.8) smart account secured by a PQ proof
/// @notice Same engine as `Vault` (commitment + IVaultVerifier), wrapped in the
///         ERC-4337 `IAccount` interface:
///         - `userOpHash` (computed and passed by the EntryPoint) is the signed digest.
///         - `userOp.signature` carries the IVaultVerifier proof.
///         - validationData = 0 on success, 1 (SIG_VALIDATION_FAILED) otherwise.
/// @dev    Extends the audited `BaseAccount` (eth-infinitism v0.8): execute/executeBatch
///         are EntryPoint-gated; nonce is managed by the EntryPoint (NonceManager).
contract StandhaftAccount is BaseAccount {
    IEntryPoint private immutable _entryPoint;
    /// @notice keccak256(PQ public key) — the only identity stored on-chain.
    bytes32 public immutable commitment;
    /// @notice IVaultVerifier judging proofs. Immutable.
    address public immutable verifier;

    constructor(bytes32 commitment_, address verifier_, IEntryPoint entryPoint_) {
        commitment = commitment_;
        verifier = verifier_;
        _entryPoint = entryPoint_;
    }

    /// @inheritdoc BaseAccount
    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    /// @notice PQ proof over `userOpHash` replaces the classic ECDSA check.
    function _validateSignature(PackedUserOperation calldata userOp, bytes32 userOpHash)
        internal
        view
        override
        returns (uint256 validationData)
    {
        bool ok = IVaultVerifier(verifier).verify(commitment, userOpHash, userOp.signature);
        validationData = ok ? 0 : 1; // 1 == SIG_VALIDATION_FAILED
    }
}
