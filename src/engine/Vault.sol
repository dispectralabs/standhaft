// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {IVaultVerifier} from "./IVaultVerifier.sol";

/// @title Vault — the post-quantum safe. Holds funds; opens only for a valid PQ proof.
/// @notice Architecture (the core standhaft design):
///         - The vault stores ONLY `commitment = keccak256(PQ_public_key)`.
///           The PQ public key and signature are never required to exist on-chain.
///         - There is NO owner key, NO admin, NO upgrade. The ONLY way to move funds
///           is `execute`/`executeBatch` with a proof the `verifier` accepts.
///         - Relaying is permissionless: any account may submit the transaction.
///           The proof — not the caller — is the authorization.
///
///         Canonical message preimage (sign THIS digest with the PQ key):
///         single call:  msgHash = keccak256(abi.encode(chainid, vault, target, value, keccak256(data), nonce))
///         batch:        callsHash = keccak256(abi.encodePacked(keccak256(abi.encode(t,v,keccak256(d))), ...))
///                       msgHash = keccak256(abi.encode(chainid, vault, callsHash, nonce))
/// @dev    Nonce increments on every accepted execution (replay protection).
///         `verifier` is immutable and constructed at deploy — never mutable.
contract Vault {
    event Executed(address indexed target, uint256 indexed value, bytes data, uint256 nonce);
    event ExecutedBatch(uint256 count, uint256 nonce);
    event Received(address indexed from, uint256 value);

    error InvalidProof();
    error CallFailed(address target, bytes returndata);

    /// @notice keccak256 of the PQ public key that owns this vault.
    bytes32 public immutable commitment;
    /// @notice IVaultVerifier that judges proofs. Immutable: no admin path to swap it.
    address public immutable verifier;

    uint256 public nonce;

    constructor(bytes32 commitment_, address verifier_) {
        commitment = commitment_;
        verifier = verifier_;
    }

    /// @notice Accept native deposits.
    receive() external payable {
        emit Received(msg.sender, msg.value);
    }

    /// @notice Execute a single call. Permissionless relay: proof is the authorization.
    function execute(address target, uint256 value, bytes calldata data, bytes calldata proof)
        external
        returns (bool success)
    {
        uint256 n = nonce;
        bytes32 msgHash = keccak256(
            abi.encode(block.chainid, address(this), target, value, keccak256(data), n)
        );
        _accept(msgHash, proof);
        nonce = n + 1;

        (success, ) = target.call{value: value}(data);
        if (!success) revert CallFailed(target, _returnData());
        emit Executed(target, value, data, n);
    }

    /// @notice Execute a batch of calls atomically: any failing call reverts everything.
    struct Call {
        address target;
        uint256 value;
        bytes data;
    }

    function executeBatch(Call[] calldata calls, bytes calldata proof) external {
        uint256 n = nonce;
        bytes32 callsHash = _hashCalls(calls);
        bytes32 msgHash = keccak256(abi.encode(block.chainid, address(this), callsHash, n));
        _accept(msgHash, proof);
        nonce = n + 1;

        uint256 len = calls.length;
        for (uint256 i = 0; i < len; ++i) {
            (bool success, ) = calls[i].target.call{value: calls[i].value}(calls[i].data);
            if (!success) revert CallFailed(calls[i].target, _returnData());
        }
        emit ExecutedBatch(len, n);
    }

    // ---------------------------------------------------------------- helpers

    function _accept(bytes32 msgHash, bytes calldata proof) internal view {
        // Replay protection lives inside the hash: the nonce is bound to the signed
        // digest, so a reused proof hashes differently and the verifier says no.
        if (!IVaultVerifier(verifier).verify(commitment, msgHash, proof)) revert InvalidProof();
    }

    function _hashCalls(Call[] calldata calls) internal pure returns (bytes32) {
        uint256 len = calls.length;
        bytes memory packedHashes = new bytes(32 * len);
        for (uint256 i = 0; i < len; ++i) {
            bytes32 h = keccak256(abi.encode(calls[i].target, calls[i].value, keccak256(calls[i].data)));
            assembly {
                mstore(add(add(packedHashes, 0x20), mul(i, 32)), h)
            }
        }
        return keccak256(packedHashes);
    }

    function _returnData() internal pure returns (bytes memory ret) {
        assembly ("memory-safe") {
            let size := returndatasize()
            ret := mload(0x40)
            mstore(0x40, add(ret, add(size, 0x20)))
            mstore(ret, size)
            returndatacopy(add(ret, 0x20), 0, size)
        }
    }
}
