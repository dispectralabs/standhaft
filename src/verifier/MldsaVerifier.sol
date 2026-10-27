// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {IMLDSAVerifier, ML_DSA_44} from "mldsa-solidity/IMLDSAVerifier.sol";
import {IVaultVerifier} from "../engine/IVaultVerifier.sol";

/// @title MldsaVerifier — direct ML-DSA-44 (FIPS 204) verification adapter
/// @notice Proof layout: `publicKey (1312 bytes) || signature (2420 bytes)`.
///         Steps: (1) keccak256(publicKey) must equal the vault's commitment — this is
///         the identity binding; (2) ML-DSA-44.Verify(publicKey, messageHash, signature).
///         The signed message is the 32-byte digest itself (pure ML-DSA, empty context),
///         matching what the Rust CLI (`standhaft-cli sign`) signs.
/// @dev    The PQ public key IS revealed in the proof (direct path). That is quantum-safe
///         (ML-DSA public keys cannot be inverted, even quantumly) but leaves an HNDL
///         paper trail. The ZK path (signature+key hidden) is the later upgrade.
contract MldsaVerifier is IVaultVerifier {
    uint256 public constant PK_LEN = 1312;
    uint256 public constant SIG_LEN = 2420;

    /// @notice The underlying FIPS 204 verifier (deploy as MLDSAVerifier(address(0))
    ///         for the full, stateless verification path).
    IMLDSAVerifier public immutable mldsa;

    constructor(IMLDSAVerifier mldsa_) {
        mldsa = mldsa_;
    }

    function verify(bytes32 commitment, bytes32 messageHash, bytes calldata proof)
        external
        view
        override
        returns (bool valid)
    {
        if (proof.length != PK_LEN + SIG_LEN) return false;
        bytes calldata publicKey = proof[:PK_LEN];
        bytes calldata signature = proof[PK_LEN:];
        if (keccak256(publicKey) != commitment) return false;
        return mldsa.verify(ML_DSA_44, publicKey, abi.encodePacked(messageHash), signature);
    }

    function scheme() external pure returns (string memory) {
        return "ML-DSA-44";
    }
}
