// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

/// @title IVaultVerifier — standhaft engine-level signature verification interface
/// @notice A vault stores ONLY a commitment (keccak256 of the PQ public key).
///         A verifier proves that `proof` demonstrates: "the holder of the PQ key
///         whose commitment is `commitment` signed `messageHash`".
///         The verifier NEVER receives the private key; depending on the scheme the
///         proof may reveal the signature+public key (direct path) or hide them (ZK path).
/// @dev    Verifiers must return `false` — never revert — on any malformed input.
interface IVaultVerifier {
    /// @return valid true iff the proof is a valid authorization of `messageHash`
    ///         by the key committed to `commitment`.
    function verify(bytes32 commitment, bytes32 messageHash, bytes calldata proof) external view returns (bool valid);

    /// @notice Human-readable scheme id, e.g. "ML-DSA-44" or "mock".
    function scheme() external view returns (string memory);
}
