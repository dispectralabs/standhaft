// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {IVaultVerifier} from "../engine/IVaultVerifier.sol";

/// @title MockVerifier — deterministic test double. NOT production code.
/// @notice Accepts a proof of exactly 65 bytes: 0x01 || commitment(32) || messageHash(32).
///         Anything else is false. Lets engine tests run without 8M-gas lattice math.
contract MockVerifier is IVaultVerifier {
    function verify(bytes32 commitment, bytes32 messageHash, bytes calldata proof)
        external
        pure
        override
        returns (bool valid)
    {
        if (proof.length != 65) return false;
        if (proof[0] != 0x01) return false;
        return bytes32(proof[1:33]) == commitment && bytes32(proof[33:65]) == messageHash;
    }

    function scheme() external pure returns (string memory) {
        return "mock";
    }
}
