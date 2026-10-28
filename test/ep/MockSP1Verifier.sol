// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {ISP1Verifier} from "../../src/verifier/ZKVerifier.sol";

/// @title MockSP1Verifier — accepts any proof ≥ 4 bytes. TEST ONLY.
contract MockSP1Verifier is ISP1Verifier {
    function verify(bytes memory proof, bytes32) external pure override {
        require(proof.length >= 4, "mock: too short");
    }
}

/// @title FailSP1Verifier — always reverts (simulates invalid SP1 proof). TEST ONLY.
contract FailSP1Verifier is ISP1Verifier {
    function verify(bytes memory, bytes32) external pure override {
        revert("sp1: invalid proof");
    }
}
