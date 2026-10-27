// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

/// @notice Vendor/lib compile sanity: proves the toolchain (solc 0.8.37, via_ir),
///         remappings and every external lib link correctly before engine work starts.

import {Test} from "forge-std/Test.sol";

import {MLDSAVerifier} from "mldsa-solidity/MLDSAVerifier.sol";
import {IMLDSAVerifier, ML_DSA_44, ML_DSA_65} from "mldsa-solidity/IMLDSAVerifier.sol";
import {PQAlgorithms} from "pq-verifier-interface/PQAlgorithms.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {IPaymaster} from "account-abstraction/interfaces/IPaymaster.sol";

contract SanityTest is Test {
    function test_mldsa_verifier_deploys_and_supports_param_sets() public {
        MLDSAVerifier v = new MLDSAVerifier(address(0)); // no precompute factory -> full path
        assertTrue(v.supportsParamSet(ML_DSA_44));
        assertTrue(v.supportsParamSet(ML_DSA_65));
        assertEq(uint256(PQAlgorithms.ML_DSA_44), 0x0101);
        // wrong-size key: verify returns false, never reverts
        assertFalse(v.verify(ML_DSA_44, hex"00", hex"00", hex"00"));
    }

    function test_4337_interfaces_link() public pure {
        assertTrue(type(IEntryPoint).interfaceId != bytes4(0));
        assertTrue(type(IAccount).interfaceId != bytes4(0));
        assertTrue(type(IPaymaster).interfaceId != bytes4(0));

        // struct fields resolve through the import
        PackedUserOperation memory op;
        assertEq(op.callData.length, 0);
    }
}
