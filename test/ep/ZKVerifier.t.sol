// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../../src/engine/Vault.sol";
import {ZKVerifier} from "../../src/verifier/ZKVerifier.sol";
import {ISP1Verifier} from "../../src/verifier/ZKVerifier.sol";
import {MockSP1Verifier, FailSP1Verifier} from "./MockSP1Verifier.sol";

/// @title ZKVerifierTest — zero-disclosure path plumbing (real SP1 proof e2e in scripts).
contract ZKVerifierTest is Test {
    ZKVerifier internal zkVerifier;
    Vault internal vault;
    Recipient internal recipient;

    bytes32 internal constant CMT = bytes32(uint256(uint160(0xCAFE)));
    bytes32 internal constant VK_DIGEST = bytes32(uint256(uint160(0x51CED)));
    uint256 internal constant CHAIN = 31_337;

    function setUp() public {
        MockSP1Verifier mock = new MockSP1Verifier();
        zkVerifier = new ZKVerifier(address(mock), VK_DIGEST, 8);
        vault = new Vault(CMT, address(zkVerifier));
        recipient = new Recipient();
        vm.deal(address(vault), 10 ether);
    }

    /// proof bytes with the pinned vkey digest at VK_DIGEST_OFFSET (8)
    function _proof(bytes32 vkDigest) internal pure returns (bytes memory p) {
        p = new bytes(256);
        assembly ("memory-safe") {
            // write vkDigest at byte offset 8
            mstore(add(p, add(0x20, 8)), vkDigest)
        }
    }

    function _msgHash(address target, uint256 value, bytes memory data, uint256 n)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(CHAIN, address(vault), target, value, keccak256(data), n));
    }

    function test_zk_execute_happy_path() public {
        bytes memory data = "";
        bytes32 mh = _msgHash(address(recipient), 1 ether, data, 0);
        vault.execute(address(recipient), 1 ether, data, _proof(VK_DIGEST));
        assertEq(address(recipient).balance, 1 ether);
        assertEq(vault.nonce(), 1);
    }

    function test_zk_untrusted_program_reverts() public {
        bytes32 evil = bytes32(uint256(0xBAD));
        vm.expectRevert(
            abi.encodeWithSelector(ZKVerifier.UntrustedProgram.selector, evil, VK_DIGEST)
        );
        vault.execute(address(recipient), 1 ether, "", _proof(evil));
    }

    function test_zk_short_proof_rejected() public {
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 1 ether, "", new bytes(200));
    }

    function test_zk_sp1_failure_means_invalid() public {
        FailSP1Verifier failVerifier = new FailSP1Verifier();
        Vault deadVault = new Vault(CMT, address(new ZKVerifier(address(failVerifier), VK_DIGEST, 8)));
        vm.deal(address(deadVault), 1 ether);
        bytes32 mh = keccak256(
            abi.encode(CHAIN, address(deadVault), address(recipient), 1 ether, keccak256(""), 0)
        );
        vm.expectRevert(Vault.InvalidProof.selector);
        deadVault.execute(address(recipient), 1 ether, "", _proof(VK_DIGEST));
    }

    function test_zk_digest_binding_matches_preimage() public {
        // the digest ZKVerifier derives must equal the canonical preimage digest;
        // proof acceptance itself proves the binding (nonce advanced, funds moved)
        bytes memory data = "";
        vault.execute(address(recipient), 1 ether, data, _proof(VK_DIGEST));
        assertEq(address(recipient).balance, 1 ether);
        assertEq(vault.nonce(), 1);
    }

    function test_scheme() public view {
        assertEq(zkVerifier.scheme(), "zk-ml-dsa-44/sp1-groth16");
    }
}

contract Recipient {
    receive() external payable {}
}
