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
    bytes4 internal constant VK_PREFIX = 0x12345678;
    uint256 internal constant CHAIN = 31_337;
    /// SP1 v6 publicValues: commitment(32) || msgHash(32) || system(8)
    bytes internal constant SYSTEM = hex"0001020304050607";

    /// Builds the full proof param: [SP1 proof (4B prefix + 64B body)][publicValues 72B]
    function _proof(bytes4 prefix, bytes memory sp1Body, bytes32 cmt, bytes32 mh)
        internal
        pure
        returns (bytes memory)
    {
        return abi.encodePacked(prefix, sp1Body, cmt, mh, SYSTEM);
    }

    function _msgHash(address target, uint256 value, bytes memory data, uint256 n)
        internal
        view
        returns (bytes32)
    {
        return keccak256(abi.encode(CHAIN, address(vault), target, value, keccak256(data), n));
    }

    function setUp() public {
        MockSP1Verifier mock = new MockSP1Verifier();
        zkVerifier = new ZKVerifier(address(mock), VK_PREFIX);
        vault = new Vault(CMT, address(zkVerifier));
        recipient = new Recipient();
        vm.deal(address(vault), 10 ether);
    }

    function test_zk_execute_happy_path() public {
        bytes memory data = "";
        bytes32 mh = _msgHash(address(recipient), 1 ether, data, 0);
        bytes memory proof = _proof(VK_PREFIX, bytes.concat(hex"beefcafe", new bytes(60)), CMT, mh);
        vault.execute(address(recipient), 1 ether, data, proof);
        assertEq(address(recipient).balance, 1 ether);
        assertEq(vault.nonce(), 1);
    }

    function test_zk_untrusted_program_prefix_reverts() public {
        bytes32 mh = _msgHash(address(recipient), 1 ether, "", 0);
        bytes memory proof = _proof(0xDEADBEAF, bytes.concat(hex"beefcafe", new bytes(60)), CMT, mh);
        vm.expectRevert(
            abi.encodeWithSelector(ZKVerifier.UntrustedProgram.selector, bytes4(0xdeadbeaf), VK_PREFIX)
        );
        vault.execute(address(recipient), 1 ether, "", proof);
    }

    function test_zk_public_values_commitment_tamper_rejected() public {
        bytes32 mh = _msgHash(address(recipient), 1 ether, "", 0);
        bytes32 evilCmt = bytes32(uint256(uint160(0xBAD)));
        bytes memory proof = _proof(VK_PREFIX, bytes.concat(hex"beefcafe", new bytes(60)), evilCmt, mh);
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 1 ether, "", proof);
    }

    function test_zk_public_values_msghash_tamper_rejected() public {
        bytes32 mh = _msgHash(address(recipient), 1 ether, "", 0);
        bytes memory proof = _proof(VK_PREFIX, bytes.concat(hex"beefcafe", new bytes(60)), CMT, bytes32(uint256(1)));
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 1 ether, "", proof);
    }

    function test_zk_short_proof_rejected() public {
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 1 ether, "", new bytes(60));
    }

    function test_zk_sp1_failure_means_invalid() public {
        FailSP1Verifier fail = new FailSP1Verifier();
        Vault deadVault = new Vault(CMT, address(new ZKVerifier(address(fail), VK_PREFIX)));
        vm.deal(address(deadVault), 1 ether);
        bytes32 mh = keccak256(
            abi.encode(CHAIN, address(deadVault), address(recipient), 1 ether, keccak256(""), 0)
        );
        bytes memory proof = _proof(VK_PREFIX, bytes.concat(hex"beefcafe", new bytes(60)), CMT, mh);
        vm.expectRevert(Vault.InvalidProof.selector);
        deadVault.execute(address(recipient), 1 ether, "", proof);
    }

    function test_zk_digest_binding_matches_preimage() public {
        bytes memory data = "";
        vault.execute(address(recipient), 1 ether, data, _proof(VK_PREFIX, bytes.concat(hex"beefcafe", new bytes(60)), CMT, _msgHash(address(recipient), 1 ether, data, 0)));
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
