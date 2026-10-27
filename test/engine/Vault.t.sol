// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../../src/engine/Vault.sol";
import {VaultFactory} from "../../src/engine/VaultFactory.sol";
import {MockVerifier} from "../../src/verifier/MockVerifier.sol";
import {IVaultVerifier} from "../../src/engine/IVaultVerifier.sol";

/// @dev Helper recipient that can receive ETH and accept calls.
contract Recipient {
    uint256 public got;

    receive() external payable {
        got += msg.value;
    }

    function setGot(uint256 v) external {
        got = v;
    }
}

/// @dev Failing recipient (rejects ETH) — for CallFailed path.
contract Rejector {
    receive() external payable {
        revert("no");
    }
}

contract VaultTest is Test {
    Vault internal vault;
    MockVerifier internal mockVerifier;
    Recipient internal recipient;

    bytes32 internal constant CMT =
        bytes32(uint256(uint160(0xA11CE)));
    uint256 internal constant CHAIN = 31_337;

    function setUp() public {
        mockVerifier = new MockVerifier();
        vault = new Vault(CMT, address(mockVerifier));
        recipient = new Recipient();
        vm.deal(address(vault), 10 ether);
    }

    // ---------------------------------------------------------- proof helper

    /// Build a valid mock proof for the canonical single-call preimage.
    function _proof(address target, uint256 value, bytes memory data, uint256 n)
        internal
        view
        returns (bytes memory)
    {
        bytes32 msgHash =
            keccak256(abi.encode(CHAIN, address(vault), target, value, keccak256(data), n));
        return abi.encodePacked(bytes1(0x01), CMT, msgHash);
    }

    function _proofBatch(Vault.Call[] memory calls, uint256 n) internal view returns (bytes memory) {
        bytes32[] memory hs = new bytes32[](calls.length);
        for (uint256 i = 0; i < calls.length; ++i) {
            hs[i] = keccak256(abi.encode(calls[i].target, calls[i].value, keccak256(calls[i].data)));
        }
        bytes32 callsHash = keccak256(abi.encodePacked(hs));
        bytes32 msgHash = keccak256(abi.encode(CHAIN, address(vault), callsHash, n));
        return abi.encodePacked(bytes1(0x01), CMT, msgHash);
    }

    // ------------------------------------------------------------ happy path

    function test_execute_transfers_and_increments_nonce() public {
        bytes memory data = "";
        bytes memory proof = _proof(address(recipient), 1 ether, data, 0);

        vault.execute(address(recipient), 1 ether, data, proof);

        assertEq(address(recipient).balance, 1 ether);
        assertEq(vault.nonce(), 1);
        assertEq(vault.nonce(), 1);
    }

    function test_execute_permissionless_relay() public {
        // A stranger relays the transaction; the proof is what authorizes.
        bytes memory data = "";
        bytes memory proof = _proof(address(recipient), 0.5 ether, data, 0);
        vm.prank(makeAddr("stranger"));
        vault.execute(address(recipient), 0.5 ether, data, proof);
        assertEq(address(recipient).balance, 0.5 ether);
    }

    function test_execute_with_calldata() public {
        // data = setGot(42) on recipient
        bytes memory data = abi.encodeWithSignature("setGot(uint256)", uint256(42));
        bytes memory proof = _proof(address(recipient), 0, data, 0);
        vault.execute(address(recipient), 0, data, proof);
        assertEq(recipient.got(), 42);
    }

    // ----------------------------------------------------------- rejections

    function test_execute_invalid_proof_reverts() public {
        bytes memory data = "";
        bytes memory bad = hex"deadbeef";
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 1 ether, data, bad);
    }

    function test_execute_tampered_value_fails() public {
        // signed for 1 ether, request sends 2 ether
        bytes memory data = "";
        bytes memory proof = _proof(address(recipient), 1 ether, data, 0);
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 2 ether, data, proof);
    }

    function test_execute_tampered_target_fails() public {
        Recipient other = new Recipient();
        bytes memory data = "";
        bytes memory proof = _proof(address(recipient), 1 ether, data, 0);
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(other), 1 ether, data, proof);
    }

    function test_execute_tampered_data_fails() public {
        bytes memory data = abi.encodeWithSignature("setGot(uint256)", uint256(1));
        bytes memory proof = _proof(address(recipient), 0, data, 0);
        bytes memory changed = abi.encodeWithSignature("setGot(uint256)", uint256(2));
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 0, changed, proof);
    }

    function test_execute_nonce_bound_in_digest() public {
        // A proof signed for nonce 5 can never execute while the vault is at nonce 0:
        // the digest baked into the signature does not match the one the vault computes.
        bytes memory data = "";
        bytes memory proof = _proof(address(recipient), 1 ether, data, 5);
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 1 ether, data, proof);
    }

    function test_execute_replay_rejected() public {
        bytes memory data = "";
        bytes memory proof = _proof(address(recipient), 1 ether, data, 0);
        vault.execute(address(recipient), 1 ether, data, proof);
        // exact same proof: vault is now at nonce 1, digest differs → verifier says no
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 1 ether, data, proof);
        assertEq(vault.nonce(), 1);
    }

    function test_execute_proof_for_other_vault_rejected() public {
        // Proof is bound to the vault address: a valid proof for vaultB is invalid on vaultA.
        Vault vaultB = new Vault(CMT, address(mockVerifier));
        vm.deal(address(vaultB), 1 ether);
        bytes memory data = "";
        bytes32 msgHashB = keccak256(
            abi.encode(CHAIN, address(vaultB), address(recipient), 1 ether, keccak256(data), 0)
        );
        bytes memory proofB = abi.encodePacked(bytes1(0x01), CMT, msgHashB);

        // execute vaultB's transaction on vaultA → digest mismatch
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 1 ether, data, proofB);
    }

    function test_execute_cross_chain_replay_rejected() public {
        // same params but signed for chain 1 — our tests run on 31337
        bytes memory data = "";
        bytes32 msgHash = keccak256(abi.encode(1, address(vault), address(recipient), 1 ether, keccak256(data), 0));
        bytes memory proof = abi.encodePacked(bytes1(0x01), CMT, msgHash);
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.execute(address(recipient), 1 ether, data, proof);
    }

    function test_execute_call_failure_bubbles() public {
        Rejector rejector = new Rejector();
        bytes memory data = "";
        bytes memory proof = _proof(address(rejector), 1 wei, data, 0);
        vm.expectRevert();
        vault.execute(address(rejector), 1 wei, data, proof);
        // nonce must NOT have advanced on failure
        assertEq(vault.nonce(), 0);
    }

    // ---------------------------------------------------------------- batch

    function test_execute_batch_two_calls() public {
        Recipient r2 = new Recipient();
        Vault.Call[] memory calls = new Vault.Call[](2);
        calls[0] = Vault.Call(address(recipient), 1 ether, "");
        calls[1] = Vault.Call(address(r2), 2 ether, "");

        bytes memory proof = _proofBatch(calls, 0);
        vault.executeBatch(calls, proof);

        assertEq(address(recipient).balance, 1 ether);
        assertEq(address(r2).balance, 2 ether);
        assertEq(vault.nonce(), 1);
    }

    function test_execute_batch_atomic_failure() public {
        Rejector rejector = new Rejector();
        Vault.Call[] memory calls = new Vault.Call[](2);
        calls[0] = Vault.Call(address(recipient), 1 ether, "");
        calls[1] = Vault.Call(address(rejector), 1 wei, "");

        bytes memory proof = _proofBatch(calls, 0);
        vm.expectRevert();
        vault.executeBatch(calls, proof);

        // atomic: nothing moved, nonce unchanged
        assertEq(address(recipient).balance, 0);
        assertEq(vault.nonce(), 0);
    }

    function test_execute_batch_wrong_proof_rejected() public {
        Vault.Call[] memory calls = new Vault.Call[](1);
        calls[0] = Vault.Call(address(recipient), 1 ether, "");
        // single-call proof instead of batch proof
        bytes memory wrong = _proof(address(recipient), 1 ether, "", 0);
        vm.expectRevert(Vault.InvalidProof.selector);
        vault.executeBatch(calls, wrong);
    }

    // ----------------------------------------------------------- deposits etc

    function test_receive_emits_and_tracks() public {
        vm.expectEmit(true, false, false, true);
        emit Vault.Received(address(this), 3 ether);
        (bool ok,) = address(vault).call{value: 3 ether}("");
        assertTrue(ok);
    }

    function test_immutables_fixed_at_deploy() public view {
        assertEq(vault.commitment(), CMT);
        assertEq(vault.verifier(), address(mockVerifier));
        assertEq(IVaultVerifier(vault.verifier()).scheme(), "mock");
    }

    function test_fuzz_execute_valid_proofs(address target, uint96 value, bytes calldata data)
        public
    {
        vm.assume(target != address(0));
        vm.assume(uint160(target) > 0xff); // skip precompiles & system addresses
        vm.assume(target.code.length == 0);
        vm.assume(value <= address(vault).balance);
        bytes memory proof = _proof(target, value, data, 0);
        uint256 before = target.balance;
        vault.execute(target, value, data, proof);
        assertEq(target.balance, before + value);
        assertEq(vault.nonce(), 1);
    }
}
