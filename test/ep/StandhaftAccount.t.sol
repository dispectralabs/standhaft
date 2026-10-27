// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {IAccount} from "account-abstraction/interfaces/IAccount.sol";
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {StandhaftAccount} from "../../src/ep/StandhaftAccount.sol";
import {MockVerifier} from "../../src/verifier/MockVerifier.sol";

/// @title StandhaftAccountTest — ERC-4337 v0.8 integration against the REAL EntryPoint.
contract StandhaftAccountTest is Test {
    EntryPoint internal ep;
    MockVerifier internal verifier;
    StandhaftAccount internal account;
    Recipient internal recipient;

    bytes32 internal constant CMT = bytes32(uint256(uint160(0xA11CE)));

    function setUp() public {
        ep = new EntryPoint();
        verifier = new MockVerifier();
        account = new StandhaftAccount(CMT, address(verifier), IEntryPoint(address(ep)));
        recipient = new Recipient();
        vm.deal(address(account), 2 ether);
    }

    // ------------------------------------------------------- validateUserOp

    /// Build a userOp whose `signature` is a valid mock proof over EP's userOpHash.
    function _op(address to, uint256 value) internal view returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = ep.getNonce(address(account), 0);
        op.callData = abi.encodeCall(BaseAccount.execute, (to, value, new bytes(0)));
        op.accountGasLimits =
            bytes32((uint256(uint128(500_000)) << 128) | uint128(2_000_000));
        op.preVerificationGas = 60_000;
        op.gasFees = bytes32((uint256(uint128(1 gwei)) << 128) | uint128(2 gwei));
        bytes32 userOpHash = ep.getUserOpHash(op);
        op.signature = abi.encodePacked(bytes1(0x01), CMT, userOpHash);
    }

    function test_validate_userop_accepts_valid_proof() public {
        PackedUserOperation memory op = _op(address(recipient), 0.1 ether);
        bytes32 userOpHash = ep.getUserOpHash(op);
        vm.prank(address(ep));
        uint256 v = IAccount(address(account)).validateUserOp(op, userOpHash, 0);
        assertEq(v, 0); // success
    }

    function test_validate_userop_rejects_wrong_proof() public {
        PackedUserOperation memory op = _op(address(recipient), 0.1 ether);
        op.signature = abi.encodePacked(bytes1(0x01), CMT, bytes32(uint256(123)));
        bytes32 userOpHash = ep.getUserOpHash(op);
        vm.prank(address(ep));
        uint256 v = IAccount(address(account)).validateUserOp(op, userOpHash, 0);
        assertEq(v, 1); // SIG_VALIDATION_FAILED
    }

    function test_validate_userop_only_entrypoint() public {
        PackedUserOperation memory op = _op(address(recipient), 0.1 ether);
        bytes32 userOpHash = ep.getUserOpHash(op);
        vm.prank(makeAddr("notEP"));
        vm.expectRevert("account: not from EntryPoint");
        IAccount(address(account)).validateUserOp(op, userOpHash, 0);
    }

    function test_validate_userop_pays_prefund_to_ep() public {
        PackedUserOperation memory op = _op(address(recipient), 0.1 ether);
        bytes32 userOpHash = ep.getUserOpHash(op);
        vm.prank(address(ep));
        IAccount(address(account)).validateUserOp(op, userOpHash, 0.05 ether);
        assertEq(address(ep).balance, 0.05 ether); // received from account
        assertLt(address(account).balance, 2 ether);
    }

    // ------------------------------------------------------ full handleOps

    function test_handle_ops_end_to_end() public {
        PackedUserOperation memory op = _op(address(recipient), 0.3 ether);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        ep.handleOps(ops, payable(makeAddr("beneficiary")));

        assertEq(address(recipient).balance, 0.3 ether);
        // nonce consumed on the EP
        assertEq(ep.getNonce(address(account), 0), 1);
    }

    function test_handle_ops_rejects_invalid_proof() public {
        PackedUserOperation memory op = _op(address(recipient), 0.3 ether);
        op.signature = hex"deadbeef";
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        vm.expectRevert(abi.encodeWithSelector(IEntryPoint.FailedOp.selector, 0, "AA24 signature error"));
        ep.handleOps(ops, payable(makeAddr("beneficiary")));
    }

    function test_handle_ops_replay_rejected() public {
        PackedUserOperation memory op = _op(address(recipient), 0.3 ether);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;
        ep.handleOps(ops, payable(makeAddr("beneficiary")));

        // exact same op again: nonce mismatch on EP → FailedOp
        PackedUserOperation[] memory ops2 = new PackedUserOperation[](1);
        ops2[0] = op;
        vm.expectRevert();
        ep.handleOps(ops2, payable(makeAddr("beneficiary")));
    }

    function test_execute_is_entrypoint_gated() public {
        vm.expectRevert("account: not from EntryPoint");
        account.execute(address(recipient), 0, "");
    }
}

contract Recipient {
    receive() external payable {}
}
