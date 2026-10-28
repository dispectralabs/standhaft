// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {EntryPoint} from "account-abstraction/core/EntryPoint.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";
import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {StandhaftAccount} from "../../src/ep/StandhaftAccount.sol";
import {MockVerifier} from "../../src/verifier/MockVerifier.sol";
import {PaymasterSkeleton} from "../../src/ep/PaymasterSkeleton.sol";

/// @title PaymasterSkeletonTest — sponsored userOp flow through the REAL EntryPoint.
contract PaymasterSkeletonTest is Test {
    EntryPoint internal ep;
    MockVerifier internal verifier;
    PaymasterSkeleton internal paymaster;
    StandhaftAccount internal account;
    Recipient internal recipient;

    bytes32 internal constant CMT = bytes32(uint256(uint160(0xB0B)));

    function setUp() public {
        ep = new EntryPoint();
        verifier = new MockVerifier();
        paymaster = new PaymasterSkeleton(IEntryPoint(address(ep)));
        account = new StandhaftAccount(CMT, address(verifier), IEntryPoint(address(ep)));
        recipient = new Recipient();

        // sponsor deposits gas money on the EntryPoint
        paymaster.deposit{value: 1 ether}();
    }

    function _sponsoredOp(address to, uint256 value) internal view returns (PackedUserOperation memory op) {
        op.sender = address(account);
        op.nonce = ep.getNonce(address(account), 0);
        op.callData = abi.encodeCall(BaseAccount.execute, (to, value, new bytes(0)));
        op.accountGasLimits = bytes32((uint256(uint128(500_000)) << 128) | uint128(2_000_000));
        op.preVerificationGas = 60_000;
        op.gasFees = bytes32((uint256(uint128(1 gwei)) << 128) | uint128(2 gwei));
        // v0.8 paymasterAndData: paymaster(20) ++ verificationGasLimit(u128) ++ postOpGasLimit(u128)
        op.paymasterAndData = abi.encodePacked(address(paymaster), uint128(300_000), uint128(150_000));
        bytes32 userOpHash = ep.getUserOpHash(op);
        op.signature = abi.encodePacked(bytes1(0x01), CMT, userOpHash);
    }

    function test_sponsored_transfer() public {
        // Sponsor pays the GAS; the transferred VALUE still comes from the account.
        vm.deal(address(account), 1 ether);
        assertEq(address(account).balance, 1 ether);

        PackedUserOperation memory op = _sponsoredOp(address(recipient), 0.2 ether);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        ep.handleOps(ops, payable(makeAddr("beneficiary")));

        assertEq(address(recipient).balance, 0.2 ether);
        // sponsor's EP deposit shrank by the gas cost
        assertLt(ep.balanceOf(address(paymaster)), 1 ether);
        // account only paid the VALUE, never gas
        assertEq(address(account).balance, 0.8 ether);
    }

    function test_sponsor_cost_cap_enforced() public {
        // deep deposits so AA31 (deposit too low) cannot fire before the cap check
        paymaster.deposit{value: 30 ether}();

        PackedUserOperation memory op = _sponsoredOp(address(recipient), 0.2 ether);
        op.gasFees = bytes32((uint256(uint128(4000 gwei)) << 128) | uint128(8000 gwei));
        bytes32 userOpHash = ep.getUserOpHash(op);
        op.signature = abi.encodePacked(bytes1(0x01), CMT, userOpHash);

        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        // inspect the wrapped revert instead of matching exact gas math
        (bool ok, bytes memory ret) =
            address(ep).call(abi.encodeCall(IEntryPoint.handleOps, (ops, payable(makeAddr("beneficiary")))));
        assertFalse(ok, "handleOps should revert on cap");

        bytes memory payload = _stripSelector(ret);
        (uint256 opIndex, string memory reason, bytes memory inner) = abi.decode(payload, (uint256, string, bytes));
        assertEq(opIndex, 0);
        assertEq(reason, "AA33 reverted");

        // inner = compact [selector(4) || maxCost(32) || cap(32)] — not word aligned
        uint256 firstWord;
        uint256 maxCost;
        uint256 cap;
        assembly ("memory-safe") {
            firstWord := mload(add(inner, 0x20))
            maxCost := mload(add(inner, 0x24))
            cap := mload(add(inner, 0x44))
        }
        assertEq(
            firstWord >> 224,
            uint256(bytes32(PaymasterSkeleton.SponsorCostExceeded.selector)) >> 224,
            "our cap error fired"
        );
        assertEq(cap, 0.5 ether, "cap value enforced");
        assertGt(maxCost, 0);
    }

    function test_owner_can_tighten_cap() public {
        paymaster.deposit{value: 30 ether}();
        paymaster.setMaxSponsorCost(0);
        PackedUserOperation memory op = _sponsoredOp(address(recipient), 0.2 ether);
        PackedUserOperation[] memory ops = new PackedUserOperation[](1);
        ops[0] = op;

        (bool ok, bytes memory ret) =
            address(ep).call(abi.encodeCall(IEntryPoint.handleOps, (ops, payable(makeAddr("beneficiary")))));
        assertFalse(ok, "handleOps should revert when cap is 0");

        (,, bytes memory inner) = abi.decode(_stripSelector(ret), (uint256, string, bytes));

        uint256 firstWord;
        uint256 maxCost;
        uint256 cap;
        assembly ("memory-safe") {
            firstWord := mload(add(inner, 0x20))
            maxCost := mload(add(inner, 0x24))
            cap := mload(add(inner, 0x44))
        }
        assertEq(
            firstWord >> 224,
            uint256(bytes32(PaymasterSkeleton.SponsorCostExceeded.selector)) >> 224,
            "our cap error fired"
        );
        assertEq(cap, 0, "cap tightened to zero");
        assertGt(maxCost, 0);
    }

    function test_withdraw_to_treasury() public {
        paymaster.deposit{value: 0.1 ether}();
        uint256 depositBefore = ep.balanceOf(address(paymaster));
        address treasury = makeAddr("treasury");
        uint256 before = treasury.balance;
        paymaster.withdrawTo(payable(treasury), depositBefore);
        assertEq(treasury.balance, before + depositBefore);
        assertEq(ep.balanceOf(address(paymaster)), 0);
    }

    function test_only_owner_can_set_cap() public {
        vm.prank(makeAddr("random"));
        vm.expectRevert();
        paymaster.setMaxSponsorCost(0);
    }

    /// @dev Drops the 4-byte error selector so abi.decode sees pure args.
    function _stripSelector(bytes memory data) internal pure returns (bytes memory out) {
        require(data.length >= 4, "short");
        out = new bytes(data.length - 4);
        for (uint256 i = 0; i < out.length; ++i) {
            out[i] = data[i + 4];
        }
    }
}

contract Recipient {
    receive() external payable {}
}
