// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {BasePaymaster} from "account-abstraction/core/BasePaymaster.sol";
import {UserOperationLib} from "account-abstraction/core/UserOperationLib.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

/// @title PaymasterSkeleton — gas sponsorship, skeleton quality. NOT production.
/// @notice Accepts any userOp whose sponsor (the paymaster owner) has deposited enough
///         (the EntryPoint enforces the deposit >= maxCost check itself). The actual
///         sponsor policy (who may be sponsored, caps, quotas) is intentionally left
///         to the real policy engine; see docs/KNOWN_ISSUES.md.
/// @dev    Extends the audited `BasePaymaster` (eth-infinitism v0.8); deposit/withdraw/
///         addStake come from StakeManager. The reported postOp-unbounded-gas issue in
///         v0.8 is EntryPoint-side; keep postOp gas low.
contract PaymasterSkeleton is BasePaymaster {
    using UserOperationLib for PackedUserOperation;

    /// @notice Cap per sponsored userOp (in wei), applied in validatePaymasterUserOp.
    uint256 public maxSponsorCost = 0.5 ether;

    event Sponsored(address indexed sender, bytes32 userOpHash, uint256 maxCost);

    constructor(IEntryPoint entryPoint) BasePaymaster(entryPoint) {}

    /// @notice Owner-adjustable per-op sponsorship cap.
    function setMaxSponsorCost(uint256 newCap) external onlyOwner {
        maxSponsorCost = newCap;
    }

    function _validatePaymasterUserOp(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash,
        uint256 maxCost
    ) internal view override returns (bytes memory context, uint256 validationData) {
        if (maxCost > maxSponsorCost) revert SponsorCostExceeded(maxCost, maxSponsorCost);

        context = abi.encode(userOp.sender, userOpHash);
        validationData = 0; // accept; time-range unused in skeleton
    }

    function _postOp(PostOpMode, bytes calldata, uint256, uint256) internal pure override {
        // skeleton: no refund/refill logic yet (KNOWN_ISSUES)
    }

    error SponsorCostExceeded(uint256 maxCost, uint256 cap);
}
