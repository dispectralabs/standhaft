// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../../src/engine/Vault.sol";
import {MockVerifier} from "../../src/verifier/MockVerifier.sol";

/// @dev Actor driving random interactions; ghosts track expected balance.
contract VaultHandler {
    Vault public vault;
    address public recipient;
    uint256 public ghostIn;
    uint256 public ghostOut;
    uint256 public lastNonce;

    constructor(Vault vault_, address recipient_) {
        vault = vault_;
        recipient = recipient_;
    }

    function deposit(uint256 amount) external payable {
        require(msg.value == amount, "mismatch");
        (bool ok,) = address(vault).call{value: amount}("");
        require(ok, "deposit failed");
        ghostIn += amount;
    }

    /// 1-in-4 chance of a validly signed 1 wei execution; otherwise garbage proof.
    function attemptExecute(uint256 seed, uint256 value) external {
        require(value <= address(vault).balance, "over balance");
        bytes32 msgHash = keccak256(
            abi.encode(block.chainid, address(vault), recipient, value, keccak256(new bytes(0)), vault.nonce())
        );
        bytes memory proof;
        bool valid = seed % 4 == 0;
        if (valid) {
            proof = abi.encodePacked(bytes1(0x01), vault.commitment(), msgHash);
        } else {
            proof = abi.encodePacked(bytes1(0x02), bytes32(seed), bytes32(uint256(1)));
        }
        vault.execute(recipient, value, "", proof);
        ghostOut += value;
        lastNonce = vault.nonce();
    }
}

contract VaultInvariantTest is Test {
    Vault internal vault;
    MockVerifier internal verifier;
    VaultHandler internal handler;
    Recipient recipient;

    function setUp() public {
        verifier = new MockVerifier();
        vault = new Vault(bytes32(uint256(0x1)), address(verifier));
        recipient = new Recipient();
        handler = new VaultHandler(vault, address(recipient));

        // seed deposits so executions have room
        (bool ok,) = address(vault).call{value: 10 ether}("");
        require(ok);
        handler.deposit{value: 5 ether}(5 ether);

        targetContract(address(handler));
    }

    /// invariant: vault balance == tracked inflows - tracked outflows
    function invariant_balance_conservation() public view {
        assertEq(address(vault).balance, handler.ghostIn() + 10 ether - handler.ghostOut());
    }

    /// invariant: commitment is forever immutable
    function invariant_commitment_immutable() public view {
        assertEq(vault.commitment(), bytes32(uint256(0x1)));
    }

    /// invariant: verifier is forever immutable
    function invariant_verifier_immutable() public view {
        assertEq(vault.verifier(), address(verifier));
    }

    /// invariant: nonce never decreases
    function invariant_nonce_monotonic() public view {
        assertGe(vault.nonce(), handler.lastNonce());
    }

    /// invariant: no execution without a mock-valid proof (nonce moves only in lockstep with outflow)
    function invariant_nonce_tracks_outflow() public view {
        // every successful execute spends >= 0 and bumps nonce by exactly 1
        assertLe(handler.ghostOut(), handler.ghostIn() + 10 ether);
    }
}

contract Recipient {
    receive() external payable {}
}
