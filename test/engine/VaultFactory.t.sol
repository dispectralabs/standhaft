// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test} from "forge-std/Test.sol";
import {Vault} from "../../src/engine/Vault.sol";
import {VaultFactory} from "../../src/engine/VaultFactory.sol";
import {MockVerifier} from "../../src/verifier/MockVerifier.sol";

contract VaultFactoryTest is Test {
    VaultFactory internal factory;
    MockVerifier internal verifier;

    bytes32 internal constant CMT = bytes32(uint256(0xBEEF));
    bytes32 internal constant SALT = bytes32(uint256(0xCAFE));

    function setUp() public {
        verifier = new MockVerifier();
        factory = new VaultFactory();
    }

    function test_compute_address_deterministic() public view {
        address a = factory.computeAddress(CMT, address(verifier), SALT);
        address b = factory.computeAddress(CMT, address(verifier), SALT);
        assertEq(a, b);
        assertTrue(a != address(0));
    }

    function test_different_salt_different_address() public view {
        address a = factory.computeAddress(CMT, address(verifier), SALT);
        address b = factory.computeAddress(CMT, address(verifier), bytes32(uint256(1)));
        assertTrue(a != b);
    }

    function test_create_deploys_at_computed_address() public {
        address expected = factory.computeAddress(CMT, address(verifier), SALT);
        address deployed = factory.createVault(CMT, address(verifier), SALT);
        assertEq(deployed, expected);
        assertTrue(deployed.code.length > 0);

        Vault vault = Vault(payable(deployed));
        assertEq(vault.commitment(), CMT);
        assertEq(vault.verifier(), address(verifier));
    }

    function test_double_deploy_reverts() public {
        factory.createVault(CMT, address(verifier), SALT);
        vm.expectRevert(abi.encodeWithSelector(VaultFactory.AlreadyDeployed.selector, factory.computeAddress(CMT, address(verifier), SALT)));
        factory.createVault(CMT, address(verifier), SALT);
    }

    function test_counterfactual_funds_survive_creation() public {
        address cf = factory.computeAddress(CMT, address(verifier), SALT);

        // Ahmet's friends send funds to the counterfactual address BEFORE deploy
        (bool ok,) = cf.call{value: 5 ether}("");
        assertTrue(ok);
        assertEq(cf.balance, 5 ether);

        factory.createVault(CMT, address(verifier), SALT);
        assertEq(cf.balance, 5 ether); // funds preserved — now spendable via proofs
    }

    function test_create_is_permissionless() public {
        vm.prank(makeAddr("someone"));
        address deployed = factory.createVault(CMT, address(verifier), SALT);
        assertTrue(deployed.code.length > 0);
    }
}
