// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Script, console} from "forge-std/Script.sol";
import {MLDSAVerifier} from "mldsa-solidity/MLDSAVerifier.sol";
import {MldsaVerifier} from "../src/verifier/MldsaVerifier.sol";
import {VaultFactory} from "../src/engine/VaultFactory.sol";

/// @notice Deploys the standhaft engine stack:
///         1. MLDSAVerifier  — FIPS 204 core (stateless full-path verification)
///         2. MldsaVerifier  — commitment-binding adapter (our engine interface)
///         3. VaultFactory   — counterfactual vault deployment
/// Usage:  forge script script/Deploy.s.sol --broadcast --rpc-url <url>
contract Deploy is Script {
    function run() external {
        vm.startBroadcast();

        // stateless: no precompute factory (address(0) = full verification path)
        MLDSAVerifier mldsaCore = new MLDSAVerifier(address(0));
        MldsaVerifier adapter = new MldsaVerifier(mldsaCore);
        VaultFactory factory = new VaultFactory();

        vm.stopBroadcast();

        console.log("MLDSAVerifier (FIPS 204 core):", address(mldsaCore));
        console.log("MldsaVerifier  (adapter):     ", address(adapter));
        console.log("VaultFactory:                 ", address(factory));
        console.log("Next: keygen via standhaft-cli -> computeAddress -> funds -> execute");
    }
}
