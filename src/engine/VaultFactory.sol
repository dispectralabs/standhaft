// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Vault} from "./Vault.sol";

/// @title VaultFactory — counterfactual (CREATE2) vault deployment
/// @notice Users learn their vault address (and can receive funds there) BEFORE paying
///         deployment gas. Deployment is permissionless — anyone can trigger it (e.g.
///         the first relayed execution can create the vault). The address binds
///         (commitment, verifier, salt): an address always means "this PQ key owns
///         this vault".
contract VaultFactory {
    event VaultCreated(address indexed vault, bytes32 indexed commitment, address verifier, bytes32 salt);

    error AlreadyDeployed(address vault);
    error DeployFailed();

    /// @notice Deploys a vault at the counterfactual address. Deterministic per
    ///         (commitment, verifier, salt); reverts if already deployed.
    function createVault(bytes32 commitment, address verifier, bytes32 salt)
        external
        returns (address vault)
    {
        vault = computeAddress(commitment, verifier, salt);
        if (vault.code.length != 0) revert AlreadyDeployed(vault);

        bytes memory code = abi.encodePacked(type(Vault).creationCode, abi.encode(commitment, verifier));
        assembly ("memory-safe") {
            vault := create2(0, add(code, 0x20), mload(code), salt)
        }
        if (vault == address(0)) revert DeployFailed();

        emit VaultCreated(vault, commitment, verifier, salt);
    }

    /// @notice Counterfactual address for (commitment, verifier, salt).
    ///         CREATE2: keccak256(0xff ++ factory ++ salt ++ keccak256(init_code ++ args))
    function computeAddress(bytes32 commitment, address verifier, bytes32 salt)
        public
        view
        returns (address)
    {
        bytes32 codeHash =
            keccak256(abi.encodePacked(type(Vault).creationCode, abi.encode(commitment, verifier)));
        bytes32 h = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, codeHash));
        return address(uint160(uint256(h)));
    }
}
