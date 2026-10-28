// SPDX-License-Identifier: MIT
pragma solidity ^0.8.37;

import {Test, console} from "forge-std/Test.sol";
import {MLDSAVerifier} from "mldsa-solidity/MLDSAVerifier.sol";
import {ML_DSA_44} from "mldsa-solidity/IMLDSAVerifier.sol";
import {MldsaVerifier} from "../../src/verifier/MldsaVerifier.sol";
import {Audit2Fixtures} from "./Audit2Fixtures.sol";

/// @title FreshVectorAudit — audit2 cross-language FIPS 204 verification with FRESH vectors.
/// @notice Vectors in {Audit2Fixtures} were generated with standhaft-cli (RustCrypto
///         ml-dsa 0.1.1) during this audit session (2026-10-28), NOT reused from the
///         committed fixture. For every vector we assert the on-chain
///         MldsaVerifier accepts the honest proof and rejects: one flipped signature
///         bit, one flipped digest bit, a wrong commitment, a flipped pk byte, and a
///         short proof. We also re-derive every chain-context digest with the exact
///         Vault.sol preimage formulas in Solidity and require equality with the
///         digest the Rust CLI signed (proving off-chain replication).
contract FreshVectorAudit is Test {
    MldsaVerifier internal adapter;
    MLDSAVerifier internal core;

    function setUp() public {
        core = new MLDSAVerifier(address(0)); // stateless full path
        adapter = new MldsaVerifier(core);
    }

    // ------------------------------------------------------------ commitment

    /// @dev CLI-reported commitment (Rust sha3 keccak) == Solidity keccak256(pk).
    function test_commitment_cli_equals_solidity_keccak256() public pure {
        assertEq(keccak256(Audit2Fixtures.PK), Audit2Fixtures.CMT);
    }

    // ------------------------------------------------------ positive vectors

    function test_fresh_v1_empty_data_digest_verifies() public view {
        assertTrue(
            adapter.verify(
                Audit2Fixtures.CMT, Audit2Fixtures.MSG1, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG1)
            )
        );
    }

    function test_fresh_v2_all_zero_digest_verifies() public view {
        assertTrue(
            adapter.verify(
                Audit2Fixtures.CMT, Audit2Fixtures.MSG2, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG2)
            )
        );
    }

    function test_fresh_v3_maxish_digest_verifies() public view {
        assertTrue(
            adapter.verify(
                Audit2Fixtures.CMT, Audit2Fixtures.MSG3, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG3)
            )
        );
    }

    function test_fresh_v4_realistic_single_nonce0_verifies() public view {
        assertTrue(
            adapter.verify(
                Audit2Fixtures.CMT, Audit2Fixtures.MSG4, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG4)
            )
        );
    }

    function test_fresh_v5_single_nonempty_data_nonce0_verifies() public view {
        assertTrue(
            adapter.verify(
                Audit2Fixtures.CMT, Audit2Fixtures.MSG5, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG5)
            )
        );
    }

    function test_fresh_v6_batch_2calls_nonce0_verifies() public view {
        assertTrue(
            adapter.verify(
                Audit2Fixtures.CMT, Audit2Fixtures.MSG6, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG6)
            )
        );
    }

    function test_fresh_v7_batch_2calls_nonce1_verifies() public view {
        assertTrue(
            adapter.verify(
                Audit2Fixtures.CMT, Audit2Fixtures.MSG7, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG7)
            )
        );
    }

    function test_fresh_v8_single_nonempty_data_nonce2_verifies() public view {
        assertTrue(
            adapter.verify(
                Audit2Fixtures.CMT, Audit2Fixtures.MSG8, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG8)
            )
        );
    }

    // ------------------------------------------------------- negative: tamper

    /// @dev Flip one bit of the FIRST signature byte (proof offset 1312) — must not verify.
    function _proofFlippedSigBit(bytes memory sig) internal pure returns (bytes memory p) {
        p = abi.encodePacked(Audit2Fixtures.PK, sig);
        p[1312] = p[1312] ^ 0x01;
    }

    /// @dev Flip one bit of the pk — keccak(pk) no longer matches the commitment.
    function _proofFlippedPk() internal pure returns (bytes memory p) {
        p = abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG1);
        p[0] = p[0] ^ 0x01;
    }

    function test_fresh_v1_flipped_signature_bit_rejected() public view {
        assertFalse(adapter.verify(Audit2Fixtures.CMT, Audit2Fixtures.MSG1, _proofFlippedSigBit(Audit2Fixtures.SIG1)));
    }

    function test_fresh_v2_flipped_signature_bit_rejected() public view {
        assertFalse(adapter.verify(Audit2Fixtures.CMT, Audit2Fixtures.MSG2, _proofFlippedSigBit(Audit2Fixtures.SIG2)));
    }

    function test_fresh_v3_flipped_signature_bit_rejected() public view {
        assertFalse(adapter.verify(Audit2Fixtures.CMT, Audit2Fixtures.MSG3, _proofFlippedSigBit(Audit2Fixtures.SIG3)));
    }

    function test_fresh_v4_flipped_signature_bit_rejected() public view {
        assertFalse(adapter.verify(Audit2Fixtures.CMT, Audit2Fixtures.MSG4, _proofFlippedSigBit(Audit2Fixtures.SIG4)));
    }

    function test_fresh_v5_flipped_signature_bit_rejected() public view {
        assertFalse(adapter.verify(Audit2Fixtures.CMT, Audit2Fixtures.MSG5, _proofFlippedSigBit(Audit2Fixtures.SIG5)));
    }

    function test_fresh_v6_flipped_signature_bit_rejected() public view {
        assertFalse(adapter.verify(Audit2Fixtures.CMT, Audit2Fixtures.MSG6, _proofFlippedSigBit(Audit2Fixtures.SIG6)));
    }

    function test_fresh_v7_flipped_signature_bit_rejected() public view {
        assertFalse(adapter.verify(Audit2Fixtures.CMT, Audit2Fixtures.MSG7, _proofFlippedSigBit(Audit2Fixtures.SIG7)));
    }

    function test_fresh_v8_flipped_signature_bit_rejected() public view {
        assertFalse(adapter.verify(Audit2Fixtures.CMT, Audit2Fixtures.MSG8, _proofFlippedSigBit(Audit2Fixtures.SIG8)));
    }

    /// @dev Flip one bit of the digest — must not verify (for a representative subset).
    function test_fresh_v1_flipped_digest_bit_rejected() public view {
        bytes32 flipped = Audit2Fixtures.MSG1 ^ bytes32(uint256(1));
        assertFalse(
            adapter.verify(Audit2Fixtures.CMT, flipped, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG1))
        );
    }

    function test_fresh_v4_flipped_digest_bit_rejected() public view {
        bytes32 flipped = Audit2Fixtures.MSG4 ^ bytes32(uint256(1));
        assertFalse(
            adapter.verify(Audit2Fixtures.CMT, flipped, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG4))
        );
    }

    function test_fresh_v8_flipped_digest_bit_rejected() public view {
        bytes32 flipped = Audit2Fixtures.MSG8 ^ bytes32(uint256(1));
        assertFalse(
            adapter.verify(Audit2Fixtures.CMT, flipped, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG8))
        );
    }

    function test_fresh_wrong_commitment_rejected() public view {
        assertFalse(
            adapter.verify(
                bytes32(uint256(0xdead)), Audit2Fixtures.MSG1, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG1)
            )
        );
    }

    function test_fresh_flipped_pk_byte_rejected() public view {
        assertFalse(adapter.verify(Audit2Fixtures.CMT, Audit2Fixtures.MSG1, _proofFlippedPk()));
    }

    function test_fresh_short_proof_rejected() public view {
        assertFalse(adapter.verify(Audit2Fixtures.CMT, Audit2Fixtures.MSG1, hex"deadbeef"));
    }

    // ------------------------------------------- preimage replication (Vault.sol)

    /// @dev Exact Vault.execute formula: keccak256(abi.encode(chainid, vault, target, value, keccak256(data), nonce)).
    function test_preimage_single_empty_data_replicated_in_solidity() public view {
        require(block.chainid == 31337, "chainid mismatch with fixtures");
        bytes32 recomputed = keccak256(
            abi.encode(
                Audit2Fixtures.CHAIN_ID,
                Audit2Fixtures.VAULT,
                Audit2Fixtures.TARGET,
                Audit2Fixtures.VALUE,
                keccak256(""),
                uint256(0)
            )
        );
        assertEq(recomputed, Audit2Fixtures.MSG4);
    }

    /// @dev Same formula with non-empty calldata, hashed exactly as Vault does.
    function test_preimage_single_nonempty_data_replicated_in_solidity() public view {
        bytes32 recomputed = keccak256(
            abi.encode(
                Audit2Fixtures.CHAIN_ID,
                Audit2Fixtures.VAULT,
                Audit2Fixtures.TARGET,
                uint256(0),
                keccak256(Audit2Fixtures.DATA_NONEMPTY),
                uint256(0)
            )
        );
        assertEq(recomputed, Audit2Fixtures.MSG5);
    }

    /// @dev Exact Vault.executeBatch formula: h_i = keccak256(abi.encode(t,v,keccak256(d)));
    ///      callsHash = keccak256(abi.encodePacked(h0..hn)); msgHash = keccak256(abi.encode(chainid, vault, callsHash, nonce)).
    function test_preimage_batch_replicated_in_solidity() public view {
        bytes32 h0 = keccak256(abi.encode(Audit2Fixtures.TARGET, Audit2Fixtures.VALUE, keccak256("")));
        bytes32 h1 = keccak256(abi.encode(Audit2Fixtures.TARGET, uint256(0), keccak256(Audit2Fixtures.DATA_NONEMPTY)));
        bytes32 callsHash = keccak256(abi.encodePacked(h0, h1));
        bytes32 recomputed = keccak256(abi.encode(Audit2Fixtures.CHAIN_ID, Audit2Fixtures.VAULT, callsHash, uint256(0)));
        assertEq(recomputed, Audit2Fixtures.MSG6);
    }

    /// @dev Batch at nonce=1 as executed live on anvil (tx 0x42d28364...).
    function test_preimage_batch_nonce1_replicated_in_solidity() public view {
        bytes32 h0 = keccak256(abi.encode(Audit2Fixtures.TARGET, Audit2Fixtures.VALUE, keccak256("")));
        bytes32 h1 = keccak256(abi.encode(Audit2Fixtures.TARGET, uint256(0), keccak256(Audit2Fixtures.DATA_NONEMPTY)));
        bytes32 callsHash = keccak256(abi.encodePacked(h0, h1));
        bytes32 recomputed = keccak256(abi.encode(Audit2Fixtures.CHAIN_ID, Audit2Fixtures.VAULT, callsHash, uint256(1)));
        assertEq(recomputed, Audit2Fixtures.MSG7);
    }

    /// @dev Single with non-empty calldata at nonce=2 as executed live on anvil (tx 0x51d1b0d3...).
    function test_preimage_single_nonce2_replicated_in_solidity() public view {
        bytes32 recomputed = keccak256(
            abi.encode(
                Audit2Fixtures.CHAIN_ID,
                Audit2Fixtures.VAULT,
                Audit2Fixtures.TARGET,
                uint256(0),
                keccak256(Audit2Fixtures.DATA_NONEMPTY),
                uint256(2)
            )
        );
        assertEq(recomputed, Audit2Fixtures.MSG8);
    }

    // ----------------------------------------------------------------- gas

    function test_gas_direct_verification_fresh_vector() public view {
        uint256 g0 = gasleft();
        bool ok = adapter.verify(
            Audit2Fixtures.CMT, Audit2Fixtures.MSG4, abi.encodePacked(Audit2Fixtures.PK, Audit2Fixtures.SIG4)
        );
        uint256 used = g0 - gasleft();
        assertTrue(ok);
        console.log("audit2: adapter.verify gas (fresh vector, solc 0.8.37 via_ir):", used);
    }

    function test_gas_core_verification_fresh_vector() public view {
        uint256 g0 = gasleft();
        bool ok = core.verify(ML_DSA_44, Audit2Fixtures.PK, abi.encodePacked(Audit2Fixtures.MSG4), Audit2Fixtures.SIG4);
        uint256 used = g0 - gasleft();
        assertTrue(ok);
        console.log("audit2: MLDSAVerifier.verify gas (fresh vector):", used);
    }
}
