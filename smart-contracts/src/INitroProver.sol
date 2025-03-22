// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title INitroProver
/// @notice Interface for AWS nitro attestation verification in Solidity
interface INitroProver {
    /// @notice Verifies the certificate chain in the attestation
    /// @param attestation The CBOR encoded attestation document
    function verifyCerts(bytes memory attestation) external;

    /// @notice Verifies attestation with PCR validation
    /// @param attestation The CBOR encoded attestation document
    /// @param PCRs Expected PCR values to validate against
    /// @param max_age Maximum age of the attestation in seconds
    /// @return enclaveKey The enclave's public key
    /// @return userData User data from the attestation
    function verifyAttestation(
        bytes memory attestation,
        bytes memory PCRs,
        uint256 max_age
    ) external view returns (bytes memory enclaveKey, bytes memory userData);

    /// @notice Verifies attestation without PCR validation
    /// @param attestation The CBOR encoded attestation document
    /// @param max_age Maximum age of the attestation in seconds
    /// @return enclaveKey The enclave's public key
    /// @return userData User data from the attestation
    /// @return rawPcrs Raw PCR values from the attestation
    function verifyAttestation(
        bytes memory attestation,
        uint256 max_age
    ) external view returns (bytes memory enclaveKey, bytes memory userData, bytes memory rawPcrs);

    /// @notice Validates PCR values against expected values
    /// @param pcrs Array of PCR values from the attestation
    /// @param expected_pcrs Expected PCR values to validate against
    function validatePCRs(bytes[2][] memory pcrs, bytes memory expected_pcrs) external pure;

}
