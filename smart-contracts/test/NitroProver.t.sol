// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/INitroProver.sol";

// forge test --fork-url https://sepolia-rollup.arbitrum.io/rpc --match-contract NitroProverTest -vvvv

contract NitroProverTest is Test {
    INitroProver nitroProver;
    bytes internal attestation_doc;

    // @dev set warp time to correct timestamp
    function setUp() public {
        vm.warp(1742684568); // timestamp: date -d '2025-03-22 20:50:00 UTC' +%s
        nitroProver = INitroProver(0x4D16A370eeE9383217da724C180A76c6a4542b5C);
        attestation_doc = vm.readFileBinary("./test/nitro-attestation/sample_attestation.bin");
    }

    function test_VerifyMyAttestation() public {
        // Load your binary attestation doc
        bytes memory attestation = vm.readFileBinary(
            "./test/nitro-attestation/attestation_hack.bin"
        );

        // PCR flags + expected values (e.g. PCR0, PCR1, PCR2, PCR4)
        bytes memory pcrs = abi.encodePacked(
        // @dev if PCR4 is included (pcr4 = hashed user data field) set bitmask to hex"00000017"
            hex"00000007", // bitmask for PCR0, PCR1, PCR2, PCR4 
            hex"181023664fd6477acdb28bb3d7b7e5eff6001a7a8c2d32309e076460fa6cda213cee6c4c0b97c96421bf6b1b74305030" // PCR0
            hex"70ea27296f1809c73bb61f5f08892536e1969c154f08bdccd4ff907df79881a4b14a0fc6f2ab6dd00d5b2e5a73fe88a7", // PCR1
            hex"c631afd653305f3a40f21579897d9308daa3145eff263b1f2875ac86d2ad800e3a7ebaf7fcd39e5485896cd94607e74e" // PCR2
            // hex"12bdd83092ec44f4bd47d8246b6905590cd6685f08725c313fe13f81915ea20ca6bca924db9ec84b024f7004f20ca620" // PCR4
        );

        (bytes memory enclaveKey, bytes memory userData) = nitroProver.verifyAttestation(attestation, pcrs, 100 days);
        console.logBytes(enclaveKey);
        console.logBytes(userData);
    }
}


