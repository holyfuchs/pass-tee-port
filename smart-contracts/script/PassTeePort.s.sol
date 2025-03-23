pragma solidity ^0.8.22;

import "../src/PassTeePort.sol";

import "forge-std/Script.sol";
import {INitroProver} from "../src/INitroProver.sol";

contract Deploy is Script {

    function setUp() public {}

    function run() public {
        vm.createSelectFork(vm.rpcUrl("arbitrumSepolia"));
        vm.startBroadcast();
        PassTeePort pt = new PassTeePort(INitroProver(0x4D16A370eeE9383217da724C180A76c6a4542b5C));
        vm.stopBroadcast();
        console.log(string.concat("deployed on: ", vm.toString(address(pt))));
    }
}

contract AddSigner is Script {
    function run() public {
        bytes memory attestation = vm.readFileBinary(
            "./test/nitro-attestation/attestation_hack.bin"
        );
        bytes memory pcrs = abi.encodePacked(
        // @dev if PCR4 is included (pcr4 = hashed user data field) set bitmask to hex"00000017"
            hex"00000007", // bitmask for PCR0, PCR1, PCR2, PCR4 
            hex"181023664fd6477acdb28bb3d7b7e5eff6001a7a8c2d32309e076460fa6cda213cee6c4c0b97c96421bf6b1b74305030" // PCR0
            hex"70ea27296f1809c73bb61f5f08892536e1969c154f08bdccd4ff907df79881a4b14a0fc6f2ab6dd00d5b2e5a73fe88a7", // PCR1
            hex"c631afd653305f3a40f21579897d9308daa3145eff263b1f2875ac86d2ad800e3a7ebaf7fcd39e5485896cd94607e74e" // PCR2
            // hex"12bdd83092ec44f4bd47d8246b6905590cd6685f08725c313fe13f81915ea20ca6bca924db9ec84b024f7004f20ca620" // PCR4
        );
        vm.createSelectFork(vm.rpcUrl("arbitrumSepolia"));
        PassTeePort pt = PassTeePort(0x191bCA32826A10558BE5db63Cc658b8653F0f783);
        vm.startBroadcast();
        // pt.debug_add_signer(0x867A632ED88CC407FdC2813D74Fb326ac1333287);
        pt.add_signer(attestation, pcrs);
        vm.stopBroadcast();
        console.log("added signer");
    }
}

contract AddPassport is Script {
    function run() public {
        bytes32 id = bytes32(0xef35e2ddc454b196b1ad9557298f30571388a1a368e2dad69494e4bf5aed92ba);
        address owner = address(0x00241ff4135743dffc170d4ca6c9339e5e06c9c7f7);
        bytes memory data = hex"502a2a2a20472a2a2a2a2a";
        PassTeePort.PassportTEEData memory pass = PassTeePort.PassportTEEData(
            {id: id, owner: owner, data: data}
        );
        bytes memory attestation = hex"2fee277ccbcd156b26d907db047af2ca7d99c04e6f1683be4fd93dea425e01783d4c0bb60ddaba0985ea460f99df2c5c88715e550d1be7348c9fd36a2ae6bddb1b";

        vm.createSelectFork(vm.rpcUrl("arbitrumSepolia"));
        PassTeePort pt = PassTeePort(0x191bCA32826A10558BE5db63Cc658b8653F0f783);
        pt.submit_passport_data(pass, attestation);
        vm.startBroadcast();
        // pt.debug_add_signer(0x867A632ED88CC407FdC2813D74Fb326ac1333287);
        pt.add_signer(attestation, pcrs);
        vm.stopBroadcast();
        console.log("added signer");
    }
}