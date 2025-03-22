// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console} from "forge-std/Script.sol";
import {CertManager} from "../src/CertManager.sol";
import {NitroProver} from "../src/NitroProver.sol";

contract DeployToSepolia is Script {
    function run() external {
        uint256 key = vm.envUint("PRIVATE_KEY");
        vm.startBroadcast(key);

        CertManager certManager = new CertManager();
        NitroProver nitroProver = new NitroProver(certManager);

        console.log("CertManager deployed at:", address(certManager));
        console.log("NitroProver deployed at:", address(nitroProver));

        vm.stopBroadcast();
    }
}
