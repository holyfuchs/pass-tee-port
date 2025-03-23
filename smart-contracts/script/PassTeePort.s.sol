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
