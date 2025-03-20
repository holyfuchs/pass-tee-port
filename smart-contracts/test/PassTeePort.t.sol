// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {PassTeePort} from "../src/PassTeePort.sol";

contract PassTeePortTest is Test {
    PassTeePort public passTeePort;

    function setUp() public {
        passTeePort = new PassTeePort();
    }

    function test_Increment() public {
        passTeePort.add_signer(bytes(""));
    }

    function testFuzz_SetNumber(uint256 x) public {
        passTeePort.add_signer(bytes(""));
    }
}
