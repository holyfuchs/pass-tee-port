// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {PassTeePort} from "../src/PassTeePort.sol";

contract PassTeePortTest is Test {
    PassTeePort public passTeePort;

    function setUp() public {
        passTeePort = new PassTeePort();
    }

    // function test_ValidatePassportData() public {
    //     PassTeePort.PassportDataID memory pass = PassTeePort.PassportDataID(
    //         {id: 1337, over18: true, name: "John Doe"}
    //     );
    //     passTeePort.submit_passport_data(pass, bytes(""));
    // }

    function test_signPassportData() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        vm.startPrank(alice);
        PassTeePort.PassportDataID memory pass = PassTeePort.PassportDataID(
            {id: 1337, over18: true, name: "A****"}
        );
        bytes32 pass_hash = passTeePort._hashPassportDataID(pass);
        console.logBytes32(pass_hash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, pass_hash);
        bytes memory signature = abi.encodePacked(r, s, v);
        passTeePort.submit_passport_data(pass, signature);

        (string memory name, bool over18) = passTeePort.wallet_to_passport(alice);
        assertEq(name, "A****");
        assertEq(over18, true);
    }
}
