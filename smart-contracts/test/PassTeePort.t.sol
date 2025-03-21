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
           {id: bytes32(uint256(0x1337)), data: "A****"}
       );
       passTeePort.debug_add_signer(alice);
       bytes32 pass_hash = passTeePort._hashPassportDataID(pass);
       console.logBytes32(pass_hash);
       (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, pass_hash);
       bytes memory signature = abi.encodePacked(r, s, v);
       passTeePort.submit_passport_data(pass, signature);

       bytes memory data = passTeePort.wallet_to_passport(alice);
       assertEq(data, "A****");
    }

    function test_externalSigned() public {
        (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        vm.startPrank(alice);
        PassTeePort.PassportDataID memory pass = PassTeePort.PassportDataID(
            {id: bytes32(0xfc3a7c7a645377e83150dc6ccdc825bcf5bf605b53f6cd4bab37bbaf5a188d0e), data: "G******* G******"}
        );
        passTeePort.debug_add_signer(address(0x00fcad0b19bb29d4674531d6f115237e16afce377c));
        bytes32 pass_hash = passTeePort._hashPassportDataID(pass);
        // got this from rust code
        assertEq(pass_hash, 0x6704f8e3f2ec11981506bbabf7d6b48c9ca397dfeb7eba506a0ce0dd235318a9);
        passTeePort.submit_passport_data(pass, hex"6ed66b0a03c4f559c57261155f6bce4892916acee62b9fbe95903152d93add306e45f71455cbb8ba31be7982e35f63bd44f938b0fe4b66cfb0ca6538069abf5f1c");

        bytes memory data = passTeePort.wallet_to_passport(alice);
        assertEq(data, "G******* G******");
    }
}


// from rust
// encoded_data: 0xfc3a7c7a645377e83150dc6ccdc825bcf5bf605b53f6cd4bab37bbaf5a188d0e472a2a2a2a2a2a2a20472a2a2a2a2a2a
// data id: PassportDataID { id: 0xfc3a7c7a645377e83150dc6ccdc825bcf5bf605b53f6cd4bab37bbaf5a188d0e, data: 0x472a2a2a2a2a2a2a20472a2a2a2a2a2a }
// Address: 0xfcad0b19bb29d4674531d6f115237e16afce377c
// Signature: 0x6ed66b0a03c4f559c57261155f6bce4892916acee62b9fbe95903152d93add306e45f71455cbb8ba31be7982e35f63bd44f938b0fe4b66cfb0ca6538069abf5f1c
// Hash: 0x6704f8e3f2ec11981506bbabf7d6b48c9ca397dfeb7eba506a0ce0dd235318a9