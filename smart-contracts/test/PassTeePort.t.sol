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
       PassTeePort.PassportTEEData memory pass = PassTeePort.PassportTEEData(
           {id: bytes32(uint256(0x1337)), owner: alice, data: "A****"}
       );
       passTeePort.debug_add_signer(alice);
       bytes32 pass_hash = passTeePort._hashPassportTEEData(pass);
       console.logBytes32(pass_hash);
       (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, pass_hash);
       bytes memory signature = abi.encodePacked(r, s, v);
       passTeePort.submit_passport_data(pass, signature);

       bytes memory data = passTeePort.wallet_to_passport(alice);
       assertEq(data, "A****");
    }

    function test_externalSigned() public {
        // (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        // vm.startPrank(alice);
        address owner = address(0xa0c28cF11F536B8bE2224Db0a26F97952D1e6cc3);
        PassTeePort.PassportTEEData memory pass = PassTeePort.PassportTEEData(
            {id: bytes32(0xfc3a7c7a645377e83150dc6ccdc825bcf5bf605b53f6cd4bab37bbaf5a188d0e), owner: owner, data: "G******* G******"}
        );
        passTeePort.debug_add_signer(address(0xFCAd0B19bB29D4674531d6f115237E16AfCE377c));
        bytes32 pass_hash = passTeePort._hashPassportTEEData(pass);
        // got this from rust code
        assertEq(pass_hash, 0x25702609b53d0ee8ddc3e9e7f52acddf1da26755b8c6fdc5044ce8c40db534ad);
        passTeePort.submit_passport_data(pass, hex"2545af546a567dfd339841c5a9fb2b24eed64503766245cc19b9dca651073a506e3d3e9ceb42df6d2c6d36f8f1fd33be916ec038cb61c163e14fef17c8dbd4dd1b");

        bytes memory data = passTeePort.wallet_to_passport(owner);
        assertEq(data, "G******* G******");
    }

    // // from rust
    // encoded_data: 0xfc3a7c7a645377e83150dc6ccdc825bcf5bf605b53f6cd4bab37bbaf5a188d0ea0c28cf11f536b8be2224db0a26f97952d1e6cc3472a2a2a2a2a2a2a20472a2a2a2a2a2a
    // data: PassportTEEData { id: 0xfc3a7c7a645377e83150dc6ccdc825bcf5bf605b53f6cd4bab37bbaf5a188d0e, owner: 0xa0c28cf11f536b8be2224db0a26f97952d1e6cc3, data: 0x472a2a2a2a2a2a2a20472a2a2a2a2a2a }
    // Address: 0xfcad0b19bb29d4674531d6f115237e16afce377c
    // Signature: 0x2545af546a567dfd339841c5a9fb2b24eed64503766245cc19b9dca651073a506e3d3e9ceb42df6d2c6d36f8f1fd33be916ec038cb61c163e14fef17c8dbd4dd1b
    // Hash: 0x25702609b53d0ee8ddc3e9e7f52acddf1da26755b8c6fdc5044ce8c40db534ad

    function test_TEESigned() public {
        // (address alice, uint256 alicePk) = makeAddrAndKey("alice");
        // vm.startPrank(alice);
        address owner = address(0x00241ff4135743dffc170d4ca6c9339e5e06c9c7f7);
        PassTeePort.PassportTEEData memory pass = PassTeePort.PassportTEEData(
            {id: bytes32(0xef35e2ddc454b196b1ad9557298f30571388a1a368e2dad69494e4bf5aed92ba), owner: owner, data: hex"502a2a2a20472a2a2a2a2a"}
        );
        passTeePort.debug_add_signer(address(0x00f3706192c54dbdf86979db3c69323fb42b6f2b16));
        bytes32 pass_hash = passTeePort._hashPassportTEEData(pass);
        // got this from rust code
        // assertEq(pass_hash, 0x25702609b53d0ee8ddc3e9e7f52acddf1da26755b8c6fdc5044ce8c40db534ad);
        passTeePort.submit_passport_data(pass, hex"15f745150d878a717ac6024977c75f0da216c578d4b33df866d3ae95741fa8511ae5153a06da8fad89bbe23c2f95c1ae398acc7b1642627cd6a7e0320c4261661c");

        bytes memory data = passTeePort.wallet_to_passport(owner);
        assertEq(data, "P*** G*****");
    }

    // {"info":{"id":"0xef35e2ddc454b196b1ad9557298f30571388a1a368e2dad69494e4bf5aed92ba",
    // "owner":"0x241ff4135743dffc170d4ca6c9339e5e06c9c7f7",
    // "data":"0x502a2a2a20472a2a2a2a2a"},
    // "signature":"15f745150d878a717ac6024977c75f0da216c578d4b33df866d3ae95741fa8511ae5153a06da8fad89bbe23c2f95c1ae398acc7b1642627cd6a7e0320c4261661c"}
}


