// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract PassTeePort {
    
    mapping(address => bool) public signers;

    mapping(bytes32 => address) public passportID_to_wallet;
    // using bytes to avoid hardcoding data layout
    mapping(address => bytes) public wallet_to_passport;

    constructor() {}

    event PassportDataVerified(address owner, address signer);

    function add_signer(bytes memory quoteBody) external {
        // verify the quoteBody
        // add the enclave as valid signer
    }

    function debug_add_signer(address _signer) external {
        signers[_signer] = true;
    }

    struct PassportDataID {
        bytes32 id;
        bytes data;
    }
    
    function submit_passport_data(
        PassportDataID calldata _data,
        bytes calldata _signature
    ) external {
        bytes32 data_hash = _hashPassportDataID(_data);
        address _signer = ECDSA.recover(data_hash, _signature);

        // need to manage to verify the enclave as signer
        require(signers[_signer], "unrecognized signer");
        emit PassportDataVerified(msg.sender, _signer);
        address previous_wallet = passportID_to_wallet[_data.id];
        if (previous_wallet != address(0)) {
            delete wallet_to_passport[previous_wallet];
        }
        passportID_to_wallet[_data.id] = msg.sender;
        wallet_to_passport[msg.sender] = _data.data;
    }

    // function get_passport_data(
    //     address _wallet
    // ) external view returns (PassportData memory) {
    //     return wallet_to_passport[_wallet];
    // }

    // TODO make internal
    function _hashPassportDataID(
        PassportDataID calldata _data
    ) public pure returns (bytes32) {
        return keccak256(
                    abi.encodePacked(
                        _data.id,
                        _data.data
                    )
                );
    }
}