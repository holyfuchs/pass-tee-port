// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

contract PassTeePort {
    
    mapping(address => bool) public signers;
    struct PassportData {
        string name;
        bool over18;
    }
    mapping(uint256 => address) public passportID_to_wallet;
    mapping(address => PassportData) public wallet_to_passport;

    constructor() {}

    event PassportDataVerified(address owner, address signer);

    function add_signer(bytes memory quoteBody) external {
        // verify the quoteBody
        // add the enclave as valid signer
    }

    struct PassportDataID {
        uint256 id;
        bool over18;
        string name;
    }
    
    function submit_passport_data(
        PassportDataID calldata _data,
        bytes calldata _signature
    ) external {
        bytes32 data_hash = _hashPassportDataID(_data);
        address _signer = ECDSA.recover(data_hash, _signature);

        // need to manage to verify the enclave as signer
        // require(signers[_signer], "unrecognized signer");
        emit PassportDataVerified(msg.sender, _signer);
        address previous_wallet = passportID_to_wallet[_data.id];
        if (previous_wallet != address(0)) {
            delete wallet_to_passport[previous_wallet];
        }
        passportID_to_wallet[_data.id] = msg.sender;
        wallet_to_passport[msg.sender] = PassportData({
            over18: _data.over18,
            name: _data.name
        });
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
                    abi.encode(
                        _data.id,
                        _data.over18,
                        _data.name
                    )
                );
    }
}