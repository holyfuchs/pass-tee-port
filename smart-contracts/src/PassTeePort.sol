// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

using ECDSA for bytes32;

contract PassTeePort {
    
    mapping(address => bool) public signers;
    struct PassportData {
        bool over18;
        string name;
    }
    mapping(uint256 => PassportData) public passportData;

    constructor() {}

    event PassportDataVerified(PassportData);

    function add_signer(bytes memory quoteBody) external {
        // verify the quoteBody
        // add the enclave as valid signer
    }

    struct PassportDataID {
        uint256 id;
        bool over18;
        string name;
    }
    
    function verify(
        PassportDataID calldata _data,
        bytes calldata _signature
    ) external view {
        bytes32 data_hash = _hashPassportDataID(_data);
        address _signer = ECDSA.recover(data_hash, _signature);

        // need to manage to verify the enclave as signer
        // require(signers[_signer], "unrecognized signer");
        emit PassportDataVerified(_data);
        passportData[_data.id] = PassportData({
            over18: _data.over18,
            name: _data.name
        });
    }

    function _hashPassportDataID(
        PassportDataID calldata _data
    ) internal pure returns (bytes32) {
        return keccak256(
                    abi.encode(
                        _data.id,
                        _data.over18,
                        _data.name
                    )
                );
    }
}