// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "./INitroProver.sol";

contract PassTeePort {
    INitroProver public nitroProver;
    mapping(address => bool) public signers;

    mapping(bytes32 => address) public passportID_to_wallet;
    // using bytes to avoid hardcoding data layout
    mapping(address => bytes) public wallet_to_passport;

    constructor(INitroProver _nitroProver) {
        nitroProver = _nitroProver;
    }

    event PassportDataVerified(address owner, address signer);

    function add_signer(bytes memory quoteBody, bytes memory pcrs) external {
        (bytes memory enclaveKey, bytes memory userData) = nitroProver.verifyAttestation(quoteBody, pcrs, 60 * 60 * 24 * 3);
        signers[address(uint160(bytes20(enclaveKey)))] = true;
    }

    function debug_add_signer(address _signer) external {
        signers[_signer] = true;
    }

    struct PassportTEEData {
        bytes32 id;
        address owner;
        bytes data;
    }
    
    function submit_passport_data(
        PassportTEEData calldata _data,
        bytes calldata _signature
    ) external {
        bytes32 data_hash = _hashPassportTEEData(_data);
        address _signer = ECDSA.recover(data_hash, _signature);

        // need to manage to verify the enclave as signer
        require(signers[_signer], "unrecognized signer");
        emit PassportDataVerified(_data.owner, _signer);
        address previous_wallet = passportID_to_wallet[_data.id];
        if (previous_wallet != address(0)) {
            delete wallet_to_passport[previous_wallet];
        }
        passportID_to_wallet[_data.id] = _data.owner;
        wallet_to_passport[_data.owner] = _data.data;
    }

    // TODO make internal
    function _hashPassportTEEData(
        PassportTEEData calldata _data
    ) public pure returns (bytes32) {
        return keccak256(
                    abi.encodePacked(
                        _data.id,
                        _data.owner,
                        _data.data
                    )
                );
    }
}