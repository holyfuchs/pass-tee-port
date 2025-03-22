from .llcrypto import ECDHMappingAgreement, desMAC, getPublicKeyData, decodePublicKeyFromBytes, computeSharedSecret, encodePublicKey, createNonceBN
from cryptography.hazmat.primitives import serialization
from .keyGenerator import KeyGenerator, KeyMode
from .tagReader import TagReader, StatusCode
from Crypto.Cipher import DES3, AES, DES
from .helpers import unwrapDO, wrapDO
from Crypto.Util.Padding import pad
from .cardAccess import CardAccess
from Crypto.Hash import CMAC
from ctypes import c_void_p
from typing import List
import hashlib
import logging



class PaceHandler:
    MRZ_PACE_KEY_REFERENCE = 0x01

    def __init__(self, cardAccess: CardAccess, tagReader: TagReader):
        self.cardAccess = cardAccess
        self.tagReader = tagReader
        self.paceInfo = self.cardAccess.securityInfos[0]

    def _createPaceKey(self, mrzKey: str):
        mrzBytes = mrzKey.encode('utf-8')
        keySeed: bytes = hashlib.sha1(mrzBytes).digest()
        cipherAlgName = self.paceInfo.getCipherAlgorithm()
        keyLength = self.paceInfo.getKeyLength()

        return KeyGenerator.getKey(keySeed, cipherAlgName, keyLength, KeyMode.PACE_MODE)

    def _generateAuthenticationToken(self, publicKey: c_void_p, macKey: bytes) -> List[int]:
        encodedPublicKeyData = bytes(encodePublicKey(self.paceInfo.oid, publicKey))

        cipherAlg = self.paceInfo.getCipherAlgorithm()
        if cipherAlg == "3DES":
            encodedPublicKeyData = pad(encodedPublicKeyData, block_size=8, style="iso7816")

        if cipherAlg == "3DES":
            macced = desMAC(macKey, encodedPublicKeyData)
        else:
            c = CMAC.new(macKey, ciphermod=AES)
            c.update(encodedPublicKeyData)
            macced = c.digest()

        auth_token = macced[:8]

        return list(auth_token)

    def handlePace(self, mrzKey: str):
        logging.debug(f"Handling PACE with OID: {self.paceInfo.oid}")

        paceKey = self._createPaceKey(mrzKey)
        logging.debug(f"PaceKey: {paceKey}")

        _, cmdStatus = self.tagReader.sendMSESetATMutualAuth(self.paceInfo.oid, self.MRZ_PACE_KEY_REFERENCE)
        if cmdStatus != StatusCode.SUCCESS:
            raise ValueError(f"MSESetATMutualAuth failed with status: {cmdStatus}")

        # ----------------------------------- Step1 ---------------------------------- #
        cmdData, cmdStatus = self.tagReader.sendGeneralAuthenticate([], isLast=False)
        if cmdStatus != StatusCode.SUCCESS:
            raise ValueError(f"GeneralAuthenticate failed with status: {cmdStatus}")
        encryptedNonce = unwrapDO(0x80, cmdData)
        cipherAlgName = self.paceInfo.getCipherAlgorithm()
        if cipherAlgName == "3DES":
            cipher = DES3.new(paceKey, DES3.MODE_CBC, bytes([0] * 8))
            decryptedPassportNonce = cipher.decrypt(bytes(encryptedNonce))
        elif cipherAlgName == "AES":
            cipher = AES.new(paceKey, AES.MODE_CBC, bytes([0] * 16))
            decryptedPassportNonce = cipher.decrypt(bytes(encryptedNonce))
        else:
            raise ValueError(f"Unsupported cipher algorithm: {cipherAlgName}")
        logging.debug(f"Decrypted nonce: {decryptedPassportNonce}")

        # ----------------------------- working!!

        # ----------------------------------- Step2 ---------------------------------- #
        mappingType = self.paceInfo.getMappingType()
        if (mappingType == "CAM" or mappingType == "GM"):
            logging.debug("General Mapping...")
            mappingKey = self.paceInfo.createMappingKey()
            publicKeyData = getPublicKeyData(mappingKey)
            logging.debug(f"Mapping public key: {publicKeyData}")

            data = wrapDO(0x81, publicKeyData)
            cmdData, cmdStatus = self.tagReader.sendGeneralAuthenticate(data, isLast=False)
            if cmdStatus != StatusCode.SUCCESS:
                raise ValueError(f"GeneralAuthenticate failed with status: {cmdStatus}")
            
            pcdMappingEncodedPublicKey = unwrapDO(0x82, cmdData)
            logging.debug(f"PICC mapping encoded public key: {pcdMappingEncodedPublicKey}")

            bigNumPassportNonce = createNonceBN(decryptedPassportNonce)
            agreementAlg = self.paceInfo.getKeyAgreementAlgorithm()
            if agreementAlg == "ECDH":
                keyPairPtr = ECDHMappingAgreement(mappingKey, pcdMappingEncodedPublicKey, bigNumPassportNonce)
                if not keyPairPtr:
                    raise ValueError("ECDHMappingAgreement failed")
            else:
                raise ValueError(f"Unsupported key agreement algorithm: {agreementAlg}")
        else:
            raise ValueError(f"Unsupported mapping type: {mappingType}")
        
        # ----------------------------------- Step3 ---------------------------------- #
        publicKeyData = getPublicKeyData(keyPairPtr)
        logging.debug(f"Ephemeral public key: {publicKeyData}")

        publicKeyDataCmd = wrapDO(0x83, publicKeyData)
        cmdData, cmdStatus = self.tagReader.sendGeneralAuthenticate(publicKeyDataCmd, isLast=False)
        if cmdStatus != StatusCode.SUCCESS:
            raise ValueError(f"GeneralAuthenticate failed with status: {cmdStatus}")
        passportEncodedPublicKey = unwrapDO(0x84, cmdData)
        passportPublicKey = decodePublicKeyFromBytes(passportEncodedPublicKey, keyPairPtr)

        # ----------------------------------- Step4 ---------------------------------- #
        sharedSecret = computeSharedSecret(keyPairPtr, passportPublicKey)
        logging.debug(f"Shared secret: {sharedSecret}")

        logging.debug("Getting ksEnc and ksMac keys from shared secret")
        cipherAlgName = self.paceInfo.getCipherAlgorithm()
        keyLength = self.paceInfo.getKeyLength()
        encKey = KeyGenerator.getKey(bytes(sharedSecret), cipherAlgName, keyLength, KeyMode.ENC_MODE)
        macKey = KeyGenerator.getKey(bytes(sharedSecret), cipherAlgName, keyLength, KeyMode.MAC_MODE)
        logging.debug(f"ksEnc: {encKey}, ksMac: {macKey}")

        pcdAuthToken = self._generateAuthenticationToken(passportPublicKey, macKey)
        logging.debug(f"PCD auth token: {pcdAuthToken}")

        pcdAuthTokenCmd = wrapDO(0x85, pcdAuthToken)
        cmdData, cmdStatus = self.tagReader.sendGeneralAuthenticate(pcdAuthTokenCmd, isLast=True)
        if cmdStatus != StatusCode.SUCCESS:
            raise ValueError(f"GeneralAuthenticate failed with status: {cmdStatus}")
