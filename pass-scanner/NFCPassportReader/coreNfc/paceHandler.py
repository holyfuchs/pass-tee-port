from .llcrypto import ECDHMappingAgreement, getPublicKeyData, decodePublicKeyFromBytes, computeSharedSecret
from cryptography.hazmat.primitives import serialization
from .helpers import unwrapDO, wrapDO, getPublicKeyBytes
from .tagReader import TagReader, StatusCode
from Crypto.Cipher import DES3, AES
from .cardAccess import CardAccess
import hashlib
import logging


class PaceHandler:
    MRZ_PACE_KEY_REFERENCE = 0x01

    def __init__(self, cardAccess: CardAccess, tagReader: TagReader):
        self.cardAccess = cardAccess
        self.tagReader = tagReader
        self.paceInfo = self.cardAccess.securityInfos[0]

    def _createKey(self, mrzKey: str):
        mrzBytes = mrzKey.encode('utf-8')
        keySeed: bytes = hashlib.sha1(mrzBytes).digest()

        modeData = [0x00, 0x00, 0x00, 0x3]
        dataEls = list(keySeed)
        dataEls.extend(modeData)
        digestAlgo = self.paceInfo.getDigestAlgorithm()
        if digestAlgo == "SHA-1":
            hashResult = hashlib.sha1(bytes(dataEls)).digest()
        elif digestAlgo == "SHA-256":
            hashResult = hashlib.sha256(bytes(dataEls)).digest()

        cipherAlgName = self.paceInfo.getCipherAlgorithm()
        keyLength = self.paceInfo.getKeyLength()
        if cipherAlgName == "3DES":
            # TR-SAC 1.01, 4.2.1.
            if keyLength == 128:
                outputKey = hashResult[:16] + hashResult[:8]
            else:
                raise ValueError(f"Unsupported 3DES key length: {keyLength}")
        elif cipherAlgName == "AES":
            # TR-SAC 1.01, 4.2.2.
            if keyLength == 128:
                outputKey = hashResult[:16]
            elif keyLength == 192:
                outputKey = hashResult[:24]
            elif keyLength == 256:
                outputKey = hashResult[:32]
            else:
                raise ValueError(f"Unsupported AES key length: {keyLength}")
        else:
            raise ValueError(f"Unsupported cipher algorithm: {cipherAlgName}")

        return outputKey

    def handlePace(self, mrzKey: str):
        logging.debug(f"Handling PACE with OID: {self.paceInfo.oid}")

        paceKey = self._createKey(mrzKey)
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
            cipher = DES3.new(paceKey, DES3.MODE_CBC, bytes(encryptedNonce[:8]))
            decryptedPassportNonce = cipher.decrypt(bytes(encryptedNonce))
        elif cipherAlgName == "AES":
            cipher = AES.new(paceKey, AES.MODE_CBC, bytes(encryptedNonce[:16]))
            decryptedPassportNonce = cipher.decrypt(bytes(encryptedNonce))
        else:
            raise ValueError(f"Unsupported cipher algorithm: {cipherAlgName}")
        logging.debug(f"Decrypted nonce: {decryptedPassportNonce}")

        # ----------------------------------- Step2 ---------------------------------- #
        mappingType = self.paceInfo.getMappingType()
        if (mappingType == "CAM" or mappingType == "GM"):
            mappingKey = self.paceInfo.createMappingKey()
            publicKeyBytes = getPublicKeyBytes(mappingKey)
            logging.debug(f"Mapping public key: {publicKeyBytes}")

            data = wrapDO(0x81, list(publicKeyBytes))
            cmdData, cmdStatus = self.tagReader.sendGeneralAuthenticate(data, isLast=False)
            if cmdStatus != StatusCode.SUCCESS:
                raise ValueError(f"GeneralAuthenticate failed with status: {cmdStatus}")
            
            piccMappingEncodedPublicKey = unwrapDO(0x82, cmdData)
            logging.debug(f"PICC mapping encoded public key: {piccMappingEncodedPublicKey}")

            bigNumPassportNonce = int.from_bytes(decryptedPassportNonce, byteorder='big')
            agreementAlg = self.paceInfo.getKeyAgreementAlgorithm()
            if agreementAlg == "ECDH":
                mapping_key_bytes = mappingKey.private_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                keyPairPtr = ECDHMappingAgreement(list(mapping_key_bytes), list(piccMappingEncodedPublicKey), bigNumPassportNonce)
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
