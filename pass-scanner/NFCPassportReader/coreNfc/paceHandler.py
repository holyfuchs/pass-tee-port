from .tagReader import TagReader, StatusCode
from Crypto.Cipher import DES3, AES
from .cardAccess import CardAccess
from .helpers import unwrapDO
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

        _, cmdStatus = self.tagReader.sendMSESetATMutualAuth(self.paceOID, self.MRZ_PACE_KEY_REFERENCE)
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
            decryptedNonce = cipher.decrypt(bytes(encryptedNonce))
        elif cipherAlgName == "AES":
            cipher = AES.new(paceKey, AES.MODE_CBC, bytes(encryptedNonce[:16]))
            decryptedNonce = cipher.decrypt(bytes(encryptedNonce))
        else:
            raise ValueError(f"Unsupported cipher algorithm: {cipherAlgName}")
        logging.debug(f"Decrypted nonce: {decryptedNonce}")

        # ----------------------------------- Step2 ---------------------------------- #
        # mappingType = self.paceInfo.getMappingType()
        # if (mappingType == "CAM" or mappingType == "GM"):
        #     mappingKey = self.paceInfo.getMappingKey()
        # else:
        #     raise ValueError(f"Unsupported mapping type: {mappingType}")
