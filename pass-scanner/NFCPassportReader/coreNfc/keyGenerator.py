from enum import Enum

class KeyMode(Enum):
    ENC_MODE = 0x1
    MAC_MODE = 0x2
    PACE_MODE = 0x3

class KeyGenerator:
    def getKey(self, keySeed: bytes, cipherAlgName: str, keyMode: KeyMode):
        modeData = [0x00, 0x00, 0x00, keyMode.value]
        dataEls = list(keySeed)
        dataEls.extend(modeData)
    
	# def _createKey(self, mrzKey: str):
    #     mrzBytes = mrzKey.encode('utf-8')
    #     keySeed: bytes = hashlib.sha1(mrzBytes).digest()

    #     modeData = [0x00, 0x00, 0x00, 0x3]
    #     dataEls = list(keySeed)
    #     dataEls.extend(modeData)
    #     digestAlgo = self.paceInfo.getDigestAlgorithm()
    #     if digestAlgo == "SHA-1":
    #         hashResult = hashlib.sha1(bytes(dataEls)).digest()
    #     elif digestAlgo == "SHA-256":
    #         hashResult = hashlib.sha256(bytes(dataEls)).digest()

    #     cipherAlgName = self.paceInfo.getCipherAlgorithm()
    #     keyLength = self.paceInfo.getKeyLength()
    #     if cipherAlgName == "3DES":
    #         # TR-SAC 1.01, 4.2.1.
    #         if keyLength == 128:
    #             outputKey = hashResult[:16] + hashResult[:8]
    #         else:
    #             raise ValueError(f"Unsupported 3DES key length: {keyLength}")
    #     elif cipherAlgName == "AES":
    #         # TR-SAC 1.01, 4.2.2.
    #         if keyLength == 128:
    #             outputKey = hashResult[:16]
    #         elif keyLength == 192:
    #             outputKey = hashResult[:24]
    #         elif keyLength == 256:
    #             outputKey = hashResult[:32]
    #         else:
    #             raise ValueError(f"Unsupported AES key length: {keyLength}")
    #     else:
    #         raise ValueError(f"Unsupported cipher algorithm: {cipherAlgName}")

    #     return outputKey
