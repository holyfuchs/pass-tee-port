from typing import List, Literal
from enum import Enum
import hashlib


class KeyMode(Enum):
    ENC_MODE = 0x1
    MAC_MODE = 0x2
    PACE_MODE = 0x3

class KeyGenerator:
    @classmethod
    def _getDigestAlgo(self, cipherAlgName: str, keyLength: int) -> Literal["SHA1", "SHA256"]:
        if cipherAlgName == "3DES" or cipherAlgName == "AES-128":
            return "SHA1"
        if cipherAlgName == "AES" and keyLength == 128:
            return "SHA1"
        if cipherAlgName == "AES-256" or cipherAlgName ==  "AES-192":
            return "SHA256"
        if cipherAlgName == "AES" and (keyLength == 192 or keyLength == 256):
            return "SHA256"
        raise ValueError(f"Unsupported cipher algorithm: {cipherAlgName}")

    @classmethod
    def _getHash(self, algo: Literal["SHA1", "SHA256"], dataEls: List[int]) -> bytes:
        if algo == "SHA1":
            return hashlib.sha1(bytes(dataEls)).digest()
        elif algo == "SHA256":
            return hashlib.sha256(bytes(dataEls)).digest()

    @classmethod
    def getKey(self, keySeed: bytes, cipherAlgName: str, keyLength: int, keyMode: KeyMode) -> bytes:
        digestAlgo = self._getDigestAlgo(cipherAlgName, keyLength)

        modeData = [0x00, 0x00, 0x00, keyMode.value]
        dataEls = list(keySeed)
        dataEls.extend(modeData)
        hashResult = self._getHash(digestAlgo, dataEls)
        
        if cipherAlgName == "3DES":
            # TR-SAC 1.01, 4.2.1.
            if keyLength == 112 or keyLength == 128:
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
