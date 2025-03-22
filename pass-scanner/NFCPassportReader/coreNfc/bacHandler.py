from .keyGenerator import KeyGenerator, KeyMode
from .tagReader import TagReader, StatusCode
from Crypto.Util.Padding import pad
from Crypto.Cipher import DES3
from typing import List, Tuple
from .llcrypto import desMAC
import logging
import hashlib
import random


class BACHandler:
    def __init__(self, tagReader: TagReader):
        self.tagReader = tagReader

    def generateInitialKseed(self, mrzKey: str) -> List[int]:
        hash = hashlib.sha1(mrzKey.encode("utf-8")).digest()
        return list(hash[:16])
        
    def deriveDocumentBasicAccessKeys(self, mrzKey: str):
        kseed = self.generateInitialKseed(mrzKey)
        
        self.ksenc = KeyGenerator.getKey(bytes(kseed), "3DES", 128, KeyMode.ENC_MODE)
        self.ksmac = KeyGenerator.getKey(bytes(kseed), "3DES", 128, KeyMode.MAC_MODE)

        return self.ksenc, self.ksmac
    
    def authentication(self, iccChallenge: List[int]) -> List[int]:
        self.rnd_icc = iccChallenge

        self.rnd_ifd = random.sample(range(0, 256), 8)
        self.kifd = random.sample(range(0, 256), 16)

        s = self.rnd_ifd + iccChallenge + self.kifd

        cipher = DES3.new(self.ksenc, DES3.MODE_CBC, bytes([0] * 8))
        eifd = list(cipher.encrypt(bytes(s)))

        mifd = desMAC(self.ksmac, pad(bytes(eifd), 8, style="iso7816"))

        return (eifd + mifd)

    def sessionKeys(self, data: List[int]) -> Tuple[List[int], List[int], List[int]]:
        cipher = DES3.new(self.ksenc, DES3.MODE_CBC, bytes([0] * 8))
        response = list(cipher.decrypt(bytes(data[:32])))

        response_kicc = response[16:32]
        # xor the two lists
        Kseed = [x ^ y for x, y in zip(self.kifd, response_kicc)]

        KSenc = KeyGenerator.getKey(bytes(Kseed), "3DES", 128, KeyMode.ENC_MODE)
        KSmac = KeyGenerator.getKey(bytes(Kseed), "3DES", 128, KeyMode.MAC_MODE)

        ssc = self.rnd_icc[4:8] + self.rnd_ifd[4:8]

        return KSenc, KSmac, ssc


    def handleBac(self, mrzKey: str):
        self.deriveDocumentBasicAccessKeys(mrzKey)

        data, status = self.tagReader.selectPassportApplication()
        if status != StatusCode.SUCCESS:
            raise ValueError(f"Failed to select passport application: {status}")

        data, status = self.tagReader.getChallenge()
        if status != StatusCode.SUCCESS:
            raise ValueError(f"Failed to get challenge: {status}")
        
        cmdData = self.authentication(data)
        data, status = self.tagReader.doMutualAuthentication(cmdData)
        if status != StatusCode.SUCCESS:
            raise ValueError(f"Failed to do mutual authentication: {status}")
        
        KSenc, KSmac, ssc = self.sessionKeys(data)
        logging.debug(f"KSenc: {KSenc}")
        logging.debug(f"KSmac: {KSmac}")
        logging.debug(f"ssc: {ssc}")
