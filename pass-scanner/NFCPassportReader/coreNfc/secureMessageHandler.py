from Crypto.Util.Padding import pad
from typing import List


# ONLY DES IS SUPPORTED
class SecureMessageHandler:
    def __init__(self, ksenc: List[int], ksmac: List[int], ssc: List[int]):
        self.ksenc = ksenc
        self.ksmac = ksmac
        self.ssc = ssc

    def _incSSC(self) -> List[int]:
        ssc_value = 0
        for byte in self.ssc:
            ssc_value = (ssc_value << 8) | byte
        ssc_value += 1
        self.ssc = [(ssc_value >> (8 * i)) & 0xFF for i in range(7, -1, -1)]
        return self.ssc
    
    def _maskClassAndPad(self, data: List[int]) -> List[int]:
        instructionCode = data[1]
        param1 = data[2]
        param2 = data[3]
        return list(pad(bytes([0x0c, instructionCode, param1, param2]), 8, style="iso7816"))
        

    def protect(self, data: List[int]) -> List[int]:
        self._incSSC()


	
