from .tagReader import ADPUCommand, Instruction
from .helpers import toAsn1Length, asn1Length
from Crypto.Util.Padding import pad, unpad
from Crypto.Cipher import DES3
from typing import List, Tuple
from .llcrypto import desMAC


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
    
    def _maskClassAndPad(self, adpuCommand: ADPUCommand) -> List[int]:
        return list(pad(bytes([0x0c, adpuCommand.instruction, adpuCommand.parameter1, adpuCommand.parameter2]), 8, style="iso7816"))
        
    def _padAndEncryptData(self, adpuCommand: ADPUCommand) -> List[int]:
        paddedData = pad(bytes(adpuCommand.data), 8, style="iso7816")
        cipher = DES3.new(self.ksenc, DES3.MODE_CBC, bytes([0] * 8))
        encryptedData = list(cipher.encrypt(bytes(paddedData)))
        return encryptedData

    def _buildD087(self, adpuCommand: ADPUCommand) -> List[int]:
        cipher = [0x01] + self._padAndEncryptData(adpuCommand)
        res = [0x87] + toAsn1Length(len(cipher)) + cipher
        return res
    
    def _buildD097(self, adpuCommand: ADPUCommand) -> List[int]:
        le = adpuCommand.responseLength
        if le <= 0xFF:
            binLe = list(le.to_bytes(1, byteorder='big'))
        else:
            binLe = list(le.to_bytes(2, byteorder='big'))
        if le == 256 or le == 65536:
            if le > 256:
                binLe = [0x00, 0x00]
            else:
                binLe = [0x00]
        res = [0x97] + toAsn1Length(len(binLe)) + binLe
        return res

    def _buildD08E(self, mac: List[int]) -> List[int]:
        res = [0x8E, len(mac)] + mac
        return res

    def protect(self, adpuCommand: ADPUCommand) -> List[int]:
        self._incSSC()

        cmdHeader = self._maskClassAndPad(adpuCommand)

        do87 = []
        if (len(adpuCommand.data) > 0):
            do87 = self._buildD087(adpuCommand)

        do97 = []
        isMse = adpuCommand.instruction == Instruction.MSE_SET.value
        if (adpuCommand.responseLength > 0 and (isMse and adpuCommand.responseLength < 256 or not isMse)):
            do97 = self._buildD097(adpuCommand)

        M = cmdHeader + do87 + do97
        
        N = pad(bytes(self.ssc + M), 8, style="iso7816")

        CC = desMAC(bytes(self.ksmac), N)
        if len(CC) > 8:
            CC = CC[:8]

        do8e = self._buildD08E(CC)

        size = len(do87) + len(do97) + len(do8e)
        if (size > 255):
            dataSize = [0x00] + list(size.to_bytes(2, byteorder='big'))
        else:
            dataSize = list(size.to_bytes(1, byteorder='big'))
        protectedAPDU = cmdHeader[:4] + dataSize
        protectedAPDU += do87 + do97 + do8e

        if size > 255:
            protectedAPDU += [0x00, 0x00]
        else:
            protectedAPDU += [0x00]

        return protectedAPDU

    def unprotect(self, data: List[int], insw1: int, insw2: int) -> Tuple[List[int], int, int]:
        self._incSSC()

        if (insw1 != 0x90 or insw2 != 0x00):
            raise Exception(f"Unprotect failed: {insw1} {insw2}")
    
        dataBin = data + [insw1, insw2]

        needCC = False
        do87 = []
        do87Data = []
        do99 = []
        offset = 0
        if dataBin[0] == 0x87:
            encDataLength, offset = asn1Length(bytes(dataBin[1:]))
            offset += 1

            if dataBin[offset] != 0x1:
                raise Exception("D087Malformed")
            
            do87 = dataBin[0:(offset+encDataLength)]
            do87Data = dataBin[(offset + 1):(offset+encDataLength)]
            offset += encDataLength
            needCC = True

        if not len(dataBin) >= (offset + 5):
            raise Exception("size error")
        
        do99 = dataBin[offset:(offset + 4)]
        sw1 = dataBin[offset + 2]
        sw2 = dataBin[offset + 3]
        offset += 4
        needCC = True

        if do99[0] != 0x99 and do99[1] != 0x02:
            raise Exception(f"Unprotect failed")
        
        if dataBin[offset] == 0x8E:
            ccLength = dataBin[offset + 1]
            CC = dataBin[(offset + 2):(offset + 2 + ccLength)]

            K = pad(bytes(self.ssc + do87 + do99), 8, style="iso7816")

            CCb = desMAC(bytes(self.ksmac), K)
            if len(CCb) > 8:
                CCb = CCb[:8]

            if CCb != CC:
                raise Exception("InvalidResponseChecksum")
        elif needCC:
            raise Exception("MissingMandatoryFields")
        
        outData = []
        if (len(do87Data) > 0):
            cipher = DES3.new(self.ksenc, DES3.MODE_CBC, bytes([0] * 8))
            decryptedData = cipher.decrypt(bytes(do87Data))
            outData = list(unpad(decryptedData, 8, style="iso7816"))

        return outData, sw1, sw2
