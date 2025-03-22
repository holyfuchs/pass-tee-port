from .helpers import asn1Length, bytesFromOID, wrapDO, unwrapDO
from .adpu import ADPUCommand, Instruction, Length, StatusCode
from .secureMessageHandler import SecureMessageHandler
from smartcard.CardConnection import CardConnection
from smartcard.System import readers
from .cardAccess import CardAccess
from typing import List, Tuple
from enum import Enum
import logging


# ---------------------------------------------------------------------------- #
#                                     Enums                                    #
# ---------------------------------------------------------------------------- #
class FileType(Enum):
    MASTER_FILE = 0x00
    ELEMENTARY_FILE = 0x02
    APPLICATION = 0x04

PROPRIETARY = 0x0C


# ---------------------------------------------------------------------------- #
#                                    Helpers                                   #
# ---------------------------------------------------------------------------- #
IS_EXTENDEDLENGTH = lambda data: len(data) > Length.SHORT_MAX_LC.value or len(data) > Length.SHORT_MAX_LE.value


# ---------------------------------------------------------------------------- #
#                                   TagReader                                  #
# ---------------------------------------------------------------------------- #
class TagReader:
    secureMessageHandler: SecureMessageHandler = None

    def __init__(self):
        available_readers = readers()
        if not available_readers:
            raise Exception("No NFC reader found")
        try:
            self.reader = available_readers[0]
            self.connection: CardConnection = self.reader.createConnection()
            self.connection.connect()
        except:
            raise Exception("Error creating connection")

    def __sendData(self, data: List[int]) -> Tuple[List[int], StatusCode]:
        logging.debug(f"Sending data: {[f'0x{b:02X}' for b in data]}")
        data, sw1, sw2 = self.connection.transmit(data)
        logging.debug(f"Received data: {[f'0x{b:02X}' for b in data]}")
        logging.debug(f"SW1: {hex(sw1)}, SW2: {hex(sw2)}")
        return data, sw1, sw2

    def __sendCommand(self, adpuCommand: ADPUCommand):
        if (self.secureMessageHandler is None):
            data, sw1, sw2 = self.__sendData(adpuCommand.getCommand())
        else:
            encdata, encsw1, encsw2 = self.__sendData(self.secureMessageHandler.protect(adpuCommand))
            data, sw1, sw2 = self.secureMessageHandler.unprotect(encdata, encsw1, encsw2)
        return data, StatusCode(sw1 * 256 + sw2)

    def selectFile(self, tag: List[int]):
        data, status = self.__sendCommand(ADPUCommand(Instruction.SELECT, FileType.ELEMENTARY_FILE.value, PROPRIETARY, bytes(tag)))
        if (status != StatusCode.SUCCESS):
            raise Exception(f"Failed to select file: {status}")
        return data

    def selectFileAndRead(self, tag: List[int]) -> List[int]:
        self.selectFile(tag)

        # Read first 4 bytes of header to see how big the data structure is
        data, status = self.__sendCommand(ADPUCommand(Instruction.READ_BINARY, 0x00, 0x00, [], Length.SHORT_BINARY_SIZE))
        if (status != StatusCode.SUCCESS):
            raise Exception(f"Failed to read header: {status}")

        length, offset = asn1Length(bytes(data[1:4]))
        remaining = length
        amount_read = offset + 1

        total_data = data[:amount_read]
        while (remaining > 0):
            offset = amount_read.to_bytes(2, byteorder="big")
            data, status = self.__sendCommand(ADPUCommand(Instruction.READ_BINARY, offset[0], offset[1], [], Length.SHORT_MAX_LE))
            if (status != StatusCode.SUCCESS):
                raise Exception(f"Failed to read data: {status}")
            total_data.extend(data)

            remaining -= len(data)
            amount_read += len(data)

        return total_data

    def readCardAccess(self) -> CardAccess:
        logging.debug("Reading card access")

        # Select Master File
        _, status = self.__sendCommand(ADPUCommand(Instruction.SELECT, FileType.MASTER_FILE.value, PROPRIETARY, bytes.fromhex("3F00")))
        if (status != StatusCode.SUCCESS):
            raise Exception(f"Failed to select master file: {status}")
        
        # Read EC.CardAccess
        data = self.selectFileAndRead([0x01, 0x1C])
        logging.debug(f"Card access data: {data}")
        return CardAccess(data)
    
    def sendMSESetATMutualAuth(self, oid: str, keyType: int) -> Tuple[List[int], StatusCode]:
        oidBytes = bytesFromOID(oid, True)
        keyTypeBytes = wrapDO(0x83, [keyType])
        totalData = oidBytes + bytes(keyTypeBytes)

        return self.__sendCommand(ADPUCommand(Instruction.MSE_SET, 0xC1, 0xA4, totalData))
    
    def sendGeneralAuthenticate(self, data: List[int], responseLength: Length = Length.SHORT_MAX_LE, isLast: bool = True) -> Tuple[List[int], StatusCode]:
        commandData = bytes(wrapDO(0x7C, data))

        data, status = self.__sendCommand(ADPUCommand(Instruction.GENERAL_AUTHENTICATE, 0x00, 0x00, commandData, responseLength, isLast))
        print(data, status)
        data = unwrapDO(0x7C, data)
        return data, status
    
    def getChallenge(self) -> Tuple[List[int], StatusCode]:
        return self.__sendCommand(ADPUCommand(Instruction.GET_CHALLENGE, 0x00, 0x00, [], Length.SHORT_CHALLENGE))

    def doMutualAuthentication(self, data: List[int]) -> Tuple[List[int], StatusCode]:
        return self.__sendCommand(ADPUCommand(Instruction.EXTERNAL_AUTHENTICATE, 0x00, 0x00, bytes(data), Length.SHORT_MAX_LE))

    def selectPassportApplication(self) -> Tuple[List[int], StatusCode]:
        return self.__sendCommand(ADPUCommand(Instruction.SELECT, FileType.APPLICATION.value, PROPRIETARY, bytes([0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01])))