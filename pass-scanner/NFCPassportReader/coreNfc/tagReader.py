from .helpers import generate_length_field, asn1Length
from smartcard.CardConnection import CardConnection
from smartcard.System import readers
from .cardAccess import CardAccess
from typing import List, Tuple
from enum import Enum
import logging

# ---------------------------------------------------------------------------- #
#                                     Enums                                    #
# ---------------------------------------------------------------------------- #
class StatusCode(Enum):
    UNKNOWN = 0x0000
    SUCCESS = 0x9000
    NO_PKCS15_APP = 0x6200
    END_OF_FILE = 0x6282
    PIN_DEACTIVATED = 0x6283
    FCI_NO_ISO7816_4 = 0x6284
    VERIFICATION_FAILED = 0x6300
    INPUT_TIMEOUT = 0x6400
    INPUT_CANCELLED = 0x6401
    PASSWORDS_DIFFER = 0x6402
    PASSWORD_OUTOF_RANGE = 0x6403
    CARD_EJECTED_AND_REINSERTED = 0x64A2
    EEPROM_CELL_DEFECT = 0x6581
    SECURITY_ENVIRONMENT = 0x6600
    WRONG_LENGTH = 0x6700
    NO_BINARY_FILE = 0x6981
    LAST_CHAIN_CMD_EXPECTED = 0x6883
    ACCESS_DENIED = 0x6982
    PASSWORD_COUNTER_EXPIRED = 0x6983
    DIRECTORY_OR_PASSWORD_LOCKED_OR_NOT_ALLOWED = 0x6984
    NO_PARENT_FILE = 0x6985
    NOT_YET_INITIALIZED = 0x6985
    NO_CURRENT_DIRECTORY_SELECTED = 0x6986
    DATAFIELD_EXPECTED = 0x6987
    INVALID_SM_OBJECTS = 0x6988
    SW_APPLET_SELECT_FAILED = 0x6999
    COMMAND_NOT_ALLOWED = 0x69F0
    INVALID_DATAFIELD = 0x6A80
    ALGORITHM_ID = 0x6A81
    FILE_NOT_FOUND = 0x6A82
    RECORD_NOT_FOUND = 0x6A83
    INVALID_PARAMETER = 0x6A86
    LC_INCONSISTANT = 0x6A87
    REFERENCED_DATA_NOT_FOUND = 0x6A88
    ILLEGAL_OFFSET = 0x6B00
    UNSUPPORTED_CLA = 0x6E00
    CANT_DISPLAY = 0x6410
    INVALID_P1P2 = 0x6A00
    UNSUPPORTED_INS = 0x6D00
    PIN_BLOCKED = 0x63C0  # retries left: 0
    PIN_SUSPENDED = 0x63C1  # retries left: 1
    PIN_RETRY_COUNT_2 = 0x63C2  # retries left: 2
    INITIAL_PIN_BLOCKED = 0x63D0
    INITIAL_PIN_RETRY_COUNT_1 = 0x63D1
    INITIAL_PIN_RETRY_COUNT_2 = 0x63D2
    INITIAL_PIN_RETRY_COUNT_3 = 0x63D3
    NO_PRECISE_DIAGNOSIS = 0x6F00

class Instruction(Enum):
    UNKNOWN = 0x00
    DEACTIVATE = 0x04
    VERIFY = 0x20
    MSE_SET = 0x22
    ACTIVATE = 0x44
    EXTERNAL_AUTHENTICATE = 0x82
    GET_CHALLENGE = 0x84
    GENERAL_AUTHENTICATE = 0x86
    PSO_VERIFY = 0x2A
    PSO_COMPUTE = 0x2B
    RESET_RETRY_COUNTER = 0x2C
    SELECT = 0xA4
    READ_BINARY = 0xB0
    GET_RESPONSE = 0xC0
    UPDATE_BINARY = 0xD6

class Length(Enum):
    NO_LE = 0x00
    SHORT_MAX_LC = 0xFF
    SHORT_MAX_LE = 0x0100
    EXTENDED_MAX_LC = 0x00FFFF
    EXTENDED_MAX_LE = 0x010000

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
        data, sw1, sw2 = self.connection.transmit(data)
        return data, StatusCode(sw1 * 256 + sw2)
	
    def __sendCommand(self, instruction: Instruction, parameter1: int, parameter2: int, data: bytes, responseLength: Length = Length.NO_LE):
        if (len(data) > Length.EXTENDED_MAX_LC.value):
            raise ValueError(f"Command data exceeds maximum value of 0x{Length.EXTENDED_MAX_LC.value:X}")

        if (responseLength.value == Length.EXTENDED_MAX_LE.value):
            raise ValueError(f"Response length exceeds maximum value of 0x{Length.EXTENDED_MAX_LE.value:X}")
        
        command = []

        header = [
            0x00, # CLA
            instruction.value, # INS
            parameter1, # P1
            parameter2, # P2
        ]
        command.extend(header)

        if (IS_EXTENDEDLENGTH(data)):
            command.append(0x00) # extended length
        
        # add data
        if (len(data) > 0):
            command.extend(generate_length_field(len(data), IS_EXTENDEDLENGTH(data)))
            command.extend(data)

        # add response length
        if (responseLength.value > 0):
            command.extend(generate_length_field(responseLength.value, IS_EXTENDEDLENGTH(data)))

        return self.__sendData(command)

    def selectFile(self, tag: List[int]):
        data, status = self.__sendCommand(Instruction.SELECT, FileType.ELEMENTARY_FILE.value, PROPRIETARY, tag)
        if (status != StatusCode.SUCCESS):
            raise Exception(f"Failed to select file: {status}")
        return data

    def selectFileAndRead(self, tag: List[int]) -> List[int]:
        self.selectFile(tag)

        # Read first 4 bytes of header to see how big the data structure is
        data, status = self.__sendData([0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x04])
        if (status != StatusCode.SUCCESS):
            raise Exception(f"Failed to read header: {status}")

        length, offset = asn1Length(bytes(data[1:4]))
        remaining = length
        amount_read = offset + 1

        total_data = data[:amount_read]
        while (remaining > 0):
            offset = amount_read.to_bytes(2, byteorder="big")
            data, status = self.__sendCommand(Instruction.READ_BINARY, offset[0], offset[1], [], Length.SHORT_MAX_LE)
            if (status != StatusCode.SUCCESS):
                raise Exception(f"Failed to read data: {status}")
            total_data.extend(data)

            remaining -= len(data)
            amount_read += len(data)

        return total_data

    def readCardAccess(self) -> List[int]:
        logging.debug("Reading card access")

        # Select Master File
        _, status = self.__sendCommand(Instruction.SELECT, FileType.MASTER_FILE.value, PROPRIETARY, bytes.fromhex("3F00"))
        if (status != StatusCode.SUCCESS):
            raise Exception(f"Failed to select master file: {status}")
        
        # Read EC.CardAccess
        data = self.selectFileAndRead([0x01, 0x1C])
        return CardAccess(data)
