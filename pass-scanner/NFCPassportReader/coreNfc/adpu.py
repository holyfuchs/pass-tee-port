from .helpers import generate_length_field
from typing import List
from enum import Enum


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
    SHORT_CHALLENGE = 0x08
    SHORT_BINARY_SIZE = 0x04


# ---------------------------------------------------------------------------- #
#                                    Helpers                                   #
# ---------------------------------------------------------------------------- #
IS_EXTENDEDLENGTH = lambda data: len(data) > Length.SHORT_MAX_LC.value or len(data) > Length.SHORT_MAX_LE.value


# ---------------------------------------------------------------------------- #
#                                    ADPUCommand                               #
# ---------------------------------------------------------------------------- #
class ADPUCommand:
    def __init__(self, instruction: Instruction, parameter1: int, parameter2: int, data: bytes, responseLength: Length = Length.NO_LE, isLast: bool = True):
        self.instruction = instruction.value
        self.parameter1 = parameter1
        self.parameter2 = parameter2
        self.data = data
        self.responseLength = responseLength.value
        self.isLast = isLast

    # @staticmethod
    # def fromBytes(data: bytes) -> 'ADPUCommand':
    #     if len(data) < 4:
    #         raise ValueError("APDU must be at least 4 bytes long.")

    #     # Extract mandatory header fields
    #     cla = data[0]
    #     ins = data[1]
    #     p1 = data[2]
    #     p2 = data[3]

    #     # Initialize optional fields
    #     lc = None
    #     command_data = b''
    #     le = None

    #     # Determine the presence and length of Lc and Le
    #     index = 4
    #     if len(data) > index:
    #         lc_byte = data[index]
    #         if lc_byte != 0:
    #             # Short Lc field
    #             lc = lc_byte
    #             index += 1
    #         else:
    #             # Check if there's enough data for extended Lc
    #             if len(data) > index + 2:
    #                 # Extended Lc field
    #                 lc = int.from_bytes(data[index + 1:index + 3], byteorder='big')
    #                 index += 3
    #             else:
    #                 # Lc is zero, no data field
    #                 lc = 0
    #                 index += 1

    #         # Extract Data field if Lc is present
    #         if lc is not None and lc > 0:
    #             if len(data) < index + lc:
    #                 raise ValueError("APDU data length is less than Lc.")
    #             command_data = data[index:index + lc]
    #             index += lc

    #         # Extract Le field if present
    #         if len(data) > index:
    #             remaining_length = len(data) - index
    #             if remaining_length == 1:
    #                 le = data[index]
    #                 if le == 0:
    #                     le = 256
    #             elif remaining_length == 2:
    #                 le = int.from_bytes(data[index:index + 2], byteorder='big')
    #                 if le == 0:
    #                     le = 65536
    #             else:
    #                 raise ValueError("Invalid Le field length.")

    #     apdu = ADPUCommand(Instruction(ins), p1, p2, command_data)
    #     apdu.responseLength = le if le is not None else 0

    #     return apdu

    def getCommand(self) -> List[int]:
        if (len(self.data) > Length.EXTENDED_MAX_LC.value):
            raise ValueError(f"Command data exceeds maximum value of 0x{Length.EXTENDED_MAX_LC.value:X}")

        if (self.responseLength == Length.EXTENDED_MAX_LE.value):
            raise ValueError(f"Response length exceeds maximum value of 0x{Length.EXTENDED_MAX_LE.value:X}")
        
        command = []
        header = [
            0x00 if self.isLast else 0x10, # CLA
            self.instruction, # INS
            self.parameter1, # P1
            self.parameter2, # P2
        ]
        command.extend(header)

        if (IS_EXTENDEDLENGTH(self.data)):
            command.append(0x00) # extended length
        
        # add data
        if (len(self.data) > 0):
            command.extend(generate_length_field(len(self.data), IS_EXTENDEDLENGTH(self.data)))
            command.extend(self.data)

        # add response length
        if (self.responseLength > 0):
            command.extend(generate_length_field(self.responseLength, IS_EXTENDEDLENGTH(self.data)))

        return command
