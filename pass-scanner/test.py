from NFCPassportReader.coreNfc.adpu import ADPUCommand, Instruction, Length
from NFCPassportReader.coreNfc.secureMessageHandler import SecureMessageHandler

# # data, status = self.__sendData([0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x04])
# adpu = ADPUCommand(Instruction.READ_BINARY, 0x00, 0x00, [], Length.SHORT_BINARY_SIZE)

# print([f"0x{b:02X}" for b in adpu.getCommand()])

# print([f"0x{b:02X}" for b in ADPUCommand(Instruction.SELECT, 0x02, 0x0C, [0x03]).getCommand()])

sec = SecureMessageHandler(
	ksenc=[55, 163, 164, 2, 109, 178, 218, 252, 67, 102, 175, 69, 18, 171, 248, 188, 55, 163, 164, 2, 109, 178, 218, 252],
	ksmac=[27, 180, 39, 92, 181, 75, 66, 93, 99, 112, 35, 32, 164, 64, 23, 187, 27, 180, 39, 92, 181, 75, 66, 93],
	ssc=[64, 58, 251, 101, 199, 91, 230, 216]
)
sec.protect(
	ADPUCommand(Instruction.SELECT, 0x02, 0x0C, [0x01, 0x1E])
)
sec.unprotect(None)
print("--------------------------------")
# protected_apdu = sec.protect(
# 	ADPUCommand.fromBytes(bytes([0x00, 0xB0, 0x00, 0x00, 0x00, 0x00, 0x04]))
# )
protected_apdu = sec.protect(
	ADPUCommand(Instruction.READ_BINARY, 0x00, 0x00, [], Length.SHORT_BINARY_SIZE)
)
print([f"0x{b:02X}" for b in [0x0C, 0xB0, 0x00, 0x00, 0x0D, 0x97, 0x01, 0x04, 0x8E, 0x08, 0x8B, 0xFA, 0xE4, 0x2B, 0x08, 0x0E, 0x50, 0x64, 0x00]])
print([f"0x{b:02X}" for b in protected_apdu])
