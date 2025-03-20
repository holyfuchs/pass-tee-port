from NFCPassportReader import PassportReader
import logging

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    
    reader = PassportReader()
    reader.readPassport("testmrz", ["COM"])
