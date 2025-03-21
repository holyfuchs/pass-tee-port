from NFCPassportReader import PassportReader
from dotenv import load_dotenv
import logging
import os

load_dotenv()

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    
    reader = PassportReader()
    reader.readPassport(os.getenv("MRZ_KEY"), ["COM"])
