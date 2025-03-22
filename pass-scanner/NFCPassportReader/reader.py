from .coreNfc.paceHandler import PaceHandler
from .coreNfc.bacHandler import BACHandler
from .coreNfc.tagReader import TagReader
from .passport import Passport


class PassportReader:
    def __init__(self):
        pass

    def readPassport(self, mrz: str, tags: list[str]):
        tagReader = TagReader()
        passport = Passport(mrz)

        bacHandler = BACHandler(tagReader)
        bacHandler.handleBac(mrz)
        # accessData = tagReader.readCardAccess()
        # paceHandler = PaceHandler(accessData, tagReader)
        # paceHandler.handlePace(mrz)
        
        data = tagReader.selectFileAndRead([0x01,0x1E])
        print(bytes(data).decode("utf-8"))
        
        data = tagReader.selectFileAndRead([0x01,0x01])
        print(bytes(data).decode("utf-8"))

        return passport
