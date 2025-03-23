# from .coreNfc.paceHandler import PaceHandler
from .coreNfc.bacHandler import BACHandler
from .coreNfc.tagReader import TagReader

class PassportReader:
    def __init__(self):
        pass

    def readPassport(self, mrz: str, tags: list[str]):
        tagReader = TagReader()

        bacHandler = BACHandler(tagReader)
        bacHandler.handleBac(mrz)
        # accessData = tagReader.readCardAccess()
        # paceHandler = PaceHandler(accessData, tagReader)
        # paceHandler.handlePace(mrz)
        
        # COM
        tagReader.selectFileAndRead([0x01,0x1E])
        # DG1
        dg1data = tagReader.selectFileAndRead([0x01,0x01])
        # SOD
        soddata = tagReader.selectFileAndRead([0x01,0x1D])

        return dg1data, soddata
