from .coreNfc.paceHandler import PaceHandler
from .coreNfc.tagReader import TagReader
from .passport import Passport


class PassportReader:
    def __init__(self):
        pass

    def readPassport(self, mrz: str, tags: list[str]):
        tagReader = TagReader()
        passport = Passport(mrz)

        accessData = tagReader.readCardAccess()
        paceHandler = PaceHandler(accessData, tagReader)
        paceHandler.handlePace(mrz)

        return passport
