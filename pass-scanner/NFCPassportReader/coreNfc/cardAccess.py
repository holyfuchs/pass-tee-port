from typing import List, Any
import asn1

# SecurityInfos ::= SET of SecurityInfo
# SecurityInfo ::= SEQUENCE {
#     protocol OBJECT IDENTIFIER,
#     requiredData ANY DEFINED BY protocol,
#     optionalData ANY DEFINED BY protocol OPTIONAL
# }

class CardAccess:
    asn1Data: List[Any]

    def __init__(self, data: List[int]):
        decoder = asn1.Decoder()
        decoder.start(bytes(data))
        _, self.asn1Data = decoder.read()


