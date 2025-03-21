# import asn1

# encoder = asn1.Encoder()
# encoder.start()
# encoder.write('1.2.3', asn1.Numbers.ObjectIdentifier)
# encoded_bytes = encoder.output()

# print(encoded_bytes)

# decoder = asn1.Decoder()
# decoder.start([49, 20, 48, 18, 6, 10, 4, 0, 127, 0, 7, 2, 2, 4, 2, 2, 2, 1, 2, 2, 1, 13])
# tag, value = decoder.read()
# print(tag, value)

from pyasn1.type.univ import ObjectIdentifier
from pyasn1.codec.der.encoder import encode

oid = ObjectIdentifier('0.4.0.127.0.7.2.2.4.2.2')
encoded = encode(oid)
print(encoded)
