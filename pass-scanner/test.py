import asn1

encoder = asn1.Encoder()
encoder.start()
encoder.write('1.2.3', asn1.Numbers.ObjectIdentifier)
encoded_bytes = encoder.output()

print(encoded_bytes)

decoder = asn1.Decoder()
decoder.start(encoded_bytes)
tag, value = decoder.read()

print(tag, value)