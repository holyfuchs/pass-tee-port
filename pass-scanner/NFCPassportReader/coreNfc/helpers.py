from cryptography.hazmat.primitives.asymmetric import dh, ec
from cryptography.hazmat.primitives import serialization
from pyasn1.type.univ import ObjectIdentifier
from pyasn1.codec.der.encoder import encode
from typing import Tuple


def generate_length_field(p_length: int, is_extended_length: bool) -> bytes:
    field = bytearray()
    
    if is_extended_length:
        field.append((p_length >> 8) & 0xFF)
    
    field.append(p_length & 0xFF)
    
    return bytes(field)

def bin_to_hex(data):
    if isinstance(data, int):  # Single byte case
        return data
    return int.from_bytes(data, byteorder="big")  # Multi-byte case

def asn1Length(data: bytes) -> Tuple[int, int]:
    if not data:
        raise ValueError("Cannot decode ASN.1 length: Empty data")

    first_byte = data[0]

    if first_byte < 0x80:
        return bin_to_hex(first_byte), 1  # Short form

    if first_byte == 0x81:
        return bin_to_hex(data[1]), 2  # Single byte length

    if first_byte == 0x82:
        return bin_to_hex(data[1:3]), 3  # Two-byte length

    raise ValueError("Cannot decode ASN.1 length")

def bytesFromOID(oid: str, tagReplace: bool = False) -> bytes:
    encoded = list(encode(ObjectIdentifier(oid)))
    if tagReplace and len(encoded) > 1:
        encoded[0] = 0x80
    return bytes(encoded)

def wrapDO(tag: int, arr: list[int]) -> list[int]:
    value = bytes(arr)
    length = len(value)

    if length < 128:
        length_bytes = bytes([length])
    else:
        len_encoded = length.to_bytes((length.bit_length() + 7) // 8, byteorder='big')
        length_bytes = bytes([0x80 | len(len_encoded)]) + len_encoded

    tlv = bytes([tag]) + length_bytes + value
    return list(tlv)

def unwrapDO(tag: int, wrapped_data: list[int]) -> list[int]:
    data = bytes(wrapped_data)
    
    if len(data) < 2:
        raise ValueError("Data too short for valid TLV")
    
    read_tag = data[0]
    if read_tag != tag:
        raise ValueError(f"Unexpected tag: got {read_tag:#x}, expected {tag:#x}")

    # Parse length
    length_byte = data[1]
    offset = 2

    if length_byte & 0x80 == 0:  # Short form
        length = length_byte
    else:  # Long form
        num_bytes = length_byte & 0x7F
        if len(data) < offset + num_bytes:
            raise ValueError("Invalid length field")
        length = int.from_bytes(data[offset:offset+num_bytes], byteorder='big')
        offset += num_bytes

    # Extract value
    if len(data) < offset + length:
        raise ValueError("Value length exceeds available data")

    value = data[offset:offset + length]
    return list(value)

def getPublicKeyBytes(private_key: dh.DHPrivateKey | ec.EllipticCurvePrivateKey) -> bytes:
    public_key = private_key.public_key()

    if isinstance(private_key, dh.DHPrivateKey):
        y = public_key.public_numbers().y
        byte_len = (y.bit_length() + 7) // 8
        return y.to_bytes(byte_len, byteorder='big')

    elif isinstance(private_key, ec.EllipticCurvePrivateKey):
        return public_key.public_bytes(
            encoding=serialization.Encoding.X962,
            format=serialization.PublicFormat.UncompressedPoint
        )
