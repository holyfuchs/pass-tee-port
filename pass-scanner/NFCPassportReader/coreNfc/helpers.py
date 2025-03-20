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