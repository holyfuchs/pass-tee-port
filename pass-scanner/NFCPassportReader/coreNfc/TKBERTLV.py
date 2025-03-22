from asn1crypto.core import Any

class TKBERTLVRecord:
    def __init__(self, tag: int, value: bytes = None, records: list['TKBERTLVRecord'] = None):
        self.tag = tag
        if value is not None:
            self.value = value
        elif records is not None:
            # Concatenate child TLVs
            self.value = b''.join(r.to_bytes() for r in records)
        else:
            self.value = b''

    def to_bytes(self) -> bytes:
        """
        Encode this record as [TAG-BYTES][LENGTH-BYTES][VALUE].
        
        'tag' is treated as a literal integer that we split into 1..N bytes big-endian.
        So 0x7F49 -> b'\x7F\x49'.
        """
        tag_bytes = self.encode_tag_literal(self.tag)
        length_bytes = self.encode_length(len(self.value))
        return tag_bytes + length_bytes + self.value

    @staticmethod
    def encode_tag_literal(tag: int) -> bytes:
        """
        If tag <= 0xFF, output 1 byte.
        If tag <= 0xFFFF, output 2 bytes big-endian.
        If tag <= 0xFFFFFF, output 3 bytes, etc.
        
        No special 'class' bits or base-128. 
        The user is assumed to know the exact tag they'd like on the wire 
        (e.g., 0x7F49 => b'\x7F\x49').
        """
        # Figure out how many bytes we need in big-endian
        byte_len = (tag.bit_length() + 7) // 8
        return tag.to_bytes(byte_len, 'big')

    @staticmethod
    def encode_length(length: int) -> bytes:
        """
        Standard DER length encoding: short form if <128, else long form.
        """
        if length < 0x80:
            return bytes([length])
        len_bytes = length.to_bytes((length.bit_length() + 7) // 8, 'big')
        return bytes([0x80 | len(len_bytes)]) + len_bytes

    @staticmethod
    def from_bytes(data: bytes | list[int]) -> 'TKBERTLVRecord':
        """
        Parse using asn1crypto, but be aware asn1crypto tries to interpret class bits.
        This will not round-trip tags > 0x1F exactly, but it will parse length/value.
        """
        if isinstance(data, list):
            data = bytes(data)

        parsed = Any.load(data)
        # The numeric 'tag' as asn1crypto sees it. If it was 0x7F49, 
        # asn1crypto reports the “tag number” = 73, class = 'application', 
        # it won't give us 0x7F49 directly. So from_bytes cannot perfectly 
        # preserve the raw multi-byte tag. 
        # We'll do a best guess: 
        tag_num = parsed.tag  # e.g., 73
        # If you want the raw bytes, you'd have to slice them from 'data' yourself.
        return TKBERTLVRecord(tag=tag_num, value=parsed.contents)

    @property
    def data(self) -> bytes:
        return self.value