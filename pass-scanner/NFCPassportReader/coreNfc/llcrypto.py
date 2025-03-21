from ctypes import c_void_p, c_int, c_size_t, POINTER, c_ubyte, byref, cast, c_long, c_char_p
import ctypes

libcrypto = ctypes.cdll.LoadLibrary("/opt/homebrew/Cellar/openssl@3/3.4.1/lib/libcrypto.3.dylib")

# ---------------------------------------------------------------------------- #
#                                   Constants                                  #
# ---------------------------------------------------------------------------- #
EVP_PKEY_DH = 28
EVP_PKEY_DHX = 30

# ---------------------------------------------------------------------------- #
#                              Predefine Functions                             #
# ---------------------------------------------------------------------------- #
libcrypto.BN_new.argtypes = []
libcrypto.BN_new.restype  = c_void_p

libcrypto.BN_free.argtypes = [c_void_p]
libcrypto.BN_free.restype  = None

libcrypto.BN_value_one.argtypes = []
libcrypto.BN_value_one.restype  = c_void_p

libcrypto.BN_set_word.argtypes = [c_void_p, ctypes.c_ulong]
libcrypto.BN_set_word.restype  = c_int

# -- EC_KEY / EC_GROUP / EC_POINT --
libcrypto.EC_KEY_get0_group.argtypes = [c_void_p]
libcrypto.EC_KEY_get0_group.restype  = c_void_p

libcrypto.EC_KEY_get0_private_key.argtypes = [c_void_p]
libcrypto.EC_KEY_get0_private_key.restype  = c_void_p

libcrypto.EC_KEY_dup.argtypes = [c_void_p]
libcrypto.EC_KEY_dup.restype  = c_void_p

libcrypto.EC_KEY_free.argtypes = [c_void_p]
libcrypto.EC_KEY_free.restype  = None

libcrypto.EC_GROUP_dup.argtypes = [c_void_p]
libcrypto.EC_GROUP_dup.restype  = c_void_p

libcrypto.EC_GROUP_free.argtypes = [c_void_p]
libcrypto.EC_GROUP_free.restype  = None

libcrypto.EC_GROUP_get_order.argtypes = [c_void_p, c_void_p, c_void_p]
libcrypto.EC_GROUP_get_order.restype  = c_int

libcrypto.EC_GROUP_get_cofactor.argtypes = [c_void_p, c_void_p, c_void_p]
libcrypto.EC_GROUP_get_cofactor.restype  = c_int

libcrypto.EC_GROUP_set_generator.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p]
libcrypto.EC_GROUP_set_generator.restype  = c_int

libcrypto.EC_GROUP_check.argtypes = [c_void_p, c_void_p]
libcrypto.EC_GROUP_check.restype  = c_int

libcrypto.EC_POINT_new.argtypes = [c_void_p]
libcrypto.EC_POINT_new.restype  = c_void_p

libcrypto.EC_POINT_free.argtypes = [c_void_p]
libcrypto.EC_POINT_free.restype  = None

libcrypto.EC_POINT_mul.argtypes = [c_void_p, c_void_p, c_void_p, c_void_p, c_void_p, c_void_p]
libcrypto.EC_POINT_mul.restype  = c_int

libcrypto.EC_POINT_oct2point.argtypes = [c_void_p, c_void_p, POINTER(c_ubyte), c_size_t, c_void_p]
libcrypto.EC_POINT_oct2point.restype  = c_int

# -- EVP_PKEY & d2i_... for loading key from bytes --
libcrypto.d2i_AutoPrivateKey.argtypes = [
    POINTER(c_void_p),
    POINTER(POINTER(c_ubyte)),
    c_long
]
libcrypto.d2i_AutoPrivateKey.restype  = c_void_p  # returns EVP_PKEY*

libcrypto.EVP_PKEY_get1_EC_KEY.argtypes = [c_void_p]
libcrypto.EVP_PKEY_get1_EC_KEY.restype  = c_void_p  # returns EC_KEY*

libcrypto.EVP_PKEY_new.argtypes = []
libcrypto.EVP_PKEY_new.restype  = c_void_p

libcrypto.EVP_PKEY_free.argtypes = [c_void_p]
libcrypto.EVP_PKEY_free.restype  = None

libcrypto.EVP_PKEY_set1_EC_KEY.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_set1_EC_KEY.restype  = c_int

libcrypto.EC_KEY_set_group.argtypes = [c_void_p, c_void_p]
libcrypto.EC_KEY_set_group.restype = c_int


libcrypto.EVP_PKEY_CTX_new.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_CTX_new.restype = c_void_p

libcrypto.EVP_PKEY_keygen_init.argtypes = [c_void_p]
libcrypto.EVP_PKEY_keygen_init.restype = c_int

libcrypto.EVP_PKEY_keygen.argtypes = [c_void_p, POINTER(c_void_p)]
libcrypto.EVP_PKEY_keygen.restype = c_int

libcrypto.EVP_PKEY_CTX_free.argtypes = [c_void_p]
libcrypto.EVP_PKEY_CTX_free.restype = None


libcrypto.DH_new.argtypes = []
libcrypto.DH_new.restype = c_void_p

libcrypto.DH_free.argtypes = [c_void_p]
libcrypto.DH_free.restype = None

libcrypto.BN_bin2bn.argtypes = [c_char_p, c_int, c_void_p]
libcrypto.BN_bin2bn.restype = c_void_p

libcrypto.DH_set0_key.argtypes = [c_void_p, c_void_p, c_void_p]
libcrypto.DH_set0_key.restype = c_int

libcrypto.EVP_PKEY_set1_DH.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_set1_DH.restype = c_int

libcrypto.EC_KEY_new.argtypes = []
libcrypto.EC_KEY_new.restype = c_void_p

libcrypto.EC_KEY_set_public_key.argtypes = [c_void_p, c_void_p]
libcrypto.EC_KEY_set_public_key.restype = c_int


libcrypto.EVP_PKEY_get_base_id.argtypes = [c_void_p]
libcrypto.EVP_PKEY_get_base_id.restype = c_int

libcrypto.EVP_PKEY_get0_DH.argtypes = [c_void_p]
libcrypto.EVP_PKEY_get0_DH.restype = c_void_p

libcrypto.DH_get0_key.argtypes = [c_void_p, ctypes.POINTER(c_void_p), ctypes.POINTER(c_void_p)]
libcrypto.DH_get0_key.restype = c_int

libcrypto.BN_num_bits.argtypes = [c_void_p]
libcrypto.BN_num_bits.restype = c_int

libcrypto.BN_bn2bin.argtypes = [c_void_p, c_char_p]
libcrypto.BN_bn2bin.restype = c_int

libcrypto.EVP_PKEY_get0_EC_KEY.argtypes = [c_void_p]
libcrypto.EVP_PKEY_get0_EC_KEY.restype = c_void_p

libcrypto.EC_KEY_get0_public_key.argtypes = [c_void_p]
libcrypto.EC_KEY_get0_public_key.restype = c_void_p

libcrypto.EC_KEY_get_conv_form.argtypes = [c_void_p]
libcrypto.EC_KEY_get_conv_form.restype = c_int

libcrypto.EC_POINT_point2oct.argtypes = [c_void_p, c_void_p, c_int, c_char_p, c_size_t, c_void_p]
libcrypto.EC_POINT_point2oct.restype = c_size_t


# ---------------------------------------------------------------------------- #
#                                   Functions                                  #
# ---------------------------------------------------------------------------- #

def load_private_evp_pkey_from_der(der_bytes: bytes) -> c_void_p:
    pkey_ptr = c_void_p(None)
    buf = (c_ubyte * len(der_bytes))(*der_bytes)
    pp = cast(ctypes.pointer(ctypes.pointer(buf)), POINTER(POINTER(c_ubyte)))
    length = c_long(len(der_bytes))

    evp_pkey = libcrypto.d2i_AutoPrivateKey(byref(pkey_ptr), pp, length)
    if not evp_pkey:
        raise ValueError("d2i_AutoPrivateKey failed. Bytes might not be a valid DER-encoded key.")
    return pkey_ptr

def computeECDHMappingKeyPoint(mappingKey: list[int], inputKey: list[int]) -> c_void_p:
    mapping_key_pkey = load_private_evp_pkey_from_der(bytes(mappingKey))

    try:
        ec_key = libcrypto.EVP_PKEY_get1_EC_KEY(mapping_key_pkey)
        if not ec_key:
            return None
        try:
            priv_bn = libcrypto.EC_KEY_get0_private_key(ec_key)
            if not priv_bn:
                return None

            group = libcrypto.EC_KEY_get0_group(ec_key)
            if not group:
                return None

            ecp = libcrypto.EC_POINT_new(group)
            if not ecp:
                return None

            try:
                in_buf = (c_ubyte * len(inputKey))(*inputKey)
                ret = libcrypto.EC_POINT_oct2point(group, ecp, in_buf, len(inputKey), None)
                if ret == 0:
                    return None

                output = libcrypto.EC_POINT_new(group)
                if not output:
                    return None

                ret2 = libcrypto.EC_POINT_mul(group, output, None, ecp, priv_bn, None)
                if ret2 == 0:
                    libcrypto.EC_POINT_free(output)
                    return None

                return output

            finally:
                libcrypto.EC_POINT_free(ecp)

        finally:
            libcrypto.EC_KEY_free(ec_key)

    finally:
        libcrypto.EVP_PKEY_free(mapping_key_pkey)

def ECDHMappingAgreement(mappingKey: list[int], passportPublicKeyData: list[int], nonce: int) -> c_void_p:
    mapping_key_pkey = load_private_evp_pkey_from_der(bytes(mappingKey))

    try:
        ec_mapping_key = libcrypto.EVP_PKEY_get1_EC_KEY(mapping_key_pkey)
        if not ec_mapping_key:
            raise Exception("Unable to get EC_KEY from mappingKey")

        try:
            base_group = libcrypto.EC_KEY_get0_group(ec_mapping_key)
            if not base_group:
                raise Exception("Unable to get group from EC_KEY")

            group = libcrypto.EC_GROUP_dup(base_group)
            if not group:
                raise Exception("Unable to dup group")

            try:
                order = libcrypto.BN_new()
                if not order:
                    raise Exception("Unable to create order bignum")

                try:
                    cofactor = libcrypto.BN_new()
                    if not cofactor:
                        raise Exception("Unable to create cofactor bignum")

                    try:
                        ret_o = libcrypto.EC_GROUP_get_order(group, order, None)
                        ret_c = libcrypto.EC_GROUP_get_cofactor(group, cofactor, None)
                        if ret_o != 1 or ret_c != 1:
                            raise Exception("Unable to get order or cofactor from group")

                        sharedSecretMappingPoint = computeECDHMappingKeyPoint(
                            mappingKey,
                            passportPublicKeyData
                        )
                        if not sharedSecretMappingPoint:
                            raise Exception("Failed to compute new shared secret mapping point")

                        try:
                            newGenerator = libcrypto.EC_POINT_new(group)
                            if not newGenerator:
                                raise Exception("Unable to create new mapping generator point")

                            try:
                                nonce_bn = libcrypto.BN_new()
                                if not nonce_bn:
                                    raise Exception("BN_new for nonce failed")

                                try:
                                    if libcrypto.BN_set_word(nonce_bn, nonce) != 1:
                                        raise Exception("BN_set_word failed")

                                    bn_one = libcrypto.BN_value_one()
                                    ret_mul = libcrypto.EC_POINT_mul(
                                        group, newGenerator, nonce_bn, 
                                        sharedSecretMappingPoint, bn_one, None
                                    )
                                    if ret_mul != 1:
                                        raise Exception("Failed to map nonce to get new generator params")

                                finally:
                                    libcrypto.BN_free(nonce_bn)

                                # Create ephemeral parameters from duplicated EC_KEY
                                ephemeralParams = libcrypto.EVP_PKEY_new()
                                if not ephemeralParams:
                                    raise Exception("Unable to create ephemeral params")

                                ephemeral_key = libcrypto.EC_KEY_dup(ec_mapping_key)
                                if not ephemeral_key:
                                    libcrypto.EVP_PKEY_free(ephemeralParams)
                                    raise Exception("Unable to dup ephemeral key")

                                try:
                                    if libcrypto.EVP_PKEY_set1_EC_KEY(ephemeralParams, ephemeral_key) != 1:
                                        libcrypto.EVP_PKEY_free(ephemeralParams)
                                        raise Exception("Unable to assign ephemeral key to EVP_PKEY")

                                    if libcrypto.EC_GROUP_set_generator(group, newGenerator, order, cofactor) != 1:
                                        libcrypto.EVP_PKEY_free(ephemeralParams)
                                        raise Exception("Unable to set generator on group")

                                    if libcrypto.EC_GROUP_check(group, None) != 1:
                                        libcrypto.EVP_PKEY_free(ephemeralParams)
                                        raise Exception("EC_GROUP_check failed on new group")

                                    if libcrypto.EC_KEY_set_group(ephemeral_key, group) != 1:
                                        libcrypto.EVP_PKEY_free(ephemeralParams)
                                        raise Exception("Unable to set group on ephemeral_key")

                                    pctx = libcrypto.EVP_PKEY_CTX_new(ephemeralParams, None)
                                    if not pctx:
                                        libcrypto.EVP_PKEY_free(ephemeralParams)
                                        raise Exception("Unable to create EVP_PKEY_CTX")

                                    try:
                                        if libcrypto.EVP_PKEY_keygen_init(pctx) != 1:
                                            raise Exception("EVP_PKEY_keygen_init failed")

                                        ephKeyPair = c_void_p()
                                        if libcrypto.EVP_PKEY_keygen(pctx, byref(ephKeyPair)) != 1:
                                            raise Exception("EVP_PKEY_keygen failed")

                                        return ephKeyPair

                                    finally:
                                        libcrypto.EVP_PKEY_CTX_free(pctx)

                                finally:
                                    libcrypto.EC_KEY_free(ephemeral_key)

                            finally:
                                libcrypto.EC_POINT_free(newGenerator)

                        finally:
                            libcrypto.EC_POINT_free(sharedSecretMappingPoint)

                    finally:
                        libcrypto.BN_free(cofactor)

                finally:
                    libcrypto.BN_free(order)

            finally:
                libcrypto.EC_GROUP_free(group)

        finally:
            libcrypto.EC_KEY_free(ec_mapping_key)

    finally:
        libcrypto.EVP_PKEY_free(mapping_key_pkey)

def getPublicKeyData(keyPair: c_void_p) -> list[int] | None:
    key_type = libcrypto.EVP_PKEY_get_base_id(keyPair)

    if key_type in (EVP_PKEY_DH, EVP_PKEY_DHX):
        dh = libcrypto.EVP_PKEY_get0_DH(keyPair)
        if not dh:
            return None

        pubkey_bn = c_void_p()
        libcrypto.DH_get0_key(dh, ctypes.byref(pubkey_bn), None)

        num_bits = libcrypto.BN_num_bits(pubkey_bn)
        num_bytes = (num_bits + 7) // 8

        buf = ctypes.create_string_buffer(num_bytes)
        libcrypto.BN_bn2bin(pubkey_bn, buf)

        return list(buf.raw[:num_bytes])

    elif key_type == 408:  # EVP_PKEY_EC, define constant if desired
        ec_key = libcrypto.EVP_PKEY_get0_EC_KEY(keyPair)
        if not ec_key:
            return None

        ec_point = libcrypto.EC_KEY_get0_public_key(ec_key)
        ec_group = libcrypto.EC_KEY_get0_group(ec_key)
        if not ec_point or not ec_group:
            return None

        form = libcrypto.EC_KEY_get_conv_form(ec_key)

        length = libcrypto.EC_POINT_point2oct(ec_group, ec_point, form, None, 0, None)
        if length == 0:
            return None

        buf = ctypes.create_string_buffer(length)
        result = libcrypto.EC_POINT_point2oct(ec_group, ec_point, form, buf, length, None)
        if result != length:
            return None

        return list(buf.raw[:length])

    return None

def decode_public_key_from_bytes(pub_key_data: list[int], params: c_void_p) -> c_void_p | None:
    pub_key_bytes = bytes(pub_key_data)
    key_type = libcrypto.EVP_PKEY_base_id(params)

    if key_type == EVP_PKEY_DH or key_type == EVP_PKEY_DHX:
        dh_key = libcrypto.DH_new()
        try:
            bn = libcrypto.BN_bin2bn(pub_key_bytes, len(pub_key_bytes), None)
            libcrypto.DH_set0_key(dh_key, bn, None)

            pub_key = libcrypto.EVP_PKEY_new()
            if libcrypto.EVP_PKEY_set1_DH(pub_key, dh_key) != 1:
                return None
            return pub_key
        finally:
            libcrypto.DH_free(dh_key)

    else:
        ec = libcrypto.EVP_PKEY_get1_EC_KEY(params)
        if not ec:
            return None

        group = libcrypto.EC_KEY_get0_group(ec)
        ecp = libcrypto.EC_POINT_new(group)
        key = libcrypto.EC_KEY_new()

        try:
            if (libcrypto.EC_POINT_oct2point(group, ecp, pub_key_bytes, len(pub_key_bytes), None) != 1 or
                libcrypto.EC_KEY_set_group(key, group) != 1 or
                libcrypto.EC_KEY_set_public_key(key, ecp) != 1):
                return None

            pub_key = libcrypto.EVP_PKEY_new()
            if libcrypto.EVP_PKEY_set1_EC_KEY(pub_key, key) != 1:
                return None
            return pub_key.value
        finally:
            libcrypto.EC_KEY_free(ec)
            libcrypto.EC_POINT_free(ecp)
            libcrypto.EC_KEY_free(key)
