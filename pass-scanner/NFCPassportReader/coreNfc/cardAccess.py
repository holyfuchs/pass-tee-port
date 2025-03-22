from cryptography.hazmat.primitives.asymmetric import ec
from typing import List, Any, Union, Literal
from ctypes import c_void_p, c_int
import logging
import ctypes
import asn1


libcrypto = ctypes.cdll.LoadLibrary("/opt/homebrew/Cellar/openssl@3/3.4.1/lib/libcrypto.3.dylib")

libcrypto.EVP_PKEY_new.argtypes = []
libcrypto.EVP_PKEY_new.restype = c_void_p
libcrypto.DH_get_1024_160.restype = c_void_p
libcrypto.DH_get_2048_224.restype = c_void_p
libcrypto.DH_get_2048_256.restype = c_void_p
libcrypto.DH_generate_key.argtypes = [c_void_p]
libcrypto.DH_generate_key.restype = c_int
libcrypto.DH_free.argtypes = [c_void_p]
libcrypto.DH_free.restype = None
libcrypto.EVP_PKEY_set1_DH.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_set1_DH.restype = c_int
libcrypto.EC_KEY_new_by_curve_name.argtypes = [c_int]
libcrypto.EC_KEY_new_by_curve_name.restype = c_void_p
libcrypto.EC_KEY_generate_key.argtypes = [c_void_p]
libcrypto.EC_KEY_generate_key.restype = c_int
libcrypto.EC_KEY_free.argtypes = [c_void_p]
libcrypto.EC_KEY_free.restype = None
libcrypto.EVP_PKEY_set1_EC_KEY.argtypes = [c_void_p, c_void_p]
libcrypto.EVP_PKEY_set1_EC_KEY.restype = c_int


NID_X9_62_prime192v1 = 409
NID_secp224r1 = 713
NID_X9_62_prime256v1 = 415
NID_secp384r1 = 715
NID_secp521r1 = 716
NID_brainpoolP192r1 = 923
NID_brainpoolP224r1 = 925
NID_brainpoolP256r1 = 927
NID_brainpoolP320r1 = 929
NID_brainpoolP384r1 = 931
NID_brainpoolP512r1 = 933


class SecurityInfo:
    oid: str = ""
    version: int = -1
    parameterId: Union[int, None] = None

    # Active Authentication OID
    ID_AA_OID = "2.23.136.1.1.5"

    # Active Authentication Signature Algorithm OIDS
    ECDSA_PLAIN_SIGNATURES = "0.4.0.127.0.7.1.1.4.1"
    ECDSA_PLAIN_SHA1_OID = f"{ECDSA_PLAIN_SIGNATURES}.1"        # ecdsa-plain-SHA1
    ECDSA_PLAIN_SHA224_OID = f"{ECDSA_PLAIN_SIGNATURES}.2"      # ecdsa-plain-SHA224
    ECDSA_PLAIN_SHA256_OID = f"{ECDSA_PLAIN_SIGNATURES}.3"      # ecdsa-plain-SHA256
    ECDSA_PLAIN_SHA384_OID = f"{ECDSA_PLAIN_SIGNATURES}.4"      # ecdsa-plain-SHA384
    ECDSA_PLAIN_SHA512_OID = f"{ECDSA_PLAIN_SIGNATURES}.5"      # ecdsa-plain-SHA512
    ECDSA_PLAIN_RIPEMD160_OID = f"{ECDSA_PLAIN_SIGNATURES}.6"   # ecdsa-plain-RIPEMD160

    # Chip Authentication Public Key OIDS
    ID_PK_DH_OID = "0.4.0.127.0.7.2.2.1.1"
    ID_PK_ECDH_OID = "0.4.0.127.0.7.2.2.1.2"

    # Chip Authentication OIDS
    ID_CA_DH_3DES_CBC_CBC_OID = "0.4.0.127.0.7.2.2.3.1.1"
    ID_CA_ECDH_3DES_CBC_CBC_OID = "0.4.0.127.0.7.2.2.3.2.1"
    ID_CA_DH_AES_CBC_CMAC_128_OID = "0.4.0.127.0.7.2.2.3.1.2"
    ID_CA_DH_AES_CBC_CMAC_192_OID = "0.4.0.127.0.7.2.2.3.1.3"
    ID_CA_DH_AES_CBC_CMAC_256_OID = "0.4.0.127.0.7.2.2.3.1.4"
    ID_CA_ECDH_AES_CBC_CMAC_128_OID = "0.4.0.127.0.7.2.2.3.2.2"
    ID_CA_ECDH_AES_CBC_CMAC_192_OID = "0.4.0.127.0.7.2.2.3.2.3"
    ID_CA_ECDH_AES_CBC_CMAC_256_OID = "0.4.0.127.0.7.2.2.3.2.4"

    # PACE OIDS
    ID_BSI = "0.4.0.127.0.7"
    ID_PACE = ID_BSI + ".2.2.4"
    ID_PACE_DH_GM = ID_PACE + ".1"
    ID_PACE_DH_GM_3DES_CBC_CBC = ID_PACE_DH_GM + ".1"       # id-PACE-DH-GM-3DES-CBC-CBC
    ID_PACE_DH_GM_AES_CBC_CMAC_128 = ID_PACE_DH_GM + ".2"   # id-PACE-DH-GM-AES-CBC-CMAC-128
    ID_PACE_DH_GM_AES_CBC_CMAC_192 = ID_PACE_DH_GM + ".3"   # id-PACE-DH-GM-AES-CBC-CMAC-192
    ID_PACE_DH_GM_AES_CBC_CMAC_256 = ID_PACE_DH_GM + ".4"   # id-PACE-DH-GM-AES-CBC-CMAC-256

    ID_PACE_ECDH_GM = ID_PACE + ".2"
    ID_PACE_ECDH_GM_3DES_CBC_CBC = ID_PACE_ECDH_GM + ".1"       # id-PACE-ECDH-GM-3DES-CBC-CBC
    ID_PACE_ECDH_GM_AES_CBC_CMAC_128 = ID_PACE_ECDH_GM + ".2"   # id-PACE-ECDH-GM-AES-CBC-CMAC-128
    ID_PACE_ECDH_GM_AES_CBC_CMAC_192 = ID_PACE_ECDH_GM + ".3"   # id-PACE-ECDH-GM-AES-CBC-CMAC-192
    ID_PACE_ECDH_GM_AES_CBC_CMAC_256 = ID_PACE_ECDH_GM + ".4"   # id-PACE-ECDH-GM-AES-CBC-CMAC-256

    ID_PACE_DH_IM = ID_PACE + ".3"
    ID_PACE_DH_IM_3DES_CBC_CBC = ID_PACE_DH_IM + ".1"       # id-PACE-DH-IM-3DES-CBC-CBC
    ID_PACE_DH_IM_AES_CBC_CMAC_128 = ID_PACE_DH_IM + ".2"   # id-PACE-DH-IM-AES-CBC-CMAC-128
    ID_PACE_DH_IM_AES_CBC_CMAC_192 = ID_PACE_DH_IM + ".3"   # id-PACE-DH-IM-AES-CBC-CMAC-192
    ID_PACE_DH_IM_AES_CBC_CMAC_256 = ID_PACE_DH_IM + ".4"   # id-PACE-DH-IM-AES-CBC-CMAC-256

    ID_PACE_ECDH_IM = ID_PACE + ".4"
    ID_PACE_ECDH_IM_3DES_CBC_CBC = ID_PACE_ECDH_IM + ".1"       # id-PACE-ECDH-IM-3DES-CBC-CBC
    ID_PACE_ECDH_IM_AES_CBC_CMAC_128 = ID_PACE_ECDH_IM + ".2"   # id-PACE-ECDH-IM-AES-CBC-CMAC-128
    ID_PACE_ECDH_IM_AES_CBC_CMAC_192 = ID_PACE_ECDH_IM + ".3"   # id-PACE-ECDH-IM-AES-CBC-CMAC-192
    ID_PACE_ECDH_IM_AES_CBC_CMAC_256 = ID_PACE_ECDH_IM + ".4"   # id-PACE-ECDH-IM-AES-CBC-CMAC-256

    ID_PACE_ECDH_CAM = ID_PACE + ".6"
    ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 = ID_PACE_ECDH_CAM + ".2" # id-PACE-ECDH-CAM-AES-CBC-CMAC-128
    ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 = ID_PACE_ECDH_CAM + ".3" # id-PACE-ECDH-CAM-AES-CBC-CMAC-192
    ID_PACE_ECDH_CAM_AES_CBC_CMAC_256 = ID_PACE_ECDH_CAM + ".4" # id-PACE-ECDH-CAM-AES-CBC-CMAC-256

    def __init__(self, securityInfoASN1: List[Union[str, int]]):
        # Read Data from ASN1
        oid = securityInfoASN1[0]
        requiredData = securityInfoASN1[1]
        optionalData = None
        if len(securityInfoASN1) > 2:
            optionalData = securityInfoASN1[2]
        logging.debug(f"OID: {oid}, Required Data: {requiredData}, Optional Data: {optionalData}")

        # ----------------- Check if ChipAuthenticationPublicKeyInfo ----------------- #
        if (
            oid == self.ID_PK_DH_OID or
            oid == self.ID_PK_ECDH_OID
        ):
            raise NotImplementedError("ChipAuthenticationPublicKey not implemented")

        # ---------------------- Check if ChipAuthenticationInfo --------------------- #
        elif (
            oid == self.ID_CA_DH_3DES_CBC_CBC_OID or
            oid == self.ID_CA_ECDH_3DES_CBC_CBC_OID or
            oid == self.ID_CA_DH_AES_CBC_CMAC_128_OID or
            oid == self.ID_CA_DH_AES_CBC_CMAC_192_OID or
            oid == self.ID_CA_DH_AES_CBC_CMAC_256_OID or
            oid == self.ID_CA_ECDH_AES_CBC_CMAC_128_OID or
            oid == self.ID_CA_ECDH_AES_CBC_CMAC_192_OID or
            oid == self.ID_CA_ECDH_AES_CBC_CMAC_256_OID
        ):
            raise NotImplementedError("ChipAuthentication not implemented")

        # ----------------------------- Check if PACEInfo ---------------------------- #
        elif (
            oid == self.ID_PACE_DH_GM_3DES_CBC_CBC or
            oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_128 or
            oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_192 or
            oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_256 or
            oid == self.ID_PACE_DH_IM_3DES_CBC_CBC or
            oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_128 or
            oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_192 or
            oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_256 or
            oid == self.ID_PACE_ECDH_GM_3DES_CBC_CBC or
            oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 or
            oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 or
            oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_256 or
            oid == self.ID_PACE_ECDH_IM_3DES_CBC_CBC or
            oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 or
            oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 or
            oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_256 or
            oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 or
            oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 or
            oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256
        ):
            self.oid = oid
            self.version = requiredData
            
            self.parameterId = None
            if optionalData is not None:
                self.parameterId = optionalData

        # --------------------- Check if ActiveAuthenticationInfo -------------------- #
        elif ( oid == self.ID_AA_OID):
            raise NotImplementedError("ActiveAuthentication not implemented")


    # Helpers
    def getParameterSpec(self) -> Union[int, ec.EllipticCurve]:
        # PARAM_ID_GFP_1024_160
        if self.parameterId == 0:
            return 0 # rfc5114_1024_160
        # PARAM_ID_GFP_2048_224
        elif self.parameterId == 1:
            return 1 # rfc5114_2048_224
        # PARAM_ID_GFP_2048_256
        elif self.parameterId == 2:
            return 2 # rfc5114_2048_256
        # PARAM_ID_ECP_NIST_P192_R1
        elif self.parameterId == 8:
            return NID_X9_62_prime192v1 # secp192r1
        # PARAM_ID_ECP_NIST_P224_R1
        elif self.parameterId == 10:
            return NID_secp224r1 # secp224r1
        # PARAM_ID_ECP_NIST_P256_R1
        elif self.parameterId == 12:
            return NID_X9_62_prime256v1 # secp256r1
        # PARAM_ID_ECP_NIST_P384_R1
        elif self.parameterId == 15:
            return NID_secp384r1 # secp384r1
        # PARAM_ID_ECP_BRAINPOOL_P192_R1
        elif self.parameterId == 9:
            return NID_brainpoolP192r1 # brainpoolp192r1
        # PARAM_ID_ECP_BRAINPOOL_P224_R1
        elif self.parameterId == 11:
            return NID_brainpoolP224r1 # brainpoolp224r1
        # PARAM_ID_ECP_BRAINPOOL_P256_R1
        elif self.parameterId == 13:
            return NID_brainpoolP256r1 # brainpoolp256r1
        # PARAM_ID_ECP_BRAINPOOL_P320_R1
        elif self.parameterId == 14:
            return NID_brainpoolP320r1 # brainpoolp320r1
        # PARAM_ID_ECP_BRAINPOOL_P384_R1
        elif self.parameterId == 16:
            return NID_brainpoolP384r1 # brainpoolp384r1
        # PARAM_ID_ECP_BRAINPOOL_P512_R1
        elif self.parameterId == 17:
            return NID_brainpoolP512r1 # brainpoolp512r1
        # PARAM_ID_ECP_NIST_P521_R1
        elif self.parameterId == 18:
            return NID_secp521r1 # secp521r1
        else:
            raise ValueError(f"Unable to find parameter spec for parameter ID: {self.parameterId}")
        
    def getMappingType(self) -> Literal["GM", "IM", "CAM"]:
        if (
            self.oid == self.ID_PACE_DH_GM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_GM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_256
        ):
            return "GM"
        elif (
            self.oid == self.ID_PACE_DH_IM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_IM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_256
        ):
            return "IM"
        elif (
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256
        ):
            return "CAM"
        else:
            raise ValueError(f"Unable to find mapping type for OID: {self.oid}")

    def getKeyAgreementAlgorithm(self) -> Literal["DH", "ECDH"]:
        if (
            self.oid == self.ID_PACE_DH_GM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_DH_IM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_256
        ):
            return "DH"
        elif (
            self.oid == self.ID_PACE_ECDH_GM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_IM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256
        ):
            return "ECDH"
        else:
            raise ValueError(f"Unable to find key agreement algorithm for OID: {self.oid}")
        
    def getCipherAlgorithm(self) -> Literal["3DES", "AES"]:
        if (
            self.oid == self.ID_PACE_DH_GM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_DH_IM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_ECDH_GM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_ECDH_IM_3DES_CBC_CBC
        ):
            return "3DES"
        elif (
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256
        ):
            return "AES"
        else:
            raise ValueError(f"Unable to find cipher algorithm for OID: {self.oid}")

    def getDigestAlgorithm(self) -> Literal["SHA-1", "SHA-256"]:
        if (
            self.oid == self.ID_PACE_DH_GM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_DH_IM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_ECDH_GM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_ECDH_IM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128
        ):
            return "SHA-1"
        elif (
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256
        ):
            return "SHA-256"
        else:
            raise ValueError(f"Unable to find digest algorithm for OID: {self.oid}")

    def getKeyLength(self) -> Literal[128, 192, 256]:
        if (
            self.oid == self.ID_PACE_DH_GM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_DH_IM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_ECDH_GM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_ECDH_IM_3DES_CBC_CBC or
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_128 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_128
        ):
            return 128
        elif (
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_192 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_192
        ):
            return 192
        elif (
            self.oid == self.ID_PACE_DH_GM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_DH_IM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_GM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_IM_AES_CBC_CMAC_256 or
            self.oid == self.ID_PACE_ECDH_CAM_AES_CBC_CMAC_256
        ):
            return 256
        else:
            raise ValueError(f"Unable to find key length for OID: {self.oid}")
        
    def createMappingKey(self) -> c_void_p:
        algorithm = self.getKeyAgreementAlgorithm()
        param_spec = self.getParameterSpec()

        mapping_key = libcrypto.EVP_PKEY_new()
        if not mapping_key:
            raise Exception("Unable to create EVP_PKEY")

        if algorithm == "DH":
            # RFC5114 named groups: 0 → 1024_160, 1 → 2048_224, 2 → 2048_256
            if param_spec == 0:
                dh = libcrypto.DH_get_1024_160()
            elif param_spec == 1:
                dh = libcrypto.DH_get_2048_224()
            elif param_spec == 2:
                dh = libcrypto.DH_get_2048_256()
            else:
                raise ValueError("Invalid DH parameter spec")

            if not dh:
                raise Exception("Unable to get DH parameters")

            # generate key pair
            if libcrypto.DH_generate_key(dh) != 1:
                libcrypto.DH_free(dh)
                raise Exception("DH_generate_key failed")

            if libcrypto.EVP_PKEY_set1_DH(mapping_key, dh) != 1:
                libcrypto.DH_free(dh)
                raise Exception("EVP_PKEY_set1_DH failed")

            libcrypto.DH_free(dh)

        elif algorithm == "ECDH":
            # param_spec is expected to be the NID of the curve (e.g., NID_X9_62_prime256v1)
            ec_key = libcrypto.EC_KEY_new_by_curve_name(param_spec)
            if not ec_key:
                raise Exception("Unable to create EC_KEY")

            if libcrypto.EC_KEY_generate_key(ec_key) != 1:
                libcrypto.EC_KEY_free(ec_key)
                raise Exception("EC_KEY_generate_key failed")

            if libcrypto.EVP_PKEY_set1_EC_KEY(mapping_key, ec_key) != 1:
                libcrypto.EC_KEY_free(ec_key)
                raise Exception("EVP_PKEY_set1_EC_KEY failed")

            libcrypto.EC_KEY_free(ec_key)

        else:
            libcrypto.EVP_PKEY_free(mapping_key)
            raise ValueError("Unsupported agreement algorithm")

        return mapping_key


# SecurityInfos ::= SET of SecurityInfo
# SecurityInfo ::= SEQUENCE {
#     protocol OBJECT IDENTIFIER,
#     requiredData ANY DEFINED BY protocol,
#     optionalData ANY DEFINED BY protocol OPTIONAL
# }
class CardAccess:
    asn1Data: List[Any] = []
    securityInfos: List[SecurityInfo] = []

    def __init__(self, data: List[int]):
        decoder = asn1.Decoder()
        decoder.start(bytes(data))
        _, self.asn1Data = decoder.read()

        for securityInfo in self.asn1Data:
            self.securityInfos.append(SecurityInfo(securityInfo))
