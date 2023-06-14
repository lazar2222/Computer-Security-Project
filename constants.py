from enum import IntEnum

RSA_EXPONENT = 65537
MODULUS_64BIT = 2**64
PRIVATE_KEY_RING = 'private.kr'
PUBLIC_KEY_RING = 'public.kr'

class AlgorithmSet (IntEnum):
    NONE = 0
    RSA = 1
    DSA_ELGAMAL = 2
    AES128 = 3
    IDEA = 4
    
class KeySize (IntEnum):
    KS_NA = 0
    KS_1024 = 1024
    KS_2048 = 2048