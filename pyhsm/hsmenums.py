#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#
# hsmenums.py
# author: Benton Stark (bestark@cisco.com)
# date: 11-14-2014

from enum import Enum


# entries map to CKK_
class HsmAsymKeyType(Enum):
    RSA = 0x00000000
    # RSA
    DSA = 0x00000001
    # Digital Signature Algorithm
    DH = 0x00000002
    # Diffie-Hellman.
    EC = 0x00000003
    # Elliptic Curve 
    KEA = 0x00000005
    # Key Exchange Algorithm.  A variation on Diffie-Hellman; proposed as the key exchange method for Capstone
    GENERIC_SECRET = 0x00000010
    # Generic Secret - Algorithm undefined


# entries map to CKK_
class HsmSymKeyType(Enum):
    GENERIC_SECRET = 0x00000010
    # Generic Secret - Algorithm undefined
    RC2 = 0x00000011
    # RC2. A 64-bit block cipher using variable-sized keys designed to replace DES. It's code has not been made public
    # although many companies have licensed RC2 for use in their products
    RC4 = 0x00000012
    # RC4.  A stream cipher using variable-sized keys; it is widely used in commercial cryptography products, although
    # it can only be exported using keys that are 40 bits or less in length.
    DES = 0x00000013
    # Data Encryption Standard 2 (DES2).
    DES2 = 0x00000014
    # Triple-DES variant that employs two 56-bit keys in AB form and ABA in function with three encryption/decryption
    # passes over the block; 3DES is also described in  FIPS 46-3 and is the recommended replacement to DES.
    DES3 = 0x00000015
    # Triple-DES variant that employs three 56-bit keys in ABC form and ABC in function with three encryption/decryption
    # passes over the block; 3DES is also described in  FIPS 46-3 and is the recommended replacement to DES.
    RC5 = 0x00000019
    # RC5. A block-cipher supporting a variety of block sizes, key sizes, and number of encryption passes over the data.
    # Described in RFC 2040.
    IDEA = 0x0000001A
    # International Data Encryption Algorithm (IDEA) is a block cipher designed by Xuejia Lai and James Massey of
    # ETH Zurich and was first described in 1991. The algorithm was intended as a replacement for the Data Encryption
    # Standard.
    SKIPJACK = 0x0000001B
    # SKC scheme proposed for Capstone. Although the details of the algorithm were never made public, Skipjack was a
    # block cipher using an 80-bit key and 32 iteration cycles per 64-bit block.
    BATON = 0x0000001C
    # BATON is a Type 1 block cipher, used by the United States government to secure all types of classified
    # information.  BATON has a 128-bit block size and a 320-bit key. 160 bits of the key are checksum material;
    # they do not affect the security of the algorithm itself but rather prevent unauthorized keys from being loaded
    # if a BATON device ends up in the hands of an adversary.
    JUNIPER = 0x0000001D
    # Juniper block cipher.
    CDMF = 0x0000001E
    # CDMF (Commercial Data Masking Facility) is an algorithm developed at IBM in 1992 to reduce the security strength
    # of the DES cipher to that of 40-bit encryption, at the time a requirement of U.S. restrictions on export of
    # cryptography. Rather than a separate cipher from DES, CDMF constitutes a key generation algorithm, called key
    # shortening. It is one of the cryptographic algorithms supported by S-HTTP.
    AES = 0x0000001F
    # Advanced Encryption Standard (AES).  In 1997, NIST initiated a very public, 4-1/2 year process to develop a new
    # secure cryptosystem for U.S. government applications. The result, the Advanced Encryption Standard, became the
    # official successor to DES in December 2001.
    CAST = 0x00000016
    # CAST
    CAST3 = 0x00000017
    # CAST3
    CAST5 = 0x00000018
    # CAST-128 (alternatively CAST5) is a block cipher used in a number of products, notably as the default cipher
    # in some versions of GPG and PGP. It has also been approved for Canadian government use by the Communications
    # Security Establishment.


# entries map to CKK_
class HsmSymKeyGen(Enum):
    AES = 0x00001080
    # Advanced Encryption Standard.
    DES = 0x00000120
    # Data Encryption Standard (DES).  The most common SKC scheme used today, DES was designed by IBM in the 1970s and
    # adopted by the National Bureau of Standards (NBS) [now the National Institute for Standards and Technology
    # (NIST)] in 1977 for commercial and unclassified government applications. DES is a block-cipher employing a
    # 56-bit key that operates on 64-bit blocks. DES has a complex set of rules and transformations that were designed
    # specifically to yield fast hardware implementations and slow software implementations, although this latter point
    # is becoming less significant today since the speed of computer processors is several orders of magnitude faster
    # today than twenty years ago. IBM also proposed a 112-bit key for DES, which was rejected at the time by the
    # government; the use of 112-bit keys was considered in the 1990s, however, conversion was never seriously
    # considered.
    DES2 = 0x00000130
    # Data Encryption Standard 2 (DES2).    
    DES3 = 0x00000131
    # DES3.  A variant of DES that employs up to three 56-bit keys and makes three encryption/decryption passes over
    # the block; 3DES is also described in  FIPS 46-3 and is the recommended replacement to DES.
    RC2 = 0x00000100
    # RC2. A 64-bit block cipher using variable-sized keys designed to replace DES. It's code has not been made public
    # although many companies have licensed RC2 for use in their products
    RC4 = 0x00000110
    # RC4.  A stream cipher using variable-sized keys; it is widely used in commercial cryptography products, although
    # it can only be exported using keys that are 40 bits or less in length.
    RC5 = 0x00000330
    # RC5. A block-cipher supporting a variety of block sizes, key sizes, and number of encryption passes over the data.
    # Described in RFC 2040.
    CAST = 0x00000300
    # CAST.
    CAST3 = 0x00000310
    # CAST 3.
    IDEA = 0x00000340
    # International Data Encryption Algorithm (IDEA) is a block cipher designed by Xuejia Lai and James Massey of ETH
    # Zurich and was first described in 1991. The algorithm was intended as a replacement for the Data Encryption
    # Standard.
    Baton = 0x00001030
    # BATON is a Type 1 block cipher, used by the United States government to secure all types of classified
    # information.  BATON has a 128-bit block size and a 320-bit key. 160 bits of the key are checksum material; they
    # do not affect the security of the algorithm itself but rather prevent unauthorized keys from being loaded if a
    # BATON device ends up in the hands of an adversary.
    Juniper = 0x00001060
    # Juniper block cipher.


class HsmUser(Enum):
    SecurityOfficer = 0
    CryptoOfficer = 1


class HsmSession(Enum):
    Undefined = 0x0000
    # No flag options.
    Exclusive = 0x0001
    # Exclusive session.  Only one open session is allowed.
    ReadWrite = 0x0002
    # Read write session which allows changes to be performed.
    SecurityOfficer = 0x8000
    # Security Officer specific session.  Vendor proprietary option.  
    SecurityOfficerExclusive = 0x8001
    # Security officer exclusive.  Vendor proprietary option.
    SecurityOfficerReadWrite = 0x8002
    # Security officer read write option. Vendor proprietary option.


# entries map to CKK_
class HsmKeyType(Enum):
    RSA = 0x00000000
    # RSA.
    DSA = 0x00000001
    # Digital Signature Algorithm
    DH = 0x00000002
    # Diffie-Hellman.
    EC = 0x00000003
    # Elliptic Curve 
    KEA = 0x00000005
    # Key Exchange Algorithm.  A variation on Diffie-Hellman; proposed as the key exchange method for Capstone
    GENERIC_SECRET = 0x00000010
    # Generic Secret - Algorithm undefined
    RC2 = 0x00000011
    # RC2. A 64-bit block cipher using variable-sized keys designed to replace DES. It's code has not been made public
    # although many companies have licensed RC2 for use in their products
    RC4 = 0x00000012
    # RC4.  A stream cipher using variable-sized keys; it is widely used in commercial cryptography products, although
    # it can only be exported using keys that are 40 bits or less in length.
    DES = 0x00000013
    # Data Encryption Standard (DES).  The most common SKC scheme used today, DES was designed by IBM in the 1970s and
    # adopted by the National Bureau of Standards (NBS) [now the National Institute for Standards and Technology
    # (NIST)] in 1977 for commercial and unclassified government applications. DES is a block-cipher employing a 56-bit
    # key that operates on 64-bit blocks. DES has a complex set of rules and transformations that were designed
    # specifically to yield fast hardware implementations and slow software implementations, although this latter point
    #  is becoming less significant today since the speed of computer processors is several orders of magnitude faster
    # today than twenty years ago. IBM also proposed a 112-bit key for DES, which was rejected at the time by the
    # government; the use of 112-bit keys was considered in the 1990s, however, conversion was never seriously
    # considered.
    DES2 = 0x00000014
    # Data Encryption Standard 2 (DES2).
    DES3 = 0x00000015
    # DES3.  A variant of DES that employs up to three 56-bit keys and makes three encryption/decryption passes over
    # the block; 3DES is also described in  FIPS 46-3 and is the recommended replacement to DES.
    RC5 = 0x00000019
    # RC5. A block-cipher supporting a variety of block sizes, key sizes, and number of encryption passes over the
    # data. Described in RFC 2040.
    IDEA = 0x0000001A
    # International Data Encryption Algorithm (IDEA) is a block cipher designed by Xuejia Lai and James Massey of ETH
    # Zurich and was first described in 1991. The algorithm was intended as a replacement for the Data Encryption
    # Standard.
    SKIPJACK = 0x0000001B
    # SKC scheme proposed for Capstone. Although the details of the algorithm were never made public, Skipjack was a
    # block cipher using an 80-bit key and 32 iteration cycles per 64-bit block.
    BATON = 0x0000001C
    # BATON is a Type 1 block cipher, used by the United States government to secure all types of classified
    # information.  BATON has a 128-bit block size and a 320-bit key. 160 bits of the key are checksum material;
    # they do not affect the security of the algorithm itself but rather prevent unauthorized keys from being loaded
    # if a BATON device ends up in the hands of an adversary.
    JUNIPER = 0x0000001D
    # Juniper block cipher.
    CDMF = 0x0000001E
    # CDMF (Commercial Data Masking Facility) is an algorithm developed at IBM in 1992 to reduce the security strength
    # of the DES cipher to that of 40-bit encryption, at the time a requirement of U.S. restrictions on export of
    # cryptography. Rather than a separate cipher from DES, CDMF constitutes a key generation algorithm, called key
    # shortening. It is one of the cryptographic algorithms supported by S-HTTP.
    AES = 0x0000001F
    # Advanced Encryption Standard (AES).  In 1997, NIST initiated a very public, 4-1/2 year process to develop a new
    # secure cryptosystem for U.S. government applications. The result, the Advanced Encryption Standard, became the
    # official successor to DES in December 2001.
    CAST = 0x00000016
    # CAST.
    CAST3 = 0x00000017
    # CAST3.
    CAST5 = 0x00000018
    # CAST-128 (alternatively CAST5) is a block cipher used in a number of products, notably as the default cipher in
    # some versions of GPG and PGP. It has also been approved for Canadian government use by the Communications
    # Security Establishment.


# entries map to CKM_
class HsmMech(Enum):
    RSA_PKCS_KEY_PAIR_GEN = 0x00000000
    # RSA PKCS Key Pair Generation.
    RSA_X9_31_KEY_PAIR_GEN = 0x0000000A
    # RSA X9_31 Key Pair Generation.
    RSA_PKCS = 0x00000001
    # RSA PKCS.
    RSA_9796 = 0x00000002
    # RSA 9796.
    RSA_X_509 = 0x00000003
    # RSA X.509.
    MD2_RSA_PKCS = 0x00000004
    # MD2 Hash with RSA PKCS.
    MD5_RSA_PKCS = 0x00000005
    # MD5 Hash with RSA PKCS.
    SHA1_RSA_PKCS = 0x00000006
    # SHA1 Hash with RSA PKCS.
    RSA_PKCS_OAEP = 0x00000009
    # RSA PKCS OAEP.  Used to encrypt/decrypt or wrap/unwrap a symmetric key using a RSA key.
    SHA1_RSA_X9_31 = 0x0000000C
    # SHA1 Hash with RSA X9.31
    SHA1_RSA_PKCS_PSS = 0x0000000E
    # SHA1 RSA PKCS PSS.
    DSA_KEY_PAIR_GEN = 0x00000010
    # DSA Key Pair Generation.
    DSA = 0x00000011
    # DSA.
    DSA_SHA1 = 0x00000012
    # DSA with SHA1 Hash.
    DH_PKCS_KEY_PAIR_GEN = 0x00000020
    # DH PCKS Key Pair Generation.
    DH_PKCS_DERIVE = 0x00000021
    # DH PKCS Derive.
    SHA256_RSA_PKCS = 0x00000040
    # SHA256 Hash with RSA PKCS.
    SHA384_RSA_PKCS = 0x00000041
    # SHA384 Hash with RSA PKCS.
    SHA512_RSA_PKCS = 0x00000042
    # SHA512 Hash with RSA PKCS.
    RC2_KEY_GEN = 0x00000100
    # RC2 Key Generation.
    RC2_ECB = 0x00000101
    # RC2 ECB Mode.
    RC2_CBC = 0x00000102
    # RC2 CBC Mode.
    RC2_MAC = 0x00000103
    # RC2 MAC.
    RC2_MAC_GENERAL = 0x00000104
    # RC2 MAC General.
    RC2_CBC_PAD = 0x00000105
    # RC2 CBC with Padding.
    RC4_KEY_GEN = 0x00000110
    # RC4 Key Generation.
    RC4 = 0x00000111
    # RC4.
    DES_KEY_GEN = 0x00000120
    # DES Key Generation.
    DES_ECB = 0x00000121
    # DES ECB Mode.
    DES_CBC = 0x00000122
    # DES CBC Mode.
    DES_MAC = 0x00000123
    # DES MAC.
    DES_MAC_GENERAL = 0x00000124
    # DES MAC General.
    DES_CBC_PAD = 0x00000125
    # DES CBC with Padding.
    DES2_KEY_GEN = 0x00000130
    # DES2 Key Generation.
    DES3_KEY_GEN = 0x00000131
    # DES3 Key Generation.
    DES3_ECB = 0x00000132
    # DES3 ECB Mode.
    DES3_CBC = 0x00000133
    # DES3 CBC Mode.
    DES3_MAC = 0x00000134
    # DES3 MAC.
    DES3_MAC_GENERAL = 0x00000135
    # DES3 MAC General.
    DES3_CBC_PAD = 0x00000136
    # DES3 CBC Mode with Padding.
    CDMF_KEY_GEN = 0x00000140
    # CDMF Key Generation.
    CDMF_ECB = 0x00000141
    # CDMF ECB Mode.
    CDMF_CBC = 0x00000142
    # CDMF CBC Mode.
    CDMF_MAC = 0x00000143
    # CDMF MAC.
    CDMF_MAC_GENERAL = 0x00000144
    # CDMF MAC General.
    CDMF_CBC_PAD = 0x00000145
    # CDMF CDC Mode with Padding.
    MD2 = 0x00000200
    # MD2.
    MD2_HMAC = 0x00000201
    # MD2 HMAC.
    MD2_HMAC_GENERAL = 0x00000202
    # MD2 HMAC General.
    MD5 = 0x00000210
    # MD5.
    MD5_HMAC = 0x00000211
    # MD5 HMAC.
    MD5_HMAC_GENERAL = 0x00000212
    # MD5 HMAC General.
    SHA_1 = 0x00000220
    # SHA1.
    SHA_1_HMAC = 0x00000221
    # SHA1 HMAC.
    SHA_1_HMAC_GENERAL = 0x00000222
    # SHA1 HMAC General.
    SHA256 = 0x00000250
    # SHA256.
    SHA256_HMAC = 0x00000251
    # SHA256 HMAC.
    SHA256_HMAC_GENERAL = 0x00000252
    # SHA256 HMAC General.
    SHA384 = 0x00000260
    # SHA 384.
    SHA384_HMAC = 0x00000261
    # SHA 384 HMAC.
    SHA384_HMAC_GENERAL = 0x00000262
    # SHA 284 HMAC General.
    SHA512 = 0x00000270
    # SHA 512.
    SHA512_HMAC = 0x00000271
    # SHA 512 HMAC.
    SHA512_HMAC_GENERAL = 0x00000272
    # SHA 512 HMAC General.
    CAST_KEY_GEN = 0x00000300
    # Cast Key Generation.
    CAST_ECB = 0x00000301
    # Cast ECB Mode.
    CAST_CBC = 0x00000302
    # Cast CBC Mode.
    CAST_MAC = 0x00000303
    # Cast MAC.
    CAST_MAC_GENERAL = 0x00000304
    # Cast MAC General.
    CAST_CBC_PAD = 0x00000305
    # Cast CBC with Padding.
    CAST3_KEY_GEN = 0x00000310
    # Cast3 Key Generation.
    CAST3_ECB = 0x00000311
    # Cast3 ECB Mode.
    CAST3_CBC = 0x00000312
    # Cast3 CBC Mode.
    CAST3_MAC = 0x00000313
    # Cast3 MAC.
    CAST3_MAC_GENERAL = 0x00000314
    # Cast3 MAC General.
    CAST3_CBC_PAD = 0x00000315
    # Cast3 CBC with Padding.
    CAST5_KEY_GEN = 0x00000320
    # Cast5 Key Generation.
    CAST128_KEY_GEN = 0x00000320
    # Cast128 Key Generation.
    CAST5_ECB = 0x00000321
    # Cast5 ECB Mode.
    CAST128_ECB = 0x00000321
    # Cast128 ECB Mode.
    CAST5_CBC = 0x00000322
    # Cast5 CBC Mode.
    CAST128_CBC = 0x00000322
    # Cast128 CBC Mode.
    CAST5_MAC = 0x00000323
    # Cast5 MAC.
    CAST128_MAC = 0x00000323
    # Cast128 MAC.
    CAST5_MAC_GENERAL = 0x00000324
    # Cast5 Mac General.
    CAST128_MAC_GENERAL = 0x00000324
    # Cast128 MAC General.
    CAST5_CBC_PAD = 0x00000325
    # Cast5 CBC with Padding.
    CAST128_CBC_PAD = 0x00000325
    # Cast128 CBC with Padding.
    RC5_KEY_GEN = 0x00000330
    # RC5 Key Generation.
    RC5_ECB = 0x00000331
    # RC5 ECB Mode.
    RC5_CBC = 0x00000332
    # RC5 CBC Mode.
    RC5_MAC = 0x00000333
    # RC5 MAC.    
    RC5_MAC_GENERAL = 0x00000334
    # RC5 MAC General.    
    RC5_CBC_PAD = 0x00000335
    # RC5 CBC with Padding.    
    IDEA_KEY_GEN = 0x00000340
    # IDEA Key Generation.
    IDEA_ECB = 0x00000341
    # IDEA ECB Mode.
    IDEA_CBC = 0x00000342
    # IDEA CBC Mode.
    IDEA_MAC = 0x00000343
    # IDEA MAC.
    IDEA_MAC_GENERAL = 0x00000344
    # IDEA MAC General.
    IDEA_CBC_PAD = 0x00000345
    # IDEA CBC with Padding.
    GENERIC_SECRET_KEY_GEN = 0x00000350
    # Generic Secret Key Generation.
    CONCATENATE_BASE_AND_KEY = 0x00000360
    # Concatengate Base and Key.
    CONCATENATE_BASE_AND_DATA = 0x00000362
    # Concatengate Base and Data.
    CONCATENATE_DATA_AND_BASE = 0x00000363
    # Concatengate Data and Base.
    XOR_BASE_AND_DATA = 0x00000364
    # XOR Base and Data.
    EXTRACT_KEY_FROM_KEY = 0x00000365
    # Extract Key from Key.
    SSL3_PRE_MASTER_KEY_GEN = 0x00000370
    # SSL version 3 Pre Master Key Generation.
    SSL3_MASTER_KEY_DERIVE = 0x00000371
    # SSL version 3 Master Key Derive.
    SSL3_KEY_AND_MAC_DERIVE = 0x00000372
    # SSL version 3 Key and MAC Derive.
    SSL3_MD5_MAC = 0x00000380
    # SSL version 3 MD5 MAC.
    SSL3_SHA1_MAC = 0x00000381
    # SSL version 3 SHA1 MAC.
    MD5_KEY_DERIVATION = 0x00000390
    # MD5 Key Derivation.
    MD2_KEY_DERIVATION = 0x00000391
    # MD2 Key Derivation.
    SHA1_KEY_DERIVATION = 0x00000392
    # SHA1 Key Derivation.
    SHA256_KEY_DERIVATION = 0x00000393
    # SHA256 Key Derivation.
    SHA384_KEY_DERIVATION = 0x00000394
    # SHA384 Key Derivation.
    SHA512_KEY_DERIVATION = 0x00000395
    # SHA512 Key Derivation.
    PBE_MD2_DES_CBC = 0x000003A0
    # PBE MD2 DES with CBC.
    PBE_MD5_DES_CBC = 0x000003A1
    # PBE MD5 DES with CBC.
    PBE_MD5_CAST_CBC = 0x000003A2
    # PBE MD5 CAST with CBC.
    PBE_MD5_CAST3_CBC = 0x000003A3
    # PBE MD5 CAST3 with CBC.
    PBE_MD5_CAST5_CBC = 0x000003A4
    # PBE MD5 CAST5 with CBC.
    PBE_MD5_CAST128_CBC = 0x000003A4
    # PBE MD5 CAST128 with CBC.
    PBE_SHA1_CAST5_CBC = 0x000003A5
    # PBE SHA1 CAST5 with CBC.
    PBE_SHA1_CAST128_CBC = 0x000003A5
    # PBE SHA1 CAST128 with CBC.
    PBE_SHA1_RC4_128 = 0x000003A6
    # PBE SHA1 RC4 128 bit.
    PBE_SHA1_RC4_40 = 0x000003A7
    # PBE SHA1 RC4 40 bit.
    PBE_SHA1_DES3_EDE_CBC = 0x000003A8
    # PBE SHA1 DES3 EDE CBC.
    PBE_SHA1_DES2_EDE_CBC = 0x000003A9
    # PBE SHA1 DES2 EDE CBC.
    PBE_SHA1_RC2_128_CBC = 0x000003AA
    # PBE SHA1 RC2 128 bit with CBC.
    PBE_SHA1_RC2_40_CBC = 0x000003AB
    # PBE SHA1 RC2 40 bit with CBC.
    KEY_WRAP_LYNKS = 0x00000400
    # Key Wrap Lynks.
    KEY_WRAP_SET_OAEP = 0x00000401
    # Key Wrap Set OAEP.
    SKIPJACK_KEY_GEN = 0x00001000
    # Skipjack Key Generation.
    SKIPJACK_ECB64 = 0x00001001
    # Skipjack ECB64.
    SKIPJACK_CBC64 = 0x00001002
    # Skipjack CBC64.
    SKIPJACK_OFB64 = 0x00001003
    # Skipjack OFB64.
    SKIPJACK_CFB64 = 0x00001004
    # Skipjack CFB64.
    SKIPJACK_CFB32 = 0x00001005
    # Skipjack CFB32.
    SKIPJACK_CFB16 = 0x00001006
    # Skipjack CFB16.
    SKIPJACK_CFB8 = 0x00001007
    # Skipjack CFB8.
    SKIPJACK_WRAP = 0x00001008
    # Skipjack Wrap.
    SKIPJACK_PRIVATE_WRAP = 0x00001009
    # Skipjack Private Wrap.
    SKIPJACK_RELAYX = 0x0000100a
    # Skipjack Relayx.
    KEA_KEY_PAIR_GEN = 0x00001010
    # Kea Key Pair Generation.
    KEA_KEY_DERIVE = 0x00001011
    # Kea Key Derive.
    FORTEZZA_TIMESTAMP = 0x00001020
    # Fortezza Time Stamp.
    BATON_KEY_GEN = 0x00001030
    # Baton Key Generation.
    BATON_ECB128 = 0x00001031
    # Baton ECB 128 bit.
    BATON_ECB96 = 0x00001032
    # Baton ECB 96 bit.
    BATON_CBC128 = 0x00001033
    # Baton CBC 128 bit.
    BATON_COUNTER = 0x00001034
    # Baton Counter.
    BATON_SHUFFLE = 0x00001035
    # Baton Shuffle.
    BATON_WRAP = 0x00001036
    # Baton Wrap.
    ECDSA_KEY_PAIR_GEN = 0x00001040
    # ECDSA Key Pair Generation.
    EC_KEY_PAIR_GEN = 0x00001040
    # Eliptical Curve Key Pair Generation.
    ECDSA = 0x00001041
    # ECDSA.    
    ECDSA_SHA1 = 0x00001042
    # ECDSA SHA1.
    ECDSA_SHA224 = 0x00001043
    # ECDSA SHA224.
    ECDSA_SHA256 = 0x00001044
    # ECDSA SHA256.
    ECDSA_SHA384 = 0x00001045
    # ECDSA SHA384.
    ECDSA_SHA512 = 0x00001046
    # ECDSA SHA512
    ECDH1_DERIVE = 0x00001050
    # ECDH1 Derive.
    ECDH1_COFACTOR_DERIVE = 0x00001051
    # ECDH1 Cofactor Derive.    
    ECMQV_DERIVE = 0x00001052
    # ECMQV Derive.
    JUNIPER_KEY_GEN = 0x00001060
    # Juniper Key Generation.
    JUNIPER_ECB128 = 0x00001061
    # Juniper ECB 128 bit.
    JUNIPER_CBC128 = 0x00001062
    # Juniper CBC 128 bit.
    JUNIPER_COUNTER = 0x00001063
    # Juniper Counter.
    JUNIPER_SHUFFLE = 0x00001064
    # Juniper Shuffle.
    JUNIPER_WRAP = 0x00001065
    # Juniper Wrap.
    FASTHASH = 0x00001070
    # Fast Hash.
    AES_KEY_GEN = 0x00001080
    # AES Key Generation.
    AES_ECB = 0x00001081
    # AES ECB Mode.
    AES_CBC = 0x00001082
    # AES CBC Mode.
    AES_MAC = 0x00001083
    # AES MAC.
    AES_MAC_GENERAL = 0x00001084
    # AES MAC General.
    AES_CBC_PAD = 0x00001085
    # AES CBC with Padding.
    AES_CMAC = 0x0000108A
    # AES CMAC signing algorithm.
    AES_OFB = 0x00002104
    # AES OFB mode.
    AES_CFB64 = 0x00002105
    # AES CFB-64 mode.
    AES_CFB8 = 0x00002106
    # AES CFB-8 mode.
    AES_CFB128 = 0x00002107
    # AES CFB-128 mode.
    CA_LUNA_ECDSA_SHA224 = 0x80000122
    # ECDSA SHA-224.  SafeNet / Gemalto Luna HSM vendor specific.
    CA_LUNA_ECDSA_SHA256 = 0x80000123
    # ECDSA SHA-256.  SafeNet / Gemalto Luna HSM vendor specific.
    CA_LUNA_ECDSA_SHA384 = 0x80000124
    # ECDSA SHA-384.  SafeNet / Gemalto Luna HSM vendor specific.
    CA_LUNA_ECDSA_SHA512 = 0x80000125
    # ECDSA SHA-512.  SafeNet / Gemalto Luna HSM vendor specific.
    CA_LUNA_AES_CBC_PAD_IPSEC = 0x8000012f
    # AES CBC mode with IPSEC padding.  SafeNet / Gemalto Luna HSM vendor specific.
    CA_LUNA_AES_CFB8 = 0x80000118
    # AES CFB-8 mode.  SafeNet / Gemalto Luna HSM vendor specific.
    CA_LUNA_AES_CFB128 = 0x80000119
    # AES CFB-128 mode.  SafeNet / Gemalto Luna HSM vendor specific.
    CA_LUNA_AES_OFB = 0x8000011a
    # AES OFB mode.  SafeNet / Gemalto Luna HSM vendor specific.
    CA_LUNA_AES_GCM = 0x8000011c
    # AES GCM mode.  SafeNet / Gemalto Luna HSM vendor specific.


# entries map to CKA_
class HsmAttribute(Enum):
    CLASS = 0x0000
    TOKEN = 0x0001
    PRIVATE = 0x0002
    LABEL = 0x0003
    APPLICATION = 0x0010
    VALUE = 0x0011
    CERTIFICATE_TYPE = 0x0080
    ISSUER = 0x0081
    SERIAL_NUMBER = 0x0082
    KEY_TYPE = 0x0100
    SUBJECT = 0x0101
    ID = 0x0102
    SENSITIVE = 0x0103
    ENCRYPT = 0x0104
    DECRYPT = 0x0105
    WRAP = 0x0106
    UNWRAP = 0x0107
    SIGN = 0x0108
    SIGN_RECOVER = 0x0109
    VERIFY = 0x010A
    VERIFY_RECOVER = 0x010B
    DERIVE = 0x010C
    START_DATE = 0x0110
    END_DATE = 0x0111
    MODULUS = 0x0120
    MODULUS_BITS = 0x0121
    PUBLIC_EXPONENT = 0x0122
    PRIVATE_EXPONENT = 0x0123
    PRIME_1 = 0x0124
    PRIME_2 = 0x0125
    EXPONENT_1 = 0x0126
    EXPONENT_2 = 0x0127
    COEFFICIENT = 0x0128
    PRIME = 0x0130
    SUBPRIME = 0x0131
    BASE = 0x0132
    VALUE_BITS = 0x0160
    VALUE_LEN = 0x0161
    EXTRACTABLE = 0x0162
    LOCAL = 0x0163
    NEVER_EXTRACTABLE = 0x0164
    ALWAYS_SENSITIVE = 0x0165
    MODIFIABLE = 0x0170
    ECDSA_PARAMS = 0x0180
    EC_PARAMS = 0x0180
    EC_POINT = 0x0181


# entries map to CKO_
class HsmObjectType(Enum):
    DATA = 0x0000
    CERTIFICATE = 0x0001
    PUBLIC_KEY = 0x0002
    PRIVATE_KEY = 0x0003
    SECRET_KEY = 0x0004

