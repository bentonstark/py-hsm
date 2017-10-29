#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#
# eccurveoids.py
# author: Benton Stark (bestark@cisco.com)
# date: 01-26-2015

from enum import Enum


class EcCurveOids(Enum):
    """
    EC Curve Definitions by OID.  It is highly recommended to use the OID definitions when specifying an EC curve.
    """
    # SECG
    secp160k1 = b"\x06\x05\x2B\x81\x04\x00\x09"
    secp160r1 = b"\x06\x05\x2B\x81\x04\x00\x08"
    secp160r2 = b"\x06\x05\x2B\x81\x04\x00\x1E"
    sect163k1 = b"\x06\x05\x2B\x81\x04\x00\x01"
    sect163r1 = b"\x06\x05\x2B\x81\x04\x00\x02"
    sect163r2 = b"\x06\x05\x2B\x81\x04\x00\x0F"
    secp192k1 = b"\x06\x05\x2B\x81\x04\x00\x1F"
    secp192r1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x01"
    sect193r1 = b"\x06\x05\x2B\x81\x04\x00\x18"
    sect193r2 = b"\x06\x05\x2B\x81\x04\x00\x19"
    secp224k1 = b"\x06\x05\x2B\x81\x04\x00\x20"
    secp224r1 = b"\x06\x05\x2B\x81\x04\x00\x21"
    sect233k1 = b"\x06\x05\x2B\x81\x04\x00\x19"
    sect233r1 = b"\x06\x05\x2B\x81\x04\x00\x1B"
    sect239k1 = b"\x06\x05\x2B\x81\x04\x00\x03"
    secp256k1 = b"\x06\x05\x2B\x81\x04\x00\x0A"
    secp256r1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07"
    sect283k1 = b"\x06\x05\x2B\x81\x04\x00\x10"
    sect283r1 = b"\x06\x05\x2B\x81\x04\x00\x11"
    secp384r1 = b"\x06\x05\x2B\x81\x04\x00\x22"
    sect409k1 = b"\x06\x05\x2B\x81\x04\x00\x24"
    sect409r1 = b"\x06\x05\x2B\x81\x04\x00\x25"
    secp521r1 = b"\x06\x05\x2B\x81\x04\x00\x23"
    sect571k1 = b"\x06\x05\x2B\x81\x04\x00\x26"
    sect571r1 = b"\x06\x05\x2B\x81\x04\x00\x27"

    # ANSI X9.62
    c2pnb163v1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x01"
    c2pnb163v2 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x02"
    c2pnb163v3 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x03"
    c2tnb191v1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x05"
    c2tnb191v2 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x06"
    c2tnb191v3 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x07"
    prime192v1 = secp192r1
    prime192v2 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x02"
    prime192v3 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x03"
    c2pnb208w1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x0A"
    prime239v2 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x05"
    prime239v3 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x06"
    c2tnb239v1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x0B"
    c2tnb239v2 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x0C"
    c2tnb239v3 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x0D"
    prime256v1 = secp256r1
    c2pnb272w1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x10"
    c2pnb304w1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x11"
    c2tnb359v1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x12"
    c2pnb368w1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x13"
    c2tnb431r1 = b"\x06\x08\x2A\x86\x48\xCE\x3D\x03\x00\x14"

    # NIST (aliases for SEC curves)
    K163 = sect163k1
    B163 = sect163r2
    P192 = secp192r1
    P224 = secp224r1
    K233 = sect233k1
    B233 = sect233r1
    P256 = secp256r1
    K283 = sect283k1
    B283 = sect283r1
    P384 = secp384r1
    K409 = sect409k1
    B409 = sect409r1
    P512 = secp521r1
    K571 = sect571k1
    B571 = sect571r1

    # Brainpool
    brainpoolP160r1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x01"
    brainpoolP160t1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x02"
    brainpoolP192r1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x03"
    brainpoolP192t1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x04"
    brainpoolP224r1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x05"
    brainpoolP224t1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x06"
    brainpoolP256r1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x07"
    brainpoolP256t1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x08"
    brainpoolP320r1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x09"
    brainpoolP320t1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0A"
    brainpoolP384r1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0B"
    brainpoolP384t1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0C"
    brainpoolP512r1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0D"
    brainpoolP512t1 = b"\x06\x09\x2B\x24\x03\x03\x02\x08\x01\x01\x0E"














