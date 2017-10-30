#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#

import argparse
from pathlib import Path
from pyhsm.hsmclient import HsmClient
from pyhsm.convert import hex_to_bytes
from pyhsm.convert import bytes_to_hex
from pyhsm.hsmenums import HsmMech


def __main():

    parser = argparse.ArgumentParser("sign", description="Sign with cryptographic key.")
    parser.add_argument("-handle", dest="keyHandle", default=0, type=int, required=True,
                        help="Handle of key.")
    parser.add_argument("-mech", dest="mech", type=str, required=True,
                        choices=[
                            "RSA_X_509",
                            "RSA_PKCS",
                            "SHA1_RSA_PKCS",
                            "SHA256_RSA_PKCS",
                            "SHA384_RSA_PKCS",
                            "SHA512_RSA_PKCS",
                            "SHA1_RSA_PKCS_PSS",
                            "ECDSA_SHA1",
                            "ECDSA_SHA224",
                            "ECDSA_SHA256",
                            "ECDSA_SHA384",
                            "ECDSA_SHA512",
                            "CA_LUNA_ECDSA_SHA224",
                            "CA_LUNA_ECDSA_SHA256",
                            "CA_LUNA_ECDSA_SHA384",
                            "CA_LUNA_ECDSA_SHA512",
                            "AES_MAC",
                            "AES_MAC_GENERAL"
                        ],
                        help="Signing mechanism (algorithm) to use.")
    parser.add_argument("-data", dest="data", type=str, required=True,
                        help="Binary data to sign as a hex encoded string.  Example: 000A0B0C0D010203")
    parser.add_argument("-pss-length", dest="pssSaltLength", type=int, default=None, required=False,
                        help="PSS salt value length.  Only used when mech is an PSS algorithm.")
    parser.add_argument("-module", dest="module", required=True,
                        help="Full path to HSM's PKCS#11 shared library.")
    parser.add_argument("-slot", dest="slot", type=int, required=True, help="HSM slot number.")
    parser.add_argument("-pin", dest="pin", type=str, required=True, help="HSM slot partition or pin.")
    parser.set_defaults(func=__menu_handler)
    args = parser.parse_args()
    args.func(args)


def __menu_handler(args):

    if not Path(args.module).is_file():
        print("(-module) path does not exist")
        exit()

    # test to see if the user provided a pss salt length for a PSS algorithm
    if "PSS" in args.mech and args.pssSaltLength is None:
        print("-pss-length must be provided when a PSS mechanism is specified")
        return
    else:
        if args.pssSaltLength is None:
            args.pssSaltLength = 0

    with HsmClient(slot=args.slot, pin=args.pin, pkcs11_lib=args.module) as c:

        sig = c.sign(handle=args.keyHandle,
                     data=hex_to_bytes(args.data),
                     mechanism=HsmMech[args.mech],
                     pss_salt_length=args.pssSaltLength)

        print(bytes_to_hex(sig))


if __name__ == '__main__':
    __main()
