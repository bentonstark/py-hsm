#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#

import argparse
from pathlib import Path
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmSymKeyGen


def __main():

    parser = argparse.ArgumentParser("keygen", description="Generates a symmetric key.")
    parser.add_argument("-keyType", dest="keyType", type=str, required=True, help="Key type.",
                        choices=[
                            "AES",
                            "DES",
                            "DES2",
                            "DES3",
                            "RC2",
                            "RC4",
                            "RC5",
                            "CAST",
                            "CAST3",
                            "IDEA",
                            "Baton",
                            "Juniper"
                        ])
    parser.add_argument("-size", dest="keySize", type=int, required=True, help="Size of key in bits.")
    parser.add_argument("-l", dest="keyLabel", type=str, required=True, help="Key label.  Can contain spaces.")
    parser.add_argument("-w", dest="wrap", action="store_true", help="Allow wrap operations.")
    parser.add_argument("-uw", dest="unwrap", action="store_true", help="Allow unwrap operations.")
    parser.add_argument("-e", dest="encrypt", action="store_true", help="Allow encrypt operations.")
    parser.add_argument("-d", dest="decrypt", action="store_true", help="Allow decrypt operations.")
    parser.add_argument("-s", dest="sign", action="store_true", help="Allow sign operations.")
    parser.add_argument("-ve", dest="verify", action="store_true", help="Allow verify operations.")
    parser.add_argument("-de", dest="derive", action="store_true", help="Allow derivation operations.")
    parser.add_argument("-X", dest="extractable", action="store_true", help="Allow key to be extracted.")
    parser.add_argument("-M", dest="modifiable", action="store_true", help="Allow key to be modified.")
    parser.add_argument("-O", dest="overwrite", action="store_true", help="Overwrite any existing key with same label.")
    parser.add_argument("-p11", dest="module", required=True,
                        help="Full path to HSM's PKCS#11 shared library.")
    parser.add_argument("-slot", dest="slot", type=int, required=True, help="HSM slot number.")
    parser.add_argument("-pin", dest="pin", type=str, required=True, help="HSM slot partition or pin.")
    parser.set_defaults(func=__menu_handler)
    args = parser.parse_args()
    args.func(args)


def __menu_handler(args):

    if not Path(args.module).is_file():
        print("(-p11) path does not exist")
        exit()

    with HsmClient(slot=args.slot, pin=args.pin, pkcs11_lib=args.module) as c:
        # create a new symmetric key on HSM
        hkey = c.create_secret_key(key_label=args.keyLabel,
                                   key_type=HsmSymKeyGen[args.keyType],
                                   key_size_in_bits=args.keySize,
                                   wrap=args.wrap,
                                   unwrap=args.unwrap,
                                   encrypt=args.encrypt,
                                   decrypt=args.decrypt,
                                   sign=args.sign,
                                   verify=args.verify,
                                   derive=args.derive,
                                   extractable=args.extractable,
                                   modifiable=args.modifiable,
                                   overwrite=args.overwrite,
                                   private=True,
                                   token=True)
        print("key with handle {} created on partition.".format(str(hkey)))


if __name__ == '__main__':
    __main()
