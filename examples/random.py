#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#

import argparse
from pathlib import Path
from base64 import b64encode
from pyhsm.hsmclient import HsmClient
from pyhsm.convert import bytes_to_hex


def __main():

    parser = argparse.ArgumentParser("random", description="Gets random data from the HSM's RNG.")
    parser.add_argument("-size", dest="size", default=16, type=int,
                        help="Number of random bytes.")
    parser.add_argument("-encoding", dest="encoding", type=str, default='hex',
                        choices=['hex', 'base64'],
                        help="Binary data encoding (default: hex)")
    parser.add_argument("-p11", dest="module", required=True,
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

    with HsmClient(slot=args.slot, pin=args.pin, pkcs11_lib=args.module) as c:
        result = c.generate_random(size=args.size)

    if args.encoding == "hex":
        print(bytes_to_hex(result))
    elif args.encoding == "base64":
        print(str(b64encode(result))[2:-1])


if __name__ == '__main__':
    __main()
