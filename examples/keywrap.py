#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#

import argparse
from pathlib import Path
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import bytes_to_hex

def __main():

    parser = argparse.ArgumentParser("aeskeywrap", description="Wraps a key using the CKM_AES_KEY_WRAP mechanism.")
    parser.add_argument("-whandle", "--wrap-handle", dest="wrapHandle", required=True, type=int,
                        help="Handle of of AES wrapping key.")
    parser.add_argument("-handle", dest="handle", required=True, type=int, help="Handle of key to wrap.")
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

        iv = c.generate_random(size=16)
        wrapped_key_bytes = c.wrap_key(key_handle=args.handle, wrap_key_handle=args.wrapHandle, wrap_key_iv=iv,
                                       wrap_key_mech=HsmMech.AES_KEY_WRAP)
        print("iv: {}".format(bytes_to_hex(iv)))
        print("wrapped_key_bytes: {}".format(bytes_to_hex(wrapped_key_bytes)))


if __name__ == '__main__':
    __main()
