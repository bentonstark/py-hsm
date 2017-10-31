#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#

import argparse
from pathlib import Path
from pyhsm.hsmclient import HsmClient


def __main():

    parser = argparse.ArgumentParser("listmechs", description="Gets supported mechanisms from HSM.")
    parser.add_argument("-p11", dest="module", required=True,
                        help="Full path to HSM's PKCS#11 shared library.")
    parser.add_argument("-slot", dest="slot", type=int, required=True, help="HSM slot number.")
    parser.add_argument("-pin", dest="pin", type=str, required=True, help="HSM slot partition or pin.")
    parser.add_argument("-al", "--show-all", dest="showAll", action="store_true",
                        help="Display long version.")
    parser.set_defaults(func=__menu_handler)
    args = parser.parse_args()
    args.func(args)


def __menu_handler(args):

    if not Path(args.module).is_file():
        print("(-module) path does not exist")
        exit()

    with HsmClient(slot=args.slot, pin=args.pin, pkcs11_lib=args.module) as c:
        for mech in c.get_mechanism_info(args.slot):
            if args.showAll:
                print("----------------------------------------")
                print(mech.to_string())
            else:
                print("{} ({})".format(mech.mechanismName, mech.mechanismValue))


if __name__ == '__main__':
    __main()
