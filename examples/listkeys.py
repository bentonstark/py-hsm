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

    parser = argparse.ArgumentParser("listkeys", description="List keys on partition.")
    parser.add_argument("-p11", dest="module", required=True,
                        help="Full path to HSM's PKCS#11 shared library.")
    parser.add_argument("-slot", dest="slot", type=int, required=True, help="HSM slot number.")
    parser.add_argument("-pin", dest="pin", type=str, required=True, help="HSM slot partition or pin.")
    parser.add_argument("-al", "--show-all", dest="showAll", action="store_true",
                        help="Display attributes long version.")
    parser.set_defaults(func=__menu_handler)
    args = parser.parse_args()
    args.func(args)


def __menu_handler(args):

    if not Path(args.module).is_file():
        print("(-module) path does not exist")
        exit()

    with HsmClient(slot=args.slot, pin=args.pin, pkcs11_lib=args.module) as c:
        serial_number = c.get_slot_info()[0].serialNumber
        print("")
        print("slot number: " + str(args.slot))
        print("serial number: " + serial_number)

        # print header and print to console
        if not args.showAll:
            print("Handle".ljust(8) + "Label".ljust(30) + "Key Type".ljust(10) + "Class".ljust(15)
                  + "Attributes".ljust(10))
            print("------- ----------------------------- --------- -------------- -------------")
            obj_list = c.get_objects(fast_load=True)
        else:
            obj_list = c.get_objects(fast_load=False)

        # loop the objects and print to console
        for o in obj_list:
            __print_object(o, args.showAll)


def __print_object(obj, detail_level):
    if detail_level:
        print("----------------------------------------")
        print(obj.to_string())
    else:
        attribs = "e" if obj.encrypt else "-"
        attribs += "d" if obj.decrypt else "-"
        attribs += "w" if obj.wrap else "-"
        attribs += "u" if obj.unwrap else "-"
        attribs += "s" if obj.sign else "-"
        attribs += "v" if obj.verify else "-"
        attribs += "X" if obj.extractable else "-"
        attribs += "M" if obj.modifiable else "-"
        attribs += "T" if obj.token else "-"
        attribs += "S" if obj.sensitive else "-"
        attribs += "R" if obj.derive else "-"
        attribs += "P" if obj.private else "-"
        print(str(obj.handle).ljust(8) + obj.label.ljust(30)[:40] + str(obj.keyType)[11:].ljust(10)
              + str(obj.class_)[14:].ljust(15) + attribs)


if __name__ == '__main__':
    __main()
