#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#

import os
import argparse
from time import time
from pathlib import Path
from pyhsm.hsmclient import HsmClient
from pyhsm.convert import bytes_to_hex
from pyhsm.eccurveoids import EcCurveOids


def __main():

    parser = argparse.ArgumentParser("ecgen-test", description="EC key generation timed test.")

    parser.add_argument("-curve", dest="curveName", type=str, default='P256', choices=['P192', 'P224', 'P256',
                        'P384', 'P512'], help="Named EC curve (default: P256)")
    parser.add_argument("-ops", dest="ops", type=int, default=10,
                        help="Number of key generation operations (default: 10)")
    parser.add_argument("-persist", dest="persist", action="store_true", help="Persist keys on the partition"
                        "and do not remove them after the session closes.")
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

    print("starting test...")

    with HsmClient(slot=args.slot, pin=args.pin, pkcs11_lib=args.module) as c:
        # get start time
        t0 = time()
        try:
            for i in range(1, args.ops + 1):
                unique_tag = bytes_to_hex(os.urandom(4))
                c.create_ecc_key_pair(public_key_label="EC_PUB_TEST_KEY_{}".format(unique_tag),
                                      private_key_label="EC_PVT_TEST_KEY_{}".format(unique_tag),
                                      ec_params=EcCurveOids[args.curveName],
                                      token=args.persist,
                                      sign_verify=True,
                                      encrypt_decrypt=False,
                                      wrap_unwrap=False,
                                      public_private=False)

        except KeyboardInterrupt:
            print("interrupted")
        # get stop time
        t1 = time()

    print("end test")

    elapsed = t1 - t0
    total_ops = args.ops
    print("\n-------------------------------------")
    print("RESULTS")
    print("-------------------------------------")
    print("test: ecgen-test")
    print("curve: {}".format(args.curveName))
    print("total_ops: {}".format(total_ops))
    print("elapsed_time_ms: " + str(round(elapsed * 1000, 4)))
    print("ops/sec: " + str(round(total_ops / elapsed, 2)))
    print("-------------------------------------\n")


if __name__ == '__main__':
    __main()
