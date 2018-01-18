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
from pyhsm.hsmenums import HsmMech


def __main():

    parser = argparse.ArgumentParser("rsagen-test", description="RSA key generation timed test.")
    parser.add_argument("-size", dest="keySize", type=int, default=2048, choices=[1024, 2048, 3072, 4096, 8192],
                        help="Size of RSA key in bits (default: 2048)")
    parser.add_argument("-mech", dest="mech", type=str, default="RSA_PKCS_KEY_PAIR_GEN",
                        choices=["RSA_PKCS_KEY_PAIR_GEN", "RSA_X9_31_KEY_PAIR_GEN"],
                        help="RSA Key generation mechanism (algorithm) to use. "
                        "(default: RSA_X9_31_KEY_PAIR_GEN")
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
        print("(-p11) path does not exist")
        exit()

    print("starting test...")

    with HsmClient(slot=args.slot, pin=args.pin, pkcs11_lib=args.module) as c:
        # get start time
        t0 = time()
        try:
            for i in range(1, args.ops + 1):
                unique_tag = bytes_to_hex(os.urandom(4))
                c.create_rsa_key_pair(public_key_label="RSA_PUB_TEST_KEY_{}".format(unique_tag),
                                      private_key_label="RSA_PVT_TEST_KEY_{}".format(unique_tag),
                                      mechanism=HsmMech[args.mech],
                                      key_length=args.keySize,
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
    print("test: rsagen-test")
    print("key_size: {}".format(args.keySize))
    print("total_ops: {}".format(total_ops))
    print("elapsed_time_ms: " + str(round(elapsed * 1000, 4)))
    print("ops/sec: " + str(round(total_ops / elapsed, 2)))
    print("-------------------------------------\n")


if __name__ == '__main__':
    __main()
