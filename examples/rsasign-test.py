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

    parser = argparse.ArgumentParser("rsasign-test", description="RSA signing timed test.")
    parser.add_argument("-smech", "--sign-mech", dest="signMech", type=str, default="SHA1_RSA_PKCS",
                        choices=[
                            "RSA_X_509",
                            "RSA_PKCS",
                            "SHA1_RSA_PKCS",
                            "SHA256_RSA_PKCS",
                            "SHA384_RSA_PKCS",
                            "SHA512_RSA_PKCS",
                            "SHA1_RSA_PKCS_PSS",
                        ],
                        help="RSA signing mechanism (algorithm) to use.  (default: SHA1_RSA_PKCS)")
    parser.add_argument("-size", dest="keySize", type=int, default=2048, choices=[1024, 2048, 3072, 4096, 8192],
                        help="Size of RSA key in bits (default: 2048)")
    parser.add_argument("-gmech", "--gen-mech", dest="genMech", type=str, default="RSA_PKCS_KEY_PAIR_GEN",
                        choices=["RSA_PKCS_KEY_PAIR_GEN", "RSA_X9_31_KEY_PAIR_GEN"],
                        help="RSA Key generation mechanism (algorithm) to use. "
                        "(default: RSA_X9_31_KEY_PAIR_GEN")
    parser.add_argument("-pss-length", dest="pssSaltLength", type=int, default=10, required=False,
                        help="PSS salt value length.  Only used when mech is an PSS algorithm.  (default: 10)")
    parser.add_argument("-ops", dest="ops", type=int, default=100,
                        help="Number of signing operations (default: 100)")
    parser.add_argument("-dz", "--data-size", dest="dataSize", type=int, default=100,
                        help="Size (in bytes) of random test data to sign.  (default: 100)")
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

        unique_tag = bytes_to_hex(os.urandom(4))
        key_handles = c.create_rsa_key_pair(public_key_label="RSA_PUB_TEST_KEY_{}".format(unique_tag),
                                            private_key_label="RSA_PVT_TEST_KEY_{}".format(unique_tag),
                                            mechanism=HsmMech[args.genMech],
                                            key_length=args.keySize,
                                            token=False,
                                            sign_verify=True,
                                            encrypt_decrypt=False,
                                            wrap_unwrap=False,
                                            public_private=False)

        pvt_h = key_handles[1]
        data = os.urandom(args.dataSize)

        # get start time
        t0 = time()
        try:
            for i in range(1, args.ops + 1):

                c.sign(handle=pvt_h,
                       data=data,
                       mechanism=HsmMech[args.signMech],
                       pss_salt_length=args.pssSaltLength)

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
    print("test: rsasign-test")
    print("key_size: {}".format(args.keySize))
    print("sign_mech: {}".format(args.signMech))
    print("gen_mech: {}".format(args.genMech))
    print("total_ops: {}".format(total_ops))
    print("elapsed_time_ms: " + str(round(elapsed * 1000, 4)))
    print("ops/sec: " + str(round(total_ops / elapsed, 2)))
    print("-------------------------------------\n")


if __name__ == '__main__':
    __main()
