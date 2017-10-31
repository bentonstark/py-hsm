#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#

import argparse
from pyhsm.hsmclient import HsmClient


parser = argparse.ArgumentParser("listslots", description="List HSM slots.")
parser.add_argument("-p11", dest="module", required=True,
                    help="Full path to HSM's PKCS#11 shared library.")
args = parser.parse_args()

# note: listing slot information does not require a login
# example connects to the open source softHSM v2
with HsmClient(pkcs11_lib=args.module) as c:
    for s in c.get_slot_info():
        print("----------------------------------------")
        print(s.to_string())
