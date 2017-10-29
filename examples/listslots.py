#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#

from pyhsm.hsmclient import HsmClient

# note: listing slot information does not require a login
# example connects to the open source softHSM v2
with HsmClient(pkcs11_lib="/usr/lib64/pkcs11/libsofthsm2.so") as c:
    for s in c.get_slot_info():
        print("----------------------------------------")
        print(s.to_string())
