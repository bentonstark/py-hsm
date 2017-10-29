#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#
# hsmerror.py
# author: Benton Stark (bestark@cisco.com)
# date: 11-22-2014


class HsmError(Exception):
    def __init__(self, message):
        self.message = message.strip()
    
    def __str__(self):
        return repr(self.message)

    def __repr__(self):
        return self.message
