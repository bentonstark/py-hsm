#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#
# hsmslot.py
# author: Benton Stark (bestark@cisco.com)
# date: 09-26-2017

from os import linesep
from pyhsm.hsmerror import HsmError


class HsmMechInfo:
    """
    HSM mech info object class for holding
    information about the HSM slots PKCS#11
    mechanisms.
    """

    FIELD_DELIMITER = "|"
    NUMBER_OF_FIELDS = 5

    def __init__(self, line):
        # split the delimited line data into a list
        fields = line.split(self.FIELD_DELIMITER)
        # verify the number of fields we got back is as expected
        if len(fields) != self.NUMBER_OF_FIELDS:
            raise HsmError("unexpected number of fields to parse")
        # set the object values
        # mechanism name
        # mechanism value in base16(hex)
        # min key size
        # max key size
        # flags
        self.mechanismName = fields[0]
        self.mechanismValue = fields[1]
        self.mechanismValueInt = int(fields[1], 0)
        self.minKeySize = fields[2]
        self.maxKeySize = fields[3]
        self.flags = fields[4]

    def __repr__(self):
        return "<HsmMechInfo>:{0} ({1})".format(self.mechanismName, self.mechanismValue)

    def details(self):
        s = "<HsmMechInfo: "
        s += "mechanismName:{0} ".format(self.mechanismName)
        s += "mechanismValue:{0} ".format(self.mechanismValue)
        s += "minKeySize:{0} ".format(self.minKeySize)
        s += "maxKeySize:{0} ".format(self.maxKeySize)
        s += "flags:{0} ".format(self.flags)
        s += ">"
        return s

    def to_string(self):
        """
        Returns a print formatted string for all the HSM slot information.
        """
        s = "mechanismName: {0}{1}".format(self.mechanismName, linesep)
        s += "mechanismValue: {0}{1}".format(self.mechanismValue, linesep)
        s += "minKeySize: {0}{1}".format(self.minKeySize, linesep)
        s += "maxKeySize: {0}{1}".format(self.maxKeySize, linesep)
        s += "flags: {0}".format(self.flags)
        return s

    def __str__(self):
        return "<HsmMechInfo>:{0} ({1})".format(self.mechanismName, self.mechanismValue)

