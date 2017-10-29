#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#
# hsmslot.py
# author: Benton Stark (bestark@cisco.com)
# date: 11-25-2014 

from os import linesep
from pyhsm.hsmerror import HsmError


class HsmSlot:
    """
    HSM slot object class for holding 
    information about the HSM slots on 
    the host.
    """

    FIELD_DELIMITER = "|"
    NUMBER_OF_FIELDS = 8

    def __init__(self, line):
        # split the delimited line data into a list
        fields = line.split(self.FIELD_DELIMITER)
        # verify the number of fields we got back is as expected
        if len(fields) != self.NUMBER_OF_FIELDS:
            raise HsmError("unexpected number of fields to parse")
        # set the object values
        self.slotNumber = fields[0]
        self.label = fields[1]
        self.manufacturer = fields[2]
        self.model = fields[3]
        self.serialNumber = fields[4].rstrip()
        self.sessionCount = fields[5]
        self.hardwareVersion = fields[6]
        self.firmwareVersion = fields[7]
        
    def __repr__(self):
        return "<HsmSlot>:{0}".format(self.slotNumber)
            
    def details(self):
        s = "<HsmSlot: "
        s += "slotNumber:{0} ".format(self.slotNumber)
        s += "label:{0} ".format(self.label)
        s += "manufacturer:{0} ".format(self.manufacturer)
        s += "model:{0} ".format(self.model)
        s += "serialNumber:{0} ".format(self.serialNumber)
        s += "sessionCount:{0} ".format(self.sessionCount)
        s += "hardwareVersion:{0} ".format(self.hardwareVersion)
        s += "firmwareVersion:{0} ".format(self.firmwareVersion)
        s += ">"
        return s
    
    def to_string(self):
        """
        Returns a print formatted string for all the HSM slot information.
        """
        s = "slotNumber: {0}{1}".format(self.slotNumber, linesep)
        s += "label: {0}{1}".format(self.label, linesep)
        s += "manufacturer: {0}{1}".format(self.manufacturer, linesep)
        s += "model: {0}{1}".format(self.model, linesep)
        s += "serialNumber: {0}{1}".format(self.serialNumber, linesep)
        s += "sessionCount: {0}{1}".format(self.sessionCount, linesep)
        s += "hardwareVersion: {0}{1}".format(self.hardwareVersion, linesep)
        s += "firmwareVersion: {0}{1}".format(self.firmwareVersion, linesep)
        return s
    
    def __str__(self):
        return "<HsmSlot>:{0}".format(self.slotNumber)

