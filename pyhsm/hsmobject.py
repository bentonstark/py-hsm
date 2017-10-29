#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#
# hsmobject.py
# author: Benton Stark (bestark@cisco.com)
# date: 11-22-2014

import binascii
from os import linesep
from pyhsm.hsmenums import HsmAttribute
from pyhsm.hsmenums import HsmKeyType
from pyhsm.hsmenums import HsmObjectType
from pyhsm.hsmerror import HsmError


class HsmObject:
    def __init__(self, hsm, handle, fast_load):
        self.hsm = hsm
        self.handle = handle
        self.class_ = self.__cclass(HsmAttribute.CLASS)
        self.token = self.__cbool(HsmAttribute.TOKEN)
        self.private = self.__cbool(HsmAttribute.PRIVATE)
        self.label = self.__cval(HsmAttribute.LABEL).decode('ascii')
        self.keyType = self.__ckeyType(HsmAttribute.KEY_TYPE)
        self.sensitive = self.__cbool(HsmAttribute.SENSITIVE)
        self.encrypt = self.__cbool(HsmAttribute.ENCRYPT)
        self.decrypt = self.__cbool(HsmAttribute.DECRYPT)
        self.wrap = self.__cbool(HsmAttribute.WRAP)
        self.unwrap = self.__cbool(HsmAttribute.UNWRAP)
        self.sign = self.__cbool(HsmAttribute.SIGN)
        self.verify = self.__cbool(HsmAttribute.VERIFY)
        self.extractable = self.__cbool(HsmAttribute.EXTRACTABLE)
        self.local = self.__cbool(HsmAttribute.LOCAL)
        self.neverExtractable = self.__cbool(HsmAttribute.NEVER_EXTRACTABLE)
        self.alwaysSensitive = self.__cbool(HsmAttribute.ALWAYS_SENSITIVE)
        self.modifiable = self.__cbool(HsmAttribute.MODIFIABLE)
        self.derive = self.__cbool(HsmAttribute.DERIVE)

        if not fast_load:
            self.application = self.__cval(HsmAttribute.APPLICATION)
            self.value = self.__cval(HsmAttribute.VALUE)           
            self.certificateType = self.__cval(HsmAttribute.CERTIFICATE_TYPE)
            self.issuer = self.__cval(HsmAttribute.ISSUER)
            self.serialNumber = self.__cval(HsmAttribute.SERIAL_NUMBER)
            self.subject = self.__cval(HsmAttribute.SUBJECT)            
            self.id = self.__cval(HsmAttribute.ID)
            self.signRecover = self.__cbool(HsmAttribute.SIGN_RECOVER)
            self.verifyRecover = self.__cbool(HsmAttribute.VERIFY_RECOVER)
            self.startDate = self.__cval(HsmAttribute.START_DATE)
            self.endDate = self.__cval(HsmAttribute.END_DATE)
            self.modulus = self.__cval(HsmAttribute.MODULUS)
            self.modulusBits = self.__cval(HsmAttribute.MODULUS_BITS)
            self.publicExponent = self.__cval(HsmAttribute.PUBLIC_EXPONENT)
            self.privateExponent = self.__cval(HsmAttribute.PRIVATE_EXPONENT)
            self.prime1 = self.__cval(HsmAttribute.PRIME_1)
            self.prime2 = self.__cval(HsmAttribute.PRIME_2)
            self.exponent1 = self.__cval(HsmAttribute.EXPONENT_1)
            self.exponent2 = self.__cval(HsmAttribute.EXPONENT_2)
            self.coefficient = self.__cval(HsmAttribute.COEFFICIENT)
            self.prime = self.__cval(HsmAttribute.PRIME)
            self.subprime = self.__cval(HsmAttribute.SUBPRIME)
            self.base = self.__cval(HsmAttribute.BASE)
            self.valueBits = self.__cval(HsmAttribute.VALUE_BITS)
            self.valueLen = self.__cval(HsmAttribute.VALUE_LEN)
            self.ecdsaParams = self.__cval(HsmAttribute.ECDSA_PARAMS)
            self.ecParams = self.__cval(HsmAttribute.EC_PARAMS)
            self.ecPoint = self.__cval(HsmAttribute.EC_POINT)
        
    def __cbool(self, attrib):
        v = self.__get_attrib(attrib)[:1]
        if v == b'\x01':
            return True
        return False

    def __cval(self, attrib):
        v = self.__get_attrib(attrib)
        return v

    def __cclass(self, attrib):
        v = self.__get_attrib(attrib)[:1]
        if v == b'\x00':
            return HsmObjectType.DATA
        elif v == b'\x01':
            return HsmObjectType.CERTIFICATE
        elif v == b'\x02':
            return HsmObjectType.PUBLIC_KEY
        elif v == b'\x03':
            return HsmObjectType.PRIVATE_KEY
        elif v == b'\x04':
            return HsmObjectType.SECRET_KEY
        return v
        
    def __ckeyType(self, attrib):
        v = self.__get_attrib(attrib)[:1]
        if v == b'\x00':
            return HsmKeyType.RSA
        elif v == b'\x01':
            return HsmKeyType.DSA
        elif v == b'\x02':
            return HsmKeyType.DH
        elif v == b'\x03':
            return HsmKeyType.EC
        elif v == b'\x05':
            return HsmKeyType.KEA
        elif v == b'\x10':
            return HsmKeyType.GENERIC_SECRET
        elif v == b'\x11':
            return HsmKeyType.RC2
        elif v == b'\x12':
            return HsmKeyType.RC4
        elif v == b'\x13':
            return HsmKeyType.DES
        elif v == b'\x14':
            return HsmKeyType.DES2
        elif v == b'\x15':
            return HsmKeyType.DES3
        elif v == b'\x19':
            return HsmKeyType.RC5
        elif v == b'\x1A':
            return HsmKeyType.IDEA
        elif v == b'\x1B':
            return HsmKeyType.SKIPJACK
        elif v == b'\x1C':
            return HsmKeyType.BATON
        elif v == b'\x1D':
            return HsmKeyType.JUNIPER
        elif v == b'\x1E':
            return HsmKeyType.CDMF
        elif v == b'\x1F':
            return HsmKeyType.AES
        elif v == b'\x16':
            return HsmKeyType.CAST
        elif v == b'\x17':
            return HsmKeyType.CAST3
        elif v == b'\x18':
            return HsmKeyType.CAST5
        return v
    
    def __get_attrib(self, attrib):
        val = ""
        try:
            val = self.hsm.get_attribute_value(self.handle, attrib)
        except HsmError:
            return ""
        return val 

    def __repr__(self):
        return "<HsmObject handle:{0} label:{1} >".format(self.handle, self.label)
            
    def details(self):
        s = "<HsmObject: "
        s += "handle:{0} ".format(self.handle)
        s += "label:{0} ".format(self.label)
        s += "class:{0} ".format(self.class_)
        s += "keyType:{0} ".format(self.keyType)
        s += "token:{0} ".format(self.token)
        s += "private:{0} ".format(self.private)
        s += "sensitive:{0} ".format(self.sensitive)
        s += "encrypt:{0} ".format(self.encrypt)
        s += "decrypt:{0} ".format(self.decrypt)
        s += "wrap:{0} ".format(self.wrap)
        s += "unwrap:{0} ".format(self.unwrap)
        s += "sign:{0} ".format(self.sign)
        s += "verify:{0} ".format(self.verify)
        s += "derive:{0} ".format(self.derive)
        s += "extractable:{0} ".format(self.extractable)
        s += "local:{0} ".format(self.local)
        s += "neverExtractable:{0} ".format(self.neverExtractable)
        s += "alwaysSensitive:{0} ".format(self.alwaysSensitive)
        s += "modifiable:{0} ".format(self.modifiable)
        s += ">"
        return s

    def __to_hex(self, byte_string):
        if not isinstance(byte_string, bytes) and not isinstance(byte_string, bytearray):
            return byte_string
        elif len(byte_string) == 0:
            return ""
        else:
            return str(binascii.hexlify(byte_string))[2:-1]

    def to_string(self):
        """
        Returns a print formatted string for all the object attributes.
        """
        
        s = "HANDLE: {0}{1}".format(self.handle, linesep)
        s += "CKA_ID: {0}{1}".format(self.__to_hex(self.id), linesep)
        s += "CKA_CLASS: {0}{1}".format(self.__to_hex(self.class_), linesep)
        s += "CKA_KEY_TYPE: {0}{1}".format(self.__to_hex(self.keyType), linesep)
        s += "CKA_TOKEN: {0}{1}".format(self.token, linesep)
        s += "CKA_PRIVATE: {0}{1}".format(self.private, linesep)
        s += "CKA_LABEL: {0}{1}".format(self.label, linesep)
        s += "CKA_SENSITIVE: {0}{1}".format(self.sensitive, linesep)
        s += "CKA_ENCRYPT: {0}{1}".format(self.encrypt, linesep)
        s += "CKA_DECRYPT: {0}{1}".format(self.decrypt, linesep)
        s += "CKA_WRAP: {0}{1}".format(self.wrap, linesep)
        s += "CKA_UNWRAP: {0}{1}".format(self.unwrap, linesep)
        s += "CKA_SIGN: {0}{1}".format(self.sign, linesep)
        s += "CKA_VERIFY: {0}{1}".format(self.verify, linesep)
        s += "CKA_EXTRACTABLE: {0}{1}".format(self.extractable, linesep)
        s += "CKA_LOCAL: {0}{1}".format(self.local, linesep)
        s += "CKA_NEVER_EXTRACTABLE: {0}{1}".format(self.neverExtractable, linesep)
        s += "CKA_ALWAYS_SENSITIVE: {0}{1}".format(self.alwaysSensitive, linesep)
        s += "CKA_MODIFIABLE: {0}{1}".format(self.modifiable, linesep)
        s += "CKA_DERIVE: {0}{1}".format(self.derive, linesep)
        s += "CKA_VALUE: {0}{1}".format(self.__to_hex(self.value), linesep)
        s += "CKA_APPLICATION: {0}{1}".format(self.application, linesep)        
        s += "CKA_CERTIFICATE_TYPE: {0}{1}".format(self.certificateType, linesep)
        s += "CKA_ISSUER: {0}{1}".format(self.issuer, linesep)
        s += "CKA_SERIAL_NUMBER: {0}{1}".format(self.serialNumber, linesep)
        s += "CKA_SUBJECT: {0}{1}".format(self.subject, linesep)
        s += "CKA_SIGN_RECOVER: {0}{1}".format(self.signRecover, linesep)        
        s += "CKA_VERIFY_RECOVER: {0}{1}".format(self.verifyRecover, linesep)
        s += "CKA_START_DATE: {0}{1}".format(self.startDate, linesep)
        s += "CKA_END_DATE: {0}{1}".format(self.endDate, linesep)
        s += "CKA_MODULUS: {0}{1}".format(self.__to_hex(self.modulus), linesep)
        s += "CKA_MODULUS_BITS: {0}{1}".format(self.__to_hex(self.modulusBits), linesep)
        s += "CKA_PUBLIC_EXPONENT: {0}{1}".format(self.__to_hex(self.publicExponent), linesep)
        s += "CKA_PRIVATE_EXPONENT: {0}{1}".format(self.__to_hex(self.privateExponent), linesep)
        s += "CKA_PRIME_1: {0}{1}".format(self.__to_hex(self.prime1), linesep)
        s += "CKA_PRIME_1: {0}{1}".format(self.__to_hex(self.prime2), linesep)
        s += "CKA_EXPONENT_1: {0}{1}".format(self.__to_hex(self.exponent1), linesep)
        s += "CKA_EXPONENT_1: {0}{1}".format(self.__to_hex(self.exponent2), linesep)
        s += "CKA_COEFFICIENT: {0}{1}".format(self.__to_hex(self.coefficient), linesep)
        s += "CKA_PRIME: {0}{1}".format(self.__to_hex(self.prime), linesep)
        s += "CKA_SUBPRIME: {0}{1}".format(self.__to_hex(self.subprime), linesep)
        s += "CKA_BASE: {0}{1}".format(self.base, linesep)
        s += "CKA_VALUE_BITS: {0}{1}".format(self.__to_hex(self.valueBits), linesep)
        s += "CKA_VALUE_LEN: {0}{1}".format(self.__to_hex(self.valueLen), linesep)
        s += "CKA_ECDSA_PARAMS: {0}{1}".format(self.__to_hex(self.ecdsaParams), linesep)
        s += "CKA_EC_PARAMS: {0}{1}".format(self.__to_hex(self.ecParams), linesep)
        s += "CKA_EC_POINT: {0}{1}".format(self.__to_hex(self.ecPoint), linesep)
        
        return s
    
    def __str__(self):
        return "<HsmObject handle:{0} label:{1} >".format(self.handle, self.label)
