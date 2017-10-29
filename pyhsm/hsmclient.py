#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#
# hsmclient.py
# author: Benton Stark (bestark@cisco.com)
# date: 10-15-2014

import os
from ctypes import CDLL
from ctypes import POINTER
from ctypes import byref
from ctypes import c_char_p
from ctypes import c_ulong
from ctypes import create_string_buffer

from pyhsm.hsmenums import HsmAsymKeyType
from pyhsm.hsmenums import HsmAttribute
from pyhsm.hsmenums import HsmMech
from pyhsm.hsmenums import HsmSession
from pyhsm.hsmenums import HsmSymKeyGen
from pyhsm.hsmenums import HsmSymKeyType
from pyhsm.hsmenums import HsmUser
from pyhsm.hsmerror import HsmError
from pyhsm.hsmobject import HsmObject
from pyhsm.hsmslot import HsmSlot
from pyhsm.hsmmechinfo import HsmMechInfo
from pyhsm.eccurveoids import EcCurveOids
from pyhsm.eccurves import EcCurves
from pyhsm.convert import str_to_bytes
from pyhsm.convert import bytes_to_str
from pyhsm.convert import bytes_to_hex


class HsmClient:
    """
    HSM Client class for connecting to and interacting
    with a Hardware Security Module.  This class 
    supports a variety of methods to create, manage,
    and export HSM objects on a HSM partition.  It utilizes
    a companion shared library named libhsm that performs
    all the PKCS#11 v2 operations.  Any standard PKCS#11 shared
    library can be given for the HsmClient to connect to as
    a path string.  The HSM client has been extensively tested
    with the SafeNet / Gemalto Luna line of HSMs.  In addition
    the library has been tested heavily with the Utimaco HSM Simulator
    and the SoftHSM PKCS#11 shared library.  Other HSMs tested include
    FutureX, Cavium, and Thales.

    The full path to the PKCS#11 shared library (module) must be passed
    in the pkcs11_lib argument.
    
    If a HSM slot and PIN value is given then a session
    will attempt to be open and a user logged in with
    the supplied PIN.  If these values are not given
    then the consumer can user the traditional 
    open_session() and login() methods respectively.
    
        Args:
            slot:                   HSM or token slot number
                                    assigned to the device for
                                    accessibility.
                                    (optional and used only if pin provided)
                          
            pin:                    partition password or PIN.
                                    (optional)
            
            pkcs11_lib:             full path to the PKCS#11 shared
                                    library file
                                    (optional)
                                    (default is '/usr/lib/libpyhsm.so')

     Below are example PKCS-11 vendor 64-bit shared libraries known to work with pyhsm.

     Utimaco Simulator: /usr/lib64/libcs_pkcs11_R2.so
     SafeNet Luna SA-5: /usr/lib64/libCryptoki2_64.so
     SoftHSM: /usr/lib64/pkcs11/libsofthsm2.so

    """
    
    def __init__(self, slot=0, pin=None, pkcs11_lib='/usr/lib/libpyhsm.so'):
        # validate args - note slots and pin args will be validated by other methods
        if not isinstance(pkcs11_lib, str):
            raise HsmError("pkcs11_lib must be of type str")

        # set the libhsm shared library for the target OS
        if os.name == "posix":
            self.__pyLibHsmName = "libhsm.so"
        elif os.name == "nt":
            self.__pyLibHsmName = "libhsm.dll"
        else:
            raise HsmError("pyhsm not supported on this platform")

        # underlying libhsm binary version
        self.__libhsmVersion = b'2.4.0'
        # slot and token information
        self.sessionHandle = 0
        self.slotNumber = 0
        self.tokenSerialNumber = ''
        self.userType = HsmUser.CryptoOfficer
        # library connection and initialization indicators
        self.__connected = False
        self.__loggedIn = False
        self.__initialized = False
        # PKCS-11 error string names
        self.__ckrSessionHandleInvalidString = 'CKR_SESSION_HANDLE_INVALID'
        self.__ckrSignatureInvalidString = 'CKR_SIGNATURE_INVALID'
        self.__ckrCryptokiAlreadyInitialized = 'CKR_CRYPTOKI_ALREADY_INITIALIZED'
        # session key constants (session key used to wrap, unwrap, encrypt and decrypt extractable keys)
        self.__sessionKeyHandle = 0
        self.__sessionKeyLabel = 'TEMP_SESSION_KEY_' + bytes_to_hex(os.urandom(3))
        self.__sessionKeySizeInBits = 256
        self.__sessionKeyType = HsmSymKeyGen.AES
        self.__sessionKeyMech = HsmMech.AES_CBC_PAD
        self.__sessionKeyIv = b'\x00\x01\x02\x03\x04\x05\x06\x07\x00\x01\x02\x03\x04\x05\x06\x07'
        # constants
        self.__messageBufferSize = 200
        self.__hsmInfoBufferSize = 2000
        self.__mechInfoBufferSize = 100000
        self.__verBufferSize = 20
        self.__aesByteBlockSize = 16
        self.__desByteBlockSize = 8
        self.__digestBufferSize = 100
        self.__encryptBufferPaddingAdjustment = 100
        self.__rsaModulusBufferSize = 8000
        self.__rsaPrivateKeyBufferSize = 8000
        self.__signBufferSize = 2000
        self.__attributeBufferSize = 8000
        self.__wrapoffKeyBufferSize = 8000
        self.__findObjectsArraySize = 2000
        self.__oaepBufferSize = 1024
        self.__minReseedEntropySize = 32
        self.__maxRandomSize = 1000
        self.__idRandomSize = 16
        # load and init the shared library for use with Python ctypes
        self.__init_libhsm()
        # verify we are working with the correct libhsm library 
        self.__verify_libhsm_version()
        # connect to the underlying PKCS-11 HSM vendor specific shared library
        self.__connect(pkcs11_lib)
        # initialize the PKCS-11 API
        self.__initialize()
        
        # if pin is given then attempt to login
        if pin is not None:
            self.open_session(slot)
            self.login(pin)
        
    def __del__(self):
        return

    def __init_libhsm(self):
        # use ctypes to load the libhsm.so C/C++ shared library that implements
        # the various direct PKCS#11 API calls
        self.__libhsm = CDLL(self.__pyLibHsmName)
        # define the C extern function prototypes with option variable arguments for type checking
        self.__libhsm.get_lib_version.argtypes = [c_char_p, c_ulong, c_char_p, c_ulong]
        self.__libhsm.connect.argtypes = [c_char_p, c_ulong, c_char_p, c_ulong]
        self.__libhsm.disconnect.argtypes = [c_char_p, c_ulong]
        self.__libhsm.initialize.argtypes = [c_char_p, c_ulong]
        self.__libhsm.finalize.argtypes = [c_char_p, c_ulong]
        self.__libhsm.open_session.argtypes = [c_char_p, c_ulong, c_ulong, c_ulong, POINTER(c_ulong)]
        self.__libhsm.close_session.argtypes = [c_char_p, c_ulong, c_ulong]
        self.__libhsm.close_all_sessions.argtypes = [c_char_p, c_ulong, c_ulong]
        self.__libhsm.login.argtypes = [c_char_p, c_ulong, c_ulong, c_ulong, c_char_p, c_ulong]
        self.__libhsm.logout.argtypes = [c_char_p, c_ulong, c_ulong]
        self.__libhsm.set_pin.argtypes = [c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong]
        self.__libhsm.find_objects.argtypes = [c_char_p, c_ulong, c_ulong, POINTER(c_ulong)]
        self.__libhsm.get_object_handle.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, POINTER(c_ulong)]
        self.__libhsm.sign.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, c_ulong, c_ulong, c_ulong,
                                       c_char_p, POINTER(c_ulong)]
        self.__libhsm.verify.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, c_ulong, c_ulong, c_ulong,
                                         c_char_p, c_ulong]
        self.__libhsm.encrypt.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, c_ulong, c_ulong, c_char_p,
                                          c_ulong, c_char_p, POINTER(c_ulong)]
        self.__libhsm.decrypt.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, c_ulong, c_ulong, c_char_p,
                                          c_ulong, c_char_p, POINTER(c_ulong)]
        self.__libhsm.digest.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, c_ulong, c_char_p,
                                         POINTER(c_ulong)]
        self.__libhsm.get_slot_count.argtypes = [c_char_p, c_ulong, POINTER(c_ulong)]
        self.__libhsm.get_token_count.argtypes = [c_char_p, c_ulong, POINTER(c_ulong)]
        self.__libhsm.get_slot_info.argtypes = [c_char_p, c_ulong, c_char_p, POINTER(c_ulong), POINTER(c_ulong)]
        self.__libhsm.get_attribute_value.argtypes = [c_char_p, c_ulong, c_ulong, c_ulong, c_ulong, c_char_p,
                                                      POINTER(c_ulong)]
        self.__libhsm.seed_random.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong]
        self.__libhsm.unwrap_private_key.argtypes = [c_char_p, c_ulong, c_ulong, c_ulong, c_char_p, c_ulong, c_ulong,
                                                     c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong, c_ulong,
                                                     c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong,
                                                     c_ulong, c_ulong, c_ulong, POINTER(c_ulong)]

        self.__libhsm.create_rsa_key_pair.argtypes = [c_char_p, c_ulong, c_ulong, c_ulong, c_char_p, c_ulong, c_char_p,
                                                      c_ulong, c_char_p, c_ulong, c_char_p, c_ulong,
                                                      c_ulong, c_char_p, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong,
                                                      c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong,
                                                      c_ulong, c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong)]
        self.__libhsm.create_ec_key_pair.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong,
                                                     c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong,
                                                     c_ulong, c_ulong, c_ulong, c_ulong, c_ulong,
                                                     c_ulong, c_ulong, c_ulong,  c_ulong, c_ulong, c_ulong, c_ulong,
                                                     c_ulong, c_ulong, POINTER(c_ulong), POINTER(c_ulong)]
        self.__libhsm.create_secret_key.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong,
                                                    c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong,
                                                    c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong,
                                                    c_ulong, POINTER(c_ulong)]
        self.__libhsm.set_attribute_value.argtypes = [c_char_p, c_ulong, c_ulong, c_ulong, c_ulong, c_char_p, c_ulong]
        self.__libhsm.generate_random.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong]
        self.__libhsm.destroy_object.argtypes = [c_char_p, c_ulong, c_ulong, c_ulong]
        self.__libhsm.import_data_object.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong,
                                                     c_char_p, c_ulong, c_ulong, c_ulong, POINTER(c_ulong)]
        self.__libhsm.import_rsa_public_key.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, c_char_p,
                                                        c_ulong, c_char_p, c_ulong, c_char_p, c_ulong, c_ulong,
                                                        c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong,
                                                        POINTER(c_ulong)]
        self.__libhsm.import_ec_public_key.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong,
                                                       c_char_p, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong,
                                                       c_ulong, c_ulong, POINTER(c_ulong)]
        self.__libhsm.wrap_key.argtypes = [c_char_p, c_ulong, c_ulong, c_ulong, c_ulong, c_char_p, c_ulong, c_ulong,
                                           c_char_p, POINTER(c_ulong)]
        self.__libhsm.unwrap_secret_key.argtypes = [c_char_p, c_ulong, c_ulong, c_ulong, c_char_p, c_ulong, c_ulong,
                                                    c_char_p, c_ulong, c_char_p, c_ulong, c_char_p, c_ulong, c_ulong,
                                                    c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong,
                                                    c_ulong, c_ulong, c_ulong, c_ulong, c_ulong, c_ulong,
                                                    c_ulong, POINTER(c_ulong)]
        self.__libhsm.get_mechanism_info.argtypes = [c_char_p, c_ulong, c_ulong, c_char_p, POINTER(c_ulong),
                                                     POINTER(c_ulong)]

    def __get_libhsm_version(self):
        """ Retrieves the libhsm library version string value. """
        msg = create_string_buffer(self.__messageBufferSize)	
        ver = create_string_buffer(self.__verBufferSize)
        rv = self.__libhsm.get_lib_version(msg, len(msg), ver, len(ver))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        # strip off the empty spaces and the C null terminator 0x00
        ver = ver.value.strip()
        ver = ver[:len(ver)]
        return ver
    
    def __verify_libhsm_version(self):
        """
        Verifies the libhsm library version string matches the expected
        value in the Python library. 
        """
        lib_hsm_version = self.__get_libhsm_version()
        if lib_hsm_version != self.__libhsmVersion:
            raise HsmError("The libhsm shared library returned unexpected version number {0}".format(lib_hsm_version))
        
    def __connect(self, p11_path):
        """ 
        Connect to the HSM PKCS#11 shared library.
        """
        msg = create_string_buffer(self.__messageBufferSize)
        p11_path_bytes = str_to_bytes(p11_path)
        rv = self.__libhsm.connect(msg, len(msg), p11_path_bytes, len(p11_path_bytes))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        self.__connected = True

    def __disconnect(self):
        """ 
        Disconnects from the PKCS#11 shared library. 
        """
        msg = create_string_buffer(self.__messageBufferSize)	
        rv = self.__libhsm.disconnect(msg, len(msg))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        self.__connected = False

    def __initialize(self):
        """ 
        Initializes the PKCS#11 API and shared library. The method __connect()
        method be called first.  Error code CKR_CRYPTOKI_ALREADY_INITIALIZED is not fatal.
        """
        msg = create_string_buffer(self.__messageBufferSize)
        self.__libhsm.initialize(msg, len(msg))
        # TODO: fix filter for already init error that can be safely ignored?
        # rv = self.__libhsm.initialize(msg, len(msg))
        # if (rv == 0):
        #    # handle CKR_CRYPTOKI_ALREADY_INITIALIZED error
        #    if not(self.__ckrCryptokiAlreadyInitialized in msg):
        #        raise HsmError(self.to_ascii_string(msg.value))
        self.__initialized = True

    def __finalize(self):
        """
        Finalize the PKCS#11 API. Release PKCS-11 API resources.
        """
        msg = create_string_buffer(self.__messageBufferSize)    
        rv = self.__libhsm.finalize(msg, len(msg))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        self.__initialized = False
        
    def __enter__(self):
        """
        Method to support Python 'with' statement (enter).
        """
        return self

    def __exit__(self, type_, value, traceback):
        """
        Method to support Python 'with' statement (exit).
        Automatically logs out, closes the session and
        releases the HSM resources.
        """
        self.logout()
        self.close_session()
        self.close()

    def __validate_session(self):
        """
        Validates that a session is open and that a user is logged in.
        """
        if self.sessionHandle == 0:
            raise HsmError("must call open_session() first")
        if not self.__loggedIn:
            raise HsmError("must call login() first")

    def open_session(self,
                     slot,
                     user_type=HsmUser.CryptoOfficer,
                     session_type=HsmSession.ReadWrite):
        """ 
        Opens a new session to the HSM based on the token serial 
        number value. 
    
        Note:
            Most HSMs support simultaneous sessions.  
            
            The method get_slot_info() can be invoked to get a list of 
            available HSM tokens / slots and their various associated
            serial numbers.
        
        Args:
            slot:         HSM token serial slot number.
                          
            user_type:     The type of user you would like to open the
                          session as.  The default is 
                          HsmUser.CryptoOfficer.
                          
            session_type:  The type of session you would like to open.
                          The default is HsmSession.ReadWrite.
        """
        if self.sessionHandle != 0:
            raise HsmError("sessionType is already open")
        if not isinstance(slot, int):
            raise HsmError("slot must be of type int")
        if slot < 0:
            raise HsmError("slot must contain a value 0 or greater")
        if not isinstance(user_type, HsmUser):
            raise HsmError("user_type must be of type HsmUser")
        if not isinstance(session_type, HsmSession):
            raise HsmError("session_type must be of type HsmSession")
        if session_type is HsmSession.Undefined:
            raise HsmError("session_type cannot be of type Undefined")
        if user_type is HsmUser.SecurityOfficer:
            if session_type is HsmUser.ReadWrite:
                session_type = HsmUser.SecurityOfficerReadWrite
            else:
                if session_type is HsmSession.Exclusive:
                    session_type = HsmSession.SecurityOfficerExclusive
        msg = create_string_buffer(self.__messageBufferSize)	 

        h_session_ptr = c_ulong()
        # open a session on the HSM 
        rv = self.__libhsm.open_session(msg,
                                        len(msg),
                                        slot,
                                        session_type.value,
                                        byref(h_session_ptr))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        # dereference the session return value
        self.sessionHandle = h_session_ptr.value
        # retain the other values
        self.slotNumber = slot
        self.userType = user_type

    def close_session(self):
        """
        Closes the open session to the token.  This method will not
        cause an error if the session is already closed.

        Args:
            (none)

        """
        if self.sessionHandle == 0:
            return
        msg = create_string_buffer(self.__messageBufferSize)
        rv = self.__libhsm.close_session(msg,
                                         len(msg),
                                         self.sessionHandle)
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        self.sessionHandle = 0
        self.slotNumber = 0
        self.tokenSerialNumber = ''
        self.__loggedIn = False

    def close_all_sessions(self, slot):
        """
        Closes all open sessions on the token for a specific slot
        number.

        Args:
            slot:  The slot value which to close all session on.

        """
        if not isinstance(slot, int):
            raise HsmError("slot must be of type int")
        if slot < 0:
            raise HsmError("invalid slot")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        rv = self.__libhsm.close_all_sessions(msg,
                                              len(msg),
                                              slot)
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        if slot == self.slotNumber:
            self.sessionHandle = 0
            self.slotNumber = 0
            self.__loggedIn = False

    def close(self):
        """
        This call may be required when using the HsmClient with specific
        HSM PKCS#11 libraries and the Python automatic management features are
        not utilized.  The method will only call the P11 API C_Finalize() if
        the P11 API C_Initialize() was previously called.
        """
        if self.__initialized:
            self.__finalize()

    def login(self, pin):
        """
        Log into the HSM using a PIN value.  The PIN value is also
        known as the partition password for some HSMs.

        Args:
            pin: HSM PIN or partition password value; can be str or bytes

        """
        if self.sessionHandle == 0:
            raise HsmError("must call open_session() first")
        if not isinstance(pin, bytes) and not isinstance(pin, str):
            raise HsmError("pin must be of type bytes or str")

        msg = create_string_buffer(self.__messageBufferSize)
        pin_bytes = str_to_bytes(pin)
        rv = self.__libhsm.login(msg, len(msg),
                                 self.sessionHandle,
                                 self.userType.value,
                                 pin_bytes,
                                 len(pin_bytes))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        self.__loggedIn = True

    def logout(self):
        """ Log out of the HSM. """
        if self.sessionHandle == 0:
            return

        msg = create_string_buffer(self.__messageBufferSize)
        rv = self.__libhsm.logout(msg,
                                  len(msg),
                                  self.sessionHandle)
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        self.__loggedIn = False

    def set_pin(self, old_pin, new_pin):
        """ Set a new PIN value for the HSM. """
        if not isinstance(old_pin, bytes) and not isinstance(old_pin, str):
            raise HsmError("old_pin must be of type bytes or str")
        if not isinstance(new_pin, bytes) and not isinstance(new_pin, str):
            raise HsmError("new_pin must be of type bytes or str")

        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        old_pin_bytes = str_to_bytes(old_pin)
        new_pin_bytes = str_to_bytes(new_pin)
        rv = self.__libhsm.set_pin(msg,
                                   len(msg),
                                   self.sessionHandle,
                                   old_pin_bytes,
                                   len(old_pin_bytes),
                                   new_pin_bytes,
                                   len(new_pin_bytes))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))

    def get_object_handle(self, label):
        """
        Locates a numeric get_object handle from the token based on
        a get_object's label (human readable name).

        Notes:
            Some HSMs allow for multiple objects to have the same label.
            This method will only retrieve the first object handle
            that matches the ASCII label value provided by the caller.
            A complete list of HSM get_objects visible to the logged in
            user can be obtained by calling the HsmClient.get_objects()
            method.

        Args:
            label: object label to locate on the HSM.

        Returns:
            Object handle if located; otherwise 0.
        """
        if not isinstance(label, str):
            raise HsmError("label must be of type str")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        h_object_ptr = c_ulong()
        label_bytes = str_to_bytes(label)
        rv = self.__libhsm.get_object_handle(msg,
                                             len(msg),
                                             self.sessionHandle,
                                             label_bytes,
                                             len(label_bytes),
                                             byref(h_object_ptr))

        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        h_object = h_object_ptr.value
        return h_object

    def get_attribute_value(self,
                            handle,
                            attribute_type=HsmAttribute.LABEL):
        """
        Retrieves the specified HSM get_object attribute data from the
        HSM based on a HSM object's handle.

        Note:
            This method allows the caller to query the HSM using an
            get_object's handle to retrieve data that has been deemed
            accessible or non-sensitive meta data about the get_objects.
            The method HsmClient.get_object() can be used to query
            all known attributes about a HSM get_object and returns a
            HsmObject get_object that can be inspected by the caller.

        Args:
            handle:         HSM get_object handle to query for attribute values

            attribute_type:  The type of attribute to query for.
                            The default is HsmAttribute (default: LABEL).

        Returns:
            Attribute data as bytes
        """
        if not isinstance(handle, int):
            raise HsmError("handle must be of type int")
        if handle <= 0:
            raise HsmError("handle must be a value greater than zero")
        if not isinstance(attribute_type, HsmAttribute):
            raise HsmError("attributeType must be of type HsmAttribute")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        buf = create_string_buffer(self.__attributeBufferSize)
        but_len_ptr = c_ulong(len(buf))
        rv = self.__libhsm.get_attribute_value(msg,
                                               len(msg),
                                               self.sessionHandle,
                                               handle,
                                               attribute_type.value,
                                               buf,
                                               byref(but_len_ptr))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        # dereference the buffer length pointer
        buf_len = but_len_ptr.value
        # resize the buffer based on the return value size
        buf = buf[:buf_len]
        # return the binary data - note that Python will attempt to assign letters to any binary data
        # values that fall within the ASCII code numbers and will make data appear odd in the Python interpreter
        return buf

    def get_object(self, handle, fast_load=False):
        """
        Returns an HsmObject that is filled with the get_object's
        attribute data as properties of a HsmObject instance.

        Note:
            This method is very helpful in retrieving meta-data and
            other types of attribute data from an get_object on the HSM.

        Args:
            handle:     HSM get_object handle to retrieve information about.

            fast_load: query and load only the most basic HSM attributes
                       (default: False).

        Returns:
            HsmObject containing all available attribute data about
            the get_object.
        """
        if not isinstance(handle, int):
            raise HsmError("handle must be of type int")
        if handle <= 0:
            raise HsmError("object handle must be > 0")
        self.__validate_session()
        if not self.does_object_exist(handle):
            raise HsmError("object with handle {0} not found on HSM".format(handle))
        return HsmObject(self, handle, fast_load)

    def get_objects(self, fast_load=False):
        """
        Gets a list of HsmObjects that are filled with the get_object's
        attribute data as properties of a HsmObject instance.

        Note:
            This method is very helpful in retrieving meta-data and
            other types of attribute data about all get_objects
            available on the HSM.

        Args:
            fast_load: query and load only the most basic HSM attributes
                       (default: False).

        Returns:
            A list data structure of HsmObjects containing all
            available attribute data about the individual get_objects.
        """
        handles = self.find_objects()
        d = []
        for h in handles:
            o = self.get_object(h, fast_load)
            d.append(o)
        return d

    def find_objects(self):
        """
        Gets a list of HSM object handles.

        Note:
            This method is very helpful in retrieving the unique HSM
            object handles for a particular token.

        Args:
            (none)

        Returns:
            A list of object integer values.
        """
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        # note that PyCharm will complain about the construction of the following statement
        # but do not be tempted to remove the parenthesis as they are needed to construct a
        # pointer to the C-int array
        array_ptr = (c_ulong * self.__findObjectsArraySize)()
        array_ptr_len = c_ulong(self.__findObjectsArraySize)
        rv = self.__libhsm.find_objects(msg,
                                        len(msg),
                                        self.sessionHandle,
                                        array_ptr,
                                        byref(array_ptr_len))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        array_len = array_ptr_len.value
        # loop the binary data array and convert to list of int32 values
        handles = []
        i = 0
        while i < array_len:
            handles.append(array_ptr[i])
            i += 1
        return handles

    def does_object_exist(self, handle):
        """
        Tests to see if an object on the HSM exists by querying for the
        LABEL property and check the result.

        Note:
            This method performs the test by attempting to retrieve
            the LABEL attribute value for a particular handle.  The
            LABEL value should be accessible for all valid objects
            on the HSM that he user has the ability to query for.

        Args:
            handle: HSM get_object handle

        Returns:
            True if the object exists; otherwise False
        """
        if not isinstance(handle, int):
            raise HsmError("handle must be of type int")
        self.__validate_session()
        try:
            self.get_attribute_value(handle, HsmAttribute.LABEL)
        except:
            return False
        return True

    def get_slot_count(self):
        """
        Retrieves the number of slots available.

        Note:
            For many HSMs the slot count and token count are the same
            value.  This method may be called without first opening a
            session to the HSM.

        Args:
            (none)

        Returns:
            Integer value representing the number of slots found.
        """
        msg = create_string_buffer(self.__messageBufferSize)
        slot_count_ptr = c_ulong()
        rv = self.__libhsm.get_slot_count(msg,
                                          len(msg),
                                          byref(slot_count_ptr))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        slot_count = slot_count_ptr.value
        return slot_count

    def get_token_count(self):
        """
        Retrieves the number of token available.

        Note:
            For many HSMs the slot count and token count are the same
            value.  This method may be called without first opening
            a session to the HSM.

        Args:
            (none)

        Returns:
            Integer value representing the number of tokens found.
        """
        msg = create_string_buffer(self.__messageBufferSize)
        token_counter_ptr = c_ulong()
        rv = self.__libhsm.get_token_count(msg,
                                           len(msg),
                                           byref(token_counter_ptr))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        token_count = token_counter_ptr.value
        return token_count

    def get_slot_info(self):
        """
        Retrieves information about the HSM slots / tokens visible to
        the HSM client user.  This method may be called without first
        opening a session to the HSM.

        Args:
            (none)

        Returns:
            List of HsmSlot objects.
        """
        msg = create_string_buffer(self.__messageBufferSize)
        buf = create_string_buffer(self.__hsmInfoBufferSize)
        buf_len_ptr = c_ulong(len(buf))
        token_count_ptr = c_ulong()
        # make the call
        rv = self.__libhsm.get_slot_info(msg,
                                         len(msg),
                                         buf,
                                         byref(buf_len_ptr),
                                         byref(token_count_ptr))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        # test if the token count is greater than 0 then trim the buffer
        # and split into a set of lines
        lines = ''
        buf = bytes_to_str(buf.value)
        if token_count_ptr.value > 0:
            buf_len = buf_len_ptr.value
            buf = buf[:buf_len]
            lines = str(buf).split('\n')
        s_list = []
        for line in lines:
            s_list.append(HsmSlot(line))
        return s_list

    def sign(self,
             handle,
             data,
             mechanism,
             pss_salt_length=0):
        """
        Cryptographically sign supplied data using referenced
        get_object handle and signing algorithm mechanism
        specified.

        Args:
            handle:           HSM object handle

            data:             byte of array of data to sign

            mechanism:        the algorithm (CKM mechanism) to use
                              which can be provided as HsmMech enumeration,
                              integer or hex value

            pss_salt_length:  the length of the PSS salt value (optional
                              and used when with PSS mechanisms only)

        Returns:
            Byte array containing digital signature.
        """
        if not isinstance(handle, int):
            raise HsmError("handle must be of type int")
        if not isinstance(data, bytes):
            raise HsmError("data must be of type bytes")
        if len(data) <= 0:
            raise HsmError("data must have length 1 or greater")
        if isinstance(mechanism, HsmMech):
            mechanism = mechanism.value
        if not isinstance(mechanism, int):
            raise HsmError("mechanism must be of type int (numeric or hex) or HsmMech")
        if not isinstance(pss_salt_length, int):
            raise HsmError("pss_salt_length must be of type int")
        if pss_salt_length < 0:
            raise HsmError("pss_salt_length must be 0 or greater")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        buf = create_string_buffer(self.__signBufferSize)
        buf_len_ptr = c_ulong(len(buf))

        rv = self.__libhsm.sign(msg,
                                len(msg),
                                self.sessionHandle,
                                data,
                                len(data),
                                handle,
                                mechanism,
                                pss_salt_length,
                                buf,
                                byref(buf_len_ptr))

        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        buf_len = buf_len_ptr.value
        buf = buf[:buf_len]
        return buf

    def verify(self,
               handle,
               data,
               signature,
               mechanism,
               pss_salt_length=0):
        """
        Cryptographically verify digital signature using referenced
        get_object handle and signing algorithm mechanism specified.
        Data and signature variables should be supplied as bytes
        in the form b'\x00\x01\x03'.

        Args:
            handle:          HSM object handle

            data:            byte array of data to sign

            signature:       byte array of digital signature to verify

            mechanism:       the algorithm (CKM mechanism) to use
                             which can be provided as HsmMech enumeration,
                             integer or hex value

            pss_salt_length: the length of the PSS salt value (optional
                             and used when with PSS mechanisms only)

        Returns:
            True if signature is valid; otherwise false.
        """
        if not isinstance(handle, int):
            raise HsmError("handle must be of type int")
        if not isinstance(data, bytes):
            raise HsmError("data must be of type bytes")
        if len(data) <= 0:
            raise HsmError("data must have length 1 or greater")
        if not isinstance(signature, bytes):
            raise HsmError("signature must be of type bytes")
        if len(signature) <= 0:
            raise HsmError("signature must have length 1 or greater")
        if isinstance(mechanism, HsmMech):
            mechanism = mechanism.value
        if not isinstance(mechanism, int):
            raise HsmError("mechanism must be of type int (numeric or hex) or HsmMech")
        if pss_salt_length < 0:
            raise HsmError("pss_salt_length must be 0 or greater")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        rv = self.__libhsm.verify(msg,
                                  len(msg),
                                  self.sessionHandle,
                                  data,
                                  len(data),
                                  handle,
                                  mechanism,
                                  pss_salt_length,
                                  signature,
                                  len(signature))
        if rv == 0:
            if self.__ckrSignatureInvalidString in msg:
                return False
            raise HsmError(bytes_to_str(msg.value))
        return True

    def encrypt(self,
                handle,
                data,
                mechanism,
                iv=b'\x00'):
        """
        Encrypt supplied data using referenced handle and
        encryption algorithm mechanism.

        Args:
            handle:         HSM object handle

            data:           byte array of clear-text data to encrypt

            mechanism:      the algorithm (CKM mechanism) to use
                            which can be provided as HsmMech enumeration,
                            integer or hex value

            iv:             initialization vector byte array (optional)
                            The IV data must be provided for CBC mode
                            encrypt algorithms.

        Returns:
            Byte array of cipher-text data.
        """
        if not isinstance(handle, int):
            raise HsmError("handle must be of type int")
        if not isinstance(data, bytes):
            raise HsmError("data must be of type bytes")
        if len(data) <= 0:
            raise HsmError("data must have length 1 or greater")
        if not isinstance(iv, bytes):
            raise HsmError("iv must be of type bytes")
        if len(iv) < 0:
            raise HsmError("iv must have length 0 or greater")
        if isinstance(mechanism, HsmMech):
            mechanism = mechanism.value
        if not isinstance(mechanism, int):
            raise HsmError("mechanism must be of type int (numeric or hex) or HsmMech")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)

        if mechanism == HsmMech.RSA_PKCS_OAEP:
            buf_size = self.__oaepBufferSize
        else:
            buf_size = len(data) + self.__encryptBufferPaddingAdjustment
        buf = create_string_buffer(buf_size)
        buf_len_ptr = c_ulong(len(buf))
        rv = self.__libhsm.encrypt(msg,
                                   len(msg),
                                   self.sessionHandle,
                                   data,
                                   len(data),
                                   handle,
                                   mechanism,
                                   iv,
                                   len(iv),
                                   buf,
                                   byref(buf_len_ptr))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        buf_len = buf_len_ptr.value
        buf = buf[:buf_len]
        return buf

    def decrypt(self,
                handle,
                data,
                mechanism,
                iv=b'\x00'):
        """
        Decrypt supplied data using referenced object handle and
        algorithm mechanism.

        Args:
            handle:         HSM object handle

            data:           byte array of cipher-text data to decrypt

            mechanism:      the algorithm (CKM mechanism) to use
                            which can be provided as HsmMech enumeration,
                            integer or hex value

            iv:             initialization vector byte array (optional)
                            The IV data must be provided for CBC mode
                            mechanisms.

        Returns:
            Byte array of clear-text data.
        """
        if not isinstance(handle, int):
            raise HsmError("handle must be of type int")
        if not isinstance(data, bytes):
            raise HsmError("data must be of type bytes")
        if len(data) <= 0:
            raise HsmError("data must have length 1 or greater")
        if not isinstance(iv, bytes):
            raise HsmError("iv must be of type bytes")
        if len(iv) < 0:
            raise HsmError("iv must have length 0 or greater")
        if isinstance(mechanism, HsmMech):
            mechanism = mechanism.value
        if not isinstance(mechanism, int):
            raise HsmError("mechanism must be of type int (numeric or hex) or HsmMech")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        buf_size = len(data)
        buf = create_string_buffer(buf_size)
        buf_len_ptr = c_ulong(len(buf))
        rv = self.__libhsm.decrypt(msg,
                                   len(msg),
                                   self.sessionHandle,
                                   data,
                                   len(data),
                                   handle,
                                   mechanism,
                                   iv,
                                   len(iv),
                                   buf,
                                   byref(buf_len_ptr))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        buf_len = buf_len_ptr.value
        buf = buf[:buf_len]
        return buf

    def digest(self,
               data,
               mechanism):
        """
        Compute digest (cryptographic hash) on supplied data.

        Args:
            data:           byte array of data to computer digest on

            mechanism:      the algorithm (CKM mechanism) to use
                            which can be provided as HsmMech enumeration,
                            integer or hex value

        Returns:
            Byte array of hash data.
        """
        if not isinstance(data, bytes):
            raise HsmError("data must be of type bytes")
        if len(data) <= 0:
            raise HsmError("data must have length 1 or greater")
        if isinstance(mechanism, HsmMech):
            mechanism = mechanism.value
        if not isinstance(mechanism, int):
            raise HsmError("mechanism must be of type int (numeric or hex) or HsmMech")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        buf = create_string_buffer(self.__digestBufferSize)
        buf_len_ptr = c_ulong(len(buf))
        rv = self.__libhsm.digest(msg,
                                  len(msg),
                                  self.sessionHandle,
                                  data,
                                  len(data),
                                  mechanism,
                                  buf,
                                  byref(buf_len_ptr))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        buf_len = buf_len_ptr.value
        buf = buf[:buf_len]
        return buf

    def seed_random_hashfold(self, entropy):
        """
        Seeds the HSM's PRNG by hashing the supplied entropy
        and then folding the hash value over the original value
        via XOR operations.

        Note:
            The entropy source can be public data such as part of
            RSA public modulus key or other non-secret sources. This
            function will hash the entropy using the SHA-256 algorithm
            on the HSM and then the hash result is bitwise XOR'd with
            the original entropy bytes to produce the seed_random
            value to feed to the HSM PRNG.

        Args:
            entropy:    byte array of entropy

        Returns:

        """
        if not isinstance(entropy, bytes):
            raise HsmError("entropy must be of type bytes")
        if len(entropy) < self.__minReseedEntropySize:
            raise HsmError("entropy must have length {0} bytes or greater".format(self.__minReseedEntropySize))
        self.__validate_session()
        hash_value = self.digest(entropy, HsmMech.SHA256)
        # fold the hash value over the originally entropy value via a bitwise XOR operation
        folded = bytearray(entropy)
        for i in range(len(hash_value)):
            folded[i] ^= hash_value[i]
        self.seed_random(bytes(folded))

    def seed_random(self, seed):
        """
        Seeds the HSM's PRNG directly using the supplied binary
        seed value.

        Args:
            seed:    byte array of seed data

        Returns:

        """
        if not isinstance(seed, bytes):
            raise HsmError("seed must be of type bytes")
        if len(seed) <= 0:
            raise HsmError("seed_random must have length 1 or greater")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        rv = self.__libhsm.seed_random(msg, len(msg), self.sessionHandle, seed, len(seed))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))

    def unwrap_private_key(self,
                           wrap_key_handle,
                           wrap_key_mechanism,
                           wrap_key_iv,
                           key_label,
                           key_data,
                           key_id=None,
                           key_type=HsmAsymKeyType.RSA,
                           token=True,
                           private=True,
                           sensitive=True,
                           modifiable=False,
                           extractable=True,
                           sign=True,
                           decrypt=True,
                           unwrap=False,
                           derive=False,
                           overwrite=False):
        """
        Unwraps (decrypts and installs) a secret asymmetric private key
        on the HSM using the specified wrapping key, iv, and
        decryption algorithm HSM mechanism.

        Args:
            wrap_key_handle:      HSM handle of wrapping key

            wrap_key_mechanism:   wrapping key mechanism

            wrap_key_iv:          wrapping key Initialization value

            key_label:            label to name the key after unwrap

            key_data:             cipher-text data containing wrapped
                                  key

            key_id:               id value of unwrapped key
                                  Note: a random 16 byte value will be generated
                                  and assigned if an ID is not provided

            key_type:             type of key (HsmAsymKeyType)

            token:                set to True if key should persist on
                                  the HSM token after session ends
                                  (CKA_TOKEN)

            private:              set to True if the key is private and
                                  should only be visible by the user
                                  (CKA_PRIVATE)

            sensitive:            set to True if the private key is sensitive and
                                  should be protected by the HSM and cannot be
                                  revealed in plaintext off the token (CKA_SENSITIVE)

            modifiable:           set to True if the key can be modified
                                  after unwrapped on the HSM (CKA_MODIFIABLE)

            extractable:          set to True if the key can be extracted
                                  (unwrapped) off the HSM (CKA_EXTRACTABLE)

            sign:                 set to True if the key is allowed to be
                                  used in signing operations (CKA_SIGN)

            decrypt:              set to True if the key is allowed to be
                                  used in decryption operations (CKA_DECRYPT)

            unwrap:               set to True if the key is allowed to be
                                  used in un-wrapping operations (CKA_UNWRAP)

            derive:               set to True if the key is allowed to be
                                  used to derive other keys (CKA_DERIVE)

            overwrite:            set to True if the unwrapped key should
                                  overwrite any existing keys with the same
                                  label

        Returns:
            Private key handle.
        """

        self.__validate_session()
        if not isinstance(wrap_key_handle, int):
            raise HsmError("wrap_key_handle must be of type int")
        if wrap_key_handle <= 0:
            raise HsmError("wrap_key_handle invalid")
        if not isinstance(wrap_key_mechanism, HsmMech):
            raise HsmError("wrap_key_mechanism must be of type HsmMech")
        if not isinstance(wrap_key_iv, bytes):
            raise HsmError("wrap_key_iv must be of type bytes")
        if len(wrap_key_iv) <= 0:
            raise HsmError("wrap_key)iv must have length 1 or greater")
        if not isinstance(key_label, str):
            raise HsmError("key_label must be of type str")
        if len(key_label) <= 0:
            raise HsmError("key_label must have length 1 or greater")
        if not isinstance(key_data, bytes):
            raise HsmError("key_data must be of type bytes")
        if len(key_data) <= 0:
            raise HsmError("key_data must have length 1 or greater")
        if key_id is None:
            key_id = os.urandom(self.__idRandomSize)
        if not isinstance(key_id, bytes):
            raise HsmError("key_id must be of type bytes")
        if not isinstance(key_type, HsmAsymKeyType):
            raise HsmError("key_type must be of type HsmAsymKeyType")
        if not isinstance(token, bool):
            raise HsmError("token must be of type bool")
        if not isinstance(private, bool):
            raise HsmError("private must be of type bool")
        if not isinstance(sensitive, bool):
            raise HsmError("sensitive must be of type bool")
        if not isinstance(modifiable, bool):
            raise HsmError("modifiable must be of type bool")
        if not isinstance(extractable, bool):
            raise HsmError("extractable must be of type bool")
        if not isinstance(sign, bool):
            raise HsmError("sign must be of type bool")
        if not isinstance(decrypt, bool):
            raise HsmError("decrypt must be of type bool")
        if not isinstance(unwrap, bool):
            raise HsmError("unwrap must be of type bool")
        if not isinstance(derive, bool):
            raise HsmError("derive must be of type bool")
        if not isinstance(overwrite, bool):
            raise HsmError("overwrite must be of type bool")

        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        key_label_bytes = str_to_bytes(key_label)
        h_pvt_key = c_ulong()
        rv = self.__libhsm.unwrap_private_key(msg,
                                              len(msg),
                                              self.sessionHandle,
                                              wrap_key_handle,
                                              wrap_key_iv,
                                              len(wrap_key_iv),
                                              wrap_key_mechanism.value,
                                              key_label_bytes,
                                              len(key_label_bytes),
                                              key_id,
                                              len(key_id),
                                              key_data,
                                              len(key_data),
                                              key_type.value,
                                              token,
                                              private,
                                              sensitive,
                                              modifiable,
                                              extractable,
                                              sign,
                                              decrypt,
                                              unwrap,
                                              derive,
                                              overwrite,
                                              byref(h_pvt_key))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        h_pvt_key = h_pvt_key.value
        if h_pvt_key == 0:
            raise HsmError("private key handle returned from HSM is invalid")
        return h_pvt_key

    def create_rsa_key_pair(self,
                            public_key_label,
                            private_key_label,
                            public_key_id=None,
                            private_key_id=None,
                            mechanism=HsmMech.RSA_PKCS_KEY_PAIR_GEN,
                            key_length=2048,
                            public_exponent=b'\x01\x00\x01',
                            token=True,
                            public_private=True,
                            private_private=True,
                            sensitive=True,
                            modifiable=False,
                            extractable=True,
                            sign_verify=True,
                            encrypt_decrypt=True,
                            wrap_unwrap=True,
                            derive=False,
                            overwrite=False):
        """
        Creates a new RSA key pair on the HSM with the specified
        attributes.

        Args:
            public_key_label:     text label of the new public key

            private_key_label:    text label of the new private key

            public_key_id:        id value of the new public key
                                  Note: a random 16 byte value will be generated
                                  and assigned if an ID is not provided

            private_key_id:       id value of the new private key
                                  Note: a random 16 byte value will be generated
                                  and assigned if an ID is not provided

            mechanism:            mechanism type (usually CKM_RSA_X9_31_KEY_PAIR_GEN or CKM_RSA_PKCS_KEY_PAIR_GEN)
                                  Note: CKM_RSA_X9_31_KEY_PAIR_GEN is functionally identical to
                                  CKM_RSA_PKCS_KEY_PAIR_GEN but provides a stronger guarantee of p and q values as
                                  defined in X9.31.  Cavium only supports CKM_RSA_X9_31_KEY_PAIR_GEN.

            key_length:           length in bits of the RSA private key

            public_exponent:      public exponent value

            token:                set to True if keys should persist on
                                  the HSM token after session ends (CKA_TOKEN)

            public_private:       set to True if the public key is HSM private and
                                  should only be visible by the user (CKA_PRIVATE)

            private_private:      set to True if the private key is HSM private and
                                  should only be visible by the user (CKA_PRIVATE)

            sensitive:            set to True if the private key is sensitive and
                                  should be protected by the HSM and cannot be
                                  revealed in plaintext off the token (CKA_SENSITIVE)

            modifiable:           set to True if the keys can be modified
                                  after unwrapped on the HSM (CKA_MODIFIABLE)

            extractable:          set to True if the private portion can be extracted
                                  (unwrapped) off the HSM (CKA_EXTRACTABLE)

            sign_verify:          set to True if the keys are allowed to be
                                  used in sign and verify operations
                                  (CKA_SIGN, CKA_VERIFY)

            encrypt_decrypt:      set to True if the keys are allowed to be
                                  used in encrypt and decrypt operations
                                  (CKA_ENCRYPT, CKA_DECRYPT)

            wrap_unwrap:          set to True if the keys are allowed to be
                                  used in wrap and unwrap operations
                                  (CKA_WRAP, CKA_UNWRAP)

            derive:               set to True if the private key is allowed
                                  to be used to derive other keys (CKA_DERIVE)

            overwrite:            set to True if the new keys should
                                  overwrite any existing keys with the same
                                  label

        Returns:
            set containing the public key object handle and the private key
            handle on the HSM.

        """
        if not isinstance(public_key_label, str):
            raise HsmError("public_key_label must be of type str")
        if len(public_key_label) <= 0:
            raise HsmError("public_key_label must have length 1 or greater")
        if not isinstance(private_key_label, str):
            raise HsmError("public_key_label must be of type str")
        if len(private_key_label) <= 0:
            raise HsmError("private_key_label must have length 1 or greater")
        if public_key_id is None and private_key_id is None:
            pair_id = os.urandom(self.__idRandomSize)
            public_key_id = pair_id
            private_key_id = pair_id
        if public_key_id is None:
            public_key_id = os.urandom(self.__idRandomSize)
        if not isinstance(public_key_id, bytes):
            raise HsmError("public_key_id must be of type bytes")
        if private_key_id is None:
            private_key_id = public_key_id
        if not isinstance(private_key_id, bytes):
            raise HsmError("private_key_id must be of type bytes")
        if isinstance(mechanism, HsmMech):
            mechanism = mechanism.value
        if not isinstance(mechanism, int):
            raise HsmError("mechanism must be of type int (numeric or hex) or HsmMech")
        if not isinstance(key_length, int):
            raise HsmError("key_length must be of type int")
        if not isinstance(public_exponent, bytes):
            raise HsmError("public_exponent must be of type bytes")
        if len(public_exponent) <= 0:
            raise HsmError("public_exponent must have length 1 or greater")
        if not isinstance(token, bool):
            raise HsmError("token must be of type bool")
        if not isinstance(public_private, bool):
            raise HsmError("public_private must be of type bool")
        if not isinstance(private_private, bool):
            raise HsmError("private_private must be of type bool")
        if not isinstance(sensitive, bool):
            raise HsmError("sensitive must be of type bool")
        if not isinstance(modifiable, bool):
            raise HsmError("modifiable must be of type bool")
        if not isinstance(extractable, bool):
            raise HsmError("extractable must be of type bool")
        if not isinstance(sign_verify, bool):
            raise HsmError("sign_verify must be of type bool")
        if not isinstance(encrypt_decrypt, bool):
            raise HsmError("encrypt_decrypt must be of type bool")
        if not isinstance(wrap_unwrap, bool):
            raise HsmError("unwrap must be of type bool")
        if not isinstance(derive, bool):
            raise HsmError("derive must be of type bool")
        if not isinstance(overwrite, bool):
            raise HsmError("overwrite must be of type bool")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        pub_key_label_bytes = str_to_bytes(public_key_label)
        pvt_key_label_bytes = str_to_bytes(private_key_label)
        h_pub_key_ptr = c_ulong()
        h_pvt_key_ptr = c_ulong()
        rv = self.__libhsm.create_rsa_key_pair(msg,
                                               len(msg),
                                               self.sessionHandle,
                                               key_length,
                                               pub_key_label_bytes,
                                               len(pub_key_label_bytes),
                                               pvt_key_label_bytes,
                                               len(pvt_key_label_bytes),
                                               public_key_id,
                                               len(public_key_id),
                                               private_key_id,
                                               len(private_key_id),
                                               mechanism,
                                               public_exponent,
                                               len(public_exponent),
                                               token,
                                               public_private,
                                               private_private,
                                               sensitive,
                                               modifiable,
                                               extractable,
                                               sign_verify,
                                               sign_verify,
                                               encrypt_decrypt,
                                               encrypt_decrypt,
                                               wrap_unwrap,
                                               wrap_unwrap,
                                               derive,
                                               overwrite,
                                               byref(h_pub_key_ptr),
                                               byref(h_pvt_key_ptr))

        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        h_pub_key = h_pub_key_ptr.value
        h_pvt_key = h_pvt_key_ptr.value
        if h_pub_key == 0:
            raise HsmError("public key handle returned from HSM is invalid")
        if h_pvt_key == 0:
            raise HsmError("private key handle returned from HSM is invalid")
        return h_pub_key, h_pvt_key

    def create_ecc_key_pair(self,
                            public_key_label,
                            private_key_label,
                            public_key_id=None,
                            private_key_id=None,
                            ec_params=EcCurveOids.P256,
                            token=True,
                            public_private=True,
                            private_private=True,
                            sensitive=True,
                            modifiable=False,
                            extractable=True,
                            sign_verify=True,
                            encrypt_decrypt=True,
                            wrap_unwrap=True,
                            derive=False,
                            overwrite=False):
        """
        Creates a new ECC key pair on the HSM with the specified
        attributes.

        Args:
            public_key_label:     text label of the new public key

            private_key_label:    text label of the new private key

            public_key_id:        id value of the new public key
                                  Note: a random 16 byte value will be generated
                                  and assigned if an ID is not provided

            private_key_id:       id value of the new private key
                                  Note: a random 16 byte value will be generated
                                  and assigned if an ID is not provided

            ec_params:            DER encoded EC curve parameters or
                                  EC curve OID as bytes data type.
                                  Use the enum EcCurveOids (recommended) or
                                  EcCurves when possible to provide the
                                  ec_params binary value.
                                  (default EcCurveOids.P256)

            token:                set to True if keys should persist on
                                  the HSM token after session ends (CKA_TOKEN)

            public_private:       set to True if the public key is HSM private and
                                  should only be visible by the user (CKA_PRIVATE)

            private_private:      set to True if the private key is HSM private and
                                  should only be visible by the user (CKA_PRIVATE)

            sensitive:            set to True if the private key is sensitive and
                                  should be protected by the HSM and cannot be
                                  revealed in plaintext off the token (CKA_SENSITIVE)

            modifiable:           set to True if the keys can be modified
                                  after unwrapped on the HSM (CKA_MODIFIABLE)

            extractable:          set to True if the private portion can be extracted
                                  (unwrapped) off the HSM (CKA_EXTRACTABLE)

            sign_verify:          set to True if the keys are allowed to be
                                  used in sign and verify operations
                                  (CKA_SIGN, CKA_VERIFY)

            encrypt_decrypt:      set to True if the keys are allowed to be
                                  used in encrypt and decrypt operations
                                  (CKA_ENCRYPT, CKA_DECRYPT)

            wrap_unwrap:          set to True if the keys are allowed to be
                                  used in wrap and unwrap operations
                                  (CKA_WRAP, CKA_UNWRAP)

            derive:               set to True if the private key is allowed
                                  to be used to derive other keys (CKA_DERIVE)

            overwrite:            set to True if the new keys should
                                  overwrite any existing keys with the same
                                  label

        Returns:
            Set containing the public key object handle and the private key
            handle on the HSM.

        """
        if not isinstance(public_key_label, str):
            raise HsmError("public_key_label must be of type str")
        if len(public_key_label) <= 0:
            raise HsmError("public_key_label must have length 1 or greater")
        if not isinstance(private_key_label, str):
            raise HsmError("public_key_label must be of type str")
        if len(private_key_label) <= 0:
            raise HsmError("private_key_label must have length 1 or greater")
        if public_key_id is None and private_key_id is None:
            pair_id = os.urandom(self.__idRandomSize)
            public_key_id = pair_id
            private_key_id = pair_id
        if public_key_id is None:
            public_key_id = os.urandom(self.__idRandomSize)
        if not isinstance(public_key_id, bytes):
            raise HsmError("public_key_id must be of type bytes")
        if private_key_id is None:
            private_key_id = os.urandom(self.__idRandomSize)
        if not isinstance(private_key_id, bytes):
            raise HsmError("private_key_id must be of type bytes")
        if isinstance(ec_params, EcCurveOids) or isinstance(ec_params, EcCurves):
            ec_params = ec_params.value
        if not isinstance(ec_params, bytes):
            raise HsmError("ec_params must be of type bytes, EcCurveOids, or EcCurves")
        if len(ec_params) <= 0:
            raise HsmError("ec_params must have length 1 or greater")
        if not isinstance(token, bool):
            raise HsmError("token must be of type bool")
        if not isinstance(public_private, bool):
            raise HsmError("public_private must be of type bool")
        if not isinstance(private_private, bool):
            raise HsmError("private_private must be of type bool")
        if not isinstance(sensitive, bool):
            raise HsmError("sensitive must be of type bool")
        if not isinstance(modifiable, bool):
            raise HsmError("modifiable must be of type bool")
        if not isinstance(extractable, bool):
            raise HsmError("extractable must be of type bool")
        if not isinstance(sign_verify, bool):
            raise HsmError("sign_verify must be of type bool")
        if not isinstance(encrypt_decrypt, bool):
            raise HsmError("encrypt_decrypt must be of type bool")
        if not isinstance(wrap_unwrap, bool):
            raise HsmError("unwrap must be of type bool")
        if not isinstance(derive, bool):
            raise HsmError("derive must be of type bool")
        if not isinstance(overwrite, bool):
            raise HsmError("overwrite must be of type bool")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        pub_key_label_bytes = str_to_bytes(public_key_label)
        pvt_key_label_bytes = str_to_bytes(private_key_label)
        h_pub_key_ptr = c_ulong()
        h_pvt_key_ptr = c_ulong()
        rv = self.__libhsm.create_ec_key_pair(msg,
                                              len(msg),
                                              self.sessionHandle,
                                              ec_params,
                                              len(ec_params),
                                              pub_key_label_bytes,
                                              len(pub_key_label_bytes),
                                              pvt_key_label_bytes,
                                              len(pvt_key_label_bytes),
                                              public_key_id,
                                              len(public_key_id),
                                              private_key_id,
                                              len(private_key_id),
                                              token,
                                              public_private,
                                              private_private,
                                              sensitive,
                                              modifiable,
                                              extractable,
                                              sign_verify,
                                              sign_verify,
                                              encrypt_decrypt,
                                              encrypt_decrypt,
                                              wrap_unwrap,
                                              wrap_unwrap,
                                              derive,
                                              overwrite,
                                              byref(h_pub_key_ptr),
                                              byref(h_pvt_key_ptr))

        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        h_pub_key = h_pub_key_ptr.value
        h_pvt_key = h_pvt_key_ptr.value
        if h_pub_key == 0:
            raise HsmError("public key handle returned from HSM is invalid")
        if h_pvt_key == 0:
            raise HsmError("private key handle returned from HSM is invalid")
        return h_pub_key, h_pvt_key

    def create_secret_key(self,
                          key_label,
                          key_id=None,
                          key_type=HsmSymKeyGen.AES,
                          key_size_in_bits=256,
                          token=True,
                          private=True,
                          sensitive=True,
                          modifiable=False,
                          extractable=True,
                          sign=True,
                          verify=True,
                          encrypt=True,
                          decrypt=True,
                          wrap=True,
                          unwrap=True,
                          derive=False,
                          overwrite=False):
        """
        Creates a new symmetric key on the HSM with the specified
        attributes.

        Args:
            key_label:            text label of the new key

            key_id:               id value of the new secret key
                                  Note: a random 16 byte value will be generated
                                  and assigned if an ID is not provided

            key_type:             type of symmetric key (HsmSymKeyGen enum)

            key_size_in_bits:     size of the symmetric key in bits

            token:                set to True if key should persist on
                                  the HSM token after session ends (CKA_TOKEN)

            private:              set to True if the key is private and
                                  should only be visible by the user (CKA_PRIVATE)

            sensitive:            set to True if the private key is sensitive and
                                  should be protected by the HSM and cannot be
                                  revealed in plaintext off the token (CKA_SENSITIVE)

            modifiable:           set to True if the key can be modified
                                  after unwrapped on the HSM (CKA_MODIFIABLE)

            extractable:          set to True if the key can be extracted
                                  (unwrapped) off the HSM (CKA_EXTRACTABLE)

            sign:                 set to True if the key is allowed to be
                                  used in sign operations (CKA_SIGN)

            verify:               set to True if the key is allowed to be
                                  used in verify operations (CKA_VERIFY)

            encrypt:              set to True if the key is allowed to be
                                  used in encrypt operations (CKA_ENCRYPT)

            decrypt:              set to True if the key is allowed to be
                                  used in decrypt operations (CKA_DECRYPY)

            wrap:                 set to True if the key is allowed to be
                                  used in wrap operations (CKA_WRAP)

            unwrap:               set to True if the key is allowed to be
                                  used in unwrap operations (CKA_UNWRAP)

            derive:               set to True if the private key is allowed
                                  to be used to derive other keys (CKA_DERIVE)

            overwrite:            set to True if the new keys should
                                  overwrite any existing keys with the same
                                  label

        Returns:
            The key object handle on the HSM.

        """
        if not isinstance(key_label, str):
            raise HsmError("key_label must be of type str")
        if len(key_label) <= 0:
            raise HsmError("key_label must have length 1 or greater")
        if key_id is None:
            key_id = os.urandom(self.__idRandomSize)
        if not isinstance(key_id, bytes):
            raise HsmError("key_id must be of type bytes")
        if not isinstance(key_type, HsmSymKeyGen):
            raise HsmError("key_type must be of type HsmSymKeyGen")
        if not isinstance(key_size_in_bits, int):
            raise HsmError("key_size_in_bits must be of type int")
        if key_size_in_bits <= 0:
            raise HsmError("key_size_in_bits must have a value 1 or greater")
        if not isinstance(token, bool):
            raise HsmError("token must be of type bool")
        if not isinstance(private, bool):
            raise HsmError("private must be of type bool")
        if not isinstance(sensitive, bool):
            raise HsmError("sensitive must be of type bool")
        if not isinstance(modifiable, bool):
            raise HsmError("modifiable must be of type bool")
        if not isinstance(extractable, bool):
            raise HsmError("extractable must be of type bool")
        if not isinstance(sign, bool):
            raise HsmError("sign must be of type bool")
        if not isinstance(verify, bool):
            raise HsmError("verify must be of type bool")
        if not isinstance(encrypt, bool):
            raise HsmError("encrypt must be of type bool")
        if not isinstance(decrypt, bool):
            raise HsmError("decrypt must be of type bool")
        if not isinstance(wrap, bool):
            raise HsmError("wrap must be of type bool")
        if not isinstance(unwrap, bool):
            raise HsmError("unwrap must be of type bool")
        if not isinstance(derive, bool):
            raise HsmError("derive must be of type bool")
        if not isinstance(overwrite, bool):
            raise HsmError("overwrite must be of type bool")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        key_label_bytes = str_to_bytes(key_label)
        h_key_ptr = c_ulong()
        rv = self.__libhsm.create_secret_key(msg,
                                             len(msg),
                                             self.sessionHandle,
                                             key_label_bytes,
                                             len(key_label_bytes),
                                             key_id,
                                             len(key_id),
                                             key_type.value,
                                             key_size_in_bits,
                                             token,
                                             private,
                                             sensitive,
                                             modifiable,
                                             extractable,
                                             sign,
                                             verify,
                                             encrypt,
                                             decrypt,
                                             wrap,
                                             unwrap,
                                             derive,
                                             overwrite,
                                             byref(h_key_ptr))

        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        h_key = h_key_ptr.value
        if h_key == 0:
            raise HsmError("key handle returned from HSM is invalid")
        return h_key

    def set_attribute_value(self,
                            handle,
                            attribute_type,
                            attribute_value):
        """
        Sets an attribute value for an HSM object.

        Args:
            handle:              handle of the HSM object

            attribute_type:      object attribute type (HsmAttribute enum)

            attribute_value:     attribute value as a bytes
        """

        if not isinstance(handle, int):
            raise HsmError("handle must be of type int")
        if handle <= 0:
            raise HsmError("handle must be a value greater than zero")
        if not isinstance(attribute_type, HsmAttribute):
            raise HsmError("attributeType must be of type HsmAttribute")
        if not isinstance(attribute_value, bytes):
            raise HsmError("attribute_value must be of type HsmAttribute")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        rv = self.__libhsm.set_attribute_value(msg,
                                               len(msg),
                                               self.sessionHandle,
                                               handle,
                                               attribute_type.value,
                                               attribute_value,
                                               len(attribute_value))

        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))

    def generate_random(self, size=16):
        """
        Generates a string of random data using the PRNG on the HSM.

        Args:
            size:               number of bytes of random data to generate
                                (default: 16 bytes)

        Returns:
            array containing random bytes

        """
        if not isinstance(size, int):
            raise HsmError("size must be of type int")
        if size <= 0:
            raise HsmError("size must be a value greater than zero")
        if size > self.__maxRandomSize:
            raise HsmError("size too large")
        if not isinstance(size, int):
            raise HsmError("size must be of type int")

        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        buf = create_string_buffer(size)
        rv = self.__libhsm.generate_random(msg,
                                           len(msg),
                                           self.sessionHandle,
                                           buf,
                                           len(buf))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        # resize the buffer to get it out of a ctype string and into a python string
        buf = buf[:size]
        if len(buf) != size:
            raise HsmError("length of random data returned by HSM does not match requested size")
        return buf

    def destroy_object(self, handle):
        """
        Destroys an object on the HSM.

        Args:
            handle:               handle of object to destroy on the HSM

        Returns:

        """
        if not isinstance(handle, int):
            raise HsmError("handle must be of type int")
        if handle <= 0:
            raise HsmError("handle must be a value greater than zero")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        rv = self.__libhsm.destroy_object(msg,
                                          len(msg),
                                          self.sessionHandle,
                                          handle)
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))

    def import_data_object(self,
                           data_label,
                           value,
                           data_id=None,
                           token=True,
                           overwrite=False):
        """
        Imports a clear-text data object object on the HSM.

        Args:
            data_label:           object label

            value:                data object value

            data_id:              object id value
                                  Note: a random 16 byte value will be generated
                                  and assigned if an ID is not provided

            token:                set to True if key should persist on
                                  the HSM token after session ends

            overwrite:            set to True if the new keys should
                                  overwrite any existing keys with the same
                                  label

        Returns:
            object handle

        """
        if not isinstance(data_label, str):
            raise HsmError("data_label must be of type str")
        if len(data_label) == 0:
            raise HsmError("data_label must have a value")
        if not isinstance(value, bytes):
            raise HsmError("value must be of type bytes")
        if len(value) == 0:
            raise HsmError("value must have a value")
        if data_id is None:
            data_id = os.urandom(self.__idRandomSize)
        if not isinstance(data_id, bytes):
            raise HsmError("data_id must be of type bytes")
        if not isinstance(token, bool):
            raise HsmError("token must be of type bool")
        if not isinstance(overwrite, bool):
            raise HsmError("overwrite must be of type bool")
        self.__validate_session()
        label_bytes = str_to_bytes(data_label)
        h_object_ptr = c_ulong()
        msg = create_string_buffer(self.__messageBufferSize)
        rv = self.__libhsm.import_data_object(msg,
                                              len(msg),
                                              self.sessionHandle,
                                              label_bytes,
                                              len(label_bytes),
                                              data_id,
                                              len(data_id),
                                              value,
                                              len(value),
                                              token,
                                              overwrite,
                                              byref(h_object_ptr))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        h_object = h_object_ptr.value
        if h_object == 0:
            raise HsmError("object handle returned from HSM is invalid")
        return h_object

    def import_rsa_public_key(self,
                              key_label,
                              modulus,
                              exponent=b'\x01\x00\x01',
                              key_id=None,
                              token=True,
                              private=True,
                              modifiable=False,
                              verify=True,
                              encrypt=True,
                              wrap=True,
                              overwrite=False):

        """
        Imports a clear-text RSA public key on the HSM with the specified
        attributes.

        Args:

            key_label:            text label of the public key

            modulus:              public modulus

            exponent:             public exponent

            key_id:               key id value
                                  Note: a random 16 byte value will be generated
                                  and assigned if an ID is not provided

            token:                set to True if key should persist on
                                  the HSM token after session ends

            private:              set to True if the key is private and
                                  should only be visible by the user

            modifiable:           set to True if the key can be modified
                                  after unwrapped on the HSM

            verify:               set to True if the key is allowed to be
                                  used in verify operations

            encrypt:              set to True if the key is allowed to be
                                  used in encrypt operations

            wrap:                 set to True if the key is allowed to be
                                  used in wrap operations

            overwrite:            set to True if the new keys should
                                  overwrite any existing keys with the same
                                  label

        Returns:
            The key object handle on the HSM.

        """
        if not isinstance(key_label, str):
            raise HsmError("key_label must be of type str")
        if len(key_label) == 0:
            raise HsmError("key_label must have length 1 or greater")
        if not isinstance(modulus, bytes):
            raise HsmError("modulus must be of type bytes")
        if len(modulus) == 0:
            raise HsmError("modulus must have length 1 or greater")
        if not isinstance(exponent, bytes):
            raise HsmError("exponent must be of type bytes")
        if len(exponent) == 0:
            raise HsmError("exponent must have length 1 or greater")
        if key_id is None:
            key_id = os.urandom(self.__idRandomSize)
        if not isinstance(key_id, bytes):
            raise HsmError("key_id must be of type bytes")
        if not isinstance(token, bool):
            raise HsmError("token must be of type bool")
        if not isinstance(private, bool):
            raise HsmError("private must be of type bool")
        if not isinstance(modifiable, bool):
            raise HsmError("modifiable must be of type bool")
        if not isinstance(verify, bool):
            raise HsmError("verify must be of type bool")
        if not isinstance(encrypt, bool):
            raise HsmError("encrypt must be of type bool")
        if not isinstance(wrap, bool):
            raise HsmError("wrap must be of type bool")
        if not isinstance(overwrite, bool):
            raise HsmError("overwrite must be of type bool")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        key_label_bytes = str_to_bytes(key_label)
        h_key_ptr = c_ulong()
        rv = self.__libhsm.import_rsa_public_key(msg,
                                                 len(msg),
                                                 self.sessionHandle,
                                                 key_label_bytes,
                                                 len(key_label_bytes),
                                                 key_id,
                                                 len(key_id),
                                                 exponent,
                                                 len(exponent),
                                                 modulus,
                                                 len(modulus),
                                                 token,
                                                 private,
                                                 modifiable,
                                                 verify,
                                                 encrypt,
                                                 wrap,
                                                 overwrite,
                                                 byref(h_key_ptr))

        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        h_key = h_key_ptr.value
        if h_key == 0:
            raise HsmError("key handle returned from HSM is invalid")
        return h_key

    def import_ec_public_key(self,
                             key_label,
                             ec_params,
                             ec_point,
                             key_id=None,
                             token=True,
                             private=True,
                             modifiable=False,
                             verify=True,
                             encrypt=True,
                             wrap=True,
                             overwrite=False):
        """
        Imports a clear-text EC public key on the HSM with the specified
        attributes.

        Args:

            key_label:            text label of the public key

            ec_params:            DER encoded EC curve parameters or
                                  EC curve OID as bytes data type.
                                  Use the enum EcCurveOids (recommended) or
                                  EcCurves when possible to provide the
                                  ec_params binary value.

            ec_point:             EC point for public key

            key_id:               key id value
                                  Note: a random 16 byte value will be generated
                                  and assigned if an ID is not provided

            token:                set to True if key should persist on
                                  the HSM token after session ends

            private:              set to True if the key is private and
                                  should only be visible by the user

            modifiable:           set to True if the key can be modified
                                  after unwrapped on the HSM

            verify:               set to True if the key is allowed to be
                                  used in verify operations

            encrypt:              set to True if the key is allowed to be
                                  used in encrypt operations

            wrap:                 set to True if the key is allowed to be
                                  used in wrap operations

            overwrite:            set to True if the new keys should
                                  overwrite any existing keys with the same
                                  label

        Returns:
            The key object handle on the HSM.

        """
        if not isinstance(key_label, str):
            raise HsmError("key_label must be of type str")
        if len(key_label) == 0:
            raise HsmError("key_label must have length 1 or greater")
        if isinstance(ec_params, EcCurveOids) or isinstance(ec_params, EcCurves):
            ec_params = ec_params.value
        if not isinstance(ec_params, bytes):
            raise HsmError("ec_params must be of type bytes, EcCurveOids, or EcCurves")
        if len(ec_params) == 0:
            raise HsmError("ec_params must have length 1 or greater")
        if not isinstance(ec_point, bytes):
            raise HsmError("ec_point must be of type bytes")
        if len(ec_point) == 0:
            raise HsmError("ec_point must have length 1 or greater")
        if key_id is None:
            key_id = os.urandom(self.__idRandomSize)
        if not isinstance(key_id, bytes):
            raise HsmError("key_id must be of type bytes")
        if not isinstance(token, bool):
            raise HsmError("token must be of type bool")
        if not isinstance(private, bool):
            raise HsmError("private must be of type bool")
        if not isinstance(modifiable, bool):
            raise HsmError("modifiable must be of type bool")
        if not isinstance(verify, bool):
            raise HsmError("verify must be of type bool")
        if not isinstance(encrypt, bool):
            raise HsmError("encrypt must be of type bool")
        if not isinstance(wrap, bool):
            raise HsmError("wrap must be of type bool")
        if not isinstance(overwrite, bool):
            raise HsmError("overwrite must be of type bool")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        key_label_bytes = str_to_bytes(key_label)
        h_key_ptr = c_ulong()
        rv = self.__libhsm.import_ec_public_key(msg,
                                                len(msg),
                                                self.sessionHandle,
                                                key_label_bytes,
                                                len(key_label_bytes),
                                                key_id,
                                                len(key_id),
                                                ec_params,
                                                len(ec_params),
                                                ec_point,
                                                len(ec_point),
                                                token,
                                                private,
                                                modifiable,
                                                verify,
                                                encrypt,
                                                wrap,
                                                overwrite,
                                                byref(h_key_ptr))

        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        h_key = h_key_ptr.value
        if h_key == 0:
            raise HsmError("key handle returned from HSM is invalid")
        return h_key

    def import_secret_key(self,
                          key_label,
                          key_type,
                          clear_key_data,
                          key_size_in_bits=0,
                          token=True,
                          private=True,
                          modifiable=False,
                          extractable=True,
                          sign=True,
                          verify=True,
                          encrypt=True,
                          decrypt=True,
                          wrap=True,
                          unwrap=True,
                          derive=False,
                          overwrite=False):
        """
        Imports a clear-text symmetric key onto the HSM.

        Args:

            key_label:            text label for the symmetric key

            key_type:             type of symmetric key
                                  (HsmSymKeyType)

            clear_key_data:       clear-text key data

            key_size_in_bits:     size of symmetric key in bits
                                  (example: 112, 128, 256)

            token:                set to True if key should persist on
                                  the HSM token after session ends

            private:              set to True if the key is private and
                                  should only be visible by the user

            modifiable:           set to True if the key can be modified
                                  after unwrapped on the HSM

            extractable:          set to True if the key can be extracted
                                  (unwrapped) off the HSM

            sign:                 set to True if the key is allowed to be
                                  used in signing operations

            verify:               set to True if the key is allowed to be
                                  used in verify operations

            encrypt:              set to True if the key is allowed to be
                                  used in encrypt operations

            decrypt:              set to True if the key is allowed to be
                                  used in decrypt operations

            wrap:                 set to True if the key is allowed to be
                                  used in wrap operations

            unwrap:               set to True if the key is allowed to be
                                  used in unwrap operations

            derive:               set to True if the key is allowed to be
                                  used in key derivation operations

            overwrite:            set to True if the new keys should
                                  overwrite any existing keys with the same
                                  label

        Returns:
            key handle

        """

        # create session key used for wrapping / unwrapping if it does not
        # already exist on the HSM
        if self.__sessionKeyHandle == 0:
            self.__sessionKeyHandle = self.create_secret_key(key_label=self.__sessionKeyLabel,
                                                             key_type=self.__sessionKeyType,
                                                             key_size_in_bits=self.__sessionKeySizeInBits,
                                                             token=False)

        # encrypt the clear-text key data using the session key
        # we have to do this because you can only unwrap encrypted
        # keys onto the HSM and not clear-text keys
        key_data = self.encrypt(handle=self.__sessionKeyHandle,
                                data=clear_key_data,
                                mechanism=self.__sessionKeyMech,
                                iv=self.__sessionKeyIv)

        # unwrap the encrypted symmetric key onto the HSM
        h_key = self.unwrap_secret_key(wrap_key_handle=self.__sessionKeyHandle,
                                       wrap_key_mech=self.__sessionKeyMech,
                                       wrap_key_iv=self.__sessionKeyIv,
                                       key_label=key_label,
                                       key_data=key_data,
                                       key_type=key_type,
                                       key_size_in_bits=key_size_in_bits,
                                       token=token,
                                       private=private,
                                       modifiable=modifiable,
                                       extractable=extractable,
                                       sign=sign,
                                       verify=verify,
                                       encrypt=encrypt,
                                       decrypt=decrypt,
                                       wrap=wrap,
                                       unwrap=unwrap,
                                       derive=derive,
                                       overwrite=overwrite)
        return h_key

    def wrap_key(self,
                 key_handle,
                 wrap_key_handle,
                 wrap_key_mech,
                 wrap_key_iv):
        """
        Wraps (encrypts) a private key or symmetric key off the HSM.

        Args:
            key_handle:             handle of the key to wrap off the HSM

            wrap_key_handle:        handle of the wrapping key to use

            wrap_key_mech:          wrapping key algorithm (CKM mechanism) to use
                                    which can be provided as HsmMech enumeration
                                    or binary value

            wrap_key_iv:            wrapping key initialization vector

        Returns:
            Wrapped key data as bytes.

        """
        if not isinstance(key_handle, int):
            raise HsmError("key_handle must be of type int")
        if key_handle <= 0:
            raise HsmError("key_handle must be 1 or greater")
        if not isinstance(wrap_key_handle, int):
            raise HsmError("wrap_key_handle must be of type int")
        if wrap_key_handle <= 0:
            raise HsmError("wrap_key_handle must be 1 or greater")
        if isinstance(wrap_key_mech, HsmMech):
            wrap_key_mech = wrap_key_mech.value
        if not isinstance(wrap_key_mech, int):
            raise HsmError("wrap_key_mech must be of type int or HsmMech")
        if not isinstance(wrap_key_iv, bytes):
            raise HsmError("wrap_key_iv must be of type bytes")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        buf = create_string_buffer(self.__wrapoffKeyBufferSize)
        buf_len_ptr = c_ulong(len(buf))
        rv = self.__libhsm.wrap_key(msg,
                                    len(msg),
                                    self.sessionHandle,
                                    key_handle,
                                    wrap_key_handle,
                                    wrap_key_iv,
                                    len(wrap_key_iv),
                                    wrap_key_mech,
                                    buf,
                                    buf_len_ptr)

        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        buf_len = buf_len_ptr.value
        buf = buf[:buf_len]
        return buf

    def unwrap_secret_key(self,
                          wrap_key_handle,
                          wrap_key_mech,
                          wrap_key_iv,
                          key_label,
                          key_data,
                          key_type=HsmSymKeyType.AES,
                          key_size_in_bits=256,
                          key_id=None,
                          token=True,
                          private=True,
                          sensitive=True,
                          modifiable=False,
                          extractable=True,
                          sign=True,
                          verify=True,
                          encrypt=True,
                          decrypt=True,
                          wrap=True,
                          unwrap=True,
                          derive=False,
                          overwrite=False):
        """
        Unwraps (decrypts and installs) a symmetric key onto the HSM.

        Args:

            wrap_key_handle:      handle of the wrapping key to use

            wrap_key_mech:        wrapping key algorithm (CKM mechanism) to use
                                  which can be provided as HsmMech enumeration
                                  or binary value

            wrap_key_iv:          wrapping key initialization vector

            key_label:            text label for the symmetric key

            key_data:             encrypted (wrapped) key data

            key_type:             type of symmetric key
                                  (HsmSymKeyType)

            key_size_in_bits:     size of key in bits (112, 128, 192, 256, etc).

            key_id:               id value of key
                                  Note: a random 16 byte value will be generated
                                  and assigned if an ID is not provided

            token:                set to True if key should persist on
                                  the HSM token after session ends (CKA_TOKEN)

            private:              set to True if the key is private and
                                  should only be visible by the user (CKA_PRIVATE)

            sensitive:            set to True if the private key is sensitive and
                                  should be protected by the HSM and cannot be
                                  revealed in plaintext off the token (CKA_SENSITIVE)

            modifiable:           set to True if the key can be modified
                                  after unwrapped on the HSM (CKA_MODIFIABLE)

            extractable:          set to True if the key can be extracted
                                  (unwrapped) off the HSM (CKA_EXTRACTABLE)

            sign:                 set to True if the key is allowed to be
                                  used in signing operations (CKA_SIGN)

            verify:               set to True if the key is allowed to be
                                  used in verify operations (CKA_VERIFY)

            encrypt:              set to True if the key is allowed to be
                                  used in encrypt operations (CKA_ENCRYPT)

            decrypt:              set to True if the key is allowed to be
                                  used in decrypt operations (CKA_DECRYPT)

            wrap:                 set to True if the key is allowed to be
                                  used in wrap operations (CKA_WRAP)

            unwrap:               set to True if the key is allowed to be
                                  used in unwrap operations (CKA_UNWRAP)

            derive:               set to True if the key is allowed to be
                                  used in key derivation operations (CKA_DERIVE)

            overwrite:            set to True if the new keys should
                                  overwrite any existing keys with the same
                                  label

        Returns:
            key handle

        """
        if not isinstance(wrap_key_handle, int):
            raise HsmError("wrap_key_handle must be of type int")
        if wrap_key_handle <= 0:
            raise HsmError("wrap_key_handle must be 1 or greater")
        if isinstance(wrap_key_mech, HsmMech):
            wrap_key_mech = wrap_key_mech.value
        if not isinstance(wrap_key_mech, int):
            raise HsmError("wrap_key_mech must be of type int or HsmMech")
        if not isinstance(wrap_key_iv, bytes):
            raise HsmError("wrap_key_iv must be of type bytes")
        if not isinstance(key_label, str):
            raise HsmError("key_label must be of type str")
        if len(key_label) == 0:
            raise HsmError("key_label must have a value")
        if not isinstance(key_data, bytes):
            raise HsmError("key_data must be of type bytes")
        if len(key_data) < 1:
            raise HsmError("key_data must have length 1 or greater")
        if not isinstance(key_type, HsmSymKeyType):
            raise HsmError("key_type must be of type HsmSymKeyType")
        if not isinstance(key_size_in_bits, int):
            raise HsmError("key_size_in_bits must be of type int")
        if key_id is None:
            key_id = os.urandom(self.__idRandomSize)
        if not isinstance(key_id, bytes):
            raise HsmError("key_id must be of type bytes")
        if not isinstance(token, bool):
            raise HsmError("token must be of type bool")
        if not isinstance(private, bool):
            raise HsmError("private must be of type bool")
        if not isinstance(sensitive, bool):
            raise HsmError("sensitive must be of type bool")
        if not isinstance(modifiable, bool):
            raise HsmError("modifiable must be of type bool")
        if not isinstance(extractable, bool):
            raise HsmError("extractable must be of type bool")
        if not isinstance(sign, bool):
            raise HsmError("sign must be of type bool")
        if not isinstance(verify, bool):
            raise HsmError("verify must be of type bool")
        if not isinstance(encrypt, bool):
            raise HsmError("encrypt must be of type bool")
        if not isinstance(decrypt, bool):
            raise HsmError("decrypt must be of type bool")
        if not isinstance(wrap, bool):
            raise HsmError("wrap must be of type bool")
        if not isinstance(unwrap, bool):
            raise HsmError("unwrap must be of type bool")
        if not isinstance(derive, bool):
            raise HsmError("derive must be of type bool")
        if not isinstance(overwrite, bool):
            raise HsmError("overwrite must be of type bool")
        self.__validate_session()
        msg = create_string_buffer(self.__messageBufferSize)
        key_label_bytes = str_to_bytes(key_label)
        h_key_ptr = c_ulong()
        rv = self.__libhsm.unwrap_secret_key(msg,
                                             len(msg),
                                             self.sessionHandle,
                                             wrap_key_handle,
                                             wrap_key_iv,
                                             len(wrap_key_iv),
                                             wrap_key_mech,
                                             key_label_bytes,
                                             len(key_label_bytes),
                                             key_id,
                                             len(key_id),
                                             key_data,
                                             len(key_data),
                                             key_type.value,
                                             key_size_in_bits,
                                             token,
                                             private,
                                             sensitive,
                                             modifiable,
                                             extractable,
                                             sign,
                                             verify,
                                             encrypt,
                                             decrypt,
                                             wrap,
                                             unwrap,
                                             derive,
                                             overwrite,
                                             byref(h_key_ptr))

        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        h_key = h_key_ptr.value
        if h_key == 0:
            raise HsmError("key handle returned from HSM is invalid")
        return h_key

    def get_mechanism_info(self, slot):
        """
        Retrieves information about the HSM slot mechanisms visible to
        the HSM client user.  This method may be called without first
        opening a session to the HSM.

        Args:
            (none)

        Returns:
            List of HsmSlot objects.
        """
        if not isinstance(slot, int):
            raise HsmError("slot must be of type int")
        if slot < 0:
            raise HsmError("invalid slot")

        msg = create_string_buffer(self.__messageBufferSize)
        buf = create_string_buffer(self.__mechInfoBufferSize)
        buf_len_ptr = c_ulong(len(buf))
        mech_count_ptr = c_ulong()
        # make the call
        rv = self.__libhsm.get_mechanism_info(msg,
                                              len(msg),
                                              slot,
                                              buf,
                                              byref(buf_len_ptr),
                                              byref(mech_count_ptr))
        if rv == 0:
            raise HsmError(bytes_to_str(msg.value))
        # test if the token count is greater than 0 then trim the buffer
        # and split into a set of lines
        lines = ''
        buf = bytes_to_str(buf.value)
        if mech_count_ptr.value > 0:
            buf_len = buf_len_ptr.value
            buf = buf[:buf_len]
            lines = str(buf).split('\n')
        m_list = []
        for line in lines:
            m_list.append(HsmMechInfo(line))
        # sort the list
        sorted_list = sorted(m_list, key=lambda hsmmechinfo: hsmmechinfo.mechanismValueInt)
        return sorted_list

    def get_session_key_handle(self):
        """
        Gets the handle of the internally created AES session key.
        """
        
        # create session key used for wrapping / unwrapping if it does not 
        # already exist on the HSM
        if self.__sessionKeyHandle == 0:
            self.__sessionKeyHandle = self.create_secret_key(key_label=self.__sessionKeyLabel,
                                                             key_type=self.__sessionKeyType,
                                                             key_size_in_bits=self.__sessionKeySizeInBits,
                                                             token=False)
        
        return self.__sessionKeyHandle

