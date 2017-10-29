# py-hsm

## Overview
The py-hsm module enables Python users simplified access to any PKCS#11 standards compliant Hardware Security Module (HSM) or software API.  The PKCS#11 API is a vendor-neutral, open standards API governed by the OASIS standards body.  It provides a standard programmatic interface to Hardware Security Modules (HSMs) and HSM PaaS solutions such as Amazon's CloudHSM.

## What is an HSM?
Hardware Security Modules (HSMs) are physical, electronic black box devices designed to provide hardware protected secure creation, management and storage of cryptographic keys and secrets.  Most HSMs are actual physical devices that go through US and foreign government certification programs such as the US government's FIPS program.  These programs rate the security and compliance level for specific HSM products.

## What is PKCS#11?
Physical HSMs are built by a variety of 3rd party vendors and come in a variety of form factors.  Yet, all mainstream HSM devices implement the industry OASIS C-based API called PKCS#11.  The PKCS#11 API was first an industry defacto standard API originally developed by RSA Security for HSM security tokens.  Later EMC acquired RSA Security.  Shortly after the acquisition, the OASIS standards body took control of the PKCS #11 Cryptographic Token Interface Base Specification standard and made it a true industry standard API.  Many existing software applications use the PKCS#11 API to interface with a variety of Hardware Security Modules in a vendor neutral manner.  Although it is possible for developers to directly interact with a vendor's PKCS#11 API implemenation, the API is very complex and full of trip-ups and pitfalls.  The goal of the pyhsm and libhsm modules is to provide Python users a simplified HSM interface, without sacrificing performance by abstracting away many of the painful complexities of the PKCS#11 API.

## Supported HSMs
The py-hsm module has been tested to work with the following HSM devices and software based testbed HSMs.
- Gemalto SafeNet Luna SA-4
- Gemalto SafeNet Luna SA-5
- Gemalto SafeNet Luna PCIe K5/K6
- Gemalto SafeNet Luna CA-4
- SafeNet ProtectServer PCIe
- FutureX Vectera Series
- Cavium LiquidSecurity FIPS PCIe Card
- Utimaco Security Server Simulator (SMOS Ver. 3.1.2.3)
- OpenDNSSEC SoftHSM 2.2.0 (softhsm2)

## Installation Prerequisites
- Python 3.x
- if Python 3.3 or less then enum34 is required ($ pip install enum34)
- libhsm.so https://github.com/bentonstark/libhsm

**pyenv** and optionally **virtualenv** can be used to create an
isolated Python 3.x environment if 3.x is not available on your system.
If there is enough demand requests, future versions may be back support Python 2.7.x

## Tested Platforms
- Fedora 19, 23, 24, 25
- Debian
- CentOS 6
- CentOS 7

## Installation Steps
Before installing, remove any existing pyhsm installations ($ pip uninstall pyhsm).
```
$ cd pyhsm
$ python setup.py install
```
## Usage Examples
### Login / Logout
```python
from pyhsm.hsmclient import HsmClient

# note: the with keyword can be used to reduce login / logout steps
# what is shown below is the verbose method
c = HsmClient(pkcs11_lib="/usr/lib/vendorp11.so")
c.open_session(slot=1)
c.login(pin="partition_password")
c.logout()
c.close_session()
```
### List Slots
```python
from pyhsm.hsmclient import HsmClient

# note: listing slot information does not require a login
with HsmClient(pkcs11_lib="/usr/lib/vendorp11.so") as c:
  for s in c.get_slot_info():
    print("----------------------------------------")
    print(s.to_string())
```
### List Objects
```python
from pyhsm.hsmclient import HsmClient

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  for s in c.get_slot_info():
    obj_list = c.get_objects()
    for obj in obj_list:
      print(obj.to_string())
```
### Sign
```python
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import bytes_to_hex

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  sig = c.sign(handle=1, data=data_to_sign, mechanism=HsmMech.SHA256_RSA_PKCS)
  print(bytes_to_hex(sig))
```
### Verify
```python
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  result = c.verify(handle=1, data=sig_to_verify, mechanism=HsmMech.SHA256_RSA_PKCS)
  print(str(result))
```
### Encrypt
```python
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import bytes_to_hex

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  ciphertext = c.encrypt(handle=aes_key_handle, data=cleartext, mechanism=HsmMech.AES_CBC_PAD, iv=init_vector)
  print(bytes_to_hex(ciphertext))
```
### Decrypt
```python
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import bytes_to_hex

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  cleartext = c.decrypt(handle=aes_key_handle, data=ciphertext, mechanism=HsmMech.AES_CBC_PAD, iv=init_vector)
  print(bytes_to_hex(cleartext))
```
### Create AES Key
```python
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmSymKeyGen

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  key_handle = c.create_secret_key(key_label="my_aes_key",
                                   HsmSymKeyGen.AES,
                                   key_size_in_bits=256,
                                   token=True,
                                   private=True,
                                   modifiable=False,
                                   extractable=False,
                                   sign=True,
                                   verify=True,
                                   decrypt=True,
                                   wrap=True,
                                   unwrap=True,
                                   derive=False)
  print(key_handle)
```
### Create RSA Key Pair
```python
from pyhsm.hsmclient import HsmClient

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  key_handles = c.create_rsa_key_pair(public_key_label="my_rsa_pub",
                                      private_key_label="my_rsa_pvt",
                                      key_length=2048,
                                      public_exponent=b"\x01\x00\x01",
                                      token=True,
                                      private=True,
                                      modifiable=False,
                                      extractable=False,
                                      sign_verify=True,
                                      encrypt_decrypt=True,
                                      wrap_unwrap=True,
                                      derive=False)
  print("public_handle: " + key_handles[0])
  print("private_handle: " + key_handles[1])
```
### Create EC Key Pair
```python
from pyhsm.hsmclient import HsmClient
from pyhsm.convert import hex_to_bytes
from pyhsm.eccurveoids import EcCurveOids

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  # NIST P-256
  key_handles = c.create_ecc_key_pair(public_key_label="my_ec_pub",
                                      private_key_label="my_ec_pvt",
                                      curve_parameters=EcCurveOids.P256,
                                      token=True,
                                      private=True,
                                      modifiable=False,
                                      extractable=False,
                                      sign_verify=True,
                                      encrypt_decrypt=True,
                                      wrap_unwrap=True,
                                      derive=False)
  print("public_handle: " + key_handles[0])
  print("private_handle: " + key_handles[1])
```
### Wrap Key (AES wrapped with AES)
```python
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import bytes_to_hex

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  my_key_handle_to_wrap = 1
  my_aes_wrapping_key_handle = 2
  iv = c.generate_random(size=16)
  wrapped_key_bytes = c.wrap_key(my_key_handle_to_wrap,
                                 my_ses_wrapping_key_handle,
                                 HsmMech.AES_CBC_PAD,
                                 iv)
  print(bytes_to_hex(wrapped_key_bytes))
```
### Unwrap Key (AES wrapped with AES)
```python
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmMech
from pyhsm.convert import bytes_to_hex

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  hkey = c.unwrap_secret_key(wrap_key_handle=wraping_key_handle,
                             wrap_key_mech=HsmMech.AES_CBC_PAD,
                             wrap_key_iv=iv,
                             key_label="my_key",
                             key_data=wrapped_key_bytes,
                             key_type=HsmSymKeyType.AES,
                             key_size_in_bits=key_size,
                             token=True,
                             private=True,
                             modifiable=False,
                             extractable=False,
                             sign=True,
                             verify=True,
                             encrypt=True,
                             decrypt=True,
                             wrap=True,
                             unwrap=True,
                             derive=False)
```
### Generate Random
```python
from pyhsm.hsmclient import HsmClient
from pyhsm.convert import bytes_to_hex

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  rnd_bytes = c.generate_random(size=16)
  print(bytes_to_hex(rnd_bytes))
```
### Get Object Handle by Label
```python
from pyhsm.hsmclient import HsmClient

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  handle = c.get_object_handle(label="my_key_label")
  print(str(handle))
```
### Change Object Label
```python
from pyhsm.hsmclient import HsmClient
from pyhsm.hsmenums import HsmAttribute
from pyhsm.convert import str_to_bytes

with HsmClient(slot=1, pin="partition_password", pkcs11_lib="/usr/lib/vendorp11.so") as c:
  my_key_label = 1
  c.set_attribute_value(handle=my_key_label,
                        attribute_type=HsmAttribute.LABEL,
                        attribute_value=str_to_bytes("my_new"label"))
```







	
