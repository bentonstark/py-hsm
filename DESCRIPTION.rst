=== pihsm

This project provides a simple but powerful interface to access Hardware
Security Modules via the PKCS#11 API.  The piHSM can be used with a variety 
of devices to access, create, manipulate, and wield objects on the HSM.

This project requires the companion libhsm.so shared library for Linux/UNIX 
or libhsm.dll dynamic library for Windows.  This library is available in 
github and can be easily compiled to Linux/UNIX systems using the provided
build script.  Once built and installed on the target system, the piHSM
Client can the access the specific HSM hardware by directly access
the vendor's provided PKCS#11 API implemenation.

The caller can specify the target HSM vendor's PKCS#11 library directly
when the HsmClient() is created by passing in an argument to the PKCS#11
library or can create a symbolic link /usr/lib/libpihsm.so on Linux/UNIX OS 
environments to point to the PKCS#11 shared library.

=== Example 1:

    from pihsm.hsmclient import HsmClient
    from pihsm.hsmclient HsmSymKeyGen 
    from pihsm.hsmclient HsmMech
		
    # create connection to HSM
    c = HsmClient(pkcs11_lib='/usr/lib64/pkcs11/libsofthsm2.so')
    c.open_session(slot=1)
    c.login(pin='12345678')
    
    # generate some random bytes
    r = c.generate_random(16)
    print(r)
    
    # create a key on the HSM
    hkey = c.create_secret_key("KEY_LABEL", keySize, HsmSymKeyGen.AES)
    print(hkey)
    
    # clean up
    c.close_session()
    c.logout()

    
=== Example 2:

    from pihsm.hsmclient import HsmClient
    from pihsm.hsmclient HsmSymKeyGen 
    from pihsm.hsmclient HsmMech
		
    # create connection to HSM using the auto open and close feature
    with c = HsmClient(slot=1, pin='12345678', pkcs11_lib='/usr/lib64/pkcs11/libsofthsm2.so'):
        # generate some random bytes
        r = c.generate_random(16)
        print(r)
        # create a key on the HSM
        hkey = c.create_secret_key("KEY_LABEL", keySize, HsmSymKeyGen.AES)
        print(hkey)
    
    


