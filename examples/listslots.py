from pihsm.hsmclient import HsmClient

# note: listing slot information does not require a login
# example connects to the open source softHSM v2
with HsmClient(pkcs11_lib="/usr/lib64/pkcs11/libsofthsm2.so") as c:
    for s in c.get_slot_info():
        print("----------------------------------------")
        print(s.to_string())
