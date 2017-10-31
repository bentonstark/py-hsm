
Cavium Examples
=========================================
-pin args       username:password
-p11            path to Cavium's libliquidsec_pkcs11.so shared library
-slot           HSM slot number

Generate Random Data (hex format)
$ python random.py -p11 /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678 -encoding hex -size 16

Timed tests for RSA signing
$ python rsasign-test.py -p11 /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678 --gen-mech RSA_X9_31_KEY_PAIR_GEN --sign-mech SHA256_RSA_PKCS -size 2048 -ops 100

Timed tests for EC signing
$ python ecsign-test.py -p11 /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678 -curve P256 --sign-mech ECDSA_SHA1 -ops 100

AES Key Generation
$ python keygen.py -p11 /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678 -keyType AES -size 256 -l my_aes_key -s -ve -e -d -w -uw -X

Timed tests for RSA generation (1 operation)
$ python rsagen-test.py -module /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678 -mech RSA_X9_31_KEY_PAIR_GEN -size 2048 -size 2048 -ops 1

Timed tests for EC generation (1 operation)
$ python ecgen-test.py -module /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678 -curve P256 -ops 1

List Keys (tabular)
$ python listkeys.py -p11 /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678

List Keys (detailed)
$ python listkeys.py -p11 /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678 --show-all

List Supported Mechanisms (detailed)
$ python listmechs.py -p11 /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678 --show-all

Sign / Verify
$ python sign.py -p11 /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678 -data 0A0B0C0102030405 -mech SHA256_RSA_PKCS -handle 24
abc83fcc070c6f103a60742543c144c9dc4f3c340647d7bbbe5862105aaf280677e58b5c5cb179b6ec683791c423f71c37d3db67014b226472aa5312f76646d5f720bd6110dff5a5234e540821034afad48c32fce39d56e4feef4b120a63d74b5c13a4e8fe0e851821c1534d27fcb19b752a47adbd1bf4563443b0d744622f6e75f63cd8b3ff17edf2dd284344f886586769d68b04e29b0fd7f8a836c8dd8a3b28577134d3a15a331c35f68db616873d10be029c95685ca3691cfdaab066e428a0568e1ce24ceb4d42679f596eff45ee1feffc632e08b7eb401f743a0c0a0689abe6bee4e81ddb6b26348a5e9d492e191784a3cad34fb0eba6671fc84aab1569

$ python verify.py -p11 /home/liquidsec_bin/lib/libliquidsec_pkcs11.so -slot 1 -pin crypto_user:12345678 -data 0A0B0C0102030405 -mech SHA256_RSA_PKCS -handle 25 -sig abc83fcc070c6f103a60742543c144c9dc4f3c340647d7bbbe5862105aaf280677e58b5c5cb179b6ec683791c423f71c37d3db67014b226472aa5312f76646d5f720bd6110dff5a5234e540821034afad48c32fce39d56e4feef4b120a63d74b5c13a4e8fe0e851821c1534d27fcb19b752a47adbd1bf4563443b0d744622f6e75f63cd8b3ff17edf2dd284344f886586769d68b04e29b0fd7f8a836c8dd8a3b28577134d3a15a331c35f68db616873d10be029c95685ca3691cfdaab066e428a0568e1ce24ceb4d42679f596eff45ee1feffc632e08b7eb401f743a0c0a0689abe6bee4e81ddb6b26348a5e9d492e191784a3cad34fb0eba6671fc84aab1569
Sig Verify Result: True



