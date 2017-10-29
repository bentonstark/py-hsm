#
#  Copyright (c) 2016-present, Cisco Systems, Inc. All rights reserved.
#
#  This source code is licensed under the GPL v2 license found in the
#  LICENSE.txt file in the root directory of this source tree.
#
from setuptools import setup, find_packages

description = '''A simplified, easy to use PKCS#11 HSM client for Python.
You can use any PKCS#11 (aka Cryptoki) module supplied by vendors of Hardware
Security Modules (HSMs) such as SafeNet/Gemalto Luna, Utimaco, FutureX, Thales, Cavium,
and DNSSec's SoftHSM.  This client supports the PKCS 11 OASIS standard v2.20 and requires
the companion, cross-platform, open source shared library libhsm.so / libhsm.dll.

The source code to compile and install libhsm.so can be found via the following link.
    https://github.com/bentonstark/libhsm/archive/2.4.0.zip
'''

classifiers = [
                "Development Status :: 5 - Production/Stable",
                "Intended Audience :: Developers",
                "License :: OSI Approved :: GNU General Public License v2 (GPLv2)",
                "Natural Language :: English",
                "Operating System :: POSIX :: Linux",
                "Operating System :: Microsoft :: Windows",
                "Operating System :: OS Independent",
                "Operating System :: Unix",
                "Programming Language :: Python",
                "Programming Language :: Python :: 3",
                "Programming Language :: Python :: 3.3",
                "Programming Language :: Python :: 3.4",
                "Programming Language :: Python :: 3.5",
                "Topic :: Security",
                "Topic :: Security :: Cryptography",
                "Topic :: Software Development :: Libraries :: Python Modules"
              ]

setup(
    name="py-hsm",
    version="2.4.0",
    description="Simplified API for interfacing PKCS#11 compliant HSMs and devices.",
    classifiers=classifiers,
    platforms="Win32 Unix",
    long_description=description,    
    author="Benton Stark",
    author_email="benton.stark@gmail.com",
    maintainer="Benton Stark",
    maintainer_email="benton.stark@gmail.com",
    url="https://github.com/bentonstark/py-hsm",
    download_url="https://github.com/bentonstark/py-hsm/archive/2.4.0.zip",
    license="GPL",
    packages=find_packages(),
    scripts=[
        './pyhsm/eccurveoids.py',
        './pyhsm/eccurves.py',
        './pyhsm/hsmclient.py',
        './pyhsm/hsmenums.py',
        './pyhsm/hsmerror.py',
        './pyhsm/hsmobject.py',
        './pyhsm/hsmslot.py',
        './pyhsm/hsmmechinfo.py',
        './pyhsm/convert.py'
    ],
    keywords="pkcs#11,pkcs11,hsm,cryptopgraphy,hardware security module,security,RSA,Elliptic Curve,AES"
)
