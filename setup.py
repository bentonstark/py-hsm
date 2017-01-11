from setuptools import setup, find_packages

description = '''A simplified, easy to use PKCS#11 HSM client for Python.
You can use any PKCS#11 (aka Cryptoki) module such as SoftHSM2
or the various vendor modules supplied by vendors of Hardware
Security Modules (HSMs) such as SafeNet/Gemalto and Utimaco HSM.
This client supports the PKCS 11 OASIS standard v2.20 and requires
the companion open source shared library libhsm to function.'''

classifiers = ["Development Status :: 5 - Production/Stable",
"Intended Audience :: Developers",
"License :: OSI Approved :: GNU General Public License (GPL)",
"Natural Language :: English",
"Operating System :: Microsoft :: Windows",
"Operating System :: OS Independent",
"Operating System :: Unix",
"Programming Language :: Python",
"Programming Language :: Python :: 3",
"Programming Language :: Python :: 3.3",
"Programming Language :: Python :: 3.4",
"Programming Language :: Python :: 3.5",
"Topic :: Security :: Cryptography",
"Topic :: Software Development :: Libraries :: Python Modules"]

setup(
    name="pihsm",
    version="2.2.0",
    description= ("A simplified, easy to use PKCS#11 HSM client for Python."),
    classifiers=classifiers,
    platforms="Win32 Unix",
    long_description=description,    
    author = "Benton Stark",
    author_email = "benton.stark@gmail.com",
    maintainer="Benton Stark",
    maintainer_email="benton.stark@gmail.com",
    url="https://github.com/bentonstark/pihsm",
    download_url="https://github.com/bentonstark/pihsm/archive/master.zip",
    license="GPL",
    packages=find_packages(),
    scripts=['./pihsm/eccurves.py', './pihsm/hsmclient.py', './pihsm/hsmenums.py', './pihsm/hsmerror.py', './pihsm/hsmobject.py', './pihsm/hsmslot.py', './pihsm/convert.py'],
    keywords="crypto,pki,pkcs11,hsm,c++"
)
