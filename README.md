This is python wrapper for curve25519 library with ed25519 signatures. The C code was pulled from [libaxolotl-android](https://github.com/WhisperSystems/libaxolotl-android)
At the moment this wrapper is meant for use by [python-axolotl](http://github.com/tgalal/python-axolotl) and provides the following methods only:

```python
import axolotl_curve25519 as curve
import os

randm32 = os.urandom(32)
randm64 = os.urandom(64)

private_key = curve.generatePrivateKey(randm32)
public_key = message = curve.generatePublicKey(private_key)

agreement = curve.calculateAgreement(private_key, public_key)
signature = curve.calculateSignature(randm64, private_key, message)
verified = curve.verifySignature(public_key, message, signature) == 0
```

# Installation

## Linux

You need to have python headers installed, usually through installing package called python-dev, then as superuser run:
```
python setup.py install
```

## Windows

 - Install [mingw](http://www.mingw.org/) compiler
 - Add mingw to your PATH
 - In PYTHONPATH\Lib\distutils create a file called distutils.cfg and add these lines:
 
```
[build]
compiler=mingw32
```

 - Install gcc: ```mingw-get.exe install gcc```
 - Install zlib [zlib](http://www.zlib.net/)
 - ```python setup.py install```


