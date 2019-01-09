PyCommonCrypto
==============

Common Crypto bindings for Python (pycommoncrypto) provides a wrapper to Mac OS X's [Common Crypto -- libSystem digest library](http://developer.apple.com/documentation/Darwin/Reference/ManPages/man3/CC_crypto.3cc.html).

From the man page: “Common Crypto library implements a wide range of cryptographic algorithms used in various      Internet standards. The services provided by this library are used by the CDSA implementations of SSL, TLS and S/MIME.”.

Fast hash functions available is this module are:

* MD2
* MD4
* MD5
* SHA1
* SHA224
* SHA256
* SHA384
* SHA512

Installation
------------

To install pycommoncrypto into your Mac, download the sources and extract the compressed tarball. The build process is straightforward as typing `make` and then `make install`.

Usage
-----

Here is how to use PyCommonCrypto to calculate the MD5 of a given string:

    >>> import CommonCrypto
    >>> md5 = CommonCrypto.MD5()
    >>> md5.init()
    >>> md5.update('abc')
    >>> md5.final()
    >>> print md5.hexdigest()
    900150983cd24fb0d6963f7d28e17f72

Note: you can call `md.update()` many times as necessary.