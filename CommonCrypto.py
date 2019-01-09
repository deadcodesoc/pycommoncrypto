"""High level interface to Common Crypto (_commoncrypto).

Common Crypto bindings for Python (pycommoncrypto) provides a wrapper to
Mac OS X's Common Crypto -- libSystem digest library.

Example:
>>> import CommonCrypto
>>> md5 = CommonCrypto.MD5()
>>> md5.init()
>>> md5.update('abc')
>>> md5.final()
>>> print md5.hexdigest()
900150983cd24fb0d6963f7d28e17f72

See also:
Manual pages for CC_crypto(3cc), CC_MD5(3cc) & CC_SHA(3cc)
"""

import _commoncrypto

def digest2hex(str):
    "Hexadecimal digest of string"
    return ''.join([hex(ord(x))[2:].zfill(2) for x in str])

class AbstractHash(object):
    def __init__(self):
        self.ctx = None
    
    def __str__(self):
        return self.digest
    
    def init(self):
        "Initializes a context."
        pass

    def update(self, str):
        "Called repeatedly with chunks of the message to be hashed."
        pass
    
    def final(self):
        "Places the message digest."
        pass
    
    def hexdigest(self):
        "Hexadecimal digest representation."
        return digest2hex(self.digest)

class MD2(AbstractHash):
    def init(self):
        self.ctx = _commoncrypto.MD2_Init()

    def update(self, data):
        _commoncrypto.MD2_Update(self.ctx, data)
    
    def final(self):
        self.digest = _commoncrypto.MD2_Final(self.ctx)
        return self.digest

class MD4(AbstractHash):
    def init(self):
        self.ctx = _commoncrypto.MD4_Init()

    def update(self, data):
        _commoncrypto.MD4_Update(self.ctx, data)

    def final(self):
        self.digest = _commoncrypto.MD4_Final(self.ctx)
        return self.digest

class MD5(AbstractHash):
    def init(self):
        self.ctx = _commoncrypto.MD5_Init()

    def update(self, data):
        _commoncrypto.MD5_Update(self.ctx, data)

    def final(self):
        self.digest = _commoncrypto.MD5_Final(self.ctx)
        return self.digest

class SHA1(AbstractHash):
    def init(self):
        self.ctx = _commoncrypto.SHA1_Init()
    
    def update(self, data):
        _commoncrypto.SHA1_Update(self.ctx, data)
    
    def final(self):
        self.digest = _commoncrypto.SHA1_Final(self.ctx)
        return self.digest

class SHA224(AbstractHash):
    def init(self):
        self.ctx = _commoncrypto.SHA224_Init()

    def update(self, data):
        _commoncrypto.SHA224_Update(self.ctx, data)

    def final(self):
        self.digest = _commoncrypto.SHA224_Final(self.ctx)
        return self.digest

class SHA256(AbstractHash):
    def init(self):
        self.ctx = _commoncrypto.SHA256_Init()

    def update(self, data):
        _commoncrypto.SHA256_Update(self.ctx, data)

    def final(self):
        self.digest = _commoncrypto.SHA256_Final(self.ctx)
        return self.digest

class SHA384(AbstractHash):
    def init(self):
        self.ctx = _commoncrypto.SHA384_Init()

    def update(self, data):
        _commoncrypto.SHA384_Update(self.ctx, data)

    def final(self):
        self.digest = _commoncrypto.SHA384_Final(self.ctx)
        return self.digest

class SHA512(AbstractHash):
    def init(self):
        self.ctx = _commoncrypto.SHA512_Init()

    def update(self, data):
        _commoncrypto.SHA512_Update(self.ctx, data)

    def final(self):
        self.digest = _commoncrypto.SHA512_Final(self.ctx)
        return self.digest

def md2(str):
    "Calculates MD2 digest."
    return _commoncrypto.MD2(str)

def md4(str):
    "Calculates MD4 digest."
    return _commoncrypto.MD4(str)

def md5(str):
    "Calculates MD5 digest."
    return _commoncrypto.MD5(str)

def sha1(str):
    "Calculates SHA-1 digest."
    return _commoncrypto.SHA1(str)

def sha224(str):
    "Calculates SHA-224 digest."
    return _commoncrypto.SHA224(str)

def sha256(str):
    "Calculates SHA-256 digest."
    return _commoncrypto.SHA256(str)

def sha384(str):
    "Calculates SHA-384 digest."
    return _commoncrypto.SHA384(str)

def sha512(str):
    "Calculates SHA-512 digest."
    return _commoncrypto.SHA512(str)
