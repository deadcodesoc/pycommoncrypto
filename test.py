import unittest
from CommonCrypto import *

class MD2Test(unittest.TestCase):
    def test_empty(self):
        c = MD2()
        c.init()
        c.update('')
        self.assertEqual( c.final(), md2('') )
        self.assertEqual( c.hexdigest(), '8350e5a3e24c153df2275c9f80692773' )

class MD4Test(unittest.TestCase):
    def test_empty(self):
        c = MD4()
        c.init()
        c.update('')
        self.assertEqual( c.final(), md4('') )
        self.assertEqual( c.hexdigest(), '31d6cfe0d16ae931b73c59d7e0c089c0' )

class MD5Test(unittest.TestCase):
    def test_empty(self):
        c = MD5()
        c.init()
        c.update('')
        self.assertEqual( c.final(), md5('') )
        self.assertEqual( c.hexdigest(), 'd41d8cd98f00b204e9800998ecf8427e' )

class SHA1Test(unittest.TestCase):
    def test_empty(self):
        c = SHA1()
        c.init()
        c.update('')
        self.assertEqual( c.final(), sha1('') )
        self.assertEqual( c.hexdigest(), 'da39a3ee5e6b4b0d3255bfef95601890afd80709' )

class SHA224Test(unittest.TestCase):
    def test_empty(self):
        c = SHA224()
        c.init()
        c.update('')
        self.assertEqual( c.final(), sha224('') )
        self.assertEqual( c.hexdigest(), 'd14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f' )

class SHA256Test(unittest.TestCase):
    def test_empty(self):
        c = SHA256()
        c.init()
        c.update('')
        self.assertEqual( c.final(), sha256('') )
        self.assertEqual( c.hexdigest(), 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855' )

class SHA384Test(unittest.TestCase):
    def test_empty(self):
        c = SHA384()
        c.init()
        c.update('')
        self.assertEqual( c.final(), sha384('') )
        self.assertEqual( c.hexdigest(), '38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b' )

class SHA512Test(unittest.TestCase):
    def test_empty(self):
        c = SHA512()
        c.init()
        c.update('')
        self.assertEqual( c.final(), sha512('') )
        self.assertEqual( c.hexdigest(), 'cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e' )

if __name__ == '__main__':
    unittest.main()
