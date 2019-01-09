from distutils.core import setup, Extension

setup(name = "CommonCrypto for Python",
      version = "0.9.2",
      author = "Ruda Moura",
      author_email = "ruda.moura@gmail.com",
      url = "http://code.google.com/p/pycommoncrypto/",
      scripts = ['md2.py', 'md4.py', 'md5.py',
                 'sha1.py', 'sha224.py', 'sha256.py',
                 'sha384.py', 'sha512.py'],
      py_modules = ['CommonCrypto'],
      ext_modules = [Extension("_commoncrypto", ["commoncrypto.c"])]
)
